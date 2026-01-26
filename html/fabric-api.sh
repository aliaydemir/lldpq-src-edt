#!/bin/bash
# Fabric Configuration API
# Backend for fabric-config.html

# Load config - explicitly read ANSIBLE_DIR from config file
if [[ -f /etc/lldpq.conf ]]; then
    ANSIBLE_DIR=$(grep "^ANSIBLE_DIR=" /etc/lldpq.conf | cut -d= -f2)
fi
ANSIBLE_DIR="${ANSIBLE_DIR:-$HOME/ansible}"

# Export for Python scripts
export ANSIBLE_DIR

# Output JSON header
echo "Content-Type: application/json"
echo ""

# Parse query string
parse_query() {
    local query="$QUERY_STRING"
    # Parse action
    ACTION=$(echo "$query" | grep -oP 'action=\K[^&]*' | head -1)
    # Parse hostname
    HOSTNAME=$(echo "$query" | grep -oP 'hostname=\K[^&]*' | head -1 | python3 -c "import sys, urllib.parse; print(urllib.parse.unquote(sys.stdin.read().strip()))")
}

# List devices from inventory/hosts
list_devices() {
    local hosts_file="$ANSIBLE_DIR/inventory/hosts"
    
    if [[ ! -f "$hosts_file" ]]; then
        echo '{"success": false, "error": "Inventory file not found: '"$hosts_file"'"}'
        return
    fi
    
    # Python script to parse hosts file
    python3 << 'PYTHON'
import sys
import json
import os

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
hosts_file = f"{ansible_dir}/inventory/hosts"

devices = {}
current_group = None

try:
    with open(hosts_file, 'r') as f:
        for line in f:
            line = line.strip()
            
            # Skip empty lines and comments
            if not line or line.startswith('#'):
                continue
            
            # Skip [all:vars] and similar sections
            if line.startswith('[') and ':' in line:
                current_group = None
                continue
            
            # Group header
            if line.startswith('[') and line.endswith(']'):
                current_group = line[1:-1]
                # Skip children groups
                if ':children' in current_group:
                    current_group = None
                else:
                    devices[current_group] = []
                continue
            
            # Device line
            if current_group and '=' in line:
                parts = line.split()
                hostname = parts[0]
                ip = None
                
                # Find ansible_host
                for part in parts[1:]:
                    if part.startswith('ansible_host='):
                        ip = part.split('=')[1]
                        break
                
                devices[current_group].append({
                    'hostname': hostname,
                    'ip': ip
                })
    
    print(json.dumps({
        'success': True,
        'devices': devices,
        'ansible_dir': ansible_dir
    }))

except Exception as e:
    print(json.dumps({
        'success': False,
        'error': str(e)
    }))
PYTHON
}

# Get device configuration
get_device() {
    local hostname="$1"
    
    if [[ -z "$hostname" ]]; then
        echo '{"success": false, "error": "Hostname is required"}'
        return
    fi
    
    local host_vars_file="$ANSIBLE_DIR/inventory/host_vars/${hostname}.yaml"
    
    # Python script to parse host_vars and find device info
    # Host vars file is optional - some devices (like spines) may not have it
    python3 << PYTHON
import sys
import json
import yaml
import os

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
hostname = "$hostname"
host_vars_file = f"{ansible_dir}/inventory/host_vars/{hostname}.yaml"
hosts_file = f"{ansible_dir}/inventory/hosts"
port_profiles_file = f"{ansible_dir}/inventory/group_vars/all/sw_port_profiles.yaml"
vlan_profiles_file = f"{ansible_dir}/inventory/group_vars/all/vlan_profiles.yaml"

try:
    # Read host_vars (optional - some devices like spines may not have it)
    config = {}
    if os.path.exists(host_vars_file):
        with open(host_vars_file, 'r') as f:
            config = yaml.safe_load(f) or {}
    
    # Find device info from hosts file
    device_info = {'hostname': hostname, 'group': None, 'ip': None}
    current_group = None
    
    with open(hosts_file, 'r') as f:
        for line in f:
            line = line.strip()
            
            if not line or line.startswith('#'):
                continue
            
            if line.startswith('[') and line.endswith(']'):
                current_group = line[1:-1]
                if ':' in current_group:
                    current_group = None
                continue
            
            if current_group and line.startswith(hostname):
                device_info['group'] = current_group
                parts = line.split()
                for part in parts[1:]:
                    if part.startswith('ansible_host='):
                        device_info['ip'] = part.split('=')[1]
                        break
                break
    
    # Check for group_vars VRFs if not in host_vars
    if 'vrfs' not in config and device_info['group']:
        group_vrfs_file = f"{ansible_dir}/inventory/group_vars/{device_info['group']}/vrfs.yaml"
        if os.path.exists(group_vrfs_file):
            with open(group_vrfs_file, 'r') as f:
                group_config = yaml.safe_load(f) or {}
                if 'vrfs' in group_config:
                    config['vrfs'] = group_config['vrfs']
    
    # Load port profiles for VLAN resolution
    port_profiles = {}
    if os.path.exists(port_profiles_file):
        with open(port_profiles_file, 'r') as f:
            pp_config = yaml.safe_load(f) or {}
            port_profiles = pp_config.get('sw_port_profiles', {})
    
    # Load VLAN profiles for VRF and IP resolution
    vlan_to_vrf = {}
    vlan_profiles_data = {}
    vxlan_int_mapping = {}  # VRF name -> VLAN ID for L3VNI interface
    
    if os.path.exists(vlan_profiles_file):
        with open(vlan_profiles_file, 'r') as f:
            vp_config = yaml.safe_load(f) or {}
            
            # Load vxlan_int mapping (nscale/kddi style: vxlan_int at top level)
            if 'vxlan_int' in vp_config and isinstance(vp_config['vxlan_int'], dict):
                vxlan_int_mapping = {str(k): str(v) for k, v in vp_config['vxlan_int'].items()}
            
            vlan_profiles = vp_config.get('vlan_profiles', {})
            # Build VLAN ID to VRF mapping and VLAN profile data
            for profile_name, profile_data in vlan_profiles.items():
                if profile_data and 'vlans' in profile_data:
                    vrr_enabled = profile_data.get('vrr', {}).get('state', False)
                    for vlan_id, vlan_config in profile_data['vlans'].items():
                        if vlan_config:
                            if 'vrf' in vlan_config:
                                vlan_to_vrf[str(vlan_id)] = vlan_config['vrf']
                            # Store VLAN profile info for SVI section
                            vlan_profiles_data[profile_name] = {
                                'vlan_id': str(vlan_id),
                                'description': vlan_config.get('description', ''),
                                'vrf': vlan_config.get('vrf', 'default'),
                                'l2vni': vlan_config.get('l2vni'),
                                'vrr_enabled': vrr_enabled,
                                'vrr_vip': vlan_config.get('vrr_vip'),
                                'even_ip': vlan_config.get('even_ip'),
                                'odd_ip': vlan_config.get('odd_ip'),
                                'ip': vlan_config.get('ip')
                            }
    
    print(json.dumps({
        'success': True,
        'config': config,
        'device_info': device_info,
        'port_profiles': port_profiles,
        'vlan_to_vrf': vlan_to_vrf,
        'vlan_profiles': vlan_profiles_data,
        'vxlan_int_mapping': vxlan_int_mapping
    }))

except Exception as e:
    print(json.dumps({
        'success': False,
        'error': str(e)
    }))
PYTHON
}

# Get VLAN profiles
get_vlan_profiles() {
    local vlan_file="$ANSIBLE_DIR/inventory/group_vars/all/vlan_profiles.yaml"
    
    if [[ ! -f "$vlan_file" ]]; then
        echo '{"success": false, "error": "VLAN profiles file not found"}'
        return
    fi
    
    python3 << PYTHON
import json
import yaml
import os

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
vlan_file = f"{ansible_dir}/inventory/group_vars/all/vlan_profiles.yaml"

try:
    with open(vlan_file, 'r') as f:
        config = yaml.safe_load(f) or {}
    
    print(json.dumps({
        'success': True,
        'vlan_profiles': config.get('vlan_profiles', {}),
        'vxlan_int': config.get('vxlan_int', {})
    }))

except Exception as e:
    print(json.dumps({
        'success': False,
        'error': str(e)
    }))
PYTHON
}

# Get port profiles
get_port_profiles() {
    local port_file="$ANSIBLE_DIR/inventory/group_vars/all/sw_port_profiles.yaml"
    
    if [[ ! -f "$port_file" ]]; then
        echo '{"success": false, "error": "Port profiles file not found"}'
        return
    fi
    
    python3 << PYTHON
import json
import yaml
import os

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
port_file = f"{ansible_dir}/inventory/group_vars/all/sw_port_profiles.yaml"

try:
    with open(port_file, 'r') as f:
        config = yaml.safe_load(f) or {}
    
    print(json.dumps({
        'success': True,
        'port_profiles': config.get('sw_port_profiles', {})
    }))

except Exception as e:
    print(json.dumps({
        'success': False,
        'error': str(e)
    }))
PYTHON
}

# Main handler
parse_query

case "$ACTION" in
    "list-devices")
        list_devices
        ;;
    "get-device")
        get_device "$HOSTNAME"
        ;;
    "get-vlan-profiles")
        get_vlan_profiles
        ;;
    "get-port-profiles")
        get_port_profiles
        ;;
    *)
        echo '{"success": false, "error": "Unknown action: '"$ACTION"'"}'
        ;;
esac
