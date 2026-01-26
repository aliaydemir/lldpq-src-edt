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

# Create VLAN - adds to vlan_profiles.yaml and sw_port_profiles.yaml
create_vlan() {
    # Read POST data
    local post_data
    read -r post_data
    
    python3 << PYTHON
import json
import yaml
import os
import sys
from datetime import datetime

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
vlan_profiles_file = f"{ansible_dir}/inventory/group_vars/all/vlan_profiles.yaml"
port_profiles_file = f"{ansible_dir}/inventory/group_vars/all/sw_port_profiles.yaml"

try:
    # Parse POST data
    post_data = '''$post_data'''
    data = json.loads(post_data)
    
    vlan_id = int(data.get('vlan_id'))
    profile_name = data.get('profile_name', f'VLAN_{vlan_id}')
    description = data.get('description', '')
    l2vni = data.get('l2vni', 100000 + vlan_id)
    stp_bpduguard = data.get('stp_bpduguard', True)
    
    # SVI/L3 configuration
    svi_enabled = data.get('svi_enabled', False)
    vrf = data.get('vrf', 'default') if svi_enabled else None
    vrr_enabled = data.get('vrr_enabled', False) if svi_enabled else False
    vrr_vip = data.get('vrr_vip', '')
    even_ip = data.get('even_ip', '')
    odd_ip = data.get('odd_ip', '')
    gateway_ip = data.get('gateway_ip', '')
    
    # Validate VLAN ID
    if vlan_id < 1 or vlan_id > 4094:
        print(json.dumps({'success': False, 'error': 'VLAN ID must be between 1 and 4094'}))
        sys.exit(0)
    
    # Load existing vlan_profiles
    vlan_config = {}
    if os.path.exists(vlan_profiles_file):
        with open(vlan_profiles_file, 'r') as f:
            vlan_config = yaml.safe_load(f) or {}
    
    if 'vlan_profiles' not in vlan_config:
        vlan_config['vlan_profiles'] = {}
    
    # Check if VLAN profile already exists
    if profile_name in vlan_config['vlan_profiles']:
        print(json.dumps({'success': False, 'error': f'VLAN profile {profile_name} already exists'}))
        sys.exit(0)
    
    # Check if VLAN ID already used
    for pname, pdata in vlan_config['vlan_profiles'].items():
        if pdata and 'vlans' in pdata:
            if vlan_id in pdata['vlans'] or str(vlan_id) in pdata['vlans']:
                print(json.dumps({'success': False, 'error': f'VLAN ID {vlan_id} already exists in profile {pname}'}))
                sys.exit(0)
    
    # Build VLAN entry
    vlan_entry = {
        'description': description,
        'l2vni': l2vni
    }
    
    # Add VRF and IP info only if SVI is enabled
    if svi_enabled:
        vlan_entry['vrf'] = vrf
        vlan_entry['ipv6'] = False  # Always disabled
        
        if vrr_enabled:
            # VRR mode with VIP and Even/Odd IPs
            if vrr_vip:
                vlan_entry['vrr_vip'] = vrr_vip
            if even_ip:
                vlan_entry['even_ip'] = even_ip
            if odd_ip:
                vlan_entry['odd_ip'] = odd_ip
        else:
            # Single gateway IP mode
            if gateway_ip:
                vlan_entry['ip'] = gateway_ip
    
    # Build profile entry
    profile_entry = {
        'vrr': {'state': vrr_enabled if svi_enabled else False},
        'vlans': {vlan_id: vlan_entry}
    }
    
    # Add to vlan_profiles
    vlan_config['vlan_profiles'][profile_name] = profile_entry
    
    # Write vlan_profiles.yaml
    with open(vlan_profiles_file, 'w') as f:
        yaml.dump(vlan_config, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
    
    # Load existing port_profiles
    port_config = {}
    if os.path.exists(port_profiles_file):
        with open(port_profiles_file, 'r') as f:
            port_config = yaml.safe_load(f) or {}
    
    if 'sw_port_profiles' not in port_config:
        port_config['sw_port_profiles'] = {}
    
    # Create ACCESS_VLAN_{id} profile
    access_profile_name = f'ACCESS_VLAN_{vlan_id}'
    if access_profile_name not in port_config['sw_port_profiles']:
        port_config['sw_port_profiles'][access_profile_name] = {
            'description': description,
            'sw_port_mode': 'access',
            'access_vlan': vlan_id,
            'stp_bpduguard': stp_bpduguard
        }
        
        # Write port_profiles.yaml
        with open(port_profiles_file, 'w') as f:
            yaml.dump(port_config, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
    
    print(json.dumps({
        'success': True,
        'message': f'VLAN {vlan_id} created successfully',
        'vlan_profile': profile_name,
        'port_profile': access_profile_name
    }))

except json.JSONDecodeError as e:
    print(json.dumps({'success': False, 'error': f'Invalid JSON: {str(e)}'}))
except Exception as e:
    print(json.dumps({'success': False, 'error': str(e)}))
PYTHON
}

# Get list of VRFs for dropdown
get_vrfs() {
    python3 << 'PYTHON'
import json
import yaml
import os

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
vlan_profiles_file = f"{ansible_dir}/inventory/group_vars/all/vlan_profiles.yaml"

vrfs = set(['default'])

try:
    # Check vxlan_int mapping for VRF names
    if os.path.exists(vlan_profiles_file):
        with open(vlan_profiles_file, 'r') as f:
            config = yaml.safe_load(f) or {}
        
        # Get VRFs from vxlan_int mapping
        if 'vxlan_int' in config:
            vrfs.update(config['vxlan_int'].keys())
        
        # Get VRFs from vlan_profiles
        if 'vlan_profiles' in config:
            for profile in config['vlan_profiles'].values():
                if profile and 'vlans' in profile:
                    for vlan in profile['vlans'].values():
                        if vlan and 'vrf' in vlan:
                            vrfs.add(vlan['vrf'])
    
    print(json.dumps({
        'success': True,
        'vrfs': sorted(list(vrfs))
    }))

except Exception as e:
    print(json.dumps({'success': False, 'error': str(e)}))
PYTHON
}

delete_vlan() {
    # Read POST data
    local post_data
    read -r post_data

    python3 << PYTHON
import json
import yaml
import os
import sys

# Parse POST data
post_data = '''$post_data'''
data = json.loads(post_data)

profile_name = data.get('profile_name', '')

if not profile_name:
    print(json.dumps({'success': False, 'error': 'Profile name is required'}))
    sys.exit(0)

# Paths
inventory_base = "$INVENTORY"
vlan_profiles_file = os.path.join(inventory_base, 'group_vars', 'all', 'vlan_profiles.yaml')
port_profiles_file = os.path.join(inventory_base, 'group_vars', 'all', 'sw_port_profiles.yaml')

# Load vlan_profiles
vlan_config = {}
if os.path.exists(vlan_profiles_file):
    with open(vlan_profiles_file, 'r') as f:
        vlan_config = yaml.safe_load(f) or {}

if 'vlan_profiles' not in vlan_config or profile_name not in vlan_config['vlan_profiles']:
    print(json.dumps({'success': False, 'error': f'VLAN profile {profile_name} not found'}))
    sys.exit(0)

# Get VLAN ID for port profile name
vlan_id = None
profile_data = vlan_config['vlan_profiles'][profile_name]
if profile_data and 'vlans' in profile_data:
    vlan_ids = list(profile_data['vlans'].keys())
    if vlan_ids:
        vlan_id = vlan_ids[0]

# Delete from vlan_profiles
del vlan_config['vlan_profiles'][profile_name]

# Save vlan_profiles
with open(vlan_profiles_file, 'w') as f:
    yaml.dump(vlan_config, f, default_flow_style=False, sort_keys=False)

# Try to delete corresponding port profile
port_profile_deleted = False
port_profile_name = None
if vlan_id:
    port_profile_name = f'ACCESS_VLAN_{vlan_id}'
    
    port_config = {}
    if os.path.exists(port_profiles_file):
        with open(port_profiles_file, 'r') as f:
            port_config = yaml.safe_load(f) or {}
    
    if 'sw_port_profiles' in port_config and port_profile_name in port_config['sw_port_profiles']:
        del port_config['sw_port_profiles'][port_profile_name]
        
        with open(port_profiles_file, 'w') as f:
            yaml.dump(port_config, f, default_flow_style=False, sort_keys=False)
        
        port_profile_deleted = True

print(json.dumps({
    'success': True,
    'profile_name': profile_name,
    'port_profile': port_profile_name,
    'port_profile_deleted': port_profile_deleted
}))
PYTHON
}

assign_vlans() {
    # Read POST data
    local post_data
    read -r post_data

    python3 << PYTHON
import json
import yaml
import os
import sys

# Parse POST data
post_data = '''$post_data'''
data = json.loads(post_data)

device = data.get('device', '')
vlans = data.get('vlans', [])

if not device:
    print(json.dumps({'success': False, 'error': 'Device name is required'}))
    sys.exit(0)

if not vlans:
    print(json.dumps({'success': False, 'error': 'No VLANs selected'}))
    sys.exit(0)

# Path to host_vars
inventory_base = "$INVENTORY"
host_vars_file = os.path.join(inventory_base, 'host_vars', device + '.yaml')

if not os.path.exists(host_vars_file):
    # Also try without .yaml
    host_vars_file = os.path.join(inventory_base, 'host_vars', device + '.yml')

if not os.path.exists(host_vars_file):
    print(json.dumps({'success': False, 'error': f'Host vars file not found for {device}'}))
    sys.exit(0)

# Load host_vars
host_config = {}
with open(host_vars_file, 'r') as f:
    host_config = yaml.safe_load(f) or {}

# Add VLANs to vlan_templates
if 'vlan_templates' not in host_config:
    host_config['vlan_templates'] = []

# Add new VLANs (avoid duplicates)
added = []
for vlan in vlans:
    if vlan not in host_config['vlan_templates']:
        host_config['vlan_templates'].append(vlan)
        added.append(vlan)

# Save host_vars
with open(host_vars_file, 'w') as f:
    yaml.dump(host_config, f, default_flow_style=False, sort_keys=False)

print(json.dumps({
    'success': True,
    'device': device,
    'added_vlans': added,
    'total_vlans': len(host_config['vlan_templates'])
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
    "get-vrfs")
        get_vrfs
        ;;
    "create-vlan")
        create_vlan
        ;;
    "delete-vlan")
        delete_vlan
        ;;
    "assign-vlans")
        assign_vlans
        ;;
    *)
        echo '{"success": false, "error": "Unknown action: '"$ACTION"'"}'
        ;;
esac
