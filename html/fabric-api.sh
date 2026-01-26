#!/bin/bash
# Fabric Configuration API
# Backend for fabric-config.html

# Load config
source /etc/lldpq.conf 2>/dev/null || true
ANSIBLE_DIR="${ANSIBLE_DIR:-$HOME/ansible}"

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
    
    if [[ ! -f "$host_vars_file" ]]; then
        echo '{"success": false, "error": "Host vars file not found: '"$host_vars_file"'"}'
        return
    fi
    
    # Python script to parse host_vars and find device info
    python3 << PYTHON
import sys
import json
import yaml
import os

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
hostname = "$hostname"
host_vars_file = f"{ansible_dir}/inventory/host_vars/{hostname}.yaml"
hosts_file = f"{ansible_dir}/inventory/hosts"

try:
    # Read host_vars
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
    
    print(json.dumps({
        'success': True,
        'config': config,
        'device_info': device_info
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
