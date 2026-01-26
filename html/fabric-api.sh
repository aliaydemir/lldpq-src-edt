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
                    vlan_ids = sorted([int(v) for v in profile_data['vlans'].keys()])
                    
                    # Build vlan_to_vrf mapping for all VLANs
                    for vlan_id, vlan_config in profile_data['vlans'].items():
                        if vlan_config and 'vrf' in vlan_config:
                            vlan_to_vrf[str(vlan_id)] = vlan_config['vrf']
                    
                    # Get first VLAN's config for description/VRF etc
                    first_vlan_id = vlan_ids[0] if vlan_ids else None
                    first_vlan_config = profile_data['vlans'].get(str(first_vlan_id)) or profile_data['vlans'].get(first_vlan_id) or {}
                    
                    # Get last VLAN's l2vni for range profiles
                    last_vlan_id = vlan_ids[-1] if vlan_ids else None
                    last_vlan_config = profile_data['vlans'].get(str(last_vlan_id)) or profile_data['vlans'].get(last_vlan_id) or {}
                    
                    # Determine VLAN ID display (single or range)
                    if len(vlan_ids) == 1:
                        vlan_id_display = str(vlan_ids[0])
                    else:
                        vlan_id_display = f"{vlan_ids[0]}-{vlan_ids[-1]}"
                    
                    # Store VLAN profile info for SVI section
                    vlan_profiles_data[profile_name] = {
                        'vlan_id': vlan_id_display,
                        'vlan_count': len(vlan_ids),
                        'description': first_vlan_config.get('description', ''),
                        'vrf': first_vlan_config.get('vrf', 'default'),
                        'l2vni': last_vlan_config.get('l2vni'),
                        'vrr_enabled': vrr_enabled,
                        'vrr_vip': first_vlan_config.get('vrr_vip'),
                        'even_ip': first_vlan_config.get('even_ip'),
                        'odd_ip': first_vlan_config.get('odd_ip'),
                        'ip': first_vlan_config.get('ip'),
                        'vlans': profile_data['vlans']  # Include raw vlans data
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

# Bulk create VLANs
bulk_create_vlans() {
    read -r POST_DATA
    python3 << PYTHON
import json
import yaml
import os
import sys

try:
    data = json.loads('''$POST_DATA''')
except:
    data = json.loads(sys.stdin.read()) if sys.stdin.isatty() == False else {}

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
vlan_file = os.path.join(ansible_dir, 'inventory', 'group_vars', 'all', 'vlan_profiles.yaml')

start_id = data.get('start_id', 1)
end_id = data.get('end_id', 1)
profile_name = data.get('profile_name', f'VLAN_{start_id}_{end_id}_L2')
description = data.get('description', f'L2 VLANs {start_id}-{end_id}')
l2vni_offset = data.get('l2vni_offset', 100000)

# Validate
if start_id < 1 or end_id > 4094 or start_id > end_id:
    print(json.dumps({'success': False, 'error': 'Invalid VLAN ID range'}))
    exit(0)

count = end_id - start_id + 1
if count > 500:
    print(json.dumps({'success': False, 'error': 'Maximum 500 VLANs at once'}))
    exit(0)

# Load existing vlan profiles
vlan_profiles = {}
if os.path.exists(vlan_file):
    with open(vlan_file, 'r') as f:
        existing = yaml.safe_load(f) or {}
        vlan_profiles = existing.get('vlan_profiles', {})

# Check if profile name already exists
if profile_name in vlan_profiles:
    print(json.dumps({'success': False, 'error': f'Profile {profile_name} already exists'}))
    exit(0)

# Create the VLAN profile with multiple VLANs inside
vlans_dict = {}
for vid in range(start_id, end_id + 1):
    vlans_dict[vid] = {
        'description': f'{description}',
        'l2vni': l2vni_offset + vid
    }

new_profile = {
    'vlans': vlans_dict
}

vlan_profiles[profile_name] = new_profile

# Write back
with open(vlan_file, 'w') as f:
    yaml.dump({'vlan_profiles': vlan_profiles}, f, default_flow_style=False, sort_keys=False)

print(json.dumps({'success': True, 'message': f'Created {count} VLANs in profile {profile_name}'}))
PYTHON
}

# ==================== VRF MANAGEMENT ====================

# Get available VRFs from all devices
get_available_vrfs() {
    python3 << PYTHON
import json
import yaml
import os
import glob

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
host_vars_dir = os.path.join(ansible_dir, 'inventory', 'host_vars')

# Collect all unique VRFs from all devices
vrfs = {}

for host_file in glob.glob(os.path.join(host_vars_dir, '*.yaml')) + glob.glob(os.path.join(host_vars_dir, '*.yml')):
    hostname = os.path.basename(host_file).rsplit('.', 1)[0]
    
    try:
        with open(host_file, 'r') as f:
            host_data = yaml.safe_load(f) or {}
            device_vrfs = host_data.get('vrfs', {})
            
            for vrf_name, vrf_config in device_vrfs.items():
                if vrf_name not in vrfs:
                    vrfs[vrf_name] = {
                        'name': vrf_name,
                        'l3vni': vrf_config.get('l3vni'),
                        'vxlan_int': vrf_config.get('vxlan_int'),
                        'bgp_profile': vrf_config.get('bgp', {}).get('bgp_profile'),
                        'device_count': 0,
                        'devices': []
                    }
                vrfs[vrf_name]['device_count'] += 1
                vrfs[vrf_name]['devices'].append(hostname)
    except:
        pass

print(json.dumps({
    'success': True,
    'vrfs': list(vrfs.values())
}))
PYTHON
}

# Create VRF in device's host_vars
create_vrf() {
    read -r POST_DATA
    python3 << PYTHON
import json
import yaml
import os
import sys

try:
    data = json.loads('''$POST_DATA''')
except:
    data = {}

device = data.get('device')
vrf_name = data.get('vrf_name')
l3vni = data.get('l3vni')
vxlan_int = data.get('vxlan_int')
bgp_asn = data.get('bgp_asn')
bgp_profile = data.get('bgp_profile')

if not device or not vrf_name:
    print(json.dumps({'success': False, 'error': 'Device and VRF name are required'}))
    sys.exit(0)

if not l3vni:
    print(json.dumps({'success': False, 'error': 'L3VNI is required'}))
    sys.exit(0)

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
host_file = os.path.join(ansible_dir, 'inventory', 'host_vars', f'{device}.yaml')

# Try .yml if .yaml doesn't exist
if not os.path.exists(host_file):
    host_file = os.path.join(ansible_dir, 'inventory', 'host_vars', f'{device}.yml')

# Load existing host_vars
host_data = {}
if os.path.exists(host_file):
    with open(host_file, 'r') as f:
        host_data = yaml.safe_load(f) or {}

# Initialize vrfs if not exists
if 'vrfs' not in host_data:
    host_data['vrfs'] = {}

# Check if VRF already exists
if vrf_name in host_data['vrfs']:
    print(json.dumps({'success': False, 'error': f'VRF {vrf_name} already exists on this device'}))
    sys.exit(0)

# Create VRF entry
vrf_entry = {
    'l3vni': l3vni,
    'lo': '{{ lo_ip }}'
}

if vxlan_int:
    vrf_entry['vxlan_int'] = vxlan_int

if bgp_asn or bgp_profile:
    vrf_entry['bgp'] = {}
    if bgp_asn:
        vrf_entry['bgp']['asn'] = bgp_asn
    if bgp_profile:
        vrf_entry['bgp']['bgp_profile'] = bgp_profile

host_data['vrfs'][vrf_name] = vrf_entry

# Write back
with open(host_file if os.path.exists(host_file) else os.path.join(ansible_dir, 'inventory', 'host_vars', f'{device}.yaml'), 'w') as f:
    yaml.dump(host_data, f, default_flow_style=False, sort_keys=False)

print(json.dumps({'success': True, 'vrf_name': vrf_name}))
PYTHON
}

# Assign VRFs to device
assign_vrfs() {
    read -r POST_DATA
    python3 << PYTHON
import json
import yaml
import os
import sys
import glob

try:
    data = json.loads('''$POST_DATA''')
except:
    data = {}

device = data.get('device')
vrf_names = data.get('vrfs', [])

if not device or not vrf_names:
    print(json.dumps({'success': False, 'error': 'Device and VRF names are required'}))
    sys.exit(0)

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
host_vars_dir = os.path.join(ansible_dir, 'inventory', 'host_vars')
host_file = os.path.join(host_vars_dir, f'{device}.yaml')

# Try .yml if .yaml doesn't exist
if not os.path.exists(host_file):
    alt_file = os.path.join(host_vars_dir, f'{device}.yml')
    if os.path.exists(alt_file):
        host_file = alt_file

# Load existing host_vars
host_data = {}
if os.path.exists(host_file):
    with open(host_file, 'r') as f:
        host_data = yaml.safe_load(f) or {}

# Initialize vrfs if not exists
if 'vrfs' not in host_data:
    host_data['vrfs'] = {}

# Find VRF configs from other devices
all_vrf_configs = {}
for hf in glob.glob(os.path.join(host_vars_dir, '*.yaml')) + glob.glob(os.path.join(host_vars_dir, '*.yml')):
    try:
        with open(hf, 'r') as f:
            hd = yaml.safe_load(f) or {}
            for vrf_name, vrf_config in hd.get('vrfs', {}).items():
                if vrf_name not in all_vrf_configs:
                    all_vrf_configs[vrf_name] = vrf_config
    except:
        pass

# Add VRFs
added = []
for vrf_name in vrf_names:
    if vrf_name not in host_data['vrfs']:
        if vrf_name in all_vrf_configs:
            host_data['vrfs'][vrf_name] = all_vrf_configs[vrf_name]
            added.append(vrf_name)
        else:
            # Create minimal VRF entry
            host_data['vrfs'][vrf_name] = {'l3vni': None}
            added.append(vrf_name)

# Write back
with open(host_file, 'w') as f:
    yaml.dump(host_data, f, default_flow_style=False, sort_keys=False)

print(json.dumps({'success': True, 'added': added}))
PYTHON
}

# Unassign VRF from device
unassign_vrf() {
    read -r POST_DATA
    python3 << PYTHON
import json
import yaml
import os
import sys

try:
    data = json.loads('''$POST_DATA''')
except:
    data = {}

device = data.get('device')
vrf_name = data.get('vrf')

if not device or not vrf_name:
    print(json.dumps({'success': False, 'error': 'Device and VRF name are required'}))
    sys.exit(0)

if vrf_name == 'default':
    print(json.dumps({'success': False, 'error': 'Cannot remove default VRF'}))
    sys.exit(0)

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
host_vars_dir = os.path.join(ansible_dir, 'inventory', 'host_vars')
host_file = os.path.join(host_vars_dir, f'{device}.yaml')

# Try .yml if .yaml doesn't exist
if not os.path.exists(host_file):
    alt_file = os.path.join(host_vars_dir, f'{device}.yml')
    if os.path.exists(alt_file):
        host_file = alt_file

if not os.path.exists(host_file):
    print(json.dumps({'success': False, 'error': 'Host vars file not found'}))
    sys.exit(0)

# Load host_vars
with open(host_file, 'r') as f:
    host_data = yaml.safe_load(f) or {}

if 'vrfs' not in host_data or vrf_name not in host_data['vrfs']:
    print(json.dumps({'success': False, 'error': f'VRF {vrf_name} not found in device config'}))
    sys.exit(0)

# Remove VRF
del host_data['vrfs'][vrf_name]

# Write back
with open(host_file, 'w') as f:
    yaml.dump(host_data, f, default_flow_style=False, sort_keys=False)

print(json.dumps({'success': True}))
PYTHON
}

# Get VRF report - VRFs with device assignments
get_vrf_report() {
    python3 << PYTHON
import json
import yaml
import os
import glob

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
host_vars_dir = os.path.join(ansible_dir, 'inventory', 'host_vars')

# Collect all VRFs from all devices
vrfs = {}
unique_devices = set()

for host_file in glob.glob(os.path.join(host_vars_dir, '*.yaml')) + glob.glob(os.path.join(host_vars_dir, '*.yml')):
    hostname = os.path.basename(host_file).rsplit('.', 1)[0]
    
    try:
        with open(host_file, 'r') as f:
            host_data = yaml.safe_load(f) or {}
            device_vrfs = host_data.get('vrfs', {})
            
            if device_vrfs:
                unique_devices.add(hostname)
            
            for vrf_name, vrf_config in device_vrfs.items():
                if vrf_name not in vrfs:
                    vrfs[vrf_name] = {
                        'name': vrf_name,
                        'l3vni': vrf_config.get('l3vni'),
                        'vxlan_int': vrf_config.get('vxlan_int'),
                        'bgp_profile': vrf_config.get('bgp', {}).get('bgp_profile') if vrf_config.get('bgp') else None,
                        'devices': []
                    }
                vrfs[vrf_name]['devices'].append(hostname)
    except:
        pass

print(json.dumps({
    'success': True,
    'vrfs': vrfs,
    'device_count': len(unique_devices)
}))
PYTHON
}

# Get VLAN report - VLANs with device assignments
get_vlan_report() {
    python3 << PYTHON
import json
import yaml
import os
import glob

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
inventory_base = os.path.join(ansible_dir, 'inventory')
vlan_file = os.path.join(inventory_base, 'group_vars', 'all', 'vlan_profiles.yaml')
host_vars_dir = os.path.join(inventory_base, 'host_vars')

# Load VLAN profiles
vlan_profiles = {}
vrfs = set()

if os.path.exists(vlan_file):
    with open(vlan_file, 'r') as f:
        data = yaml.safe_load(f) or {}
        vlan_profiles = data.get('vlan_profiles', {})

# Collect VRFs from VLAN profiles
for vlan_name, vlan_data in vlan_profiles.items():
    if vlan_data and 'vlans' in vlan_data:
        for vid, vinfo in vlan_data['vlans'].items():
            if vinfo and vinfo.get('vrf'):
                vrfs.add(vinfo['vrf'])

# Build VLAN to device mapping and collect unique devices
vlan_device_map = {vlan_name: [] for vlan_name in vlan_profiles.keys()}
unique_devices = set()

# Scan all host_vars files for vlan_templates
for host_file in glob.glob(os.path.join(host_vars_dir, '*.yaml')) + glob.glob(os.path.join(host_vars_dir, '*.yml')):
    hostname = os.path.basename(host_file).rsplit('.', 1)[0]
    
    try:
        with open(host_file, 'r') as f:
            host_data = yaml.safe_load(f) or {}
            vlan_templates = host_data.get('vlan_templates', [])
            
            if vlan_templates:
                unique_devices.add(hostname)
            
            for vlan_name in vlan_templates:
                if vlan_name in vlan_device_map:
                    vlan_device_map[vlan_name].append(hostname)
                else:
                    vlan_device_map[vlan_name] = [hostname]
    except:
        pass

print(json.dumps({
    'success': True,
    'vlan_profiles': vlan_profiles,
    'vlan_device_map': vlan_device_map,
    'device_count': len(unique_devices),
    'vrf_count': len(vrfs)
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
ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
inventory_base = os.path.join(ansible_dir, 'inventory')
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
ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
inventory_base = os.path.join(ansible_dir, 'inventory')
host_vars_file = os.path.join(inventory_base, 'host_vars', device + '.yaml')

if not os.path.exists(host_vars_file):
    # Also try without .yaml
    host_vars_file = os.path.join(inventory_base, 'host_vars', device + '.yml')

# Load host_vars or create empty config
host_config = {}
if os.path.exists(host_vars_file):
    with open(host_vars_file, 'r') as f:
        host_config = yaml.safe_load(f) or {}
else:
    # Create new file with .yaml extension
    host_vars_file = os.path.join(inventory_base, 'host_vars', device + '.yaml')

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

unassign_vlan() {
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
vlan = data.get('vlan', '')

if not device:
    print(json.dumps({'success': False, 'error': 'Device name is required'}))
    sys.exit(0)

if not vlan:
    print(json.dumps({'success': False, 'error': 'VLAN name is required'}))
    sys.exit(0)

# Path to host_vars
ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
inventory_base = os.path.join(ansible_dir, 'inventory')
host_vars_file = os.path.join(inventory_base, 'host_vars', device + '.yaml')

# Try .yaml first, then .yml
if not os.path.exists(host_vars_file):
    host_vars_file = os.path.join(inventory_base, 'host_vars', device + '.yml')

# Load host_vars (create empty if doesn't exist)
host_config = {}
if os.path.exists(host_vars_file):
    with open(host_vars_file, 'r') as f:
        host_config = yaml.safe_load(f) or {}
else:
    # File doesn't exist - check if we should create it
    # Use .yaml extension for new files
    host_vars_file = os.path.join(inventory_base, 'host_vars', device + '.yaml')
    host_config = {}

# Check if VLAN is in vlan_templates
if 'vlan_templates' not in host_config or vlan not in host_config.get('vlan_templates', []):
    print(json.dumps({'success': False, 'error': f'VLAN {vlan} not found in device config (may be inherited from group_vars)'}))
    sys.exit(0)

# Remove VLAN from vlan_templates
host_config['vlan_templates'].remove(vlan)

# Save host_vars
with open(host_vars_file, 'w') as f:
    yaml.dump(host_config, f, default_flow_style=False, sort_keys=False)

print(json.dumps({
    'success': True,
    'device': device,
    'removed_vlan': vlan
}))
PYTHON
}

update_vlan() {
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

original_name = data.get('original_name', '')
profile_name = data.get('profile_name', original_name)
vlan_id = data.get('vlan_id')
description = data.get('description', '')
l2vni = data.get('l2vni')
svi_enabled = data.get('svi_enabled', False)
vrr_enabled = data.get('vrr_enabled', False)
vrf = data.get('vrf', 'default')
vrr_vip = data.get('vrr_vip', '')
even_ip = data.get('even_ip', '')
odd_ip = data.get('odd_ip', '')
gateway_ip = data.get('gateway_ip', '')

if not original_name:
    print(json.dumps({'success': False, 'error': 'Original profile name is required'}))
    sys.exit(0)

# Paths
ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
inventory_base = os.path.join(ansible_dir, 'inventory')
vlan_profiles_file = os.path.join(inventory_base, 'group_vars', 'all', 'vlan_profiles.yaml')

# Load vlan_profiles
vlan_config = {}
if os.path.exists(vlan_profiles_file):
    with open(vlan_profiles_file, 'r') as f:
        vlan_config = yaml.safe_load(f) or {}

if 'vlan_profiles' not in vlan_config or original_name not in vlan_config['vlan_profiles']:
    print(json.dumps({'success': False, 'error': f'VLAN profile {original_name} not found'}))
    sys.exit(0)

# Get existing profile data
existing = vlan_config['vlan_profiles'][original_name]

# Build updated VLAN entry
vlan_entry = {
    'description': description,
    'l2vni': l2vni if l2vni else existing.get('vlans', {}).get(vlan_id, {}).get('l2vni', 100000 + vlan_id)
}

if svi_enabled:
    vlan_entry['vrf'] = vrf
    vlan_entry['ipv6'] = False
    
    if vrr_enabled:
        if vrr_vip:
            vlan_entry['vrr_vip'] = vrr_vip
        if even_ip:
            vlan_entry['even_ip'] = even_ip
        if odd_ip:
            vlan_entry['odd_ip'] = odd_ip
    else:
        if gateway_ip:
            vlan_entry['ip'] = gateway_ip

# Update profile
profile_entry = {
    'vrr': {'state': vrr_enabled if svi_enabled else False},
    'vlans': {vlan_id: vlan_entry}
}

# If profile name changed, remove old and add new
if profile_name != original_name:
    del vlan_config['vlan_profiles'][original_name]

vlan_config['vlan_profiles'][profile_name] = profile_entry

# Save
with open(vlan_profiles_file, 'w') as f:
    yaml.dump(vlan_config, f, default_flow_style=False, sort_keys=False)

print(json.dumps({
    'success': True,
    'profile_name': profile_name,
    'renamed': profile_name != original_name
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
    "get-vlan-report")
        get_vlan_report
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
    "unassign-vlan")
        unassign_vlan
        ;;
    "update-vlan")
        update_vlan
        ;;
    "bulk-create-vlans")
        bulk_create_vlans
        ;;
    "get-available-vrfs")
        get_available_vrfs
        ;;
    "create-vrf")
        create_vrf
        ;;
    "assign-vrfs")
        assign_vrfs
        ;;
    "unassign-vrf")
        unassign_vrf
        ;;
    "get-vrf-report")
        get_vrf_report
        ;;
    *)
        echo '{"success": false, "error": "Unknown action: '"$ACTION"'"}'
        ;;
esac
