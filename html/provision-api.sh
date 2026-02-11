#!/bin/bash
# provision-api.sh - Provision API (ZTP + Base Config)
# Backend for provision.html
# Called by nginx fcgiwrap

# Load config
if [[ -f /etc/lldpq.conf ]]; then
    source /etc/lldpq.conf
fi

LLDPQ_DIR="${LLDPQ_DIR:-/home/lldpq/lldpq}"
LLDPQ_USER="${LLDPQ_USER:-lldpq}"
WEB_ROOT="${WEB_ROOT:-/var/www/html}"

# DHCP config paths
DHCP_HOSTS_FILE="${DHCP_HOSTS_FILE:-/etc/dhcp/dhcpd.hosts}"
DHCP_CONF_FILE="${DHCP_CONF_FILE:-/etc/dhcp/dhcpd.conf}"
DHCP_LEASES_FILE="${DHCP_LEASES_FILE:-/var/lib/dhcp/dhcpd.leases}"
ZTP_SCRIPT_FILE="${ZTP_SCRIPT_FILE:-${WEB_ROOT}/cumulus-ztp.sh}"
BASE_CONFIG_DIR="${BASE_CONFIG_DIR:-${LLDPQ_DIR}/base-config}"

# Output JSON header
echo "Content-Type: application/json"
echo ""

# Parse query string
ACTION=$(echo "$QUERY_STRING" | grep -oP 'action=\K[^&]*' | head -1)

# Read POST data if present
POST_DATA=""
if [ "$REQUEST_METHOD" = "POST" ] && [ -n "$CONTENT_LENGTH" ] && [ "$CONTENT_LENGTH" -gt 0 ] 2>/dev/null; then
    POST_DATA=$(dd bs=1 count="$CONTENT_LENGTH" 2>/dev/null)
fi

# Export for Python
export LLDPQ_DIR LLDPQ_USER WEB_ROOT
export DHCP_HOSTS_FILE DHCP_CONF_FILE DHCP_LEASES_FILE ZTP_SCRIPT_FILE BASE_CONFIG_DIR
export POST_DATA ACTION

python3 << 'PYTHON_SCRIPT'
import json
import sys
import os
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

ACTION = os.environ.get('ACTION', '')
POST_DATA = os.environ.get('POST_DATA', '')
LLDPQ_DIR = os.environ.get('LLDPQ_DIR', '/home/lldpq/lldpq')
LLDPQ_USER = os.environ.get('LLDPQ_USER', 'lldpq')
WEB_ROOT = os.environ.get('WEB_ROOT', '/var/www/html')
DHCP_HOSTS_FILE = os.environ.get('DHCP_HOSTS_FILE', '/etc/dhcp/dhcpd.hosts')
DHCP_LEASES_FILE = os.environ.get('DHCP_LEASES_FILE', '/var/lib/dhcp/dhcpd.leases')
ZTP_SCRIPT_FILE = os.environ.get('ZTP_SCRIPT_FILE', f'{WEB_ROOT}/cumulus-ztp.sh')
BASE_CONFIG_DIR = os.environ.get('BASE_CONFIG_DIR', f'{LLDPQ_DIR}/base-config')

# Also check alternate path for dhcpd.hosts (some setups use dhcpd.host)
DHCP_HOSTS_ALT = DHCP_HOSTS_FILE.replace('dhcpd.hosts', 'dhcpd.host')

def get_dhcp_hosts_path():
    """Find the actual dhcpd.hosts file"""
    for p in [DHCP_HOSTS_FILE, DHCP_HOSTS_ALT]:
        if os.path.exists(p):
            return p
    # Default to primary path (will be created if needed)
    return DHCP_HOSTS_FILE

def result_json(data):
    print(json.dumps(data))
    sys.exit(0)

def error_json(msg):
    result_json({"success": False, "error": msg})

# ======================== BINDINGS ========================

def parse_dhcp_hosts(filepath):
    """Parse ISC dhcpd.hosts file into a list of bindings.
    Format: host HOSTNAME {hardware ethernet MAC; fixed-address IP; ...}
    Also handles commented-out lines (starting with #).
    """
    bindings = []
    if not os.path.exists(filepath):
        return bindings
    
    with open(filepath, 'r') as f:
        content = f.read()
    
    # Match host entries (both active and commented)
    pattern = re.compile(
        r'^(\s*#?\s*)'                            # optional comment marker
        r'host\s+(\S+)\s*\{'                      # host HOSTNAME {
        r'[^}]*hardware\s+ethernet\s+([\w:]+)\s*;' # hardware ethernet MAC;
        r'[^}]*fixed-address\s+([\d.]+)\s*;'       # fixed-address IP;
        r'[^}]*\}',                                 # }
        re.MULTILINE
    )
    
    for m in pattern.finditer(content):
        prefix = m.group(1).strip()
        commented = prefix.startswith('#')
        hostname = m.group(2)
        mac = m.group(3).lower()
        ip = m.group(4)
        bindings.append({
            'hostname': hostname,
            'mac': mac,
            'ip': ip,
            'commented': commented
        })
    
    return bindings

def generate_dhcp_hosts(bindings, orig_filepath):
    """Generate ISC dhcpd.hosts file content from bindings list.
    Preserves the group header from original file if present.
    """
    lines = []
    
    # Try to preserve header from original file
    header = ""
    if os.path.exists(orig_filepath):
        with open(orig_filepath, 'r') as f:
            orig = f.read()
        # Extract everything before first 'host' line
        first_host = re.search(r'^#?\s*host\s+', orig, re.MULTILINE)
        if first_host:
            header = orig[:first_host.start()]
    
    if not header.strip():
        # Default header
        header = """group {

  option domain-name "nvidia";
  option domain-name-servers 192.168.58.1;
  option routers 192.168.58.1;

"""
    
    lines.append(header.rstrip() + '\n')
    
    for b in bindings:
        prefix = '#' if b.get('commented') else ''
        line = (
            f'{prefix}host {b["hostname"]} '
            f'{{hardware ethernet {b["mac"]}; '
            f'fixed-address {b["ip"]}; '
            f'option host-name "{b["hostname"]}"; '
            f'option fqdn.hostname "{b["hostname"]}"; '
            f'option cumulus-provision-url "http://{get_server_ip()}/cumulus-ztp.sh";}}'
        )
        lines.append(line)
    
    # Close group if header had one
    if 'group {' in header or 'group{' in header:
        lines.append('\n}')
    
    return '\n'.join(lines) + '\n'

def get_server_ip():
    """Try to determine this server's IP for ZTP URL.
    Falls back to reading from existing dhcpd.conf or hosts file.
    """
    # Try to get from dhcpd.conf
    conf_path = os.environ.get('DHCP_CONF_FILE', '/etc/dhcp/dhcpd.conf')
    if os.path.exists(conf_path):
        with open(conf_path, 'r') as f:
            content = f.read()
        m = re.search(r'cumulus-provision-url\s+"http://([^/]+)/', content)
        if m:
            return m.group(1)
    
    # Try existing hosts file
    hosts_path = get_dhcp_hosts_path()
    if os.path.exists(hosts_path):
        with open(hosts_path, 'r') as f:
            content = f.read()
        m = re.search(r'cumulus-provision-url\s+"http://([^/]+)/', content)
        if m:
            return m.group(1)
    
    # Fallback: try to get our own IP
    try:
        result = subprocess.run(
            ['hostname', '-I'], capture_output=True, text=True, timeout=5
        )
        ips = result.stdout.strip().split()
        if ips:
            return ips[0]
    except:
        pass
    
    return '192.168.58.200'

def action_list_bindings():
    filepath = get_dhcp_hosts_path()
    bindings = parse_dhcp_hosts(filepath)
    result_json({"success": True, "bindings": bindings, "file": filepath})

def action_save_bindings():
    try:
        data = json.loads(POST_DATA)
    except:
        error_json("Invalid JSON data")
    
    bindings = data.get('bindings', [])
    filepath = get_dhcp_hosts_path()
    
    # Generate new content
    content = generate_dhcp_hosts(bindings, filepath)
    
    # Write file (may need sudo)
    try:
        # Try direct write first
        with open(filepath, 'w') as f:
            f.write(content)
    except PermissionError:
        # Use sudo via tee
        try:
            proc = subprocess.run(
                ['sudo', 'tee', filepath],
                input=content, capture_output=True, text=True, timeout=10
            )
            if proc.returncode != 0:
                error_json(f"Failed to write {filepath}: {proc.stderr}")
        except Exception as e:
            error_json(f"Failed to write {filepath}: {e}")
    
    # Restart DHCP
    restart_ok, restart_msg = restart_dhcp()
    
    result_json({
        "success": True,
        "message": f"Saved {len(bindings)} bindings",
        "dhcp_restart": restart_ok,
        "dhcp_message": restart_msg
    })

def restart_dhcp():
    """Restart ISC DHCP server. Returns (success, message)."""
    for svc in ['isc-dhcp-server', 'dhcpd']:
        try:
            result = subprocess.run(
                ['sudo', 'systemctl', 'restart', svc],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0:
                return True, f"{svc} restarted"
        except:
            continue
    
    # Try direct dhcpd restart (Docker)
    try:
        # Kill existing
        subprocess.run(['sudo', 'pkill', '-x', 'dhcpd'], capture_output=True, timeout=5)
        # Find interface
        iface = 'eth0'
        isc_default = '/etc/default/isc-dhcp-server'
        if os.path.exists(isc_default):
            with open(isc_default) as f:
                m = re.search(r'INTERFACES="(\S+)"', f.read())
                if m:
                    iface = m.group(1)
        # Start
        result = subprocess.run(
            ['sudo', 'dhcpd', '-cf', os.environ.get('DHCP_CONF_FILE', '/etc/dhcp/dhcpd.conf'), iface],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            return True, "dhcpd restarted"
        return False, result.stderr.strip()[:200]
    except Exception as e:
        return False, str(e)

# ======================== DISCOVERED ========================

def action_discovered():
    """Cross-reference LLDP/ARP data with DHCP bindings."""
    # Load bindings
    bindings = parse_dhcp_hosts(get_dhcp_hosts_path())
    binding_map = {b['hostname']: b for b in bindings}
    binding_mac_map = {b['mac'].lower(): b for b in bindings}
    
    entries = []
    discovered_hostnames = set()
    
    # Load fabric-scan cache (contains LLDP neighbor + ARP data)
    cache_file = os.path.join(WEB_ROOT, 'fabric-scan-cache.json')
    if not os.path.exists(cache_file):
        cache_file = os.path.join(WEB_ROOT, 'device-cache.json')
    
    scan_data = {}
    if os.path.exists(cache_file):
        try:
            with open(cache_file, 'r') as f:
                scan_data = json.load(f)
        except:
            pass
    
    # Also load devices.yaml for known devices
    devices_file = os.path.join(LLDPQ_DIR, 'devices.yaml')
    known_devices = {}
    if os.path.exists(devices_file):
        try:
            import yaml
            with open(devices_file, 'r') as f:
                dev_data = yaml.safe_load(f)
            devices_section = dev_data.get('devices', dev_data)
            for ip, info in devices_section.items():
                if ip in ('defaults', 'endpoint_hosts'):
                    continue
                hostname = info.get('hostname', str(info)) if isinstance(info, dict) else str(info).split('@')[0].strip()
                known_devices[hostname] = str(ip)
        except:
            pass
    
    # Extract discovered MACs from scan data
    # scan_data may have per-device LLDP neighbor info
    discovered_macs = {}  # hostname -> mac
    
    if isinstance(scan_data, dict):
        for device_name, device_data in scan_data.items():
            if not isinstance(device_data, dict):
                continue
            # Check LLDP neighbors
            neighbors = device_data.get('lldp_neighbors', device_data.get('neighbors', {}))
            if isinstance(neighbors, dict):
                for iface, neigh_list in neighbors.items():
                    if isinstance(neigh_list, list):
                        for n in neigh_list:
                            nh = n.get('hostname', n.get('neighbor', ''))
                            nm = n.get('mac', n.get('chassis_id', '')).lower()
                            if nh and nm:
                                discovered_macs[nh] = nm
                    elif isinstance(neigh_list, dict):
                        nh = neigh_list.get('hostname', neigh_list.get('neighbor', ''))
                        nm = neigh_list.get('mac', neigh_list.get('chassis_id', '')).lower()
                        if nh and nm:
                            discovered_macs[nh] = nm
            
            # Check ARP table
            arp = device_data.get('arp', {})
            if isinstance(arp, dict):
                for ip_addr, arp_entry in arp.items():
                    if isinstance(arp_entry, dict):
                        am = arp_entry.get('mac', '').lower()
                        ah = arp_entry.get('hostname', '')
                        if am and ah:
                            discovered_macs[ah] = am
    
    # Also try device-cache.json format (simpler)
    device_cache = os.path.join(WEB_ROOT, 'device-cache.json')
    if os.path.exists(device_cache) and device_cache != cache_file:
        try:
            with open(device_cache, 'r') as f:
                dc = json.load(f)
            if isinstance(dc, dict):
                for hostname, info in dc.items():
                    if isinstance(info, dict) and 'mac' in info:
                        discovered_macs[hostname] = info['mac'].lower()
        except:
            pass
    
    # Cross-reference: for each binding, check if discovered
    for b in bindings:
        hostname = b['hostname']
        discovered_hostnames.add(hostname)
        disc_mac = discovered_macs.get(hostname, '')
        
        entry = {
            'hostname': hostname,
            'binding_mac': b['mac'],
            'binding_ip': b['ip'],
            'discovered_mac': disc_mac or '',
            'source': 'LLDP/ARP' if disc_mac else '',
            'status': 'missing'  # not discovered
        }
        
        if disc_mac:
            if disc_mac == b['mac'].lower():
                entry['status'] = 'match'
            else:
                entry['status'] = 'mismatch'
        
        entries.append(entry)
    
    # Devices discovered but not in bindings
    for hostname, mac in discovered_macs.items():
        if hostname not in discovered_hostnames:
            entries.append({
                'hostname': hostname,
                'binding_mac': '',
                'binding_ip': '',
                'discovered_mac': mac,
                'source': 'LLDP/ARP',
                'status': 'unbound'
            })
    
    result_json({"success": True, "entries": entries})

# ======================== ZTP SCRIPT ========================

def action_get_ztp_script():
    if not os.path.exists(ZTP_SCRIPT_FILE):
        # Try alternate locations
        for alt in ['/var/www/html/cumulus-ztp.sh', f'{WEB_ROOT}/cumulus-ztp.sh']:
            if os.path.exists(alt):
                with open(alt, 'r') as f:
                    result_json({"success": True, "content": f.read(), "file": alt})
        result_json({"success": True, "content": "", "file": ZTP_SCRIPT_FILE})
    
    with open(ZTP_SCRIPT_FILE, 'r') as f:
        content = f.read()
    result_json({"success": True, "content": content, "file": ZTP_SCRIPT_FILE})

def action_save_ztp_script():
    try:
        data = json.loads(POST_DATA)
    except:
        error_json("Invalid JSON data")
    
    content = data.get('content', '')
    if not content.strip():
        error_json("Script content is empty")
    
    filepath = ZTP_SCRIPT_FILE
    
    try:
        with open(filepath, 'w') as f:
            f.write(content)
        # Ensure executable
        os.chmod(filepath, 0o755)
    except PermissionError:
        try:
            proc = subprocess.run(
                ['sudo', 'tee', filepath],
                input=content, capture_output=True, text=True, timeout=10
            )
            if proc.returncode != 0:
                error_json(f"Failed to write: {proc.stderr}")
            subprocess.run(['sudo', 'chmod', '755', filepath], capture_output=True, timeout=5)
        except Exception as e:
            error_json(str(e))
    
    result_json({"success": True, "message": "ZTP script saved"})

# ======================== DHCP STATUS ========================

def action_dhcp_service_status():
    """Check if DHCP service is running."""
    running = False
    
    # Try systemctl
    try:
        for svc in ['isc-dhcp-server', 'dhcpd']:
            r = subprocess.run(
                ['systemctl', 'is-active', svc],
                capture_output=True, text=True, timeout=5
            )
            if r.stdout.strip() == 'active':
                running = True
                break
    except:
        pass
    
    if not running:
        # Check if dhcpd process is running
        try:
            r = subprocess.run(['pgrep', '-x', 'dhcpd'], capture_output=True, timeout=5)
            running = r.returncode == 0
        except:
            pass
    
    result_json({"success": True, "running": running})

def parse_dhcp_leases(filepath):
    """Parse ISC dhcpd.leases file."""
    leases = []
    if not os.path.exists(filepath):
        return leases
    
    with open(filepath, 'r') as f:
        content = f.read()
    
    # Parse lease blocks
    lease_pattern = re.compile(
        r'lease\s+([\d.]+)\s*\{(.*?)\}',
        re.DOTALL
    )
    
    for m in lease_pattern.finditer(content):
        ip = m.group(1)
        block = m.group(2)
        
        lease = {'ip': ip, 'mac': '', 'hostname': '', 'start': '', 'end': '', 'state': 'active'}
        
        # Parse fields
        mac_m = re.search(r'hardware\s+ethernet\s+([\w:]+)', block)
        if mac_m:
            lease['mac'] = mac_m.group(1).lower()
        
        host_m = re.search(r'client-hostname\s+"([^"]*)"', block)
        if host_m:
            lease['hostname'] = host_m.group(1)
        
        start_m = re.search(r'starts\s+\d+\s+([\d/]+\s+[\d:]+)', block)
        if start_m:
            lease['start'] = start_m.group(1)
        
        end_m = re.search(r'ends\s+\d+\s+([\d/]+\s+[\d:]+)', block)
        if end_m:
            lease['end'] = end_m.group(1)
        
        state_m = re.search(r'binding\s+state\s+(\w+)', block)
        if state_m:
            lease['state'] = state_m.group(1)
        
        leases.append(lease)
    
    # Deduplicate: keep last lease per IP (most recent)
    seen = {}
    for l in leases:
        seen[l['ip']] = l
    
    return sorted(seen.values(), key=lambda x: x['ip'])

def action_dhcp_leases():
    leases = parse_dhcp_leases(DHCP_LEASES_FILE)
    bindings = parse_dhcp_hosts(get_dhcp_hosts_path())
    result_json({
        "success": True,
        "leases": leases,
        "reserved_count": len(bindings)
    })

# ======================== LIST DEVICES ========================

def action_list_devices():
    """List devices from devices.yaml for base config deploy target selection."""
    devices_file = os.path.join(LLDPQ_DIR, 'devices.yaml')
    
    if not os.path.exists(devices_file):
        error_json(f"devices.yaml not found at {devices_file}")
    
    try:
        import yaml
        with open(devices_file, 'r') as f:
            data = yaml.safe_load(f)
    except Exception as e:
        error_json(str(e))
    
    defaults = data.get('defaults', {})
    default_username = defaults.get('username', 'cumulus')
    
    devices_section = data.get('devices', data)
    devices = []
    
    for ip, info in devices_section.items():
        if ip in ('defaults', 'endpoint_hosts'):
            continue
        
        if isinstance(info, dict):
            hostname = info.get('hostname', str(ip))
            username = info.get('username', default_username)
        elif isinstance(info, str):
            parts = info.strip().split('@')
            hostname = parts[0].strip()
            username = default_username
        else:
            hostname = str(info) if info else str(ip)
            username = default_username
        
        devices.append({
            'ip': str(ip),
            'hostname': hostname,
            'username': username
        })
    
    devices.sort(key=lambda x: x['hostname'])
    result_json({"success": True, "devices": devices})

# ======================== BASE CONFIG DEPLOY ========================

# File deployment mapping: source name -> (destination, permissions, extra_dest)
FILE_DEPLOY_MAP = {
    'bash.bashrc': [
        {'dest': '/etc/bash.bashrc', 'mode': '644'},
        {'dest': '/home/cumulus/.bashrc', 'mode': '644'}
    ],
    'motd.sh': [
        {'dest': '/etc/profile.d/motd.sh', 'mode': '755'}
    ],
    'tmux.conf': [
        {'dest': '/etc/tmux.conf', 'mode': '644'}
    ],
    'nanorc': [
        {'dest': '/etc/nanorc', 'mode': '644'}
    ],
    'cmd': [
        {'dest': '/usr/local/bin/cmd', 'mode': '755'}
    ],
    'nvc': [
        {'dest': '/usr/local/bin/nvc', 'mode': '755'}
    ],
    'nvt': [
        {'dest': '/usr/local/bin/nvt', 'mode': '755'}
    ],
    'exa': [
        {'dest': '/usr/bin/exa', 'mode': '755'}
    ],
    'btop': [
        {'dest': '/usr/bin/btop', 'mode': '755'}
    ],
    'iftop': [
        {'dest': '/usr/bin/iftop', 'mode': '755'}
    ]
}

def deploy_to_device(device, files, disable_ztp):
    """Deploy base config files to a single device via SCP + SSH.
    Returns result dict.
    """
    ip = device['ip']
    hostname = device['hostname']
    username = device.get('username', 'cumulus')
    
    result = {
        'ip': ip,
        'hostname': hostname,
        'success': False,
        'message': '',
        'error': ''
    }
    
    ssh_opts = ['-o', 'ConnectTimeout=10', '-o', 'StrictHostKeyChecking=no', '-o', 'BatchMode=yes']
    
    # Step 1: Check connectivity
    try:
        check = subprocess.run(
            ['sudo', '-u', LLDPQ_USER, 'ssh'] + ssh_opts + ['-q', f'{username}@{ip}', 'echo ok'],
            capture_output=True, text=True, timeout=15
        )
        if check.returncode != 0:
            result['error'] = 'SSH connection failed (key not configured?)'
            return result
    except subprocess.TimeoutExpired:
        result['error'] = 'SSH connection timeout'
        return result
    except Exception as e:
        result['error'] = str(e)
        return result
    
    # Step 2: SCP files to /tmp/
    scp_files = []
    for fname in files:
        src = os.path.join(BASE_CONFIG_DIR, fname)
        if os.path.exists(src):
            scp_files.append(src)
    
    if not scp_files:
        result['error'] = 'No source files found'
        return result
    
    try:
        scp_cmd = ['sudo', '-u', LLDPQ_USER, 'scp'] + ssh_opts + scp_files + [f'{username}@{ip}:/tmp/']
        scp_result = subprocess.run(scp_cmd, capture_output=True, text=True, timeout=60)
        if scp_result.returncode != 0:
            result['error'] = f'SCP failed: {scp_result.stderr.strip()[:200]}'
            return result
    except subprocess.TimeoutExpired:
        result['error'] = 'SCP timeout'
        return result
    except Exception as e:
        result['error'] = f'SCP error: {e}'
        return result
    
    # Step 3: SSH to move files to correct locations
    mv_commands = []
    for fname in files:
        if fname in FILE_DEPLOY_MAP:
            for target in FILE_DEPLOY_MAP[fname]:
                dest = target['dest']
                mode = target['mode']
                mv_commands.append(f'sudo cp /tmp/{fname} {dest} && sudo chmod {mode} {dest}')
    
    if disable_ztp:
        mv_commands.append('sudo ztp -d 2>/dev/null || true')
    
    # Cleanup tmp files
    cleanup = ' '.join(f'/tmp/{fname}' for fname in files)
    mv_commands.append(f'rm -f {cleanup}')
    
    remote_cmd = ' && '.join(mv_commands)
    
    try:
        ssh_cmd = ['sudo', '-u', LLDPQ_USER, 'ssh'] + ssh_opts + [f'{username}@{ip}', remote_cmd]
        ssh_result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=30)
        if ssh_result.returncode != 0:
            result['error'] = f'Remote install failed: {ssh_result.stderr.strip()[:200]}'
            return result
    except subprocess.TimeoutExpired:
        result['error'] = 'SSH command timeout'
        return result
    except Exception as e:
        result['error'] = f'SSH error: {e}'
        return result
    
    result['success'] = True
    result['message'] = f'{len(files)} files deployed'
    return result

def action_deploy_base_config():
    try:
        data = json.loads(POST_DATA)
    except:
        error_json("Invalid JSON data")
    
    files = data.get('files', [])
    devices = data.get('devices', [])
    disable_ztp = data.get('disable_ztp', False)
    
    if not files:
        error_json("No files selected")
    if not devices:
        error_json("No devices selected")
    
    # Validate files exist
    for f in files:
        if f not in FILE_DEPLOY_MAP:
            error_json(f"Unknown file: {f}")
    
    # Deploy in parallel (20 workers max)
    results = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {
            executor.submit(deploy_to_device, dev, files, disable_ztp): dev
            for dev in devices
        }
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as e:
                dev = futures[future]
                results.append({
                    'ip': dev['ip'],
                    'hostname': dev['hostname'],
                    'success': False,
                    'error': str(e)
                })
    
    # Sort by hostname
    results.sort(key=lambda x: x['hostname'])
    
    ok = sum(1 for r in results if r['success'])
    fail = len(results) - ok
    
    result_json({
        "success": True,
        "results": results,
        "summary": {"ok": ok, "fail": fail, "total": len(results)}
    })

# ======================== ROUTER ========================

if ACTION == 'list-bindings':
    action_list_bindings()
elif ACTION == 'save-bindings':
    action_save_bindings()
elif ACTION == 'discovered':
    action_discovered()
elif ACTION == 'get-ztp-script':
    action_get_ztp_script()
elif ACTION == 'save-ztp-script':
    action_save_ztp_script()
elif ACTION == 'dhcp-service-status':
    action_dhcp_service_status()
elif ACTION == 'dhcp-leases':
    action_dhcp_leases()
elif ACTION == 'list-devices':
    action_list_devices()
elif ACTION == 'deploy-base-config':
    action_deploy_base_config()
else:
    error_json(f"Unknown action: {ACTION}")

PYTHON_SCRIPT
