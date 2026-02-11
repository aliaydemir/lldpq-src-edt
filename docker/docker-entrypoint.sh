#!/bin/bash
# LLDPq Docker Entrypoint
# Self-healing startup: ensures all required files/dirs exist with correct permissions
# Starts: nginx + fcgiwrap + cron

set -e

echo "╔══════════════════════════════════════╗"
echo "║      LLDPq Network Monitoring        ║"
echo "║      Docker Container v$(cat /var/www/html/VERSION 2>/dev/null || echo '?')        ║"
echo "╚══════════════════════════════════════╝"

# ─── VRF Setup (Cumulus switch only) ───
# If mgmt VRF exists (Cumulus Linux), route outbound traffic through it
if ip vrf show mgmt >/dev/null 2>&1; then
    MGMT_TABLE=$(ip vrf show mgmt 2>/dev/null | awk '/mgmt/{print $2}')
    if [ -n "$MGMT_TABLE" ]; then
        ip rule add pref 100 table "$MGMT_TABLE" 2>/dev/null || true
        echo "✓ mgmt VRF detected (table $MGMT_TABLE) — outbound via mgmt"
    fi
fi

# ─── SSH Key Setup ───
# Support mounting host SSH keys as read-only volume
if [ -d /home/lldpq/.ssh-mount ]; then
    # Copy mounted keys (read-only mount → writable .ssh)
    cp -n /home/lldpq/.ssh-mount/id_* /home/lldpq/.ssh/ 2>/dev/null || true
    cp -n /home/lldpq/.ssh-mount/known_hosts /home/lldpq/.ssh/ 2>/dev/null || true
    chown -R lldpq:lldpq /home/lldpq/.ssh/
    chmod 700 /home/lldpq/.ssh
    chmod 600 /home/lldpq/.ssh/id_* 2>/dev/null || true
fi

if [ -f /home/lldpq/.ssh/id_rsa ] || [ -f /home/lldpq/.ssh/id_ed25519 ]; then
    echo "✓ SSH keys found"
else
    echo "⚠ No SSH keys — use SSH Setup from web UI, or mount keys:"
    echo "  docker run ... -v ~/.ssh:/home/lldpq/.ssh-mount:ro ..."
fi

# ─── Ansible Directory Setup ───
if [ -n "$ANSIBLE_DIR" ] && [ "$ANSIBLE_DIR" != "NoNe" ] && [ -d "$ANSIBLE_DIR" ]; then
    sed -i "s|^ANSIBLE_DIR=.*|ANSIBLE_DIR=$ANSIBLE_DIR|" /etc/lldpq.conf
    chown -R lldpq:www-data "$ANSIBLE_DIR" 2>/dev/null || true
    echo "✓ Ansible directory: $ANSIBLE_DIR"
else
    echo "  Ansible: not configured (Ansible menu disabled)"
fi

# ─── devices.yaml Setup ───
if [ -f /home/lldpq/lldpq/devices.yaml ]; then
    chown lldpq:www-data /home/lldpq/lldpq/devices.yaml
    chmod 664 /home/lldpq/lldpq/devices.yaml
    echo "✓ devices.yaml loaded ($(grep -c '^\s*[0-9]' /home/lldpq/lldpq/devices.yaml 2>/dev/null || echo 0) devices)"
else
    echo "⚠ No devices.yaml found"
    echo "  Mount with: -v /path/to/devices.yaml:/home/lldpq/lldpq/devices.yaml"
fi

# ─── Topology files Setup ───
# Real files in web root (editable from web UI), symlinks in lldpq dir (used by scripts)
for f in topology.dot topology_config.yaml; do
    # If file exists in web root (baked in or volume-mounted), ensure symlink
    if [ -f "/var/www/html/$f" ] && [ ! -L "/home/lldpq/lldpq/$f" ]; then
        rm -f "/home/lldpq/lldpq/$f"
        ln -sf "/var/www/html/$f" "/home/lldpq/lldpq/$f"
    fi
    # If file only exists in lldpq dir (not a symlink), move to web root
    if [ -f "/home/lldpq/lldpq/$f" ] && [ ! -L "/home/lldpq/lldpq/$f" ] && [ ! -f "/var/www/html/$f" ]; then
        mv "/home/lldpq/lldpq/$f" "/var/www/html/$f"
        ln -sf "/var/www/html/$f" "/home/lldpq/lldpq/$f"
    fi
    if [ -f "/var/www/html/$f" ]; then
        chown lldpq:www-data "/var/www/html/$f"
        chmod 664 "/var/www/html/$f"
    fi
done
echo "✓ Topology files ready"

# ─── Persistent data directories ───
for dir in /home/lldpq/lldpq/monitor-results \
           /home/lldpq/lldpq/monitor-results/fabric-tables \
           /var/www/html/hstr \
           /var/www/html/configs \
           /var/www/html/monitor-results \
           /var/www/html/topology; do
    mkdir -p "$dir"
    chown -R lldpq:www-data "$dir"
    chmod 775 "$dir"
done

# Symlink monitor-results to web root
ln -sf /home/lldpq/lldpq/monitor-results /var/www/html/monitor-results 2>/dev/null || true

# ─── Cache files (assets.sh, fabric-scan.sh need these writable by lldpq) ───
for f in /var/www/html/device-cache.json /var/www/html/fabric-scan-cache.json; do
    [ ! -f "$f" ] && echo '{}' > "$f"
    chown lldpq:www-data "$f"
    chmod 664 "$f"
done

# ─── Auth Setup (self-healing: recreate if missing) ───
if [ ! -f /etc/lldpq-users.conf ]; then
    echo "  Creating default users file..."
    ADMIN_HASH=$(echo -n "admin" | openssl dgst -sha256 | awk '{print $2}')
    OPERATOR_HASH=$(echo -n "operator" | openssl dgst -sha256 | awk '{print $2}')
    echo "admin:$ADMIN_HASH:admin" > /etc/lldpq-users.conf
    echo "operator:$OPERATOR_HASH:operator" >> /etc/lldpq-users.conf
    echo "  ⚠ Default credentials: admin/admin, operator/operator"
fi
chmod 600 /etc/lldpq-users.conf
chown www-data:www-data /etc/lldpq-users.conf
mkdir -p /var/lib/lldpq/sessions
chown -R www-data:www-data /var/lib/lldpq
chmod 700 /var/lib/lldpq/sessions
echo "✓ Authentication ready"

# ─── Cron Setup ───
# lldpq = assets.sh + check-lldp.sh + monitor.sh + fabric-scan.sh + alerts
# lldpq-trigger = web UI refresh buttons (Refresh Assets, Refresh LLDP, etc.)
cat > /etc/cron.d/lldpq << 'CRON'
# LLDPq full run (assets + lldp + monitor + alerts) - every 5 minutes
*/5 * * * * lldpq /usr/local/bin/lldpq > /dev/null 2>&1
# Web trigger daemon (handles Refresh buttons from UI) - every minute
* * * * * lldpq /usr/local/bin/lldpq-trigger > /dev/null 2>&1
# Fabric scan (topology data for search) - every minute
* * * * * lldpq cd /home/lldpq/lldpq && ./fabric-scan.sh > /dev/null 2>&1
# Config backup - every 12 hours
0 */12 * * * lldpq /usr/local/bin/get-conf > /dev/null 2>&1
CRON
chmod 644 /etc/cron.d/lldpq

# ─── DHCP Server Setup ───
# Ensure DHCP directories and files exist
mkdir -p /var/lib/dhcp /etc/dhcp
touch /var/lib/dhcp/dhcpd.leases
[ ! -f /etc/dhcp/dhcpd.hosts ] && touch /etc/dhcp/dhcpd.hosts
chown lldpq:www-data /etc/dhcp/dhcpd.hosts
chmod 664 /etc/dhcp/dhcpd.hosts

# ZTP script in web root (writable by lldpq)
if [ ! -f /var/www/html/cumulus-ztp.sh ]; then
    echo '#!/bin/bash' > /var/www/html/cumulus-ztp.sh
    echo '# CUMULUS-AUTOPROVISIONING' >> /var/www/html/cumulus-ztp.sh
    echo '# Edit this script from the Provision page' >> /var/www/html/cumulus-ztp.sh
fi
chown lldpq:www-data /var/www/html/cumulus-ztp.sh
chmod 775 /var/www/html/cumulus-ztp.sh

# Base config files permissions
if [ -d /home/lldpq/lldpq/sw-base ]; then
    chown -R lldpq:lldpq /home/lldpq/lldpq/sw-base
    chmod 755 /home/lldpq/lldpq/sw-base
    find /home/lldpq/lldpq/sw-base -type f -exec chmod 644 {} \;
    # Binaries and scripts need execute
    for f in btop exa iftop cmd nvc nvt motd.sh; do
        [ -f "/home/lldpq/lldpq/sw-base/$f" ] && chmod 755 "/home/lldpq/lldpq/sw-base/$f"
    done
    echo "✓ sw-base files ready ($(ls /home/lldpq/lldpq/sw-base/ 2>/dev/null | wc -l) files)"
fi

# Start DHCP server if config exists
if [ -f /etc/dhcp/dhcpd.conf ]; then
    # Determine interface
    DHCP_IFACE="eth0"
    if [ -f /etc/default/isc-dhcp-server ]; then
        DHCP_IFACE=$(grep '^INTERFACES=' /etc/default/isc-dhcp-server 2>/dev/null | sed 's/INTERFACES="//;s/"//' || echo "eth0")
    fi
    # Start dhcpd
    dhcpd -cf /etc/dhcp/dhcpd.conf "$DHCP_IFACE" 2>/dev/null && echo "✓ DHCP server started (interface: $DHCP_IFACE)" || echo "  DHCP: not started (no config or interface issue)"
else
    echo "  DHCP: no /etc/dhcp/dhcpd.conf (configure from Provision page)"
fi

# ─── Start Services ───
echo ""
echo "Starting services..."

# Start cron
service cron start > /dev/null 2>&1
echo "  ✓ cron"

# Start fcgiwrap (CGI scripts for web API)
/usr/sbin/fcgiwrap -f -s unix:/var/run/fcgiwrap.socket &
sleep 0.5
chown www-data:www-data /var/run/fcgiwrap.socket
chmod 660 /var/run/fcgiwrap.socket
echo "  ✓ fcgiwrap"

# Start nginx (foreground - keeps container alive)
echo "  ✓ nginx (port 80)"
echo ""
echo "LLDPq is ready! Access: http://localhost:${LLDPQ_PORT:-80}"
echo ""

exec nginx -g 'daemon off;'
