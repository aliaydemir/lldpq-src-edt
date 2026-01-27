#!/bin/bash
# Fabric Scan Cron Job - runs diff playbook daily
# Scheduled: 03:33

source /etc/lldpq.conf 2>/dev/null

CACHE_FILE="$WEB_ROOT/fabric-scan-cache.json"

cd "$ANSIBLE_DIR" || exit 1

# Run diff playbook and capture output
OUTPUT=$(ansible-playbook playbooks/diff_switch_configs.yaml 2>&1)

# Parse pending devices from output
PENDING=""
IN_SECTION=false
while IFS= read -r line; do
    if [[ "$line" == *"SWITCHES WITH CHANGES"* ]]; then
        IN_SECTION=true
        continue
    fi
    if [[ "$IN_SECTION" == true ]]; then
        if [[ "$line" == *"PLAY RECAP"* ]]; then
            break
        fi
        # Extract hostname from lines like "✗ lsw-3na-05-29: 2 changes"
        if [[ "$line" =~ ([a-z]{2,4}-[a-z0-9-]+):[[:space:]]*[0-9]+[[:space:]]+change ]]; then
            HOSTNAME="${BASH_REMATCH[1]}"
            [[ -n "$PENDING" ]] && PENDING="$PENDING,"
            PENDING="$PENDING\"$HOSTNAME\""
        fi
    fi
done <<< "$OUTPUT"

# Write JSON cache
TIMESTAMP=$(date +%s)000
echo "{\"timestamp\":$TIMESTAMP,\"pendingDevices\":[$PENDING]}" > "$CACHE_FILE"
