#!/usr/bin/env bash
# edit-devices.sh - Read/Write devices.yaml via CGI
# Called by nginx fcgiwrap

# Load config with fallback
source /etc/lldpq.conf 2>/dev/null || true
LLDPQ_USER="${LLDPQ_USER:-$(whoami)}"
LLDPQ_HOME="${LLDPQ_DIR:-$HOME/lldpq}"

# devices.yaml location
DEVICES_FILE="$LLDPQ_HOME/devices.yaml"

# Read request method
METHOD="${REQUEST_METHOD:-GET}"

# Output headers
echo "Content-Type: application/json"
echo ""

if [ "$METHOD" = "GET" ]; then
    # Read and return devices.yaml content
    if [ -f "$DEVICES_FILE" ]; then
        # Escape content for JSON (read as LLDPQ_USER in case of permission issues)
        CONTENT=$( (sudo -u "$LLDPQ_USER" cat "$DEVICES_FILE" 2>/dev/null || cat "$DEVICES_FILE") | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))')
        echo "{\"success\": true, \"content\": $CONTENT}"
    else
        echo "{\"success\": false, \"error\": \"File not found: $DEVICES_FILE\"}"
    fi
    
elif [ "$METHOD" = "POST" ]; then
    # Read POST data from stdin
    if [ -n "$CONTENT_LENGTH" ] && [ "$CONTENT_LENGTH" -gt 0 ] 2>/dev/null; then
        POST_DATA=$(dd bs=1 count="$CONTENT_LENGTH" 2>/dev/null)
    else
        POST_DATA=$(cat)
    fi
    
    # Extract content from JSON using Python
    CONTENT=$(echo "$POST_DATA" | python3 -c '
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get("content", ""))
except:
    print("")
' 2>/dev/null)
    
    if [ -n "$CONTENT" ]; then
        # Validate YAML syntax before saving
        VALIDATION=$(echo "$CONTENT" | python3 -c '
import sys, yaml
try:
    yaml.safe_load(sys.stdin)
    print("valid")
except yaml.YAMLError as e:
    print(f"YAML Error: {str(e)[:100]}")
except Exception as e:
    print(f"Error: {str(e)[:100]}")
' 2>/dev/null)
        
        if [ "$VALIDATION" = "valid" ]; then
            # Create backup before writing (as LLDPQ_USER who owns the file)
            if [ -f "$DEVICES_FILE" ]; then
                sudo -u "$LLDPQ_USER" cp "$DEVICES_FILE" "${DEVICES_FILE}.bak" 2>/dev/null || cp "$DEVICES_FILE" "${DEVICES_FILE}.bak"
            fi
            
            # Write new content (as LLDPQ_USER who owns the file)
            echo "$CONTENT" | sudo -u "$LLDPQ_USER" tee "$DEVICES_FILE" > /dev/null 2>&1
            
            if [ $? -eq 0 ]; then
                echo "{\"success\": true, \"message\": \"devices.yaml saved successfully\"}"
            else
                echo "{\"success\": false, \"error\": \"Failed to write file\"}"
            fi
        else
            echo "{\"success\": false, \"error\": \"$VALIDATION\"}"
        fi
    else
        echo "{\"success\": false, \"error\": \"No content provided\"}"
    fi
else
    echo "{\"success\": false, \"error\": \"Invalid method\"}"
fi
