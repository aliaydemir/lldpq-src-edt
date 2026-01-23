#!/usr/bin/env bash
# ansible-api.sh - Ansible Config Editor API
# Called by nginx fcgiwrap
#
# Actions:
#   - list: List all editable files (host_vars, group_vars, playbooks)
#   - read: Read a specific file
#   - write: Write to a specific file
#   - diff: Run ansible diff playbook
#   - deploy: Run ansible deploy playbook

# Load config with fallback
source /etc/lldpq.conf 2>/dev/null || true
LLDPQ_DIR="${LLDPQ_DIR:-$HOME/lldpq}"

# Ansible directory (relative to lldpq-src parent)
# Adjust this path based on your installation
ANSIBLE_DIR="${ANSIBLE_DIR:-$(dirname "$LLDPQ_DIR")}"

# Setup ansible environment for www-data user
export ANSIBLE_HOME="/tmp/ansible-www"
export HOME="$ANSIBLE_HOME"
export ANSIBLE_LOCAL_TEMP="/tmp/ansible-tmp"
export ANSIBLE_CACHE_PLUGIN_CONNECTION="/tmp/ansible-cache"
mkdir -p "$ANSIBLE_HOME" "$ANSIBLE_LOCAL_TEMP" "$ANSIBLE_CACHE_PLUGIN_CONNECTION" 2>/dev/null || true
chmod 777 "$ANSIBLE_HOME" "$ANSIBLE_LOCAL_TEMP" "$ANSIBLE_CACHE_PLUGIN_CONNECTION" 2>/dev/null || true

# Parse query string
parse_query() {
    local query="$QUERY_STRING"
    # Extract action
    ACTION=$(echo "$query" | sed -n 's/.*action=\([^&]*\).*/\1/p')
    # Extract file parameter
    FILE=$(echo "$query" | sed -n 's/.*file=\([^&]*\).*/\1/p' | python3 -c "import sys, urllib.parse; print(urllib.parse.unquote(sys.stdin.read().strip()))")
    # Extract host parameter
    HOST=$(echo "$query" | sed -n 's/.*host=\([^&]*\).*/\1/p')
}

# Output JSON response
json_response() {
    echo "Content-Type: application/json"
    echo "Access-Control-Allow-Origin: *"
    echo ""
    echo "$1"
}

# Security: validate file path is within allowed directories
validate_path() {
    local file="$1"
    local realpath=$(realpath -m "$ANSIBLE_DIR/$file" 2>/dev/null)
    local ansible_realpath=$(realpath "$ANSIBLE_DIR" 2>/dev/null)
    
    # Check if path is within ansible directory
    if [[ "$realpath" != "$ansible_realpath"* ]]; then
        return 1
    fi
    
    # Block dangerous/binary file types
    if [[ "$file" =~ \.(pyc|so|exe|dll|bin|class)$ ]]; then
        return 1
    fi
    
    # Block system files
    if [[ "$file" =~ ^\.git/ ]] || [[ "$file" =~ ^\.vscode/ ]] || [[ "$file" =~ ^\.crossnote/ ]] || [[ "$file" =~ __pycache__/ ]]; then
        return 1
    fi
    
    return 0
}

# List editable files
list_files() {
    # Cache file for faster subsequent loads
    local cache_file="/tmp/ansible-files-cache.txt"
    local cache_age=60  # seconds
    
    # Check if cache is fresh
    if [ -f "$cache_file" ] && [ $(($(date +%s) - $(stat -c %Y "$cache_file" 2>/dev/null || echo 0))) -lt $cache_age ]; then
        local files_json=$(cat "$cache_file")
    else
        # Find all files quickly using find with optimized options
        local files_json=""
        if [ -d "$ANSIBLE_DIR" ]; then
            files_json=$(find "$ANSIBLE_DIR" -type f \
                ! -path "*/.git/*" \
                ! -path "*/.vscode/*" \
                ! -path "*/.crossnote/*" \
                ! -path "*/__pycache__/*" \
                ! -path "*/.ansible/*" \
                ! -name "*.pyc" \
                ! -name "*.swp" \
                ! -name "*~" \
                2>/dev/null | sed "s|^$ANSIBLE_DIR/||" | sort | python3 -c 'import sys,json; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))')
            echo "$files_json" > "$cache_file"
        else
            files_json="[]"
        fi
    fi
    
    # Get groups from inventory/hosts file
    local groups=()
    if [ -f "$ANSIBLE_DIR/inventory/hosts" ]; then
        while IFS= read -r line; do
            # Skip comments and empty lines
            if [[ "$line" =~ ^[[:space:]]*# ]] || [[ "$line" =~ ^[[:space:]]*$ ]]; then
                continue
            fi
            
            # Group header [groupname]
            if [[ "$line" =~ ^\[([^]]+)\] ]]; then
                current_group="${BASH_REMATCH[1]}"
                groups+=("$current_group")
            fi
        done < "$ANSIBLE_DIR/inventory/hosts"
    fi
    
    # Get individual hosts from host_vars directory
    local hosts=()
    if [ -d "$ANSIBLE_DIR/inventory/host_vars" ]; then
        while IFS= read -r -d '' file; do
            # Extract hostname from filename (without extension)
            local hostname=$(basename "$file")
            hostname="${hostname%.yaml}"
            hostname="${hostname%.yml}"
            hosts+=("$hostname")
        done < <(find "$ANSIBLE_DIR/inventory/host_vars" -maxdepth 1 -type f \( -name "*.yaml" -o -name "*.yml" \) -print0 2>/dev/null)
    fi
    
    # Build JSON for groups and hosts (files_json already built above with caching)
    local groups_json=$(printf '%s\n' "${groups[@]}" | sort -u | python3 -c 'import sys,json; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))')
    local hosts_json=$(printf '%s\n' "${hosts[@]}" | sort -u | python3 -c 'import sys,json; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))')
    
    json_response "{\"success\": true, \"files\": $files_json, \"groups\": $groups_json, \"hosts\": $hosts_json}"
}

# Read file
read_file() {
    local file="$1"
    
    if ! validate_path "$file"; then
        json_response '{"success": false, "error": "Invalid file path"}'
        return
    fi
    
    local full_path="$ANSIBLE_DIR/$file"
    
    if [ ! -f "$full_path" ]; then
        json_response '{"success": false, "error": "File not found"}'
        return
    fi
    
    local content=$(cat "$full_path" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))')
    json_response "{\"success\": true, \"content\": $content}"
}

# Write file
write_file() {
    local file="$1"
    
    if ! validate_path "$file"; then
        json_response '{"success": false, "error": "Invalid file path"}'
        return
    fi
    
    local full_path="$ANSIBLE_DIR/$file"
    
    # Read POST data
    local post_data
    if [ -n "$CONTENT_LENGTH" ] && [ "$CONTENT_LENGTH" -gt 0 ] 2>/dev/null; then
        post_data=$(dd bs=1 count="$CONTENT_LENGTH" 2>/dev/null)
    else
        post_data=$(cat)
    fi
    
    # Extract content from JSON
    local content=$(echo "$post_data" | python3 -c '
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get("content", ""))
except:
    print("")
' 2>/dev/null)
    
    if [ -z "$content" ]; then
        json_response '{"success": false, "error": "No content provided"}'
        return
    fi
    
    # Backup existing file
    if [ -f "$full_path" ]; then
        cp "$full_path" "${full_path}.bak"
    fi
    
    # Write new content
    echo "$content" > "$full_path"
    
    if [ $? -eq 0 ]; then
        json_response '{"success": true, "message": "File saved successfully"}'
    else
        json_response '{"success": false, "error": "Failed to write file"}'
    fi
}

# Delete file
delete_file() {
    local file="$1"
    
    if ! validate_path "$file"; then
        json_response '{"success": false, "error": "Invalid file path"}'
        return
    fi
    
    local full_path="$ANSIBLE_DIR/$file"
    
    if [ ! -f "$full_path" ]; then
        json_response '{"success": false, "error": "File not found"}'
        return
    fi
    
    rm -f "$full_path" 2>/dev/null
    
    if [ $? -eq 0 ]; then
        json_response '{"success": true}'
    else
        json_response '{"success": false, "error": "Failed to delete file"}'
    fi
}

# Run ansible diff
run_diff() {
    local host="$1"
    
    if [ -z "$host" ]; then
        json_response '{"success": false, "error": "No host specified"}'
        return
    fi
    
    # Sanitize host name
    host=$(echo "$host" | tr -cd '[:alnum:]-_')
    
    cd "$ANSIBLE_DIR" || {
        json_response '{"success": false, "error": "Cannot access ansible directory"}'
        return
    }
    
    # Run diff playbook
    local output
    output=$(ansible-playbook playbooks/diff_switch_configs.yaml -l "$host" 2>&1)
    local exit_code=$?
    
    # Escape output for JSON
    local output_json=$(echo "$output" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))')
    
    if [ $exit_code -eq 0 ]; then
        json_response "{\"success\": true, \"output\": $output_json}"
    else
        json_response "{\"success\": false, \"output\": $output_json, \"error\": \"Diff failed with exit code $exit_code\"}"
    fi
}

# Run ansible deploy
run_deploy() {
    local host="$1"
    
    if [ -z "$host" ]; then
        json_response '{"success": false, "error": "No host specified"}'
        return
    fi
    
    # Sanitize host name
    host=$(echo "$host" | tr -cd '[:alnum:]-_')
    
    cd "$ANSIBLE_DIR" || {
        json_response '{"success": false, "error": "Cannot access ansible directory"}'
        return
    }
    
    # Run deploy playbook
    local output
    output=$(ansible-playbook playbooks/deploy_switch_configs.yaml -l "$host" 2>&1)
    local exit_code=$?
    
    # Escape output for JSON
    local output_json=$(echo "$output" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))')
    
    if [ $exit_code -eq 0 ]; then
        json_response "{\"success\": true, \"output\": $output_json}"
    else
        json_response "{\"success\": false, \"output\": $output_json, \"error\": \"Deploy failed with exit code $exit_code\"}"
    fi
}

# Run ansible generate configs
run_generate() {
    local host="$1"
    
    cd "$ANSIBLE_DIR" || {
        json_response '{"success": false, "error": "Cannot access ansible directory"}'
        return
    }
    
    # Run generate playbook
    local output
    if [ -n "$host" ] && [ "$host" != "all" ]; then
        # Sanitize host name
        host=$(echo "$host" | tr -cd '[:alnum:]-_')
        output=$(ansible-playbook playbooks/generate_switch_nvue_yaml_configs.yaml -l "$host" 2>&1)
    else
        output=$(ansible-playbook playbooks/generate_switch_nvue_yaml_configs.yaml 2>&1)
    fi
    local exit_code=$?
    
    # Escape output for JSON
    local output_json=$(echo "$output" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))')
    
    if [ $exit_code -eq 0 ]; then
        json_response "{\"success\": true, \"output\": $output_json}"
    else
        json_response "{\"success\": false, \"output\": $output_json, \"error\": \"Generate failed with exit code $exit_code\"}"
    fi
}

# Git functions
git_commit_push() {
    local message="$1"
    
    if [ -z "$message" ]; then
        json_response '{"success": false, "error": "No commit message provided"}'
        return
    fi
    
    cd "$ANSIBLE_DIR" || {
        json_response '{"success": false, "error": "Cannot access ansible directory"}'
        return
    }
    
    # Fix ownership and add safe directory
    export HOME="$ANSIBLE_HOME"
    git config --global user.email "ansible-editor@lldpq.local" 2>/dev/null || true
    git config --global user.name "Ansible Editor" 2>/dev/null || true
    git config --global --add safe.directory "$ANSIBLE_DIR" 2>/dev/null || true
    
    # Stage all changes
    git add -A 2>&1
    
    # Check if there are changes to commit
    if git diff --cached --quiet; then
        json_response '{"success": true, "output": "Nothing to commit - working tree clean"}'
        return
    fi
    
    # Commit and push
    local output
    output=$(git commit -m "$message" 2>&1)
    local commit_code=$?
    
    if [ $commit_code -eq 0 ]; then
        # Try to push
        local push_output
        push_output=$(git push 2>&1)
        local push_code=$?
        output="$output\n$push_output"
        
        if [ $push_code -eq 0 ]; then
            local output_json=$(echo -e "$output" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))')
            json_response "{\"success\": true, \"output\": $output_json}"
        else
            local output_json=$(echo -e "$output" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))')
            json_response "{\"success\": false, \"output\": $output_json, \"error\": \"Push failed\"}"
        fi
    else
        local output_json=$(echo "$output" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))')
        json_response "{\"success\": false, \"output\": $output_json, \"error\": \"Commit failed\"}"
    fi
}

git_pull() {
    cd "$ANSIBLE_DIR" || {
        json_response '{"success": false, "error": "Cannot access ansible directory"}'
        return
    }
    
    export GIT_CONFIG_GLOBAL=/tmp/ansible-gitconfig
    git config --global --add safe.directory "$ANSIBLE_DIR" 2>/dev/null || true
    
    local output
    output=$(git pull 2>&1)
    local exit_code=$?
    
    local output_json=$(echo "$output" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))')
    
    if [ $exit_code -eq 0 ]; then
        json_response "{\"success\": true, \"output\": $output_json}"
    else
        json_response "{\"success\": false, \"output\": $output_json, \"error\": \"Git pull failed\"}"
    fi
}

git_status() {
    cd "$ANSIBLE_DIR" || {
        json_response '{"success": false, "error": "Cannot access ansible directory"}'
        return
    }
    
    export GIT_CONFIG_GLOBAL=/tmp/ansible-gitconfig
    git config --global --add safe.directory "$ANSIBLE_DIR" 2>/dev/null || true
    
    local output
    output=$(git status 2>&1)
    local output_json=$(echo "$output" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))')
    
    json_response "{\"success\": true, \"output\": $output_json}"
}

git_log() {
    cd "$ANSIBLE_DIR" || {
        json_response '{"success": false, "error": "Cannot access ansible directory"}'
        return
    }
    
    export GIT_CONFIG_GLOBAL=/tmp/ansible-gitconfig
    git config --global --add safe.directory "$ANSIBLE_DIR" 2>/dev/null || true
    
    local output
    # Pretty format with fixed widths: hash | date | relative time | author | message
    output=$(git --no-pager log --graph --decorate=no --date=format:'%Y-%m-%d %H:%M' --pretty=format:'%<(8,trunc)%h │ %<(16)%ad │ %<(14)%cr │ %<(12,trunc)%an │ %s' -n 30 2>&1)
    local output_json=$(echo "$output" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))')
    
    json_response "{\"success\": true, \"output\": $output_json}"
}

git_diff() {
    cd "$ANSIBLE_DIR" || {
        json_response '{"success": false, "error": "Cannot access ansible directory"}'
        return
    }
    
    export GIT_CONFIG_GLOBAL=/tmp/ansible-gitconfig
    git config --global --add safe.directory "$ANSIBLE_DIR" 2>/dev/null || true
    
    local output
    output=$(git diff 2>&1)
    local output_json=$(echo "$output" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))')
    
    json_response "{\"success\": true, \"output\": $output_json}"
}

# Main
parse_query

# Get commit message from POST data if present
if [ "$ACTION" = "git-commit" ]; then
    if [ -n "$CONTENT_LENGTH" ] && [ "$CONTENT_LENGTH" -gt 0 ] 2>/dev/null; then
        POST_DATA=$(dd bs=1 count="$CONTENT_LENGTH" 2>/dev/null)
        MESSAGE=$(echo "$POST_DATA" | sed -n 's/.*message=\([^&]*\).*/\1/p' | python3 -c "import sys, urllib.parse; print(urllib.parse.unquote(sys.stdin.read().strip()))")
    fi
fi

case "$ACTION" in
    list)
        list_files
        ;;
    read)
        read_file "$FILE"
        ;;
    write)
        write_file "$FILE"
        ;;
    delete)
        delete_file "$FILE"
        ;;
    generate)
        run_generate "$HOST"
        ;;
    diff)
        run_diff "$HOST"
        ;;
    deploy)
        run_deploy "$HOST"
        ;;
    git-commit)
        git_commit_push "$MESSAGE"
        ;;
    git-pull)
        git_pull
        ;;
    git-status)
        git_status
        ;;
    git-log)
        git_log
        ;;
    git-diff)
        git_diff
        ;;
    image)
        # Serve image file
        FILE=$(echo "$QUERY_STRING" | sed -n 's/.*file=\([^&]*\).*/\1/p' | python3 -c "import sys, urllib.parse; print(urllib.parse.unquote(sys.stdin.read().strip()))")
        FULL_PATH="$ANSIBLE_DIR/$FILE"
        if [ -f "$FULL_PATH" ]; then
            EXT="${FILE##*.}"
            case "$EXT" in
                png) MIME="image/png" ;;
                jpg|jpeg) MIME="image/jpeg" ;;
                gif) MIME="image/gif" ;;
                svg) MIME="image/svg+xml" ;;
                *) MIME="application/octet-stream" ;;
            esac
            echo "Content-Type: $MIME"
            echo ""
            cat "$FULL_PATH"
        else
            echo "Status: 404 Not Found"
            echo "Content-Type: text/plain"
            echo ""
            echo "Image not found"
        fi
        exit 0
        ;;
    *)
        json_response '{"success": false, "error": "Unknown action"}'
        ;;
esac
