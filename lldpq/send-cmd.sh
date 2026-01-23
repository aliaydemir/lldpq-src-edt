#!/usr/bin/env bash
# LLDPq Send Commands - Execute commands on network devices
# Copyright (c) 2024 LLDPq Project - Licensed under MIT License

SCRIPT_DIR=$(dirname "$(readlink -f "$BASH_SOURCE")")

show_help() {
    cat << EOF
LLDPq Send Commands - Execute commands on network devices

Usage: send-cmd.sh [options]

Options:
  -c <cmd>  Execute command on all devices (can use multiple times)
  -h        Show this help message
  -l        List available commands (from commands file)
  -e        Edit commands file

Description:
  Reads commands from '$SCRIPT_DIR/commands' file.
  Lines starting with # are ignored (commented out).
  Executes uncommented commands on all devices in devices.yaml.

Examples:
  send-cmd                           # Run all uncommented commands from file
  send-cmd -c "nv show system"       # Run single command on all devices
  send-cmd -c "uptime" -c "hostname" # Run multiple commands
  send-cmd -l                        # List commands in file
  send-cmd -e                        # Edit commands file

EOF
    exit 0
}

# Parse arguments
cli_commands=()
while getopts "hlec:" opt; do
    case $opt in
        h) show_help ;;
        c) cli_commands+=("$OPTARG") ;;
        l) 
            echo "Commands file: $SCRIPT_DIR/commands"
            echo ""
            cat "$SCRIPT_DIR/commands"
            exit 0
            ;;
        e)
            ${EDITOR:-nano} "$SCRIPT_DIR/commands"
            exit 0
            ;;
        *) show_help ;;
    esac
done

# Parse devices.yaml using Python parser (same as other lldpq scripts)
eval "$(python3 "$SCRIPT_DIR/parse_devices.py")"

# Check if devices array is populated
if [[ ${#devices[@]} -eq 0 ]]; then
    echo "ERROR: No devices found. Check devices.yaml configuration."
    exit 1
fi

# Use CLI commands if provided, otherwise read from file
commands=()
if [[ ${#cli_commands[@]} -gt 0 ]]; then
    commands=("${cli_commands[@]}")
    echo -e "\e[0;36mUsing command-line arguments\e[0m"
else
    # Read commands from file (skip comments and empty lines)
    COMMANDS_FILE="$SCRIPT_DIR/commands"
    if [[ ! -f "$COMMANDS_FILE" ]]; then
        echo "ERROR: Commands file not found: $COMMANDS_FILE"
        exit 1
    fi

    while IFS= read -r line; do
        # Skip comments and empty lines
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${line// }" ]] && continue
        commands+=("$line")
    done < "$COMMANDS_FILE"

    if [[ ${#commands[@]} -eq 0 ]]; then
        echo "No commands to execute. Edit $COMMANDS_FILE and uncomment commands."
        echo "Or use: send-cmd -c \"your command\""
        exit 0
    fi
fi

echo ""
echo -e "\e[1;34mExecuting ${#commands[@]} command(s) on ${#devices[@]} device(s)...\e[0m"
echo ""

unreachable_hosts=()

ping_test() {
    local device=$1
    local hostname=$2
    ping -c 1 -W 1 "$device" >/dev/null 2>&1 || { unreachable_hosts+=("$device $hostname"); return 1; }
    return 0
}

TMPDIR=$(mktemp -d)
cleanup(){ rm -rf "$TMPDIR"; }
trap cleanup EXIT

execute_commands() {
    local device=$1
    local user=$2
    local hostname=$3
    local out="$TMPDIR/${hostname}.out"

    for command in "${commands[@]}"; do
        ssh_output=$(ssh -T -q -o StrictHostKeyChecking=no "$user@$device" "$command" 2>/dev/null)
        if [ -n "$ssh_output" ]; then
            {
                echo ""
                echo -e "\e[0;31m----------------------------------------------------------\e[0m"
                echo ""
                printf "\e[1;34m[ %-1s ] \e[1;33m%-1s\e[0m\n" "$hostname" "ssh $user@${device}"
                echo -e "\e[0;36mCommand: $command\e[0m"
                echo ""
                echo -e "\e[0;32m$ssh_output\e[0m"
                echo ""
                echo -e "\e[0;31m----------------------------------------------------------\e[0m"
            } >>"$out"
        fi
    done
}

for device in "${!devices[@]}"; do
    IFS=' ' read -r user hostname <<< "${devices[$device]}"
    ping_test "$device" "$hostname" && { execute_commands "$device" "$user" "$hostname" & sleep 0.1; }
done

wait

if compgen -G "$TMPDIR"/* >/dev/null; then
    while IFS= read -r f; do cat "$f"; done < <(printf "%s\n" "$TMPDIR"/* | sort)
fi

echo ""
echo -e "\e[1;34mAll commands have been executed.\e[0m"
echo ""

if [ ${#unreachable_hosts[@]} -ne 0 ]; then
    echo -e "\e[0;36mUnreachable hosts:\e[0m"
    echo ""
    printf "%s\n" "${unreachable_hosts[@]}" | sort -k2,2 | while IFS=' ' read -r ip hostname; do
        printf "\e[31m[%-14s]\t\e[0;31m[%-1s]\e[0m\n" "$ip" "$hostname"
    done
    echo ""
else
    echo -e "\e[0;32mAll hosts are reachable.\e[0m"
    echo ""
fi

exit 0
