#!/bin/bash
################################################################################
# WireGuard List Clients Script
# Description: List all clients for a specific WireGuard server
# Usage: ./list-clients.sh <interface> [--format FORMAT]
################################################################################

set -euo pipefail

################################################################################
# CONFIGURATION
################################################################################

WG_CONFIG_DIR="/etc/wireguard"
WG_INTERFACE=""
OUTPUT_FORMAT="interactive"  # interactive, names-only, array

################################################################################
# COLORS
################################################################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_success() {
    echo -e "${GREEN}[✓]${NC} $1" >&2
}

print_error() {
    echo -e "${RED}[✗]${NC} $1" >&2
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1" >&2
}

print_info() {
    echo -e "${BLUE}[i]${NC} $1" >&2
}

################################################################################
# HELPER FUNCTIONS
################################################################################

error_exit() {
    print_error "$1" >&2
    exit 1
}

get_client_ip() {
    local client_name="$1"
    local config_file="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"
    local found_client=0
    local client_ip=""

    while IFS= read -r line; do
        if [[ "$line" =~ ^#\ Client:\ ${client_name}$ ]]; then
            found_client=1
        elif [[ $found_client -eq 1 ]] && [[ "$line" =~ ^AllowedIPs\ =\ (.+)$ ]]; then
            client_ip="${BASH_REMATCH[1]}"
            break
        fi
    done < "$config_file"

    echo "$client_ip"
}

get_client_public_key() {
    local client_name="$1"
    local config_file="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"
    local found_client=0
    local client_key=""

    while IFS= read -r line; do
        if [[ "$line" =~ ^#\ Client:\ ${client_name}$ ]]; then
            found_client=1
        elif [[ $found_client -eq 1 ]] && [[ "$line" =~ ^PublicKey\ =\ (.+)$ ]]; then
            client_key="${BASH_REMATCH[1]}"
            break
        fi
    done < "$config_file"

    echo "$client_key"
}

detect_servers() {
    local servers=()

    if [[ -d "$WG_CONFIG_DIR" ]]; then
        shopt -s nullglob
        local conf_files=("$WG_CONFIG_DIR"/*.conf)
        shopt -u nullglob

        for conf in "${conf_files[@]}"; do
            [[ ! -f "$conf" ]] && continue
            local iface_name=$(basename "$conf" .conf)
            servers+=("$iface_name")
        done
    fi

    if [[ ${#servers[@]} -eq 0 ]]; then
        error_exit "No WireGuard servers found. Run setup-wireguard.sh first."
    fi

    echo "${servers[@]}"
}

select_server() {
    local servers=($(detect_servers))
    local server_count=${#servers[@]}

    # If only one server exists, use it automatically (silently)
    if [[ $server_count -eq 1 ]]; then
        WG_INTERFACE="${servers[0]}"
        return
    fi

    # Multiple servers - show selection menu
    print_info "Multiple WireGuard servers detected"
    echo ""
    echo "Available servers:"
    echo ""

    local i=1
    for iface in "${servers[@]}"; do
        local conf_ip=$(grep -E "^Address\s*=" "${WG_CONFIG_DIR}/${iface}.conf" | head -n1 | awk '{print $3}')
        local conf_port=$(grep -E "^ListenPort\s*=" "${WG_CONFIG_DIR}/${iface}.conf" | head -n1 | awk '{print $3}')
        printf "  ${BLUE}%d)${NC} %s - %s, Port %s\n" "$i" "$iface" "$conf_ip" "$conf_port"
        ((i++))
    done

    echo ""
    read -p "Select server (1-${server_count}): " selection

    if ! [[ "$selection" =~ ^[0-9]+$ ]] || [ "$selection" -lt 1 ] || [ "$selection" -gt "$server_count" ]; then
        error_exit "Invalid selection"
    fi

    WG_INTERFACE="${servers[$((selection-1))]}"
    print_success "Selected server: ${WG_INTERFACE}"
}

check_client_exists() {
    local client_name="$1"
    local config_file="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"

    if grep -q "^# Client: ${client_name}$" "$config_file" 2>/dev/null; then
        return 0  # Client exists
    else
        return 1  # Client doesn't exist
    fi
}

list_clients() {
    local config_file="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"
    local clients=()

    # Validate interface
    if [[ ! -f "$config_file" ]]; then
        error_exit "WireGuard server '${WG_INTERFACE}' not found"
    fi

    # Extract client names from comments in config
    while IFS= read -r line; do
        if [[ "$line" =~ ^#\ Client:\ (.+)$ ]]; then
            local client_name="${BASH_REMATCH[1]}"
            clients+=("$client_name")
        fi
    done < "$config_file"

    echo "${clients[@]}"
}

output_interactive() {
    local clients=($1)
    local client_count=${#clients[@]}

    if [[ $client_count -eq 0 ]]; then
        print_info "No clients found in ${WG_INTERFACE}"
        return
    fi

    print_info "Clients in ${WG_INTERFACE}:" >&2
    echo "" >&2

    local i=1
    for client in "${clients[@]}"; do
        local client_ip=$(get_client_ip "$client")
        if [[ -n "$client_ip" ]]; then
            printf "  ${BLUE}%d)${NC} %s - %s\n" "$i" "$client" "$client_ip" >&2
        else
            printf "  ${BLUE}%d)${NC} %s\n" "$i" "$client" >&2
        fi
        ((i++))
    done

    echo "" >&2
}

output_names_only() {
    local clients=($1)

    for client in "${clients[@]}"; do
        echo "$client"
    done
}

output_array() {
    echo "$1"
}

output_detailed() {
    local clients=($1)
    local client_count=${#clients[@]}

    if [[ $client_count -eq 0 ]]; then
        print_info "No clients found in ${WG_INTERFACE}"
        return
    fi

    print_info "Clients in ${WG_INTERFACE}:" >&2
    echo "" >&2

    for client in "${clients[@]}"; do
        local client_ip=$(get_client_ip "$client")
        local client_key=$(get_client_public_key "$client")
        printf "${BLUE}Client:${NC} %s\n" "$client" >&2
        printf "  IP: %s\n" "$client_ip" >&2
        printf "  Public Key: %s...%s\n" "${client_key:0:20}" "${client_key: -20}" >&2
        echo "" >&2
    done
}

parse_arguments() {
    local check_client=""
    local count_only=false

    # Check if first argument is an interface name or an option
    if [[ $# -gt 0 ]] && [[ ! "$1" =~ ^-- ]] && [[ "$1" != "-h" ]]; then
        # First argument is interface
        WG_INTERFACE="$1"
        shift
    fi

    # Parse remaining options
    while [[ $# -gt 0 ]]; do
        case $1 in
            --format)
                OUTPUT_FORMAT="$2"
                shift 2
                ;;
            --check)
                check_client="$2"
                shift 2
                ;;
            --count)
                count_only=true
                shift
                ;;
            -h|--help)
                echo "Usage: $0 [interface] [OPTIONS]" >&2
                echo "" >&2
                echo "Arguments:" >&2
                echo "  interface              WireGuard interface (e.g., wg0) - optional, will auto-detect" >&2
                echo "" >&2
                echo "Options:" >&2
                echo "  --format FORMAT        Output format: interactive, names-only, array, detailed" >&2
                echo "  --check NAME           Check if client NAME exists (exit 0 if yes, 1 if no)" >&2
                echo "  --count                Return client count only" >&2
                echo "  -h, --help            Show this help" >&2
                echo "" >&2
                echo "Examples:" >&2
                echo "  $0                                      # Auto-detect server, interactive list" >&2
                echo "  $0 wg0                                  # List clients for wg0" >&2
                echo "  $0 wg0 --format names-only              # Just names" >&2
                echo "  $0 wg0 --format array                   # Space-separated array" >&2
                echo "  $0 wg0 --format detailed                # With public keys" >&2
                echo "  $0 wg0 --check laptop                   # Check if 'laptop' exists" >&2
                echo "  $0 wg0 --count                          # Count clients" >&2
                exit 0
                ;;
            *)
                echo "Unknown option: $1" >&2
                exit 1
                ;;
        esac
    done

    # If interface not specified, auto-detect
    if [[ -z "$WG_INTERFACE" ]]; then
        select_server
    fi

    # Handle --check flag
    if [[ -n "$check_client" ]]; then
        if check_client_exists "$check_client"; then
            exit 0
        else
            exit 1
        fi
    fi

    # Handle --count flag
    if [[ "$count_only" == "true" ]]; then
        local clients=($(list_clients))
        echo "${#clients[@]}"
        exit 0
    fi
}

################################################################################
# MAIN
################################################################################

main() {
    parse_arguments "$@"

    # Get clients
    local clients=$(list_clients)

    # Output based on format
    case "$OUTPUT_FORMAT" in
        interactive)
            output_interactive "$clients"
            ;;
        names-only)
            output_names_only "$clients"
            ;;
        array)
            output_array "$clients"
            ;;
        detailed)
            output_detailed "$clients"
            ;;
        *)
            error_exit "Unknown format: $OUTPUT_FORMAT"
            ;;
    esac
}

main "$@"
