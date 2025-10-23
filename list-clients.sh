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
        echo -e "  ${BLUE}${i})${NC} ${client} ${client_ip:+- ${client_ip}}" >&2
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
        echo -e "${BLUE}Client:${NC} ${client}" >&2
        echo -e "  IP: ${client_ip}" >&2
        echo -e "  Public Key: ${client_key:0:20}...${client_key: -20}" >&2
        echo "" >&2
    done
}

parse_arguments() {
    # First argument should be the interface (required)
    if [[ $# -eq 0 ]]; then
        echo "Usage: $0 <interface> [OPTIONS]" >&2
        echo "" >&2
        echo "Arguments:" >&2
        echo "  interface              WireGuard interface (e.g., wg0)" >&2
        echo "" >&2
        echo "Options:" >&2
        echo "  --format FORMAT        Output format: interactive, names-only, array, detailed" >&2
        echo "  --check NAME           Check if client NAME exists (exit 0 if yes, 1 if no)" >&2
        echo "  --count                Return client count only" >&2
        echo "  -h, --help            Show this help" >&2
        echo "" >&2
        echo "Examples:" >&2
        echo "  $0 wg0                                  # Interactive list" >&2
        echo "  $0 wg0 --format names-only              # Just names" >&2
        echo "  $0 wg0 --format array                   # Space-separated array" >&2
        echo "  $0 wg0 --format detailed                # With public keys" >&2
        echo "  $0 wg0 --check laptop                   # Check if 'laptop' exists" >&2
        echo "  $0 wg0 --count                          # Count clients" >&2
        exit 1
    fi

    WG_INTERFACE="$1"
    shift

    local check_client=""
    local count_only=false

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
                parse_arguments  # Will trigger usage message
                ;;
            *)
                echo "Unknown option: $1" >&2
                exit 1
                ;;
        esac
    done

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
