#!/bin/bash
################################################################################
# WireGuard List Peers Script
# Description: List all clients and sites for a WireGuard server
# Usage: ./list-peers.sh <interface> [OPTIONS]
################################################################################

set -euo pipefail

WG_CONFIG_DIR="/etc/wireguard"
WG_INTERFACE=""
OUTPUT_FORMAT="interactive"

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
print_error() { echo -e "${RED}[✗]${NC} $1" >&2; }
print_info() { echo -e "${BLUE}[i]${NC} $1" >&2; }
error_exit() { print_error "$1"; exit 1; }

# Extract peer names from config comments
list_peers() {
    local config_file="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"
    [[ -f "$config_file" ]] || error_exit "Server '${WG_INTERFACE}' not found"

    # Extract names from "# Client: NAME" or "# Site: NAME" lines
    grep -oP '^#\s*(Client|Site):\s*\K.+' "$config_file" 2>/dev/null | sed 's/\s*$//' || true
}

# Get peer's AllowedIPs
get_peer_ip() {
    local name="$1"
    local config="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"
    awk -v name="$name" '
        $0 ~ "^#\\s*(Client|Site):\\s*" name "\\s*$" { found=1; next }
        found && /^AllowedIPs/ { sub(/.*=\s*/, ""); print; exit }
    ' "$config" 2>/dev/null
}

# Check if peer exists
check_peer_exists() {
    local name="$1"
    grep -qP "^#\s*(Client|Site):\s*${name}\s*$" "${WG_CONFIG_DIR}/${WG_INTERFACE}.conf" 2>/dev/null
}

# Detect servers
detect_servers() {
    local servers=($(ls "${WG_CONFIG_DIR}"/*.conf 2>/dev/null | xargs -n1 basename -s .conf))
    [[ ${#servers[@]} -gt 0 ]] || error_exit "No WireGuard servers found"
    echo "${servers[@]}"
}

# Select server (auto or interactive)
select_server() {
    local servers=($(detect_servers))

    if [[ ${#servers[@]} -eq 1 ]]; then
        WG_INTERFACE="${servers[0]}"
    else
        print_info "Multiple servers detected" >&2
        echo "" >&2
        local i=1
        for iface in "${servers[@]}"; do
            local ip=$(grep -oP '^Address\s*=\s*\K\S+' "${WG_CONFIG_DIR}/${iface}.conf" 2>/dev/null | head -1)
            printf "  ${BLUE}%d)${NC} %s - %s\n" "$i" "$iface" "$ip" >&2
            ((i++)) || true
        done
        echo "" >&2
        read -p "Select server (1-${#servers[@]}): " selection >&2
        [[ "$selection" =~ ^[0-9]+$ ]] && [[ $selection -ge 1 ]] && [[ $selection -le ${#servers[@]} ]] || error_exit "Invalid selection"
        WG_INTERFACE="${servers[$((selection-1))]}"
    fi
}

# Output formats
output_interactive() {
    local peers=($1)
    [[ ${#peers[@]} -eq 0 ]] && { print_info "No peers found in ${WG_INTERFACE}"; return; }

    print_info "Peers in ${WG_INTERFACE}:" >&2
    echo "" >&2
    local i=1
    for peer in "${peers[@]}"; do
        local ip=$(get_peer_ip "$peer")
        printf "  ${BLUE}%d)${NC} %s - %s\n" "$i" "$peer" "$ip" >&2
        ((i++)) || true
    done
    echo "" >&2
}

output_array() { echo "$1"; }
output_names_only() { local peers=($1); printf "%s\n" "${peers[@]}"; }

# Parse arguments
parse_args() {
    local check_peer=""
    local count_only=false

    [[ $# -gt 0 ]] && [[ ! "$1" =~ ^-- ]] && [[ "$1" != "-h" ]] && { WG_INTERFACE="$1"; shift; }

    while [[ $# -gt 0 ]]; do
        case $1 in
            --format) OUTPUT_FORMAT="$2"; shift 2 ;;
            --check) check_peer="$2"; shift 2 ;;
            --count) count_only=true; shift ;;
            -h|--help)
                echo "Usage: $0 [interface] [OPTIONS]" >&2
                echo "Options:" >&2
                echo "  --format FORMAT   Output: interactive, names-only, array" >&2
                echo "  --check NAME      Check if peer exists (exit 0/1)" >&2
                echo "  --count           Return peer count" >&2
                exit 0 ;;
            *) error_exit "Unknown option: $1" ;;
        esac
    done

    [[ -z "$WG_INTERFACE" ]] && select_server

    if [[ -n "$check_peer" ]]; then
        check_peer_exists "$check_peer" && exit 0 || exit 1
    fi

    if [[ "$count_only" == "true" ]]; then
        local peers=($(list_peers))
        echo "${#peers[@]}"
        exit 0
    fi
}

# Main
parse_args "$@"
peers=$(list_peers)

case "$OUTPUT_FORMAT" in
    interactive) output_interactive "$peers" ;;
    array) output_array "$peers" ;;
    names-only) output_names_only "$peers" ;;
    *) error_exit "Unknown format: $OUTPUT_FORMAT" ;;
esac
