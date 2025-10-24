#!/bin/bash
################################################################################
# WireGuard Remove Client Script
# Description: Safely remove a client from a specific WireGuard server
# Usage: sudo ./remove-client.sh [OPTIONS]
################################################################################

set -euo pipefail

################################################################################
# CONFIGURATION
################################################################################

WG_CONFIG_DIR="/etc/wireguard"
CLIENT_NAME=""
WG_INTERFACE=""

################################################################################
# COLORS
################################################################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[i]${NC} $1"
}

################################################################################
# HELPER FUNCTIONS
################################################################################

error_exit() {
    print_error "$1"
    exit 1
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root (use sudo)"
    fi
}

detect_servers() {
    local servers=()

    if [[ -d "$WG_CONFIG_DIR" ]]; then
        # Use nullglob to handle case where no .conf files exist
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

    # If interface specified via argument, validate it
    if [[ -n "$WG_INTERFACE" ]]; then
        if [[ ! -f "${WG_CONFIG_DIR}/${WG_INTERFACE}.conf" ]]; then
            error_exit "WireGuard server '${WG_INTERFACE}' not found."
        fi
        print_success "Using server: ${WG_INTERFACE}"
        return
    fi

    # If only one server exists, use it automatically (silently)
    if [[ $server_count -eq 1 ]]; then
        WG_INTERFACE="${servers[0]}"
        return
    fi

    # Multiple servers - show selection menu
    print_info "Multiple WireGuard servers detected"
    print_warning "TIP: Use --interface wg0 to skip this menu"
    echo ""
    echo "Available servers:"
    echo ""

    local i=1
    for iface in "${servers[@]}"; do
        local conf_ip=$(grep -E "^Address\s*=" "${WG_CONFIG_DIR}/${iface}.conf" | head -n1 | awk '{print $3}')
        local conf_port=$(grep -E "^ListenPort\s*=" "${WG_CONFIG_DIR}/${iface}.conf" | head -n1 | awk '{print $3}')
        local is_running=""

        if systemctl is-active --quiet "wg-quick@${iface}"; then
            is_running="${GREEN}[RUNNING]${NC}"
        else
            is_running="${YELLOW}[STOPPED]${NC}"
        fi

        printf "  ${BLUE}%d)${NC} %s %b - %s, Port %s\n" "$i" "$iface" "$is_running" "$conf_ip" "$conf_port"
        ((i++))
    done

    echo ""
    read -p "Select server (1-${server_count}): " selection

    # Validate selection
    if ! [[ "$selection" =~ ^[0-9]+$ ]] || [ "$selection" -lt 1 ] || [ "$selection" -gt "$server_count" ]; then
        error_exit "Invalid selection"
    fi

    WG_INTERFACE="${servers[$((selection-1))]}"
    print_success "Selected server: ${WG_INTERFACE}"
}

list_clients() {
    # Use list-clients.sh to get clients
    local clients=$(./list-clients.sh "${WG_INTERFACE}" --format array 2>/dev/null)

    echo "$clients"
}

select_client() {
    local clients=($(list_clients))
    local client_count=${#clients[@]}

    # Check if any clients exist
    if [[ $client_count -eq 0 ]]; then
        error_exit "No clients found in ${WG_INTERFACE}"
    fi

    # If client specified via argument, validate it using list-clients.sh
    if [[ -n "$CLIENT_NAME" ]]; then
        if ! ./list-clients.sh "${WG_INTERFACE}" --check "${CLIENT_NAME}" 2>/dev/null; then
            error_exit "Client '${CLIENT_NAME}' not found in ${WG_INTERFACE}"
        fi

        print_success "Using client: ${CLIENT_NAME}"
        return
    fi

    # Show client selection menu using list-clients.sh interactive mode
    print_info "Select a client to remove from the VPN server"
    echo ""
    ./list-clients.sh "${WG_INTERFACE}" --format interactive

    read -p "Select client to remove (1-${client_count}): " selection

    # Validate selection
    if ! [[ "$selection" =~ ^[0-9]+$ ]] || [ "$selection" -lt 1 ] || [ "$selection" -gt "$client_count" ]; then
        error_exit "Invalid selection"
    fi

    CLIENT_NAME="${clients[$((selection-1))]}"
    print_success "Selected client: ${CLIENT_NAME}"
}

remove_client_from_config() {
    local config_file="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"
    local backup_file="${config_file}.backup.$(date +%Y%m%d_%H%M%S)"

    print_info "Removing client from server configuration..."

    # Backup config
    cp "$config_file" "$backup_file"
    print_info "Backed up config to: $backup_file"

    # Remove client peer section
    # Find the client comment line and remove it + the [Peer] section + PublicKey + AllowedIPs
    local temp_file=$(mktemp)
    # Ensure temp file is cleaned up on exit or error
    trap "rm -f '$temp_file'" EXIT ERR

    # Backup original permissions
    local original_perms=$(stat -c '%a' "$config_file" 2>/dev/null || echo "600")
    local original_owner=$(stat -c '%U:%G' "$config_file" 2>/dev/null || echo "root:root")

    local in_client_section=0

    while IFS= read -r line; do
        # Check if this is our client comment
        if [[ "$line" =~ ^#\ Client:\ ${CLIENT_NAME}$ ]]; then
            in_client_section=1
            continue
        fi

        # Skip lines while in client section
        if [[ $in_client_section -eq 1 ]]; then
            # Skip [Peer], PublicKey, AllowedIPs lines
            if [[ "$line" =~ ^\[Peer\]$ ]] || [[ "$line" =~ ^PublicKey ]] || [[ "$line" =~ ^AllowedIPs ]]; then
                continue
            # Skip empty lines immediately after
            elif [[ -z "$line" ]]; then
                in_client_section=0
                continue
            else
                # Found next section, stop skipping
                in_client_section=0
            fi
        fi

        # Write line to temp file
        echo "$line" >> "$temp_file"
    done < "$config_file"

    # Replace original config with cleaned version
    mv "$temp_file" "$config_file"
    chmod "$original_perms" "$config_file"
    chown "$original_owner" "$config_file"

    # Clear the trap since we successfully moved the file
    trap - EXIT ERR

    print_success "Client removed from ${config_file}"
}

remove_client_keys() {
    local keys_dir="${WG_CONFIG_DIR}/${WG_INTERFACE}"

    print_info "Removing client keys and config..."

    local files_removed=0

    # Remove private key
    if [[ -f "${keys_dir}/${CLIENT_NAME}-privatekey" ]]; then
        rm -f "${keys_dir}/${CLIENT_NAME}-privatekey"
        ((files_removed++))
    fi

    # Remove public key
    if [[ -f "${keys_dir}/${CLIENT_NAME}-publickey" ]]; then
        rm -f "${keys_dir}/${CLIENT_NAME}-publickey"
        ((files_removed++))
    fi

    # Remove client config
    if [[ -f "${keys_dir}/${CLIENT_NAME}.conf" ]]; then
        rm -f "${keys_dir}/${CLIENT_NAME}.conf"
        ((files_removed++))
    fi

    if [[ $files_removed -gt 0 ]]; then
        print_success "Removed ${files_removed} client file(s) from ${keys_dir}"
    else
        print_warning "No client files found in ${keys_dir}"
    fi
}

reload_server() {
    print_info "Reloading WireGuard configuration without dropping connections..."

    # Use wg syncconf to reload config without disrupting active connections
    wg syncconf "${WG_INTERFACE}" <(wg-quick strip "${WG_INTERFACE}") || error_exit "Failed to reload ${WG_INTERFACE}"

    print_success "WireGuard configuration reloaded for ${WG_INTERFACE}"
    print_info "Active connections remain intact"
}

show_summary() {
    echo ""
    echo "=========================================="
    print_success "Client Removed Successfully!"
    echo "=========================================="
    echo ""
    print_info "Removed client: ${CLIENT_NAME}"
    print_info "From server: ${WG_INTERFACE}"
    echo ""
    print_info "What was removed:"
    echo "  - Client peer from ${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"
    echo "  - Client keys from ${WG_CONFIG_DIR}/${WG_INTERFACE}/"
    echo "  - Client config file"
    echo ""
    echo "=========================================="
    echo ""
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --interface|-i)
                WG_INTERFACE="$2"
                shift 2
                ;;
            --client|-c)
                CLIENT_NAME="$2"
                shift 2
                ;;
            -h|--help)
                echo "Usage: sudo $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  -i, --interface NAME    WireGuard interface (e.g., wg0)"
                echo "  -c, --client NAME       Client name to remove"
                echo "  -h, --help             Show this help"
                echo ""
                echo "Example:"
                echo "  sudo $0 --interface wg0 --client laptop"
                echo "  sudo $0  # Interactive mode"
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                exit 1
                ;;
        esac
    done
}

################################################################################
# MAIN
################################################################################

main() {
    echo "=========================================="
    echo "  WireGuard Remove Client"
    echo "=========================================="
    echo ""

    parse_arguments "$@"

    check_root
    select_server
    select_client

    echo ""
    print_warning "This will remove client '${CLIENT_NAME}' from ${WG_INTERFACE}"
    read -p "Are you sure? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        error_exit "Client removal cancelled"
    fi

    remove_client_from_config
    remove_client_keys
    reload_server
    show_summary
}

main "$@"
