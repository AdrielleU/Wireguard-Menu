#!/bin/bash
################################################################################
# WireGuard Rotate Server Keys Script
# Description: Regenerate server encryption keys and update all client configs
# Usage: sudo ./rotate-keys-server.sh [OPTIONS]
################################################################################

set -euo pipefail

################################################################################
# CONFIGURATION
################################################################################

WG_CONFIG_DIR="/etc/wireguard"
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
        for conf in "$WG_CONFIG_DIR"/*.conf; do
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

    # If only one server exists, use it automatically
    if [[ $server_count -eq 1 ]]; then
        WG_INTERFACE="${servers[0]}"
        print_success "Auto-detected server: ${WG_INTERFACE}"
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

        echo -e "  ${BLUE}${i})${NC} ${iface} $is_running - ${conf_ip}, Port ${conf_port}"
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

get_all_clients() {
    # Use list-clients.sh if available, otherwise fallback
    if [[ -x "./list-clients.sh" ]]; then
        local clients=$(./list-clients.sh "${WG_INTERFACE}" --format array 2>/dev/null)
    else
        # Fallback: extract from config directly
        local config_file="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"
        local clients=()
        while IFS= read -r line; do
            if [[ "$line" =~ ^#\ Client:\ (.+)$ ]]; then
                clients+=("${BASH_REMATCH[1]}")
            fi
        done < "$config_file"
        clients="${clients[@]}"
    fi

    echo "$clients"
}

get_client_info() {
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

remove_old_server_keys() {
    local keys_dir="${WG_CONFIG_DIR}/${WG_INTERFACE}"

    print_info "Removing old server keys..."

    # Remove old server keys to avoid conflicts
    rm -f "${keys_dir}/server-privatekey"
    rm -f "${keys_dir}/server-publickey"

    print_success "Old server keys removed"
}

generate_new_server_keys() {
    local keys_dir="${WG_CONFIG_DIR}/${WG_INTERFACE}"

    print_info "Generating new server encryption keys..."

    mkdir -p "$keys_dir"
    cd "$keys_dir" || error_exit "Failed to access ${keys_dir}"

    umask 077

    local private_key_file="${keys_dir}/server-privatekey"
    local public_key_file="${keys_dir}/server-publickey"

    wg genkey | tee "$private_key_file" | wg pubkey > "$public_key_file" || error_exit "Failed to generate keys"
    chmod 600 "$private_key_file" "$public_key_file"

    SERVER_PRIVATE_KEY=$(cat "$private_key_file")
    SERVER_PUBLIC_KEY=$(cat "$public_key_file")

    print_success "New server keys generated"
}

update_server_config() {
    local config_file="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"

    print_info "Updating server configuration..."

    # Read current config and update PrivateKey
    local temp_file=$(mktemp)

    while IFS= read -r line; do
        if [[ "$line" =~ ^PrivateKey ]]; then
            echo "PrivateKey = ${SERVER_PRIVATE_KEY}" >> "$temp_file"
        else
            echo "$line" >> "$temp_file"
        fi
    done < "$config_file"

    # Replace original config
    mv "$temp_file" "$config_file"
    chmod 600 "$config_file"

    print_success "Server config updated with new private key"
}

regenerate_all_client_configs() {
    local keys_dir="${WG_CONFIG_DIR}/${WG_INTERFACE}"
    local config_file="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"
    local clients=($(get_all_clients))

    if [[ ${#clients[@]} -eq 0 ]]; then
        print_warning "No clients found. Skipping client config regeneration."
        return
    fi

    print_info "Regenerating configs for ${#clients[@]} client(s)..."

    # Get server info
    local server_port=$(grep -E "^ListenPort\s*=" "$config_file" | head -n1 | awk '{print $3}')

    for client in "${clients[@]}"; do
        local client_ip=$(get_client_info "$client")
        local client_config="${keys_dir}/${client}.conf"
        local client_private_key=""

        # Get client private key if it exists
        if [[ -f "${keys_dir}/${client}-privatekey" ]]; then
            client_private_key=$(cat "${keys_dir}/${client}-privatekey")
        else
            print_warning "Private key not found for ${client}, skipping config generation"
            continue
        fi

        # Get server endpoint from existing config if available
        local server_endpoint=""
        if [[ -f "$client_config" ]]; then
            server_endpoint=$(grep -E "^Endpoint\s*=" "$client_config" | awk '{print $3}' | cut -d':' -f1)
        fi

        if [[ -z "$server_endpoint" ]]; then
            print_warning "Could not determine endpoint for ${client}, using placeholder"
            server_endpoint="YOUR_SERVER_IP"
        fi

        # Regenerate client config with new server public key
        cat > "$client_config" <<EOF
[Interface]
PrivateKey = ${client_private_key}
Address = ${client_ip}
DNS = 8.8.8.8

[Peer]
PublicKey = ${SERVER_PUBLIC_KEY}
Endpoint = ${server_endpoint}:${server_port}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

        chmod 600 "$client_config"
        print_success "Regenerated config for ${client}"
    done

    print_success "All client configs updated with new server public key"
}

reload_server() {
    print_info "Reloading WireGuard server..."

    # Stop the service
    systemctl stop "wg-quick@${WG_INTERFACE}" 2>/dev/null || true

    # Start with new keys
    systemctl start "wg-quick@${WG_INTERFACE}" || error_exit "Failed to start ${WG_INTERFACE}"

    print_success "WireGuard server restarted with new keys"
    print_warning "All clients are now disconnected and need updated configs!"
}

show_summary() {
    local keys_dir="${WG_CONFIG_DIR}/${WG_INTERFACE}"
    local clients=($(get_all_clients))

    echo ""
    echo "=========================================="
    print_success "Server Keys Rotated Successfully!"
    echo "=========================================="
    echo ""
    print_info "Server: ${WG_INTERFACE}"
    print_info "New Server Public Key:"
    echo "  ${SERVER_PUBLIC_KEY}"
    echo ""
    print_warning "ALL CLIENTS MUST UPDATE THEIR CONFIGS!"
    echo ""

    if [[ ${#clients[@]} -gt 0 ]]; then
        print_info "Updated client configs (${#clients[@]} total):"
        for client in "${clients[@]}"; do
            echo "  - ${client}: ${keys_dir}/${client}.conf"
        done
        echo ""
        print_info "Distribute new configs to clients:"
        echo "  Method 1 - Copy individual configs:"
        for client in "${clients[@]}"; do
            echo "    scp root@server:${keys_dir}/${client}.conf ~/${client}.conf"
        done
        echo ""
        echo "  Method 2 - Generate QR codes:"
        for client in "${clients[@]}"; do
            echo "    sudo ./qr-show.sh --interface ${WG_INTERFACE} --client ${client}"
        done
    else
        print_warning "No clients found"
    fi

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
            -h|--help)
                echo "Usage: sudo $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  -i, --interface NAME    WireGuard interface (e.g., wg0)"
                echo "  -h, --help             Show this help"
                echo ""
                echo "Example:"
                echo "  sudo $0 --interface wg0"
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
    echo "  WireGuard Rotate Server Keys"
    echo "=========================================="
    echo ""

    parse_arguments "$@"

    check_root
    select_server

    local clients=($(get_all_clients))
    local client_count=${#clients[@]}

    echo ""
    print_warning "This will PERMANENTLY regenerate server encryption keys!"
    print_warning "ALL ${client_count} client(s) will be disconnected!"
    echo ""
    print_info "NOTE: Old keys will be OVERWRITTEN. To backup first:"
    echo "  cp -r /etc/wireguard/${WG_INTERFACE}/ /tmp/backup-${WG_INTERFACE}/"
    echo ""
    read -p "Continue? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        error_exit "Server key rotation cancelled"
    fi

    remove_old_server_keys
    generate_new_server_keys
    update_server_config
    regenerate_all_client_configs
    reload_server
    show_summary
}

main "$@"
