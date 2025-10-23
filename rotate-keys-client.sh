#!/bin/bash
################################################################################
# WireGuard Rotate Keys Script
# Description: Regenerate encryption keys for existing client
# Usage: sudo ./rotate-keys.sh [OPTIONS]
################################################################################

set -euo pipefail

################################################################################
# CONFIGURATION
################################################################################

WG_CONFIG_DIR="/etc/wireguard"
CLIENT_NAME=""
WG_INTERFACE=""
CLIENT_IP=""
SERVER_PUBLIC_KEY=""
SERVER_ENDPOINT=""
SERVER_PORT=""

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

list_clients() {
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

    if [[ -z "$clients" ]]; then
        error_exit "No clients found in ${WG_INTERFACE}"
    fi

    echo "$clients"
}

select_client() {
    local clients=($(list_clients))
    local client_count=${#clients[@]}

    # If client specified via argument, validate it
    if [[ -n "$CLIENT_NAME" ]]; then
        if [[ -x "./list-clients.sh" ]]; then
            if ! ./list-clients.sh "${WG_INTERFACE}" --check "${CLIENT_NAME}" 2>/dev/null; then
                error_exit "Client '${CLIENT_NAME}' not found in ${WG_INTERFACE}"
            fi
        fi
        print_success "Using client: ${CLIENT_NAME}"
        return
    fi

    # Show client selection menu
    echo ""
    echo "Clients in ${WG_INTERFACE}:"
    echo ""

    local i=1
    for client in "${clients[@]}"; do
        echo -e "  ${BLUE}${i})${NC} ${client}"
        ((i++))
    done

    echo ""
    read -p "Select client to rotate keys (1-${client_count}): " selection

    # Validate selection
    if ! [[ "$selection" =~ ^[0-9]+$ ]] || [ "$selection" -lt 1 ] || [ "$selection" -gt "$client_count" ]; then
        error_exit "Invalid selection"
    fi

    CLIENT_NAME="${clients[$((selection-1))]}"
    print_success "Selected client: ${CLIENT_NAME}"
}

get_current_client_info() {
    local config_file="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"
    local keys_dir="${WG_CONFIG_DIR}/${WG_INTERFACE}"

    print_info "Reading current client configuration..."

    # Get client IP from server config
    local found_client=0
    while IFS= read -r line; do
        if [[ "$line" =~ ^#\ Client:\ ${CLIENT_NAME}$ ]]; then
            found_client=1
        elif [[ $found_client -eq 1 ]] && [[ "$line" =~ ^AllowedIPs\ =\ (.+)$ ]]; then
            CLIENT_IP="${BASH_REMATCH[1]}"
            break
        fi
    done < "$config_file"

    if [[ -z "$CLIENT_IP" ]]; then
        error_exit "Could not find IP address for client ${CLIENT_NAME}"
    fi

    # Get server info
    SERVER_PORT=$(grep -E "^ListenPort\s*=" "$config_file" | head -n1 | awk '{print $3}')

    if [[ -f "${keys_dir}/server-publickey" ]]; then
        SERVER_PUBLIC_KEY=$(cat "${keys_dir}/server-publickey")
    else
        error_exit "Server public key not found"
    fi

    # Get server endpoint from existing client config if it exists
    local client_config="${keys_dir}/${CLIENT_NAME}.conf"
    if [[ -f "$client_config" ]]; then
        SERVER_ENDPOINT=$(grep -E "^Endpoint\s*=" "$client_config" | awk '{print $3}' | cut -d':' -f1)
    fi

    if [[ -z "$SERVER_ENDPOINT" ]]; then
        print_warning "Could not determine server endpoint from existing config"
        read -p "Enter server public IP/domain: " SERVER_ENDPOINT
    fi

    print_success "Current client IP: ${CLIENT_IP}"
    print_success "Server endpoint: ${SERVER_ENDPOINT}:${SERVER_PORT}"
}


generate_new_keys() {
    local keys_dir="${WG_CONFIG_DIR}/${WG_INTERFACE}"

    print_info "Generating new encryption keys..."

    cd "$keys_dir" || error_exit "Failed to access ${keys_dir}"

    umask 077

    local private_key_file="${keys_dir}/${CLIENT_NAME}-privatekey"
    local public_key_file="${keys_dir}/${CLIENT_NAME}-publickey"

    wg genkey | tee "$private_key_file" | wg pubkey > "$public_key_file" || error_exit "Failed to generate keys"
    chmod 600 "$private_key_file" "$public_key_file"

    CLIENT_PRIVATE_KEY=$(cat "$private_key_file")
    CLIENT_PUBLIC_KEY=$(cat "$public_key_file")

    print_success "New keys generated"
}

update_server_config() {
    local config_file="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"
    local backup_file="${config_file}.backup.$(date +%Y%m%d_%H%M%S)"

    print_info "Updating server configuration with new public key..."

    # Backup server config
    cp "$config_file" "$backup_file"

    # Find and update the client's public key
    local temp_file=$(mktemp)
    local in_client_section=0

    while IFS= read -r line; do
        # Check if this is our client comment
        if [[ "$line" =~ ^#\ Client:\ ${CLIENT_NAME}$ ]]; then
            in_client_section=1
            echo "$line" >> "$temp_file"
        # Update PublicKey if we're in this client's section
        elif [[ $in_client_section -eq 1 ]] && [[ "$line" =~ ^PublicKey ]]; then
            echo "PublicKey = ${CLIENT_PUBLIC_KEY}" >> "$temp_file"
            in_client_section=0
        else
            echo "$line" >> "$temp_file"
        fi
    done < "$config_file"

    # Replace original config
    mv "$temp_file" "$config_file"
    chmod 600 "$config_file"

    print_success "Server config updated"
    print_info "Backup saved to: $backup_file"
}

create_new_client_config() {
    local keys_dir="${WG_CONFIG_DIR}/${WG_INTERFACE}"
    local client_config_file="${keys_dir}/${CLIENT_NAME}.conf"

    print_info "Creating new client configuration..."

    cat > "$client_config_file" <<EOF
[Interface]
PrivateKey = ${CLIENT_PRIVATE_KEY}
Address = ${CLIENT_IP}
DNS = 8.8.8.8

[Peer]
PublicKey = ${SERVER_PUBLIC_KEY}
Endpoint = ${SERVER_ENDPOINT}:${SERVER_PORT}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

    chmod 600 "$client_config_file"

    print_success "New client config created: ${client_config_file}"
}

reload_server() {
    print_info "Reloading WireGuard configuration without dropping connections..."

    # Use wg syncconf to reload config without disrupting active connections
    wg syncconf "${WG_INTERFACE}" <(wg-quick strip "${WG_INTERFACE}") || error_exit "Failed to reload ${WG_INTERFACE}"

    print_success "WireGuard configuration reloaded for ${WG_INTERFACE}"
    print_info "Other active connections remain intact"
}

show_summary() {
    local keys_dir="${WG_CONFIG_DIR}/${WG_INTERFACE}"
    local client_config_file="${keys_dir}/${CLIENT_NAME}.conf"

    echo ""
    echo "=========================================="
    print_success "Keys Rotated Successfully!"
    echo "=========================================="
    echo ""
    print_info "Client: ${CLIENT_NAME}"
    print_info "Server: ${WG_INTERFACE}"
    echo ""
    print_warning "IMPORTANT: Client must update their configuration!"
    echo ""
    print_info "New Client Configuration:"
    echo "  ${client_config_file}"
    echo ""
    print_info "Distribute new config to client:"
    echo "  1. Copy config to client device:"
    echo "     scp root@server:${client_config_file} ~/"
    echo ""
    echo "  2. Or display as QR code:"
    echo "     sudo ./qr-show.sh --interface ${WG_INTERFACE} --client ${CLIENT_NAME}"
    echo ""
    print_warning "Client is now disconnected and needs the new config to reconnect!"
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
                echo "  -c, --client NAME       Client name"
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
    echo "  WireGuard Rotate Client Keys"
    echo "=========================================="
    echo ""

    parse_arguments "$@"

    check_root
    select_server
    select_client
    get_current_client_info

    echo ""
    print_warning "This will PERMANENTLY regenerate encryption keys for '${CLIENT_NAME}'"
    print_warning "The client will be disconnected until they get the new config!"
    echo ""
    print_info "NOTE: Old keys will be OVERWRITTEN. To backup first:"
    echo "  cp -r /etc/wireguard/${WG_INTERFACE}/${CLIENT_NAME}* /tmp/backup/"
    echo ""
    read -p "Continue? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        error_exit "Key rotation cancelled"
    fi

    generate_new_keys
    update_server_config
    create_new_client_config
    reload_server
    show_summary
}

main "$@"
