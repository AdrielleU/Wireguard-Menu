#!/bin/bash
################################################################################
# WireGuard Add Client Script
# Description: Safely add a new client to a specific WireGuard server
# Usage: sudo ./add-client.sh [OPTIONS]
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

    # Check if server is running
    if ! systemctl is-active --quiet "wg-quick@${WG_INTERFACE}"; then
        echo ""
        print_warning "WireGuard server '${WG_INTERFACE}' is not running."
        read -p "Do you want to start it? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            systemctl start "wg-quick@${WG_INTERFACE}" || error_exit "Failed to start ${WG_INTERFACE}"
            print_success "Started wg-quick@${WG_INTERFACE}"
        fi
    fi
}

get_server_info() {
    local config_file="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"

    # Get server network
    local server_ip=$(grep -E "^Address\s*=" "$config_file" | head -n1 | awk '{print $3}')
    local server_network=$(echo "$server_ip" | cut -d'/' -f1 | awk -F. '{print $1"."$2"."$3}')

    # Get server port
    SERVER_PORT=$(grep -E "^ListenPort\s*=" "$config_file" | head -n1 | awk '{print $3}')

    # Get server public key
    local keys_dir="${WG_CONFIG_DIR}/${WG_INTERFACE}"
    if [[ -f "${keys_dir}/server-publickey" ]]; then
        SERVER_PUBLIC_KEY=$(cat "${keys_dir}/server-publickey")
    else
        error_exit "Server public key not found at ${keys_dir}/server-publickey"
    fi

    print_info "Server network: ${server_network}.0/24"
    print_info "Server port: ${SERVER_PORT}"

    echo "$server_network"
}

get_next_available_ip() {
    local server_network="$1"
    local config_file="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"

    # Get all used IPs from config
    local used_ips=$(grep -E "AllowedIPs\s*=" "$config_file" | awk '{print $3}' | cut -d'/' -f1 | cut -d'.' -f4 | sort -n)

    # Find next available IP (start from .2, server is usually .1)
    for i in {2..254}; do
        if ! echo "$used_ips" | grep -q "^${i}$"; then
            echo "${server_network}.${i}"
            return
        fi
    done

    error_exit "No available IP addresses in the ${server_network}.0/24 range"
}

prompt_client_info() {
    print_info "Client Configuration"
    echo ""

    # Get server network
    local server_network=$(get_server_info)

    # Prompt for client name
    if [[ -z "$CLIENT_NAME" ]]; then
        read -p "Enter client name (e.g., laptop, phone, john): " CLIENT_NAME
    fi

    # Validate client name
    if [[ -z "$CLIENT_NAME" ]]; then
        error_exit "Client name cannot be empty"
    fi

    # Check if client already exists using list-clients.sh
    if ./list-clients.sh "${WG_INTERFACE}" --check "${CLIENT_NAME}" 2>/dev/null; then
        print_warning "Client '${CLIENT_NAME}' already exists for ${WG_INTERFACE}"
        read -p "Do you want to regenerate keys? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            error_exit "Client addition cancelled"
        fi
    fi

    # Get next available IP
    local suggested_ip=$(get_next_available_ip "$server_network")

    # Prompt for client IP
    if [[ -z "$CLIENT_IP" ]]; then
        read -p "Enter client IP address [${suggested_ip}]: " input_ip
        CLIENT_IP="${input_ip:-$suggested_ip}"
    fi

    # Validate IP is in correct network
    local client_network=$(echo "$CLIENT_IP" | awk -F. '{print $1"."$2"."$3}')
    if [[ "$client_network" != "$server_network" ]]; then
        error_exit "Client IP must be in the ${server_network}.0/24 network"
    fi

    # Prompt for server endpoint
    if [[ -z "$SERVER_ENDPOINT" ]]; then
        print_info "Enter the server's public IP address or domain name"
        read -p "Server endpoint: " SERVER_ENDPOINT
    fi

    if [[ -z "$SERVER_ENDPOINT" ]]; then
        error_exit "Server endpoint cannot be empty"
    fi

    print_success "Client name: ${CLIENT_NAME}"
    print_success "Client IP: ${CLIENT_IP}/32"
    print_success "Server endpoint: ${SERVER_ENDPOINT}:${SERVER_PORT}"
}

generate_client_keys() {
    local keys_dir="${WG_CONFIG_DIR}/${WG_INTERFACE}"

    print_info "Generating client keys..."

    cd "$keys_dir" || error_exit "Failed to access ${keys_dir}"

    umask 077

    local private_key_file="${keys_dir}/${CLIENT_NAME}-privatekey"
    local public_key_file="${keys_dir}/${CLIENT_NAME}-publickey"

    wg genkey | tee "$private_key_file" | wg pubkey > "$public_key_file" || error_exit "Failed to generate keys"
    chmod 600 "$private_key_file" "$public_key_file"

    CLIENT_PRIVATE_KEY=$(cat "$private_key_file")
    CLIENT_PUBLIC_KEY=$(cat "$public_key_file")

    print_success "Client keys generated: ${private_key_file}"
}

add_client_to_server_config() {
    local config_file="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"

    print_info "Adding client to server configuration..."

    # Add peer to config
    cat >> "$config_file" <<EOF

# Client: ${CLIENT_NAME}
[Peer]
PublicKey = ${CLIENT_PUBLIC_KEY}
AllowedIPs = ${CLIENT_IP}/32
EOF

    print_success "Client added to ${config_file}"
}

create_client_config() {
    local keys_dir="${WG_CONFIG_DIR}/${WG_INTERFACE}"
    local client_config_file="${keys_dir}/${CLIENT_NAME}.conf"

    print_info "Creating client configuration file..."

    cat > "$client_config_file" <<EOF
[Interface]
PrivateKey = ${CLIENT_PRIVATE_KEY}
Address = ${CLIENT_IP}/32
DNS = 8.8.8.8

[Peer]
PublicKey = ${SERVER_PUBLIC_KEY}
Endpoint = ${SERVER_ENDPOINT}:${SERVER_PORT}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

    chmod 600 "$client_config_file"

    print_success "Client config created: ${client_config_file}"
}

reload_server() {
    print_info "Reloading WireGuard configuration without dropping connections..."

    # Use wg syncconf to reload config without disrupting active connections
    wg syncconf "${WG_INTERFACE}" <(wg-quick strip "${WG_INTERFACE}") || error_exit "Failed to reload ${WG_INTERFACE}"

    print_success "WireGuard configuration reloaded for ${WG_INTERFACE}"
    print_info "Active connections remain intact"
}

show_summary() {
    local keys_dir="${WG_CONFIG_DIR}/${WG_INTERFACE}"
    local client_config_file="${keys_dir}/${CLIENT_NAME}.conf"

    echo ""
    echo "=========================================="
    print_success "Client Added Successfully!"
    echo "=========================================="
    echo ""
    print_info "Client Details:"
    echo "  Name: ${CLIENT_NAME}"
    echo "  IP: ${CLIENT_IP}/32"
    echo "  Server: ${WG_INTERFACE}"
    echo ""
    print_info "Client Configuration File:"
    echo "  ${client_config_file}"
    echo ""
    print_info "Next Steps:"
    echo "  1. Copy the client config to your device:"
    echo "     scp root@server:${client_config_file} ~/"
    echo ""
    echo "  2. Or display as QR code for mobile:"
    echo "     sudo qrencode -t ansiutf8 < ${client_config_file}"
    echo "     (Install qrencode: dnf install qrencode)"
    echo ""
    echo "  3. Import the config on your client device"
    echo ""
    print_info "View client config:"
    echo "  sudo cat ${client_config_file}"
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
            --ip)
                CLIENT_IP="$2"
                shift 2
                ;;
            --endpoint|-e)
                SERVER_ENDPOINT="$2"
                shift 2
                ;;
            -h|--help)
                echo "Usage: sudo $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  -i, --interface NAME    WireGuard interface (e.g., wg0)"
                echo "  -c, --client NAME       Client name"
                echo "  --ip IP                 Client IP address"
                echo "  -e, --endpoint ADDR     Server public IP/domain"
                echo "  -h, --help             Show this help"
                echo ""
                echo "Example:"
                echo "  sudo $0 --interface wg0 --client laptop"
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
    echo "  WireGuard Add Client"
    echo "=========================================="
    echo ""

    parse_arguments "$@"

    check_root
    select_server
    prompt_client_info

    echo ""
    read -p "Continue with this configuration? (Y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        error_exit "Client addition cancelled"
    fi

    generate_client_keys
    add_client_to_server_config
    create_client_config
    reload_server
    show_summary
}

main "$@"
