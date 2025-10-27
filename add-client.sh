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
SERVER_NETWORK=""
SERVER_PUBLIC_KEY=""
SERVER_ENDPOINT=""
SERVER_PORT=""
ALLOWED_IPS=""
ROUTING_DESC=""

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
    SERVER_NETWORK=$(echo "$server_ip" | cut -d'/' -f1 | awk -F. '{print $1"."$2"."$3}')

    # Get server port
    SERVER_PORT=$(grep -E "^ListenPort\s*=" "$config_file" | head -n1 | awk '{print $3}')

    # Get server public key
    local keys_dir="${WG_CONFIG_DIR}/${WG_INTERFACE}"
    if [[ -f "${keys_dir}/server-publickey" ]]; then
        SERVER_PUBLIC_KEY=$(cat "${keys_dir}/server-publickey")
    else
        error_exit "Server public key not found at ${keys_dir}/server-publickey"
    fi
}

get_primary_interface_network() {
    # Detect primary network interface (same as setup-wireguard.sh)
    local primary_iface=$(ip route | grep default | awk '{print $5}' | head -n1)

    if [[ -z "$primary_iface" ]]; then
        echo ""
        return
    fi

    # Get the IP/CIDR from primary interface
    local iface_ip=$(ip -4 addr show "$primary_iface" | grep -oP 'inet \K[\d.]+/\d+' | head -n1)

    if [[ -z "$iface_ip" ]]; then
        echo ""
        return
    fi

    # Convert to network address (e.g., 192.168.1.50/24 -> 192.168.1.0/24)
    local ip_addr=$(echo "$iface_ip" | cut -d'/' -f1)
    local cidr=$(echo "$iface_ip" | cut -d'/' -f2)

    # If CIDR is empty, not set properly, or /32 (single host), default to /24
    if [[ -z "$cidr" ]] || [[ "$cidr" == "32" ]]; then
        cidr="24"
    fi

    local network_base=$(echo "$ip_addr" | awk -F. '{print $1"."$2"."$3".0"}')

    echo "${network_base}/${cidr}"
}

get_public_ip() {
    # Try multiple services to detect public IP
    local public_ip=""

    # Try ipify.org (fast and reliable)
    public_ip=$(curl -s --connect-timeout 3 --max-time 5 https://api.ipify.org 2>/dev/null)
    if [[ -n "$public_ip" ]] && [[ "$public_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "$public_ip"
        return
    fi

    # Try icanhazip.com as fallback
    public_ip=$(curl -s --connect-timeout 3 --max-time 5 https://icanhazip.com 2>/dev/null | tr -d '\n')
    if [[ -n "$public_ip" ]] && [[ "$public_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "$public_ip"
        return
    fi

    # Try ifconfig.me as second fallback
    public_ip=$(curl -s --connect-timeout 3 --max-time 5 https://ifconfig.me 2>/dev/null)
    if [[ -n "$public_ip" ]] && [[ "$public_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "$public_ip"
        return
    fi

    # Could not detect
    echo ""
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

    # Get server network and info (don't use command substitution to preserve global vars)
    get_server_info
    local server_network="${SERVER_NETWORK}"

    # Display server info first
    print_info "Server network: ${server_network}.0/24"
    print_info "Server port: ${SERVER_PORT}"
    echo ""

    # Prompt for client name
    if [[ -z "$CLIENT_NAME" ]]; then
        echo "Client name: A unique identifier for this device/user"
        echo "  Examples: laptop, phone, alice-laptop, bob-phone"
        echo ""
        read -p "Enter client name: " CLIENT_NAME
    fi

    # Validate client name
    if [[ -z "$CLIENT_NAME" ]]; then
        error_exit "Client name cannot be empty"
    fi

    # Check if client already exists using list-clients.sh
    if ./list-clients.sh "${WG_INTERFACE}" --check "${CLIENT_NAME}" 2>/dev/null; then
        echo ""
        print_warning "Client '${CLIENT_NAME}' already exists for ${WG_INTERFACE}"
        read -p "Do you want to regenerate keys? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            error_exit "Client addition cancelled"
        fi
    fi

    echo ""

    # Get next available IP
    local suggested_ip=$(get_next_available_ip "$server_network")

    # Prompt for client IP with auto-assignment
    if [[ -z "$CLIENT_IP" ]]; then
        echo "Client VPN IP: Internal IP address for this client on the VPN network"
        echo "  Suggested: ${suggested_ip} (next available)"
        echo "  Range: ${server_network}.2 - ${server_network}.254"
        echo ""
        read -p "Enter client VPN IP [${suggested_ip}]: " input_ip
        CLIENT_IP="${input_ip:-$suggested_ip}"
    fi

    # Validate IP is in correct network
    local client_network=$(echo "$CLIENT_IP" | awk -F. '{print $1"."$2"."$3}')
    if [[ "$client_network" != "$server_network" ]]; then
        echo ""
        error_exit "Client IP must be in the ${server_network}.0/24 network"
    fi

    echo ""

    # Prompt for server endpoint
    if [[ -z "$SERVER_ENDPOINT" ]]; then
        echo "Server Endpoint: The public IP or domain name where clients connect"
        echo "  This is your server's EXTERNAL/PUBLIC address (not VPN address)"
        echo ""

        # Try to detect public IP
        local detected_public_ip=$(get_public_ip)

        if [[ -n "$detected_public_ip" ]]; then
            print_info "Detected public IP: ${detected_public_ip}"
            echo "  You can use this or enter a custom domain/IP"
            echo "  Examples: vpn.example.com, custom-ip-address"
            echo ""
            read -p "Enter server public IP or domain [${detected_public_ip}]: " SERVER_ENDPOINT
            SERVER_ENDPOINT="${SERVER_ENDPOINT:-$detected_public_ip}"
        else
            print_warning "Could not auto-detect public IP"
            echo "  Examples: 203.0.113.50, vpn.example.com, my-server.dyndns.org"
            echo ""
            read -p "Enter server public IP or domain: " SERVER_ENDPOINT
        fi
    fi

    if [[ -z "$SERVER_ENDPOINT" ]]; then
        error_exit "Server endpoint cannot be empty"
    fi

    echo ""

    # Prompt for routing mode (if not set via command-line)
    if [[ -z "$ALLOWED_IPS" ]]; then
        echo "Traffic Routing: Choose what traffic should go through the VPN tunnel"
        echo ""
        echo "  1) VPN + Server's internal network [RECOMMENDED]"
        echo "     Access VPN clients AND server's internal LAN"
        echo ""
        echo "  2) All traffic (0.0.0.0/0) - Use VPN as exit node"
        echo "     Routes ALL internet traffic through VPN for privacy/security"
        echo ""
        read -p "Select routing mode (1-2) [1]: " routing_choice
        routing_choice="${routing_choice:-1}"

        case "$routing_choice" in
            1)
                # Question 1: Include VPN network in trusted networks?
                echo ""
                echo "1) Include VPN network (${server_network}.0/24) in allowed routes?"
                read -p "   Allow VPN client-to-client traffic? (Y/n) [Y]: " include_vpn
                include_vpn="${include_vpn:-Y}"

                if [[ "$include_vpn" =~ ^[Yy]$ ]]; then
                    ALLOWED_IPS="${server_network}.0/24"
                else
                    ALLOWED_IPS=""
                fi

                # Question 2: What is the server's internal network?
                local detected_network=$(get_primary_interface_network)
                echo ""
                echo "2) Server's internal network (LAN) to access through VPN"
                if [[ -n "$detected_network" ]]; then
                    print_info "Detected primary network: ${detected_network}"
                    echo "   Examples: 192.168.1.0/24, 10.0.0.0/24"
                    echo ""
                    read -p "   Enter internal network CIDR [${detected_network}]: " internal_network
                    internal_network="${internal_network:-$detected_network}"
                else
                    echo "   Examples: 192.168.1.0/24, 10.0.0.0/24"
                    echo ""
                    read -p "   Enter internal network CIDR: " internal_network
                fi

                # Combine networks
                if [[ -n "$ALLOWED_IPS" ]] && [[ -n "$internal_network" ]]; then
                    ALLOWED_IPS="${ALLOWED_IPS},${internal_network}"
                    ROUTING_DESC="VPN network + Internal LAN (${internal_network})"
                elif [[ -n "$internal_network" ]]; then
                    ALLOWED_IPS="${internal_network}"
                    ROUTING_DESC="Internal LAN only (${internal_network})"
                elif [[ -n "$ALLOWED_IPS" ]]; then
                    ROUTING_DESC="VPN network only"
                else
                    error_exit "At least one network must be configured"
                fi
                ;;
            2)
                ALLOWED_IPS="0.0.0.0/0"
                ROUTING_DESC="All traffic through VPN (exit node)"
                ;;
            *)
                error_exit "Invalid routing mode selection"
                ;;
        esac
    elif [[ "$ALLOWED_IPS" == "vpn-only" ]]; then
        # Handle --route-vpn-only flag
        ALLOWED_IPS="${server_network}.0/24"
        ROUTING_DESC="VPN network only"
    fi

    echo ""
    echo "=========================================="
    print_success "Configuration Summary:"
    echo "  Client name: ${CLIENT_NAME}"
    echo "  Client VPN IP: ${CLIENT_IP}/32"
    echo "  Server endpoint: ${SERVER_ENDPOINT}:${SERVER_PORT}"
    echo "  Server VPN IP: ${server_network}.1/24"
    echo "  Traffic routing: ${ROUTING_DESC}"
    echo "  AllowedIPs: ${ALLOWED_IPS}"
    echo "=========================================="
    echo ""
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
AllowedIPs = ${ALLOWED_IPS}
PersistentKeepalive = 25
EOF

    chmod 600 "$client_config_file"

    print_success "Client config created: ${client_config_file}"
    print_info "Traffic routing: ${ROUTING_DESC}"
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
            --route-all)
                ALLOWED_IPS="0.0.0.0/0"
                ROUTING_DESC="All traffic through VPN (exit node)"
                shift
                ;;
            --route-vpn-only)
                # Will be set to VPN network in prompt_client_info
                ALLOWED_IPS="vpn-only"
                shift
                ;;
            --route-custom)
                ALLOWED_IPS="$2"
                ROUTING_DESC="Custom routing"
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
                echo "  --route-all             Route all traffic (0.0.0.0/0) - VPN exit node"
                echo "  --route-vpn-only        Route only VPN network traffic"
                echo "  --route-custom CIDR     Custom AllowedIPs (e.g., '10.0.0.0/24,192.168.1.0/24')"
                echo "  -h, --help             Show this help"
                echo ""
                echo "Examples:"
                echo "  sudo $0 --interface wg0 --client laptop --route-all"
                echo "  sudo $0 --interface wg0 --client phone --route-custom '10.188.128.0/24,192.168.1.0/24'"
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
