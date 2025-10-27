#!/bin/bash
################################################################################
# WireGuard Add Site-to-Site Script
# Description: Create site-to-site VPN tunnel between two WireGuard servers
# Usage: sudo ./add-site-to-site.sh [OPTIONS]
################################################################################

set -euo pipefail

################################################################################
# CONFIGURATION
################################################################################

WG_CONFIG_DIR="/etc/wireguard"
SITE_NAME=""
WG_INTERFACE=""
TUNNEL_IP=""
REMOTE_NETWORK=""
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

validate_cidr() {
    local cidr="$1"
    if [[ "$cidr" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
        return 0
    else
        return 1
    fi
}

validate_ip() {
    local ip="$1"
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        return 0
    else
        return 1
    fi
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

get_local_network() {
    local config_file="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"
    local server_address=$(grep -E "^Address\s*=" "$config_file" | head -n1 | awk '{print $3}')

    # Extract network from server address (e.g., 10.0.0.1/24 -> 10.0.0.0/24)
    local network_base=$(echo "$server_address" | cut -d'/' -f1 | awk -F. '{print $1"."$2"."$3".0"}')
    local network_cidr=$(echo "$server_address" | cut -d'/' -f2)

    echo "${network_base}/${network_cidr}"
}

get_primary_interface_network() {
    # Detect primary network interface
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

get_next_tunnel_ip() {
    local config_file="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"
    local server_address=$(grep -E "^Address\s*=" "$config_file" | head -n1 | awk '{print $3}')
    local network_base=$(echo "$server_address" | cut -d'/' -f1 | awk -F. '{print $1"."$2"."$3}')

    # Get all used IPs from config (same logic as add-client.sh)
    local used_ips=$(grep -E "AllowedIPs\s*=" "$config_file" | awk '{print $3}' | cut -d',' -f1 | cut -d'/' -f1 | cut -d'.' -f4 | sort -n)

    # Find next available IP (start from .2, server is usually .1)
    for i in {2..254}; do
        if ! echo "$used_ips" | grep -q "^${i}$"; then
            echo "${network_base}.${i}"
            return
        fi
    done

    error_exit "No available IP addresses in the ${network_base}.0/24 range"
}

get_public_ip() {
    local public_ip=""

    # Try ipify.org
    public_ip=$(curl -s --connect-timeout 3 --max-time 5 https://api.ipify.org 2>/dev/null)
    if [[ -n "$public_ip" ]] && [[ "$public_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "$public_ip"
        return
    fi

    # Try icanhazip.com
    public_ip=$(curl -s --connect-timeout 3 --max-time 5 https://icanhazip.com 2>/dev/null | tr -d '\n')
    if [[ -n "$public_ip" ]] && [[ "$public_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "$public_ip"
        return
    fi

    # Try ifconfig.me
    public_ip=$(curl -s --connect-timeout 3 --max-time 5 https://ifconfig.me 2>/dev/null)
    if [[ -n "$public_ip" ]] && [[ "$public_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "$public_ip"
        return
    fi

    echo ""
}

prompt_site_config() {
    local config_file="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"

    echo ""
    print_info "Site-to-Site VPN Configuration"
    echo ""
    print_info "The remote site will connect TO this server"
    echo ""

    # Site Name (like client name)
    if [[ -z "$SITE_NAME" ]]; then
        echo "Site Name: A descriptive name for the remote site"
        echo "  Examples: branch-office, datacenter-east, office-la"
        read -p "Enter site name: " SITE_NAME

        if [[ -z "$SITE_NAME" ]]; then
            error_exit "Site name is required"
        fi

        # Validate site name doesn't already exist
        if grep -q "^# Site: ${SITE_NAME}$" "$config_file" 2>/dev/null; then
            error_exit "Site '${SITE_NAME}' already exists in ${WG_INTERFACE}"
        fi
    fi

    # Remote Network (REQUIRED) - Ask this FIRST before tunnel IP
    if [[ -z "$REMOTE_NETWORK" ]]; then
        echo ""
        echo "Remote Site's LAN Network: The network behind the remote site (Site B)"
        echo "  This is what Site A (this server) will route TO"
        echo "  Examples: 192.168.50.0/24, 10.100.0.0/16, 172.16.5.0/24"
        print_warning "This is REQUIRED - the remote LAN you want to access"
        read -p "Enter remote site's LAN network CIDR: " REMOTE_NETWORK

        if [[ -z "$REMOTE_NETWORK" ]]; then
            error_exit "Remote network CIDR is required for site-to-site VPN"
        fi
    fi

    # Validate remote network
    if ! validate_cidr "$REMOTE_NETWORK"; then
        error_exit "Invalid remote network CIDR format (e.g., 192.168.50.0/24)"
    fi

    # Tunnel IP (next available from VPN network) - Ask AFTER remote network
    if [[ -z "$TUNNEL_IP" ]]; then
        local server_network=$(echo "$(grep -E "^Address\s*=" "$config_file" | head -n1 | awk '{print $3}')" | cut -d'/' -f1 | awk -F. '{print $1"."$2"."$3}')
        local server_cidr=$(grep -E "^Address\s*=" "$config_file" | head -n1 | awk '{print $3}' | cut -d'/' -f2)
        local suggested_ip=$(get_next_tunnel_ip)
        echo ""
        echo "Tunnel IP: IP address to assign to remote site on VPN tunnel"
        echo "  Suggested: ${suggested_ip}/${server_cidr} (next available)"
        echo "  Range: ${server_network}.2 - ${server_network}.254"
        echo "  Note: CIDR should match server's VPN network (/${server_cidr})"
        echo ""
        read -p "Enter tunnel IP with CIDR [${suggested_ip}/${server_cidr}]: " input_ip
        TUNNEL_IP="${input_ip:-${suggested_ip}/${server_cidr}}"
    fi

    # Add CIDR if not already present (use server's CIDR, not /32)
    if [[ ! "$TUNNEL_IP" =~ / ]]; then
        local server_cidr=$(grep -E "^Address\s*=" "$config_file" | head -n1 | awk '{print $3}' | cut -d'/' -f2)
        TUNNEL_IP="${TUNNEL_IP}/${server_cidr}"
    fi

    # Validate tunnel IP format
    if ! validate_cidr "$TUNNEL_IP"; then
        error_exit "Invalid tunnel IP format. Use CIDR notation (e.g., 10.0.0.2/24)"
    fi

    # Validate IP is in correct network
    local tunnel_network=$(echo "$TUNNEL_IP" | cut -d'/' -f1 | awk -F. '{print $1"."$2"."$3}')
    local server_network=$(echo "$(grep -E "^Address\s*=" "$config_file" | head -n1 | awk '{print $3}')" | cut -d'/' -f1 | awk -F. '{print $1"."$2"."$3}')
    if [[ "$tunnel_network" != "$server_network" ]]; then
        error_exit "Tunnel IP must be in the ${server_network}.0/24 network"
    fi

    # Get server info for remote site config
    SERVER_PORT=$(grep -E "^ListenPort\s*=" "$config_file" | head -n1 | awk '{print $3}')

    # Get server public key
    local keys_dir="${WG_CONFIG_DIR}/${WG_INTERFACE}"
    if [[ -f "${keys_dir}/server-publickey" ]]; then
        SERVER_PUBLIC_KEY=$(cat "${keys_dir}/server-publickey")
    else
        error_exit "Server public key not found at ${keys_dir}/server-publickey"
    fi

    local server_public_ip=$(get_public_ip)

    if [[ -n "$server_public_ip" ]]; then
        echo ""
        print_info "Detected this server's public IP: ${server_public_ip}"
        read -p "Confirm or enter this server's public IP/domain [${server_public_ip}]: " SERVER_ENDPOINT
        SERVER_ENDPOINT="${SERVER_ENDPOINT:-$server_public_ip}"
    else
        echo ""
        print_warning "Could not auto-detect public IP"
        read -p "Enter this server's public IP/domain: " SERVER_ENDPOINT
    fi

    print_success "Configuration complete"
}

generate_keypair() {
    local keys_dir="${WG_CONFIG_DIR}/${WG_INTERFACE}"

    print_info "Generating encryption keys for remote site..."

    mkdir -p "$keys_dir"
    cd "$keys_dir" || error_exit "Failed to access ${keys_dir}"

    umask 077

    local private_key_file="${keys_dir}/${SITE_NAME}-privatekey"
    local public_key_file="${keys_dir}/${SITE_NAME}-publickey"

    wg genkey | tee "$private_key_file" | wg pubkey > "$public_key_file" || error_exit "Failed to generate keys"
    chmod 600 "$private_key_file" "$public_key_file"

    SITE_PRIVATE_KEY=$(cat "$private_key_file")
    SITE_PUBLIC_KEY=$(cat "$public_key_file")

    print_success "Keys generated"
}

add_peer_to_server() {
    local config_file="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"

    print_info "Adding remote site peer to server configuration..."

    # Extract just the IP without CIDR for AllowedIPs on server side
    local tunnel_ip_only=$(echo "$TUNNEL_IP" | cut -d'/' -f1)

    # Add peer configuration - tunnel IP as /32 + remote network
    cat >> "$config_file" <<EOF

# Site: ${SITE_NAME}
[Peer]
PublicKey = ${SITE_PUBLIC_KEY}
AllowedIPs = ${tunnel_ip_only}/32, ${REMOTE_NETWORK}
EOF

    print_success "Peer added to ${config_file}"
}

create_remote_site_config() {
    local keys_dir="${WG_CONFIG_DIR}/${WG_INTERFACE}"
    local site_config_file="${keys_dir}/${SITE_NAME}.conf"
    local config_file="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"

    print_info "Creating configuration for remote site..."

    # Configure routing for remote site (if not already set via command-line)
    local vpn_network=$(get_local_network)
    local local_network=""

    if [[ -z "$ALLOWED_IPS" ]]; then
        echo ""
        print_info "Configuring what Site B (remote) can access on Site A (this server)"
        echo ""
        echo "Traffic Routing: Choose what networks remote site should access"
        echo ""
        echo "  1) VPN tunnel network + Server's LAN [RECOMMENDED for site-to-site]"
        echo "     Remote site can access VPN clients AND server's internal LAN"
        echo ""
        echo "  2) VPN tunnel network only"
        echo "     Remote site can only access other VPN clients"
        echo ""
        echo "  3) All traffic (0.0.0.0/0) - Use VPN as exit node"
        echo "     Routes ALL remote site's internet traffic through VPN"
        echo ""
        read -p "Select routing mode (1-3) [1]: " routing_choice
        routing_choice="${routing_choice:-1}"

        case "$routing_choice" in
            1)
                # Site-to-site: VPN network + Local LAN
                ALLOWED_IPS="${vpn_network}"

                # Get Site A's local network
                local detected_network=$(get_primary_interface_network)
                echo ""
                echo "Site A's (this server's) internal LAN network:"
                echo "  This is the local network that Site B will be able to access"
                if [[ -n "$detected_network" ]]; then
                    print_info "Detected primary network: ${detected_network}"
                    echo "  Examples: 192.168.1.0/24, 10.0.0.0/24"
                    echo ""
                    read -p "Enter Site A's LAN network CIDR [${detected_network}]: " local_network
                    local_network="${local_network:-$detected_network}"
                else
                    echo "  Examples: 192.168.1.0/24, 10.0.0.0/24"
                    echo ""
                    read -p "Enter Site A's LAN network CIDR: " local_network
                fi

                if [[ -n "$local_network" ]]; then
                    ALLOWED_IPS="${ALLOWED_IPS}, ${local_network}"
                    ROUTING_DESC="VPN network (${vpn_network}) + Site A LAN (${local_network})"
                else
                    ROUTING_DESC="VPN network only (${vpn_network})"
                fi
                ;;
            2)
                # VPN network only
                ALLOWED_IPS="${vpn_network}"
                ROUTING_DESC="VPN tunnel network only (${vpn_network})"
                ;;
            3)
                # All traffic
                ALLOWED_IPS="0.0.0.0/0"
                ROUTING_DESC="All traffic through VPN (exit node)"
                ;;
            *)
                error_exit "Invalid routing mode selection"
                ;;
        esac
    elif [[ "$ALLOWED_IPS" == "vpn-only" ]]; then
        # Handle --route-vpn-only flag
        ALLOWED_IPS="${vpn_network}"
        ROUTING_DESC="VPN network only"
    fi

    # Default to VPN network if nothing selected
    if [[ -z "$ALLOWED_IPS" ]]; then
        ALLOWED_IPS="${vpn_network}"
        ROUTING_DESC="VPN network only (default)"
        print_info "Defaulting to VPN network only: ${vpn_network}"
    fi

    cat > "$site_config_file" <<EOF
[Interface]
PrivateKey = ${SITE_PRIVATE_KEY}
Address = ${TUNNEL_IP}

[Peer]
PublicKey = ${SERVER_PUBLIC_KEY}
Endpoint = ${SERVER_ENDPOINT}:${SERVER_PORT}
AllowedIPs = ${ALLOWED_IPS}
PersistentKeepalive = 25
EOF

    chmod 600 "$site_config_file"

    print_success "Remote site config created: ${site_config_file}"
    print_info "Site B (remote) will be able to access: ${ALLOWED_IPS}"
}

reload_server() {
    print_info "Reloading WireGuard configuration..."

    # Use wg syncconf to reload without dropping connections
    wg syncconf "${WG_INTERFACE}" <(wg-quick strip "${WG_INTERFACE}") || error_exit "Failed to reload ${WG_INTERFACE}"

    print_success "WireGuard configuration reloaded for ${WG_INTERFACE}"
    print_info "Existing connections remain intact"
}

show_summary() {
    local keys_dir="${WG_CONFIG_DIR}/${WG_INTERFACE}"
    local site_config_file="${keys_dir}/${SITE_NAME}.conf"
    local local_vpn_network=$(get_local_network)
    local tunnel_ip_only=$(echo "$TUNNEL_IP" | cut -d'/' -f1)

    echo ""
    echo "=========================================="
    print_success "Site-to-Site VPN Created!"
    echo "=========================================="
    echo ""
    print_info "Site A - Server (This Side):"
    echo "  Interface: ${WG_INTERFACE}"
    echo "  VPN Tunnel Network: ${local_vpn_network}"
    echo "  Public Endpoint: ${SERVER_ENDPOINT}:${SERVER_PORT}"
    echo "  Can route to Site B: ${tunnel_ip_only}/32, ${REMOTE_NETWORK}"
    echo ""
    print_info "Site B - Remote Site:"
    echo "  Name: ${SITE_NAME}"
    echo "  Tunnel IP: ${TUNNEL_IP}"
    echo "  LAN Network: ${REMOTE_NETWORK}"
    echo "  Can route to Site A: ${ALLOWED_IPS}"
    echo "  Config File: ${site_config_file}"
    echo ""
    print_info "Routing Summary:"
    echo "  ${ROUTING_DESC}"
    echo ""
    print_warning "NEXT STEPS - Deploy config to remote site:"
    echo ""
    echo "1. Copy configuration to remote site:"
    echo "   scp root@server:${site_config_file} remote-site:/etc/wireguard/wg-s2s.conf"
    echo ""
    echo "2. On the remote site, use setup-site-remote.sh to complete setup:"
    echo "   sudo ./setup-site-remote.sh --config /etc/wireguard/wg-s2s.conf"
    echo ""
    echo "   Or manually:"
    echo "   sudo wg-quick up wg-s2s"
    echo "   sudo systemctl enable wg-quick@wg-s2s"
    echo ""
    echo "3. Test connectivity from this server (Site A):"
    echo "   ping ${tunnel_ip_only}  # Ping remote tunnel IP"
    echo "   ping <IP-in-${REMOTE_NETWORK}>  # Ping device on remote LAN"
    echo ""
    echo "4. Test connectivity from remote site (Site B):"
    echo "   ping ${local_vpn_network%/*}1  # Ping this server's tunnel IP"
    if [[ "$ALLOWED_IPS" =~ "," ]]; then
        echo "   ping <IP-in-Site-A-LAN>  # Ping device on this server's LAN"
    fi
    echo ""
    print_info "Traffic Flow: Site A LAN <-> VPN Tunnel <-> Site B LAN"
    print_info "For LAN relay (Site B devices routing through VPN): Use setup-site-remote.sh"
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
            --site-name|-s)
                SITE_NAME="$2"
                shift 2
                ;;
            --tunnel-ip|-t)
                TUNNEL_IP="$2"
                shift 2
                ;;
            --remote-network|-r)
                REMOTE_NETWORK="$2"
                shift 2
                ;;
            --route-all)
                ALLOWED_IPS="0.0.0.0/0"
                ROUTING_DESC="All traffic through VPN (exit node)"
                shift
                ;;
            --route-vpn-only)
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
                echo "  -i, --interface NAME         WireGuard interface (e.g., wg0)"
                echo "  -s, --site-name NAME         Remote site name"
                echo "  -t, --tunnel-ip IP           Tunnel IP for remote site (CIDR)"
                echo "  -r, --remote-network CIDR    Remote site's LAN network (REQUIRED)"
                echo ""
                echo "Routing Options:"
                echo "  --route-all                  Route all traffic (0.0.0.0/0, exit node)"
                echo "  --route-vpn-only             Route only VPN network traffic"
                echo "  --route-custom CIDR          Custom AllowedIPs (e.g., '10.0.0.0/24,192.168.1.0/24')"
                echo ""
                echo "  -h, --help                   Show this help"
                echo ""
                echo "Description:"
                echo "  Creates a site-to-site VPN where the remote site connects TO this server"
                echo "  (like a client, but routes an entire network instead of single IP)"
                echo ""
                echo "Examples:"
                echo "  # Interactive mode"
                echo "  sudo $0"
                echo ""
                echo "  # Basic site-to-site"
                echo "  sudo $0 -i wg0 -s branch-office -r 192.168.50.0/24"
                echo ""
                echo "  # Site-to-site with all traffic routed (exit node)"
                echo "  sudo $0 -i wg0 -s branch-office -r 192.168.50.0/24 --route-all"
                echo ""
                echo "  # Site-to-site with VPN network only"
                echo "  sudo $0 -i wg0 -s branch-office -r 192.168.50.0/24 --route-vpn-only"
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
    echo "  WireGuard Site-to-Site VPN Setup"
    echo "=========================================="
    echo ""

    parse_arguments "$@"

    check_root
    select_server
    prompt_site_config
    generate_keypair
    add_peer_to_server
    create_remote_site_config
    reload_server
    show_summary
}

main "$@"
