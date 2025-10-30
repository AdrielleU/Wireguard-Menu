#!/bin/bash
################################################################################
# WireGuard Add Peer Script
# Description: Add a client or site-to-site peer to WireGuard server
# Usage: sudo ./add-peer.sh [OPTIONS]
################################################################################

set -euo pipefail

################################################################################
# CONFIGURATION
################################################################################

WG_CONFIG_DIR="/etc/wireguard"

# Server endpoint port for client configs (external/public port clients connect to)
# Set this if your server uses port forwarding (e.g., external 51828 -> internal 51820)
# Leave empty to auto-detect from server's ListenPort in config
SERVER_PORT="51828"

PEER_NAME=""              # Client or site name
WG_INTERFACE=""
PEER_IP=""                # Client IP or tunnel IP for site
PEER_TYPE=""              # "client" or "site"
REMOTE_NETWORK=""         # For site-to-site only
SERVER_PUBLIC_KEY=""
SERVER_ENDPOINT=""
ALLOWED_IPS=""
ROUTING_DESC=""

# Keys
PEER_PRIVATE_KEY=""
PEER_PUBLIC_KEY=""

################################################################################
# COLORS
################################################################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

print_success() { echo -e "${GREEN}[✓]${NC} $1"; }
print_error() { echo -e "${RED}[✗]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_info() { echo -e "${BLUE}[i]${NC} $1"; }

################################################################################
# HELPER FUNCTIONS
################################################################################

error_exit() {
    print_error "$1"
    exit 1
}

check_root() {
    [[ $EUID -eq 0 ]] || error_exit "This script must be run as root (use sudo)"
}

validate_cidr() {
    [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]
}

validate_ip() {
    [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
}

detect_servers() {
    local servers=()

    if [[ -d "$WG_CONFIG_DIR" ]]; then
        shopt -s nullglob
        local conf_files=("$WG_CONFIG_DIR"/*.conf)
        shopt -u nullglob

        for conf in "${conf_files[@]}"; do
            [[ ! -f "$conf" ]] && continue
            servers+=("$(basename "$conf" .conf)")
        done
    fi

    [[ ${#servers[@]} -gt 0 ]] || error_exit "No WireGuard servers found. Run setup-wireguard.sh first."
    echo "${servers[@]}"
}

select_server() {
    local servers=($(detect_servers))
    local server_count=${#servers[@]}

    if [[ -n "$WG_INTERFACE" ]]; then
        [[ -f "${WG_CONFIG_DIR}/${WG_INTERFACE}.conf" ]] || error_exit "WireGuard server '${WG_INTERFACE}' not found."
        print_success "Using server: ${WG_INTERFACE}"
        return
    fi

    if [[ $server_count -eq 1 ]]; then
        WG_INTERFACE="${servers[0]}"
        return
    fi

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
    local network_base=$(echo "$server_address" | cut -d'/' -f1 | awk -F. '{print $1"."$2"."$3".0"}')
    local network_cidr=$(echo "$server_address" | cut -d'/' -f2)
    echo "${network_base}/${network_cidr}"
}

get_primary_interface_network() {
    local primary_iface=$(ip route | grep default | awk '{print $5}' | head -n1)
    [[ -z "$primary_iface" ]] && return

    local iface_ip=$(ip -4 addr show "$primary_iface" | grep -oP 'inet \K[\d.]+/\d+' | head -n1)
    [[ -z "$iface_ip" ]] && return

    local ip_addr=$(echo "$iface_ip" | cut -d'/' -f1)
    local cidr=$(echo "$iface_ip" | cut -d'/' -f2)
    [[ -z "$cidr" || "$cidr" == "32" ]] && cidr="24"

    local network_base=$(echo "$ip_addr" | awk -F. '{print $1"."$2"."$3".0"}')
    echo "${network_base}/${cidr}"
}

get_next_available_ip() {
    local config_file="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"
    local server_address=$(grep -E "^Address\s*=" "$config_file" | head -n1 | awk '{print $3}')
    local network_base=$(echo "$server_address" | cut -d'/' -f1 | awk -F. '{print $1"."$2"."$3}')
    local used_ips=$(grep -E "AllowedIPs\s*=" "$config_file" | awk '{print $3}' | cut -d',' -f1 | cut -d'/' -f1 | cut -d'.' -f4 | sort -n)

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
    for service in "https://api.ipify.org" "https://icanhazip.com" "https://ifconfig.me"; do
        public_ip=$(curl -s --connect-timeout 3 --max-time 5 "$service" 2>/dev/null | tr -d '\n')
        if [[ -n "$public_ip" ]] && [[ "$public_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "$public_ip"
            return
        fi
    done
}

reload_server() {
    print_info "Reloading WireGuard configuration..."
    wg syncconf "${WG_INTERFACE}" <(wg-quick strip "${WG_INTERFACE}") || error_exit "Failed to reload ${WG_INTERFACE}"
    print_success "WireGuard configuration reloaded for ${WG_INTERFACE}"
    print_info "Existing connections remain intact"
}

################################################################################
# PEER TYPE SELECTION
################################################################################

select_peer_type() {
    [[ -n "$PEER_TYPE" ]] && return 0

    echo ""
    echo "=========================================="
    echo -e "  ${CYAN}WireGuard Add Peer${NC}"
    echo "=========================================="
    echo ""
    print_info "What type of peer do you want to add?"
    echo ""
    echo -e "  ${CYAN}1)${NC} Client"
    echo "     Single device (laptop, phone, desktop)"
    echo "     Access: VPN network, optionally route all traffic"
    echo ""
    echo -e "  ${CYAN}2)${NC} Site"
    echo "     Remote network/office (site-to-site VPN)"
    echo "     Access: Connect entire networks together"
    echo ""
    read -p "Select peer type (1-2): " peer_choice

    case "$peer_choice" in
        1) PEER_TYPE="client"; print_success "Selected: Client" ;;
        2) PEER_TYPE="site"; print_success "Selected: Site (site-to-site)" ;;
        *) error_exit "Invalid selection" ;;
    esac
    echo ""
}

################################################################################
# UNIFIED PEER CONFIGURATION FUNCTIONS
################################################################################

get_server_info() {
    local config_file="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"

    # Get server's listening port
    local server_listen_port=$(grep -E "^ListenPort\s*=" "$config_file" | head -n1 | awk '{print $3}')

    # Get server public key
    local keys_dir="${WG_CONFIG_DIR}/${WG_INTERFACE}"
    if [[ -f "${keys_dir}/server-publickey" ]]; then
        SERVER_PUBLIC_KEY=$(cat "${keys_dir}/server-publickey")
    else
        error_exit "Server public key not found at ${keys_dir}/server-publickey"
    fi

    # Get server endpoint
    local server_public_ip=$(get_public_ip)
    if [[ -n "$server_public_ip" ]]; then
        echo ""
        print_info "Detected this server's public IP: ${server_public_ip}"
        read -p "Confirm or enter server's public IP/domain [${server_public_ip}]: " SERVER_ENDPOINT
        SERVER_ENDPOINT="${SERVER_ENDPOINT:-$server_public_ip}"
    else
        echo ""
        print_warning "Could not auto-detect public IP"
        read -p "Enter server's public IP/domain: " SERVER_ENDPOINT
    fi

    # Get endpoint port (use configured SERVER_PORT or prompt if empty)
    # Note: SERVER_PORT may already be set at top of script or via --port flag
    local server_port_configured="$SERVER_PORT"

    # If SERVER_PORT is empty, prompt for it
    if [[ -z "$server_port_configured" ]]; then
        echo ""
        echo "Server Endpoint Port: Port that clients will connect to"
        echo "  Server's listening port: ${server_listen_port}"
        echo "  Note: Use different port if server is behind NAT/firewall with port forwarding"
        echo ""
        read -p "Enter endpoint port [${server_listen_port}]: " input_port
        SERVER_PORT="${input_port:-$server_listen_port}"
    elif [[ "$server_port_configured" != "$server_listen_port" ]]; then
        # Show info when configured port differs from listening port
        print_info "Using configured endpoint port: ${server_port_configured} (server listens on ${server_listen_port})"
    fi

    # Validate port number
    if ! [[ "$SERVER_PORT" =~ ^[0-9]+$ ]] || [ "$SERVER_PORT" -lt 1 ] || [ "$SERVER_PORT" -gt 65535 ]; then
        error_exit "Invalid port number. Must be between 1-65535"
    fi
}

prompt_peer_name() {
    local config_file="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"
    local name_type="$([[ "$PEER_TYPE" == "client" ]] && echo "Client" || echo "Site")"
    local examples="$([[ "$PEER_TYPE" == "client" ]] && echo "laptop-john, phone-alice, desktop-work" || echo "branch-office, datacenter-east, office-la")"

    if [[ -z "$PEER_NAME" ]]; then
        echo "${name_type} Name: A descriptive name for this ${PEER_TYPE}"
        echo "  Examples: ${examples}"
        read -p "Enter ${PEER_TYPE} name: " PEER_NAME

        [[ -z "$PEER_NAME" ]] && error_exit "${name_type} name is required"

        # Check if name already exists
        if grep -q "^# ${name_type}: ${PEER_NAME}$" "$config_file" 2>/dev/null; then
            error_exit "${name_type} '${PEER_NAME}' already exists in ${WG_INTERFACE}"
        fi
    fi
}

prompt_remote_network() {
    [[ "$PEER_TYPE" != "site" ]] && return

    if [[ -z "$REMOTE_NETWORK" ]]; then
        echo ""
        echo "Remote Site's LAN Network: The network behind the remote site (Site B)"
        echo "  This is what Site A (this server) will route TO"
        echo "  Examples: 192.168.50.0/24, 10.100.0.0/16, 172.16.5.0/24"
        print_warning "This is REQUIRED - the remote LAN you want to access"
        read -p "Enter remote site's LAN network CIDR: " REMOTE_NETWORK

        [[ -z "$REMOTE_NETWORK" ]] && error_exit "Remote network CIDR is required for site-to-site VPN"
    fi

    validate_cidr "$REMOTE_NETWORK" || error_exit "Invalid remote network CIDR format (e.g., 192.168.50.0/24)"
}

prompt_peer_ip() {
    local config_file="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"
    local ip_label="$([[ "$PEER_TYPE" == "client" ]] && echo "Client IP" || echo "Tunnel IP")"

    if [[ -z "$PEER_IP" ]]; then
        local server_network=$(grep -E "^Address\s*=" "$config_file" | head -n1 | awk '{print $3}' | cut -d'/' -f1 | awk -F. '{print $1"."$2"."$3}')
        local server_cidr=$(grep -E "^Address\s*=" "$config_file" | head -n1 | awk '{print $3}' | cut -d'/' -f2)
        local suggested_ip=$(get_next_available_ip)

        echo ""
        echo "${ip_label}: IP address to assign to this ${PEER_TYPE} on VPN"
        echo "  Suggested: ${suggested_ip}/${server_cidr} (next available)"
        echo "  Range: ${server_network}.2 - ${server_network}.254"
        echo "  Note: CIDR should match server's VPN network (/${server_cidr})"
        echo ""
        read -p "Enter ${ip_label} with CIDR [${suggested_ip}/${server_cidr}]: " input_ip
        PEER_IP="${input_ip:-${suggested_ip}/${server_cidr}}"
    fi

    # Add CIDR if not present
    if [[ ! "$PEER_IP" =~ / ]]; then
        local server_cidr=$(grep -E "^Address\s*=" "${WG_CONFIG_DIR}/${WG_INTERFACE}.conf" | head -n1 | awk '{print $3}' | cut -d'/' -f2)
        PEER_IP="${PEER_IP}/${server_cidr}"
    fi

    validate_cidr "$PEER_IP" || error_exit "Invalid IP format. Use CIDR notation (e.g., 10.0.0.2/24)"

    # Validate IP is in correct network
    local peer_network=$(echo "$PEER_IP" | cut -d'/' -f1 | awk -F. '{print $1"."$2"."$3}')
    local server_network=$(grep -E "^Address\s*=" "${WG_CONFIG_DIR}/${WG_INTERFACE}.conf" | head -n1 | awk '{print $3}' | cut -d'/' -f1 | awk -F. '{print $1"."$2"."$3}')
    [[ "$peer_network" == "$server_network" ]] || error_exit "IP must be in the ${server_network}.0/24 network"
}

prompt_peer_config() {
    echo ""
    print_info "$([[ "$PEER_TYPE" == "client" ]] && echo "Client Configuration" || echo "Site-to-Site VPN Configuration")"
    [[ "$PEER_TYPE" == "site" ]] && echo "" && print_info "The remote site will connect TO this server"
    echo ""

    prompt_peer_name
    [[ "$PEER_TYPE" == "site" ]] && prompt_remote_network
    prompt_peer_ip
    get_server_info

    print_success "Configuration complete"
}

generate_keypair() {
    local keys_dir="${WG_CONFIG_DIR}/${WG_INTERFACE}"

    print_info "Generating encryption keys for ${PEER_TYPE}..."

    mkdir -p "$keys_dir"
    cd "$keys_dir" || error_exit "Failed to access ${keys_dir}"

    umask 077

    local private_key_file="${keys_dir}/${PEER_NAME}-privatekey"
    local public_key_file="${keys_dir}/${PEER_NAME}-publickey"

    wg genkey | tee "$private_key_file" | wg pubkey > "$public_key_file" || error_exit "Failed to generate keys"
    chmod 600 "$private_key_file" "$public_key_file"

    PEER_PRIVATE_KEY=$(cat "$private_key_file")
    PEER_PUBLIC_KEY=$(cat "$public_key_file")

    print_success "Keys generated"
}

add_peer_to_server() {
    local config_file="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"
    local peer_ip_only=$(echo "$PEER_IP" | cut -d'/' -f1)
    local peer_label="$([[ "$PEER_TYPE" == "client" ]] && echo "Client" || echo "Site")"

    print_info "Adding ${PEER_TYPE} peer to server configuration..."

    # For sites, include both tunnel IP and remote network
    local allowed_ips="${peer_ip_only}/32"
    [[ "$PEER_TYPE" == "site" ]] && allowed_ips="${allowed_ips}, ${REMOTE_NETWORK}"

    cat >> "$config_file" <<EOF

# ${peer_label}: ${PEER_NAME}
[Peer]
PublicKey = ${PEER_PUBLIC_KEY}
AllowedIPs = ${allowed_ips}
EOF

    print_success "Peer added to ${config_file}"
}

configure_routing() {
    local vpn_network=$(get_local_network)

    if [[ -n "$ALLOWED_IPS" && "$ALLOWED_IPS" != "vpn-only" ]]; then
        [[ "$ALLOWED_IPS" == "vpn-only" ]] && ALLOWED_IPS="${vpn_network}" && ROUTING_DESC="VPN network only"
        return
    fi

    echo ""
    print_info "$([[ "$PEER_TYPE" == "client" ]] && echo "Configuring client traffic routing" || echo "Configuring what Site B (remote) can access on Site A (this server)")"
    echo ""
    echo "Traffic Routing: Choose what $([[ "$PEER_TYPE" == "client" ]] && echo "traffic should go through the VPN" || echo "networks remote site should access")"
    echo ""

    if [[ "$PEER_TYPE" == "client" ]]; then
        echo "  1) VPN network only [RECOMMENDED]"
        echo "     Only access other VPN clients and server"
        echo ""
        echo "  2) All traffic (0.0.0.0/0)"
        echo "     Route ALL internet traffic through VPN (use VPN as exit node)"
        echo ""
        echo "  3) Custom networks"
        echo "     Specify custom CIDR ranges"
    else
        echo "  1) VPN tunnel network + Server's LAN [RECOMMENDED for site-to-site]"
        echo "     Remote site can access VPN clients AND server's internal LAN"
        echo ""
        echo "  2) VPN tunnel network only"
        echo "     Remote site can only access other VPN clients"
        echo ""
        echo "  3) All traffic (0.0.0.0/0) - Use VPN as exit node"
        echo "     Routes ALL remote site's internet traffic through VPN"
    fi

    echo ""
    read -p "Select routing mode (1-3) [1]: " routing_choice
    routing_choice="${routing_choice:-1}"

    case "$routing_choice" in
        1)
            if [[ "$PEER_TYPE" == "client" ]]; then
                ALLOWED_IPS="${vpn_network}"
                ROUTING_DESC="VPN network only (${vpn_network})"
            else
                # Site-to-site: VPN + LAN
                ALLOWED_IPS="${vpn_network}"

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
            fi
            ;;
        2)
            ALLOWED_IPS="${vpn_network}"
            ROUTING_DESC="VPN $([[ "$PEER_TYPE" == "client" ]] && echo "network only (${vpn_network})" || echo "tunnel network only (${vpn_network})")"
            ;;
        3)
            if [[ "$PEER_TYPE" == "client" ]]; then
                echo ""
                echo "Custom networks: Enter comma-separated CIDR ranges"
                echo "  Examples: 10.0.0.0/24,192.168.1.0/24"
                read -p "Enter custom AllowedIPs: " ALLOWED_IPS
                ROUTING_DESC="Custom routing (${ALLOWED_IPS})"
            else
                ALLOWED_IPS="0.0.0.0/0"
                ROUTING_DESC="All traffic through VPN (exit node)"
            fi
            ;;
        *)
            error_exit "Invalid routing mode selection"
            ;;
    esac
}

create_peer_config() {
    local keys_dir="${WG_CONFIG_DIR}/${WG_INTERFACE}"
    local config_file="${keys_dir}/${PEER_NAME}.conf"

    print_info "Creating $([[ "$PEER_TYPE" == "client" ]] && echo "client" || echo "remote site") configuration file..."

    configure_routing

    # Default to VPN network if nothing selected
    if [[ -z "$ALLOWED_IPS" ]]; then
        local vpn_network=$(get_local_network)
        ALLOWED_IPS="${vpn_network}"
        ROUTING_DESC="VPN network only (default)"
        print_info "Defaulting to VPN network only: ${vpn_network}"
    fi

    # Create config (DNS only for clients)
    if [[ "$PEER_TYPE" == "client" ]]; then
        cat > "$config_file" <<EOF
[Interface]
PrivateKey = ${PEER_PRIVATE_KEY}
Address = ${PEER_IP}
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = ${SERVER_PUBLIC_KEY}
Endpoint = ${SERVER_ENDPOINT}:${SERVER_PORT}
AllowedIPs = ${ALLOWED_IPS}
PersistentKeepalive = 25
EOF
    else
        cat > "$config_file" <<EOF
[Interface]
PrivateKey = ${PEER_PRIVATE_KEY}
Address = ${PEER_IP}

[Peer]
PublicKey = ${SERVER_PUBLIC_KEY}
Endpoint = ${SERVER_ENDPOINT}:${SERVER_PORT}
AllowedIPs = ${ALLOWED_IPS}
PersistentKeepalive = 25
EOF
    fi

    chmod 600 "$config_file"
    print_success "$([[ "$PEER_TYPE" == "client" ]] && echo "Client" || echo "Remote site") config created: ${config_file}"
    [[ "$PEER_TYPE" == "site" ]] && print_info "Site B (remote) will be able to access: ${ALLOWED_IPS}"
}

add_route_for_remote_network() {
    [[ "$PEER_TYPE" != "site" ]] && return

    print_info "Setting up route for remote network..."

    [[ -z "$REMOTE_NETWORK" ]] && print_info "No remote network specified, skipping route setup" && return

    IFS=',' read -ra NETWORKS <<< "$REMOTE_NETWORK"
    local routes_added=0

    for network in "${NETWORKS[@]}"; do
        network=$(echo "$network" | xargs)
        [[ "$network" =~ /32$ ]] && continue

        if ip route show "$network" 2>/dev/null | grep -q "dev ${WG_INTERFACE}"; then
            print_info "Route already exists: $network dev ${WG_INTERFACE}"
        else
            print_info "Adding route: $network dev ${WG_INTERFACE}"
            if ip route add "$network" dev "${WG_INTERFACE}" 2>/dev/null; then
                print_success "Route added: $network → ${WG_INTERFACE}"
                ((routes_added++))
            else
                print_warning "Failed to add route for $network (may already exist)"
            fi
        fi
    done

    if [[ $routes_added -gt 0 ]]; then
        print_success "Added $routes_added route(s) for site-to-site connectivity"
        echo ""
        print_info "Route verification:"
        ip route show | grep "${WG_INTERFACE}" | while read -r line; do
            echo "  $line"
        done
    else
        print_info "No new routes needed (already configured)"
    fi
}

show_summary() {
    local keys_dir="${WG_CONFIG_DIR}/${WG_INTERFACE}"
    local config_file="${keys_dir}/${PEER_NAME}.conf"

    echo ""
    echo "=========================================="
    print_success "$([[ "$PEER_TYPE" == "client" ]] && echo "Client Created Successfully!" || echo "Site-to-Site VPN Created!")"
    echo "=========================================="
    echo ""

    if [[ "$PEER_TYPE" == "client" ]]; then
        print_info "Client Details:"
        echo "  Name: ${PEER_NAME}"
        echo "  IP: ${PEER_IP}"
        echo "  Server: ${WG_INTERFACE}"
        echo "  Routing: ${ROUTING_DESC}"
        echo "  Config File: ${config_file}"
        echo ""
        print_warning "NEXT STEPS - Distribute configuration to client:"
        echo ""
        echo "1. Copy config file to client device:"
        echo "   scp root@server:${config_file} client-device:~/"
        echo ""
        echo "2. Mobile devices (Android/iOS):"
        echo "   Use qr-show.sh to generate QR code:"
        echo "   sudo ./qr-show.sh ${PEER_NAME}"
        echo ""
        echo "3. Laptop/Desktop (Linux):"
        echo "   sudo cp ${PEER_NAME}.conf /etc/wireguard/"
        echo "   sudo wg-quick up ${PEER_NAME}"
        echo ""
        echo "4. Laptop/Desktop (Windows/Mac):"
        echo "   Import ${PEER_NAME}.conf into WireGuard app"
    else
        local local_vpn_network=$(get_local_network)
        local tunnel_ip_only=$(echo "$PEER_IP" | cut -d'/' -f1)

        print_info "Site A - Server (This Side):"
        echo "  Interface: ${WG_INTERFACE}"
        echo "  VPN Tunnel Network: ${local_vpn_network}"
        echo "  Public Endpoint: ${SERVER_ENDPOINT}:${SERVER_PORT}"
        echo "  Can route to Site B: ${tunnel_ip_only}/32, ${REMOTE_NETWORK}"
        echo ""
        print_info "Site B - Remote Site:"
        echo "  Name: ${PEER_NAME}"
        echo "  Tunnel IP: ${PEER_IP}"
        echo "  LAN Network: ${REMOTE_NETWORK}"
        echo "  Can route to Site A: ${ALLOWED_IPS}"
        echo "  Config File: ${config_file}"
        echo ""
        print_info "Routing Summary:"
        echo "  ${ROUTING_DESC}"
        echo ""
        print_warning "NEXT STEPS - Deploy config to remote site:"
        echo ""
        echo "1. Copy configuration to remote site:"
        echo "   scp root@server:${config_file} remote-site:/etc/wireguard/wg-s2s.conf"
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
        [[ "$ALLOWED_IPS" =~ "," ]] && echo "   ping <IP-in-Site-A-LAN>  # Ping device on this server's LAN"
        echo ""
        print_info "Traffic Flow: Site A LAN <-> VPN Tunnel <-> Site B LAN"
        print_info "For LAN relay (Site B devices routing through VPN): Use setup-site-remote.sh"
    fi

    echo ""
    echo "=========================================="
    echo ""
}

################################################################################
# ARGUMENT PARSING
################################################################################

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --type) PEER_TYPE="$2"; shift 2 ;;
            --interface|-i) WG_INTERFACE="$2"; shift 2 ;;
            --port|-p) SERVER_PORT="$2"; shift 2 ;;
            --client-name|-c) PEER_NAME="$2"; PEER_TYPE="client"; shift 2 ;;
            --client-ip) PEER_IP="$2"; shift 2 ;;
            --site-name|-s) PEER_NAME="$2"; PEER_TYPE="site"; shift 2 ;;
            --tunnel-ip|-t) PEER_IP="$2"; shift 2 ;;
            --remote-network|-r) REMOTE_NETWORK="$2"; shift 2 ;;
            --route-all) ALLOWED_IPS="0.0.0.0/0"; ROUTING_DESC="All traffic through VPN (exit node)"; shift ;;
            --route-vpn-only) ALLOWED_IPS="vpn-only"; shift ;;
            --route-custom) ALLOWED_IPS="$2"; ROUTING_DESC="Custom routing"; shift 2 ;;
            -h|--help)
                echo "Usage: sudo $0 [OPTIONS]"
                echo ""
                echo "Common Options:"
                echo "  --type TYPE              Peer type: 'client' or 'site'"
                echo "  -i, --interface NAME     WireGuard interface (e.g., wg0)"
                echo "  -p, --port PORT          Server endpoint port"
                echo ""
                echo "Client Options:"
                echo "  -c, --client-name NAME   Client name (implies --type client)"
                echo "  --client-ip IP           Client IP address (CIDR)"
                echo ""
                echo "Site Options:"
                echo "  -s, --site-name NAME     Site name (implies --type site)"
                echo "  -t, --tunnel-ip IP       Tunnel IP for remote site (CIDR)"
                echo "  -r, --remote-network CIDR    Remote site's LAN network (REQUIRED for site)"
                echo ""
                echo "Routing Options (both client and site):"
                echo "  --route-all              Route all traffic (0.0.0.0/0, exit node)"
                echo "  --route-vpn-only         Route only VPN network traffic"
                echo "  --route-custom CIDR      Custom AllowedIPs (e.g., '10.0.0.0/24,192.168.1.0/24')"
                echo ""
                echo "  -h, --help               Show this help"
                echo ""
                echo "Examples:"
                echo ""
                echo "  # Interactive mode (menu)"
                echo "  sudo $0"
                echo ""
                echo "  # Add client interactively"
                echo "  sudo $0 --type client"
                echo ""
                echo "  # Add client with all options"
                echo "  sudo $0 -c laptop-john --client-ip 10.0.0.5/24 --route-all"
                echo ""
                echo "  # Add client with custom port (e.g., NAT port forwarding)"
                echo "  sudo $0 -c phone-alice --port 51222"
                echo ""
                echo "  # Add site interactively"
                echo "  sudo $0 --type site"
                echo ""
                echo "  # Add site with all options"
                echo "  sudo $0 -s branch-office -r 192.168.50.0/24 --route-vpn-only"
                echo ""
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                echo "Use --help for usage information"
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
    echo "  WireGuard Add Peer"
    echo "=========================================="
    echo ""

    parse_arguments "$@"
    check_root
    select_peer_type
    select_server
    prompt_peer_config
    generate_keypair
    add_peer_to_server
    create_peer_config
    reload_server
    add_route_for_remote_network
    show_summary
}

main "$@"
