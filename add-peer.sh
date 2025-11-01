#!/bin/bash
################################################################################
# WireGuard Add Peer Script
# Description: Add a client, site-to-site, or peer-to-peer connection
# Usage: sudo ./add-peer.sh [OPTIONS]
################################################################################

set -euo pipefail

################################################################################
# CONFIGURATION
################################################################################

WG_CONFIG_DIR="/etc/wireguard"
SERVER_PORT=""           # Endpoint port (auto-detected or custom)
PEER_NAME=""
WG_INTERFACE=""
PEER_IP=""
PEER_TYPE=""             # "client", "site", or "p2p"
REMOTE_NETWORK=""        # For site and p2p
PEER_LISTEN_PORT=""      # For p2p only
SERVER_PUBLIC_KEY=""
SERVER_ENDPOINT=""
ALLOWED_IPS=""
ROUTING_DESC=""
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
NC='\033[0m'

print_success() { echo -e "${GREEN}[✓]${NC} $1"; }
print_error() { echo -e "${RED}[✗]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_info() { echo -e "${BLUE}[i]${NC} $1"; }

################################################################################
# HELPER FUNCTIONS
################################################################################

error_exit() { print_error "$1"; exit 1; }
check_root() { [[ $EUID -eq 0 ]] || error_exit "This script must be run as root (use sudo)"; }
validate_cidr() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; }
validate_ip() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }

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
        ((i++)) || true
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
    print_info "Detecting public IP address..."
    local public_ip=""
    local services=("https://api.ipify.org" "https://icanhazip.com")

    for service in "${services[@]}"; do
        public_ip=$(curl -s --connect-timeout 2 --max-time 3 "$service" 2>/dev/null | tr -d '\n')
        if [[ -n "$public_ip" ]] && [[ "$public_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "$public_ip"
            return
        fi
    done

    # Failed to detect
    return 1
}

reload_server() {
    print_info "Reloading WireGuard configuration..."
    wg syncconf "${WG_INTERFACE}" <(wg-quick strip "${WG_INTERFACE}") || error_exit "Failed to reload ${WG_INTERFACE}"
    print_success "WireGuard configuration reloaded for ${WG_INTERFACE}"
    print_info "Existing connections remain intact"
}

################################################################################
# PEER TYPE CONFIGURATION
################################################################################

get_peer_config() {
    local type="$1"
    local field="$2"

    case "$type:$field" in
        # Display names
        client:label) echo "Client" ;;
        site:label) echo "Site" ;;
        p2p:label) echo "Peer-to-Peer" ;;

        # Descriptions
        client:desc) echo "Single device (laptop, phone, desktop)" ;;
        site:desc) echo "Remote network/office (site-to-site VPN)" ;;
        p2p:desc) echo "Equal peer server (bidirectional, both accept connections)" ;;

        # Name examples
        client:name_examples) echo "laptop-john, phone-alice, desktop-work" ;;
        site:name_examples) echo "branch-office, datacenter-east, office-la" ;;
        p2p:name_examples) echo "datacenter-west, backup-server, peer-office" ;;

        # Features
        client:needs_remote_network) echo "false" ;;
        site:needs_remote_network) echo "true" ;;
        p2p:needs_remote_network) echo "true" ;;

        client:needs_listen_port) echo "false" ;;
        site:needs_listen_port) echo "false" ;;
        p2p:needs_listen_port) echo "true" ;;

        client:has_dns) echo "true" ;;
        site:has_dns) echo "false" ;;
        p2p:has_dns) echo "false" ;;

        *) echo "" ;;
    esac
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
    echo "     $(get_peer_config client desc)"
    echo "     Access: VPN network, optionally route all traffic"
    echo ""
    echo -e "  ${CYAN}2)${NC} Site-to-Site"
    echo "     $(get_peer_config site desc)"
    echo "     Access: Connect entire networks together"
    echo "     Connection: Remote site connects TO this server"
    echo ""
    echo -e "  ${CYAN}3)${NC} Peer-to-Peer"
    echo "     $(get_peer_config p2p desc)"
    echo "     Access: Full bidirectional network access"
    echo "     Connection: Either side can initiate (both have ListenPort)"
    echo ""
    read -p "Select peer type (1-3): " peer_choice

    case "$peer_choice" in
        1) PEER_TYPE="client"; print_success "Selected: Client" ;;
        2) PEER_TYPE="site"; print_success "Selected: Site-to-Site" ;;
        3) PEER_TYPE="p2p"; print_success "Selected: Peer-to-Peer" ;;
        *) error_exit "Invalid selection" ;;
    esac
    echo ""
}

################################################################################
# UNIFIED CONFIGURATION PROMPTS
################################################################################

get_server_info() {
    local config_file="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"
    local server_listen_port=$(grep -E "^ListenPort\s*=" "$config_file" | head -n1 | awk '{print $3}')

    # Get server public key
    local keys_dir="${WG_CONFIG_DIR}/${WG_INTERFACE}"
    if [[ -f "${keys_dir}/server-publickey" ]]; then
        SERVER_PUBLIC_KEY=$(cat "${keys_dir}/server-publickey")
    else
        error_exit "Server public key not found at ${keys_dir}/server-publickey"
    fi

    # Get server endpoint
    echo ""
    local server_public_ip=$(get_public_ip)

    if [[ -n "$server_public_ip" ]]; then
        print_success "Detected public IP: ${server_public_ip}"
        echo ""
        read -p "Confirm or enter server's public IP/domain [${server_public_ip}]: " SERVER_ENDPOINT
        SERVER_ENDPOINT="${SERVER_ENDPOINT:-$server_public_ip}"
    else
        print_warning "Could not auto-detect public IP (no internet or behind NAT)"
        echo ""
        echo "Please enter this server's public IP address or domain name."
        echo "  - Public IP: The external IP clients will connect to"
        echo "  - Domain: A DNS name pointing to this server (e.g., vpn.example.com)"
        echo "  - If unsure, check: curl ifconfig.me (from a machine with internet)"
        echo ""

        while true; do
            read -p "Enter server's public IP/domain (required): " SERVER_ENDPOINT

            if [[ -z "$SERVER_ENDPOINT" ]]; then
                print_error "Server endpoint cannot be empty"
                echo ""
            else
                break
            fi
        done

        print_success "Using endpoint: ${SERVER_ENDPOINT}"
    fi

    # Get endpoint port
    if [[ -z "$SERVER_PORT" ]]; then
        echo ""
        echo "=========================================="
        print_info "Server Endpoint Port Configuration"
        echo "=========================================="
        echo ""
        echo "This is the port that clients/sites will connect to."
        echo ""
        print_info "Server's WireGuard listening port: ${server_listen_port}"
        echo ""
        echo "Options:"
        echo "  - Press ENTER to use default (${server_listen_port}) [RECOMMENDED]"
        echo "  - Enter a custom port if using NAT/port forwarding"
        echo "    Example: External port 51820 → forwards to → Internal ${server_listen_port}"
        echo ""
        read -p "Endpoint port [default: ${server_listen_port}]: " input_port

        if [[ -z "$input_port" ]]; then
            SERVER_PORT="$server_listen_port"
            print_success "Using default port: ${SERVER_PORT}"
        else
            SERVER_PORT="$input_port"
            if [[ "$SERVER_PORT" != "$server_listen_port" ]]; then
                print_warning "Custom port ${SERVER_PORT} specified (server listens on ${server_listen_port})"
                print_info "Ensure port forwarding is configured: ${SERVER_PORT} → ${server_listen_port}"
            else
                print_success "Using port: ${SERVER_PORT}"
            fi
        fi
    elif [[ "$SERVER_PORT" != "$server_listen_port" ]]; then
        print_info "Using configured endpoint port: ${SERVER_PORT} (server listens on ${server_listen_port})"
    fi

    # Validate port
    if ! [[ "$SERVER_PORT" =~ ^[0-9]+$ ]] || [ "$SERVER_PORT" -lt 1 ] || [ "$SERVER_PORT" -gt 65535 ]; then
        error_exit "Invalid port number. Must be between 1-65535"
    fi
}

prompt_peer_name() {
    local config_file="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"
    local label=$(get_peer_config "$PEER_TYPE" label)
    local examples=$(get_peer_config "$PEER_TYPE" name_examples)

    if [[ -z "$PEER_NAME" ]]; then
        echo ""
        echo "${label} Name: A descriptive name for this ${PEER_TYPE}"
        echo "  Examples: ${examples}"
        read -p "Enter ${PEER_TYPE} name: " PEER_NAME

        [[ -z "$PEER_NAME" ]] && error_exit "${label} name is required"

        # Check if name already exists
        if grep -q "^# ${label}: ${PEER_NAME}$" "$config_file" 2>/dev/null; then
            error_exit "${label} '${PEER_NAME}' already exists in ${WG_INTERFACE}"
        fi
    fi
}

prompt_remote_network() {
    local needs_remote=$(get_peer_config "$PEER_TYPE" needs_remote_network)
    [[ "$needs_remote" != "true" ]] && return

    if [[ -z "$REMOTE_NETWORK" ]]; then
        echo ""
        if [[ "$PEER_TYPE" == "p2p" ]]; then
            echo "Remote Peer's LAN Network: The network behind the remote peer"
        else
            echo "Remote Site's LAN Network: The network behind the remote site"
        fi
        echo "  Examples: 192.168.50.0/24, 10.100.0.0/16, 172.16.5.0/24"
        print_warning "This is REQUIRED - the remote LAN you want to access"
        read -p "Enter remote network CIDR: " REMOTE_NETWORK

        [[ -z "$REMOTE_NETWORK" ]] && error_exit "Remote network CIDR is required for ${PEER_TYPE}"
    fi

    validate_cidr "$REMOTE_NETWORK" || error_exit "Invalid remote network CIDR format (e.g., 192.168.50.0/24)"
}

prompt_peer_listen_port() {
    local needs_port=$(get_peer_config "$PEER_TYPE" needs_listen_port)
    [[ "$needs_port" != "true" ]] && return

    if [[ -z "$PEER_LISTEN_PORT" ]]; then
        echo ""
        echo "=========================================="
        print_info "Peer Listen Port Configuration"
        echo "=========================================="
        echo ""
        echo "For peer-to-peer, the remote peer also needs a listening port."
        echo "This allows bidirectional connection initiation."
        echo ""
        echo "Options:"
        echo "  - Press ENTER to use default (51820) [RECOMMENDED]"
        echo "  - Enter custom port if remote peer uses different port"
        echo ""
        read -p "Remote peer's listening port [default: 51820]: " input_port
        PEER_LISTEN_PORT="${input_port:-51820}"
        print_success "Remote peer will listen on port: ${PEER_LISTEN_PORT}"
    fi

    # Validate port
    if ! [[ "$PEER_LISTEN_PORT" =~ ^[0-9]+$ ]] || [ "$PEER_LISTEN_PORT" -lt 1 ] || [ "$PEER_LISTEN_PORT" -gt 65535 ]; then
        error_exit "Invalid port number. Must be between 1-65535"
    fi
}

prompt_peer_ip() {
    local config_file="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"
    local label=$(get_peer_config "$PEER_TYPE" label)

    if [[ -z "$PEER_IP" ]]; then
        local server_network=$(grep -E "^Address\s*=" "$config_file" | head -n1 | awk '{print $3}' | cut -d'/' -f1 | awk -F. '{print $1"."$2"."$3}')
        local server_cidr=$(grep -E "^Address\s*=" "$config_file" | head -n1 | awk '{print $3}' | cut -d'/' -f2)
        local suggested_ip=$(get_next_available_ip)

        echo ""
        echo "Tunnel IP: IP address to assign to this ${PEER_TYPE} on VPN"
        echo "  Suggested: ${suggested_ip}/${server_cidr} (next available)"
        echo "  Range: ${server_network}.2 - ${server_network}.254"
        echo ""
        read -p "Enter tunnel IP with CIDR [${suggested_ip}/${server_cidr}]: " input_ip
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

configure_routing() {
    local vpn_network=$(get_local_network)

    if [[ -n "$ALLOWED_IPS" && "$ALLOWED_IPS" != "vpn-only" ]]; then
        return
    fi

    echo ""
    print_info "Configuring traffic routing..."
    echo ""
    echo "Traffic Routing: Choose what networks the remote peer can access"
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
        # Site and P2P have same options
        echo "  1) VPN tunnel network + Server's LAN [RECOMMENDED]"
        echo "     Remote can access VPN clients AND server's internal LAN"
        echo ""
        echo "  2) VPN tunnel network only"
        echo "     Remote can only access other VPN clients"
        echo ""
        echo "  3) All traffic (0.0.0.0/0) - Use VPN as exit node"
        echo "     Routes ALL remote traffic through this VPN"
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
                # Site/P2P: VPN + LAN
                ALLOWED_IPS="${vpn_network}"
                local detected_network=$(get_primary_interface_network)
                echo ""
                echo "This server's internal LAN network:"
                if [[ -n "$detected_network" ]]; then
                    print_info "Detected primary network: ${detected_network}"
                    echo "  Examples: 192.168.1.0/24, 10.0.0.0/24"
                    echo ""
                    read -p "Enter this server's LAN network CIDR [${detected_network}]: " local_network
                    local_network="${local_network:-$detected_network}"
                else
                    echo "  Examples: 192.168.1.0/24, 10.0.0.0/24"
                    echo ""
                    read -p "Enter this server's LAN network CIDR: " local_network
                fi

                if [[ -n "$local_network" ]]; then
                    ALLOWED_IPS="${ALLOWED_IPS}, ${local_network}"
                    ROUTING_DESC="VPN network (${vpn_network}) + Server LAN (${local_network})"
                else
                    ROUTING_DESC="VPN network only (${vpn_network})"
                fi
            fi
            ;;
        2)
            ALLOWED_IPS="${vpn_network}"
            ROUTING_DESC="VPN network only (${vpn_network})"
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

################################################################################
# PEER CONFIGURATION
################################################################################

prompt_peer_config() {
    local label=$(get_peer_config "$PEER_TYPE" label)
    echo ""
    print_info "${label} Configuration"
    echo ""

    prompt_peer_name
    prompt_remote_network
    prompt_peer_listen_port
    prompt_peer_ip
    get_server_info

    print_success "Configuration complete"
}

generate_keypair() {
    local keys_dir="${WG_CONFIG_DIR}/${WG_INTERFACE}"

    print_info "Generating encryption keys..."

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
    local label=$(get_peer_config "$PEER_TYPE" label)

    print_info "Adding peer to server configuration..."

    # Build AllowedIPs for server config
    local allowed_ips="${peer_ip_only}/32"
    local needs_remote=$(get_peer_config "$PEER_TYPE" needs_remote_network)
    [[ "$needs_remote" == "true" && -n "$REMOTE_NETWORK" ]] && allowed_ips="${allowed_ips}, ${REMOTE_NETWORK}"

    # For P2P, add Endpoint to server config
    local peer_endpoint=""
    if [[ "$PEER_TYPE" == "p2p" ]]; then
        echo ""
        print_info "Peer-to-Peer requires remote peer's public endpoint"
        echo ""
        echo "Enter the public IP or domain of the remote peer."
        echo "  - This is where THIS server will connect to reach the remote peer"
        echo "  - Must be reachable from this server"
        echo ""

        local peer_endpoint_host=""
        while true; do
            read -p "Enter remote peer's public IP/domain (required): " peer_endpoint_host

            if [[ -z "$peer_endpoint_host" ]]; then
                print_error "Remote peer endpoint cannot be empty"
                echo ""
            else
                break
            fi
        done

        peer_endpoint="${peer_endpoint_host}:${PEER_LISTEN_PORT}"
        print_success "Remote peer endpoint: ${peer_endpoint}"
    fi

    cat >> "$config_file" <<EOF

# ${label}: ${PEER_NAME}
[Peer]
PublicKey = ${PEER_PUBLIC_KEY}
EOF

    [[ -n "$peer_endpoint" ]] && echo "Endpoint = ${peer_endpoint}" >> "$config_file"
    echo "AllowedIPs = ${allowed_ips}" >> "$config_file"

    print_success "Peer added to ${config_file}"
}

create_peer_config() {
    local keys_dir="${WG_CONFIG_DIR}/${WG_INTERFACE}"
    local config_file="${keys_dir}/${PEER_NAME}.conf"
    local label=$(get_peer_config "$PEER_TYPE" label)

    print_info "Creating peer configuration file..."

    configure_routing

    # Default to VPN network if nothing selected
    if [[ -z "$ALLOWED_IPS" ]]; then
        local vpn_network=$(get_local_network)
        ALLOWED_IPS="${vpn_network}"
        ROUTING_DESC="VPN network only (default)"
    fi

    # Build config
    cat > "$config_file" <<EOF
[Interface]
PrivateKey = ${PEER_PRIVATE_KEY}
Address = ${PEER_IP}
EOF

    # Add ListenPort for P2P
    if [[ "$PEER_TYPE" == "p2p" ]]; then
        echo "ListenPort = ${PEER_LISTEN_PORT}" >> "$config_file"
    fi

    # Add DNS for clients only
    local has_dns=$(get_peer_config "$PEER_TYPE" has_dns)
    [[ "$has_dns" == "true" ]] && echo "DNS = 1.1.1.1, 8.8.8.8" >> "$config_file"

    cat >> "$config_file" <<EOF

[Peer]
PublicKey = ${SERVER_PUBLIC_KEY}
Endpoint = ${SERVER_ENDPOINT}:${SERVER_PORT}
AllowedIPs = ${ALLOWED_IPS}
PersistentKeepalive = 25
EOF

    chmod 600 "$config_file"
    print_success "${label} config created: ${config_file}"
}

add_route_for_remote_network() {
    local needs_remote=$(get_peer_config "$PEER_TYPE" needs_remote_network)
    [[ "$needs_remote" != "true" ]] && return

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
                ((routes_added++)) || true
            else
                print_warning "Failed to add route for $network (may already exist)"
            fi
        fi
    done

    if [[ $routes_added -gt 0 ]]; then
        print_success "Added $routes_added route(s)"
    fi
}

show_summary() {
    local keys_dir="${WG_CONFIG_DIR}/${WG_INTERFACE}"
    local config_file="${keys_dir}/${PEER_NAME}.conf"
    local label=$(get_peer_config "$PEER_TYPE" label)

    echo ""
    echo "=========================================="
    print_success "${label} Created Successfully!"
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
        print_warning "NEXT STEPS - Distribute configuration:"
        echo ""
        echo "1. Mobile devices: Use QR code"
        echo "   sudo ./qr-show.sh ${PEER_NAME}"
        echo ""
        echo "2. Desktop/Laptop: Copy config file"
        echo "   scp root@server:${config_file} client-device:~/"
    else
        local tunnel_ip_only=$(echo "$PEER_IP" | cut -d'/' -f1)
        local vpn_network=$(get_local_network)

        print_info "This Server (Site A):"
        echo "  Interface: ${WG_INTERFACE}"
        echo "  VPN Network: ${vpn_network}"
        echo "  Endpoint: ${SERVER_ENDPOINT}:${SERVER_PORT}"
        echo ""
        print_info "Remote Peer (Site B):"
        echo "  Name: ${PEER_NAME}"
        echo "  Tunnel IP: ${PEER_IP}"
        [[ -n "$REMOTE_NETWORK" ]] && echo "  LAN Network: ${REMOTE_NETWORK}"
        [[ "$PEER_TYPE" == "p2p" ]] && echo "  Listen Port: ${PEER_LISTEN_PORT}"
        echo "  Config File: ${config_file}"
        echo "  Can access: ${ALLOWED_IPS}"
        echo ""
        print_warning "NEXT STEPS - Deploy to remote:"
        echo ""
        echo "1. Copy config to remote peer:"
        echo "   scp root@server:${config_file} remote:/etc/wireguard/wg0.conf"
        echo ""
        if [[ "$PEER_TYPE" == "p2p" ]]; then
            echo "2. On remote peer, start WireGuard:"
            echo "   sudo wg-quick up wg0"
            echo "   sudo systemctl enable wg-quick@wg0"
        else
            echo "2. On remote site, use setup-site-remote.sh:"
            echo "   sudo ./setup-site-remote.sh --config /etc/wireguard/wg0.conf"
        fi
        echo ""
        echo "3. Test connectivity:"
        echo "   ping ${tunnel_ip_only}"
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
            --name|-n) PEER_NAME="$2"; shift 2 ;;
            --client-name|-c) PEER_NAME="$2"; PEER_TYPE="client"; shift 2 ;;
            --site-name|-s) PEER_NAME="$2"; PEER_TYPE="site"; shift 2 ;;
            --p2p-name) PEER_NAME="$2"; PEER_TYPE="p2p"; shift 2 ;;
            --peer-ip|--client-ip|--tunnel-ip|-t) PEER_IP="$2"; shift 2 ;;
            --remote-network|-r) REMOTE_NETWORK="$2"; shift 2 ;;
            --peer-port) PEER_LISTEN_PORT="$2"; shift 2 ;;
            --route-all) ALLOWED_IPS="0.0.0.0/0"; ROUTING_DESC="All traffic"; shift ;;
            --route-vpn-only) ALLOWED_IPS="vpn-only"; shift ;;
            --route-custom) ALLOWED_IPS="$2"; ROUTING_DESC="Custom routing"; shift 2 ;;
            -h|--help)
                echo "Usage: sudo $0 [OPTIONS]"
                echo ""
                echo "Peer Types:"
                echo "  --type TYPE              Peer type: 'client', 'site', or 'p2p'"
                echo ""
                echo "Common Options:"
                echo "  -i, --interface NAME     WireGuard interface (e.g., wg0)"
                echo "  -p, --port PORT          Server endpoint port"
                echo "  -n, --name NAME          Peer name"
                echo "  -t, --peer-ip IP         Peer tunnel IP (CIDR)"
                echo ""
                echo "Site/P2P Options:"
                echo "  -r, --remote-network CIDR    Remote network (required for site/p2p)"
                echo ""
                echo "P2P Only:"
                echo "  --peer-port PORT         Remote peer's listening port"
                echo ""
                echo "Routing:"
                echo "  --route-all              Route all traffic (0.0.0.0/0)"
                echo "  --route-vpn-only         Route only VPN network"
                echo "  --route-custom CIDR      Custom routes"
                echo ""
                echo "Examples:"
                echo "  sudo $0                                    # Interactive"
                echo "  sudo $0 -c laptop-john --route-all         # Add client"
                echo "  sudo $0 -s branch-office -r 192.168.50.0/24  # Add site"
                echo "  sudo $0 --type p2p -n peer-dc -r 10.5.0.0/24 --peer-port 51820  # Add P2P"
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
