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

# Default DNS servers (can be customized during peer creation)
DEFAULT_DNS_SERVERS="1.1.1.1, 8.8.8.8"

# Persistent keepalive interval in seconds (0 to disable)
# Recommended: 25 for NAT traversal, 0 if both peers have public IPs
DEFAULT_KEEPALIVE=25

# Runtime variables (set during execution)
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
DNS_SERVERS=""           # Custom DNS (defaults to DEFAULT_DNS_SERVERS)
KEEPALIVE=""             # Custom keepalive (defaults to DEFAULT_KEEPALIVE)

################################################################################
# COLORS
################################################################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

print_success() { echo -e "${GREEN}[✓]${NC} $1" >&2; }
print_error() { echo -e "${RED}[✗]${NC} $1" >&2; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1" >&2; }
print_info() { echo -e "${BLUE}[i]${NC} $1" >&2; }

################################################################################
# HELPER FUNCTIONS
################################################################################

error_exit() { print_error "$1"; exit 1; }
check_root() { [[ $EUID -eq 0 ]] || error_exit "This script must be run as root (use sudo)"; }
validate_cidr() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; }
validate_ip() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }

validate_peer_name() {
    local name="$1"

    # Check if empty
    [[ -z "$name" ]] && return 1

    # Check length (3-30 chars)
    local len=${#name}
    [[ $len -lt 3 || $len -gt 30 ]] && return 1

    # Check for invalid characters (only alphanumeric, dash, underscore)
    [[ ! "$name" =~ ^[a-zA-Z0-9_-]+$ ]] && return 1

    # Check doesn't start/end with dash or underscore
    [[ "$name" =~ ^[-_] ]] && return 1
    [[ "$name" =~ [-_]$ ]] && return 1

    return 0
}

validate_port() {
    local port="$1"
    [[ "$port" =~ ^[0-9]+$ ]] && [[ $port -ge 1 ]] && [[ $port -le 65535 ]]
}

# Convert subnet mask to CIDR notation
# Accepts: 255.255.255.0, /24, or 24
# Returns: 24 (just the number)
convert_to_cidr() {
    local input="$1"

    # If already in /24 format, strip the slash
    if [[ "$input" =~ ^/([0-9]+)$ ]]; then
        echo "${BASH_REMATCH[1]}"
        return 0
    fi

    # If just a number like 24
    if [[ "$input" =~ ^[0-9]+$ ]]; then
        echo "$input"
        return 0
    fi

    # Convert dotted decimal (255.255.255.0) to CIDR
    case "$input" in
        255.255.255.255) echo "32" ;;
        255.255.255.254) echo "31" ;;
        255.255.255.252) echo "30" ;;
        255.255.255.248) echo "29" ;;
        255.255.255.240) echo "28" ;;
        255.255.255.224) echo "27" ;;
        255.255.255.192) echo "26" ;;
        255.255.255.128) echo "25" ;;
        255.255.255.0)   echo "24" ;;
        255.255.254.0)   echo "23" ;;
        255.255.252.0)   echo "22" ;;
        255.255.248.0)   echo "21" ;;
        255.255.240.0)   echo "20" ;;
        255.255.224.0)   echo "19" ;;
        255.255.192.0)   echo "18" ;;
        255.255.128.0)   echo "17" ;;
        255.255.0.0)     echo "16" ;;
        255.254.0.0)     echo "15" ;;
        255.252.0.0)     echo "14" ;;
        255.248.0.0)     echo "13" ;;
        255.240.0.0)     echo "12" ;;
        255.224.0.0)     echo "11" ;;
        255.192.0.0)     echo "10" ;;
        255.128.0.0)     echo "9"  ;;
        255.0.0.0)       echo "8"  ;;
        254.0.0.0)       echo "7"  ;;
        252.0.0.0)       echo "6"  ;;
        248.0.0.0)       echo "5"  ;;
        240.0.0.0)       echo "4"  ;;
        224.0.0.0)       echo "3"  ;;
        192.0.0.0)       echo "2"  ;;
        128.0.0.0)       echo "1"  ;;
        0.0.0.0)         echo "0"  ;;
        *) return 1 ;;  # Invalid format
    esac
}

# Convert CIDR to dotted decimal
cidr_to_dotted() {
    local cidr="$1"
    case "$cidr" in
        32) echo "255.255.255.255" ;;
        31) echo "255.255.255.254" ;;
        30) echo "255.255.255.252" ;;
        29) echo "255.255.255.248" ;;
        28) echo "255.255.255.240" ;;
        27) echo "255.255.255.224" ;;
        26) echo "255.255.255.192" ;;
        25) echo "255.255.255.128" ;;
        24) echo "255.255.255.0" ;;
        23) echo "255.255.254.0" ;;
        22) echo "255.255.252.0" ;;
        21) echo "255.255.248.0" ;;
        20) echo "255.255.240.0" ;;
        19) echo "255.255.224.0" ;;
        18) echo "255.255.192.0" ;;
        17) echo "255.255.128.0" ;;
        16) echo "255.255.0.0" ;;
        15) echo "255.254.0.0" ;;
        14) echo "255.252.0.0" ;;
        13) echo "255.248.0.0" ;;
        12) echo "255.240.0.0" ;;
        11) echo "255.224.0.0" ;;
        10) echo "255.192.0.0" ;;
        9)  echo "255.128.0.0" ;;
        8)  echo "255.0.0.0" ;;
        *) echo "255.255.255.0" ;;  # Default to /24
    esac
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
        local conf_ip=$(grep -E "^Address\s*=" "${WG_CONFIG_DIR}/${iface}.conf" 2>/dev/null | head -n1 | awk '{print $3}' || echo "N/A")
        local conf_port=$(grep -E "^ListenPort\s*=" "${WG_CONFIG_DIR}/${iface}.conf" 2>/dev/null | head -n1 | awk '{print $3}' || echo "N/A")
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
    local server_address=$(grep -E "^Address\s*=" "$config_file" 2>/dev/null | head -n1 | awk '{print $3}')
    [[ -z "$server_address" ]] && { echo "10.0.0.0/24"; return; }
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

get_site_to_site_networks() {
    # Extract all site-to-site remote networks from server config
    # Site peers have AllowedIPs with both /32 (peer VPN IP) and other CIDR networks (remote LANs)
    local config_file="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"
    local site_networks=""

    [[ ! -f "$config_file" ]] && { echo ""; return; }

    # Parse all [Peer] sections and extract remote networks (not /32)
    local in_peer=false
    local current_allowed=""

    while IFS= read -r line; do
        # Trim whitespace
        line=$(echo "$line" | xargs)

        # Check if we're entering a new peer section
        if [[ "$line" =~ ^\[Peer\] ]]; then
            in_peer=true
            current_allowed=""
        # Check for AllowedIPs line
        elif [[ "$in_peer" == true ]] && [[ "$line" =~ ^AllowedIPs[[:space:]]*=[[:space:]]*(.*) ]]; then
            current_allowed="${BASH_REMATCH[1]}"

            # Extract networks that are NOT /32 (those are remote LANs from site-to-site peers)
            # Split by comma and check each network
            IFS=',' read -ra networks <<< "$current_allowed"
            for net in "${networks[@]}"; do
                net=$(echo "$net" | xargs)  # Trim spaces

                # Skip /32 (individual peer IPs) and only include networks
                if [[ ! "$net" =~ /32$ ]]; then
                    # This is a remote network (site-to-site)
                    if [[ -z "$site_networks" ]]; then
                        site_networks="$net"
                    else
                        # Check if not already added (avoid duplicates)
                        if [[ ! "$site_networks" =~ $net ]]; then
                            site_networks="${site_networks}, ${net}"
                        fi
                    fi
                fi
            done
        # If we hit another section marker, we're done with this peer
        elif [[ "$line" =~ ^\[ ]]; then
            in_peer=false
        fi
    done < "$config_file"

    echo "$site_networks"
}

get_next_available_ip() {
    local config_file="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"
    local server_address=$(grep -E "^Address\s*=" "$config_file" 2>/dev/null | head -n1 | awk '{print $3}')
    [[ -z "$server_address" ]] && { echo "10.0.0.2"; return; }
    local network_base=$(echo "$server_address" | cut -d'/' -f1 | awk -F. '{print $1"."$2"."$3}')
    local used_ips=$(grep -E "AllowedIPs\s*=" "$config_file" 2>/dev/null | awk '{print $3}' | cut -d',' -f1 | cut -d'/' -f1 | cut -d'.' -f4 | sort -n)

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
        public_ip=$(curl -s --connect-timeout 2 --max-time 3 "$service" 2>/dev/null | tr -d '\n' | tr -d '\r')
        if [[ -n "$public_ip" ]] && [[ "$public_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "$public_ip"
            return 0
        fi
    done

    # Failed to detect
    return 1
}

reload_server() {
    print_info "Restarting WireGuard to apply routes..."
    echo ""
    print_warning "This will briefly disconnect all peers (~2 seconds)"

    # Full restart required to update kernel routes
    # wg syncconf only updates interface config, NOT routes!
    if wg-quick down "${WG_INTERFACE}" 2>/dev/null && wg-quick up "${WG_INTERFACE}" 2>/dev/null; then
        print_success "WireGuard restarted for ${WG_INTERFACE}"
        print_info "Routes updated based on AllowedIPs"
    else
        error_exit "Failed to restart ${WG_INTERFACE}"
    fi
}

################################################################################
# PEER TYPE CONFIG
################################################################################

get_label() {
    case "$1" in
        client) echo "Client" ;;
        site) echo "Site" ;;
        p2p) echo "Peer-to-Peer" ;;
    esac
}

needs_remote_network() { [[ "$1" == "site" || "$1" == "p2p" ]]; }
needs_listen_port() { [[ "$1" == "p2p" ]]; }
has_dns() { [[ "$1" == "client" ]]; }

################################################################################
# PEER TYPE SELECTION
################################################################################

select_peer_type() {
    [[ -n "$PEER_TYPE" ]] && return 0

    echo ""
    print_info "Select peer type:"
    echo -e "  ${CYAN}1)${NC} Client - Single device"
    echo -e "  ${CYAN}2)${NC} Site - Remote network (site-to-site)"
    echo -e "  ${CYAN}3)${NC} P2P - Equal peer (bidirectional)"
    echo ""
    read -p "Choice (1-3): " choice

    case "$choice" in
        1) PEER_TYPE="client" ;;
        2) PEER_TYPE="site" ;;
        3) PEER_TYPE="p2p" ;;
        *) error_exit "Invalid selection" ;;
    esac
    print_success "Selected: $(get_label "$PEER_TYPE")"
}

################################################################################
# UNIFIED CONFIGURATION PROMPTS
################################################################################

get_server_info() {
    local config_file="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"
    local server_listen_port=$(grep -E "^ListenPort\s*=" "$config_file" 2>/dev/null | head -n1 | awk '{print $3}')
    [[ -z "$server_listen_port" ]] && error_exit "Could not read ListenPort from ${config_file}"

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
    local label=$(get_label "$PEER_TYPE")

    if [[ -z "$PEER_NAME" ]]; then
        while true; do
            echo ""
            echo "Peer name (3-30 chars, alphanumeric, dash, underscore)"
            read -p "Enter name: " PEER_NAME
            PEER_NAME=$(echo "$PEER_NAME" | xargs)

            if ! validate_peer_name "$PEER_NAME"; then
                print_error "Invalid: Use 3-30 alphanumeric, dash, or underscore (no spaces)"
                read -p "Retry? (y/n): " retry
                [[ "$retry" =~ ^[Yy] ]] || error_exit "Name required"
                continue
            fi

            if grep -q "^# ${label}: ${PEER_NAME}$" "$config_file" 2>/dev/null; then
                print_error "${label} '${PEER_NAME}' already exists"
                read -p "Retry? (y/n): " retry
                [[ "$retry" =~ ^[Yy] ]] || error_exit "Name exists"
                PEER_NAME=""
                continue
            fi
            break
        done
    else
        validate_peer_name "$PEER_NAME" || error_exit "Invalid name format"
        grep -q "^# ${label}: ${PEER_NAME}$" "$config_file" 2>/dev/null && error_exit "Name already exists"
    fi
}

prompt_remote_network() {
    needs_remote_network "$PEER_TYPE" || return 0

    if [[ -z "$REMOTE_NETWORK" ]]; then
        while true; do
            echo ""
            echo "Remote LAN network (e.g., 192.168.50.0/24)"
            read -p "Enter CIDR: " REMOTE_NETWORK
            REMOTE_NETWORK=$(echo "$REMOTE_NETWORK" | xargs)

            [[ -z "$REMOTE_NETWORK" ]] && { print_error "Required"; read -p "Retry? (y/n): " r; [[ "$r" =~ ^[Yy] ]] || error_exit "Required"; continue; }
            validate_cidr "$REMOTE_NETWORK" || { print_error "Invalid CIDR"; read -p "Retry? (y/n): " r; [[ "$r" =~ ^[Yy] ]] || error_exit "Invalid"; REMOTE_NETWORK=""; continue; }
            break
        done
    else
        validate_cidr "$REMOTE_NETWORK" || error_exit "Invalid CIDR"
    fi
}

prompt_peer_listen_port() {
    needs_listen_port "$PEER_TYPE" || return 0

    if [[ -z "$PEER_LISTEN_PORT" ]]; then
        while true; do
            echo ""
            read -p "Remote peer listen port [51820]: " input_port
            PEER_LISTEN_PORT="${input_port:-51820}"
            validate_port "$PEER_LISTEN_PORT" || { print_error "Invalid port (1-65535)"; read -p "Retry? (y/n): " r; [[ "$r" =~ ^[Yy] ]] || error_exit "Invalid"; PEER_LISTEN_PORT=""; continue; }
            break
        done
    else
        validate_port "$PEER_LISTEN_PORT" || error_exit "Invalid port"
    fi
}

prompt_peer_ip() {
    local config_file="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"

    # Debug: Check if config file exists
    if [[ ! -f "$config_file" ]]; then
        error_exit "Configuration file not found: ${config_file}"
    fi

    local server_cidr=$(grep -E "^Address\s*=" "$config_file" 2>/dev/null | head -n1 | awk '{print $3}' | cut -d'/' -f2 || echo "24")
    local server_net=$(grep -E "^Address\s*=" "$config_file" 2>/dev/null | head -n1 | awk '{print $3}' | cut -d'/' -f1 | awk -F. '{print $1"."$2"."$3}' || echo "")
    local server_subnet=$(cidr_to_dotted "$server_cidr")

    if [[ -z "$server_net" ]]; then
        print_error "Could not read server address from ${config_file}"
        print_info "Make sure your WireGuard config has an 'Address' line like: Address = 10.0.0.1/24"
        exit 1
    fi

    if [[ -z "$PEER_IP" ]]; then
        # Step 1: Ask for IP address only (no CIDR)
        local peer_ip_only=""
        while true; do
            local suggested=$(get_next_available_ip | cut -d'/' -f1)
            echo ""
            echo "Tunnel IP address (without subnet mask)"
            read -p "Enter IP [${suggested}]: " input
            peer_ip_only="${input:-${suggested}}"

            # Validate it's a valid IP
            if ! validate_ip "$peer_ip_only"; then
                print_error "Invalid IP address format"
                read -p "Retry? (y/n): " r
                [[ "$r" =~ ^[Yy] ]] || error_exit "Invalid IP"
                continue
            fi

            # Check if IP is in correct network range
            local peer_net=$(echo "$peer_ip_only" | awk -F. '{print $1"."$2"."$3}')
            if [[ "$peer_net" != "$server_net" ]]; then
                print_error "Must be in ${server_net}.0 network"
                read -p "Retry? (y/n): " r
                [[ "$r" =~ ^[Yy] ]] || error_exit "Wrong network"
                continue
            fi

            # Check if IP exists in any AllowedIPs line (handles comma-separated lists)
            if grep -E "^AllowedIPs[[:space:]]*=" "$config_file" 2>/dev/null | grep -q "[[:space:],]${peer_ip_only}/32\|^AllowedIPs[[:space:]]*=[[:space:]]*${peer_ip_only}/32"; then
                print_error "IP in use: ${peer_ip_only}"
                read -p "Retry? (y/n): " r
                [[ "$r" =~ ^[Yy] ]] || error_exit "In use"
                continue
            fi
            break
        done

        # Step 2: Ask for subnet mask separately
        local peer_cidr=""
        while true; do
            echo ""
            echo "Subnet mask (e.g., /24, 24, or ${server_subnet})"
            read -p "Enter subnet [/${server_cidr}]: " input
            input="${input:-/${server_cidr}}"

            # Convert to CIDR number
            if peer_cidr=$(convert_to_cidr "$input"); then
                # Validate CIDR range (8-32 is reasonable for host)
                if [[ $peer_cidr -ge 8 ]] && [[ $peer_cidr -le 32 ]]; then
                    break
                else
                    print_error "CIDR must be between 8 and 32"
                    read -p "Retry? (y/n): " r
                    [[ "$r" =~ ^[Yy] ]] || error_exit "Invalid CIDR"
                fi
            else
                print_error "Invalid subnet format. Use: /24, 24, or 255.255.255.0"
                read -p "Retry? (y/n): " r
                [[ "$r" =~ ^[Yy] ]] || error_exit "Invalid"
            fi
        done

        # Combine IP + CIDR
        PEER_IP="${peer_ip_only}/${peer_cidr}"
        print_success "Peer IP: ${PEER_IP}"

    else
        # Command-line argument provided
        [[ ! "$PEER_IP" =~ / ]] && PEER_IP="${PEER_IP}/${server_cidr}"
        validate_cidr "$PEER_IP" || error_exit "Invalid IP"
        local peer_net=$(echo "$PEER_IP" | cut -d'/' -f1 | awk -F. '{print $1"."$2"."$3}')
        [[ "$peer_net" == "$server_net" ]] || error_exit "Wrong network"
    fi
}

configure_dns() {
    # Only for clients
    [[ "$PEER_TYPE" != "client" ]] && return 0

    if [[ -z "$DNS_SERVERS" ]]; then
        echo ""
        echo "=========================================="
        print_info "DNS Configuration"
        echo "=========================================="
        echo ""
        echo "DNS servers for client to use when connected to VPN."
        echo "Default: ${DEFAULT_DNS_SERVERS}"
        echo ""
        echo "Options:"
        echo "  1) Use default (${DEFAULT_DNS_SERVERS})"
        echo "  2) Custom DNS servers"
        echo "  3) No DNS (client uses existing DNS)"
        echo ""
        read -p "Select DNS option (1-3) [1]: " dns_choice
        dns_choice="${dns_choice:-1}"

        case "$dns_choice" in
            1)
                DNS_SERVERS="${DEFAULT_DNS_SERVERS}"
                print_success "Using default DNS: ${DNS_SERVERS}"
                ;;
            2)
                echo ""
                echo "Enter DNS servers (comma-separated)"
                echo "Examples: 1.1.1.1, 8.8.8.8  or  10.0.0.1"
                read -p "DNS servers: " custom_dns
                DNS_SERVERS="${custom_dns}"
                [[ -n "$DNS_SERVERS" ]] && print_success "Using custom DNS: ${DNS_SERVERS}"
                ;;
            3)
                DNS_SERVERS=""
                print_info "DNS disabled (client will use existing DNS settings)"
                ;;
            *)
                print_warning "Invalid choice, using default"
                DNS_SERVERS="${DEFAULT_DNS_SERVERS}"
                ;;
        esac
    fi
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
        # Check for site-to-site networks
        local site_nets=$(get_site_to_site_networks)

        echo "  1) VPN network + all site-to-site LANs [RECOMMENDED]"
        echo "     Access VPN clients, server, and all connected remote sites"
        if [[ -n "$site_nets" ]]; then
            echo "     (Auto-detected remote sites: ${site_nets})"
        fi
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
                # Start with VPN network
                ALLOWED_IPS="${vpn_network}"

                # Auto-detect and add all site-to-site remote networks
                local site_nets=$(get_site_to_site_networks)
                if [[ -n "$site_nets" ]]; then
                    ALLOWED_IPS="${ALLOWED_IPS}, ${site_nets}"
                    ROUTING_DESC="VPN network + site-to-site LANs (${vpn_network}, ${site_nets})"
                else
                    ROUTING_DESC="VPN network only (${vpn_network})"
                fi
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
            if [[ "$PEER_TYPE" == "client" ]]; then
                # All traffic through VPN (exit node)
                ALLOWED_IPS="0.0.0.0/0"
                ROUTING_DESC="All traffic through VPN (exit node)"
            else
                # Site/P2P: VPN network only (no LAN access)
                ALLOWED_IPS="${vpn_network}"
                ROUTING_DESC="VPN network only (${vpn_network})"
            fi
            ;;
        3)
            if [[ "$PEER_TYPE" == "client" ]]; then
                # Custom networks for clients
                echo ""
                echo "Custom networks: Enter comma-separated CIDR ranges"
                echo "  Examples: 10.0.0.0/24,192.168.1.0/24"
                read -p "Enter custom AllowedIPs: " ALLOWED_IPS
                ROUTING_DESC="Custom routing (${ALLOWED_IPS})"
            else
                # Site/P2P: All traffic (exit node)
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
    prompt_peer_name
    print_success "Peer name validated: ${PEER_NAME}"

    print_info "Checking for remote network requirements..."
    prompt_remote_network

    print_info "Checking for listen port requirements..."
    prompt_peer_listen_port

    print_info "Configuring peer IP address..."
    prompt_peer_ip

    print_info "Getting server information..."
    get_server_info

    # Configure DNS (clients only)
    configure_dns
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
    local peer_ip=$(echo "$PEER_IP" | cut -d'/' -f1)
    local label=$(get_label "$PEER_TYPE")
    local allowed="${peer_ip}/32"

    needs_remote_network "$PEER_TYPE" && [[ -n "$REMOTE_NETWORK" ]] && allowed="${allowed}, ${REMOTE_NETWORK}"

    local endpoint=""
    if needs_listen_port "$PEER_TYPE"; then
        echo ""
        read -p "Remote peer's public IP/domain: " host
        [[ -z "$host" ]] && error_exit "Endpoint required for P2P"
        endpoint="${host}:${PEER_LISTEN_PORT}"
    fi

    cat >> "$config_file" <<EOF

# ${label}: ${PEER_NAME}
[Peer]
PublicKey = ${PEER_PUBLIC_KEY}
EOF
    [[ -n "$endpoint" ]] && echo "Endpoint = ${endpoint}" >> "$config_file"
    echo "AllowedIPs = ${allowed}" >> "$config_file"
}

create_peer_config() {
    local keys_dir="${WG_CONFIG_DIR}/${WG_INTERFACE}"
    local config_file="${keys_dir}/${PEER_NAME}.conf"
    local label=$(get_label "$PEER_TYPE")

    print_info "Creating peer configuration file..."

    configure_routing

    # Default to VPN network if nothing selected
    if [[ -z "$ALLOWED_IPS" ]]; then
        local vpn_network=$(get_local_network)
        ALLOWED_IPS="${vpn_network}"
        ROUTING_DESC="VPN network only (default)"
    fi

    # Set keepalive (default if not specified)
    [[ -z "$KEEPALIVE" ]] && KEEPALIVE="${DEFAULT_KEEPALIVE}"

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

    # Add DNS for clients (if configured)
    if [[ "$PEER_TYPE" == "client" && -n "$DNS_SERVERS" ]]; then
        echo "DNS = ${DNS_SERVERS}" >> "$config_file"
    fi

    cat >> "$config_file" <<EOF

[Peer]
PublicKey = ${SERVER_PUBLIC_KEY}
Endpoint = ${SERVER_ENDPOINT}:${SERVER_PORT}
AllowedIPs = ${ALLOWED_IPS}
PersistentKeepalive = ${KEEPALIVE}
EOF

    chmod 600 "$config_file"
    print_success "${label} config created: ${config_file}"
}

add_route_for_remote_network() {
    needs_remote_network "$PEER_TYPE" || return 0

    [[ -z "$REMOTE_NETWORK" ]] && return

    # Routes are automatically managed by wg-quick based on AllowedIPs
    # IMPORTANT: Must use 'wg-quick down && wg-quick up' to update routes
    # - wg syncconf does NOT update kernel routes (only peer config)
    # - wg-quick up/down creates/removes routes from AllowedIPs
    #
    # NO manual 'ip route add' needed!
    # - wg-quick up reads AllowedIPs and adds routes to kernel
    # - wg-quick down removes all routes
    # - Full restart ensures clean route table

    print_info "Routes for ${REMOTE_NETWORK} will be added by wg-quick restart"
    print_info "Based on AllowedIPs in peer configuration"
}

show_summary() {
    local config="${WG_CONFIG_DIR}/${WG_INTERFACE}/${PEER_NAME}.conf"
    local label=$(get_label "$PEER_TYPE")

    echo ""
    print_success "${label} '${PEER_NAME}' created!"
    echo "  IP: ${PEER_IP}"
    echo "  Config: ${config}"

    if [[ "$PEER_TYPE" == "client" ]]; then
        echo ""
        echo "Next: Distribute config"
        echo "  Mobile: sudo ./qr-show.sh ${PEER_NAME}"
        echo "  Desktop: scp root@server:${config} ~/"
    else
        echo "  Remote LAN: ${REMOTE_NETWORK}"
        echo ""
        echo "Next: Deploy to remote"
        echo "  1. scp root@server:${config} remote:/etc/wireguard/wg0.conf"
        [[ "$PEER_TYPE" == "p2p" ]] && echo "  2. sudo wg-quick up wg0" || echo "  2. sudo ./setup-site-remote.sh --config wg0.conf"
    fi
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
            --dns) DNS_SERVERS="$2"; shift 2 ;;
            --no-dns) DNS_SERVERS=""; shift ;;
            --keepalive) KEEPALIVE="$2"; shift 2 ;;
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
                echo "Network Options:"
                echo "  --dns SERVERS            Custom DNS (e.g., '1.1.1.1, 8.8.8.8')"
                echo "  --no-dns                 Disable DNS (use client's existing DNS)"
                echo "  --keepalive SECONDS      PersistentKeepalive interval (default: ${DEFAULT_KEEPALIVE})"
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
