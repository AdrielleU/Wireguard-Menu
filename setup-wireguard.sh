#!/bin/bash
################################################################################
# WireGuard Server Setup Script
# Description: Automated WireGuard VPN server setup with automatic OS detection
#
# Supported Operating Systems:
#   - RHEL 8/9 (Red Hat Enterprise Linux)
#   - CentOS 8/9 Stream
#   - Rocky Linux 8/9
#   - AlmaLinux 8/9
#   - Fedora 35+
#   - Ubuntu 20.04/22.04/24.04
#   - Debian 11/12
#
# Kernel Requirements:
#   WireGuard is included in the Linux kernel since version 5.6 (March 2020)
#
#   Recommended: Linux kernel 5.6+ (native WireGuard support)
#   Minimum:     Linux kernel 3.10+ (with wireguard-dkms module)
#
#   Kernel versions by OS:
#   - RHEL 9:        5.14+  ✓ Native support
#   - RHEL 8:        4.18+  ✓ Backported support (kernel module included)
#   - Ubuntu 20.04:  5.4+   ✓ Backported support
#   - Ubuntu 22.04:  5.15+  ✓ Native support
#   - Ubuntu 24.04:  6.8+   ✓ Native support
#   - Debian 11:     5.10+  ✓ Native support
#   - Debian 12:     6.1+   ✓ Native support
#
#   Note: Older kernels may require installing wireguard-dkms package
#
# Features:
#   - Automatic OS detection and package manager selection
#   - Automatic firewall detection (firewalld, ufw, iptables, nftables)
#   - Support for multiple WireGuard servers on same VM
#   - Network/port/interface conflict detection
#   - SELinux support (RHEL-based systems)
#   - Automatic kernel module detection and loading
#
# Usage: sudo ./setup-wireguard.sh [OPTIONS]
# Options:
#   --server-ip IP        Server IP address (default: 10.0.0.1/24)
#   --network CIDR        VPN network CIDR (default: 10.0.0.0/24)
#   --port PORT           WireGuard listen port (default: 51820)
#   --interface NAME      Interface name (default: wg0)
#   --exit-node           Enable exit node (NAT all client traffic to internet)
#   -h, --help           Show this help message
#
# Examples:
#   # First server with defaults
#   sudo ./setup-wireguard.sh
#
#   # Second server on same VM
#   sudo ./setup-wireguard.sh --interface wg1 --port 51821 \
#        --server-ip 10.0.1.1/24 --network 10.0.1.0/24
#
#   # Create exit node server
#   sudo ./setup-wireguard.sh --exit-node
################################################################################

set -euo pipefail

################################################################################
# CONFIGURATION VARIABLES - Defaults
################################################################################

DEFAULT_WG_INTERFACE="wg0"
DEFAULT_WG_PORT=51820
DEFAULT_SERVER_IP="10.0.0.1/24"
DEFAULT_SERVER_NETWORK="10.0.0.0/24"

# MODE: "server", "client", "site-to-site", or "import-config"
MODE=""

# Import existing config
CONFIG_FILE_PATH=""

# SERVER MODE - These will be set by parse_arguments() and prompt_user_config()
WG_INTERFACE=""
WG_PORT=""
SERVER_IP=""
SERVER_NETWORK=""
EXIT_NODE=false
INTERNET_INTERFACE=""

# CLIENT/PEER MODE - Additional variables
PEER_ENDPOINT=""           # Remote server endpoint (IP:PORT)
SERVER_PUBKEY=""           # Remote server's public key
PEER_IP=""                 # This peer's IP on VPN network

# SITE-TO-SITE MODE - Additional variables (includes CLIENT MODE vars above)
LOCAL_NETWORK=""           # Local LAN network to route
LAN_INTERFACE=""           # Local LAN interface

WG_CONFIG_DIR="/etc/wireguard"
LOG_FILE="/var/log/wireguard-setup.log"

# Interface-specific directories (set after interface name is determined)
WG_INTERFACE_DIR=""
WG_KEYS_DIR=""

# Detect primary network interface
PRIMARY_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)

################################################################################
# HELPER FUNCTIONS - Colors
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
# HELPER FUNCTIONS - Logging and Error Handling
################################################################################

log() {
    local message="$1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $message" >> "$LOG_FILE"
}

error_exit() {
    local message="$1"
    print_error "$message"
    log "ERROR: $message"
    exit 1
}

check_command() {
    if ! command -v "$1" &> /dev/null; then
        return 1
    fi
    return 0
}

################################################################################
# ARGUMENT PARSING AND USER INPUT
################################################################################

show_usage() {
    echo "Usage: sudo $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --config FILE         Import existing WireGuard config file"
    echo "  --interface NAME      Interface name (default: auto-detect from filename)"
    echo ""
    echo "  SERVER MODE:"
    echo "  --server-ip IP        Server IP address (default: ${DEFAULT_SERVER_IP})"
    echo "  --network CIDR        VPN network CIDR (default: ${DEFAULT_SERVER_NETWORK})"
    echo "  --port PORT           WireGuard listen port (default: ${DEFAULT_WG_PORT})"
    echo "  --exit-node           Enable exit node (NAT all client traffic to internet)"
    echo ""
    echo "  CLIENT/SITE-TO-SITE MODE:"
    echo "  --peer-of ENDPOINT    Remote server endpoint (IP:PORT)"
    echo "  --server-pubkey KEY   Remote server's public key"
    echo "  --peer-ip IP          This peer's VPN IP address"
    echo "  --local-network CIDR  Local LAN network (for site-to-site only)"
    echo "  --lan-interface NAME  LAN interface (for site-to-site only)"
    echo ""
    echo "  -h, --help            Show this help message"
    echo ""
    echo "Examples:"
    echo "  # Import existing config"
    echo "  sudo $0 --config /path/to/wg0.conf"
    echo ""
    echo "  # Create new server"
    echo "  sudo $0 --server-ip 10.0.0.1/24 --network 10.0.0.0/24 --port 51820"
    echo ""
    echo "  # Connect as client"
    echo "  sudo $0 --peer-of 1.2.3.4:51820 --server-pubkey <key> --peer-ip 10.0.0.2/24"
    echo ""
    echo "  # Site-to-site connection"
    echo "  sudo $0 --peer-of 1.2.3.4:51820 --server-pubkey <key> \\"
    echo "          --peer-ip 10.0.0.2/24 --local-network 192.168.1.0/24"
    echo ""
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            # Import existing config
            --config)
                CONFIG_FILE_PATH="$2"
                MODE="import-config"
                shift 2
                ;;
            # Server mode arguments
            --server-ip)
                SERVER_IP="$2"
                shift 2
                ;;
            --network)
                SERVER_NETWORK="$2"
                shift 2
                ;;
            --port)
                WG_PORT="$2"
                shift 2
                ;;
            --interface)
                WG_INTERFACE="$2"
                shift 2
                ;;
            --exit-node)
                EXIT_NODE=true
                shift
                ;;
            # Peer mode arguments
            --peer-of)
                MODE="peer"
                PEER_ENDPOINT="$2"
                shift 2
                ;;
            --server-pubkey)
                SERVER_PUBKEY="$2"
                shift 2
                ;;
            --peer-ip)
                PEER_IP="$2"
                shift 2
                ;;
            --local-network)
                LOCAL_NETWORK="$2"
                shift 2
                ;;
            --lan-interface)
                LAN_INTERFACE="$2"
                shift 2
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
}

validate_ip_cidr() {
    local ip="$1"
    # Basic validation for IP/CIDR format (e.g., 10.0.0.1/24)
    if [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
        return 0
    else
        return 1
    fi
}

validate_network_cidr() {
    local network="$1"
    # Basic validation for network CIDR format (e.g., 10.0.0.0/24)
    if [[ $network =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
        return 0
    else
        return 1
    fi
}

validate_port() {
    local port="$1"
    if [[ $port =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; then
        return 0
    else
        return 1
    fi
}

prompt_mode_selection() {
    # If MODE already set via arguments, skip interactive prompt
    if [[ -n "$MODE" ]]; then
        return 0
    fi

    echo ""
    echo "======================================================================"
    echo "                    WireGuard Setup - Mode Selection"
    echo "======================================================================"
    echo ""
    echo "Choose setup mode:"
    echo ""
    echo "  1) Server Mode"
    echo "     - Create a new WireGuard VPN server"
    echo "     - Accept incoming connections from clients/peers"
    echo "     - Use this to create the main VPN hub"
    echo ""
    echo "  2) Client Mode"
    echo "     - Connect this machine as a regular VPN client"
    echo "     - Routes only this machine's traffic through VPN"
    echo "     - Road warrior / remote access setup"
    echo ""
    echo "  3) Site-to-Site Mode"
    echo "     - Connect this site to a remote WireGuard server"
    echo "     - Routes entire local LAN through VPN"
    echo "     - Both sites can access each other's networks"
    echo ""

    while true; do
        read -p "Select mode [1-3]: " mode_choice
        case $mode_choice in
            1)
                MODE="server"
                print_success "Server mode selected"
                break
                ;;
            2)
                MODE="client"
                print_success "Client mode selected"
                break
                ;;
            3)
                MODE="site-to-site"
                print_success "Site-to-Site mode selected"
                break
                ;;
            *)
                print_error "Invalid choice. Please enter 1, 2, or 3."
                ;;
        esac
    done
    echo ""
}

check_network_conflicts() {
    local network_to_check="$1"
    local conflicts_found=0

    print_info "Checking for network conflicts..."

    # Extract network prefix (e.g., 10.0.0 from 10.0.0.0/24)
    local network_base=$(echo "$network_to_check" | cut -d'/' -f1 | cut -d'.' -f1-3)

    # Check all existing IP addresses on all interfaces
    while IFS= read -r line; do
        # Skip empty lines
        [[ -z "$line" ]] && continue

        # Extract IP and interface name
        local existing_ip=$(echo "$line" | awk '{print $2}' | cut -d'/' -f1)
        local existing_iface=$(echo "$line" | awk '{print $NF}')

        # Get the first 3 octets of existing IP
        local existing_base=$(echo "$existing_ip" | cut -d'.' -f1-3)

        # Check if they're in the same subnet
        if [[ "$network_base" == "$existing_base" ]]; then
            print_warning "Network conflict detected: $existing_ip on interface $existing_iface"
            conflicts_found=1
        fi
    done < <(ip -4 addr show | grep "inet " | grep -v "127.0.0.1")

    # Check existing WireGuard configurations
    if [[ -d "$WG_CONFIG_DIR" ]]; then
        for conf in "$WG_CONFIG_DIR"/*.conf; do
            [[ ! -f "$conf" ]] && continue

            local conf_network=$(grep -E "^Address\s*=" "$conf" | head -n1 | awk '{print $3}' | cut -d'/' -f1)
            if [[ -n "$conf_network" ]]; then
                local conf_base=$(echo "$conf_network" | cut -d'.' -f1-3)
                if [[ "$network_base" == "$conf_base" ]]; then
                    print_warning "Network conflict with existing WireGuard config: $conf"
                    conflicts_found=1
                fi
            fi
        done
    fi

    if [[ $conflicts_found -eq 1 ]]; then
        print_warning "Network conflicts detected with: $network_to_check"
        return 1
    else
        print_success "No network conflicts detected"
        return 0
    fi
}

check_port_conflicts() {
    local port_to_check="$1"

    print_info "Checking if port $port_to_check is available..."

    # Check if port is already in use (UDP)
    if ss -ulnp 2>/dev/null | grep -q ":${port_to_check} "; then
        print_error "Port $port_to_check/udp is already in use!"
        ss -ulnp 2>/dev/null | grep ":${port_to_check} "
        return 1
    fi

    # Check existing WireGuard configurations for port conflicts
    if [[ -d "$WG_CONFIG_DIR" ]]; then
        for conf in "$WG_CONFIG_DIR"/*.conf; do
            [[ ! -f "$conf" ]] && continue

            local conf_port=$(grep -E "^ListenPort\s*=" "$conf" | head -n1 | awk '{print $3}')
            if [[ "$conf_port" == "$port_to_check" ]]; then
                print_error "Port $port_to_check is already configured in: $conf"
                return 1
            fi
        done
    fi

    print_success "Port $port_to_check is available"
    return 0
}

check_interface_conflicts() {
    local iface_to_check="$1"

    print_info "Checking if interface $iface_to_check exists..."

    # Check if interface already exists
    if ip link show "$iface_to_check" &>/dev/null; then
        print_error "Interface $iface_to_check already exists!"
        ip addr show "$iface_to_check"
        return 1
    fi

    # Check if config file exists
    if [[ -f "${WG_CONFIG_DIR}/${iface_to_check}.conf" ]]; then
        print_warning "Configuration file already exists: ${WG_CONFIG_DIR}/${iface_to_check}.conf"
        return 1
    fi

    print_success "Interface name $iface_to_check is available"
    return 0
}

get_next_available_interface() {
    # Find next available wgN interface
    local n=0
    while [[ -f "${WG_CONFIG_DIR}/wg${n}.conf" ]] || ip link show "wg${n}" &>/dev/null; do
        ((n++)) || true
    done
    echo "wg${n}"
}

get_next_available_port() {
    # Find next available port starting from 51820
    local port=51820
    local used_ports=()

    # Get all used ports from existing configs
    if [[ -d "$WG_CONFIG_DIR" ]]; then
        for conf in "$WG_CONFIG_DIR"/*.conf; do
            [[ ! -f "$conf" ]] && continue
            local conf_port=$(grep -E "^ListenPort\s*=" "$conf" | head -n1 | awk '{print $3}')
            [[ -n "$conf_port" ]] && used_ports+=("$conf_port")
        done
    fi

    # Find next available port
    while [[ " ${used_ports[@]} " =~ " ${port} " ]] || ss -ulnp 2>/dev/null | grep -q ":${port} "; do
        ((port++)) || true
    done
    echo "$port"
}

get_next_available_network() {
    # Find next available 10.0.N.0/24 network
    local n=0
    local used_networks=()

    # Get all used networks from existing configs
    if [[ -d "$WG_CONFIG_DIR" ]]; then
        for conf in "$WG_CONFIG_DIR"/*.conf; do
            [[ ! -f "$conf" ]] && continue
            local conf_network=$(grep -E "^Address\s*=" "$conf" | head -n1 | awk '{print $3}' | cut -d'/' -f1 | awk -F. '{print $1"."$2"."$3".0/24"}')
            [[ -n "$conf_network" ]] && used_networks+=("$conf_network")
        done
    fi

    # Find next available 10.0.N.0/24
    while [[ " ${used_networks[@]} " =~ " 10.0.${n}.0/24 " ]]; do
        ((n++)) || true
        # Prevent infinite loop, max 255 networks
        if [[ $n -gt 255 ]]; then
            echo "10.0.0.0/24"
            return
        fi
    done
    echo "10.0.${n}.0/24"
}

detect_default_interface() {
    # Detect the default internet-facing interface
    local default_iface=$(ip route | grep '^default' | head -n1 | awk '{print $5}')

    if [[ -z "$default_iface" ]]; then
        # Fallback: try to find first non-loopback interface
        default_iface=$(ip -o link show | grep -v 'lo:' | grep 'state UP' | head -n1 | awk -F': ' '{print $2}')
    fi

    if [[ -z "$default_iface" ]]; then
        # Last resort fallback
        default_iface="eth0"
    fi

    echo "$default_iface"
}

list_existing_wireguard_servers() {
    print_info "Existing WireGuard servers on this system:"

    local found_servers=0

    if [[ -d "$WG_CONFIG_DIR" ]]; then
        for conf in "$WG_CONFIG_DIR"/*.conf; do
            [[ ! -f "$conf" ]] && continue

            found_servers=1
            local iface_name=$(basename "$conf" .conf)
            local conf_ip=$(grep -E "^Address\s*=" "$conf" | head -n1 | awk '{print $3}')
            local conf_port=$(grep -E "^ListenPort\s*=" "$conf" | head -n1 | awk '{print $3}')
            local is_running=""

            if systemctl is-active --quiet "wg-quick@${iface_name}"; then
                is_running="${GREEN}[RUNNING]${NC}"
            else
                is_running="${YELLOW}[STOPPED]${NC}"
            fi

            echo -e "  - ${BLUE}${iface_name}${NC} $is_running - IP: $conf_ip, Port: $conf_port"
        done
    fi

    if [[ $found_servers -eq 0 ]]; then
        echo "  None found"
    fi
    echo ""
}

prompt_user_config() {
    print_info "Configuration Setup"
    echo ""

    # Show existing WireGuard servers
    list_existing_wireguard_servers

    # Auto-detect smart defaults based on existing servers
    local suggested_interface=$(get_next_available_interface)
    local suggested_port=$(get_next_available_port)
    local suggested_network=$(get_next_available_network)

    # Prompt for interface name if not set
    if [[ -z "$WG_INTERFACE" ]]; then
        echo "Interface Name: Network interface identifier for WireGuard"
        echo "  Suggested: ${suggested_interface} (next available)"
        echo "  For multiple servers: Use wg1, wg2, wg3..."
        while true; do
            read -p "Enter interface name [${suggested_interface}]: " input_interface
            WG_INTERFACE="${input_interface:-$suggested_interface}"

            if check_interface_conflicts "$WG_INTERFACE"; then
                break
            else
                print_error "Interface '${WG_INTERFACE}' already exists. Please choose a different name"
            fi
        done
    else
        if ! check_interface_conflicts "$WG_INTERFACE"; then
            error_exit "Interface $WG_INTERFACE is already in use. Please choose a different name."
        fi
    fi

    echo ""

    # Prompt for port if not set
    if [[ -z "$WG_PORT" ]]; then
        echo "Listen Port: UDP port where WireGuard listens for connections"
        echo "  Suggested: ${suggested_port} (next available)"
        echo "  For multiple servers: Each needs a unique port"
        echo "  Note: Clients need to know this port to connect"
        while true; do
            read -p "Enter listen port [${suggested_port}]: " input_port
            WG_PORT="${input_port:-$suggested_port}"

            if ! validate_port "$WG_PORT"; then
                print_error "Invalid port number. Must be between 1 and 65535."
                continue
            fi

            if check_port_conflicts "$WG_PORT"; then
                break
            else
                print_error "Port ${WG_PORT} is already in use. Please choose a different port"
            fi
        done
    else
        if ! validate_port "$WG_PORT"; then
            error_exit "Invalid port number: $WG_PORT"
        fi
        if ! check_port_conflicts "$WG_PORT"; then
            error_exit "Port $WG_PORT is already in use. Please choose a different port."
        fi
    fi

    echo ""

    # Prompt for network CIDR first if not set
    if [[ -z "$SERVER_NETWORK" ]]; then
        echo "VPN Network Range: Private IP range for the VPN tunnel"
        echo "  Suggested: ${suggested_network} (next available)"
        echo "  Common ranges: 10.0.0.0/24, 10.0.1.0/24, 10.0.2.0/24"
        echo "  For multiple servers: Use different subnets"
        while true; do
            read -p "Enter VPN network CIDR [${suggested_network}]: " input_network
            SERVER_NETWORK="${input_network:-$suggested_network}"

            if ! validate_network_cidr "$SERVER_NETWORK"; then
                print_error "Invalid network CIDR format. Example: 10.0.0.0/24"
                continue
            fi

            if check_network_conflicts "$SERVER_NETWORK"; then
                break
            else
                print_warning "This network may conflict with existing interfaces"
                read -p "Continue anyway? (y/N): " -n 1 -r
                echo
                if [[ $REPLY =~ ^[Yy]$ ]]; then
                    break
                fi
            fi
        done
    else
        if ! validate_network_cidr "$SERVER_NETWORK"; then
            error_exit "Invalid network CIDR format: $SERVER_NETWORK"
        fi
    fi

    echo ""

    # Prompt for server IP if not set (auto-derive default from network)
    if [[ -z "$SERVER_IP" ]]; then
        # Extract network base and CIDR from SERVER_NETWORK
        local network_base=$(echo "$SERVER_NETWORK" | cut -d'/' -f1)
        local network_cidr=$(echo "$SERVER_NETWORK" | cut -d'/' -f2)

        # Derive default server IP: change last octet to 1
        local derived_server_ip=$(echo "$network_base" | awk -F. '{print $1"."$2"."$3".1"}')"/${network_cidr}"

        echo "Server VPN IP: The server's IP address inside the VPN tunnel"
        echo "  Suggested: ${derived_server_ip} (automatically derived from network)"
        echo "  Convention: Usually .1 is used for the server/gateway"
        echo "  Clients will use: .2, .3, .4, etc."
        while true; do
            read -p "Enter server VPN IP [${derived_server_ip}]: " input_server_ip
            SERVER_IP="${input_server_ip:-$derived_server_ip}"

            if ! validate_ip_cidr "$SERVER_IP"; then
                print_error "Invalid IP/CIDR format. Example: 10.0.0.1/24"
                continue
            fi

            # Validate that server IP is within the network range
            local server_ip_base=$(echo "$SERVER_IP" | cut -d'/' -f1)
            local server_network_prefix=$(echo "$server_ip_base" | cut -d'.' -f1-3)
            local network_prefix=$(echo "$network_base" | cut -d'.' -f1-3)

            if [[ "$server_network_prefix" != "$network_prefix" ]]; then
                print_error "Server IP must be within the network range ${SERVER_NETWORK}"
                continue
            fi

            break
        done
    else
        if ! validate_ip_cidr "$SERVER_IP"; then
            error_exit "Invalid IP/CIDR format: $SERVER_IP"
        fi

        # Validate that server IP matches network when both are provided via arguments
        local server_ip_base=$(echo "$SERVER_IP" | cut -d'/' -f1)
        local server_network_prefix=$(echo "$server_ip_base" | cut -d'.' -f1-3)
        local network_base=$(echo "$SERVER_NETWORK" | cut -d'/' -f1)
        local network_prefix=$(echo "$network_base" | cut -d'.' -f1-3)

        if [[ "$server_network_prefix" != "$network_prefix" ]]; then
            error_exit "Server IP $SERVER_IP must be within the network range ${SERVER_NETWORK}"
        fi
    fi

    echo ""

    # Prompt for exit node mode (default: no)
    echo "Exit Node Mode: Route all client internet traffic through this VPN server"
    echo "  Enable this if you want clients to use this server as their internet gateway"
    echo "  Note: Requires proper firewall/NAT configuration"
    read -p "Enable exit node mode? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        EXIT_NODE=true
        INTERNET_INTERFACE=$(detect_default_interface)
        print_info "Exit node enabled. Internet interface: ${INTERNET_INTERFACE}"
    else
        EXIT_NODE=false
        print_info "Exit node disabled (VPN network access only)"
    fi

    # Set interface-specific paths now that we have the interface name
    WG_INTERFACE_DIR="${WG_CONFIG_DIR}/${WG_INTERFACE}"
    WG_KEYS_DIR="${WG_INTERFACE_DIR}"
    WG_CONFIG_FILE="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"

    # Show configuration summary
    echo ""
    print_info "Configuration Summary:"
    echo "  Interface: ${WG_INTERFACE}"
    echo "  Port: ${WG_PORT}"
    echo "  Server IP: ${SERVER_IP}"
    echo "  Network: ${SERVER_NETWORK}"
    echo "  Keys Directory: ${WG_KEYS_DIR}"
    if [[ "$EXIT_NODE" == true ]]; then
        echo "  Exit Node: ENABLED (NAT via ${INTERNET_INTERFACE})"
    else
        echo "  Exit Node: DISABLED (VPN access only)"
    fi
    echo ""

    read -p "Continue with this configuration? (Y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        error_exit "Configuration cancelled by user"
    fi

    log "Configuration: Interface=${WG_INTERFACE}, Port=${WG_PORT}, ServerIP=${SERVER_IP}, Network=${SERVER_NETWORK}, ExitNode=${EXIT_NODE}"
    log "Keys Directory: ${WG_KEYS_DIR}"
}

prompt_client_config() {
    if [[ "$MODE" == "site-to-site" ]]; then
        print_info "Site-to-Site VPN Configuration"
    else
        print_info "Client VPN Configuration"
    fi
    echo ""

    # Auto-detect smart defaults
    local suggested_interface=$(get_next_available_interface)
    local detected_lan=$(ip route | grep default | awk '{print $5}' | head -n1)
    local detected_lan_network=$(ip -4 addr show "$detected_lan" 2>/dev/null | grep "inet " | awk '{print $2}' | head -n1 | cut -d'.' -f1-3).0/24

    # Interface name
    if [[ -z "$WG_INTERFACE" ]]; then
        echo "Interface Name: WireGuard interface for this peer connection"
        while true; do
            read -p "Enter interface name [${suggested_interface}]: " input_interface
            WG_INTERFACE="${input_interface:-$suggested_interface}"

            if check_interface_conflicts "$WG_INTERFACE"; then
                break
            else
                print_error "Interface '${WG_INTERFACE}' already exists. Choose different name"
            fi
        done
    fi
    echo ""

    # Remote server endpoint
    if [[ -z "$PEER_ENDPOINT" ]]; then
        echo "Remote Server Endpoint: IP:PORT of the WireGuard server to connect to"
        echo "  Example: 1.2.3.4:51820"
        while true; do
            read -p "Enter remote server endpoint: " PEER_ENDPOINT
            if [[ -n "$PEER_ENDPOINT" ]] && [[ "$PEER_ENDPOINT" =~ ^[0-9.]+:[0-9]+$ ]]; then
                break
            else
                print_error "Invalid format. Use IP:PORT (e.g., 1.2.3.4:51820)"
            fi
        done
    fi
    echo ""

    # Server public key
    if [[ -z "$SERVER_PUBKEY" ]]; then
        echo "Remote Server Public Key: Get this from the remote server"
        echo "  Run on remote server: cat /etc/wireguard/<interface>/server-publickey"
        while true; do
            read -p "Enter remote server public key: " SERVER_PUBKEY
            if [[ -n "$SERVER_PUBKEY" ]]; then
                break
            else
                print_error "Public key cannot be empty"
            fi
        done
    fi
    echo ""

    # This peer's IP on VPN
    if [[ -z "$PEER_IP" ]]; then
        echo "Peer VPN IP: This peer's IP address on the VPN network"
        echo "  Example: 10.0.0.2/24 (must be in server's VPN network)"
        while true; do
            read -p "Enter peer VPN IP: " PEER_IP
            if validate_ip_cidr "$PEER_IP"; then
                break
            else
                print_error "Invalid IP/CIDR format. Example: 10.0.0.2/24"
            fi
        done
    fi
    echo ""

    # Site-to-Site specific: Local network and LAN interface
    if [[ "$MODE" == "site-to-site" ]]; then
        # Local network to route
        if [[ -z "$LOCAL_NETWORK" ]]; then
            echo "Local LAN Network: Your local network to route through VPN"
            echo "  Detected: ${detected_lan_network}"
            echo "  This allows remote site to access your local devices"
            while true; do
                read -p "Enter local LAN network [${detected_lan_network}]: " input_network
                LOCAL_NETWORK="${input_network:-$detected_lan_network}"
                if validate_network_cidr "$LOCAL_NETWORK"; then
                    break
                else
                    print_error "Invalid network CIDR. Example: 192.168.1.0/24"
                fi
            done
        fi
        echo ""

        # LAN interface
        if [[ -z "$LAN_INTERFACE" ]]; then
            echo "LAN Interface: Network interface connected to local LAN"
            echo "  Detected: ${detected_lan}"
            read -p "Enter LAN interface [${detected_lan}]: " input_lan
            LAN_INTERFACE="${input_lan:-$detected_lan}"
        fi
        echo ""
    fi

    # Set interface-specific paths
    WG_INTERFACE_DIR="${WG_CONFIG_DIR}/${WG_INTERFACE}"
    WG_KEYS_DIR="${WG_INTERFACE_DIR}"
    WG_CONFIG_FILE="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"

    # Show configuration summary
    echo ""
    if [[ "$MODE" == "site-to-site" ]]; then
        print_info "Site-to-Site Configuration Summary:"
        echo "  Interface: ${WG_INTERFACE}"
        echo "  Remote Server: ${PEER_ENDPOINT}"
        echo "  Peer VPN IP: ${PEER_IP}"
        echo "  Local LAN: ${LOCAL_NETWORK} (via ${LAN_INTERFACE})"
        echo "  Keys Directory: ${WG_KEYS_DIR}"
    else
        print_info "Client Configuration Summary:"
        echo "  Interface: ${WG_INTERFACE}"
        echo "  Remote Server: ${PEER_ENDPOINT}"
        echo "  Client VPN IP: ${PEER_IP}"
        echo "  Keys Directory: ${WG_KEYS_DIR}"
    fi
    echo ""

    read -p "Continue with this configuration? (Y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        error_exit "Configuration cancelled by user"
    fi

    if [[ "$MODE" == "site-to-site" ]]; then
        log "Site-to-Site Configuration: Interface=${WG_INTERFACE}, RemoteServer=${PEER_ENDPOINT}, PeerIP=${PEER_IP}, LocalLAN=${LOCAL_NETWORK}"
    else
        log "Client Configuration: Interface=${WG_INTERFACE}, RemoteServer=${PEER_ENDPOINT}, ClientIP=${PEER_IP}"
    fi
}

################################################################################
# PREREQUISITE CHECKS
################################################################################

check_root() {
    print_info "Checking root privileges..."
    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root (use sudo)"
    fi
    print_success "Running as root"
    log "Root privileges confirmed"
}

check_kernel() {
    print_info "Checking kernel version..."

    local kernel_version=$(uname -r)
    local kernel_major=$(echo "$kernel_version" | cut -d'.' -f1)
    local kernel_minor=$(echo "$kernel_version" | cut -d'.' -f2)

    print_info "Running kernel: $kernel_version"
    log "Kernel version: $kernel_version"

    # WireGuard native support since 5.6
    if [[ $kernel_major -ge 5 ]] && [[ $kernel_minor -ge 6 ]]; then
        print_success "Kernel $kernel_version has native WireGuard support"
    elif [[ $kernel_major -ge 5 ]]; then
        print_success "Kernel $kernel_version has WireGuard support (backported or native)"
    elif [[ $kernel_major -eq 4 ]] && [[ $kernel_minor -ge 18 ]]; then
        print_warning "Kernel $kernel_version may need wireguard-dkms module"
    elif [[ $kernel_major -ge 3 ]] && [[ $kernel_minor -ge 10 ]]; then
        print_warning "Kernel $kernel_version requires wireguard-dkms module"
    else
        print_error "Kernel $kernel_version may be too old for WireGuard"
        print_warning "Minimum kernel: 3.10+ (continuing anyway...)"
    fi
}

check_os() {
    print_info "Checking OS compatibility..."

    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        print_success "Detected OS: $NAME $VERSION"
        log "OS: $NAME $VERSION"

        case "$ID" in
            rhel|centos|rocky|almalinux|fedora)
                OS_TYPE="rhel"
                PACKAGE_MANAGER="dnf"
                if ! check_command dnf; then
                    PACKAGE_MANAGER="yum"
                fi
                ;;
            ubuntu|debian)
                OS_TYPE="debian"
                PACKAGE_MANAGER="apt"
                ;;
            *)
                print_warning "Unsupported OS: $ID. Attempting to continue..."
                OS_TYPE="unknown"
                ;;
        esac
    else
        error_exit "Cannot detect OS version"
    fi
}

check_wireguard_installed() {
    print_info "Checking WireGuard kernel module..."

    if lsmod | grep -q wireguard; then
        print_success "WireGuard kernel module is loaded"
        log "WireGuard kernel module detected"
        return 0
    elif modprobe wireguard 2>/dev/null; then
        print_success "WireGuard kernel module loaded successfully"
        log "WireGuard kernel module loaded"
        return 0
    else
        print_warning "WireGuard kernel module not found"
        return 1
    fi
}

check_wireguard_tools() {
    print_info "Checking WireGuard tools..."

    if check_command wg && check_command wg-quick; then
        print_success "WireGuard tools are installed"
        log "WireGuard tools detected: $(wg --version 2>&1 | head -n1)"
        return 0
    else
        print_warning "WireGuard tools not found"
        return 1
    fi
}

check_existing_config() {
    print_info "Checking for existing WireGuard configuration..."

    if [[ -f "$WG_CONFIG_FILE" ]]; then
        print_warning "Existing configuration found: $WG_CONFIG_FILE"

        # Check if service is running
        if systemctl is-active --quiet "wg-quick@${WG_INTERFACE}"; then
            print_warning "WireGuard service wg-quick@${WG_INTERFACE} is currently running!"
            read -p "Stop the service and overwrite configuration? (y/N): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                error_exit "Installation cancelled by user"
            fi

            print_info "Stopping WireGuard service..."
            systemctl stop "wg-quick@${WG_INTERFACE}" || print_warning "Failed to stop service"
            log "Stopped existing service for overwrite"
        else
            read -p "Do you want to overwrite it? (y/N): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                error_exit "Installation cancelled by user"
            fi
        fi

        # Backup existing config
        local backup_file="${WG_CONFIG_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
        cp "$WG_CONFIG_FILE" "$backup_file"
        print_success "Backed up existing config to: $backup_file"
        log "User chose to overwrite existing configuration. Backup: $backup_file"
    else
        print_success "No existing configuration found for $WG_INTERFACE"
    fi
}

################################################################################
# MAIN INSTALLATION FUNCTIONS
################################################################################

install_packages() {
    print_info "Checking required packages..."

    local packages_needed=()

    # Check WireGuard tools
    if ! check_wireguard_tools; then
        packages_needed+=("wireguard-tools")
    fi

    # Check other utilities
    for cmd in iptables ip; do
        if ! check_command "$cmd"; then
            case "$OS_TYPE" in
                rhel)
                    packages_needed+=("iproute")
                    ;;
                debian)
                    packages_needed+=("iproute2")
                    ;;
            esac
        fi
    done

    if [[ ${#packages_needed[@]} -gt 0 ]]; then
        print_info "Installing packages: ${packages_needed[*]}"
        log "Installing packages: ${packages_needed[*]}"

        case "$OS_TYPE" in
            rhel)
                $PACKAGE_MANAGER install -y "${packages_needed[@]}" || error_exit "Failed to install packages"
                ;;
            debian)
                apt update || error_exit "Failed to update package lists"
                apt install -y "${packages_needed[@]}" || error_exit "Failed to install packages"
                ;;
            *)
                error_exit "Cannot install packages on unknown OS type"
                ;;
        esac

        print_success "Packages installed successfully"
    else
        print_success "All required packages are already installed"
    fi
}

enable_ip_forwarding() {
    print_info "Enabling IP forwarding..."

    # Enable temporarily
    sysctl -w net.ipv4.ip_forward=1 &>/dev/null || error_exit "Failed to enable IP forwarding"

    # Make permanent
    local sysctl_conf="/etc/sysctl.d/99-wireguard.conf"
    if [[ ! -f "$sysctl_conf" ]] || ! grep -q "net.ipv4.ip_forward" "$sysctl_conf" 2>/dev/null; then
        cat > "$sysctl_conf" <<EOF
# WireGuard VPN Configuration
# Enable IP forwarding
net.ipv4.ip_forward = 1

# Disable reverse path filtering (required for site-to-site VPN)
# rp_filter=0 disables reverse path validation completely
net.ipv4.conf.default.rp_filter = 0
net.ipv4.conf.all.rp_filter = 0
EOF
        log "IP forwarding and rp_filter configured permanently in $sysctl_conf"
    fi

    print_success "IP forwarding enabled (rp_filter=disabled)"
}

generate_keys() {
    print_info "Generating WireGuard keys for ${WG_INTERFACE}..."

    # Create interface-specific directories
    mkdir -p "$WG_KEYS_DIR"
    cd "$WG_KEYS_DIR" || error_exit "Failed to access $WG_KEYS_DIR"

    # Set restrictive umask for key generation
    umask 077

    local private_key_file="${WG_KEYS_DIR}/server-privatekey"
    local public_key_file="${WG_KEYS_DIR}/server-publickey"

    if [[ ! -f "$private_key_file" ]]; then
        wg genkey | tee "$private_key_file" | wg pubkey > "$public_key_file" || error_exit "Failed to generate keys"
        chmod 600 "$private_key_file" "$public_key_file"
        print_success "Server keys generated in ${WG_KEYS_DIR}"
        log "Server keys generated: $private_key_file and $public_key_file"
    else
        print_warning "Keys already exist for ${WG_INTERFACE}, reusing them"
        log "Reusing existing keys: $private_key_file"
    fi

    SERVER_PRIVATE_KEY=$(cat "$private_key_file")
    SERVER_PUBLIC_KEY=$(cat "$public_key_file")
}

create_config() {
    print_info "Creating WireGuard configuration..."

    # Detect internet interface if exit node enabled and not yet detected
    if [[ "$EXIT_NODE" == true ]] && [[ -z "$INTERNET_INTERFACE" ]]; then
        INTERNET_INTERFACE=$(detect_default_interface)
        print_info "Detected internet interface: ${INTERNET_INTERFACE}"
    fi

    # Create basic config
    cat > "$WG_CONFIG_FILE" <<EOF
[Interface]
Address = ${SERVER_IP}
ListenPort = ${WG_PORT}
PrivateKey = ${SERVER_PRIVATE_KEY}
EOF

    # Add exit node (NAT) configuration if enabled
    if [[ "$EXIT_NODE" == true ]]; then
        cat >> "$WG_CONFIG_FILE" <<EOF

# Exit Node Configuration - NAT all client traffic to internet
PostUp = iptables -A FORWARD -i ${WG_INTERFACE} -j ACCEPT; iptables -t nat -A POSTROUTING -o ${INTERNET_INTERFACE} -j MASQUERADE
PostDown = iptables -D FORWARD -i ${WG_INTERFACE} -j ACCEPT; iptables -t nat -D POSTROUTING -o ${INTERNET_INTERFACE} -j MASQUERADE
EOF
        print_info "Added exit node NAT rules for interface: ${INTERNET_INTERFACE}"
        log "Exit node enabled with NAT on ${INTERNET_INTERFACE}"
    fi

    # Add example client config comments
    cat >> "$WG_CONFIG_FILE" <<EOF

# Add client configurations below
# Example:
# [Peer]
# PublicKey = CLIENT_PUBLIC_KEY
# AllowedIPs = 10.0.0.2/32
#
# Client keys can be generated in: ${WG_KEYS_DIR}/
# Example: cd ${WG_KEYS_DIR} && wg genkey | tee client1-privatekey | wg pubkey > client1-publickey

EOF

    chmod 600 "$WG_CONFIG_FILE" || error_exit "Failed to set permissions on config file"
    print_success "Configuration file created: $WG_CONFIG_FILE"
    log "Configuration created: $WG_CONFIG_FILE"
}

generate_client_keys() {
    print_info "Generating WireGuard client keys for ${WG_INTERFACE}..."

    # Create interface-specific directories
    mkdir -p "$WG_KEYS_DIR"
    cd "$WG_KEYS_DIR" || error_exit "Failed to access $WG_KEYS_DIR"

    # Set restrictive umask for key generation
    umask 077

    local private_key_file="${WG_KEYS_DIR}/client-privatekey"
    local public_key_file="${WG_KEYS_DIR}/client-publickey"

    if [[ ! -f "$private_key_file" ]]; then
        wg genkey | tee "$private_key_file" | wg pubkey > "$public_key_file" || error_exit "Failed to generate client keys"
        chmod 600 "$private_key_file" "$public_key_file"
        print_success "Client keys generated in ${WG_KEYS_DIR}"
        log "Client keys generated: $private_key_file and $public_key_file"
    else
        print_warning "Client keys already exist for ${WG_INTERFACE}, reusing them"
        log "Reusing existing client keys: $private_key_file"
    fi

    CLIENT_PRIVATE_KEY=$(cat "$private_key_file")
    CLIENT_PUBLIC_KEY=$(cat "$public_key_file")
}

create_client_config() {
    if [[ "$MODE" == "site-to-site" ]]; then
        print_info "Creating site-to-site configuration..."
    else
        print_info "Creating client configuration..."
    fi

    # Get remote server's network from PEER_IP (assuming /24)
    local vpn_network_base=$(echo "$PEER_IP" | cut -d'/' -f1 | cut -d'.' -f1-3).0/24

    if [[ "$MODE" == "site-to-site" ]]; then
        # Site-to-Site config: wg-quick handles routing via AllowedIPs
        cat > "$WG_CONFIG_FILE" <<EOF
[Interface]
Address = ${PEER_IP}
PrivateKey = ${CLIENT_PRIVATE_KEY}

[Peer]
PublicKey = ${SERVER_PUBKEY}
Endpoint = ${PEER_ENDPOINT}
# AllowedIPs automatically creates routes via wg-quick
# Remote VPN network and local LAN advertisement
AllowedIPs = ${vpn_network_base}
PersistentKeepalive = 25
EOF
    else
        # Regular client config: Just connect this machine to VPN
        cat > "$WG_CONFIG_FILE" <<EOF
[Interface]
Address = ${PEER_IP}
PrivateKey = ${CLIENT_PRIVATE_KEY}

[Peer]
PublicKey = ${SERVER_PUBKEY}
Endpoint = ${PEER_ENDPOINT}
# Route to remote VPN network (wg-quick handles routing automatically)
AllowedIPs = ${vpn_network_base}
PersistentKeepalive = 25
EOF
    fi

    chmod 600 "$WG_CONFIG_FILE" || error_exit "Failed to set permissions on config file"
    print_success "Configuration file created: $WG_CONFIG_FILE"
    log "Configuration created: $WG_CONFIG_FILE"

    echo ""
    print_warning "IMPORTANT: Add this client/peer to the remote server!"
    echo ""
    echo "On the remote server, run:"
    echo "  sudo add-peer.sh"
    echo ""
    if [[ "$MODE" == "site-to-site" ]]; then
        echo "Use these values:"
        echo "  Peer Name: $(hostname)-site"
        echo "  Public Key: ${CLIENT_PUBLIC_KEY}"
        echo "  Allowed IPs: ${PEER_IP%/*}/32, ${LOCAL_NETWORK}"
    else
        echo "Use these values:"
        echo "  Peer Name: $(hostname)-client"
        echo "  Public Key: ${CLIENT_PUBLIC_KEY}"
        echo "  Allowed IPs: ${PEER_IP%/*}/32"
    fi
    echo ""
}

import_existing_config() {
    print_info "Importing existing WireGuard configuration..."

    # Validate config file exists
    if [[ ! -f "$CONFIG_FILE_PATH" ]]; then
        error_exit "Config file not found: $CONFIG_FILE_PATH"
    fi

    # Extract interface name from filename if not provided
    if [[ -z "$WG_INTERFACE" ]]; then
        WG_INTERFACE=$(basename "$CONFIG_FILE_PATH" .conf)
        print_info "Interface name extracted from filename: ${WG_INTERFACE}"
    fi

    # Set paths
    WG_INTERFACE_DIR="${WG_CONFIG_DIR}/${WG_INTERFACE}"
    WG_KEYS_DIR="${WG_INTERFACE_DIR}"
    WG_CONFIG_FILE="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"

    # Create directories
    mkdir -p "$WG_KEYS_DIR"

    # Check if config already exists
    if [[ -f "$WG_CONFIG_FILE" ]]; then
        print_warning "Configuration already exists: $WG_CONFIG_FILE"
        read -p "Overwrite existing config? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            error_exit "Import cancelled by user"
        fi
        # Backup existing config
        local backup_file="${WG_CONFIG_FILE}.backup.$(date +%Y%m%d-%H%M%S)"
        cp "$WG_CONFIG_FILE" "$backup_file"
        print_info "Existing config backed up to: $backup_file"
    fi

    # Copy config file
    cp "$CONFIG_FILE_PATH" "$WG_CONFIG_FILE" || error_exit "Failed to copy config file"
    chmod 600 "$WG_CONFIG_FILE"
    print_success "Config imported to: $WG_CONFIG_FILE"

    # Try to detect mode from config content
    if grep -q "PostUp.*FORWARD" "$WG_CONFIG_FILE" || grep -q "AllowedIPs.*192.168\|10\.\|172\." "$WG_CONFIG_FILE"; then
        print_info "Detected site-to-site configuration (has FORWARD rules or LAN routes)"

        # Try to detect LAN interface
        if [[ -z "$LAN_INTERFACE" ]]; then
            LAN_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
            print_info "Auto-detected LAN interface: ${LAN_INTERFACE}"
        fi
    else
        print_info "Detected client configuration"
    fi

    log "Config imported: $CONFIG_FILE_PATH -> $WG_CONFIG_FILE"
}

detect_firewall() {
    print_info "Detecting active firewall..."

    if systemctl is-active --quiet firewalld 2>/dev/null; then
        FIREWALL_TYPE="firewalld"
        print_success "Detected: firewalld"
    elif systemctl is-active --quiet ufw 2>/dev/null; then
        FIREWALL_TYPE="ufw"
        print_success "Detected: ufw"
    elif check_command iptables && iptables -L -n &>/dev/null; then
        if check_command nft && nft list tables 2>/dev/null | grep -q .; then
            FIREWALL_TYPE="nftables"
            print_success "Detected: nftables"
        else
            FIREWALL_TYPE="iptables"
            print_success "Detected: iptables"
        fi
    else
        FIREWALL_TYPE="none"
        print_warning "No firewall detected"
    fi

    log "Firewall type: $FIREWALL_TYPE"
}

configure_firewall() {
    detect_firewall

    print_info "Configuring firewall rules..."

    case "$FIREWALL_TYPE" in
        firewalld)
            configure_firewalld
            ;;
        ufw)
            configure_ufw
            ;;
        iptables)
            configure_iptables
            ;;
        nftables)
            configure_nftables
            ;;
        none)
            print_warning "No firewall to configure, creating basic iptables rules"
            configure_iptables
            ;;
    esac

    print_success "Firewall configured"
}

configure_firewalld() {
    print_info "Configuring firewalld..."

    if [[ "$MODE" == "server" ]]; then
        # SERVER MODE: Open port and optionally enable masquerading
        print_info "Configuring firewall for server mode..."

        # Open WireGuard port on public zone
        print_info "Opening WireGuard port ${WG_PORT}/udp on public zone"
        if firewall-cmd --permanent --zone=public --add-port=${WG_PORT}/udp 2>/dev/null; then
            print_success "WireGuard port ${WG_PORT}/udp opened on public zone"
        else
            print_warning "Failed to add port to public zone (may already exist)"
        fi

        # Add WireGuard to trusted zone
        print_info "Adding ${WG_INTERFACE} to trusted zone..."
        firewall-cmd --permanent --zone=trusted --add-interface=${WG_INTERFACE} 2>/dev/null || true

        # Enable masquerading for exit node functionality
        if [[ "$EXIT_NODE" == true ]]; then
            firewall-cmd --permanent --zone=public --add-masquerade || error_exit "Failed to enable masquerading"
            print_info "Masquerading enabled for exit node mode (VPN → Internet)"
        fi

        print_success "Server firewall rules configured"

    elif [[ "$MODE" == "site-to-site" ]]; then
        # SITE-TO-SITE MODE: Add FORWARD rules between WireGuard and LAN
        print_info "Configuring firewall for site-to-site VPN..."
        echo ""

        # Add WireGuard to trusted zone
        print_info "Adding ${WG_INTERFACE} to trusted zone..."
        firewall-cmd --permanent --zone=trusted --add-interface=${WG_INTERFACE} 2>/dev/null || true

        # Add direct FORWARD rules (works on all firewalld versions)
        print_info "Adding FORWARD rules for ${WG_INTERFACE} ↔ ${LAN_INTERFACE}..."
        firewall-cmd --permanent --direct --add-rule ipv4 filter FORWARD 0 -i ${WG_INTERFACE} -o ${LAN_INTERFACE} -j ACCEPT 2>/dev/null || true
        firewall-cmd --permanent --direct --add-rule ipv4 filter FORWARD 0 -i ${LAN_INTERFACE} -o ${WG_INTERFACE} -j ACCEPT 2>/dev/null || true
        firewall-cmd --permanent --direct --add-rule ipv4 filter FORWARD 0 -i ${WG_INTERFACE} -o ${WG_INTERFACE} -j ACCEPT 2>/dev/null || true

        print_success "Site-to-site firewall rules configured"
        print_info "  - ${WG_INTERFACE} in trusted zone"
        print_info "  - Direct FORWARD rules: ${WG_INTERFACE} ↔ ${LAN_INTERFACE}"

    else
        # CLIENT MODE: Just add WireGuard to trusted zone
        print_info "Configuring firewall for client mode..."

        # Add WireGuard to trusted zone
        print_info "Adding ${WG_INTERFACE} to trusted zone..."
        firewall-cmd --permanent --zone=trusted --add-interface=${WG_INTERFACE} 2>/dev/null || true

        print_success "Client firewall rules configured"
        print_info "  - ${WG_INTERFACE} in trusted zone"
    fi

    # Restart firewall to apply changes
    print_info "Restarting firewall..."
    if systemctl restart firewalld 2>/dev/null; then
        print_success "Firewall restarted successfully"
    else
        print_warning "Firewall restart failed, trying reload..."
        firewall-cmd --reload || error_exit "Failed to reload firewalld"
    fi

    echo ""
    print_success "firewalld configured for site-to-site VPN"
    print_info "Configuration summary:"
    print_info "  - Port ${WG_PORT}/udp opened on public zone"
    print_info "  - ${WG_INTERFACE} in trusted zone"

    if [[ -n "$lan_interface" ]]; then
        print_info "  - ${lan_interface} in public zone (default)"
        print_info "  - Policies: lan-to-vpn (public → trusted)"
        print_info "  - Policies: vpn-to-lan (trusted → public)"
    fi

    if [[ "$EXIT_NODE" == true ]]; then
        print_info "  - Exit node enabled (VPN → Internet)"
    fi

    print_info "  - Source IPs preserved (no NAT on VPN)"

    log "firewalld configured: port=${WG_PORT}, interface=${WG_INTERFACE}, policies configured"
}

configure_ufw() {
    print_info "Configuring ufw..."

    # Allow WireGuard port
    ufw allow ${WG_PORT}/udp || error_exit "Failed to add WireGuard port"

    # Enable forwarding in ufw (essential for site-to-site VPN)
    sed -i 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw 2>/dev/null || true

    # Allow traffic on WireGuard interface
    ufw allow in on ${WG_INTERFACE} 2>/dev/null || true
    ufw allow out on ${WG_INTERFACE} 2>/dev/null || true

    # Reload ufw
    ufw reload 2>/dev/null || true

    print_success "ufw configured"
    print_info "  - Port ${WG_PORT}/udp opened"
    print_info "  - Forwarding enabled for site-to-site VPN"
    log "ufw configured with port ${WG_PORT}/udp and forwarding enabled"
}

configure_iptables() {
    print_info "Configuring iptables..."

    # Allow FORWARD traffic for VPN (essential for site-to-site)
    iptables -A FORWARD -i ${WG_INTERFACE} -j ACCEPT 2>/dev/null || true
    iptables -A FORWARD -o ${WG_INTERFACE} -j ACCEPT 2>/dev/null || true

    # Enable masquerading only if exit node mode is enabled
    if [[ "$EXIT_NODE" == true ]]; then
        iptables -t nat -A POSTROUTING -s ${SERVER_NETWORK} -o ${PRIMARY_INTERFACE} -j MASQUERADE 2>/dev/null || true
        print_info "Masquerading enabled for exit node mode"
    fi

    print_success "iptables configured"
    print_info "  - FORWARD rules configured for site-to-site VPN"
    log "iptables rules applied for ${WG_INTERFACE}"
}

configure_nftables() {
    print_info "Configuring nftables..."

    # Create table and chain for WireGuard
    nft add table inet wireguard 2>/dev/null || true
    nft add chain inet wireguard forward { type filter hook forward priority 0 \; policy accept \; } 2>/dev/null || true

    # Allow FORWARD traffic for VPN (essential for site-to-site)
    nft add rule inet wireguard forward iifname "${WG_INTERFACE}" accept 2>/dev/null || true
    nft add rule inet wireguard forward oifname "${WG_INTERFACE}" accept 2>/dev/null || true

    # Enable masquerading only if exit node mode is enabled
    if [[ "$EXIT_NODE" == true ]]; then
        nft add table ip nat 2>/dev/null || true
        nft add chain ip nat postrouting { type nat hook postrouting priority 100 \; } 2>/dev/null || true
        nft add rule ip nat postrouting ip saddr ${SERVER_NETWORK} oifname "${PRIMARY_INTERFACE}" masquerade 2>/dev/null || true
        print_info "Masquerading enabled for exit node mode"
    fi

    print_success "nftables configured"
    print_info "  - FORWARD rules configured for site-to-site VPN"
    log "nftables rules applied for ${WG_INTERFACE}"
}

handle_selinux() {
    print_info "Checking SELinux status..."

    if check_command getenforce; then
        local selinux_status=$(getenforce)
        print_info "SELinux status: $selinux_status"
        log "SELinux status: $selinux_status"

        if [[ "$selinux_status" != "Disabled" ]]; then
            print_warning "SELinux is enabled. Ensuring proper context..."

            if check_command restorecon; then
                restorecon -Rv "$WG_CONFIG_DIR" || print_warning "Failed to restore SELinux context"
            fi

            # Allow WireGuard port if semanage is available
            if check_command semanage; then
                semanage port -a -t wireguard_port_t -p udp ${WG_PORT} 2>/dev/null || \
                semanage port -m -t wireguard_port_t -p udp ${WG_PORT} 2>/dev/null || \
                print_warning "Could not set SELinux port context"
            fi

            print_success "SELinux context configured"
        fi
    else
        print_info "SELinux not detected"
    fi
}

setup_site_routes() {
    print_info "Setting up routes for site-to-site connections..."

    # Parse config file to find site-to-site peers (AllowedIPs with networks, not just single IPs)
    local site_networks=()
    local in_peer=false
    local is_site_peer=false
    local peer_networks=()

    while IFS= read -r line; do
        # Detect [Peer] section
        if [[ "$line" =~ ^\[Peer\] ]]; then
            # Process previous peer if it was a site
            if [[ "$is_site_peer" == true ]] && [[ ${#peer_networks[@]} -gt 0 ]]; then
                site_networks+=("${peer_networks[@]}")
            fi

            in_peer=true
            is_site_peer=false
            peer_networks=()
            continue
        fi

        # Parse AllowedIPs in peer section
        if [[ "$in_peer" == true ]] && [[ "$line" =~ ^AllowedIPs[[:space:]]*=[[:space:]]*(.+)$ ]]; then
            local allowed_ips="${BASH_REMATCH[1]}"

            # Split by comma
            IFS=',' read -ra IP_ARRAY <<< "$allowed_ips"
            for ip in "${IP_ARRAY[@]}"; do
                ip=$(echo "$ip" | xargs)  # Trim whitespace

                # Check if this is a network (not a /32 single host or VPN single IP)
                if [[ "$ip" =~ ^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/([0-9]+)$ ]]; then
                    local network="${BASH_REMATCH[1]}"
                    local prefix="${BASH_REMATCH[2]}"

                    # If it's a site-to-site network (not /32 and not our VPN network)
                    if [[ "$prefix" -ne 32 ]] && [[ "$ip" != "$SERVER_NETWORK" ]]; then
                        # Check if it's within our VPN range - if not, it's a remote LAN
                        local vpn_base=$(echo "$SERVER_NETWORK" | cut -d'/' -f1 | cut -d'.' -f1-3)
                        local network_base=$(echo "$network" | cut -d'.' -f1-3)

                        if [[ "$network_base" != "$vpn_base" ]]; then
                            is_site_peer=true
                            peer_networks+=("$ip")
                        fi
                    fi
                fi
            done
        fi
    done < "$WG_CONFIG_FILE"

    # Process last peer
    if [[ "$is_site_peer" == true ]] && [[ ${#peer_networks[@]} -gt 0 ]]; then
        site_networks+=("${peer_networks[@]}")
    fi

    # Add routes for site networks
    if [[ ${#site_networks[@]} -gt 0 ]]; then
        print_info "Found ${#site_networks[@]} site-to-site network(s)"

        # Get server's VPN IP (without CIDR) for source routing
        local config_file="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"
        local server_vpn_ip=$(grep -E "^Address\s*=" "$config_file" 2>/dev/null | head -n1 | awk '{print $3}' | cut -d'/' -f1)

        for network in "${site_networks[@]}"; do
            # Check if route already exists
            if ip route show "$network" 2>/dev/null | grep -q "dev ${WG_INTERFACE}"; then
                print_info "Route already exists: $network dev ${WG_INTERFACE}"
            else
                print_info "Adding route: $network dev ${WG_INTERFACE} src ${server_vpn_ip}"
                ip route add "$network" dev "${WG_INTERFACE}" src "${server_vpn_ip}" 2>/dev/null || print_warning "Failed to add route for $network"
                log "Added site-to-site route: $network dev ${WG_INTERFACE} src ${server_vpn_ip}"
            fi
        done

        print_success "Site-to-site routes configured"
    else
        print_info "No site-to-site networks found (only client peers)"
    fi
}

start_services() {
    print_info "Starting WireGuard service..."

    # Enable and start WireGuard
    systemctl enable wg-quick@${WG_INTERFACE} || error_exit "Failed to enable WireGuard service"
    systemctl start wg-quick@${WG_INTERFACE} || error_exit "Failed to start WireGuard service"

    # Verify it's running (with retries)
    print_info "Verifying service is active..."
    local max_attempts=3
    local attempt=1
    local service_active=false

    while [[ $attempt -le $max_attempts ]]; do
        sleep 1
        if systemctl is-active --quiet wg-quick@${WG_INTERFACE}; then
            service_active=true
            break
        fi

        if [[ $attempt -lt $max_attempts ]]; then
            print_warning "Service not active yet, retrying ($attempt/$max_attempts)..."
        fi
        ((attempt++)) || true
    done

    if [[ "$service_active" == false ]]; then
        echo ""
        print_error "WireGuard interface failed to start after $max_attempts attempts!"
        echo ""
        print_info "Checking for errors..."
        journalctl -xeu wg-quick@${WG_INTERFACE}.service --no-pager -n 20
        echo ""
        error_exit "Failed to start ${WG_INTERFACE}. Check the error logs above."
    fi

    print_success "WireGuard service is running"
    log "WireGuard service started successfully"

    # Re-apply firewall zone after interface is created
    if command -v firewall-cmd &> /dev/null && systemctl is-active --quiet firewalld 2>/dev/null; then
        print_info "Verifying firewall zone assignment..."

        # Make sure WireGuard is in trusted zone
        if ! firewall-cmd --zone=trusted --query-interface=${WG_INTERFACE} 2>/dev/null; then
            print_warning "WireGuard interface not in trusted zone, fixing..."
            firewall-cmd --zone=trusted --add-interface=${WG_INTERFACE} 2>/dev/null || true
        fi

        print_success "Firewall zone verified"
    fi

    # Show interface status
    if wg show ${WG_INTERFACE} &>/dev/null; then
        print_success "WireGuard interface ${WG_INTERFACE} is up"
    fi

    # Set up routes for site-to-site connections
    setup_site_routes
}

################################################################################
# POST-INSTALL SUMMARY
################################################################################

show_summary() {
    echo ""
    echo "=========================================="
    print_success "WireGuard Server Setup Complete!"
    echo "=========================================="
    echo ""
    print_info "Configuration Details:"
    echo "  Interface: ${WG_INTERFACE}"
    echo "  Server IP: ${SERVER_IP}"
    echo "  Listen Port: ${WG_PORT}"
    echo "  Primary Interface: ${PRIMARY_INTERFACE}"
    echo "  Firewall: ${FIREWALL_TYPE}"
    echo ""
    print_info "Server Public Key:"
    echo "  ${SERVER_PUBLIC_KEY}"
    echo ""
    print_info "Configuration File:"
    echo "  ${WG_CONFIG_FILE}"
    echo ""
    print_info "Useful Commands:"
    echo "  Show status:    wg show"
    echo "  Show all:       wg show all"
    echo "  Stop service:   systemctl stop wg-quick@${WG_INTERFACE}"
    echo "  Start service:  systemctl start wg-quick@${WG_INTERFACE}"
    echo "  Restart:        systemctl restart wg-quick@${WG_INTERFACE}"
    echo "  View logs:      journalctl -u wg-quick@${WG_INTERFACE} -f"
    echo ""
    print_info "Next Steps:"
    echo "  1. Add client configurations to ${WG_CONFIG_FILE}"
    echo "  2. Generate client keys and configs"
    echo "  3. Restart WireGuard: systemctl restart wg-quick@${WG_INTERFACE}"
    echo ""

    # Check if there are other WireGuard servers running
    local other_servers=0
    if [[ -d "$WG_CONFIG_DIR" ]]; then
        for conf in "$WG_CONFIG_DIR"/*.conf; do
            [[ ! -f "$conf" ]] && continue
            local iface=$(basename "$conf" .conf)
            if [[ "$iface" != "$WG_INTERFACE" ]] && systemctl is-active --quiet "wg-quick@${iface}"; then
                ((other_servers++)) || true
            fi
        done
    fi

    if [[ $other_servers -gt 0 ]]; then
        echo ""
        print_info "Multiple WireGuard Servers:"
        echo "  You now have multiple WireGuard servers running on this VM."
        echo "  Each server uses its own interface, port, and network."
        echo "  Make sure clients connect to the correct server/port combination."
        echo ""
        echo "  View all active servers: wg show all"
        echo ""
    fi

    print_info "Log file: ${LOG_FILE}"
    echo "=========================================="
    echo ""

    # Final reminder about running this script again
    if [[ $other_servers -eq 0 ]]; then
        echo ""
        print_info "Running Multiple WireGuard Servers:"
        echo "  You can run this script again to create additional WireGuard servers"
        echo "  on this VM. Each server must use:"
        echo "    - A unique interface name (e.g., wg0, wg1, wg2)"
        echo "    - A unique port number (e.g., 51820, 51821, 51822)"
        echo "    - A unique network range (e.g., 10.0.0.0/24, 10.0.1.0/24)"
        echo ""
        echo "  Example: sudo ./setup-wireguard.sh --interface wg1 --port 51821 --server-ip 10.0.1.1/24 --network 10.0.1.0/24"
        echo ""
    fi
}

################################################################################
# MAIN EXECUTION FLOW
################################################################################

main() {
    echo "=========================================="
    echo "  WireGuard Setup Script"
    echo "=========================================="
    echo ""

    # Initialize log file
    mkdir -p "$(dirname "$LOG_FILE")"
    log "=== WireGuard Setup Started ==="

    # Parse command-line arguments
    parse_arguments "$@"

    # Prerequisite checks
    check_root
    check_kernel
    check_os
    check_wireguard_installed

    # Check if importing existing config
    if [[ "$MODE" == "import-config" ]]; then
        print_info "Import mode: Using existing configuration file"

        # Import the config
        import_existing_config

        # Installation steps
        install_packages
        enable_ip_forwarding

        # Configure firewall (detect mode from config)
        if [[ -n "$LAN_INTERFACE" ]]; then
            # Site-to-site mode detected
            MODE="site-to-site"
        else
            # Regular client mode
            MODE="client"
        fi
        configure_firewall
        handle_selinux
        start_services
    else
        # Normal mode: create new config

        # Ask user to select mode (server or peer)
        prompt_mode_selection

        # Get user configuration based on mode
        if [[ "$MODE" == "server" ]]; then
            prompt_user_config
        else
            # Both client and site-to-site use the same prompt function
            prompt_client_config
        fi

        # Check existing config after we know the interface name
        check_existing_config

        # Installation steps
        install_packages
        enable_ip_forwarding

        # Mode-specific configuration
        if [[ "$MODE" == "server" ]]; then
            generate_keys
            create_config
        else
            # Both client and site-to-site generate keys and config the same way
            generate_client_keys
            create_client_config
        fi

        configure_firewall
        handle_selinux
        start_services
    fi

    # Summary
    show_summary

    log "=== WireGuard Setup Completed Successfully ==="
}

# Execute main function
main "$@"
