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
#   -h, --help           Show this help message
#
# Examples:
#   # First server with defaults
#   sudo ./setup-wireguard.sh
#
#   # Second server on same VM
#   sudo ./setup-wireguard.sh --interface wg1 --port 51821 \
#        --server-ip 10.0.1.1/24 --network 10.0.1.0/24
################################################################################

set -euo pipefail

################################################################################
# CONFIGURATION VARIABLES - Defaults
################################################################################

DEFAULT_WG_INTERFACE="wg0"
DEFAULT_WG_PORT=51820
DEFAULT_SERVER_IP="10.0.0.1/24"
DEFAULT_SERVER_NETWORK="10.0.0.0/24"

# These will be set by parse_arguments() and prompt_user_config()
WG_INTERFACE=""
WG_PORT=""
SERVER_IP=""
SERVER_NETWORK=""

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
    echo "  --server-ip IP        Server IP address (default: ${DEFAULT_SERVER_IP})"
    echo "  --network CIDR        VPN network CIDR (default: ${DEFAULT_SERVER_NETWORK})"
    echo "  --port PORT           WireGuard listen port (default: ${DEFAULT_WG_PORT})"
    echo "  --interface NAME      Interface name (default: ${DEFAULT_WG_INTERFACE})"
    echo "  -h, --help           Show this help message"
    echo ""
    echo "Example:"
    echo "  sudo $0 --server-ip 192.168.100.1/24 --network 192.168.100.0/24 --port 51820"
    echo ""
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
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

    # Prompt for interface name if not set
    if [[ -z "$WG_INTERFACE" ]]; then
        while true; do
            read -p "Enter WireGuard interface name [${DEFAULT_WG_INTERFACE}]: " input_interface
            WG_INTERFACE="${input_interface:-$DEFAULT_WG_INTERFACE}"

            if check_interface_conflicts "$WG_INTERFACE"; then
                break
            else
                print_error "Please choose a different interface name"
            fi
        done
    else
        if ! check_interface_conflicts "$WG_INTERFACE"; then
            error_exit "Interface $WG_INTERFACE is already in use. Please choose a different name."
        fi
    fi

    # Prompt for port if not set
    if [[ -z "$WG_PORT" ]]; then
        while true; do
            read -p "Enter WireGuard listen port [${DEFAULT_WG_PORT}]: " input_port
            WG_PORT="${input_port:-$DEFAULT_WG_PORT}"

            if ! validate_port "$WG_PORT"; then
                print_error "Invalid port number. Must be between 1 and 65535."
                continue
            fi

            if check_port_conflicts "$WG_PORT"; then
                break
            else
                print_error "Please choose a different port"
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

    # Prompt for server IP if not set
    if [[ -z "$SERVER_IP" ]]; then
        while true; do
            read -p "Enter server IP address with CIDR [${DEFAULT_SERVER_IP}]: " input_server_ip
            SERVER_IP="${input_server_ip:-$DEFAULT_SERVER_IP}"

            if ! validate_ip_cidr "$SERVER_IP"; then
                print_error "Invalid IP/CIDR format. Example: 10.0.0.1/24"
                continue
            fi

            # Extract just the network part for conflict checking
            local network_check=$(echo "$SERVER_IP" | cut -d'/' -f1 | awk -F. '{print $1"."$2"."$3".0/"}')"$(echo "$SERVER_IP" | cut -d'/' -f2)"

            if check_network_conflicts "$network_check"; then
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
        if ! validate_ip_cidr "$SERVER_IP"; then
            error_exit "Invalid IP/CIDR format: $SERVER_IP"
        fi
    fi

    # Prompt for network if not set
    if [[ -z "$SERVER_NETWORK" ]]; then
        while true; do
            read -p "Enter VPN network CIDR [${DEFAULT_SERVER_NETWORK}]: " input_network
            SERVER_NETWORK="${input_network:-$DEFAULT_SERVER_NETWORK}"

            if validate_network_cidr "$SERVER_NETWORK"; then
                break
            else
                print_error "Invalid network CIDR format. Example: 10.0.0.0/24"
            fi
        done
    else
        if ! validate_network_cidr "$SERVER_NETWORK"; then
            error_exit "Invalid network CIDR format: $SERVER_NETWORK"
        fi
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
    echo ""

    read -p "Continue with this configuration? (Y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        error_exit "Configuration cancelled by user"
    fi

    log "Configuration: Interface=${WG_INTERFACE}, Port=${WG_PORT}, ServerIP=${SERVER_IP}, Network=${SERVER_NETWORK}"
    log "Keys Directory: ${WG_KEYS_DIR}"
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
    if ! grep -q "net.ipv4.ip_forward" "$sysctl_conf" 2>/dev/null; then
        echo "net.ipv4.ip_forward = 1" > "$sysctl_conf"
        log "IP forwarding enabled permanently in $sysctl_conf"
    fi

    print_success "IP forwarding enabled"
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

    cat > "$WG_CONFIG_FILE" <<EOF
[Interface]
Address = ${SERVER_IP}
ListenPort = ${WG_PORT}
PrivateKey = ${SERVER_PRIVATE_KEY}

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

    # Add WireGuard port
    firewall-cmd --permanent --add-port=${WG_PORT}/udp || error_exit "Failed to add WireGuard port"

    # Enable masquerading
    firewall-cmd --permanent --add-masquerade || error_exit "Failed to enable masquerading"

    # Add WireGuard interface to internal zone
    firewall-cmd --permanent --zone=internal --add-interface=${WG_INTERFACE} 2>/dev/null || true

    # Reload firewall
    firewall-cmd --reload || error_exit "Failed to reload firewalld"

    print_success "firewalld configured"
    log "firewalld configured with port ${WG_PORT}/udp"
}

configure_ufw() {
    print_info "Configuring ufw..."

    # Allow WireGuard port
    ufw allow ${WG_PORT}/udp || error_exit "Failed to add WireGuard port"

    # Enable forwarding in ufw
    sed -i 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw 2>/dev/null || true

    print_success "ufw configured"
    log "ufw configured with port ${WG_PORT}/udp"
}

configure_iptables() {
    print_info "Configuring iptables..."

    # Apply iptables rules directly
    iptables -A FORWARD -i ${WG_INTERFACE} -j ACCEPT 2>/dev/null || true
    iptables -A FORWARD -o ${WG_INTERFACE} -j ACCEPT 2>/dev/null || true
    iptables -t nat -A POSTROUTING -s ${SERVER_NETWORK} -o ${PRIMARY_INTERFACE} -j MASQUERADE 2>/dev/null || true

    print_success "iptables configured"
    log "iptables rules applied for ${WG_INTERFACE}"
}

configure_nftables() {
    print_info "Configuring nftables..."

    # Apply nftables rules directly
    nft add table inet wireguard 2>/dev/null || true
    nft add chain inet wireguard forward { type filter hook forward priority 0 \; policy accept \; } 2>/dev/null || true
    nft add rule inet wireguard forward iifname "${WG_INTERFACE}" accept 2>/dev/null || true
    nft add rule inet wireguard forward oifname "${WG_INTERFACE}" accept 2>/dev/null || true
    nft add table ip nat 2>/dev/null || true
    nft add chain ip nat postrouting { type nat hook postrouting priority 100 \; } 2>/dev/null || true
    nft add rule ip nat postrouting ip saddr ${SERVER_NETWORK} oifname "${PRIMARY_INTERFACE}" masquerade 2>/dev/null || true

    print_success "nftables configured"
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

start_services() {
    print_info "Starting WireGuard service..."

    # Enable and start WireGuard
    systemctl enable wg-quick@${WG_INTERFACE} || error_exit "Failed to enable WireGuard service"
    systemctl start wg-quick@${WG_INTERFACE} || error_exit "Failed to start WireGuard service"

    # Verify it's running
    if systemctl is-active --quiet wg-quick@${WG_INTERFACE}; then
        print_success "WireGuard service is running"
        log "WireGuard service started successfully"
    else
        error_exit "WireGuard service failed to start"
    fi

    # Show interface status
    if wg show ${WG_INTERFACE} &>/dev/null; then
        print_success "WireGuard interface ${WG_INTERFACE} is up"
    fi
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
                ((other_servers++))
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
    echo "  WireGuard Server Setup Script"
    echo "=========================================="
    echo ""

    # Initialize log file
    mkdir -p "$(dirname "$LOG_FILE")"
    log "=== WireGuard Server Setup Started ==="

    # Parse command-line arguments
    parse_arguments "$@"

    # Prerequisite checks
    check_root
    check_kernel
    check_os
    check_wireguard_installed

    # Get user configuration (prompts for any values not provided via arguments)
    prompt_user_config

    # Check existing config after we know the interface name
    check_existing_config

    # Installation steps
    install_packages
    enable_ip_forwarding
    generate_keys
    create_config
    configure_firewall
    handle_selinux
    start_services

    # Summary
    show_summary

    log "=== WireGuard Server Setup Completed Successfully ==="
}

# Execute main function
main "$@"
