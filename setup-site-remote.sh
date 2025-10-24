#!/bin/bash
################################################################################
# WireGuard Remote Site Setup Script
# Description: Configure a remote site to connect to main WireGuard server
# Usage: sudo ./setup-site-remote.sh [OPTIONS]
################################################################################

set -euo pipefail

################################################################################
# CONFIGURATION
################################################################################

WG_INTERFACE="wg-client"
WG_CONFIG_FILE=""
LAN_INTERFACE=""
VPN_NETWORKS=""

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

remove_existing_wireguard() {
    print_info "Removing existing WireGuard setup for '${WG_INTERFACE}'..."

    # Stop interface if running
    if ip link show "${WG_INTERFACE}" &>/dev/null; then
        print_info "Stopping interface..."
        wg-quick down "${WG_INTERFACE}" 2>/dev/null || true
        sleep 1
    fi

    # Disable service
    if systemctl is-enabled "wg-quick@${WG_INTERFACE}" &>/dev/null; then
        print_info "Disabling service on boot..."
        systemctl disable "wg-quick@${WG_INTERFACE}" 2>/dev/null || true
    fi

    # Remove config file
    if [[ -f "/etc/wireguard/${WG_INTERFACE}.conf" ]]; then
        print_info "Removing config file..."
        rm -f "/etc/wireguard/${WG_INTERFACE}.conf"
    fi

    print_success "Existing setup removed"
    echo ""
}

check_existing_wireguard() {
    local config_exists=false
    local interface_running=false
    local service_exists=false

    # Check if WireGuard config already exists
    if [[ -f "/etc/wireguard/${WG_INTERFACE}.conf" ]]; then
        config_exists=true
    fi

    # Check if interface is already running
    if ip link show "${WG_INTERFACE}" &>/dev/null; then
        interface_running=true
    fi

    # Check if systemd service exists
    if systemctl list-unit-files | grep -q "wg-quick@${WG_INTERFACE}.service"; then
        service_exists=true
    fi

    # If any exists, prompt user to remove or exit
    if [[ "$config_exists" == true ]] || [[ "$interface_running" == true ]] || [[ "$service_exists" == true ]]; then
        echo ""
        print_warning "WireGuard site setup already exists for interface '${WG_INTERFACE}'"
        echo ""

        if [[ "$service_exists" == true ]]; then
            print_info "Systemd service exists: wg-quick@${WG_INTERFACE}.service"
            local service_status=$(systemctl is-active "wg-quick@${WG_INTERFACE}" 2>/dev/null || echo "inactive")
            local service_enabled=$(systemctl is-enabled "wg-quick@${WG_INTERFACE}" 2>/dev/null || echo "disabled")
            echo "  Status: ${service_status}"
            echo "  Enabled: ${service_enabled}"
            echo ""
        fi

        if [[ "$interface_running" == true ]]; then
            print_info "Interface is currently running:"
            wg show "${WG_INTERFACE}" 2>/dev/null || true
            echo ""
        fi

        if [[ "$config_exists" == true ]]; then
            print_info "Configuration file: /etc/wireguard/${WG_INTERFACE}.conf"
            echo ""
        fi

        echo "Options:"
        echo "  1. Remove existing setup and continue"
        echo "  2. Cancel and exit"
        echo "  3. Use a different interface name"
        echo ""
        read -p "Choose an option [1/2/3] (default: 2): " -n 1 -r
        echo
        echo ""

        case "$REPLY" in
            1)
                remove_existing_wireguard
                ;;
            3)
                echo "Use the --interface option to specify a different name:"
                echo "  sudo $0 --interface wg-site2 --config <config-file>"
                echo ""
                exit 0
                ;;
            2|"")
                print_info "Setup cancelled. Existing configuration preserved."
                echo ""
                echo "To remove manually:"
                echo "  sudo wg-quick down ${WG_INTERFACE}"
                echo "  sudo systemctl disable wg-quick@${WG_INTERFACE}"
                echo "  sudo rm /etc/wireguard/${WG_INTERFACE}.conf"
                echo ""
                exit 0
                ;;
            *)
                print_error "Invalid option. Setup cancelled."
                exit 1
                ;;
        esac
    fi

    print_success "No conflicting WireGuard setup found"
}

detect_lan_interface() {
    # Detect primary LAN interface (the one with default route)
    local primary_iface=$(ip route | grep default | awk '{print $5}' | head -n1)

    if [[ -z "$primary_iface" ]]; then
        echo ""
        return
    fi

    echo "$primary_iface"
}

get_vpn_networks_from_config() {
    local config_file="$1"

    if [[ ! -f "$config_file" ]]; then
        echo ""
        return
    fi

    # Extract AllowedIPs from config
    local allowed_ips=$(grep -E "^AllowedIPs\s*=" "$config_file" | awk '{print $3}')

    echo "$allowed_ips"
}

install_wireguard() {
    print_info "Checking WireGuard installation..."

    if command -v wg &> /dev/null; then
        print_success "WireGuard is already installed"
        return
    fi

    print_info "Installing WireGuard..."

    # Detect OS
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS=$ID
    else
        error_exit "Cannot detect OS. Please install WireGuard manually."
    fi

    case "$OS" in
        rhel|centos|rocky|almalinux|fedora)
            dnf install -y wireguard-tools || yum install -y wireguard-tools || error_exit "Failed to install WireGuard"
            ;;
        ubuntu|debian)
            apt-get update
            apt-get install -y wireguard-tools || error_exit "Failed to install WireGuard"
            ;;
        *)
            error_exit "Unsupported OS: $OS. Please install WireGuard manually."
            ;;
    esac

    print_success "WireGuard installed"
}

enable_ip_forwarding() {
    print_info "Enabling IP forwarding..."

    # Check current status
    local current_forward=$(sysctl -n net.ipv4.ip_forward)

    if [[ "$current_forward" == "1" ]]; then
        print_success "IP forwarding already enabled"
    else
        # Enable temporarily
        sysctl -w net.ipv4.ip_forward=1 > /dev/null

        # Enable permanently
        if grep -q "^net.ipv4.ip_forward" /etc/sysctl.conf; then
            sed -i 's/^net.ipv4.ip_forward.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf
        else
            echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
        fi

        sysctl -p > /dev/null

        print_success "IP forwarding enabled"
    fi
}

configure_firewall() {
    print_info "Configuring firewall rules..."

    # Detect firewall type
    local firewall_type=""

    if systemctl is-active --quiet firewalld; then
        firewall_type="firewalld"
    elif command -v ufw &> /dev/null && ufw status | grep -q "Status: active"; then
        firewall_type="ufw"
    elif command -v iptables &> /dev/null; then
        firewall_type="iptables"
    else
        print_warning "No recognized firewall found, skipping firewall configuration"
        return
    fi

    print_info "Detected firewall: ${firewall_type}"

    case "$firewall_type" in
        firewalld)
            configure_firewalld
            ;;
        ufw)
            configure_ufw
            ;;
        iptables)
            configure_iptables
            ;;
    esac
}

configure_firewalld() {
    print_info "Configuring firewalld..."

    # Add WireGuard interface to trusted zone
    firewall-cmd --permanent --zone=trusted --add-interface=${WG_INTERFACE} 2>/dev/null || true

    # Enable masquerading on public zone (for LAN interface)
    firewall-cmd --permanent --zone=public --add-masquerade

    # Add forwarding rules
    firewall-cmd --permanent --direct --add-rule ipv4 filter FORWARD 0 -i ${LAN_INTERFACE} -o ${WG_INTERFACE} -j ACCEPT
    firewall-cmd --permanent --direct --add-rule ipv4 filter FORWARD 0 -i ${WG_INTERFACE} -o ${LAN_INTERFACE} -j ACCEPT

    # Reload firewall
    firewall-cmd --reload

    print_success "Firewalld configured"
}

configure_ufw() {
    print_info "Configuring ufw..."

    # Enable forwarding in ufw config
    sed -i 's/^DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw 2>/dev/null || true

    # Add NAT rules to before.rules
    local ufw_before="/etc/ufw/before.rules"

    if ! grep -q "# WireGuard Site NAT rules" "$ufw_before" 2>/dev/null; then
        # Backup before.rules
        cp "$ufw_before" "${ufw_before}.backup.$(date +%Y%m%d_%H%M%S)"

        # Add NAT rules at the top after *filter
        cat > /tmp/wg-nat-rules <<EOF

# WireGuard Site NAT rules
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -o ${WG_INTERFACE} -j MASQUERADE
COMMIT

EOF

        # Insert after *filter line
        sed -i '/^\*filter/r /tmp/wg-nat-rules' "$ufw_before"
        rm /tmp/wg-nat-rules
    fi

    # Allow forwarding between interfaces
    ufw allow in on ${WG_INTERFACE} 2>/dev/null || true
    ufw allow out on ${WG_INTERFACE} 2>/dev/null || true

    # Reload ufw
    ufw reload 2>/dev/null || true

    print_success "UFW configured"
}

configure_iptables() {
    print_info "Configuring iptables..."

    # Add masquerading for VPN traffic
    iptables -t nat -C POSTROUTING -o ${WG_INTERFACE} -j MASQUERADE 2>/dev/null || \
        iptables -t nat -A POSTROUTING -o ${WG_INTERFACE} -j MASQUERADE

    # Add forwarding rules
    iptables -C FORWARD -i ${LAN_INTERFACE} -o ${WG_INTERFACE} -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -i ${LAN_INTERFACE} -o ${WG_INTERFACE} -j ACCEPT

    iptables -C FORWARD -i ${WG_INTERFACE} -o ${LAN_INTERFACE} -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -i ${WG_INTERFACE} -o ${LAN_INTERFACE} -j ACCEPT

    # Save rules (distribution-specific)
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        case "$ID" in
            rhel|centos|rocky|almalinux|fedora)
                if command -v iptables-save &> /dev/null; then
                    iptables-save > /etc/sysconfig/iptables 2>/dev/null || true
                fi
                ;;
            ubuntu|debian)
                if command -v netfilter-persistent &> /dev/null; then
                    netfilter-persistent save 2>/dev/null || true
                elif command -v iptables-persistent &> /dev/null; then
                    # Older method
                    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
                else
                    print_warning "Install iptables-persistent to make rules permanent:"
                    echo "  apt install iptables-persistent"
                fi
                ;;
        esac
    fi

    print_success "Iptables configured"
}

install_wireguard_config() {
    local config_file="$1"
    local dest="/etc/wireguard/${WG_INTERFACE}.conf"

    print_info "Installing WireGuard configuration..."

    # Create WireGuard config directory
    mkdir -p /etc/wireguard
    chmod 700 /etc/wireguard

    # Copy config
    cp "$config_file" "$dest"
    chmod 600 "$dest"

    print_success "Configuration installed: $dest"
}

start_wireguard() {
    print_info "Starting WireGuard..."

    # Stop if already running
    systemctl stop wg-quick@${WG_INTERFACE} 2>/dev/null || true
    sleep 1

    # Start WireGuard
    if ! wg-quick up ${WG_INTERFACE}; then
        error_exit "Failed to start WireGuard. Check configuration."
    fi

    # Enable on boot
    systemctl enable wg-quick@${WG_INTERFACE} 2>/dev/null || true

    print_success "WireGuard started and enabled on boot"
}

show_routing_instructions() {
    echo ""
    echo "=========================================="
    print_success "Site Setup Complete!"
    echo "=========================================="
    echo ""
    print_info "WireGuard Status:"
    wg show ${WG_INTERFACE} 2>/dev/null || true
    echo ""
    print_info "Configuration:"
    echo "  Interface: ${WG_INTERFACE}"
    echo "  LAN Interface: ${LAN_INTERFACE}"
    echo "  VPN Networks: ${VPN_NETWORKS}"
    echo ""
    print_warning "IMPORTANT: Configure LAN devices to route VPN traffic"
    echo ""
    echo "Option 1 - Add static routes on each LAN device:"
    echo "  For each network in VPN_NETWORKS, run on LAN devices:"

    # Parse VPN networks and show route commands
    local lan_gateway=$(ip route | grep default | awk '{print $3}' | head -n1)
    IFS=',' read -ra NETWORKS <<< "$VPN_NETWORKS"
    for network in "${NETWORKS[@]}"; do
        network=$(echo "$network" | xargs)  # Trim whitespace
        echo "    sudo ip route add ${network} via ${lan_gateway}"
    done

    echo ""
    echo "Option 2 - Configure DHCP server (recommended):"
    echo "  Add static routes to your router/DHCP server configuration"
    echo "  This pushes routes to all LAN devices automatically"
    echo ""
    print_info "Test connectivity:"
    echo "  From this site: ping <remote-vpn-ip>"
    echo "  From LAN device: ping <remote-vpn-ip>"
    echo ""
    echo "=========================================="
    echo ""
}

validate_config_file() {
    local config_file="$1"

    # Check if file exists
    if [[ ! -f "$config_file" ]]; then
        error_exit "Config file not found: $config_file"
    fi

    # Check if file is readable
    if [[ ! -r "$config_file" ]]; then
        error_exit "Config file not readable: $config_file (check permissions)"
    fi

    # Validate it's a WireGuard config
    if ! grep -q "\[Interface\]" "$config_file" 2>/dev/null; then
        error_exit "Invalid WireGuard config: missing [Interface] section in $config_file"
    fi

    if ! grep -q "\[Peer\]" "$config_file" 2>/dev/null; then
        error_exit "Invalid WireGuard config: missing [Peer] section in $config_file"
    fi

    # Check for required fields
    if ! grep -q "^PrivateKey" "$config_file" 2>/dev/null; then
        error_exit "Invalid WireGuard config: missing PrivateKey in $config_file"
    fi

    if ! grep -q "^Address" "$config_file" 2>/dev/null; then
        error_exit "Invalid WireGuard config: missing Address in $config_file"
    fi

    if ! grep -q "^Endpoint" "$config_file" 2>/dev/null; then
        error_exit "Invalid WireGuard config: missing Endpoint in $config_file"
    fi

    print_success "Config file validated: $config_file"
}

prompt_config() {
    echo ""
    print_info "Remote Site Configuration"
    echo ""

    # Config file
    if [[ -z "$WG_CONFIG_FILE" ]]; then
        echo "WireGuard Configuration File:"
        echo "  This is the .conf file generated by add-site-to-site.sh on main server"
        echo "  Example: /tmp/branch-office.conf"
        echo ""
        read -p "Enter path to WireGuard config file: " WG_CONFIG_FILE

        if [[ -z "$WG_CONFIG_FILE" ]]; then
            error_exit "Config file path is required"
        fi
    fi

    # Validate config file
    validate_config_file "$WG_CONFIG_FILE"

    # Extract VPN networks from config
    VPN_NETWORKS=$(get_vpn_networks_from_config "$WG_CONFIG_FILE")

    # LAN interface
    if [[ -z "$LAN_INTERFACE" ]]; then
        local detected_lan=$(detect_lan_interface)
        echo ""
        echo "LAN Network Interface:"
        echo "  This is the interface connected to your local network"

        if [[ -n "$detected_lan" ]]; then
            print_info "Detected primary interface: ${detected_lan}"
            read -p "Enter LAN interface [${detected_lan}]: " LAN_INTERFACE
            LAN_INTERFACE="${LAN_INTERFACE:-$detected_lan}"
        else
            echo "  Examples: eth0, ens192, enp0s3"
            echo ""
            echo "Available interfaces:"
            ip -br addr show | grep -v "lo " | awk '{print "    " $1 " - " $3}'
            echo ""
            read -p "Enter LAN interface: " LAN_INTERFACE

            if [[ -z "$LAN_INTERFACE" ]]; then
                error_exit "LAN interface is required"
            fi
        fi
    fi

    # Verify interface exists
    if ! ip link show "$LAN_INTERFACE" &>/dev/null; then
        error_exit "Interface '$LAN_INTERFACE' not found"
    fi

    print_success "Configuration validated"
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --config|-c)
                WG_CONFIG_FILE="$2"
                # Validate immediately if provided via argument
                if [[ -n "$WG_CONFIG_FILE" ]]; then
                    validate_config_file "$WG_CONFIG_FILE"
                fi
                shift 2
                ;;
            --lan-interface|-l)
                LAN_INTERFACE="$2"
                shift 2
                ;;
            --interface|-i)
                WG_INTERFACE="$2"
                shift 2
                ;;
            -h|--help)
                echo "Usage: sudo $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  -c, --config FILE         WireGuard config file from main server"
                echo "  -l, --lan-interface NAME  LAN network interface (e.g., eth0)"
                echo "  -i, --interface NAME      WireGuard interface name [wg-client]"
                echo "  -h, --help               Show this help"
                echo ""
                echo "Description:"
                echo "  Configures a remote site to connect to main WireGuard server"
                echo "  - Installs WireGuard"
                echo "  - Enables IP forwarding"
                echo "  - Configures NAT/masquerading"
                echo "  - Sets up firewall rules"
                echo ""
                echo "Example:"
                echo "  sudo $0 --config /tmp/branch-office.conf --lan-interface eth0"
                echo ""
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
    echo "  WireGuard Remote Site Setup"
    echo "=========================================="
    echo ""

    parse_arguments "$@"

    check_root
    check_existing_wireguard
    prompt_config

    echo ""
    print_warning "This will configure this system as a WireGuard site"
    echo "  Config file: ${WG_CONFIG_FILE}"
    echo "  LAN interface: ${LAN_INTERFACE}"
    echo "  WireGuard interface: ${WG_INTERFACE}"
    echo ""
    read -p "Continue? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        error_exit "Setup cancelled"
    fi

    install_wireguard
    enable_ip_forwarding
    install_wireguard_config "$WG_CONFIG_FILE"
    start_wireguard
    configure_firewall
    show_routing_instructions
}

main "$@"
