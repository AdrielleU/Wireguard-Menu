#!/bin/bash
################################################################################
# WireGuard Remote Site Setup Script
# Description: Configure a remote site to connect to main WireGuard server
# Usage: sudo ./setup-site-remote.sh [OPTIONS]
#
# Modes:
#   Setup Mode (default): Install and configure WireGuard site
#   Reset Mode: Remove WireGuard client configuration completely
################################################################################

set -euo pipefail

################################################################################
# CONFIGURATION
################################################################################

WG_CONFIG_DIR="/etc/wireguard"
WG_INTERFACE=""
WG_CONFIG_FILE=""
LAN_INTERFACE=""
VPN_NETWORKS=""
RESET_MODE=false
FIX_MASQUERADE_MODE=false

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

get_next_available_interface() {
    # Find next available wgN interface
    local n=0
    while [[ -f "${WG_CONFIG_DIR}/wg${n}.conf" ]] || ip link show "wg${n}" &>/dev/null; do
        ((n++)) || true
    done
    echo "wg${n}"
}

list_existing_wireguard_sites() {
    local found_sites=0

    if [[ -d "$WG_CONFIG_DIR" ]]; then
        # Use nullglob to handle case where no .conf files exist
        shopt -s nullglob
        local conf_files=("$WG_CONFIG_DIR"/*.conf)
        shopt -u nullglob

        for conf in "${conf_files[@]}"; do
            [[ ! -f "$conf" ]] && continue

            found_sites=1
            local iface_name=$(basename "$conf" .conf)
            local conf_ip=$(grep -E "^Address\s*=" "$conf" 2>/dev/null | head -n1 | awk '{print $3}' || echo "Unknown")
            local endpoint=$(grep -E "^Endpoint\s*=" "$conf" 2>/dev/null | head -n1 | awk '{print $3}' || echo "Unknown")
            local is_running=""

            if systemctl is-active --quiet "wg-quick@${iface_name}"; then
                is_running="${GREEN}[RUNNING]${NC}"
            else
                is_running="${YELLOW}[STOPPED]${NC}"
            fi

            echo -e "  - ${BLUE}${iface_name}${NC} $is_running - VPN IP: $conf_ip, Endpoint: $endpoint"
        done
    fi

    if [[ $found_sites -eq 0 ]]; then
        echo "  None found"
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

    # Remove old firewall rules to prevent conflicts
    print_info "Cleaning up old firewall rules..."
    remove_all_firewall_rules 2>/dev/null || true

    print_success "Existing setup removed"
    echo ""
}

################################################################################
# FULL RESET FUNCTIONS
################################################################################

detect_lan_from_config() {
    # Try to detect LAN interface from existing config or system
    local detected=""

    # First try to find it from existing firewall rules
    if systemctl is-active --quiet firewalld 2>/dev/null; then
        # Check firewalld direct rules for our WireGuard interface
        detected=$(firewall-cmd --direct --get-all-rules 2>/dev/null | grep -E "FORWARD.*-i [a-z0-9]+ -o ${WG_INTERFACE}" | grep -oP '\-i \K[a-z0-9]+' | head -n1 || echo "")
    elif command -v iptables &>/dev/null; then
        # Check iptables rules
        detected=$(iptables -L FORWARD -v 2>/dev/null | grep "${WG_INTERFACE}" | grep -oP 'in\s+\K[a-z0-9]+' | head -n1 || echo "")
    fi

    # Fallback to primary interface
    if [[ -z "$detected" ]]; then
        detected=$(detect_lan_interface)
    fi

    echo "$detected"
}

remove_firewalld_rules() {
    local lan_iface="$1"

    print_info "Removing firewalld rules..."

    # Remove interface from trusted zone
    if firewall-cmd --zone=trusted --query-interface=${WG_INTERFACE} 2>/dev/null; then
        firewall-cmd --permanent --zone=trusted --remove-interface=${WG_INTERFACE} 2>/dev/null || true
        print_success "Removed ${WG_INTERFACE} from trusted zone"
    fi

    # Remove masquerading from public zone (only if no other WireGuard interfaces exist)
    local other_wg_interfaces=$(ip link show type wireguard 2>/dev/null | grep -v "${WG_INTERFACE}" | grep -oP '^\d+: \K[^:]+' || true)
    if [[ -z "$other_wg_interfaces" ]]; then
        if firewall-cmd --zone=public --query-masquerade 2>/dev/null; then
            print_warning "Masquerading still enabled on public zone (may be used by other services)"
            echo "  To remove manually: sudo firewall-cmd --permanent --zone=public --remove-masquerade"
        fi
    fi

    # Remove forwarding rules
    if [[ -n "$lan_iface" ]]; then
        firewall-cmd --permanent --direct --remove-rule ipv4 filter FORWARD 0 -i ${lan_iface} -o ${WG_INTERFACE} -j ACCEPT 2>/dev/null || true
        firewall-cmd --permanent --direct --remove-rule ipv4 filter FORWARD 0 -i ${WG_INTERFACE} -o ${lan_iface} -j ACCEPT 2>/dev/null || true
        print_success "Removed forwarding rules for ${lan_iface} <-> ${WG_INTERFACE}"
    fi

    # Reload firewall
    firewall-cmd --reload 2>/dev/null || true

    print_success "Firewalld rules removed"
}

remove_ufw_rules() {
    print_info "Removing UFW rules..."

    local ufw_before="/etc/ufw/before.rules"

    # Check if our NAT rules exist
    if grep -q "# WireGuard Site NAT rules" "$ufw_before" 2>/dev/null; then
        # Create backup
        cp "$ufw_before" "${ufw_before}.backup.$(date +%Y%m%d_%H%M%S)"

        # Remove NAT rules section
        sed -i '/# WireGuard Site NAT rules/,/COMMIT/d' "$ufw_before"

        # Remove extra blank lines
        sed -i '/^$/N;/^\n$/D' "$ufw_before"

        print_success "Removed NAT rules from ${ufw_before}"
        echo "  Backup created: ${ufw_before}.backup.*"
    fi

    # Remove allow rules for WireGuard interface
    ufw delete allow in on ${WG_INTERFACE} 2>/dev/null || true
    ufw delete allow out on ${WG_INTERFACE} 2>/dev/null || true

    # Reset forward policy to DROP if no other WireGuard interfaces
    local other_wg_interfaces=$(ip link show type wireguard 2>/dev/null | grep -v "${WG_INTERFACE}" | grep -oP '^\d+: \K[^:]+' || true)
    if [[ -z "$other_wg_interfaces" ]]; then
        print_warning "Consider resetting forward policy to DROP:"
        echo "  Edit /etc/default/ufw and set: DEFAULT_FORWARD_POLICY=\"DROP\""
    fi

    # Reload UFW
    ufw reload 2>/dev/null || true

    print_success "UFW rules removed"
}

remove_iptables_rules() {
    print_info "Removing iptables rules..."

    # Remove masquerading for VPN traffic
    iptables -t nat -D POSTROUTING -o ${WG_INTERFACE} -j MASQUERADE 2>/dev/null || true

    # Remove forwarding rules (try with detected LAN interface)
    local lan_iface=$(detect_lan_from_config)
    if [[ -n "$lan_iface" ]]; then
        iptables -D FORWARD -i ${lan_iface} -o ${WG_INTERFACE} -j ACCEPT 2>/dev/null || true
        iptables -D FORWARD -i ${WG_INTERFACE} -o ${lan_iface} -j ACCEPT 2>/dev/null || true
        print_success "Removed forwarding rules for ${lan_iface} <-> ${WG_INTERFACE}"
    else
        print_warning "Could not detect LAN interface, skipping FORWARD rules"
        echo "  Check manually: sudo iptables -L FORWARD -v"
    fi

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
                elif [[ -f /etc/iptables/rules.v4 ]]; then
                    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
                fi
                ;;
        esac
    fi

    print_success "Iptables rules removed"
}

remove_all_firewall_rules() {
    print_info "Removing firewall rules..."

    # Detect LAN interface for rule removal
    local lan_iface=$(detect_lan_from_config)
    if [[ -n "$lan_iface" ]]; then
        print_info "Detected LAN interface: ${lan_iface}"
    fi

    # Detect and remove firewall rules
    if systemctl is-active --quiet firewalld 2>/dev/null; then
        remove_firewalld_rules "$lan_iface"
    elif command -v ufw &> /dev/null && ufw status | grep -q "Status: active"; then
        remove_ufw_rules
    elif command -v iptables &> /dev/null; then
        remove_iptables_rules
    else
        print_warning "No recognized firewall found"
    fi
}

remove_ip_forwarding_config() {
    print_info "Checking IP forwarding configuration..."

    local sysctl_modified=false

    # Check if IP forwarding was added by this script to /etc/sysctl.conf
    if grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null; then
        print_warning "IP forwarding enabled in /etc/sysctl.conf"
        echo "  This may be used by other services or WireGuard instances"
        echo ""
        read -p "Remove IP forwarding from /etc/sysctl.conf? (y/N): " -n 1 -r
        echo

        if [[ $REPLY =~ ^[Yy]$ ]]; then
            # Remove or comment out the line
            sed -i 's/^net.ipv4.ip_forward=1/# net.ipv4.ip_forward=1 # Disabled by setup-site-remote.sh reset/' /etc/sysctl.conf

            # Disable temporarily
            sysctl -w net.ipv4.ip_forward=0 > /dev/null 2>&1 || true

            print_success "IP forwarding disabled"
            sysctl_modified=true
        else
            print_info "IP forwarding left enabled"
        fi
    else
        print_info "IP forwarding not found in /etc/sysctl.conf"
    fi

    if [[ "$sysctl_modified" == true ]]; then
        sysctl -p > /dev/null 2>&1 || true
    fi
}

full_reset_client() {
    echo ""
    echo "=========================================="
    print_warning "WireGuard Client Reset Mode"
    echo "=========================================="
    echo ""
    print_info "This will remove ALL WireGuard client configurations for: ${WG_INTERFACE}"
    echo ""
    echo "Actions to be performed:"
    echo "  1. Stop and disable WireGuard service"
    echo "  2. Remove WireGuard interface"
    echo "  3. Delete configuration files"
    echo "  4. Remove firewall rules (NAT, forwarding, masquerading)"
    echo "  5. Optionally remove IP forwarding configuration"
    echo ""
    print_warning "WireGuard packages will NOT be removed"
    echo ""

    # Check if WireGuard client exists
    local config_exists=false
    local interface_running=false

    if [[ -f "/etc/wireguard/${WG_INTERFACE}.conf" ]]; then
        config_exists=true
    fi

    if ip link show "${WG_INTERFACE}" &>/dev/null; then
        interface_running=true
    fi

    if [[ "$config_exists" == false ]] && [[ "$interface_running" == false ]]; then
        print_warning "No WireGuard client configuration found for '${WG_INTERFACE}'"
        echo ""

        # Still offer to clean firewall rules
        read -p "Clean up any remaining firewall rules? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            remove_all_firewall_rules
        fi

        print_info "Nothing to reset"
        exit 0
    fi

    # Show current configuration
    if [[ "$config_exists" == true ]]; then
        print_info "Current configuration:"
        echo "  Config: /etc/wireguard/${WG_INTERFACE}.conf"

        if [[ -f "/etc/wireguard/${WG_INTERFACE}.conf" ]]; then
            local vpn_ip=$(grep -E "^Address\s*=" "/etc/wireguard/${WG_INTERFACE}.conf" | awk '{print $3}' || echo "Unknown")
            local endpoint=$(grep -E "^Endpoint\s*=" "/etc/wireguard/${WG_INTERFACE}.conf" | awk '{print $3}' || echo "Unknown")
            echo "  VPN IP: ${vpn_ip}"
            echo "  Endpoint: ${endpoint}"
        fi
        echo ""
    fi

    if [[ "$interface_running" == true ]]; then
        print_info "Interface status:"
        wg show "${WG_INTERFACE}" 2>/dev/null || echo "  (interface exists but no active tunnels)"
        echo ""
    fi

    # Confirm action
    print_warning "This action cannot be undone!"
    echo ""
    read -p "Type 'yes' to confirm full reset: " confirmation

    if [[ "$confirmation" != "yes" ]]; then
        print_info "Reset cancelled"
        exit 0
    fi

    echo ""
    print_info "Starting reset process..."
    echo ""

    # Step 1: Stop and disable service
    print_info "Step 1/5: Stopping WireGuard service..."
    if systemctl is-active --quiet "wg-quick@${WG_INTERFACE}" 2>/dev/null; then
        systemctl stop "wg-quick@${WG_INTERFACE}" 2>/dev/null || true
        print_success "Service stopped"
    else
        print_info "Service not running"
    fi

    if systemctl is-enabled --quiet "wg-quick@${WG_INTERFACE}" 2>/dev/null; then
        systemctl disable "wg-quick@${WG_INTERFACE}" 2>/dev/null || true
        print_success "Service disabled"
    else
        print_info "Service not enabled"
    fi

    # Step 2: Remove interface
    echo ""
    print_info "Step 2/5: Removing network interface..."
    if ip link show "${WG_INTERFACE}" &>/dev/null; then
        wg-quick down "${WG_INTERFACE}" 2>/dev/null || ip link delete "${WG_INTERFACE}" 2>/dev/null || true
        sleep 1

        if ip link show "${WG_INTERFACE}" &>/dev/null; then
            print_warning "Interface still exists, forcing removal..."
            ip link delete "${WG_INTERFACE}" 2>/dev/null || true
        fi

        print_success "Interface removed"
    else
        print_info "Interface not found"
    fi

    # Step 3: Delete configuration
    echo ""
    print_info "Step 3/5: Removing configuration files..."
    if [[ -f "/etc/wireguard/${WG_INTERFACE}.conf" ]]; then
        rm -f "/etc/wireguard/${WG_INTERFACE}.conf"
        print_success "Configuration deleted: /etc/wireguard/${WG_INTERFACE}.conf"
    else
        print_info "No configuration file found"
    fi

    # Step 4: Remove firewall rules
    echo ""
    print_info "Step 4/5: Removing firewall rules..."
    remove_all_firewall_rules

    # Step 5: IP forwarding
    echo ""
    print_info "Step 5/5: IP forwarding configuration..."
    remove_ip_forwarding_config

    # Final summary
    echo ""
    echo "=========================================="
    print_success "Reset Complete!"
    echo "=========================================="
    echo ""
    print_info "Summary:"
    echo "  ✓ WireGuard client '${WG_INTERFACE}' removed"
    echo "  ✓ Service stopped and disabled"
    echo "  ✓ Configuration files deleted"
    echo "  ✓ Firewall rules cleaned up"
    echo ""
    print_info "WireGuard packages remain installed"
    echo ""
    print_info "Next steps:"
    echo "  - To reinstall: sudo $0 --config <config-file> --lan-interface <interface>"
    echo "  - To remove packages:"

    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        case "$ID" in
            rhel|centos|rocky|almalinux|fedora)
                echo "      sudo dnf remove wireguard-tools"
                ;;
            ubuntu|debian)
                echo "      sudo apt remove wireguard-tools"
                ;;
        esac
    fi

    echo ""
    echo "=========================================="
    echo ""
}

select_or_create_interface() {
    # Check if there are ANY existing WireGuard sites
    local has_existing_sites=false

    if [[ -d "$WG_CONFIG_DIR" ]]; then
        shopt -s nullglob
        local conf_files=("$WG_CONFIG_DIR"/*.conf)
        shopt -u nullglob

        if [[ ${#conf_files[@]} -gt 0 ]]; then
            has_existing_sites=true
        fi
    fi

    # If user already specified interface via command line, validate it
    if [[ -n "$WG_INTERFACE" ]]; then
        print_info "Using specified interface: ${WG_INTERFACE}"

        # Check if this interface already exists
        if [[ -f "/etc/wireguard/${WG_INTERFACE}.conf" ]] || ip link show "${WG_INTERFACE}" &>/dev/null; then
            print_warning "Interface '${WG_INTERFACE}' already exists"

            # Show details and ask for confirmation
            if [[ -f "/etc/wireguard/${WG_INTERFACE}.conf" ]]; then
                local vpn_ip=$(grep -E "^Address\s*=" "/etc/wireguard/${WG_INTERFACE}.conf" 2>/dev/null | awk '{print $3}' || echo "Unknown")
                local endpoint=$(grep -E "^Endpoint\s*=" "/etc/wireguard/${WG_INTERFACE}.conf" 2>/dev/null | awk '{print $3}' || echo "Unknown")
                echo "  VPN IP: ${vpn_ip}"
                echo "  Endpoint: ${endpoint}"
            fi

            echo ""
            read -p "Replace existing ${WG_INTERFACE} config? (y/N): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                error_exit "Setup cancelled. Use --interface to specify a different interface."
            fi

            # Stop and backup existing config
            if ip link show "${WG_INTERFACE}" &>/dev/null; then
                print_info "Stopping interface..."
                wg-quick down "${WG_INTERFACE}" 2>/dev/null || true
                sleep 1
            fi

            if [[ -f "/etc/wireguard/${WG_INTERFACE}.conf" ]]; then
                local backup_file="/etc/wireguard/${WG_INTERFACE}.conf.backup.$(date +%Y%m%d_%H%M%S)"
                cp "/etc/wireguard/${WG_INTERFACE}.conf" "$backup_file"
                print_success "Old config backed up to: $backup_file"
            fi
        fi

        return
    fi

    # No interface specified - show menu
    if [[ "$has_existing_sites" == true ]]; then
        echo ""
        print_info "Existing WireGuard sites on this system:"
        list_existing_wireguard_sites
        echo ""

        # Get next available interface
        local suggested_interface=$(get_next_available_interface)

        echo "=========================================="
        echo "What would you like to do?"
        echo "=========================================="
        echo ""
        echo "  ${BLUE}1)${NC} Replace an existing site's configuration"
        echo "     - Select which interface to replace (wg0, wg1, etc.)"
        echo "     - Backs up old config"
        echo "     - Installs new config"
        echo ""
        echo "  ${BLUE}2)${NC} Create new site with different interface (suggested: ${suggested_interface})"
        echo "     - Keeps all existing sites running"
        echo "     - Creates new independent site"
        echo ""
        echo "  ${BLUE}3)${NC} Remove an existing site completely first"
        echo "     - Select which site to remove"
        echo "     - Then create new site"
        echo ""
        echo "  ${BLUE}4)${NC} Cancel and exit (keep everything as-is)"
        echo ""
        read -p "Choose an option (1/2/3/4) [default: 2]: " -n 1 -r
        echo
        echo ""

        case "$REPLY" in
            1)
                # Replace existing site
                echo "Available interfaces:"
                local i=1
                local interfaces=()

                shopt -s nullglob
                for conf in "$WG_CONFIG_DIR"/*.conf; do
                    local iface=$(basename "$conf" .conf)
                    interfaces+=("$iface")

                    local vpn_ip=$(grep -E "^Address\s*=" "$conf" 2>/dev/null | awk '{print $3}' || echo "Unknown")
                    local endpoint=$(grep -E "^Endpoint\s*=" "$conf" 2>/dev/null | awk '{print $3}' || echo "Unknown")
                    local is_running=""

                    if systemctl is-active --quiet "wg-quick@${iface}"; then
                        is_running="${GREEN}[RUNNING]${NC}"
                    else
                        is_running="${YELLOW}[STOPPED]${NC}"
                    fi

                    echo -e "  ${BLUE}${i})${NC} ${iface} ${is_running} - ${vpn_ip}, ${endpoint}"
                    ((i++)) || true
                done
                shopt -u nullglob

                echo ""
                read -p "Select interface to replace (1-${#interfaces[@]}): " selection

                if ! [[ "$selection" =~ ^[0-9]+$ ]] || [ "$selection" -lt 1 ] || [ "$selection" -gt "${#interfaces[@]}" ]; then
                    error_exit "Invalid selection"
                fi

                WG_INTERFACE="${interfaces[$((selection-1))]}"
                print_info "Selected: ${WG_INTERFACE}"
                echo ""

                # Stop and backup
                if ip link show "${WG_INTERFACE}" &>/dev/null; then
                    print_info "Stopping interface..."
                    wg-quick down "${WG_INTERFACE}" 2>/dev/null || true
                    sleep 1
                fi

                if [[ -f "/etc/wireguard/${WG_INTERFACE}.conf" ]]; then
                    local backup_file="/etc/wireguard/${WG_INTERFACE}.conf.backup.$(date +%Y%m%d_%H%M%S)"
                    cp "/etc/wireguard/${WG_INTERFACE}.conf" "$backup_file"
                    print_success "Old config backed up to: $backup_file"
                fi
                ;;
            2|"")
                # Create new site
                WG_INTERFACE="$suggested_interface"
                print_info "Creating new site with interface: ${WG_INTERFACE}"
                ;;
            3)
                # Remove existing first
                echo "Available interfaces to remove:"
                local i=1
                local interfaces=()

                shopt -s nullglob
                for conf in "$WG_CONFIG_DIR"/*.conf; do
                    local iface=$(basename "$conf" .conf)
                    interfaces+=("$iface")

                    local vpn_ip=$(grep -E "^Address\s*=" "$conf" 2>/dev/null | awk '{print $3}' || echo "Unknown")
                    local is_running=""

                    if systemctl is-active --quiet "wg-quick@${iface}"; then
                        is_running="${GREEN}[RUNNING]${NC}"
                    else
                        is_running="${YELLOW}[STOPPED]${NC}"
                    fi

                    echo -e "  ${BLUE}${i})${NC} ${iface} ${is_running} - ${vpn_ip}"
                    ((i++)) || true
                done
                shopt -u nullglob

                echo ""
                read -p "Select interface to remove (1-${#interfaces[@]}): " selection

                if ! [[ "$selection" =~ ^[0-9]+$ ]] || [ "$selection" -lt 1 ] || [ "$selection" -gt "${#interfaces[@]}" ]; then
                    error_exit "Invalid selection"
                fi

                WG_INTERFACE="${interfaces[$((selection-1))]}"
                print_info "Removing: ${WG_INTERFACE}"
                echo ""

                remove_existing_wireguard

                # After removal, use the same interface name for new setup
                print_info "Will create new site with interface: ${WG_INTERFACE}"
                ;;
            4)
                print_info "Setup cancelled. Existing configuration preserved."
                echo ""
                echo "Current sites:"
                list_existing_wireguard_sites
                echo ""
                exit 0
                ;;
            *)
                print_error "Invalid option. Setup cancelled."
                exit 1
                ;;
        esac
    else
        # No existing sites - create first one
        WG_INTERFACE="wg0"
        print_success "No existing sites found. Creating first site with interface: ${WG_INTERFACE}"
    fi

    echo ""
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

check_incorrect_masquerade() {
    print_info "Checking for incorrect masquerade rules on VPN interface..."

    local found_issues=false

    # Check firewalld
    if systemctl is-active --quiet firewalld 2>/dev/null; then
        # Check if masquerade is enabled on trusted zone (where WG interface is)
        if firewall-cmd --zone=trusted --query-masquerade 2>/dev/null; then
            print_warning "Found masquerade on trusted zone (affects VPN interface)"
            found_issues=true
        fi
    fi

    # Check UFW before.rules
    if command -v ufw &> /dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
        local ufw_before="/etc/ufw/before.rules"
        if grep -q "POSTROUTING -o ${WG_INTERFACE} -j MASQUERADE" "$ufw_before" 2>/dev/null; then
            print_warning "Found masquerade rule for ${WG_INTERFACE} in ${ufw_before}"
            found_issues=true
        fi
    fi

    # Check iptables NAT rules
    if command -v iptables &> /dev/null; then
        if iptables -t nat -L POSTROUTING -n 2>/dev/null | grep -q "${WG_INTERFACE}.*MASQUERADE"; then
            print_warning "Found masquerade rule for ${WG_INTERFACE} in iptables"
            found_issues=true
        fi
    fi

    if [[ "$found_issues" == true ]]; then
        echo ""
        print_warning "DETECTED INCORRECT MASQUERADE CONFIGURATION!"
        echo ""
        echo "For site-to-site VPN, the WireGuard interface should NOT masquerade traffic."
        echo "Masquerading hides the real source IP of the remote LAN from the main server."
        echo ""
        echo "This prevents the main server from:"
        echo "  - Pinging devices on the remote LAN"
        echo "  - Properly routing return traffic"
        echo "  - Seeing real client IPs in logs"
        echo ""
        read -p "Fix masquerade issues automatically? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            fix_incorrect_masquerade
        else
            print_warning "Masquerade issues not fixed - site-to-site routing may not work"
            echo "To fix manually later, run: sudo $0 --fix-masquerade"
        fi
    else
        print_success "No incorrect masquerade rules found"
    fi
}

fix_incorrect_masquerade() {
    print_info "Fixing incorrect masquerade rules..."

    local fixed_count=0

    # Fix firewalld
    if systemctl is-active --quiet firewalld 2>/dev/null; then
        if firewall-cmd --zone=trusted --query-masquerade 2>/dev/null; then
            print_info "Removing masquerade from trusted zone..."
            firewall-cmd --permanent --zone=trusted --remove-masquerade 2>/dev/null || true
            firewall-cmd --reload 2>/dev/null || true
            print_success "Fixed firewalld masquerade"
            ((fixed_count++))
        fi
    fi

    # Fix UFW
    if command -v ufw &> /dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
        local ufw_before="/etc/ufw/before.rules"
        if grep -q "POSTROUTING -o ${WG_INTERFACE} -j MASQUERADE" "$ufw_before" 2>/dev/null; then
            print_info "Removing masquerade from ${ufw_before}..."

            # Backup
            cp "$ufw_before" "${ufw_before}.backup-nomasq-$(date +%Y%m%d_%H%M%S)"

            # Remove the masquerade rule
            sed -i "/POSTROUTING -o ${WG_INTERFACE} -j MASQUERADE/d" "$ufw_before"

            # Remove empty NAT section if it exists
            sed -i '/# WireGuard Site NAT rules/,/COMMIT/{/# WireGuard Site NAT rules/d; /^\*nat/d; /:POSTROUTING ACCEPT/d; /COMMIT/d;}' "$ufw_before"

            # Clean up extra blank lines
            sed -i '/^$/N;/^\n$/D' "$ufw_before"

            ufw reload 2>/dev/null || true
            print_success "Fixed UFW masquerade (backup created)"
            ((fixed_count++))
        fi
    fi

    # Fix iptables
    if command -v iptables &> /dev/null; then
        if iptables -t nat -L POSTROUTING -n 2>/dev/null | grep -q "${WG_INTERFACE}.*MASQUERADE"; then
            print_info "Removing masquerade from iptables..."

            # Remove all MASQUERADE rules for WG interface
            while iptables -t nat -D POSTROUTING -o ${WG_INTERFACE} -j MASQUERADE 2>/dev/null; do
                :
            done

            # Save rules
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
                        elif [[ -f /etc/iptables/rules.v4 ]]; then
                            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
                        fi
                        ;;
                esac
            fi

            print_success "Fixed iptables masquerade"
            ((fixed_count++))
        fi
    fi

    if [[ $fixed_count -gt 0 ]]; then
        echo ""
        print_success "Fixed $fixed_count masquerade issue(s)"
        echo ""
        print_info "Changes applied:"
        echo "  - Removed masquerade on ${WG_INTERFACE}"
        echo "  - Forwarding rules remain intact"
        echo ""
        print_info "Site-to-site routing should now work correctly"
    else
        print_info "No masquerade issues found to fix"
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

    # Check for incorrect masquerade after initial setup
    echo ""
    check_incorrect_masquerade
}

configure_firewalld() {
    print_info "Configuring firewalld..."

    # Add WireGuard interface to trusted zone (allows all VPN traffic)
    # Check if interface is already in another zone
    local current_zone=$(firewall-cmd --get-zone-of-interface=${WG_INTERFACE} 2>/dev/null || echo "")
    if [[ -n "$current_zone" && "$current_zone" != "trusted" ]]; then
        echo ""
        print_error "Interface ${WG_INTERFACE} is already in zone '${current_zone}'"
        print_warning "For site-to-site VPN, ${WG_INTERFACE} must be in the 'trusted' zone"
        echo ""
        echo "To fix this, run:"
        echo "  sudo firewall-cmd --permanent --zone=${current_zone} --remove-interface=${WG_INTERFACE}"
        echo "  sudo firewall-cmd --permanent --zone=trusted --add-interface=${WG_INTERFACE}"
        echo "  sudo firewall-cmd --reload"
        echo ""
        error_exit "Fix the zone conflict and re-run this script"
    fi

    # Add to trusted zone
    print_info "Adding ${WG_INTERFACE} to trusted zone"
    if ! firewall-cmd --permanent --zone=trusted --add-interface=${WG_INTERFACE} 2>/dev/null; then
        print_warning "Failed to add ${WG_INTERFACE} to trusted zone (may already be added)"
    fi

    # IMPORTANT: Do NOT masquerade on WG interface for site-to-site
    # The main server needs to see the real source IP of the remote LAN
    # For site-to-site VPN, we do NOT enable masquerade at all
    # This allows proper routing between Site A LAN <-> VPN <-> Site B LAN

    # Add FORWARD rules for LAN <-> VPN traffic
    firewall-cmd --permanent --direct --add-rule ipv4 filter FORWARD 0 -i ${LAN_INTERFACE} -o ${WG_INTERFACE} -j ACCEPT 2>/dev/null || true
    firewall-cmd --permanent --direct --add-rule ipv4 filter FORWARD 0 -i ${WG_INTERFACE} -o ${LAN_INTERFACE} -j ACCEPT 2>/dev/null || true

    # Add FORWARD rules for peer-to-peer VPN traffic (essential for site-to-site)
    # Allow traffic between VPN peers through the tunnel
    firewall-cmd --permanent --direct --add-rule ipv4 filter FORWARD 0 -i ${WG_INTERFACE} -o ${WG_INTERFACE} -j ACCEPT 2>/dev/null || true
    firewall-cmd --permanent --direct --add-rule ipv4 filter FORWARD 0 -i ${WG_INTERFACE} -j ACCEPT 2>/dev/null || true
    firewall-cmd --permanent --direct --add-rule ipv4 filter FORWARD 0 -o ${WG_INTERFACE} -j ACCEPT 2>/dev/null || true

    # NEW: Add firewalld policy for zone-to-zone forwarding (required for firewalld 0.9.0+)
    # Policies control traffic flow between zones in newer firewalld versions
    echo ""
    print_info "Configuring firewall zones for site-to-site VPN..."
    print_info "  - WireGuard interface (${WG_INTERFACE}) → 'trusted' zone"
    print_info "  - LAN interface (${LAN_INTERFACE}) → auto-detected zone"
    print_info "  - Default: 'public' zone (recommended for VPN)"
    echo ""

    # Detect the zone of the LAN interface
    local lan_zone=$(firewall-cmd --get-zone-of-interface=${LAN_INTERFACE} 2>/dev/null)

    # For VPN purposes, we simplify to use only public and trusted zones
    # Ignore internal zone and other zones, treat as public for consistency
    if [[ -z "$lan_zone" ]] || [[ "$lan_zone" == "internal" ]]; then
        lan_zone="public"
        print_success "Auto-selected zone 'public' for ${LAN_INTERFACE} (default for VPN)"
    else
        print_success "Detected zone '${lan_zone}' for ${LAN_INTERFACE}"
    fi

    # Check if firewalld supports policies (version 0.9.0+)
    if firewall-cmd --get-policies &>/dev/null; then
        print_info "Detected firewalld with policy support (0.9.0+)"

        # Create policy name based on zones
        local policy_name="${lan_zone}-to-trusted"

        # Remove existing policy if it exists (for clean reconfiguration)
        firewall-cmd --permanent --delete-policy=${policy_name} 2>/dev/null || true

        # Create new policy for LAN zone -> trusted zone (WireGuard)
        print_info "Creating firewalld policy: ${policy_name}"
        firewall-cmd --permanent --new-policy=${policy_name} 2>/dev/null || true
        firewall-cmd --permanent --policy=${policy_name} --set-target=ACCEPT
        firewall-cmd --permanent --policy=${policy_name} --add-ingress-zone=${lan_zone}
        firewall-cmd --permanent --policy=${policy_name} --add-egress-zone=trusted

        # Create reverse policy for trusted zone -> LAN zone (return traffic)
        local reverse_policy_name="trusted-to-${lan_zone}"
        firewall-cmd --permanent --delete-policy=${reverse_policy_name} 2>/dev/null || true
        firewall-cmd --permanent --new-policy=${reverse_policy_name} 2>/dev/null || true
        firewall-cmd --permanent --policy=${reverse_policy_name} --set-target=ACCEPT
        firewall-cmd --permanent --policy=${reverse_policy_name} --add-ingress-zone=trusted
        firewall-cmd --permanent --policy=${reverse_policy_name} --add-egress-zone=${lan_zone}

        print_success "Firewalld policies created for zone-to-zone forwarding"
        print_info "  - Policy: ${policy_name} (${lan_zone} → trusted)"
        print_info "  - Policy: ${reverse_policy_name} (trusted → ${lan_zone})"
    else
        print_info "Using direct rules only (older firewalld version)"
    fi

    # Reload firewall
    firewall-cmd --reload

    print_success "Firewalld configured (no masquerade - proper site-to-site routing)"
    print_info "  - ${WG_INTERFACE} added to trusted zone"
    print_info "  - ${LAN_INTERFACE} zone: ${lan_zone}"
    print_info "  - FORWARD rules: ${LAN_INTERFACE} <-> ${WG_INTERFACE}"
    print_info "  - FORWARD rules: VPN peer-to-peer traffic enabled"
}

configure_ufw() {
    print_info "Configuring ufw..."

    # Enable forwarding in ufw config (essential for site-to-site VPN)
    sed -i 's/^DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw 2>/dev/null || true

    # IMPORTANT: Do NOT add MASQUERADE on WG interface for site-to-site
    # The main server needs to see the real source IP of the remote LAN
    # No NAT rules needed in before.rules

    # Allow traffic on WireGuard interface (in/out)
    ufw allow in on ${WG_INTERFACE} 2>/dev/null || true
    ufw allow out on ${WG_INTERFACE} 2>/dev/null || true

    # Reload ufw
    ufw reload 2>/dev/null || true

    print_success "UFW configured (no masquerade on VPN interface)"
    print_info "  - Forwarding enabled for site-to-site VPN"
    print_info "  - Traffic allowed on ${WG_INTERFACE}"
}

configure_iptables() {
    print_info "Configuring iptables..."

    # IMPORTANT: Do NOT masquerade on WG interface for site-to-site
    # The main server needs to see the real source IP of the remote LAN
    # Only add forwarding rules (no NAT/MASQUERADE on VPN traffic)

    # Add FORWARD rules for LAN <-> VPN traffic
    iptables -C FORWARD -i ${LAN_INTERFACE} -o ${WG_INTERFACE} -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -i ${LAN_INTERFACE} -o ${WG_INTERFACE} -j ACCEPT

    iptables -C FORWARD -i ${WG_INTERFACE} -o ${LAN_INTERFACE} -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -i ${WG_INTERFACE} -o ${LAN_INTERFACE} -j ACCEPT

    # Add FORWARD rules for peer-to-peer VPN traffic (essential for site-to-site)
    iptables -C FORWARD -i ${WG_INTERFACE} -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -i ${WG_INTERFACE} -j ACCEPT

    iptables -C FORWARD -o ${WG_INTERFACE} -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -o ${WG_INTERFACE} -j ACCEPT

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

    print_success "Iptables configured (no masquerade on VPN interface)"
    print_info "  - FORWARD rules: ${LAN_INTERFACE} <-> ${WG_INTERFACE}"
    print_info "  - FORWARD rules: VPN peer-to-peer traffic enabled"
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

add_routes_for_vpn_networks() {
    print_info "Setting up routes for VPN networks..."

    # Extract AllowedIPs from the config file (networks we can reach via VPN)
    local config_file="/etc/wireguard/${WG_INTERFACE}.conf"
    local allowed_ips=$(grep -E "^AllowedIPs\s*=" "$config_file" | awk '{print $3}' | head -n1)

    if [[ -z "$allowed_ips" ]]; then
        print_warning "No AllowedIPs found in config, skipping route setup"
        return
    fi

    print_info "Networks accessible via VPN: $allowed_ips"

    # Parse AllowedIPs (comma-separated)
    IFS=',' read -ra NETWORKS <<< "$allowed_ips"
    local routes_added=0

    for network in "${NETWORKS[@]}"; do
        network=$(echo "$network" | xargs)  # Trim whitespace

        # Skip single host IPs (/32) - only add network routes
        if [[ "$network" =~ /32$ ]]; then
            print_info "Skipping /32 host route: $network (single IP)"
            continue
        fi

        # Check if route already exists
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
        print_success "Added $routes_added route(s) for VPN connectivity"
        echo ""
        print_info "Route verification:"
        ip route show | grep "${WG_INTERFACE}" | while read -r line; do
            echo "  $line"
        done
    else
        print_info "No new routes needed (already configured)"
    fi
}

start_wireguard() {
    print_info "Starting WireGuard..."

    # Stop if already running
    print_info "Stopping ${WG_INTERFACE} (if running)..."
    if ip link show "${WG_INTERFACE}" &>/dev/null; then
        systemctl stop wg-quick@${WG_INTERFACE} 2>/dev/null || wg-quick down ${WG_INTERFACE} 2>/dev/null || true
        sleep 1
        if ip link show "${WG_INTERFACE}" &>/dev/null; then
            print_warning "Interface still exists, forcing removal..."
            ip link delete dev "${WG_INTERFACE}" 2>/dev/null || true
        fi
    fi

    sleep 2

    # Start WireGuard with output capture
    print_info "Starting ${WG_INTERFACE}..."
    local start_time=$(date '+%Y-%m-%d %H:%M:%S')
    local start_output
    local start_success=false

    if start_output=$(wg-quick up ${WG_INTERFACE} 2>&1); then
        print_success "Interface started with wg-quick"
        start_success=true
    elif start_output=$(systemctl start wg-quick@${WG_INTERFACE} 2>&1); then
        print_success "Interface started with systemctl"
        start_success=true
    fi

    if [[ "$start_success" == false ]]; then
        echo ""
        print_error "Failed to start WireGuard interface!"
        echo ""
        print_info "Command output:"
        echo "$start_output"
        echo ""
        error_exit "Could not start ${WG_INTERFACE}"
    fi

    # Verify interface is actually up (check actual interface, not just systemd service)
    print_info "Verifying interface is up..."
    local max_attempts=3
    local attempt=1
    local interface_up=false

    while [[ $attempt -le $max_attempts ]]; do
        sleep 1
        if ip link show "${WG_INTERFACE}" &>/dev/null && wg show "${WG_INTERFACE}" &>/dev/null; then
            interface_up=true
            break
        fi

        if [[ $attempt -lt $max_attempts ]]; then
            print_warning "Interface not up yet, retrying ($attempt/$max_attempts)..."
        fi
        ((attempt++))
    done

    if [[ "$interface_up" == false ]]; then
        echo ""
        print_error "WireGuard interface failed to come up after $max_attempts attempts!"
        echo ""
        print_info "Checking for errors (logs since ${start_time})..."
        journalctl -xeu wg-quick@${WG_INTERFACE}.service --no-pager --since "$start_time"
        echo ""
        print_info "Current interface status:"
        ip link show "${WG_INTERFACE}" 2>&1 || echo "Interface not found"
        echo ""
        error_exit "Failed to start ${WG_INTERFACE}. Check the error logs above."
    fi

    print_success "WireGuard interface is up and running"

    # Enable on boot
    systemctl enable wg-quick@${WG_INTERFACE} 2>/dev/null || true
    print_success "WireGuard enabled on boot"

    # Add routes for VPN networks
    echo ""
    add_routes_for_vpn_networks
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
            --reset)
                RESET_MODE=true
                shift
                ;;
            --fix-masquerade)
                FIX_MASQUERADE_MODE=true
                shift
                ;;
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
                echo "Modes:"
                echo "  (default)                 Setup mode - configure WireGuard site"
                echo "  --reset                   Reset mode - remove WireGuard client completely"
                echo "  --fix-masquerade          Fix incorrect masquerade configuration"
                echo ""
                echo "Options:"
                echo "  -c, --config FILE         WireGuard config file from main server"
                echo "  -l, --lan-interface NAME  LAN network interface (e.g., eth0)"
                echo "  -i, --interface NAME      WireGuard interface name [auto: wg0, wg1, etc.]"
                echo "  -h, --help               Show this help"
                echo ""
                echo "Description:"
                echo "  Configures a remote site to connect to main WireGuard server"
                echo "  - Installs WireGuard"
                echo "  - Enables IP forwarding"
                echo "  - Configures firewall rules (NO masquerade on VPN)"
                echo "  - Checks for incorrect masquerade configuration"
                echo ""
                echo "Fix Masquerade Mode:"
                echo "  Detects and fixes incorrect masquerade on WireGuard interface"
                echo "  - For site-to-site VPN, masquerade breaks routing"
                echo "  - Removes MASQUERADE rules from firewall"
                echo "  - Keeps forwarding rules intact"
                echo ""
                echo "Reset Mode:"
                echo "  Removes WireGuard client configuration completely"
                echo "  - Stops and disables service"
                echo "  - Removes interface and config files"
                echo "  - Cleans up firewall rules (NAT, forwarding, masquerading)"
                echo "  - Optionally removes IP forwarding configuration"
                echo "  - Keeps WireGuard packages installed"
                echo ""
                echo "Examples:"
                echo "  sudo $0 --config /tmp/branch-office.conf --lan-interface eth0"
                echo ""
                echo "  sudo $0  # Interactive setup mode"
                echo ""
                echo "  sudo $0 --fix-masquerade  # Fix masquerade issues"
                echo ""
                echo "  sudo $0 --reset  # Remove WireGuard client (auto-detects wg0)"
                echo ""
                echo "  sudo $0 --reset --interface wg1  # Remove specific interface"
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
    parse_arguments "$@"
    check_root

    # Handle fix masquerade mode (needs interface)
    if [[ "$FIX_MASQUERADE_MODE" == true ]]; then
        # Set default interface if not specified
        if [[ -z "$WG_INTERFACE" ]]; then
            WG_INTERFACE=$(get_next_available_interface)
        fi

        echo "=========================================="
        echo "  Fix Masquerade Configuration"
        echo "=========================================="
        echo ""
        print_info "Checking for incorrect masquerade rules on ${WG_INTERFACE}..."
        echo ""
        check_incorrect_masquerade
        echo ""
        print_info "Done!"
        echo ""
        exit 0
    fi

    # Handle reset mode (needs interface)
    if [[ "$RESET_MODE" == true ]]; then
        # Set default interface if not specified
        if [[ -z "$WG_INTERFACE" ]]; then
            WG_INTERFACE=$(get_next_available_interface)
        fi

        full_reset_client
        exit 0
    fi

    # Normal setup mode
    echo "=========================================="
    echo "  WireGuard Remote Site Setup"
    echo "=========================================="
    echo ""

    # Step 1: Get config file first (required input)
    prompt_config

    # Step 2: Select or create interface (handles existing sites intelligently)
    select_or_create_interface

    # Step 3: Final confirmation
    echo ""
    echo "=========================================="
    print_warning "Setup Summary"
    echo "=========================================="
    echo ""
    echo "  Config file:         ${WG_CONFIG_FILE}"
    echo "  WireGuard interface: ${WG_INTERFACE}"
    echo "  LAN interface:       ${LAN_INTERFACE}"
    echo "  VPN networks:        ${VPN_NETWORKS}"
    echo ""
    read -p "Continue with setup? (Y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        error_exit "Setup cancelled"
    fi

    echo ""
    install_wireguard
    enable_ip_forwarding
    install_wireguard_config "$WG_CONFIG_FILE"
    start_wireguard
    configure_firewall
    show_routing_instructions
}

main "$@"
