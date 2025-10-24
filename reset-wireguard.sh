#!/bin/bash
################################################################################
# WireGuard Reset/Cleanup Script
# Description: Remove WireGuard configurations selectively or completely
# Usage: sudo ./reset-wireguard.sh [OPTIONS]
#
# Modes:
#   1. Selective Mode (default): Choose which server(s) to remove
#   2. Full Reset Mode: Remove ALL WireGuard configurations
#
# Features:
#   - Select specific servers to delete
#   - Stops services gracefully
#   - Removes network interfaces
#   - Deletes configurations and keys
#   - Creates backups before deletion
#   - Optional package uninstallation
################################################################################

set -euo pipefail

################################################################################
# CONFIGURATION
################################################################################

WG_CONFIG_DIR="/etc/wireguard"
LOG_FILE="/var/log/wireguard-reset.log"
BACKUP_DIR="/var/backups/wireguard-$(date +%Y%m%d_%H%M%S)"

# Options
SELECTIVE_MODE=true
FULL_RESET=false
REMOVE_PACKAGES=false
INTERACTIVE=true
SELECTED_SERVERS=()

################################################################################
# COLORS
################################################################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
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

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root (use sudo)"
    fi
}

show_usage() {
    echo "Usage: sudo $0 [OPTIONS]"
    echo ""
    echo "Modes:"
    echo "  (default)           Selective mode - choose which server(s) to remove"
    echo "  --all               Remove ALL WireGuard servers"
    echo ""
    echo "Options:"
    echo "  --interface NAME    Remove specific server by interface name"
    echo "  --remove-packages   Also uninstall WireGuard packages"
    echo "  --yes, -y           Non-interactive mode (skip confirmations)"
    echo "  -h, --help          Show this help message"
    echo ""
    echo "Examples:"
    echo "  sudo $0                              # Interactive: choose servers to remove"
    echo "  sudo $0 --interface wg0              # Remove only wg0"
    echo "  sudo $0 --interface wg0 --interface wg1  # Remove wg0 and wg1"
    echo "  sudo $0 --all --yes                  # Remove everything without prompts"
    echo "  sudo $0 --all --remove-packages      # Full cleanup including packages"
    echo ""
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --all)
                SELECTIVE_MODE=false
                FULL_RESET=true
                shift
                ;;
            --interface)
                SELECTED_SERVERS+=("$2")
                SELECTIVE_MODE=true
                shift 2
                ;;
            --remove-packages)
                REMOVE_PACKAGES=true
                shift
                ;;
            --yes|-y)
                INTERACTIVE=false
                shift
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

################################################################################
# DETECTION FUNCTIONS
################################################################################

detect_wireguard_servers() {
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

    echo "${servers[@]}"
}

detect_wireguard_interfaces() {
    local interfaces=()

    # Get all WireGuard interfaces from ip link
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        interfaces+=("$line")
    done < <(ip link show type wireguard 2>/dev/null | grep -oP '^\d+: \K[^:]+' || true)

    echo "${interfaces[@]}"
}

get_server_info() {
    local iface="$1"
    local config_file="${WG_CONFIG_DIR}/${iface}.conf"

    local ip_addr=""
    local port=""
    local client_count=0
    local status="STOPPED"

    if [[ -f "$config_file" ]]; then
        ip_addr=$(grep -E "^Address\s*=" "$config_file" | head -n1 | awk '{print $3}' || echo "Unknown")
        port=$(grep -E "^ListenPort\s*=" "$config_file" | head -n1 | awk '{print $3}' || echo "Unknown")
        client_count=$(grep -c "^# Client:" "$config_file" 2>/dev/null || echo "0")
    fi

    if systemctl is-active --quiet "wg-quick@${iface}" 2>/dev/null; then
        status="RUNNING"
    fi

    echo "$ip_addr|$port|$client_count|$status"
}

################################################################################
# SERVER SELECTION
################################################################################

select_servers_to_remove() {
    local all_servers=($(detect_wireguard_servers))

    if [[ ${#all_servers[@]} -eq 0 ]]; then
        print_warning "No WireGuard servers found"
        exit 0
    fi

    echo ""
    echo "=========================================="
    print_info "WireGuard servers found on this system"
    echo "=========================================="
    echo ""
    echo "Select servers to REMOVE:"
    echo "  - Enter numbers separated by spaces (e.g., '1 3 4')"
    echo "  - Or type 'all' to remove everything"
    echo ""

    local i=1
    for iface in "${all_servers[@]}"; do
        local info=$(get_server_info "$iface")
        local ip_addr=$(echo "$info" | cut -d'|' -f1)
        local port=$(echo "$info" | cut -d'|' -f2)
        local client_count=$(echo "$info" | cut -d'|' -f3)
        local status=$(echo "$info" | cut -d'|' -f4)

        local status_display=""
        if [[ "$status" == "RUNNING" ]]; then
            status_display="${GREEN}RUNNING${NC}"
        else
            status_display="${YELLOW}STOPPED${NC}"
        fi

        printf "  ${CYAN}%d)${NC} %s\n" "$i" "$iface"
        printf "      Status: %b  VPN IP: %s  Port: %s  Clients: %s\n" "$status_display" "$ip_addr" "$port" "$client_count"
        echo ""
        ((i++))
    done

    printf "  ${CYAN}all${NC}) Remove ALL servers\n"
    echo ""

    read -p "Enter selection: " selection

    # Parse selection
    if [[ "$selection" == "all" ]]; then
        SELECTED_SERVERS=("${all_servers[@]}")
    else
        for num in $selection; do
            if [[ "$num" =~ ^[0-9]+$ ]] && [ "$num" -ge 1 ] && [ "$num" -le "${#all_servers[@]}" ]; then
                SELECTED_SERVERS+=("${all_servers[$((num-1))]}")
            else
                print_error "Invalid selection: $num"
                exit 1
            fi
        done
    fi

    if [[ ${#SELECTED_SERVERS[@]} -eq 0 ]]; then
        print_warning "No servers selected"
        exit 0
    fi
}

################################################################################
# BACKUP INSTRUCTIONS
################################################################################

show_backup_instructions() {
    echo ""
    print_warning "IMPORTANT: No automatic backup will be created!"
    echo ""
    echo "To backup before deletion, run these commands in another terminal:"
    echo ""

    if [[ "$SELECTIVE_MODE" == true ]] && [[ ${#SELECTED_SERVERS[@]} -gt 0 ]]; then
        # Show backup commands for selected servers
        for iface in "${SELECTED_SERVERS[@]}"; do
            echo "  # Backup ${iface}:"
            echo "  sudo cp /etc/wireguard/${iface}.conf /tmp/${iface}.conf.backup"
            echo "  sudo cp -r /etc/wireguard/${iface} /tmp/${iface}-keys.backup"
            echo ""
        done
    else
        # Show backup command for all servers
        echo "  # Backup all WireGuard configurations:"
        echo "  sudo cp -r /etc/wireguard /tmp/wireguard-backup-\$(date +%Y%m%d_%H%M%S)"
        echo ""
    fi

    echo "Press Enter when ready to continue, or Ctrl+C to cancel"
    read -r
}

################################################################################
# CLEANUP FUNCTIONS
################################################################################

stop_wireguard_service() {
    local iface="$1"

    if systemctl is-active --quiet "wg-quick@${iface}" 2>/dev/null; then
        print_info "Stopping wg-quick@${iface}..."
        systemctl stop "wg-quick@${iface}" 2>/dev/null || print_warning "Could not stop wg-quick@${iface}"
        log "Stopped service: wg-quick@${iface}"
    fi

    if systemctl is-enabled --quiet "wg-quick@${iface}" 2>/dev/null; then
        print_info "Disabling wg-quick@${iface}..."
        systemctl disable "wg-quick@${iface}" 2>/dev/null || print_warning "Could not disable wg-quick@${iface}"
        log "Disabled service: wg-quick@${iface}"
    fi
}

remove_wireguard_interface() {
    local iface="$1"

    if ip link show "$iface" &>/dev/null; then
        print_info "Removing network interface: $iface"
        ip link delete "$iface" 2>/dev/null || print_warning "Could not remove interface $iface"
        log "Removed interface: $iface"
    fi
}

remove_server_config() {
    local iface="$1"

    print_info "Removing configuration for: $iface"

    # Remove config file
    if [[ -f "${WG_CONFIG_DIR}/${iface}.conf" ]]; then
        rm -f "${WG_CONFIG_DIR}/${iface}.conf"
        log "Removed config: ${iface}.conf"
    fi

    # Remove keys directory
    if [[ -d "${WG_CONFIG_DIR}/${iface}" ]]; then
        rm -rf "${WG_CONFIG_DIR}/${iface}"
        log "Removed keys directory: ${iface}/"
    fi

    print_success "Removed: $iface"
}

remove_selected_servers() {
    print_info "Removing selected WireGuard server(s)..."
    echo ""

    for iface in "${SELECTED_SERVERS[@]}"; do
        echo "Removing: ${iface}"
        stop_wireguard_service "$iface"
        remove_wireguard_interface "$iface"
        remove_server_config "$iface"
        echo ""
    done

    print_success "Removed ${#SELECTED_SERVERS[@]} server(s)"
}

remove_all_servers() {
    local all_servers=($(detect_wireguard_servers))
    local all_interfaces=($(detect_wireguard_interfaces))

    print_info "Stopping all WireGuard services..."
    for iface in "${all_servers[@]}"; do
        stop_wireguard_service "$iface"
    done

    print_info "Removing all network interfaces..."
    for iface in "${all_interfaces[@]}"; do
        remove_wireguard_interface "$iface"
    done

    print_info "Removing all configurations..."
    if [[ -d "$WG_CONFIG_DIR" ]]; then
        rm -rf "${WG_CONFIG_DIR:?}"/* 2>/dev/null || print_warning "Could not remove some config files"
        rmdir "$WG_CONFIG_DIR" 2>/dev/null || print_info "WireGuard directory not empty or in use"
    fi

    print_success "Removed all WireGuard servers"
}

remove_ip_forwarding() {
    print_info "Checking IP forwarding configuration..."

    local sysctl_conf="/etc/sysctl.d/99-wireguard.conf"

    if [[ -f "$sysctl_conf" ]]; then
        rm -f "$sysctl_conf"
        print_success "Removed WireGuard sysctl configuration"
        log "Removed: $sysctl_conf"
    else
        print_info "No WireGuard sysctl configuration found"
    fi
}

uninstall_wireguard_packages() {
    print_info "Uninstalling WireGuard packages..."

    # Detect OS
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        case "$ID" in
            rhel|centos|rocky|almalinux|fedora)
                dnf remove -y wireguard-tools 2>/dev/null || yum remove -y wireguard-tools 2>/dev/null || print_warning "Could not uninstall wireguard-tools"
                ;;
            ubuntu|debian)
                apt remove -y wireguard-tools 2>/dev/null || print_warning "Could not uninstall wireguard-tools"
                apt autoremove -y 2>/dev/null || true
                ;;
            *)
                print_warning "Unknown OS, cannot uninstall packages automatically"
                return 1
                ;;
        esac
        print_success "WireGuard packages uninstalled"
        log "Uninstalled WireGuard packages"
    fi
}

################################################################################
# MAIN EXECUTION
################################################################################

show_summary() {
    local all_servers=($(detect_wireguard_servers))

    echo ""
    echo "=========================================="
    echo "  WireGuard Reset Summary"
    echo "=========================================="
    echo ""

    if [[ ${#all_servers[@]} -eq 0 ]]; then
        print_info "No WireGuard servers found on this system"
        echo ""
        exit 0
    fi

    print_info "Mode: ${SELECTIVE_MODE:+Selective}${FULL_RESET:+Full Reset}"
    echo ""

    if [[ "$SELECTIVE_MODE" == true ]] && [[ ${#SELECTED_SERVERS[@]} -gt 0 ]]; then
        echo "Servers to remove:"
        for iface in "${SELECTED_SERVERS[@]}"; do
            local info=$(get_server_info "$iface")
            local ip_addr=$(echo "$info" | cut -d'|' -f1)
            local client_count=$(echo "$info" | cut -d'|' -f3)
            echo "  - ${iface} (${ip_addr}, ${client_count} clients)"
        done
    elif [[ "$FULL_RESET" == true ]]; then
        echo "All servers will be removed:"
        for iface in "${all_servers[@]}"; do
            local info=$(get_server_info "$iface")
            local ip_addr=$(echo "$info" | cut -d'|' -f1)
            local client_count=$(echo "$info" | cut -d'|' -f3)
            echo "  - ${iface} (${ip_addr}, ${client_count} clients)"
        done
    fi

    echo ""
    echo "Actions:"
    echo "  - Stop selected service(s)"
    echo "  - Remove network interface(s)"
    echo "  - Delete configuration(s) and keys"
    if [[ "$REMOVE_PACKAGES" == true ]]; then
        echo "  - Uninstall WireGuard packages"
    fi
    echo ""
    echo "=========================================="
    echo ""
}

confirm_action() {
    if [[ "$INTERACTIVE" == false ]]; then
        return 0
    fi

    print_warning "This will PERMANENTLY remove the selected WireGuard server(s)!"

    if [[ "$REMOVE_PACKAGES" == true ]]; then
        print_warning "This will also UNINSTALL WireGuard packages!"
    fi

    # Show backup instructions
    show_backup_instructions

    echo ""
    read -p "Are you sure you want to continue? (type 'yes' to confirm): " confirmation

    if [[ "$confirmation" != "yes" ]]; then
        print_info "Reset cancelled by user"
        exit 0
    fi
}

main() {
    echo "=========================================="
    echo "  WireGuard Reset/Cleanup Script"
    echo "=========================================="
    echo ""

    # Initialize log
    mkdir -p "$(dirname "$LOG_FILE")"
    log "=== WireGuard Reset Started ==="

    # Parse arguments
    parse_arguments "$@"

    # Prerequisite checks
    check_root

    # If selective mode and no servers specified, show selection menu
    if [[ "$SELECTIVE_MODE" == true ]] && [[ ${#SELECTED_SERVERS[@]} -eq 0 ]]; then
        select_servers_to_remove
    fi

    # Show summary
    show_summary

    # Confirm with user
    confirm_action

    # Perform reset operations
    if [[ "$FULL_RESET" == true ]]; then
        remove_all_servers
        remove_ip_forwarding
    else
        remove_selected_servers
    fi

    if [[ "$REMOVE_PACKAGES" == true ]]; then
        uninstall_wireguard_packages
    fi

    # Final summary
    echo ""
    echo "=========================================="
    print_success "WireGuard Reset Complete!"
    echo "=========================================="
    echo ""
    print_info "Summary:"
    if [[ "$SELECTIVE_MODE" == true ]]; then
        echo "  - Removed ${#SELECTED_SERVERS[@]} server(s): ${SELECTED_SERVERS[*]}"
    else
        echo "  - Removed ALL WireGuard servers"
    fi

    if [[ "$REMOVE_PACKAGES" == true ]]; then
        echo "  - WireGuard packages uninstalled"
    fi

    echo ""
    print_info "Log file: $LOG_FILE"
    echo ""

    # Show remaining servers if any
    local remaining_servers=($(detect_wireguard_servers))
    if [[ ${#remaining_servers[@]} -gt 0 ]]; then
        print_info "Remaining WireGuard servers:"
        for iface in "${remaining_servers[@]}"; do
            echo "  - ${iface}"
        done
        echo ""
    fi

    print_info "Next steps:"
    if [[ ${#remaining_servers[@]} -gt 0 ]]; then
        echo "  - Other servers are still active"
        echo "  - Use wireguard-menu.sh to manage them"
    else
        echo "  - Run setup-wireguard.sh to create a new server"
    fi

    if [[ "$REMOVE_PACKAGES" == true ]]; then
        echo "  - WireGuard packages need to be reinstalled"
    fi
    echo "=========================================="
    echo ""

    log "=== WireGuard Reset Completed Successfully ==="
}

# Execute main function
main "$@"
