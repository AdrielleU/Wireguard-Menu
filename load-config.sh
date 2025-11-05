#!/bin/bash
################################################################################
# WireGuard Load Config Script
# Description: Import and load existing WireGuard configuration files
# Usage: sudo ./load-config.sh [OPTIONS]
#
# Features:
#   - Import existing .conf files
#   - Detect existing WireGuard interfaces on server
#   - Replace existing configurations (prompts user to backup manually)
#   - Enable IP forwarding
#   - Start WireGuard service
#
# Note: This script does NOT configure firewall rules.
#       Use setup-wireguard.sh for full setup with firewall configuration.
#
# Note: This script does NOT automatically backup old configs.
#       It shows you the backup command to run if you want to backup.
#
# Examples:
#   sudo ./load-config.sh
#   sudo ./load-config.sh --config /path/to/wg0.conf
#   sudo ./load-config.sh --config site.conf --interface wg1
#   sudo ./load-config.sh --config wg0.conf --force
################################################################################

set -euo pipefail

################################################################################
# CONFIGURATION
################################################################################

WG_CONFIG_DIR="/etc/wireguard"
LOG_FILE="/var/log/wireguard-setup.log"

# Config import settings
CONFIG_FILE_PATH=""
WG_INTERFACE=""
FORCE_REPLACE=false

################################################################################
# COLORS
################################################################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_success() { echo -e "${GREEN}[✓]${NC} $1"; }
print_error() { echo -e "${RED}[✗]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_info() { echo -e "${BLUE}[i]${NC} $1"; }

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
    echo "Options:"
    echo "  --config FILE         Path to WireGuard config file (required if not interactive)"
    echo "  --interface NAME      WireGuard interface name (default: auto-detect)"
    echo "  --force               Replace existing config without prompting"
    echo "  -h, --help            Show this help message"
    echo ""
    echo "Examples:"
    echo "  # Interactive mode"
    echo "  sudo $0"
    echo ""
    echo "  # Import specific config"
    echo "  sudo $0 --config /path/to/wg0.conf"
    echo ""
    echo "  # Import with custom interface name"
    echo "  sudo $0 --config myconfig.conf --interface wg1"
    echo ""
    echo "  # Force replace existing config (no prompts)"
    echo "  sudo $0 --config wg0.conf --force"
    echo ""
    echo "NOTES:"
    echo "  - This script detects existing WireGuard interfaces on the server"
    echo "  - It does NOT automatically backup old configs (shows backup command)"
    echo "  - It does NOT configure firewall rules"
    echo "  - Use setup-wireguard.sh for full setup with firewall configuration"
    echo ""
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --config)
                CONFIG_FILE_PATH="$2"
                shift 2
                ;;
            --interface)
                WG_INTERFACE="$2"
                shift 2
                ;;
            --force)
                FORCE_REPLACE=true
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

prompt_config_file() {
    if [[ -n "$CONFIG_FILE_PATH" ]]; then
        return 0
    fi

    echo ""
    echo "======================================================================"
    echo "                WireGuard Configuration Import"
    echo "======================================================================"
    echo ""

    while true; do
        read -p "Enter path to WireGuard config file: " CONFIG_FILE_PATH

        if [[ -z "$CONFIG_FILE_PATH" ]]; then
            print_error "Config file path cannot be empty"
            continue
        fi

        # Expand tilde to home directory
        CONFIG_FILE_PATH="${CONFIG_FILE_PATH/#\~/$HOME}"

        if [[ ! -f "$CONFIG_FILE_PATH" ]]; then
            print_error "File not found: $CONFIG_FILE_PATH"
            continue
        fi

        if [[ ! -r "$CONFIG_FILE_PATH" ]]; then
            print_error "Cannot read file: $CONFIG_FILE_PATH"
            continue
        fi

        break
    done
}

validate_config_file() {
    print_info "Validating configuration file..."

    # Check if file exists
    if [[ ! -f "$CONFIG_FILE_PATH" ]]; then
        error_exit "Config file not found: $CONFIG_FILE_PATH"
    fi

    # Basic validation - check for required sections
    if ! grep -q "^\[Interface\]" "$CONFIG_FILE_PATH"; then
        error_exit "Invalid config: Missing [Interface] section"
    fi

    # Check for PrivateKey or reference to key file
    if ! grep -q -E "^PrivateKey\s*=" "$CONFIG_FILE_PATH"; then
        print_warning "No PrivateKey found in config (may use external key file)"
    fi

    # Show config details
    echo ""
    print_info "Config file details:"

    # Extract Address
    local address=$(grep -E "^Address\s*=" "$CONFIG_FILE_PATH" | head -1 | sed 's/^Address\s*=\s*//')
    if [[ -n "$address" ]]; then
        echo "  VPN Address: $address"
    fi

    # Extract Endpoint (for client/peer configs)
    local endpoint=$(grep -E "^Endpoint\s*=" "$CONFIG_FILE_PATH" | head -1 | sed 's/^Endpoint\s*=\s*//')
    if [[ -n "$endpoint" ]]; then
        echo "  Server Endpoint: $endpoint"
    fi

    # Extract ListenPort (for server configs)
    local listen_port=$(grep -E "^ListenPort\s*=" "$CONFIG_FILE_PATH" | head -1 | sed 's/^ListenPort\s*=\s*//')
    if [[ -n "$listen_port" ]]; then
        echo "  Listen Port: $listen_port"
    fi

    # Count peers
    local peer_count=$(grep -c "^\[Peer\]" "$CONFIG_FILE_PATH" || echo "0")
    echo "  Peers: $peer_count"

    print_success "Config file validation passed"
}

detect_existing_interfaces() {
    local interfaces=()

    # Check for running interfaces
    if command -v wg &>/dev/null; then
        while IFS= read -r iface; do
            interfaces+=("$iface")
        done < <(wg show interfaces 2>/dev/null | tr ' ' '\n')
    fi

    # Also check config directory
    if [[ -d "$WG_CONFIG_DIR" ]]; then
        shopt -s nullglob
        for conf in "$WG_CONFIG_DIR"/*.conf; do
            [[ ! -f "$conf" ]] && continue
            local iface=$(basename "$conf" .conf)
            # Only add if not already in list
            if [[ ! " ${interfaces[@]} " =~ " ${iface} " ]]; then
                interfaces+=("$iface")
            fi
        done
        shopt -u nullglob
    fi

    echo "${interfaces[@]}"
}

extract_interface_name() {
    if [[ -n "$WG_INTERFACE" ]]; then
        print_info "Using specified interface: $WG_INTERFACE"
        return 0
    fi

    # Detect existing WireGuard interfaces on this server
    local existing_interfaces=($(detect_existing_interfaces))
    local filename=$(basename "$CONFIG_FILE_PATH")
    local filename_interface="${filename%.conf}"

    echo ""

    if [[ ${#existing_interfaces[@]} -gt 0 ]]; then
        print_info "Found existing WireGuard interface(s) on this server:"
        for iface in "${existing_interfaces[@]}"; do
            local status="(stopped)"
            if wg show "$iface" &>/dev/null; then
                status="(active)"
            fi
            echo "  - $iface $status"
        done
        echo ""

        if [[ ${#existing_interfaces[@]} -eq 1 ]]; then
            # Only one interface exists
            print_info "Only one interface found: ${existing_interfaces[0]}"
            echo "Config filename suggests: $filename_interface"
            echo ""
            read -p "Replace config for existing interface '${existing_interfaces[0]}'? (Y/n): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Nn]$ ]]; then
                WG_INTERFACE="${existing_interfaces[0]}"
            else
                read -p "Enter interface name: " WG_INTERFACE
            fi
        else
            # Multiple interfaces exist
            echo "Which interface should receive this config?"
            for i in "${!existing_interfaces[@]}"; do
                echo "  $((i+1))) ${existing_interfaces[$i]}"
            done
            echo "  $((${#existing_interfaces[@]}+1))) Use filename: $filename_interface"
            echo "  $((${#existing_interfaces[@]}+2))) Custom name"
            echo ""

            while true; do
                read -p "Select option [1-$((${#existing_interfaces[@]}+2))]: " choice
                if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le $((${#existing_interfaces[@]}+2)) ]; then
                    if [ "$choice" -le "${#existing_interfaces[@]}" ]; then
                        WG_INTERFACE="${existing_interfaces[$((choice-1))]}"
                        break
                    elif [ "$choice" -eq $((${#existing_interfaces[@]}+1)) ]; then
                        WG_INTERFACE="$filename_interface"
                        break
                    else
                        read -p "Enter interface name: " WG_INTERFACE
                        break
                    fi
                else
                    print_error "Invalid choice"
                fi
            done
        fi
    else
        # No existing interfaces - use filename
        print_info "No existing WireGuard interfaces found on this server"
        WG_INTERFACE="$filename_interface"
        echo "Using interface name from filename: $WG_INTERFACE"
        echo ""
        read -p "Use interface name '$WG_INTERFACE'? (Y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Nn]$ ]]; then
            read -p "Enter interface name: " WG_INTERFACE
        fi
    fi

    print_success "Interface selected: $WG_INTERFACE"
    echo ""
}

check_existing_interface() {
    local target_config="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"

    if [[ -f "$target_config" ]]; then
        print_info "Configuration already exists: $target_config"

        if [[ "$FORCE_REPLACE" == true ]]; then
            print_info "Force mode enabled - will replace existing config"
        else
            print_info "You will be prompted to confirm replacement during import"
        fi
    fi
}

import_config() {
    print_info "Importing configuration..."

    local target_config="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"
    local wg_interface_dir="${WG_CONFIG_DIR}/${WG_INTERFACE}"

    # Create interface directory
    mkdir -p "$wg_interface_dir"

    # Warn if config already exists (no automatic backup)
    if [[ -f "$target_config" ]]; then
        print_warning "Existing config will be replaced: $target_config"

        if [[ "$FORCE_REPLACE" != true ]]; then
            echo ""
            echo "To backup your old config first, run:"
            echo "  cp $target_config $target_config.backup.$(date +%Y%m%d-%H%M%S)"
            echo ""
            read -p "Continue and replace existing config? (y/N): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                error_exit "Import cancelled by user"
            fi
        fi

        # Stop the service if running
        if systemctl is-active --quiet "wg-quick@${WG_INTERFACE}" 2>/dev/null; then
            print_info "Stopping existing WireGuard service..."
            systemctl stop "wg-quick@${WG_INTERFACE}" || print_warning "Failed to stop service"
        elif ip link show "$WG_INTERFACE" &>/dev/null 2>&1; then
            # Interface is manually up (wg-quick up), stop it
            print_info "Stopping manually started interface..."
            wg-quick down "${WG_INTERFACE}" 2>/dev/null || print_warning "Failed to stop interface"
        fi
    fi

    # Copy config file
    cp "$CONFIG_FILE_PATH" "$target_config" || error_exit "Failed to copy config file"
    chmod 600 "$target_config"

    print_success "Configuration imported to: $target_config"
    log "Config imported: $CONFIG_FILE_PATH -> $target_config"
}

enable_ip_forwarding() {
    print_info "Enabling IP forwarding..."

    # Check if already enabled
    if [[ $(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0) -eq 1 ]]; then
        print_success "IP forwarding already enabled"
        return 0
    fi

    # Enable immediately
    sysctl -w net.ipv4.ip_forward=1 >/dev/null

    # Make persistent
    local sysctl_conf="/etc/sysctl.d/99-wireguard.conf"
    if ! grep -q "net.ipv4.ip_forward" "$sysctl_conf" 2>/dev/null; then
        echo "net.ipv4.ip_forward = 1" >> "$sysctl_conf"
        print_success "IP forwarding enabled and made persistent"
    else
        print_success "IP forwarding enabled"
    fi
}

start_wireguard() {
    # Check if service was running before OR interface is manually up
    local was_running=false
    local was_manual=false

    if systemctl is-active --quiet "wg-quick@${WG_INTERFACE}" 2>/dev/null; then
        was_running=true
    elif ip link show "$WG_INTERFACE" &>/dev/null 2>&1; then
        # Interface exists but service not running - probably manual wg-quick up
        was_manual=true
    fi

    # Enable service (so it starts on boot)
    systemctl enable "wg-quick@${WG_INTERFACE}" 2>/dev/null || error_exit "Failed to enable service"

    # Ask user if they want to start the service
    echo ""
    if [[ "$was_running" == true ]]; then
        print_info "Service was running before import - will restart it"
        read -p "Start WireGuard service now? (Y/n): " -n 1 -r
        echo
        start_service=true
        if [[ $REPLY =~ ^[Nn]$ ]]; then
            start_service=false
        fi
    elif [[ "$was_manual" == true ]]; then
        print_warning "Interface was manually brought up (wg-quick up) - service not running"
        print_info "Recommend using systemctl to manage service for auto-start on boot"
        read -p "Start WireGuard service now? (y/N): " -n 1 -r
        echo
        start_service=false
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            start_service=true
        fi
    else
        print_info "Service was NOT running before import"
        read -p "Start WireGuard service now? (y/N): " -n 1 -r
        echo
        start_service=false
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            start_service=true
        fi
    fi

    if [[ "$start_service" == true ]]; then
        print_info "Starting WireGuard service..."

        # Start service
        if systemctl start "wg-quick@${WG_INTERFACE}" 2>/dev/null; then
            print_success "WireGuard service started: wg-quick@${WG_INTERFACE}"
        else
            print_error "Failed to start WireGuard service"
            echo ""
            echo "Check the service status with:"
            echo "  systemctl status wg-quick@${WG_INTERFACE}"
            echo "  journalctl -u wg-quick@${WG_INTERFACE}"
            error_exit "Service start failed"
        fi

        # Give it a moment to initialize
        sleep 1

        # Verify interface is up
        if ip link show "$WG_INTERFACE" &>/dev/null; then
            print_success "WireGuard interface is up"
        else
            print_error "WireGuard interface is not up"
            error_exit "Interface verification failed"
        fi
    else
        print_info "Service NOT started - config loaded but interface is down"
        echo ""
        echo "To start WireGuard later, run:"
        echo "  systemctl start wg-quick@${WG_INTERFACE}"
        echo "  or"
        echo "  wg-quick up ${WG_INTERFACE}"
    fi
}

show_summary() {
    local config_file="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"
    local service_status=$(systemctl is-active wg-quick@${WG_INTERFACE} 2>/dev/null || echo 'inactive')

    echo ""
    echo "======================================================================"
    echo "                    Configuration Loaded Successfully"
    echo "======================================================================"
    echo ""
    echo "Interface:     $WG_INTERFACE"
    echo "Config File:   $config_file"

    # Show VPN address from loaded config
    local address=$(grep -E "^Address\s*=" "$config_file" 2>/dev/null | head -1 | sed 's/^Address\s*=\s*//')
    if [[ -n "$address" ]]; then
        echo "VPN Address:   $address"
    fi

    echo "Service:       wg-quick@${WG_INTERFACE}"
    if [[ "$service_status" == "active" ]]; then
        echo "Status:        ${GREEN}active${NC} (running)"
    else
        echo "Status:        ${YELLOW}inactive${NC} (stopped)"
    fi

    echo ""
    echo "Useful commands:"
    if [[ "$service_status" == "active" ]]; then
        echo "  Check status:   wg show $WG_INTERFACE"
        echo "  View config:    cat $config_file"
        echo "  View logs:      journalctl -u wg-quick@${WG_INTERFACE} -f"
        echo "  Stop service:   wg-quick down ${WG_INTERFACE}"
        echo "  Restart:        systemctl restart wg-quick@${WG_INTERFACE}"
        echo "  Reload config:  wg syncconf $WG_INTERFACE <(wg-quick strip $WG_INTERFACE)"
    else
        echo "  Start service:  wg-quick up ${WG_INTERFACE}"
        echo "  View config:    cat $config_file"
        echo "  Check logs:     journalctl -u wg-quick@${WG_INTERFACE}"
    fi
    echo ""
    echo "NOTE: Firewall rules are NOT configured by this script."
    echo "      Use setup-wireguard.sh to configure firewall if needed."
    echo ""
}

################################################################################
# MAIN EXECUTION
################################################################################

main() {
    echo "=========================================="
    echo "  WireGuard Configuration Loader"
    echo "=========================================="
    echo ""

    # Initialize log
    mkdir -p "$(dirname "$LOG_FILE")"
    log "=== WireGuard Config Import Started ==="

    # Parse arguments
    parse_arguments "$@"

    # Check prerequisites
    check_root

    # Prompt for config file if not provided
    prompt_config_file

    # Validate config file
    validate_config_file

    # Extract interface name
    extract_interface_name

    # Check if interface already exists
    check_existing_interface

    # Show summary before importing
    echo ""
    echo "======================================================================"
    print_info "Ready to Import Configuration"
    echo "======================================================================"
    echo ""
    echo "Source config file:     $CONFIG_FILE_PATH"
    echo "Destination:            ${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"
    echo "WireGuard interface:    $WG_INTERFACE"
    echo "Service name:           wg-quick@${WG_INTERFACE}"
    echo ""

    read -p "Continue with import? (Y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        error_exit "Import cancelled by user"
    fi

    # Import the configuration
    import_config

    # Enable IP forwarding
    enable_ip_forwarding

    # Start WireGuard service
    start_wireguard

    # Show summary
    show_summary

    log "=== WireGuard Config Import Completed Successfully ==="
}

# Execute main function
main "$@"
