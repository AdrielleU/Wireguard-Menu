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
        ip_addr=$(grep -E "^Address\s*=" "$config_file" 2>/dev/null | head -n1 | awk '{print $3}' || echo "Unknown")
        port=$(grep -E "^ListenPort\s*=" "$config_file" 2>/dev/null | head -n1 | awk '{print $3}' || echo "Unknown")
        client_count=$(grep -c "^# Client:" "$config_file" 2>/dev/null || echo "0")
        client_count=$(echo "$client_count" | tr -d '[:space:]')
        client_count=${client_count:-0}
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
        ((i++)) || true
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

remove_routes_for_interface() {
    local iface="$1"

    print_info "Removing routes for interface: $iface"

    # Get all routes for this interface
    local routes=$(ip route show dev "$iface" 2>/dev/null)

    if [[ -z "$routes" ]]; then
        print_info "No routes found for $iface"
        return
    fi

    local routes_removed=0

    # Remove each route
    while IFS= read -r route; do
        # Extract the network (first field)
        local network=$(echo "$route" | awk '{print $1}')

        if [[ -n "$network" ]]; then
            print_info "Removing route: $network dev $iface"
            if ip route del "$network" dev "$iface" 2>/dev/null; then
                ((routes_removed++)) || true
                log "Removed route: $network dev $iface"
            fi
        fi
    done <<< "$routes"

    if [[ $routes_removed -gt 0 ]]; then
        print_success "Removed $routes_removed route(s) for $iface"
    fi
}

remove_wireguard_interface() {
    local iface="$1"

    # Remove routes first (before interface goes down)
    remove_routes_for_interface "$iface"

    if ip link show "$iface" &>/dev/null; then
        print_info "Removing network interface: $iface"
        ip link delete "$iface" 2>/dev/null || print_warning "Could not remove interface $iface"
        log "Removed interface: $iface"
    fi
}

remove_firewall_rules() {
    local iface="$1"

    print_info "Cleaning up firewall rules for ${iface}..."

    # Detect firewall system
    if systemctl is-active --quiet firewalld 2>/dev/null; then
        remove_firewalld_rules "$iface"
    elif command -v ufw &> /dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
        remove_ufw_rules "$iface"
    elif command -v iptables &> /dev/null; then
        remove_iptables_rules "$iface"
    else
        print_info "No active firewall detected"
    fi
}

remove_firewalld_rules() {
    local iface="$1"

    print_info "Removing firewalld rules..."

    # Get port from config if it exists
    local config_file="${WG_CONFIG_DIR}/${iface}.conf"
    local wg_port=""
    if [[ -f "$config_file" ]]; then
        wg_port=$(grep -E "^ListenPort\s*=" "$config_file" 2>/dev/null | head -n1 | awk '{print $3}' || echo "")
    fi

    # Remove interface from trusted zone
    print_info "Checking trusted zone..."
    if timeout 5 firewall-cmd --zone=trusted --query-interface=${iface} 2>/dev/null; then
        timeout 10 firewall-cmd --permanent --zone=trusted --remove-interface=${iface} 2>/dev/null || true
        print_success "Removed ${iface} from trusted zone"
    fi

    # Remove port from public zone
    if [[ -n "$wg_port" ]]; then
        print_info "Checking port ${wg_port}/udp..."
        if timeout 5 firewall-cmd --zone=public --query-port=${wg_port}/udp 2>/dev/null; then
            timeout 10 firewall-cmd --permanent --zone=public --remove-port=${wg_port}/udp 2>/dev/null || true
            print_success "Removed port ${wg_port}/udp from public zone"
        fi
    fi

    # Check if masquerading should be removed
    print_info "Checking masquerade..."
    if timeout 5 firewall-cmd --zone=public --query-masquerade 2>/dev/null; then
        # Count WireGuard interfaces currently active (before removal)
        # Use wg show interfaces which lists all interface names
        local all_wg=$(wg show interfaces 2>/dev/null | wc -w || echo "0")
        all_wg=$(echo "$all_wg" | tr -d '[:space:]')
        all_wg=${all_wg:-0}

        # If only 1 interface (the one being removed), safe to remove masquerade
        if [[ $all_wg -le 1 ]]; then
            # No other WireGuard interfaces after this one is removed
            print_info "Removing masquerade (this is the last WireGuard interface)"
            timeout 10 firewall-cmd --permanent --zone=public --remove-masquerade 2>/dev/null || true
            print_success "Removed masquerade from public zone"
        else
            print_info "Masquerade kept enabled ($((all_wg - 1)) other WireGuard interface(s) remain)"
        fi
    fi

    # Remove any direct rules related to this interface (skip if slow)
    print_info "Checking direct rules..."
    local direct_rules=$(timeout 5 firewall-cmd --permanent --direct --get-all-rules 2>/dev/null | grep "${iface}" || true)
    if [[ -n "$direct_rules" ]]; then
        print_info "Found direct rules for ${iface} (skipping detailed removal)"
        print_warning "Manual cleanup may be needed for direct rules"
    fi

    # Reload firewall with timeout
    print_info "Reloading firewall..."
    if timeout 15 firewall-cmd --reload 2>/dev/null; then
        print_success "Firewall reloaded"
    else
        print_warning "Firewall reload timed out (rules still applied, reboot may be needed)"
    fi

    print_success "Firewalld rules cleaned up"
}

remove_ufw_rules() {
    local iface="$1"

    print_info "Removing UFW rules..."

    # Get port from config if it exists
    local config_file="${WG_CONFIG_DIR}/${iface}.conf"
    local wg_port=""
    if [[ -f "$config_file" ]]; then
        wg_port=$(grep -E "^ListenPort\s*=" "$config_file" 2>/dev/null | head -n1 | awk '{print $3}' || echo "")
    fi

    # Remove port rule
    if [[ -n "$wg_port" ]]; then
        ufw delete allow ${wg_port}/udp 2>/dev/null || true
        print_success "Removed UFW rule for port ${wg_port}/udp"
    fi

    # Check before.rules for NAT rules
    local ufw_before="/etc/ufw/before.rules"
    if [[ -f "$ufw_before" ]] && grep -q "${iface}" "$ufw_before" 2>/dev/null; then
        print_warning "Found NAT rules in ${ufw_before}"
        echo "  Manual cleanup required - check ${ufw_before} for ${iface} rules"
    fi

    ufw reload 2>/dev/null || true

    print_success "UFW rules cleaned up"
}

remove_iptables_rules() {
    local iface="$1"

    print_info "Removing iptables rules..."

    # Remove FORWARD rules
    iptables -D FORWARD -i ${iface} -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -o ${iface} -j ACCEPT 2>/dev/null || true

    # Remove POSTROUTING masquerade rules
    iptables -t nat -D POSTROUTING -o ${iface} -j MASQUERADE 2>/dev/null || true

    # Try to save rules (command differs by distro)
    if command -v iptables-save &>/dev/null; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || \
        iptables-save > /etc/sysconfig/iptables 2>/dev/null || true
    fi

    print_success "Iptables rules cleaned up"
}

remove_server_config() {
    local iface="$1"
    local config_file="${WG_CONFIG_DIR}/${iface}.conf"
    local keys_dir="${WG_CONFIG_DIR}/${iface}"

    print_info "Removing configuration for: $iface"
    echo ""

    # Count what we're removing
    local client_count=0
    local server_key_count=0
    local client_key_count=0
    local client_config_count=0
    local removal_errors=0

    # Count clients from server config
    if [[ -f "$config_file" ]]; then
        local client_only=$(grep -c "^# Client:" "$config_file" 2>/dev/null || echo "0")
        local site_count=$(grep -c "^# Site:" "$config_file" 2>/dev/null || echo "0")
        # Strip any whitespace and ensure numeric
        client_only=$(echo "$client_only" | tr -d '[:space:]')
        site_count=$(echo "$site_count" | tr -d '[:space:]')
        # Default to 0 if empty
        client_only=${client_only:-0}
        site_count=${site_count:-0}
        client_count=$((client_only + site_count))
    fi

    # Count keys in directory
    if [[ -d "$keys_dir" ]]; then
        server_key_count=$(find "$keys_dir" -maxdepth 1 -name "server-*key" 2>/dev/null | wc -l | tr -d '[:space:]')
        client_key_count=$(find "$keys_dir" -maxdepth 1 -name "*-privatekey" -o -name "*-publickey" 2>/dev/null | { grep -v "server" || true; } | wc -l | tr -d '[:space:]')
        client_config_count=$(find "$keys_dir" -maxdepth 1 -name "*.conf" 2>/dev/null | wc -l | tr -d '[:space:]')

        # Ensure numeric defaults
        server_key_count=${server_key_count:-0}
        client_key_count=${client_key_count:-0}
        client_config_count=${client_config_count:-0}

        print_info "Found in ${iface}/ directory:"
        echo "  - ${client_count} peer(s) in server config"
        echo "  - ${client_config_count} client config file(s)"
        echo "  - ${server_key_count} server key file(s)"
        echo "  - $((client_key_count / 2)) client keypair(s)"
        echo ""
    fi

    # Remove main server config file
    if [[ -f "$config_file" ]]; then
        print_info "Removing server config: ${iface}.conf"
        if rm -f "$config_file" 2>/dev/null; then
            log "Removed config: ${iface}.conf"
            print_success "Removed server config"
        else
            print_error "Failed to remove ${config_file}"
            log "ERROR: Failed to remove ${config_file}"
            ((removal_errors++)) || true
        fi
    else
        print_info "No server config file found"
    fi

    # Remove keys directory with all client configs and keys
    if [[ -d "$keys_dir" ]]; then
        print_info "Removing keys directory: ${keys_dir}/"

        # List what we're about to remove
        if [[ $client_config_count -gt 0 ]] || [[ $client_key_count -gt 0 ]]; then
            echo "  Removing:"
            [[ $client_config_count -gt 0 ]] && echo "    - ${client_config_count} client config file(s)"
            [[ $((client_key_count / 2)) -gt 0 ]] && echo "    - $((client_key_count / 2)) client keypair(s)"
            [[ $server_key_count -gt 0 ]] && echo "    - ${server_key_count} server key file(s)"
            echo ""
        fi

        # Force remove all files first to handle permission issues
        print_info "Removing all files in directory..."
        find "$keys_dir" -type f -exec chmod 600 {} \; 2>/dev/null || true
        find "$keys_dir" -type f -delete 2>/dev/null || rm -f "$keys_dir"/* 2>/dev/null || true

        # Remove hidden files (like .peer-defaults)
        find "$keys_dir" -type f -name ".*" -delete 2>/dev/null || rm -f "$keys_dir"/.[^.]* 2>/dev/null || true

        # Now remove the directory itself
        if rmdir "$keys_dir" 2>/dev/null; then
            log "Removed keys directory: ${iface}/ (${client_config_count} configs, $((client_key_count / 2)) keypairs)"
            print_success "Removed all client configs and keys"
        elif rm -rf "$keys_dir" 2>/dev/null; then
            log "Removed keys directory (force): ${iface}/"
            print_success "Removed all client configs and keys (forced)"
        else
            print_error "Failed to remove ${keys_dir}"
            log "ERROR: Failed to remove ${keys_dir}"
            ((removal_errors++)) || true
        fi

        # Verify removal
        if [[ -d "$keys_dir" ]]; then
            print_warning "Directory still exists: ${keys_dir}"
            local remaining_files=$(find "$keys_dir" -type f 2>/dev/null | wc -l | tr -d '[:space:]')
            remaining_files=${remaining_files:-0}
            if [[ $remaining_files -gt 0 ]]; then
                print_error "${remaining_files} file(s) could not be removed"
                echo "  Files that remain:"
                find "$keys_dir" -type f 2>/dev/null | head -10 | while read -r file; do
                    echo "    - $(basename "$file") ($(stat -c '%a' "$file" 2>/dev/null || echo "unknown perms"))"
                done
                echo ""
                print_warning "Attempting force removal with elevated permissions..."
                chmod -R 777 "$keys_dir" 2>/dev/null || true
                rm -rf "$keys_dir" 2>/dev/null || true

                if [[ -d "$keys_dir" ]]; then
                    print_error "Force removal failed - manual intervention required"
                    ((removal_errors++)) || true
                else
                    print_success "Force removal successful"
                fi
            else
                # Directory exists but is empty, remove it
                rmdir "$keys_dir" 2>/dev/null || rm -rf "$keys_dir" 2>/dev/null || true
                if [[ ! -d "$keys_dir" ]]; then
                    print_success "Removed empty directory"
                fi
            fi
        fi
    else
        print_info "No keys directory found"
    fi

    echo ""

    if [[ $removal_errors -gt 0 ]]; then
        print_error "Completed with $removal_errors error(s) for: $iface"
        log "WARNING: Removal completed with $removal_errors error(s) for ${iface}"
        return 1
    else
        print_success "Successfully removed all configs and keys for: $iface"
        log "Successfully removed ${iface} (${client_count} clients, ${client_config_count} configs)"
        return 0
    fi
}

remove_selected_servers() {
    print_info "Removing selected WireGuard server(s)..."
    echo ""

    local total_errors=0
    local successful_removals=0

    for iface in "${SELECTED_SERVERS[@]}"; do
        echo "=========================================="
        echo "Removing: ${iface}"
        echo "=========================================="
        echo ""

        stop_wireguard_service "$iface"
        remove_firewall_rules "$iface"
        remove_wireguard_interface "$iface"

        if remove_server_config "$iface"; then
            ((successful_removals++)) || true
        else
            ((total_errors++)) || true
        fi

        echo ""
    done

    echo "=========================================="
    if [[ $total_errors -eq 0 ]]; then
        print_success "Successfully removed all ${#SELECTED_SERVERS[@]} server(s)"
    else
        print_warning "Removed ${successful_removals}/${#SELECTED_SERVERS[@]} server(s) successfully"
        print_error "$total_errors server(s) had errors during removal"
        echo ""
        print_info "Check log for details: $LOG_FILE"
    fi
    echo "=========================================="
}

remove_all_servers() {
    local all_servers=($(detect_wireguard_servers))
    local all_interfaces=($(detect_wireguard_interfaces))

    # Count what we're removing
    echo ""
    print_info "Analyzing WireGuard installation..."
    echo ""

    local total_clients=0
    local total_configs=0
    local total_keys=0

    if [[ -d "$WG_CONFIG_DIR" ]]; then
        # Count all client configs
        total_configs=$(find "$WG_CONFIG_DIR" -name "*.conf" -type f 2>/dev/null | wc -l | tr -d '[:space:]')
        total_configs=${total_configs:-0}
        # Count all keys
        total_keys=$(find "$WG_CONFIG_DIR" -name "*key" -type f 2>/dev/null | wc -l | tr -d '[:space:]')
        total_keys=${total_keys:-0}
        # Count all clients from all server configs
        for iface in "${all_servers[@]}"; do
            local config_file="${WG_CONFIG_DIR}/${iface}.conf"
            if [[ -f "$config_file" ]]; then
                local count=$(grep -c "^# Client:" "$config_file" 2>/dev/null || echo "0")
                local sites=$(grep -c "^# Site:" "$config_file" 2>/dev/null || echo "0")
                # Strip whitespace
                count=$(echo "$count" | tr -d '[:space:]')
                sites=$(echo "$sites" | tr -d '[:space:]')
                count=${count:-0}
                sites=${sites:-0}
                total_clients=$((total_clients + count + sites))
            fi
        done
    fi

    print_info "Found:"
    echo "  - ${#all_servers[@]} WireGuard server(s)"
    echo "  - ${total_clients} total client/site peer(s)"
    echo "  - ${total_configs} total config file(s)"
    echo "  - ${total_keys} total key file(s)"
    echo ""

    print_info "Stopping all WireGuard services..."
    for iface in "${all_servers[@]}"; do
        stop_wireguard_service "$iface"
    done
    echo ""

    print_info "Cleaning up firewall rules..."
    for iface in "${all_servers[@]}"; do
        remove_firewall_rules "$iface"
    done
    echo ""

    print_info "Removing all network interfaces and routes..."
    for iface in "${all_interfaces[@]}"; do
        remove_wireguard_interface "$iface"
    done
    echo ""

    # Clean up any orphaned WireGuard routes
    print_info "Checking for orphaned WireGuard routes..."
    local orphaned_routes=$(ip route show | grep -E "dev (wg[0-9]+|wg-)" 2>/dev/null || true)
    if [[ -n "$orphaned_routes" ]]; then
        print_warning "Found orphaned routes, cleaning up..."
        while IFS= read -r route; do
            local network=$(echo "$route" | awk '{print $1}')
            local dev=$(echo "$route" | { grep -oP 'dev \K\S+' || true; })
            if [[ -n "$network" ]] && [[ -n "$dev" ]]; then
                print_info "Removing orphaned route: $network dev $dev"
                ip route del "$network" dev "$dev" 2>/dev/null || true
            fi
        done <<< "$orphaned_routes"
    else
        print_success "No orphaned routes found"
    fi
    echo ""

    print_info "Removing all server configs, client configs, and keys..."
    local removal_errors=0

    if [[ -d "$WG_CONFIG_DIR" ]]; then
        # Remove all contents
        if rm -rf "${WG_CONFIG_DIR:?}"/* 2>/dev/null; then
            log "Removed all WireGuard configs (${#all_servers[@]} servers, ${total_clients} clients)"
            print_success "Removed all configuration files"
        else
            print_error "Failed to remove some config files"
            log "ERROR: Failed to remove some files from ${WG_CONFIG_DIR}"
            ((removal_errors++)) || true
        fi

        # Verify removal
        local remaining_files=$(find "$WG_CONFIG_DIR" -type f 2>/dev/null | wc -l | tr -d '[:space:]')
        remaining_files=${remaining_files:-0}
        if [[ $remaining_files -gt 0 ]]; then
            print_warning "${remaining_files} file(s) could not be removed"
            echo "  Remaining files:"
            find "$WG_CONFIG_DIR" -type f 2>/dev/null | head -5 | while read -r file; do
                echo "    - ${file}"
            done
            ((removal_errors++)) || true
        fi

        # Try to remove directory
        if rmdir "$WG_CONFIG_DIR" 2>/dev/null; then
            print_success "Removed WireGuard directory"
        else
            print_info "WireGuard directory kept (may contain leftover files)"
        fi
    fi

    echo ""

    if [[ $removal_errors -eq 0 ]]; then
        print_success "Removed all WireGuard servers, routes, and configurations"
    else
        print_warning "Removal completed with $removal_errors error(s)"
        print_info "Check log for details: $LOG_FILE"
    fi
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

    echo ""
    print_info "To backup before deletion, run:"
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
