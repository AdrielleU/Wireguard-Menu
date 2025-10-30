#!/bin/bash
################################################################################
# WireGuard Remove Peer Script
# Description: Safely remove a client or site peer from a WireGuard server
# Usage: sudo ./remove-peer.sh [OPTIONS]
################################################################################

set -euo pipefail

################################################################################
# CONFIGURATION
################################################################################

WG_CONFIG_DIR="/etc/wireguard"
PEER_NAME=""
WG_INTERFACE=""

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

error_exit() {
    print_error "$1"
    exit 1
}

check_root() {
    [[ $EUID -eq 0 ]] || error_exit "This script must be run as root (use sudo)"
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
        local is_running=""

        if systemctl is-active --quiet "wg-quick@${iface}"; then
            is_running="${GREEN}[RUNNING]${NC}"
        else
            is_running="${YELLOW}[STOPPED]${NC}"
        fi

        printf "  ${BLUE}%d)${NC} %s %b - %s, Port %s\n" "$i" "$iface" "$is_running" "$conf_ip" "$conf_port"
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

list_peers() {
    local peers=$(./list-clients.sh "${WG_INTERFACE}" --format array 2>/dev/null)
    echo "$peers"
}

select_peer() {
    local peers=($(list_peers))
    local peer_count=${#peers[@]}

    [[ $peer_count -gt 0 ]] || error_exit "No peers found in ${WG_INTERFACE}"

    if [[ -n "$PEER_NAME" ]]; then
        if ! ./list-clients.sh "${WG_INTERFACE}" --check "${PEER_NAME}" 2>/dev/null; then
            error_exit "Peer '${PEER_NAME}' not found in ${WG_INTERFACE}"
        fi
        print_success "Using peer: ${PEER_NAME}"
        return
    fi

    print_info "Select a peer (client or site) to remove from the VPN server"
    echo ""
    ./list-clients.sh "${WG_INTERFACE}" --format interactive

    read -p "Select peer to remove (1-${peer_count}): " selection

    if ! [[ "$selection" =~ ^[0-9]+$ ]] || [ "$selection" -lt 1 ] || [ "$selection" -gt "$peer_count" ]; then
        error_exit "Invalid selection"
    fi

    PEER_NAME="${peers[$((selection-1))]}"
    print_success "Selected peer: ${PEER_NAME}"
}

get_peer_allowed_ips() {
    local config_file="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"
    local in_peer_section=0
    local allowed_ips=""

    while IFS= read -r line; do
        if [[ "$line" =~ ^#\ (Client|Site):\ ${PEER_NAME}$ ]]; then
            in_peer_section=1
            continue
        fi

        if [[ $in_peer_section -eq 1 ]]; then
            if [[ "$line" =~ ^AllowedIPs[[:space:]]*=[[:space:]]*(.+)$ ]]; then
                allowed_ips="${BASH_REMATCH[1]}"
            elif [[ -z "$line" ]] || [[ "$line" =~ ^#\ (Client|Site): ]]; then
                break
            fi
        fi
    done < "$config_file"

    echo "$allowed_ips"
}

remove_routes_for_peer() {
    local allowed_ips="$1"

    if [[ -z "$allowed_ips" ]]; then
        print_info "No AllowedIPs found for peer, skipping route removal"
        return
    fi

    print_info "Checking for routes to remove..."

    IFS=',' read -ra IP_ARRAY <<< "$allowed_ips"
    local routes_removed=0

    for ip in "${IP_ARRAY[@]}"; do
        ip=$(echo "$ip" | xargs)
        [[ "$ip" =~ /32$ ]] && continue

        if ip route show "$ip" 2>/dev/null | grep -q "dev ${WG_INTERFACE}"; then
            print_info "Removing route: $ip dev ${WG_INTERFACE}"
            if ip route del "$ip" dev "${WG_INTERFACE}" 2>/dev/null; then
                print_success "Route removed: $ip"
                ((routes_removed++)) || true
            else
                print_warning "Failed to remove route for $ip"
            fi
        fi
    done

    if [[ $routes_removed -gt 0 ]]; then
        print_success "Removed $routes_removed route(s)"
    else
        print_info "No routes to remove (peer had no network routes)"
    fi
}

remove_peer_from_config() {
    local config_file="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"

    print_info "Removing peer from server configuration..."

    local temp_file=$(mktemp)
    trap "rm -f '$temp_file'" EXIT ERR

    local original_perms=$(stat -c '%a' "$config_file" 2>/dev/null || echo "600")
    local original_owner=$(stat -c '%U:%G' "$config_file" 2>/dev/null || echo "root:root")

    local in_peer_section=0

    while IFS= read -r line; do
        if [[ "$line" =~ ^#\ (Client|Site):\ ${PEER_NAME}$ ]]; then
            in_peer_section=1
            continue
        fi

        if [[ $in_peer_section -eq 1 ]]; then
            if [[ "$line" =~ ^\[Peer\]$ ]] || [[ "$line" =~ ^PublicKey ]] || [[ "$line" =~ ^AllowedIPs ]] || [[ "$line" =~ ^PersistentKeepalive ]]; then
                continue
            elif [[ -z "$line" ]]; then
                in_peer_section=0
                continue
            else
                in_peer_section=0
            fi
        fi

        echo "$line" >> "$temp_file"
    done < "$config_file"

    mv "$temp_file" "$config_file"
    chmod "$original_perms" "$config_file"
    chown "$original_owner" "$config_file"

    if command -v restorecon &> /dev/null && sestatus 2>/dev/null | grep -q "enabled"; then
        restorecon "$config_file" 2>/dev/null || true
    fi

    trap - EXIT ERR

    print_success "Peer removed from ${config_file}"
}

remove_peer_files() {
    local keys_dir="${WG_CONFIG_DIR}/${WG_INTERFACE}"

    print_info "Removing peer keys and config..."

    local files_removed=0

    for file in "${keys_dir}/${PEER_NAME}-privatekey" "${keys_dir}/${PEER_NAME}-publickey" "${keys_dir}/${PEER_NAME}.conf"; do
        if [[ -f "$file" ]]; then
            rm -f "$file" || print_warning "Failed to remove $(basename "$file")"
            ((files_removed++)) || true
        fi
    done

    if [[ $files_removed -gt 0 ]]; then
        print_success "Removed ${files_removed} peer file(s) from ${keys_dir}"
    else
        print_warning "No peer files found in ${keys_dir}"
    fi
}

reload_server() {
    local peer_public_key="$1"

    print_info "Restarting WireGuard interface to disconnect peer..."

    print_info "Stopping ${WG_INTERFACE}..."

    if ! ip link show "${WG_INTERFACE}" &>/dev/null; then
        print_info "Interface ${WG_INTERFACE} is already down"
    else
        if wg-quick down "${WG_INTERFACE}"; then
            print_success "Interface stopped with wg-quick"
        elif systemctl stop "wg-quick@${WG_INTERFACE}"; then
            print_success "Interface stopped with systemctl"
        else
            error_exit "Could not stop ${WG_INTERFACE}"
        fi

        sleep 1
        if ip link show "${WG_INTERFACE}" &>/dev/null; then
            error_exit "Failed to stop interface"
        fi
        print_success "Verified interface is stopped"
    fi

    sleep 2

    print_info "Starting ${WG_INTERFACE}..."
    local start_success=false

    if wg-quick up "${WG_INTERFACE}" 2>&1; then
        print_success "Interface started with wg-quick"
        start_success=true
    elif systemctl start "wg-quick@${WG_INTERFACE}" 2>&1; then
        print_success "Interface started with systemctl"
        start_success=true
    fi

    print_info "Verifying service is active..."
    local max_attempts=3
    local attempt=1
    local service_active=false

    while [[ $attempt -le $max_attempts ]]; do
        sleep 1
        if systemctl is-active --quiet "wg-quick@${WG_INTERFACE}"; then
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
        journalctl -xeu "wg-quick@${WG_INTERFACE}.service" --no-pager -n 20
        echo ""
        error_exit "Failed to restart ${WG_INTERFACE}. Check the error logs above."
    fi

    print_success "WireGuard interface restarted successfully"
    print_success "Removed peer has been disconnected from VPN"
}

show_summary() {
    echo ""
    echo "=========================================="
    print_success "Peer Removed Successfully!"
    echo "=========================================="
    echo ""
    print_info "Removed peer: ${PEER_NAME}"
    print_info "From server: ${WG_INTERFACE}"
    echo ""
    print_info "What was removed:"
    echo "  - Peer from ${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"
    echo "  - Peer keys from ${WG_CONFIG_DIR}/${WG_INTERFACE}/"
    echo "  - Peer config file"
    echo ""
    echo "=========================================="
    echo ""
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --interface|-i) WG_INTERFACE="$2"; shift 2 ;;
            --peer|-p|--client|-c) PEER_NAME="$2"; shift 2 ;;
            -h|--help)
                echo "Usage: sudo $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  -i, --interface NAME    WireGuard interface (e.g., wg0)"
                echo "  -p, --peer NAME         Peer name to remove (client or site)"
                echo "  -c, --client NAME       Alias for --peer (for compatibility)"
                echo "  -h, --help              Show this help"
                echo ""
                echo "Examples:"
                echo "  sudo $0                              # Interactive mode"
                echo "  sudo $0 --interface wg0 --peer laptop-john"
                echo "  sudo $0 -i wg0 -p branch-office"
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
    echo "  WireGuard Remove Peer"
    echo "=========================================="
    echo ""

    parse_arguments "$@"

    check_root
    select_server
    select_peer

    echo ""
    print_warning "This will remove peer '${PEER_NAME}' from ${WG_INTERFACE}"
    print_warning "The VPN server will restart - ALL connected peers will briefly disconnect"
    echo ""
    print_info "To backup before removal, run:"
    echo "  sudo cp /etc/wireguard/${WG_INTERFACE}.conf /etc/wireguard/${WG_INTERFACE}.conf.backup"
    echo ""
    read -p "Are you sure? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        error_exit "Peer removal cancelled"
    fi

    local keys_dir="${WG_CONFIG_DIR}/${WG_INTERFACE}"
    local peer_public_key=""
    if [[ -f "${keys_dir}/${PEER_NAME}-publickey" ]]; then
        peer_public_key=$(cat "${keys_dir}/${PEER_NAME}-publickey")
    fi

    print_info "Extracting peer network information..."
    local peer_allowed_ips=$(get_peer_allowed_ips)

    remove_peer_from_config
    remove_peer_files

    echo ""
    print_info "Restarting VPN server..."
    reload_server "$peer_public_key"

    echo ""
    remove_routes_for_peer "$peer_allowed_ips"

    show_summary
}

main "$@"
