#!/bin/bash
################################################################################
# WireGuard Show QR Code Script
# Description: Display client or site config as QR code for mobile devices
# Usage: sudo ./qr-show.sh [OPTIONS]
################################################################################

set -euo pipefail

################################################################################
# CONFIGURATION
################################################################################

WG_CONFIG_DIR="/etc/wireguard"
CLIENT_NAME=""
WG_INTERFACE=""

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

check_qrencode() {
    if ! command -v qrencode &> /dev/null; then
        error_exit "qrencode is not installed. Install it with: dnf install qrencode (RHEL) or apt install qrencode (Ubuntu)"
    fi
}

detect_servers() {
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

    if [[ ${#servers[@]} -eq 0 ]]; then
        error_exit "No WireGuard servers found. Run setup-wireguard.sh first."
    fi

    echo "${servers[@]}"
}

select_server() {
    local servers=($(detect_servers))
    local server_count=${#servers[@]}

    # If interface specified via argument, validate it
    if [[ -n "$WG_INTERFACE" ]]; then
        if [[ ! -f "${WG_CONFIG_DIR}/${WG_INTERFACE}.conf" ]]; then
            error_exit "WireGuard server '${WG_INTERFACE}' not found."
        fi
        print_success "Using server: ${WG_INTERFACE}"
        return
    fi

    # If only one server exists, use it automatically (silently)
    if [[ $server_count -eq 1 ]]; then
        WG_INTERFACE="${servers[0]}"
        return
    fi

    # Multiple servers - show selection menu
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
        ((i++))
    done

    echo ""
    read -p "Select server (1-${server_count}): " selection

    # Validate selection
    if ! [[ "$selection" =~ ^[0-9]+$ ]] || [ "$selection" -lt 1 ] || [ "$selection" -gt "$server_count" ]; then
        error_exit "Invalid selection"
    fi

    WG_INTERFACE="${servers[$((selection-1))]}"
    print_success "Selected server: ${WG_INTERFACE}"
}

list_clients() {
    # Use list-peers.sh if available, otherwise fallback
    if [[ -x "./list-peers.sh" ]]; then
        local clients=$(./list-peers.sh "${WG_INTERFACE}" --format array 2>/dev/null)
    else
        # Fallback: extract from config directly
        local config_file="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"
        local clients=()
        while IFS= read -r line; do
            if [[ "$line" =~ ^#\ Client:\ (.+)$ ]]; then
                clients+=("${BASH_REMATCH[1]}")
            fi
        done < "$config_file"
        clients="${clients[@]}"
    fi

    echo "$clients"
}

select_client() {
    local clients=($(list_clients))
    local client_count=${#clients[@]}

    # Check if any clients exist
    if [[ $client_count -eq 0 ]]; then
        error_exit "No clients found in ${WG_INTERFACE}"
    fi

    # If client specified via argument, validate it
    if [[ -n "$CLIENT_NAME" ]]; then
        local client_config="${WG_CONFIG_DIR}/${WG_INTERFACE}/${CLIENT_NAME}.conf"
        if [[ ! -f "$client_config" ]]; then
            error_exit "Client config '${CLIENT_NAME}' not found in ${WG_INTERFACE}"
        fi

        print_success "Using client: ${CLIENT_NAME}"
        return
    fi

    # Show client selection menu
    echo ""
    print_info "Select a client or site to display its QR code (for mobile devices)"
    echo ""
    echo "Clients/Sites in ${WG_INTERFACE}:"
    echo ""

    local i=1
    for client in "${clients[@]}"; do
        printf "  ${BLUE}%d)${NC} %s\n" "$i" "$client"
        ((i++))
    done

    echo ""
    read -p "Select client (1-${client_count}): " selection

    # Validate selection
    if ! [[ "$selection" =~ ^[0-9]+$ ]] || [ "$selection" -lt 1 ] || [ "$selection" -gt "$client_count" ]; then
        error_exit "Invalid selection"
    fi

    CLIENT_NAME="${clients[$((selection-1))]}"
    print_success "Selected client: ${CLIENT_NAME}"
}

show_qr_code() {
    local client_config="${WG_CONFIG_DIR}/${WG_INTERFACE}/${CLIENT_NAME}.conf"

    if [[ ! -f "$client_config" ]]; then
        error_exit "Client config not found: ${client_config}"
    fi

    echo ""
    echo "=========================================="
    print_info "QR Code for ${CLIENT_NAME} (${WG_INTERFACE})"
    echo "=========================================="
    echo ""

    # Generate QR code
    qrencode -t ansiutf8 < "$client_config"

    echo ""
    echo "=========================================="
    print_info "Scan this QR code with the WireGuard mobile app"
    echo "=========================================="
    echo ""
    print_info "Config file location:"
    echo "  ${client_config}"
    echo ""
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --interface|-i)
                WG_INTERFACE="$2"
                shift 2
                ;;
            --client|-c)
                CLIENT_NAME="$2"
                shift 2
                ;;
            -h|--help)
                echo "Usage: sudo $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  -i, --interface NAME    WireGuard interface (e.g., wg0)"
                echo "  -c, --client NAME       Client name"
                echo "  -h, --help             Show this help"
                echo ""
                echo "Example:"
                echo "  sudo $0 --interface wg0 --client phone"
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
    echo "  WireGuard QR Code Generator"
    echo "=========================================="
    echo ""

    parse_arguments "$@"

    check_root
    check_qrencode
    select_server
    select_client
    show_qr_code
}

main "$@"
