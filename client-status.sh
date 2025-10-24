#!/bin/bash
################################################################################
# WireGuard Client Status Script
# Description: Show detailed connection status for a specific client
# Usage: sudo ./client-status.sh [OPTIONS]
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
    # Use list-clients.sh if available, otherwise fallback
    if [[ -x "./list-clients.sh" ]]; then
        local clients=$(./list-clients.sh "${WG_INTERFACE}" --format array 2>/dev/null)
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
        if [[ -x "./list-clients.sh" ]]; then
            if ! ./list-clients.sh "${WG_INTERFACE}" --check "${CLIENT_NAME}" 2>/dev/null; then
                error_exit "Client '${CLIENT_NAME}' not found in ${WG_INTERFACE}"
            fi
        fi
        print_success "Using client: ${CLIENT_NAME}"
        return
    fi

    # Show client selection menu
    echo ""
    print_info "Select a client to view connection status and statistics"
    echo ""
    echo "Clients in ${WG_INTERFACE}:"
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

get_client_info() {
    local config_file="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"

    # Get client IP and public key from config
    local found_client=0
    while IFS= read -r line; do
        if [[ "$line" =~ ^#\ Client:\ ${CLIENT_NAME}$ ]]; then
            found_client=1
        elif [[ $found_client -eq 1 ]] && [[ "$line" =~ ^PublicKey\ =\ (.+)$ ]]; then
            CLIENT_PUBLIC_KEY="${BASH_REMATCH[1]}"
        elif [[ $found_client -eq 1 ]] && [[ "$line" =~ ^AllowedIPs\ =\ (.+)$ ]]; then
            CLIENT_IP="${BASH_REMATCH[1]}"
            break
        fi
    done < "$config_file"

    if [[ -z "$CLIENT_IP" ]]; then
        error_exit "Could not find client information for ${CLIENT_NAME}"
    fi
}

get_live_status() {
    # Get live status from wg show command
    local wg_output=$(wg show "${WG_INTERFACE}" 2>/dev/null)

    # Initialize variables
    STATUS="Never Connected"
    ENDPOINT="N/A"
    LAST_HANDSHAKE="Never"
    TRANSFER_RX="0 B"
    TRANSFER_TX="0 B"

    # Parse wg output for this specific peer
    local in_peer=0
    while IFS= read -r line; do
        # Check if we found our peer
        if [[ "$line" =~ ^peer:\ (.+)$ ]]; then
            if [[ "${BASH_REMATCH[1]}" == "$CLIENT_PUBLIC_KEY" ]]; then
                in_peer=1
            else
                in_peer=0
            fi
        elif [[ $in_peer -eq 1 ]]; then
            # Extract endpoint
            if [[ "$line" =~ ^[[:space:]]+endpoint:\ (.+)$ ]]; then
                ENDPOINT="${BASH_REMATCH[1]}"
            # Extract latest handshake
            elif [[ "$line" =~ ^[[:space:]]+latest\ handshake:\ (.+)$ ]]; then
                local handshake="${BASH_REMATCH[1]}"

                # Parse handshake time
                if [[ "$handshake" =~ ([0-9]+)\ (second|minute|hour|day) ]]; then
                    local time_value="${BASH_REMATCH[1]}"
                    local time_unit="${BASH_REMATCH[2]}"
                    LAST_HANDSHAKE="${time_value} ${time_unit}(s) ago"

                    # Determine status based on time
                    if [[ "$time_unit" == "second" ]]; then
                        STATUS="${GREEN}Connected${NC}"
                    elif [[ "$time_unit" == "minute" ]] && [[ $time_value -le 3 ]]; then
                        STATUS="${GREEN}Connected${NC}"
                    else
                        STATUS="${YELLOW}Idle${NC}"
                    fi
                fi
            # Extract transfer data
            elif [[ "$line" =~ ^[[:space:]]+transfer:\ ([^,]+),\ (.+)$ ]]; then
                TRANSFER_RX="${BASH_REMATCH[1]}"
                TRANSFER_TX="${BASH_REMATCH[2]}"
            fi
        fi
    done <<< "$wg_output"
}

show_status() {
    echo ""
    echo "=========================================="
    print_info "Client Status: ${CLIENT_NAME}"
    echo "=========================================="
    echo ""

    print_info "Configuration:"
    echo "  Name:       ${CLIENT_NAME}"
    echo "  IP:         ${CLIENT_IP}"
    echo "  Public Key: ${CLIENT_PUBLIC_KEY:0:20}...${CLIENT_PUBLIC_KEY: -20}"
    echo ""

    print_info "Connection:"
    echo -e "  Status:          $STATUS"
    echo "  Remote IP:       ${ENDPOINT}"
    echo "  Last Handshake:  ${LAST_HANDSHAKE}"
    echo ""

    print_info "Data Transfer:"
    echo "  Downloaded:  ${TRANSFER_RX}"
    echo "  Uploaded:    ${TRANSFER_TX}"
    echo ""
    echo "=========================================="
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
                echo "  sudo $0 --interface wg0 --client laptop"
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
    echo "  WireGuard Client Status"
    echo "=========================================="
    echo ""

    parse_arguments "$@"

    check_root
    select_server
    select_client
    get_client_info
    get_live_status
    show_status
}

main "$@"
