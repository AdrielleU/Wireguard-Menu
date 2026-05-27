#!/bin/bash
################################################################################
# WireGuard Remove Peer Script
# Description: Safely remove a client, site, or p2p peer from a WireGuard
#              server. Uses `wg set peer <pubkey> remove` for a live kernel
#              update plus a marker-aware config rewrite — no restart, other
#              peers stay connected.
# Usage: sudo ./remove-peer.sh [OPTIONS]
################################################################################

set -euo pipefail

source "$(dirname "$0")/utils.sh"

PEER_NAME=""
WG_INTERFACE=""

################################################################################
# INTERACTIVE SELECTION
################################################################################

select_server() {
    local -a servers
    mapfile -t servers < <(detect_servers)
    local server_count=${#servers[@]}
    [[ $server_count -gt 0 ]] || error_exit "No WireGuard servers found. Run setup-wireguard.sh first."

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
        local conf_ip conf_port is_running
        conf_ip=$(grep -E "^Address\s*=" "${WG_CONFIG_DIR}/${iface}.conf" 2>/dev/null | head -n1 | awk '{print $3}')
        conf_port=$(grep -E "^ListenPort\s*=" "${WG_CONFIG_DIR}/${iface}.conf" 2>/dev/null | head -n1 | awk '{print $3}')
        if systemctl is-active --quiet "wg-quick@${iface}"; then
            is_running="${GREEN}[RUNNING]${NC}"
        else
            is_running="${YELLOW}[STOPPED]${NC}"
        fi
        printf "  ${BLUE}%d)${NC} %s %b - %s, Port %s\n" "$i" "$iface" "$is_running" "${conf_ip:-?}" "${conf_port:-?}"
        ((i++)) || true
    done
    echo ""
    read -p "Select server (1-${server_count}): " selection
    if ! [[ "$selection" =~ ^[0-9]+$ ]] || (( selection < 1 || selection > server_count )); then
        error_exit "Invalid selection"
    fi
    WG_INTERFACE="${servers[$((selection-1))]}"
    print_success "Selected server: ${WG_INTERFACE}"
}

select_peer() {
    local config_file="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"
    local -a peers
    mapfile -t peers < <(list_config_peers "$config_file")
    local peer_count=${#peers[@]}
    [[ $peer_count -gt 0 ]] || error_exit "No peers found in ${WG_INTERFACE}"

    if [[ -n "$PEER_NAME" ]]; then
        local found=0
        for p in "${peers[@]}"; do [[ "$p" == "$PEER_NAME" ]] && found=1 && break; done
        [[ $found -eq 1 ]] || error_exit "Peer '${PEER_NAME}' not found in ${WG_INTERFACE}"
        print_success "Using peer: ${PEER_NAME}"
        return
    fi

    print_info "Select a peer to remove"
    echo ""
    local i=1
    for peer in "${peers[@]}"; do
        printf "  ${BLUE}%d)${NC} %s\n" "$i" "$peer"
        ((i++)) || true
    done
    echo ""
    read -p "Select peer to remove (1-${peer_count}): " selection
    if ! [[ "$selection" =~ ^[0-9]+$ ]] || (( selection < 1 || selection > peer_count )); then
        error_exit "Invalid selection"
    fi
    PEER_NAME="${peers[$((selection-1))]}"
    print_success "Selected peer: ${PEER_NAME}"
}

################################################################################
# REMOVAL
################################################################################

# Remove the peer from the running tunnel without touching other peers.
# Uses `wg set peer <pubkey> remove` (O(1), no restart).
live_remove_peer() {
    local pubkey="$1"
    [[ -z "$pubkey" ]] && { print_warning "No public key known for '${PEER_NAME}' — skipping live remove"; return; }

    if ! ip link show "$WG_INTERFACE" &>/dev/null; then
        print_info "Interface ${WG_INTERFACE} is not up; config change alone is enough"
        return
    fi

    if wg set "$WG_INTERFACE" peer "$pubkey" remove 2>/dev/null; then
        print_success "Peer removed from running tunnel (other peers unaffected)"
    else
        print_warning "wg set remove failed; falling back to hot-reload"
        wg syncconf "$WG_INTERFACE" <(wg-quick strip "$WG_INTERFACE") \
            || print_warning "Hot-reload failed — restart with: systemctl restart wg-quick@${WG_INTERFACE}"
    fi
}

remove_peer_files() {
    local keys_dir="${WG_CONFIG_DIR}/${WG_INTERFACE}"
    local removed=0
    for file in \
        "${keys_dir}/${PEER_NAME}-privatekey" \
        "${keys_dir}/${PEER_NAME}-publickey" \
        "${keys_dir}/${PEER_NAME}.conf"; do
        if [[ -f "$file" ]]; then
            rm -f "$file" || print_warning "Failed to remove $(basename "$file")"
            ((removed++)) || true
        fi
    done
    if (( removed > 0 )); then
        print_success "Removed ${removed} peer file(s) from ${keys_dir}"
    else
        print_warning "No peer key/config files found (already cleaned up?)"
    fi
}

show_summary() {
    echo ""
    echo "=========================================="
    print_success "Peer Removed Successfully!"
    echo "=========================================="
    echo ""
    print_info "Removed peer: ${PEER_NAME}"
    print_info "From server:  ${WG_INTERFACE}"
    echo ""
    echo "What was removed:"
    echo "  - Peer block in ${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"
    echo "  - Live kernel peer on ${WG_INTERFACE}"
    echo "  - Peer keys + config in ${WG_CONFIG_DIR}/${WG_INTERFACE}/"
    echo "=========================================="
    echo ""
}

################################################################################
# ARG PARSING
################################################################################

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --interface|-i) WG_INTERFACE="$2"; shift 2 ;;
            --name|-n|--peer|-p|--client|-c) PEER_NAME="$2"; shift 2 ;;
            -h|--help)
                cat <<EOF
Usage: sudo $0 [OPTIONS]

Options:
  -i, --interface NAME    WireGuard interface (e.g., wg0)
  -n, --name NAME         Peer name to remove
  -h, --help              Show this help

Examples:
  sudo $0                                  # Interactive mode
  sudo $0 --interface wg0 --name laptop
  sudo $0 -i wg0 -n branch-office

The live tunnel is updated via 'wg set peer <pubkey> remove' — other peers
stay connected. A marker-aware (or legacy-format) config rewrite persists
the removal.
EOF
                exit 0
                ;;
            *) error_exit "Unknown option: $1" ;;
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
    print_warning "This will PERMANENTLY remove peer '${PEER_NAME}' from ${WG_INTERFACE}"
    print_info "Only this peer will be disconnected; others stay online"
    echo ""
    print_info "To backup before removal, run:"
    echo "  sudo cp ${WG_CONFIG_DIR}/${WG_INTERFACE}.conf ${WG_CONFIG_DIR}/${WG_INTERFACE}.conf.backup.$(date +%Y%m%d_%H%M%S)"
    echo ""
    read -p "Are you sure? (y/N): " -n 1 -r
    echo
    [[ $REPLY =~ ^[Yy]$ ]] || error_exit "Peer removal cancelled"

    local config_file="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"
    local pubkey
    pubkey=$(get_peer_pubkey "$config_file" "$PEER_NAME")
    # Fallback: stored pubkey file (older configs)
    if [[ -z "$pubkey" && -f "${WG_CONFIG_DIR}/${WG_INTERFACE}/${PEER_NAME}-publickey" ]]; then
        pubkey=$(cat "${WG_CONFIG_DIR}/${WG_INTERFACE}/${PEER_NAME}-publickey")
    fi

    print_info "Removing peer block from ${config_file}..."
    remove_peer_block "$config_file" "$PEER_NAME"
    print_success "Config rewritten"

    live_remove_peer "$pubkey"
    remove_peer_files

    log_audit "REMOVE_PEER" "client=${PEER_NAME} interface=${WG_INTERFACE}"
    show_summary
}

main "$@"
