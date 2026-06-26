#!/bin/bash
################################################################################
# WireGuard Show QR Code Script
# Description: Display a peer's config as a QR code for mobile devices.
# Usage: sudo ./show-qr.sh [OPTIONS]
#   -i, --interface NAME    WireGuard interface (e.g. wg0)
#   -c, --client NAME       Peer/client name
#   -h, --help              Show this help
################################################################################

set -euo pipefail

source "$(dirname "$0")/utils.sh"

WG_INTERFACE=""
CLIENT_NAME=""

# Names of peer configs available to display: the *.conf files in the
# interface's key directory (each is a complete client/site config we can QR).
list_clients() {
    local peer_dir="${WG_CONFIG_DIR}/${WG_INTERFACE}"
    [[ -d "$peer_dir" ]] || return 0
    local f
    shopt -s nullglob
    for f in "$peer_dir"/*.conf; do
        basename "$f" .conf
    done
    shopt -u nullglob
}

select_client() {
    local -a clients
    mapfile -t clients < <(list_clients)
    (( ${#clients[@]} > 0 )) || die "No peer configs found in ${WG_INTERFACE}"

    if [[ -n "$CLIENT_NAME" ]]; then
        [[ -f "${WG_CONFIG_DIR}/${WG_INTERFACE}/${CLIENT_NAME}.conf" ]] \
            || die "Peer config '${CLIENT_NAME}' not found in ${WG_INTERFACE}"
        return
    fi

    echo ""
    print_info "Select a peer to display its QR code (for mobile devices)"
    echo ""
    local i
    for i in "${!clients[@]}"; do
        printf "  ${BLUE}%d)${NC} %s\n" "$((i + 1))" "${clients[$i]}"
    done
    echo ""
    read -r -p "Select peer (1-${#clients[@]}): " selection
    [[ "$selection" =~ ^[0-9]+$ ]] && (( selection >= 1 && selection <= ${#clients[@]} )) \
        || die "Invalid selection"
    CLIENT_NAME="${clients[$((selection - 1))]}"
}

show_qr_code() {
    local client_config="${WG_CONFIG_DIR}/${WG_INTERFACE}/${CLIENT_NAME}.conf"
    [[ -f "$client_config" ]] || die "Peer config not found: ${client_config}"

    echo ""
    echo "=========================================="
    print_info "QR code for ${CLIENT_NAME} (${WG_INTERFACE})"
    echo "=========================================="
    echo ""
    qrencode -t ansiutf8 < "$client_config"
    echo ""
    print_info "Scan with the WireGuard mobile app. Config: ${client_config}"
    echo ""
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --interface|-i) WG_INTERFACE="$2"; shift 2 ;;
            --client|-c)    CLIENT_NAME="$2"; shift 2 ;;
            -h|--help)      sed -n '3,9p' "$0" | sed 's/^# \?//'; exit 0 ;;
            *)              die "Unknown option: $1" ;;
        esac
    done
}

main() {
    echo "=========================================="
    echo "  WireGuard QR Code Generator"
    echo "=========================================="

    parse_arguments "$@"
    check_root
    check_deps qrencode
    select_server
    select_client
    show_qr_code
}

main "$@"
