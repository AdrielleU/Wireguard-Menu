#!/bin/bash
################################################################################
# WireGuard Rotate Keys Script
# Description: Regenerate encryption keys for the server or a single peer.
#              Keys are swapped IN PLACE — only the PrivateKey/PublicKey lines
#              change, so any custom DNS / MTU / AllowedIPs / Endpoint in a
#              peer's config is preserved.
# Usage: sudo ./rotate-keys.sh [OPTIONS]
#   -s, --server            Rotate server keys (all peers must update)
#   -p, --peer NAME         Rotate one peer's keys
#   -i, --interface NAME    WireGuard interface (e.g. wg0)
#   -h, --help              Show this help
################################################################################

set -euo pipefail

source "$(dirname "$0")/utils.sh"

WG_INTERFACE=""
ROTATION_TYPE=""   # "server" or "peer"
PEER_NAME=""

# Peer names declared in the server config (BEGIN_PEER markers).
list_peers() { peer_list "${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"; }

peer_exists() { list_peers | grep -qxF "$1"; }

select_rotation_type() {
    [[ -n "$ROTATION_TYPE" ]] && return
    echo ""
    print_info "What would you like to rotate?"
    echo -e "  ${CYAN}1)${NC} Peer keys   - regenerate a single peer's keys"
    echo -e "  ${CYAN}2)${NC} Server keys - regenerate server keys (all peers need the new server key)"
    echo ""
    read -r -p "Choice (1-2): " choice
    case "$choice" in
        1) ROTATION_TYPE="peer" ;;
        2) ROTATION_TYPE="server" ;;
        *) die "Invalid selection" ;;
    esac
}

select_peer() {
    if [[ -n "$PEER_NAME" ]]; then
        peer_exists "$PEER_NAME" || die "Peer '${PEER_NAME}' not found in ${WG_INTERFACE}"
        return
    fi
    local -a peers
    mapfile -t peers < <(list_peers)
    (( ${#peers[@]} > 0 )) || die "No peers found in ${WG_INTERFACE}"

    echo ""
    print_info "Select peer to rotate keys for:"
    echo ""
    local i
    for i in "${!peers[@]}"; do
        printf "  ${BLUE}%d)${NC} %s\n" "$((i + 1))" "${peers[$i]}"
    done
    echo ""
    read -r -p "Select peer (1-${#peers[@]}): " selection
    [[ "$selection" =~ ^[0-9]+$ ]] && (( selection >= 1 && selection <= ${#peers[@]} )) \
        || die "Invalid selection"
    PEER_NAME="${peers[$((selection - 1))]}"
}

################################################################################
# SERVER KEY ROTATION
################################################################################

rotate_server_keys() {
    local keys_dir="${WG_CONFIG_DIR}/${WG_INTERFACE}"
    local config_file="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"
    local -a peers
    mapfile -t peers < <(list_peers)

    echo ""
    print_warning "This regenerates the SERVER keys for ${WG_INTERFACE}."
    print_warning "All ${#peers[@]} peer(s) will be disconnected until they receive the new server key."
    confirm "Rotate server keys?" || die "Server key rotation cancelled"

    backup_config "$config_file" >/dev/null

    print_info "Generating new server keys..."
    mkdir -p "$keys_dir"; chmod 700 "$keys_dir"
    ( umask 077; wg genkey | tee "${keys_dir}/server-privatekey" | wg pubkey > "${keys_dir}/server-publickey" ) \
        || die "Failed to generate keys"
    chmod 600 "${keys_dir}/server-privatekey" "${keys_dir}/server-publickey"
    local server_private_key server_public_key
    server_private_key=$(cat "${keys_dir}/server-privatekey")
    server_public_key=$(cat "${keys_dir}/server-publickey")
    print_success "New server keys generated"

    # Swap only the server's PrivateKey line in [Interface]; leave the rest.
    local tmp; tmp=$(mktemp) || die "mktemp failed"
    sed "s|^PrivateKey.*|PrivateKey = ${server_private_key}|" "$config_file" > "$tmp"
    mv "$tmp" "$config_file"; chmod 600 "$config_file"
    print_success "Server config updated"

    # Update each local peer config's [Peer] PublicKey (= the new server key).
    # Custom DNS / MTU / AllowedIPs / Endpoint in those files are preserved.
    local peer peer_config updated=0
    for peer in "${peers[@]}"; do
        peer_config="${keys_dir}/${peer}.conf"
        if [[ -f "$peer_config" ]]; then
            sed -i "s|^PublicKey.*|PublicKey = ${server_public_key}|" "$peer_config"
            updated=$((updated + 1))
            print_success "Updated server key in: ${peer}.conf"
        else
            print_warning "No local config for ${peer}; update its [Peer] PublicKey manually"
        fi
    done

    print_info "Restarting ${WG_INTERFACE}..."
    systemctl restart "wg-quick@${WG_INTERFACE}" || die "Failed to restart ${WG_INTERFACE}"
    log_audit "KEY_ROTATION" "interface=${WG_INTERFACE} scope=server peers_updated=${updated}"

    echo ""
    print_success "Server keys rotated. New server public key:"
    echo "  ${server_public_key}"
    echo ""
    print_warning "Every peer must use the new server public key above."
    if (( ${#peers[@]} > 0 )); then
        print_info "Updated local configs (distribute via scp or ./show-qr.sh):"
        for peer in "${peers[@]}"; do
            [[ -f "${keys_dir}/${peer}.conf" ]] && echo "  - ${keys_dir}/${peer}.conf"
        done
    fi
    echo ""
}

################################################################################
# PEER KEY ROTATION
################################################################################

rotate_peer_keys() {
    local keys_dir="${WG_CONFIG_DIR}/${WG_INTERFACE}"
    local config_file="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"
    local peer_config="${keys_dir}/${PEER_NAME}.conf"

    echo ""
    print_warning "This regenerates keys for peer '${PEER_NAME}'."
    print_warning "It will be disconnected until it receives the new config."
    confirm "Rotate keys for ${PEER_NAME}?" || die "Peer key rotation cancelled"

    backup_config "$config_file" >/dev/null
    [[ -f "$peer_config" ]] && backup_config "$peer_config" >/dev/null

    print_info "Generating new keys..."
    ( umask 077; wg genkey | tee "${keys_dir}/${PEER_NAME}-privatekey" | wg pubkey > "${keys_dir}/${PEER_NAME}-publickey" ) \
        || die "Failed to generate keys"
    chmod 600 "${keys_dir}/${PEER_NAME}-privatekey" "${keys_dir}/${PEER_NAME}-publickey"
    local peer_private_key peer_public_key
    peer_private_key=$(cat "${keys_dir}/${PEER_NAME}-privatekey")
    peer_public_key=$(cat "${keys_dir}/${PEER_NAME}-publickey")
    print_success "New keys generated"

    # Replace the peer's PublicKey inside its BEGIN_PEER/END_PEER block only.
    local tmp; tmp=$(mktemp) || die "mktemp failed"
    awk -v name="$PEER_NAME" -v pk="$peer_public_key" '
        $0 == "# BEGIN_PEER " name { inblk = 1 }
        inblk && /^[[:space:]]*PublicKey[[:space:]]*=/ { sub(/=.*/, "= " pk); inblk = 0 }
        $0 == "# END_PEER " name { inblk = 0 }
        { print }
    ' "$config_file" > "$tmp" || die "Failed to update server config"
    mv "$tmp" "$config_file"; chmod 600 "$config_file"
    print_success "Server config updated"

    # Swap only the PrivateKey in the peer's own config — preserve everything else.
    if [[ -f "$peer_config" ]]; then
        sed -i "s|^PrivateKey.*|PrivateKey = ${peer_private_key}|" "$peer_config"
        print_success "Peer config updated (custom settings preserved)"
    else
        print_warning "No local config at ${peer_config}. Deliver the new private key to the peer:"
        echo "  ${peer_private_key}"
    fi

    # Reload without disturbing other peers; fall back to a restart.
    if wg syncconf "${WG_INTERFACE}" <(wg-quick strip "${WG_INTERFACE}") 2>/dev/null; then
        print_success "Reloaded via syncconf (other peers unaffected)"
    else
        print_warning "syncconf failed; restarting ${WG_INTERFACE}..."
        systemctl restart "wg-quick@${WG_INTERFACE}" || die "Failed to restart ${WG_INTERFACE}"
    fi
    log_audit "KEY_ROTATION" "interface=${WG_INTERFACE} scope=peer peer=${PEER_NAME}"

    echo ""
    print_success "Peer keys rotated for ${PEER_NAME}."
    print_warning "The peer must update its configuration."
    if [[ -f "$peer_config" ]]; then
        print_info "Distribute the new config:"
        echo "  sudo ./show-qr.sh -i ${WG_INTERFACE} -c ${PEER_NAME}"
    fi
    echo ""
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --server|-s)    ROTATION_TYPE="server"; shift ;;
            --peer|-p)      ROTATION_TYPE="peer"; PEER_NAME="$2"; shift 2 ;;
            --interface|-i) WG_INTERFACE="$2"; shift 2 ;;
            -h|--help)      sed -n '3,13p' "$0" | sed 's/^# \?//'; exit 0 ;;
            *)              die "Unknown option: $1" ;;
        esac
    done
}

main() {
    echo "=========================================="
    echo "  WireGuard Key Rotation"
    echo "=========================================="

    parse_arguments "$@"
    check_root
    check_deps wg wg-quick
    select_server
    select_rotation_type

    if [[ "$ROTATION_TYPE" == "server" ]]; then
        rotate_server_keys
    else
        select_peer
        rotate_peer_keys
    fi
}

main "$@"
