#!/bin/bash
################################################################################
# WireGuard Peer Toggle
# Description: Enable or disable a peer in <iface>.conf without removing it.
#              Comments out the peer's [Peer] block in place; hot-reloads with
#              wg syncconf so other peers stay connected.
# Usage: sudo ./toggle-peer.sh [OPTIONS]
#
# Requires the new BEGIN_PEER / END_PEER marker format written by add-peer.sh.
# Peers from older configs (legacy `# Client: name` form) are not supported —
# remove and re-add them with add-peer.sh to get the markers.
################################################################################

set -euo pipefail

source "$(dirname "$0")/utils.sh"

WG_INTERFACE=""
PEER_NAME=""

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -i|--interface) WG_INTERFACE="$2"; shift 2 ;;
            -n|--name|-p|--peer) PEER_NAME="$2"; shift 2 ;;
            -h|--help)
                cat <<EOF
Usage: sudo $0 [OPTIONS]

Toggle (enable/disable) a peer in <iface>.conf without deleting any files.
Hot-reloads via 'wg syncconf' — other peers stay connected.

Options:
  -i, --interface NAME   WireGuard interface (e.g., wg0)
  -n, --name NAME        Peer name to toggle
  -h, --help             Show this help
EOF
                exit 0
                ;;
            *) error_exit "Unknown option: $1" ;;
        esac
    done
}

select_server() {
    local -a servers
    mapfile -t servers < <(detect_servers)
    [[ ${#servers[@]} -gt 0 ]] || error_exit "No WireGuard servers found"

    if [[ -n "$WG_INTERFACE" ]]; then
        [[ -f "${WG_CONFIG_DIR}/${WG_INTERFACE}.conf" ]] || error_exit "Server '${WG_INTERFACE}' not found"
        return
    fi

    if [[ ${#servers[@]} -eq 1 ]]; then
        WG_INTERFACE="${servers[0]}"
        return
    fi

    print_info "Multiple servers detected (use -i to skip menu)"
    local i=1
    for s in "${servers[@]}"; do printf "  %d) %s\n" "$i" "$s"; ((i++)) || true; done
    read -p "Select server (1-${#servers[@]}): " sel
    [[ "$sel" =~ ^[0-9]+$ ]] && (( sel >= 1 && sel <= ${#servers[@]} )) || error_exit "Invalid selection"
    WG_INTERFACE="${servers[$((sel-1))]}"
}

# Disable marker — distinct from intrinsic `# ` comments so we can round-trip
# without eating the descriptive `# Client: name` line.
DISABLE_PREFIX="#! "

# Echo "enabled" or "disabled" for a peer name. Requires marker format.
peer_state() {
    local cf="$1" name="$2"
    awk -v name="$name" -v dp="$DISABLE_PREFIX" '
        $0 == "# BEGIN_PEER " name { in_b=1; next }
        in_b && $0 == "# END_PEER " name { exit }
        in_b && index($0, dp) == 1 { print "disabled"; exit }
        in_b && /^[[:space:]]*\[Peer\]/ { print "enabled"; exit }
    ' "$cf"
}

select_peer() {
    local cf="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"
    local -a names
    mapfile -t names < <(grep -oP "^${PEER_BEGIN_PREFIX}\K\S+" "$cf" 2>/dev/null)
    [[ ${#names[@]} -gt 0 ]] || error_exit "No marker-format peers in ${WG_INTERFACE}. (Legacy peers must be re-added via add-peer.sh.)"

    if [[ -n "$PEER_NAME" ]]; then
        local found=0
        for n in "${names[@]}"; do [[ "$n" == "$PEER_NAME" ]] && found=1 && break; done
        [[ $found -eq 1 ]] || error_exit "Peer '${PEER_NAME}' not found (or in legacy format)"
        return
    fi

    echo "Peers on ${WG_INTERFACE}:"
    local i=1
    for n in "${names[@]}"; do
        local s; s=$(peer_state "$cf" "$n")
        printf "  %d) %-20s [%s]\n" "$i" "$n" "${s:-unknown}"
        ((i++)) || true
    done
    read -p "Select peer to toggle (1-${#names[@]}): " sel
    [[ "$sel" =~ ^[0-9]+$ ]] && (( sel >= 1 && sel <= ${#names[@]} )) || error_exit "Invalid selection"
    PEER_NAME="${names[$((sel-1))]}"
}

# Toggle the [Peer] block between BEGIN_PEER/END_PEER markers in place.
# Markers themselves are never touched. Other lines get `# ` prefixed/stripped.
toggle_block() {
    local cf="$1" name="$2" action="$3"   # action: enable|disable
    local tmp; tmp=$(mktemp) || error_exit "mktemp failed"
    trap 'rm -f "$tmp"' RETURN

    local perms owner
    perms=$(stat -c '%a' "$cf" 2>/dev/null || echo 600)
    owner=$(stat -c '%U:%G' "$cf" 2>/dev/null || echo root:root)

    awk -v name="$name" -v action="$action" -v dp="$DISABLE_PREFIX" '
        $0 == "# BEGIN_PEER " name { in_b=1; print; next }
        in_b && $0 == "# END_PEER " name { in_b=0; print; next }
        in_b {
            if (action == "disable") {
                if ($0 ~ /^[[:space:]]*$/) { print; next }
                if (index($0, dp) == 1) { print; next }              # already disabled
                print dp $0; next
            } else {
                if (index($0, dp) == 1) { print substr($0, length(dp)+1); next }
                print; next
            }
        }
        { print }
    ' "$cf" > "$tmp" || error_exit "Failed to rewrite config"

    mv -f "$tmp" "$cf"
    chmod "$perms" "$cf"
    chown "$owner" "$cf" 2>/dev/null || true
    if command -v restorecon &>/dev/null && command -v sestatus &>/dev/null \
       && sestatus 2>/dev/null | grep -q enabled; then
        restorecon "$cf" 2>/dev/null || true
    fi
    trap - RETURN
}

main() {
    parse_arguments "$@"
    check_root
    select_server
    select_peer

    local cf="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"
    local state action new
    state=$(peer_state "$cf" "$PEER_NAME")
    [[ -n "$state" ]] || error_exit "Could not determine state for '${PEER_NAME}'"
    if [[ "$state" == "enabled" ]]; then action=disable; new=disabled
    else                                  action=enable;  new=enabled
    fi

    echo ""
    echo "Peer:      ${PEER_NAME} (${WG_INTERFACE})"
    echo "Currently: ${state}"
    echo "Action:    ${action}"
    echo ""
    read -p "Type '${action}' to confirm: " reply
    [[ "$reply" == "$action" ]] || error_exit "Cancelled"

    toggle_block "$cf" "$PEER_NAME" "$action"
    print_success "Peer ${PEER_NAME} is now ${new} in config"

    if ip link show "$WG_INTERFACE" &>/dev/null; then
        if wg syncconf "$WG_INTERFACE" <(wg-quick strip "$WG_INTERFACE") 2>/dev/null; then
            print_success "Hot-reload OK — change is live (other peers unaffected)"
        else
            print_warning "Hot-reload failed; restart with: systemctl restart wg-quick@${WG_INTERFACE}"
        fi
    else
        print_info "Interface ${WG_INTERFACE} not up; change applies on next start"
    fi

    log_audit "TOGGLE_PEER" "client=${PEER_NAME} action=${action} new_status=${new} interface=${WG_INTERFACE}"
}

main "$@"
