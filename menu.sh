#!/bin/bash
################################################################################
# WireGuard Management Menu
# Description: Interactive menu that does the WireGuard work itself — every
#              action is a function in this file, built on the shared helpers
#              in utils.sh, rather than a separate script per action.
#
# Actions:
#   Setup WireGuard Server   write <iface>.conf and the server keys
#   Add Peer                 generate a client key, add it to the config, sync
#   Remove Peer              delete the peer's block and keys, sync, verify
#   Toggle Peer              pause (comment the peer out) or resume, sync, verify
#   Rotate Keys              new keypair for a peer or the server, sync, verify
#   List Peers               wg show all: what the kernel has right now
#
# "sync" is `wg syncconf <iface> <(wg-quick strip <conf>)` when the interface is
# up: the running interface is made to match the file (see sync_live).
#
# Usage: sudo ./menu.sh
################################################################################

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/utils.sh"

################################################################################
# HELPERS
################################################################################

pause() {
    echo ""
    read -rp "Press Enter to continue..."
}

# Every IP already claimed in <conf> — the interface Address and each peer's
# AllowedIPs, paused and commented-out ones included — one per line, without
# the /prefix.
conf_used_ips() {
    strip_pause_prefixes "$1" \
        | grep -E '^[[:space:]]*#?[[:space:]]*(Address|AllowedIPs)[[:space:]]*=' \
        | sed 's/^[^=]*=//' | tr ',' '\n' | sed 's/[[:space:]]//g; s#/.*##' \
        | grep -v '^$' || true
}

# The first free host in the interface's /24, offered as the default at the IP
# prompt. Prints nothing if <conf> has no IPv4 Address.
next_free_ip() {
    local conf="$1" used prefix i
    used=$(conf_used_ips "$conf")
    prefix=$(sed -nE '/^[[:space:]]*Address[[:space:]]*=/{s/^[^=]*=[[:space:]]*([0-9]+\.[0-9]+\.[0-9]+)\.[0-9]+.*/\1/p;q}' "$conf")
    [[ -n "$prefix" ]] || return 0
    for i in {2..254}; do
        if ! grep -qxF "${prefix}.${i}" <<<"$used"; then
            echo "${prefix}.${i}"
            return 0
        fi
    done
}

# Print the lines of <name>'s block in <conf>, markers excluded.
peer_block() {
    awk -v b="${PEER_BEGIN_PREFIX}$2" -v e="${PEER_END_PREFIX}$2" '
        $0 == b { inb = 1; next }
        $0 == e { inb = 0 }
        inb { print }' "$1"
}

# "paused" when <name>'s block has no live [Peer] line (it is commented out),
# otherwise "active". Also peer_select's annotator, so the list shows each
# peer's state.
peer_pause_state() {
    local block
    block=$(peer_block "$1" "$2")
    if grep -qE '^[[:space:]]*\[Peer\]' <<<"$block"; then echo active; else echo paused; fi
}

# Pause <name> in <conf> by commenting out every WireGuard line in its block
# with PEER_PAUSE_PREFIX (blank lines, comments and the markers are left
# alone), or resume it by stripping that prefix. Rewrites in place, so the file
# keeps its owner, mode and SELinux label.
peer_set_paused() {
    local conf="$1" name="$2" action="$3" tmp
    tmp=$(mktemp) || die "mktemp failed"
    awk -v b="${PEER_BEGIN_PREFIX}${name}" -v e="${PEER_END_PREFIX}${name}" \
        -v pp="$PEER_PAUSE_PREFIX" -v act="$action" '
        $0 == b { inb = 1; print; next }
        inb && $0 == e { inb = 0; print; next }
        inb && act == "pause" && $0 !~ /^[[:space:]]*(#|$)/ { print pp $0; next }
        inb && act == "resume" && index($0, pp) == 1 { print substr($0, length(pp) + 1); next }
        { print }
    ' "$conf" > "$tmp" || { rm -f "$tmp"; die "Failed to rewrite ${conf}"; }
    cat "$tmp" > "$conf"
    rm -f "$tmp"
}

# Make the running interface match <conf>: `wg syncconf` with the config after
# `wg-quick strip`. Peers no longer in the file — removed, or paused and so
# commented out — are dropped, new and resumed ones are added, and peers whose
# settings did not change keep their sessions. Works however the interface was
# started. Returns 0 when the interface is down (the file applies when it comes
# up), 1 when the sync failed.
sync_live() {
    local iface="$1" conf="$2" stripped
    if ! wg show "$iface" &>/dev/null; then
        print_info "${iface} is not up, so the config change is all that's needed"
        return 0
    fi
    # Strip first: piped straight into syncconf, a strip that failed would hand
    # it an empty config, which drops every peer.
    if ! stripped=$(wg-quick strip "$conf"); then
        print_error "wg-quick strip failed on ${conf}; the running ${iface} was left as it was"
        return 1
    fi
    if wg syncconf "$iface" <(printf '%s\n' "$stripped"); then
        print_success "Synced the running ${iface} from ${conf}; unchanged peers stayed connected"
    else
        print_error "wg syncconf failed; ${conf} is changed but the running ${iface} is not"
        return 1
    fi
}

################################################################################
# ACTIONS
################################################################################
# One function per menu entry. run_action calls each in a subshell, so an action
# can exit — directly, through utils.sh's die/check_root, or by failing under
# `set -e` — without taking the menu down, and the variables it sets don't leak
# into the next action.

# --- Setup WireGuard Server --------------------------------------------------
# Write <iface>.conf with a server keypair, in the format and places
# verify-config.sh and the peer scripts expect. A config that already exists is
# never overwritten; it is checked with verify-config.sh instead.
#
# The config gets a "# Healthcheck-Role = server" line, so healthcheck.sh never
# auto-restarts this server.
#
# Not done here: installing packages, IP forwarding, firewall rules, SELinux, or
# starting wg-quick@<iface>.
setup_server() {
    check_root
    check_deps wg

    local iface port address
    read -rp "Interface name [wg0]: " iface
    iface="${iface:-wg0}"
    validate_interface_name "$iface" || die "Invalid interface name: ${iface}"

    local conf="${WG_CONFIG_DIR}/${iface}.conf"
    local keys_dir="${WG_CONFIG_DIR}/${iface}"

    # verify-config.sh exits 1 for a missing config and for a config with errors
    # alike, so whether it exists is a plain file test; verify-config.sh then
    # checks whatever config is there.
    if [[ -f "$conf" ]]; then
        print_warning "${conf} already exists; leaving it as is and checking it"
        "${SCRIPT_DIR}/verify-config.sh" -i "$iface"
        return
    fi

    read -rp "Listen port [51820]: " port
    port="${port:-51820}"
    if ! [[ "$port" =~ ^[0-9]+$ ]] || (( 10#$port < 1 || 10#$port > 65535 )); then
        die "Invalid port: ${port}"
    fi
    port=$((10#$port))

    read -rp "Server address [10.0.0.1/24]: " address
    address="${address:-10.0.0.1/24}"
    [[ "$address" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]] \
        || die "Invalid address (expected IP/CIDR, e.g. 10.0.0.1/24): ${address}"

    # Server keys live in <iface>/, where verify-config.sh and the peer scripts
    # look for them. Existing keys are reused, so peers that already hold this
    # server's public key keep working when only the config was lost.
    local priv="${keys_dir}/server-privatekey" pub="${keys_dir}/server-publickey"
    mkdir -p "$keys_dir"
    chmod 700 "$keys_dir"
    if [[ -f "$priv" ]]; then
        print_warning "Keys already exist for ${iface}, reusing them"
    else
        # umask first, so the private key is never readable by others, even briefly.
        ( umask 077; wg genkey | tee "$priv" | wg pubkey > "$pub" ) || die "Failed to generate keys"
        print_success "Server keys generated in ${keys_dir}"
    fi
    [[ -f "$pub" ]] || ( umask 077; wg pubkey < "$priv" > "$pub" ) || die "Failed to derive the public key"
    chmod 600 "$priv" "$pub"

    # The Healthcheck-Role line is inert to wg, but it is what stops
    # healthcheck.sh --restart from bouncing this server (and dropping every
    # peer) on a structural failure. verify-config.sh fails a server without it.
    ( umask 077
      printf '[Interface]\n# Healthcheck-Role = server\nAddress = %s\nListenPort = %s\nPrivateKey = %s\n' \
          "$address" "$port" "$(< "$priv")" > "$conf" ) || die "Failed to write ${conf}"
    chmod 600 "$conf"
    print_success "Configuration file created: ${conf}"
    print_info "Server public key (give this to peers): $(< "$pub")"

    echo ""
    print_info "Checking it with verify-config.sh (no peers and no setup manifest yet, so expect warnings for those):"
    "${SCRIPT_DIR}/verify-config.sh" -i "$iface" -q
}

# --- Add Peer ----------------------------------------------------------------
# Add a client peer: generate its keypair, add it to <iface>.conf in the
# BEGIN_PEER/END_PEER format the peer scripts and verify-config.sh read, and
# sync the running interface from the file (sync_live). A /32 inside the
# interface's own subnet needs no new route, which is why a sync is enough.
#
# Not done here: site and p2p peers (their remote networks need routes, so a
# restart), the peer's own config file, and QR codes.
add_peer() {
    check_root
    check_deps wg wg-quick

    select_server
    local iface="$WG_INTERFACE"
    local conf="${WG_CONFIG_DIR}/${iface}.conf"
    local keys_dir="${WG_CONFIG_DIR}/${iface}"

    local name peers
    read -rp "Peer name: " name
    peer_validate_name "$name" || return 1
    peers=$(peer_list "$conf")
    if grep -qxF "$name" <<<"$peers"; then
        die "Peer '${name}' already exists in ${iface}"
    fi

    local ip suggested used
    suggested=$(next_free_ip "$conf")
    read -rp "Peer tunnel IP${suggested:+ [${suggested}]}: " ip
    ip="${ip:-$suggested}"
    ip="${ip%/32}"
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "Invalid IP (expected e.g. 10.0.0.2): ${ip}"
    used=$(conf_used_ips "$conf")
    if grep -qxF "$ip" <<<"$used"; then
        die "${ip} is already used in ${conf}"
    fi

    # Keys go next to the server's, as <name>-privatekey / <name>-publickey.
    local priv="${keys_dir}/${name}-privatekey" pub="${keys_dir}/${name}-publickey"
    mkdir -p "$keys_dir"
    ( umask 077; wg genkey | tee "$priv" | wg pubkey > "$pub" ) || die "Failed to generate keys"
    chmod 600 "$priv" "$pub"
    print_success "Keys generated in ${keys_dir}"

    backup_config "$conf" >/dev/null
    printf '\n%s%s\n# Client: %s\n[Peer]\nPublicKey = %s\nAllowedIPs = %s/32\n%s%s\n' \
        "$PEER_BEGIN_PREFIX" "$name" "$name" "$(< "$pub")" "$ip" "$PEER_END_PREFIX" "$name" \
        >> "$conf" || die "Failed to add the peer to ${conf}"
    print_success "Added peer '${name}' (${ip}/32) to ${conf}"

    local rc=0
    sync_live "$iface" "$conf" || rc=1

    local server_priv
    server_priv=$(sed -nE '/^[[:space:]]*PrivateKey[[:space:]]*=/{s/^[^=]*=[[:space:]]*//p;q}' "$conf")
    echo ""
    print_info "Peer private key: ${priv}"
    print_info "Server public key: $(wg pubkey <<<"$server_priv")"
    return "$rc"
}

# --- Remove Peer -------------------------------------------------------------
# The reverse of Add Peer: delete the peer's block — everything from its
# `# BEGIN_PEER <name>` line through `# END_PEER <name>` — and its key files,
# sync the running interface from the file, which drops just that peer
# (sync_live), and always finish by checking the config with verify-config.sh.
remove_peer() {
    check_root
    check_deps wg wg-quick

    select_server
    local iface="$WG_INTERFACE"
    local conf="${WG_CONFIG_DIR}/${iface}.conf"
    local keys_dir="${WG_CONFIG_DIR}/${iface}"

    local name
    name=$(peer_select "$conf" "" "Select a peer to remove") || return 1
    if ! confirm "Remove peer '${name}' from ${iface}?"; then
        print_info "Cancelled; nothing was changed"
        return 0
    fi

    backup_config "$conf" >/dev/null
    peer_remove "$conf" "$name"
    print_success "Removed peer '${name}' from ${conf}"

    # Its keys, plus its client config if one was made.
    rm -f "${keys_dir}/${name}-privatekey" "${keys_dir}/${name}-publickey" "${keys_dir}/${name}.conf"
    print_success "Removed ${name}'s key files from ${keys_dir}"

    local rc=0
    sync_live "$iface" "$conf" || rc=1

    echo ""
    print_info "Checking the config with verify-config.sh:"
    "${SCRIPT_DIR}/verify-config.sh" -i "$iface" -q || rc=1
    return "$rc"
}

# --- Toggle Peer (pause / resume) -------------------------------------------
# Take a peer offline without deleting it, or bring it back, by editing its
# block and syncing the running interface from the file (sync_live).
#   Pause:  comment out its WireGuard lines ("#! "). wg-quick strip leaves them
#           out, so the sync drops the peer, and it stays paused across restarts.
#   Resume: uncomment; the sync adds the peer back with every setting in its
#           block.
# Either way it finishes by checking the config with verify-config.sh.
toggle_peer() {
    check_root
    check_deps wg wg-quick

    select_server
    local iface="$WG_INTERFACE"
    local conf="${WG_CONFIG_DIR}/${iface}.conf"

    local name action
    name=$(peer_select "$conf" "" "Select a peer to pause or resume" peer_pause_state) || return 1
    if [[ "$(peer_pause_state "$conf" "$name")" == active ]]; then action="pause"; else action="resume"; fi
    if ! confirm "${action^} peer '${name}' on ${iface}?"; then
        print_info "Cancelled; nothing was changed"
        return 0
    fi

    backup_config "$conf" >/dev/null
    peer_set_paused "$conf" "$name" "$action"
    print_success "${action^}d '${name}' in ${conf}"

    local rc=0
    sync_live "$iface" "$conf" || rc=1

    echo ""
    print_info "Checking the config with verify-config.sh:"
    "${SCRIPT_DIR}/verify-config.sh" -i "$iface" -q || rc=1
    return "$rc"
}

# --- Rotate Keys -------------------------------------------------------------
# Give one peer, or the server, a new keypair: the key files are replaced, the
# key is swapped where it sits in the config, a running interface is synced from
# the file (sync_live), and the config is checked with verify-config.sh.
#   Peer:   <name>-privatekey/-publickey, and the PublicKey in its block (a
#           paused peer's too). Only that peer is cut off, until it has its new
#           private key.
#   Server: server-privatekey/-publickey, and PrivateKey in [Interface]. Every
#           peer is cut off until its config has the new server public key.
# Client configs kept as <iface>/<name>.conf get their new key automatically.
rotate_keys() {
    check_root
    check_deps wg wg-quick

    select_server
    local iface="$WG_INTERFACE"
    local conf="${WG_CONFIG_DIR}/${iface}.conf"
    local keys_dir="${WG_CONFIG_DIR}/${iface}"

    echo "  1) One peer's keys"
    echo "  2) The server's keys (every peer needs the new server public key)"
    local which name=""
    read -rp "Rotate (1-2): " which
    case "$which" in
        1)
            name=$(peer_select "$conf" "" "Select a peer to rotate keys for" peer_pause_state) || return 1
            if ! confirm "Rotate keys for '${name}'? It is cut off until it has its new private key."; then
                print_info "Cancelled; nothing was changed"
                return 0
            fi
            ;;
        2)
            if ! confirm "Rotate the server keys for ${iface}? Every peer is cut off until it has the new server public key."; then
                print_info "Cancelled; nothing was changed"
                return 0
            fi
            ;;
        *) die "Invalid selection: ${which}" ;;
    esac

    local who="${name:-server}"
    local priv="${keys_dir}/${who}-privatekey" pub="${keys_dir}/${who}-publickey"
    backup_config "$conf" >/dev/null
    mkdir -p "$keys_dir"
    ( umask 077; wg genkey | tee "$priv" | wg pubkey > "$pub" ) || die "Failed to generate keys"
    chmod 600 "$priv" "$pub"
    print_success "New keypair: ${priv}, ${pub}"

    local newpriv newpub tmp
    newpriv=$(< "$priv")
    newpub=$(< "$pub")
    tmp=$(mktemp) || die "mktemp failed"
    if [[ -n "$name" ]]; then
        # The PublicKey in its block, commented out (paused) or not.
        awk -v b="${PEER_BEGIN_PREFIX}${name}" -v e="${PEER_END_PREFIX}${name}" \
            -v pp="$PEER_PAUSE_PREFIX" -v k="$newpub" '
            $0 == b { inb = 1 }
            $0 == e { inb = 0 }
            inb && (/^[[:space:]]*PublicKey[[:space:]]*=/ || index($0, pp "PublicKey") == 1) { sub(/=.*/, "= " k) }
            { print }' "$conf" > "$tmp" || { rm -f "$tmp"; die "Failed to rewrite ${conf}"; }
    else
        # PrivateKey in [Interface] only.
        awk -v k="$newpriv" '
            /^[[:space:]]*\[/ { in_i = ($0 ~ /^[[:space:]]*\[Interface\]/) }
            in_i && /^[[:space:]]*PrivateKey[[:space:]]*=/ { sub(/=.*/, "= " k) }
            { print }' "$conf" > "$tmp" || { rm -f "$tmp"; die "Failed to rewrite ${conf}"; }
    fi
    cat "$tmp" > "$conf"
    rm -f "$tmp"
    print_success "Put the new ${who} key in ${conf}"

    # Client configs kept as <iface>/<name>.conf: the peer's own gets its new
    # PrivateKey; on a server rotation each one gets the new server PublicKey.
    local -a clients=()
    local p client
    if [[ -n "$name" ]]; then
        if [[ -f "${keys_dir}/${name}.conf" ]]; then clients=("${keys_dir}/${name}.conf"); fi
    else
        while read -r p; do
            if [[ -n "$p" && -f "${keys_dir}/${p}.conf" ]]; then clients+=("${keys_dir}/${p}.conf"); fi
        done < <(peer_list "$conf")
    fi
    for client in ${clients[@]+"${clients[@]}"}; do
        backup_config "$client" >/dev/null
        if [[ -n "$name" ]]; then
            sed -i "s|^PrivateKey[[:space:]]*=.*|PrivateKey = ${newpriv}|" "$client"
        else
            sed -i "s|^PublicKey[[:space:]]*=.*|PublicKey = ${newpub}|" "$client"
        fi
        print_success "Updated client config ${client}"
    done

    local rc=0
    sync_live "$iface" "$conf" || rc=1

    echo ""
    if [[ -n "$name" ]]; then
        print_info "'${name}' needs its new private key: ${priv}"
    else
        print_info "Every peer needs the new server public key: ${newpub}"
    fi
    print_info "Checking the config with verify-config.sh:"
    "${SCRIPT_DIR}/verify-config.sh" -i "$iface" -q || rc=1
    return "$rc"
}

# --- List Peers --------------------------------------------------------------
# What the kernel has right now: `wg show all` — every interface with its peers,
# endpoints, handshakes and transfer. A paused peer is not on the interface, so
# it does not appear here; the config is where it shows, and verify-config.sh
# reports it as paused.
list_peers() {
    check_root
    check_deps wg

    local out
    out=$(wg show all)
    if [[ -z "$out" ]]; then
        print_info "No WireGuard interfaces are up"
        return 0
    fi
    echo "$out"
}

################################################################################
# MENU
################################################################################

show_header() {
    if [[ -t 1 ]]; then clear; fi
    echo ""
    echo "=========================================="
    echo -e "  ${CYAN}WireGuard Management Menu${NC}"
    echo "=========================================="
    echo ""
}

show_menu() {
    show_header

    echo -e "${BLUE}Peer Management:${NC}"
    echo "  1) Add Peer (Client)"
    echo "  2) Remove Peer"
    echo "  3) Toggle Peer (pause/resume)"
    echo "  4) List Peers (wg show all)"
    echo ""

    echo -e "${BLUE}Server Setup & Management:${NC}"
    echo "  5) Setup WireGuard Server"
    echo "  6) Rotate Keys (server or peer)"
    echo ""

    echo -e "${BLUE}System:${NC}"
    echo "  0) Exit"
    echo ""
    echo "=========================================="
    echo ""
}

# Run one action function between banners, report how it ended, and wait for
# Enter — the in-file counterpart of menu.sh's run_script.
run_action() {
    local fn="$1" title="$2"

    echo ""
    print_info "Running: ${title}"
    echo "=========================================="
    echo ""

    # errexit is re-enabled inside the subshell: set +e here only keeps a
    # failing action from exiting the menu itself.
    set +e
    ( set -e; "$fn" )
    local exit_code=$?
    set -e

    echo ""
    echo "=========================================="
    if [[ $exit_code -eq 0 ]]; then
        print_success "${title}: completed successfully"
    else
        print_warning "${title}: exited with code ${exit_code}"
    fi
    pause
}

################################################################################
# MAIN
################################################################################

main() {
    while true; do
        show_menu
        read -rp "Select an option: " choice
        case "$choice" in
            1) run_action add_peer     "Add Peer (Client)" ;;
            2) run_action remove_peer  "Remove Peer" ;;
            3) run_action toggle_peer  "Toggle Peer (pause/resume)" ;;
            4) run_action list_peers   "List Peers (wg show all)" ;;
            5) run_action setup_server "Setup WireGuard Server" ;;
            6) run_action rotate_keys  "Rotate Keys (server or peer)" ;;
            0)
                echo ""
                print_info "Exiting WireGuard Management Menu"
                echo ""
                exit 0
                ;;
            *)
                print_error "Invalid selection: ${choice}"
                pause
                ;;
        esac
    done
}

main "$@"
