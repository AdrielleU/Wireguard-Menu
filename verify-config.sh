#!/bin/bash
################################################################################
# WireGuard Config Verification
# Description: Assert that an interface's on-disk state matches the conventions
#              this toolkit writes and reads. This is a CONFORMANCE check, not
#              a health check — it never touches the running tunnel.
#
#   healthcheck.sh  answers "is the tunnel working right now?"  (runtime)
#   verify-config.sh answers "is this config shaped the way our
#                             scripts expect?"                   (on disk)
#
# The check that matters most is marker coverage: WireGuard happily loads a
# [Peer] block with no `# BEGIN_PEER <name>` markers, but list/toggle/remove/
# rotate all read peers via those markers, so such a peer connects fine while
# being invisible to — and unmanageable by — every script here. That happens
# after a hand-edit, or when restoring a config written before the marker
# format existed. Nothing else in the toolkit reports it.
#
# Usage: sudo ./verify-config.sh [OPTIONS]
#   -i, --interface NAME   Interface to verify (default: prompt / autodetect)
#   -a, --all              Verify every detected interface
#   -s, --strict           Treat warnings as failures too
#   -q, --quiet            Only print problems and the summary
#   -h, --help             Show this help
#
# Exit codes: 0 = no errors (see --strict), 1 = errors found.
################################################################################

set -uo pipefail   # not -e — a failed check must not abort the whole report

source "$(dirname "$0")/utils.sh"

WG_INTERFACE=""
ALL=false
STRICT=false
QUIET=false

ERRORS=0
WARNINGS=0

################################################################################
# REPORTING
################################################################################
# Report lines go to stdout (this script's output IS the report), unlike the
# print_* helpers in utils.sh which are stderr-bound status chatter.

section() { $QUIET || { echo; echo -e "${CYAN}== $1 ==${NC}"; }; }
ok()      { $QUIET || echo -e "  ${GREEN}ok${NC}   $1"; }
warn()    { WARNINGS=$((WARNINGS + 1)); echo -e "  ${YELLOW}warn${NC} $1"; }
err()     { ERRORS=$((ERRORS + 1));     echo -e "  ${RED}FAIL${NC} $1"; }

# Expected mode is 600 for anything holding key material.
check_mode() {
    local f="$1" want="${2:-600}" mode
    [[ -e "$f" ]] || return 0
    mode=$(stat -c '%a' "$f" 2>/dev/null) || return 0
    if [[ "$mode" == "$want" ]]; then
        ok "mode ${mode} ${f}"
    else
        warn "mode ${mode} (expected ${want}): ${f}"
    fi
}

################################################################################
# CHECKS
################################################################################

# --- the server config itself ---------------------------------------------
verify_server_config() {
    local conf="$1" iface="$2"

    section "server config  (${conf})"

    if [[ ! -f "$conf" ]]; then
        err "no config file at ${conf}"
        return 1
    fi

    # NB: `wg-quick strip` is NOT a validator — it is a filter that echoes the
    # file with comments and wg-quick-only keys removed, and it exits 0 on
    # arbitrary garbage. So parse the structure here instead: exactly one
    # [Interface], no unknown section headers, and every substantive line in
    # `Key = Value` form.
    local structure
    structure=$(awk '
        /^[[:space:]]*(#|$)/ { next }
        /^[[:space:]]*\[/ {
            hdr = $0
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", hdr)
            if (hdr == "[Interface]")   { ifaces++; next }
            if (hdr == "[Peer]")        { next }
            print "unknown section header on line " NR ": " hdr
            next
        }
        !/^[[:space:]]*[A-Za-z][A-Za-z0-9]*[[:space:]]*=/ {
            print "not a Key = Value line (" NR "): " $0
        }
        END {
            if (ifaces == 0) print "no [Interface] section"
            if (ifaces > 1)  print "more than one [Interface] section (" ifaces ")"
        }
    ' "$conf")

    if [[ -z "$structure" ]]; then
        ok "structure is valid (one [Interface], well-formed Key = Value lines)"
    else
        while read -r line; do
            [[ -n "$line" ]] && err "$line"
        done <<<"$structure"
    fi

    local key
    for key in PrivateKey Address ListenPort; do
        if awk -v k="$key" '
                /^[[:space:]]*\[/ { in_i = ($0 ~ /^\[Interface\]/); next }
                in_i && $0 ~ "^[[:space:]]*" k "[[:space:]]*=" { found = 1 }
                END { exit !found }
            ' "$conf"; then
            ok "[Interface] has ${key}"
        else
            # A client-mode config legitimately has no ListenPort; everything
            # this toolkit calls a server does.
            if [[ "$key" == "ListenPort" ]]; then
                warn "[Interface] has no ListenPort (fine for a client config, not for a server)"
            else
                err "[Interface] has no ${key}"
            fi
        fi
    done

    check_mode "$conf" 600
}

# --- marker coverage: the drift that nothing else catches ------------------
verify_marker_coverage() {
    local conf="$1"

    section "peer marker coverage"

    # grep -c already prints 0 when nothing matches (and exits 1) — a `|| echo 0`
    # here would append a second 0 and corrupt the arithmetic below.
    local raw marked
    raw=$(grep -c '^[[:space:]]*\[Peer\]' "$conf" 2>/dev/null)
    marked=$(peer_list "$conf" | grep -c .)
    raw=${raw:-0}; marked=${marked:-0}

    if (( raw == marked )); then
        ok "${marked}/${raw} [Peer] blocks carry BEGIN_PEER markers"
        return 0
    fi

    err "${marked}/${raw} [Peer] blocks carry BEGIN_PEER markers — $((raw - marked)) peer(s) are invisible to list/toggle/remove/rotate"

    # Name the offenders by public key so they can be found and re-added.
    local unmanaged
    unmanaged=$(awk '
        /^# BEGIN_PEER / { inb = 1 }
        /^# END_PEER /   { inb = 0; next }
        /^[[:space:]]*\[Peer\]/ { if (!inb) orphan = 1; else orphan = 0 }
        orphan && /^[[:space:]]*PublicKey[[:space:]]*=/ {
            sub(/^[^=]*=[[:space:]]*/, ""); print "    unmarked peer, PublicKey = " $0
        }
    ' "$conf")
    [[ -n "$unmanaged" ]] && echo "$unmanaged"
    echo "    fix: re-add these with add-peer.sh, or wrap each block in"
    echo "         '# BEGIN_PEER <name>' / '# END_PEER <name>' by hand"
}

# --- structure of each marker block ---------------------------------------
verify_peer_blocks() {
    local conf="$1"

    section "peer blocks"

    local -a peers
    mapfile -t peers < <(peer_list "$conf")
    if (( ${#peers[@]} == 0 )); then
        warn "no marker-format peers declared"
        return 0
    fi

    # Unterminated blocks: every BEGIN_PEER needs its own END_PEER.
    local name
    for name in "${peers[@]}"; do
        if ! grep -Fxq "${PEER_END_PREFIX}${name}" "$conf"; then
            err "peer '${name}': BEGIN_PEER with no matching END_PEER"
        fi
    done

    # Duplicate names — peer_select would silently only ever reach the first.
    local dupes
    dupes=$(printf '%s\n' "${peers[@]}" | sort | uniq -d)
    if [[ -n "$dupes" ]]; then
        while read -r name; do
            [[ -n "$name" ]] && err "peer name '${name}' declared more than once"
        done <<<"$dupes"
    fi

    # Per-block required fields.
    for name in "${peers[@]}"; do
        local block
        block=$(awk -v b="# BEGIN_PEER ${name}" -v e="# END_PEER ${name}" '
            $0 == b { inb = 1; next } $0 == e { exit } inb { print }
        ' "$conf")

        local problems=()
        grep -qE '^[[:space:]]*PublicKey[[:space:]]*=' <<<"$block"  || problems+=("no PublicKey")
        grep -qE '^[[:space:]]*AllowedIPs[[:space:]]*=' <<<"$block" || problems+=("no AllowedIPs")

        if (( ${#problems[@]} > 0 )); then
            err "peer '${name}': $(IFS=', '; echo "${problems[*]}")"
            continue
        fi

        # Type metadata is what list-peers.sh renders in its type column;
        # missing it degrades the display but breaks nothing, so: warning.
        if ! grep -qE '^#[[:space:]]*(Client|Site|Peer-to-Peer):' <<<"$block"; then
            warn "peer '${name}': no '# Client:/# Site:/# Peer-to-Peer:' type line (list-peers.sh will show it as Client)"
        fi

        peer_validate_name "$name" 2>/dev/null \
            || warn "peer '${name}': name would be rejected by add-peer.sh today"
    done

    (( ERRORS == 0 )) && ok "${#peers[@]} block(s) structurally complete"

    verify_no_collisions "$conf" "${peers[@]}"
}

# Duplicate public keys and duplicate AllowedIPs entries across peers.
# Exact-duplicate detection only — genuine CIDR overlap arithmetic is beyond
# what's worth doing in bash, so a contained subnet is NOT reported here.
verify_no_collisions() {
    local conf="$1"; shift
    local -a peers=("$@")
    local name field

    for field in PublicKey AllowedIPs; do
        local pairs="" line
        for name in "${peers[@]}"; do
            local vals
            vals=$(awk -v b="# BEGIN_PEER ${name}" -v e="# END_PEER ${name}" -v k="$field" '
                $0 == b { inb = 1; next } $0 == e { exit }
                inb && $0 ~ "^[[:space:]]*" k "[[:space:]]*=" {
                    sub(/^[^=]*=[[:space:]]*/, "")
                    n = split($0, a, ",")
                    for (i = 1; i <= n; i++) { gsub(/^[[:space:]]+|[[:space:]]+$/, "", a[i]); print a[i] }
                }
            ' "$conf")
            while read -r line; do
                [[ -n "$line" ]] && pairs+="${line}|${name}"$'\n'
            done <<<"$vals"
        done

        local dup
        dup=$(cut -d'|' -f1 <<<"$pairs" | grep -v '^$' | sort | uniq -d)
        if [[ -n "$dup" ]]; then
            while read -r line; do
                [[ -z "$line" ]] && continue
                local owners
                owners=$(grep -F "${line}|" <<<"$pairs" | cut -d'|' -f2 | paste -sd', ')
                err "${field} '${line}' is claimed by more than one peer: ${owners}"
            done <<<"$dup"
        else
            ok "no duplicate ${field} across peers"
        fi
    done
}

# --- key material on disk --------------------------------------------------
verify_key_files() {
    local conf="$1" iface="$2"
    local keys_dir="${WG_CONFIG_DIR}/${iface}"

    section "key material  (${keys_dir})"

    if [[ ! -d "$keys_dir" ]]; then
        warn "no key directory at ${keys_dir} (peer configs and QR codes unavailable)"
        return 0
    fi

    # Server keypair must agree with what the running config declares.
    local priv_file="${keys_dir}/server-privatekey"
    local pub_file="${keys_dir}/server-publickey"
    if [[ -f "$priv_file" ]]; then
        local conf_priv file_priv
        conf_priv=$(awk '
            /^[[:space:]]*\[/ { in_i = ($0 ~ /^\[Interface\]/); next }
            in_i && /^[[:space:]]*PrivateKey[[:space:]]*=/ { sub(/^[^=]*=[[:space:]]*/, ""); print; exit }
        ' "$conf")
        file_priv=$(tr -d '[:space:]' < "$priv_file")
        if [[ -n "$conf_priv" && "$conf_priv" == "$file_priv" ]]; then
            ok "server-privatekey matches [Interface] PrivateKey"
        else
            err "server-privatekey does NOT match the PrivateKey in ${conf##*/} (a rotation left them out of sync)"
        fi

        if [[ -f "$pub_file" ]]; then
            local derived
            derived=$(wg pubkey <<<"$file_priv" 2>/dev/null)
            if [[ -n "$derived" && "$derived" == "$(tr -d '[:space:]' < "$pub_file")" ]]; then
                ok "server-publickey is derived from server-privatekey"
            else
                err "server-publickey is not the public key of server-privatekey (peers are being handed a stale key)"
            fi
        else
            warn "no ${pub_file} (add-peer.sh reads it to build peer configs)"
        fi
    else
        warn "no ${priv_file}"
    fi

    check_mode "$priv_file" 600
    check_mode "$pub_file" 600

    local -a peers
    mapfile -t peers < <(peer_list "$conf")
    local name
    for name in "${peers[@]}"; do
        local peer_pub_file="${keys_dir}/${name}-publickey"
        local peer_conf="${keys_dir}/${name}.conf"

        if [[ -f "$peer_pub_file" ]]; then
            # The server config is the source of truth; a mismatch means the
            # peer is holding a key the server no longer accepts.
            local in_conf on_disk
            in_conf=$(peer_pubkey "$conf" "$name" | tr -d '[:space:]')
            on_disk=$(tr -d '[:space:]' < "$peer_pub_file")
            if [[ -n "$in_conf" && "$in_conf" != "$on_disk" ]]; then
                err "peer '${name}': ${name}-publickey disagrees with the PublicKey in ${conf##*/}"
            fi
        else
            warn "peer '${name}': no ${name}-publickey on disk"
        fi

        [[ -f "$peer_conf" ]] || warn "peer '${name}': no ${name}.conf (show-qr.sh cannot render it)"
        check_mode "$peer_conf" 600
        check_mode "${keys_dir}/${name}-privatekey" 600
    done

    # Peer configs in the key dir with no corresponding block in the server
    # config — an add that half-completed, or a peer removed by hand.
    local f base
    shopt -s nullglob
    for f in "$keys_dir"/*.conf; do
        base=$(basename "$f" .conf)
        [[ "$base" == "$iface" ]] && continue
        if ! printf '%s\n' "${peers[@]}" | grep -qxF "$base"; then
            warn "orphan ${base}.conf in ${keys_dir} with no peer block in ${conf##*/}"
        fi
    done
    shopt -u nullglob
}

# --- the manifest healthcheck.sh depends on --------------------------------
verify_manifest() {
    local iface="$1"
    local manifest; manifest=$(manifest_path "$iface")

    section "setup manifest  (${manifest})"

    if [[ ! -f "$manifest" ]]; then
        warn "no manifest — healthcheck.sh cannot verify the firewall, and reset.sh cannot cleanly undo setup. Re-run setup.sh to regenerate."
        return 0
    fi
    ok "manifest present"
    check_mode "$manifest" 600

    local backends
    backends=$(cut -d'|' -f1 "$manifest" | grep '^FW_' | sort -u | paste -sd', ')
    if [[ -n "$backends" ]]; then
        ok "firewall backend(s) recorded: ${backends}"
    else
        warn "manifest records no firewall rules (FW_*) — healthcheck's firewall check is a no-op"
    fi

    if manifest_entries "$iface" SERVICE | grep -qxF "wg-quick@${iface}"; then
        ok "service recorded: wg-quick@${iface}"
    else
        warn "manifest has no SERVICE entry for wg-quick@${iface}"
    fi
}

################################################################################
# DRIVER
################################################################################

verify_interface() {
    local iface="$1"
    local conf="${WG_CONFIG_DIR}/${iface}.conf"

    $QUIET || { echo; echo -e "${BLUE}########  ${iface}  ########${NC}"; }

    verify_server_config "$conf" "$iface" || return
    verify_marker_coverage "$conf"
    verify_peer_blocks "$conf"
    verify_key_files "$conf" "$iface"
    verify_manifest "$iface"
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -i|--interface) WG_INTERFACE="$2"; shift 2 ;;
            -a|--all)       ALL=true; shift ;;
            -s|--strict)    STRICT=true; shift ;;
            -q|--quiet)     QUIET=true; shift ;;
            -h|--help)      sed -n '3,27p' "$0" | sed 's/^# \?//'; exit 0 ;;
            *)              die "Unknown option: $1" ;;
        esac
    done
}

main() {
    parse_arguments "$@"
    check_root
    check_deps wg wg-quick

    local -a targets
    if $ALL; then
        mapfile -t targets < <(detect_servers)
        (( ${#targets[@]} > 0 )) || die "No WireGuard interfaces found"
    else
        select_server
        targets=("$WG_INTERFACE")
    fi

    local iface
    for iface in "${targets[@]}"; do
        verify_interface "$iface"
    done

    echo
    echo "=========================================="
    if (( ERRORS == 0 && WARNINGS == 0 )); then
        echo -e "${GREEN}Config matches the expected format.${NC} (${#targets[@]} interface(s) checked)"
    else
        echo -e "${ERRORS} error(s), ${WARNINGS} warning(s) across ${#targets[@]} interface(s)"
    fi
    echo "=========================================="

    (( ERRORS > 0 )) && exit 1
    $STRICT && (( WARNINGS > 0 )) && exit 1
    exit 0
}

main "$@"
