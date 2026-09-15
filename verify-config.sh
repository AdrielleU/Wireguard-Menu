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
# [Peer] block with no `# BEGIN_PEER <name>` markers, but Remove Peer,
# Toggle Peer and Rotate Keys all read peers via those markers, so such a peer connects fine while
# being invisible to — and unmanageable by — every script here. That happens
# after a hand-edit, or when restoring a config written before the marker
# format existed. Nothing else in the toolkit reports it.
#
# Site boxes are held to a different standard. A spoke, or either end of a 1:1
# site-to-site link, runs a config nobody here wrote: one bare [Peer] and no
# key directory. The marker and key checks would fail it on every
# run, so it is checked instead for what a site box needs to connect and
# heal itself: an Endpoint (or a ListenPort), PersistentKeepalive, and a
# Healthcheck-Reachability target. An interface gets the site profile when its
# conf says "# Healthcheck-Role = site" (or client), carries a
# "# Healthcheck-Reachability" line, or --site is given. "Role = server" wins
# over a reachability line.
#
# Usage: sudo ./verify-config.sh [OPTIONS]
#   -i, --interface NAME   Interface to verify (default: prompt / autodetect)
#   -a, --all              Verify every detected interface
#       --site             Check every target as a site box
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
SITE=false
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

# True if the [Interface] section of <conf> sets <key>.
iface_has_key() {
    local conf="$1" key="$2"
    awk -v k="$key" '
        /^[[:space:]]*\[/ { in_i = ($0 ~ /^\[Interface\]/); next }
        in_i && $0 ~ "^[[:space:]]*" k "[[:space:]]*=" { found = 1 }
        END { exit !found }
    ' "$conf"
}

# Which set of checks <conf> is held to: "server" or "site" (see the header).
# Keyed on the same comment lines healthcheck.sh reads, so a site box that is
# set up for the healthcheck needs nothing extra to be verified as one.
config_profile() {
    local conf="$1" role
    if $SITE; then echo site; return; fi
    role=$(awk '
        /^[[:space:]]*#[[:space:]]*Healthcheck-Role[[:space:]]*=/ {
            sub(/^[^=]*=/, ""); gsub(/[[:space:]]/, ""); print tolower($0); exit
        }' "$conf" 2>/dev/null)
    case "$role" in
        server|hub)  echo server ;;
        site|client) echo site ;;
        *)
            if grep -qE '^[[:space:]]*#[[:space:]]*Healthcheck-Reachability[[:space:]]*=' "$conf" 2>/dev/null; then
                echo site
            else
                echo server
            fi
            ;;
    esac
}

# --- the server config itself ---------------------------------------------
verify_server_config() {
    local conf="$1" iface="$2" profile="${3:-server}"

    section "${profile} config  (${conf})"

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
        if iface_has_key "$conf" "$key"; then
            ok "[Interface] has ${key}"
        else
            # A client-mode config legitimately has no ListenPort; everything
            # this toolkit calls a server does. A site box that only dials out
            # needs none, and verify_site_peers checks it can still connect.
            if [[ "$key" == "ListenPort" ]]; then
                [[ "$profile" == site ]] && continue
                warn "[Interface] has no ListenPort (fine for a client config, not for a server)"
            else
                err "[Interface] has no ${key}"
            fi
        fi
    done

    check_mode "$conf" 600
}

# --- a site box: can it connect, and can it heal itself? -------------------
# Nothing here manages a site box's peers, so markers and key files don't
# matter on one. What does: whether it can reach its upstream at all, whether
# the kernel keeps retrying when that upstream blips, and whether healthcheck.sh
# has a target that lets it notice a tunnel that is up but dead.
verify_site_peers() {
    local conf="$1"

    section "site peers"

    local listen=false
    iface_has_key "$conf" ListenPort && listen=true

    # One "level|message" line per finding, then a final "count|<n>".
    local findings
    findings=$(awk -v listen="$listen" '
        function value(  v) { v = $0; sub(/^[^=]*=[[:space:]]*/, "", v); sub(/[[:space:]]+$/, "", v); return v }
        function flush(  label) {
            label = "[Peer] #" n (ep != "" ? " (" ep ")" : "")
            if (!pk)   print "err|" label ": no PublicKey"
            if (!aips) print "err|" label ": no AllowedIPs"
            if (ep == "" && listen != "true")
                print "err|" label ": no Endpoint, and [Interface] has no ListenPort, so this box can neither dial out nor be reached"
            else if (ep == "")
                print "ok|" label ": no Endpoint; waits to be dialled on its ListenPort"
            else if (ka == "" || ka == "0" || ka == "off")
                print "warn|" label ": no PersistentKeepalive; after ~90s of failed handshakes the kernel stops retrying, so the tunnel cannot come back on its own"
            else
                print "ok|" label ": Endpoint set, PersistentKeepalive = " ka
        }
        /^[[:space:]]*\[/ {
            if (inp) flush()
            inp = ($0 ~ /^[[:space:]]*\[Peer\]/)
            if (inp) { n++; pk = 0; aips = 0; ep = ""; ka = "" }
            next
        }
        !inp { next }
        /^[[:space:]]*PublicKey[[:space:]]*=/           { pk = 1 }
        /^[[:space:]]*AllowedIPs[[:space:]]*=/          { aips = 1 }
        /^[[:space:]]*Endpoint[[:space:]]*=/            { ep = value() }
        /^[[:space:]]*PersistentKeepalive[[:space:]]*=/ { ka = value() }
        END { if (inp) flush(); print "count|" (n + 0) }
    ' "$conf")

    local level msg count=0
    while IFS='|' read -r level msg; do
        case "$level" in
            count) count="$msg" ;;
            err)   err "$msg" ;;
            warn)  warn "$msg" ;;
            ok)    ok "$msg" ;;
        esac
    done <<<"$findings"
    (( count > 0 )) || err "no [Peer] section; this box has nothing to connect to"
}

# --- marker coverage: the drift that nothing else catches ------------------
verify_marker_coverage() {
    local conf="$1"

    section "peer marker coverage"

    # grep -c already prints 0 when nothing matches (and exits 1) — a `|| echo 0`
    # here would append a second 0 and corrupt the arithmetic below.
    local raw marked
    # Paused blocks count too: their [Peer] line is only commented out.
    raw=$(strip_pause_prefixes "$conf" 2>/dev/null | grep -c '^[[:space:]]*\[Peer\]')
    marked=$(peer_list "$conf" | grep -c .)
    raw=${raw:-0}; marked=${marked:-0}

    if (( raw == marked )); then
        ok "${marked}/${raw} [Peer] blocks carry BEGIN_PEER markers"
        return 0
    fi

    err "${marked}/${raw} [Peer] blocks carry BEGIN_PEER markers — $((raw - marked)) peer(s) are invisible to Remove Peer, Toggle Peer and Rotate Keys"

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
    echo "    fix: re-add them, or wrap each block in"
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
        # Paused blocks are checked through their prefix.
        block=$(awk -v b="# BEGIN_PEER ${name}" -v e="# END_PEER ${name}" '
            $0 == b { inb = 1; next } $0 == e { exit } inb { print }
        ' "$conf" | strip_pause_prefixes)

        # Paused and live WireGuard lines in the same block: wg-quick strip keeps
        # comments, so WireGuard applies the live ones to the [Peer] above.
        local raw_block paused_lines live_lines
        raw_block=$(awk -v b="# BEGIN_PEER ${name}" -v e="# END_PEER ${name}" '
            $0 == b { inb = 1; next } $0 == e { exit } inb { print }
        ' "$conf")
        paused_lines=$(grep -c "^${PEER_PAUSE_PREFIX}" <<<"$raw_block")
        live_lines=$(grep -cE '^[[:space:]]*(\[Peer\]|[A-Za-z][A-Za-z0-9]*[[:space:]]*=)' <<<"$raw_block")
        if (( paused_lines > 0 && live_lines > 0 )); then
            err "peer '${name}': half paused — ${paused_lines} line(s) commented out with '${PEER_PAUSE_PREFIX}', ${live_lines} still live; WireGuard would apply the live one(s) to the peer above it"
        elif (( paused_lines > 0 )); then
            ok "peer '${name}': paused"
        fi

        local problems=()
        grep -qE '^[[:space:]]*PublicKey[[:space:]]*=' <<<"$block"  || problems+=("no PublicKey")
        grep -qE '^[[:space:]]*AllowedIPs[[:space:]]*=' <<<"$block" || problems+=("no AllowedIPs")

        if (( ${#problems[@]} > 0 )); then
            err "peer '${name}': $(IFS=', '; echo "${problems[*]}")"
            continue
        fi

        # Type metadata records what the peer is; missing it loses that note
        # but breaks nothing, so: warning.
        if ! grep -qE '^#[[:space:]]*(Client|Site|Peer-to-Peer):' <<<"$block"; then
            warn "peer '${name}': no '# Client:/# Site:/# Peer-to-Peer:' type line (nothing records what this peer is)"
        fi

        peer_validate_name "$name" 2>/dev/null \
            || warn "peer '${name}': name would be rejected by the peer-name rules today"
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
            # A paused peer still owns its key and IPs.
            vals=$(strip_pause_prefixes "$conf" | awk -v b="# BEGIN_PEER ${name}" -v e="# END_PEER ${name}" -v k="$field" '
                $0 == b { inb = 1; next } $0 == e { inb = 0; next }
                inb && $0 ~ "^[[:space:]]*" k "[[:space:]]*=" {
                    sub(/^[^=]*=[[:space:]]*/, "")
                    n = split($0, a, ",")
                    for (i = 1; i <= n; i++) { gsub(/^[[:space:]]+|[[:space:]]+$/, "", a[i]); print a[i] }
                }
            ')
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
            warn "no ${pub_file} (the server public key that peers put in their config)"
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

# --- the comments healthcheck.sh acts on ------------------------------------
# Two inert "#" lines in [Interface] decide what healthcheck.sh does with this
# box, and nothing else reports on them:
#   # Healthcheck-Role = server        never auto-restart this tunnel
#   # Healthcheck-Reachability = <ip>  ping this through the tunnel, and restart
#                                      when it stops answering (site/client box)
verify_healthcheck() {
    local conf="$1" profile="$2"

    section "healthcheck comments"

    local role targets
    role=$(awk '
        /^[[:space:]]*#[[:space:]]*Healthcheck-Role[[:space:]]*=/ {
            sub(/^[^=]*=/, ""); gsub(/[[:space:]]/, ""); print tolower($0); exit
        }' "$conf")
    targets=$(awk '
        /^[[:space:]]*#[[:space:]]*Healthcheck-Reachability[[:space:]]*=/ {
            sub(/^[^=]*=[[:space:]]*/, ""); sub(/[[:space:]]+$/, ""); if ($0 != "") print
        }' "$conf")

    # Neither line: nothing says what this box is, and healthcheck.sh falls back
    # to treating it as a client — so --restart would bounce a server.
    if [[ -z "$role" && -z "$targets" ]]; then
        err "nothing declares what this box is: add '# Healthcheck-Role = server' to [Interface] on a server (never auto-restarted), or '# Healthcheck-Role = client' plus '# Healthcheck-Reachability = <upstream tunnel IP>' on a client or site box"
        return 0
    fi

    if [[ "$profile" == server ]]; then
        case "$role" in
            server|hub) ok "Healthcheck-Role = ${role}: healthcheck.sh never restarts this tunnel" ;;
            "")         err "no '# Healthcheck-Role = server' line in [Interface]: healthcheck.sh --restart would bounce this server on a structural failure, dropping every connected peer" ;;
            *)          err "'# Healthcheck-Role = ${role}' is not a value healthcheck.sh knows: use server (or hub) here, or client/site with a Healthcheck-Reachability target" ;;
        esac
        if [[ -n "$targets" ]]; then
            warn "Healthcheck-Reachability is set, but a server never restarts on reachability, so the line does nothing"
        fi
        return 0
    fi

    case "$role" in
        "")          ;;
        client|site) ok "Healthcheck-Role = ${role}" ;;
        *)           err "'# Healthcheck-Role = ${role}' is not a value healthcheck.sh knows: use client or site here, or server on a server" ;;
    esac
    if [[ -z "$targets" ]]; then
        warn "no '# Healthcheck-Reachability = <upstream tunnel IP>' line: define one and healthcheck.sh can see a tunnel that is up but passing no traffic; without it only a dead service or a missing address is caught"
        return 0
    fi

    # Every target must be something healthcheck.sh can ping, and pinging our own
    # address proves nothing about the tunnel.
    local own t bad=0
    own=$(awk '
        /^[[:space:]]*\[/ { in_i = ($0 ~ /^\[Interface\]/); next }
        in_i && /^[[:space:]]*Address[[:space:]]*=/ {
            sub(/^[^=]*=[[:space:]]*/, ""); n = split($0, a, ",")
            for (i = 1; i <= n; i++) { gsub(/[[:space:]]/, "", a[i]); sub(/\/.*/, "", a[i]); print a[i] }
        }' "$conf")
    for t in ${targets//,/ }; do
        if ! looks_like_host "$t"; then
            err "Healthcheck-Reachability target '${t}' is not a valid IP or hostname; healthcheck.sh ignores it"
            bad=1
        elif grep -qxF "$t" <<<"$own"; then
            warn "Healthcheck-Reachability target '${t}' is this box's own address, so pinging it never tests the tunnel"
            bad=1
        fi
    done
    if (( ! bad )); then
        ok "Healthcheck-Reachability: $(paste -sd' ' <<<"$targets") — pinged through the tunnel"
    fi
}

################################################################################
# DRIVER
################################################################################

verify_interface() {
    local iface="$1"
    local conf="${WG_CONFIG_DIR}/${iface}.conf"
    local profile; profile=$(config_profile "$conf")

    if ! $QUIET; then
        echo
        if [[ "$profile" == site ]]; then
            echo -e "${BLUE}########  ${iface}  (site box)  ########${NC}"
        else
            echo -e "${BLUE}########  ${iface}  ########${NC}"
        fi
    fi

    verify_server_config "$conf" "$iface" "$profile" || return

    if [[ "$profile" == site ]]; then
        verify_site_peers "$conf"
        verify_healthcheck "$conf" site
        return
    fi

    verify_marker_coverage "$conf"
    verify_peer_blocks "$conf"
    verify_key_files "$conf" "$iface"
    verify_healthcheck "$conf" server
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -i|--interface) WG_INTERFACE="$2"; shift 2 ;;
            -a|--all)       ALL=true; shift ;;
            --site)         SITE=true; shift ;;
            -s|--strict)    STRICT=true; shift ;;
            -q|--quiet)     QUIET=true; shift ;;
            -h|--help)      sed -n '3,37p' "$0" | sed 's/^# \?//'; exit 0 ;;
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
