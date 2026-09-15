#!/bin/bash
################################################################################
# WireGuard Connection Logger
# Description: One-shot connect/disconnect audit logger. Polls `wg show dump`,
#              diffs against a state file, and writes events to journald under
#              tag `wireguard-connections`.
#
# Designed to be run from a systemd timer (every ~2 min, matching the
# WireGuard handshake interval).
#
# Events carry indexed journald fields (see log_conn_event in utils.sh), so an
# audit is a field query rather than a grep:
#   journalctl WG_ACTION=CONNECT -o short-iso        # every connect, with year
#   journalctl WG_PEER=alice --since -30d            # one peer, last 30 days
#   journalctl WG_SESSION=<id>                       # one session, both ends
#   journalctl -t wireguard-connections -f           # follow live, human form
#
# Each connected period gets a session id shared by its CONNECT and DISCONNECT;
# the DISCONNECT also carries duration_sec. A mid-session endpoint change
# (roaming) logs a second CONNECT reusing the same session id.
#
# Options:
#   -i <iface>   log only this interface (default: all detected interfaces)
#   --dry-run    print the records it would write; log nothing, write no state
#
# Retention (HIPAA): the journal keeps ~9 months by default. For a longer
# window install the drop-in shipped with this repo:
#   sudo ./install-logging.sh --with-retention
################################################################################

set -uo pipefail   # not -e — keep going if one interface dump fails

source "$(dirname "$0")/utils.sh"

# STATE_DIR / ACTIVE_WITHIN are env-overridable so this script can be driven
# against an isolated state dir with a short activity window, without
# disturbing the production logger.
STATE_DIR="${WIREGUARD_CONN_STATE_DIR:-/var/lib/wireguard-connections}"
ACTIVE_WITHIN="${WIREGUARD_CONN_ACTIVE_WITHIN:-180}"   # secs since last handshake = connected

WG_INTERFACE=""   # -i limits logging to one interface (default: all detected)
DRY_RUN=false     # --dry-run: print what would be logged, change nothing
while [[ $# -gt 0 ]]; do
    case "$1" in
        -i|--interface) WG_INTERFACE="$2"; shift 2 ;;
        --dry-run)      DRY_RUN=true; shift ;;
        -h|--help)      sed -n '3,27p' "$0" | sed 's/^# \?//'; exit 0 ;;
        *)              die "Unknown option: $1" ;;
    esac
done

check_root
if ! $DRY_RUN; then
    mkdir -p "$STATE_DIR"
    chmod 700 "$STATE_DIR"
fi

# One connect/disconnect record: logged for real, or printed under --dry-run.
emit_event() {
    local event="$1" details="$2"
    if $DRY_RUN; then
        echo "  would log: action=${event} ${details}"
    else
        log_conn_event "$event" "$details"
    fi
}

# Map a public key to its peer name from /etc/wireguard/<iface>.conf.
# Accepts the new `# BEGIN_PEER <name>` form and the legacy `# Client/Site:` form.
peer_name() {
    local iface="$1" pubkey="$2"
    local config="${WG_CONFIG_DIR}/${iface}.conf"
    [[ -f "$config" ]] || { echo unknown; return; }
    awk -v pk="$pubkey" '
        /^# BEGIN_PEER /                              { name=$3; next }
        /^# (Client|Site|Peer-to-Peer):/              { sub(/^#[[:space:]]*(Client|Site|Peer-to-Peer):[[:space:]]*/, ""); name=$0; next }
        /^PublicKey/ {
            for (i=2; i<=NF; i++) if ($i == pk) { print (name ? name : "unknown"); exit }
        }
    ' "$config"
}

# Correlation id shared by a CONNECT and its matching DISCONNECT. The peer
# prefix keeps ids readable and collision-free across peers; the start
# timestamp makes each session of the same peer distinct. Non-alphanumerics are
# stripped so the id is safe as a journald field value and as a grep target.
session_id() {
    local pubkey="$1" started="$2" prefix
    prefix=$(printf '%s' "$pubkey" | tr -dc 'A-Za-z0-9' | cut -c1-8)
    printf '%s-%s' "${prefix:-unknown}" "$started"
}

if [[ -n "$WG_INTERFACE" ]]; then
    interfaces=("$WG_INTERFACE")
else
    mapfile -t interfaces < <(detect_servers)
fi

for iface in "${interfaces[@]}"; do
    [[ -z "$iface" ]] && continue
    state_file="${STATE_DIR}/${iface}.state"
    # A dry run reads whatever state exists, but never creates or writes it.
    if $DRY_RUN; then
        [[ -f "$state_file" ]] || state_file=/dev/null
    else
        touch "$state_file"
    fi
    now=$(date +%s)

    # State lines are:
    #   <pubkey>\t<status>|<endpoint>|<allowed_ips>\t<since>\t<session>
    # The separator must be a tab, not '=': base64 public keys end in '='
    # padding, so an '='-split would truncate the key and the diff would never
    # match. `since`/`session` were added alongside WG_SCHEMA=1; older two-field
    # lines still load, they just cannot report a duration for the session that
    # was open when the upgrade happened.
    declare -A previous=() prev_since=() prev_sess=()
    while IFS=$'\t' read -r pk val since sess; do
        [[ -n "$pk" ]] || continue
        previous[$pk]="$val"
        prev_since[$pk]="$since"
        prev_sess[$pk]="$sess"
    done < "$state_file"

    declare -A current=() cur_since=() cur_sess=()
    dump_ok=false
    if dump=$(wg show "$iface" dump 2>/dev/null); then
        dump_ok=true
        while IFS=$'\t' read -r pubkey _ endpoint allowed_ips handshake _; do
            [[ -z "$pubkey" ]] && continue
            # Strip any whitespace inside allowed_ips (it's comma-separated)
            allowed_ips="${allowed_ips// /}"
            # `handshake` is the absolute unix time of the last handshake (0 if
            # never), so a peer counts as connected when that was within the
            # last ACTIVE_WITHIN seconds — not when the timestamp itself is < it.
            if [[ "$handshake" != "0" ]] && (( now - handshake < ACTIVE_WITHIN )); then
                current[$pubkey]="connected|${endpoint:-none}|${allowed_ips:-none}"
                # Carry the session forward while the peer stays connected, so a
                # mid-session endpoint change (roaming) reports the same id
                # rather than opening a second session.
                if [[ "${previous[$pubkey]:-}" == connected\|* && -n "${prev_since[$pubkey]:-}" ]]; then
                    cur_since[$pubkey]="${prev_since[$pubkey]}"
                    cur_sess[$pubkey]="${prev_sess[$pubkey]}"
                else
                    cur_since[$pubkey]="$now"
                    cur_sess[$pubkey]="$(session_id "$pubkey" "$now")"
                fi
            else
                current[$pubkey]="idle|${endpoint:-none}|${allowed_ips:-none}"
                cur_since[$pubkey]=""
                cur_sess[$pubkey]=""
            fi
        done < <(echo "$dump" | tail -n +2)
    fi

    # A failed dump is not evidence that every peer disconnected — the
    # interface may simply be momentarily unavailable. Leave the state file
    # untouched so open sessions survive and no phantom events are logged.
    if ! $dump_ok; then
        unset current previous cur_since cur_sess prev_since prev_sess
        continue
    fi

    for pk in "${!current[@]}"; do
        new="${current[$pk]}"
        old="${previous[$pk]:-}"
        [[ "$new" == "$old" ]] && continue

        new_status="${new%%|*}"
        rest="${new#*|}"
        endpoint="${rest%%|*}"
        allowed_ips="${rest#*|}"
        old_status="${old%%|*}"

        if [[ "$new_status" == "connected" ]]; then
            event=CONNECT
        elif [[ "$old_status" == "connected" ]]; then
            event=DISCONNECT
        else
            continue
        fi

        name=$(peer_name "$iface" "$pk")
        if [[ "$event" == CONNECT ]]; then
            session="${cur_sess[$pk]}"
            duration=""
        else
            # Close against the session that was open, not a new one.
            session="${prev_sess[$pk]:-}"
            if [[ -n "${prev_since[$pk]:-}" ]]; then
                duration=$(( now - prev_since[$pk] ))
            else
                duration=""
            fi
        fi
        emit_event "$event" \
            "peer=$name interface=$iface endpoint=$endpoint allowed_ips=$allowed_ips${session:+ session=$session}${duration:+ duration_sec=$duration} pubkey=$pk"
    done

    # A peer dropped from the config disappears from the dump entirely, so the
    # loop above never sees it. Without this sweep a session that was open at
    # that moment would keep a CONNECT with no matching DISCONNECT forever.
    for pk in "${!previous[@]}"; do
        [[ -n "${current[$pk]:-}" ]] && continue
        [[ "${previous[$pk]}" == connected\|* ]] || continue

        rest="${previous[$pk]#*|}"
        endpoint="${rest%%|*}"
        allowed_ips="${rest#*|}"
        session="${prev_sess[$pk]:-}"
        if [[ -n "${prev_since[$pk]:-}" ]]; then
            duration=$(( now - prev_since[$pk] ))
        else
            duration=""
        fi
        name=$(peer_name "$iface" "$pk")
        emit_event DISCONNECT \
            "peer=$name interface=$iface endpoint=$endpoint allowed_ips=$allowed_ips${session:+ session=$session}${duration:+ duration_sec=$duration} reason=peer-removed pubkey=$pk"
    done

    if ! $DRY_RUN; then
        : > "$state_file"
        for pk in "${!current[@]}"; do
            printf '%s\t%s\t%s\t%s\n' \
                "$pk" "${current[$pk]}" "${cur_since[$pk]}" "${cur_sess[$pk]}" >> "$state_file"
        done
    fi

    unset current previous cur_since cur_sess prev_since prev_sess
done

if $DRY_RUN; then
    print_info "Dry run: nothing was logged and no state was written."
fi
