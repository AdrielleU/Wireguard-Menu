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
# Query:
#   journalctl -t wireguard-connections -f                     # follow live
#   journalctl -t wireguard-connections --since "1 week ago"   # recent
#   journalctl -t wireguard-connections | grep peer=alice      # one peer
#
# Options:
#   -i <iface>   log only this interface (default: all detected interfaces)
#
# Retention (HIPAA): edit /etc/systemd/journald.conf, then
# `systemctl restart systemd-journald`:
#   SystemMaxUse=2G
#   MaxRetentionSec=6year
################################################################################

set -uo pipefail   # not -e — keep going if one interface dump fails

source "$(dirname "$0")/utils.sh"

# STATE_DIR / ACTIVE_WITHIN are env-overridable so the integration test
# (test-monitoring.sh) can drive this script against an isolated state dir
# with a short activity window, without disturbing the production logger.
STATE_DIR="${WIREGUARD_CONN_STATE_DIR:-/var/lib/wireguard-connections}"
TAG="wireguard-connections"
ACTIVE_WITHIN="${WIREGUARD_CONN_ACTIVE_WITHIN:-180}"   # secs since last handshake = connected

WG_INTERFACE=""   # -i limits logging to one interface (default: all detected)
while [[ $# -gt 0 ]]; do
    case "$1" in
        -i|--interface) WG_INTERFACE="$2"; shift 2 ;;
        -h|--help)      sed -n '3,20p' "$0" | sed 's/^# \?//'; exit 0 ;;
        *)              die "Unknown option: $1" ;;
    esac
done

check_root
mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"

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

if [[ -n "$WG_INTERFACE" ]]; then
    interfaces=("$WG_INTERFACE")
else
    mapfile -t interfaces < <(detect_servers)
fi

for iface in "${interfaces[@]}"; do
    [[ -z "$iface" ]] && continue
    state_file="${STATE_DIR}/${iface}.state"
    touch "$state_file"

    # State lines are "<pubkey>\t<status>|<endpoint>|<allowed_ips>". The
    # separator must be a tab, not '=': base64 public keys end in '=' padding,
    # so an '='-split would truncate the key and the diff would never match.
    declare -A previous=()
    while IFS=$'\t' read -r pk val; do
        [[ -n "$pk" ]] && previous[$pk]="$val"
    done < "$state_file"

    declare -A current=()
    if dump=$(wg show "$iface" dump 2>/dev/null); then
        now=$(date +%s)
        while IFS=$'\t' read -r pubkey _ endpoint allowed_ips handshake _; do
            [[ -z "$pubkey" ]] && continue
            # Strip any whitespace inside allowed_ips (it's comma-separated)
            allowed_ips="${allowed_ips// /}"
            # `handshake` is the absolute unix time of the last handshake (0 if
            # never), so a peer counts as connected when that was within the
            # last ACTIVE_WITHIN seconds — not when the timestamp itself is < it.
            if [[ "$handshake" != "0" ]] && (( now - handshake < ACTIVE_WITHIN )); then
                current[$pubkey]="connected|${endpoint:-none}|${allowed_ips:-none}"
            else
                current[$pubkey]="idle|${endpoint:-none}|${allowed_ips:-none}"
            fi
        done < <(echo "$dump" | tail -n +2)
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
        logger -t "$TAG" -p authpriv.notice \
            "$event peer=$name iface=$iface endpoint=$endpoint allowed_ips=$allowed_ips pubkey=$pk"
    done

    : > "$state_file"
    for pk in "${!current[@]}"; do
        printf '%s\t%s\n' "$pk" "${current[$pk]}" >> "$state_file"
    done

    unset current previous
done
