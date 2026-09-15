#!/bin/bash
################################################################################
# WireGuard Health Check
# Description: One-shot health check for one or all WireGuard interfaces.
#              Designed to be run from cron or a systemd timer.
#
# Health checks (all must pass):
#   1. wg-quick@<iface> service is active
#   2. the kernel interface exists
#   3. every Address declared in <iface>.conf is actually assigned to the
#      kernel interface — catches the wg-quick race where the service comes
#      up "successfully" but the IP never makes it onto the interface
# Peer reachability is reported informationally only — peers may legitimately
# be offline, so they don't trigger restarts.
#
# Upstream reachability (optional, per-interface): a site/client box can opt in
# by adding a "# Healthcheck-Reachability = <target>" comment to the [Interface]
# section of its <iface>.conf (or passing --ping-target for a manual run). The
# target may be one or more IPs and/or hostnames (comma/space separated, or on
# several lines); the tunnel is alive if ANY of them answers. When set, the
# interface is pinged through the tunnel once it is confirmed healthy. The main server's conf has no such line, so a many-peer server is never
# restarted on an unreachable host.
#
# Server protection (strict): mark the main VPN server's conf with
#     # Healthcheck-Role = server
# in its [Interface] section. A server is monitored and alerted on but its tunnel
# is NEVER auto-restarted — not on a structural failure, not on reachability, not
# even with --restart — because bouncing it would drop every connected peer, and
# a false positive must never do that.
# Client/site boxes omit the line (or set "= client") to keep normal --restart
# behavior. When a server is unhealthy the run logs HEALTHCHECK_NORESTART and
# exits non-zero so you're alerted; restart it by hand once you've confirmed it's
# real. ("= hub" is still accepted as a synonym for "= server".)
#
# A failed ping is corroborated before any restart, so we don't churn the tunnel
# on a blip or on a restart that can't help. Recovery is a two-tier ladder keyed
# on handshake age, because the cheap rung and the destructive rung have very
# different false-positive costs:
#
#   < 120s  HANDS OFF. WireGuard retries a handshake every 5s for ~90s of its
#           own accord (MAX_TIMER_HANDSHAKES), and with PersistentKeepalive it
#           keeps retrying every 25s after that. Never pre-empt it.
#
#   120s+   TIER 1, non-disruptive: re-resolve peer Endpoints (`wg set`). This
#           fixes the one failure WireGuard provably CANNOT fix itself — the
#           kernel caches the address wg-quick resolved at start time and never
#           re-resolves it, so a server that moved retries forever in vain.
#           Safe this early because `wg set ... endpoint` never touches the
#           crypto session and drops nobody: a false positive costs nothing.
#
#   180s+   TIER 2, disruptive: full `wg-quick` restart, only if tier 1 didn't
#           recover it. 180s is REJECT_AFTER_TIME — the moment WireGuard itself
#           declares the session key dead. We wait for WireGuard's own 3 minutes
#           and not a second longer. It is also the floor: handshake ages up to
#           ~165s are NORMAL on a healthy responder session, so restarting below
#           180s would drop live peers on a false positive. Rate-limited to one
#           restart per RESTART_COOLDOWN_SECS (15 min) per interface so a failure
#           a restart can't fix never becomes a restart storm.
#
#   * WAN gate — before either tier we ping OFF the tunnel to ask "is the
#     internet even up?": the server's public endpoint (host-routed via the
#     physical uplink) plus public resolvers (1.1.1.1, 8.8.8.8) since many
#     servers drop ICMP on their public IP. WAN is up if ANY answers. If the
#     internet itself is unreachable, no local action can help, so we LOG and
#     HOLD (never restart-loop) and recover on our own when it returns.
#     Override the anchor list with a "# Healthcheck-WAN = <host>,..." comment.
#   * The streak (PING_FAIL_THRESHOLD, persisted between runs) gates tier 2 on
#     consecutive confirmed-down checks. A restart that doesn't recover resets
#     the streak so we back off.
#
# Exit codes:
#   0 = all checked interfaces healthy
#   1 = one or more interfaces unhealthy (and --restart did not recover them)
#
# Usage:
#   sudo ./healthcheck.sh                     # check all wg interfaces
#   sudo ./healthcheck.sh -i wg0              # check just wg0
#   sudo ./healthcheck.sh --restart           # restart any unhealthy iface
#   sudo ./healthcheck.sh -v                  # verbose (also report healthy)
#
#   # Reachability is enabled per interface via a conf comment (see above); to
#   # try it without editing the conf, override the target for one manual run:
#   sudo ./healthcheck.sh --ping-target 10.0.0.1 --restart   # also verify the
#                                             # tunnel can reach the server IP
#   sudo ./healthcheck.sh --ping-target 10.0.0.1 --fail-threshold 5 --restart
#                                             # restart only after 5 consecutive
#                                             # unreachable checks (ride out gaps)
#
# Cron example (every minute, auto-recover, quiet on success):
#   * * * * * /etc/wireguard/scripts/healthcheck.sh --restart
#
# systemd timer: pair this with a oneshot service that runs the script. Probe
# every 60s (OnUnitActiveSec=60s, see systemd/*.timer). The probe is read-only
# and costs ~80ms, so polling frequency is decoupled from safety: the 120s/180s
# gates above are what keep us out of WireGuard's way, not the timer interval.
# A slower timer buys no safety, it only widens the outage — at 5min a tick
# landing just under a gate waits a full extra period (restart at up to ~8.8min
# instead of 3-4min).
#
# NOTE: PersistentKeepalive is load-bearing for self-healing. Without it the
# kernel purges staged packets and stops retrying entirely after ~90s, so the
# tunnel stays dead until userspace acts. Peer configs should set 25s.
################################################################################

set -uo pipefail   # not -e — we want the script to keep going across interfaces

source "$(dirname "$0")/utils.sh"

WG_INTERFACE=""
DO_RESTART=false
VERBOSE=false
STALE_HANDSHAKE_SECS=300   # report a peer as "stale" if no handshake in this long

# Optional upstream reachability check — OFF unless explicitly enabled on a
# per-interface basis. To enable it on a site/client box, add this comment line
# to the [Interface] section of that box's /etc/wireguard/<iface>.conf:
#
#     # Healthcheck-Reachability = 10.0.0.1   (the upstream server's in-tunnel IP)
#
# You can list several targets (IPs and/or hostnames), comma- or space-separated
# on one line, or as multiple such comment lines:
#
#     # Healthcheck-Reachability = 10.0.0.1, vpn.example.com, 10.0.0.2
#
# The tunnel counts as alive if ANY listed target answers, so one offline
# upstream host won't trigger a restart. This script pings the target(s) through
# the tunnel and restarts wg-quick only when none are reachable. The main server's
# conf carries no such line, so the server is never pinged or restarted on
# reachability — there's no single upstream to ping and one offline host must
# not bounce the tunnel for every peer.
PING_TARGET=""             # set only by --ping-target, for one-off manual runs
PING_COUNT=3               # echo requests per check (success = any one replies)
PING_TIMEOUT=2             # seconds to wait per request

# Public anchors for the off-tunnel "is the internet up?" (WAN) check, in
# addition to the peer's own Endpoint. The endpoint answers the precise "can I
# reach the server?" question but many servers drop ICMP on their public IP, so
# we also try these globally-pingable resolvers: if any answers, the internet is
# up even when the server won't reply to ping. Overridable per interface with a
# "# Healthcheck-WAN = ..." conf comment (which then replaces this default list).
WAN_PUBLIC_ANCHORS="1.1.1.1 8.8.8.8"

# ---------------------------------------------------------------------------
# Timing gates, derived from the kernel's own WireGuard constants
# (drivers/net/wireguard/{messages.h,timers.c,send.c,receive.c}):
#
#   REKEY_TIMEOUT        = 5s    retransmit interval for a handshake initiation
#   MAX_TIMER_HANDSHAKES = 90/5  = 18 retries, i.e. WireGuard stops retrying
#                                aggressively after ~90s and logs "giving up"
#   REKEY_AFTER_TIME     = 120s  initiator renews the session at this age
#   REJECT_AFTER_TIME    = 180s  session key is hard-dead at this age
#
# Two facts drive the two gates below, and both are easy to get wrong:
#
#  1. WireGuard's aggressive self-healing ends at 90s, NOT 180s. After
#     MAX_TIMER_HANDSHAKES the kernel purges staged packets and gives up. It
#     only keeps trying at all because PersistentKeepalive re-triggers a
#     handshake every 25s (timers.c -> send.c:out_nokey). A peer conf WITHOUT
#     PersistentKeepalive goes permanently dead after ~90s until userspace acts.
#
#  2. Handshake age from 0 to ~165s is NORMAL on a healthy tunnel. Both rekey
#     triggers are gated on `keypair->i_am_the_initiator` (send.c:133,
#     receive.c:231) — a RESPONDER never renews the session itself, it waits for
#     the initiator, which holds off until REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT
#     - REKEY_TIMEOUT = 165s. So a perfectly healthy responder session routinely
#     sits at 130-170s of handshake age.
#
# => Any DISRUPTIVE action must stay at or above 180s or it will fire on healthy
#    tunnels. Non-disruptive action may safely happen earlier.
# Kept as a named constant, not used in code: the SOFT_RECOVERY_SECS reasoning
# below is stated in terms of it, and it belongs beside its sibling.
# shellcheck disable=SC2034
WG_REKEY_ATTEMPT_SECS=90    # WireGuard gives up its own fast retry here
WG_REJECT_AFTER_SECS=180    # session key hard-dead here

# --- Tier 1: non-disruptive recovery ---------------------------------------
# Once the handshake is older than this we re-resolve peer endpoints, and do
# NOTHING else. 120s is deliberately just past WireGuard's own 90s give-up: we
# let the protocol finish its retry ladder untouched, then fix the one failure
# it provably CANNOT fix on its own — a changed Endpoint IP/DNS. The kernel
# caches the address wg-quick resolved at start time and never re-resolves it
# (timers.c only clears the *source* addr via wg_socket_clear_peer_endpoint_src),
# so a moved server retries forever and never connects.
#
# Safe to run this early even though 120s is inside the normal rekey band,
# because `wg set <iface> peer <pub> endpoint <ep>` does not touch the crypto
# session, does not drop any peer, and is a no-op when the address is unchanged.
# A false positive here costs nothing.
SOFT_RECOVERY_SECS="${SOFT_RECOVERY_SECS:-120}"

# --- Tier 2: disruptive restart --------------------------------------------
# Buffer added on top of the hard-dead time before we bounce the interface.
# Set to 0: we act at exactly WG_REJECT_AFTER_SECS (180s / 3 min), the point at
# which WireGuard itself declares the session key dead and starts dropping data
# packets encrypted with it. Waiting for WireGuard's own 3 minutes and no longer
# is the deliberate policy here.
#
# This is the tightest defensible value. The margin over a healthy tunnel is the
# 15s between the initiator's last-minute rekey (165s, receive.c:231) and 180s,
# so a rekey still in flight at 180s — e.g. one retransmitting through packet
# loss — can in principle be caught mid-recovery. Three things keep that from
# being harmful: the tier-1 re-resolve has already run and failed, the WAN gate
# has confirmed the internet is up, and RESTART_COOLDOWN_SECS caps the blast
# radius of any false positive at one restart per 15 min instead of one per tick.
#
# Do NOT lower this further. Below 180s you are inside the band where a healthy
# RESPONDER session legitimately sits (see fact (2) above) and restarts stop
# being corroborated by anything.
RESTART_BUFFER_SECS=0

# A failed ping only counts as "tunnel down" once the newest handshake is older
# than this. Younger ⇒ the crypto session is alive and a failed ping just means
# the *target* is down (don't restart). This gate is itself the anti-flap
# smoothing, so a large consecutive-failure streak on top would only push
# recovery past 3 min.
HANDSHAKE_DEAD_SECS="${HANDSHAKE_DEAD_SECS:-$(( WG_REJECT_AFTER_SECS + RESTART_BUFFER_SECS ))}"   # 180s / 3 min

# Minimum seconds between two disruptive restarts of the same interface. Without
# this, a failure that a restart cannot fix restarts the interface on EVERY tick
# (the post-restart streak reset re-arms immediately at PING_FAIL_THRESHOLD=1),
# which on a 60s timer is a restart storm that drops peers every minute. The
# cooldown makes the destructive step "once, and only if sure" while still
# retrying occasionally so the box self-heals when the real cause clears.
RESTART_COOLDOWN_SECS="${RESTART_COOLDOWN_SECS:-900}"   # 15 min

# Consecutive confirmed-down checks required before a restart. Kept at 1 because
# the 180s handshake gate above already guarantees a sustained, corroborated
# failure (ping fail AND WAN up AND 3 min of dead session); requiring more ticks
# would only delay recovery past the intended 3-minute mark. Raise via
# --fail-threshold if you want an even more conservative box.
PING_FAIL_THRESHOLD=1

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -i|--interface)   WG_INTERFACE="$2"; shift 2 ;;
            -r|--restart)     DO_RESTART=true; shift ;;
            -p|--ping-target) PING_TARGET="$2"; shift 2 ;;
            --fail-threshold) PING_FAIL_THRESHOLD="$2"; shift 2 ;;
            -v|--verbose)     VERBOSE=true; shift ;;
            -h|--help)
                sed -n '3,102p' "$0" | sed 's/^# \?//'
                exit 0
                ;;
            *) die "Unknown option: $1" ;;
        esac
    done
}

# Echoes "ok" or a short failure reason for one interface.
# Health = service active AND kernel interface exists AND every Address
# declared in <iface>.conf is actually assigned to the kernel interface.
# That last check catches the case where wg-quick reports success but the
# IP didn't make it onto the interface — restart usually fixes it.
check_interface() {
    local iface="$1"

    if ! systemctl is-active --quiet "wg-quick@${iface}"; then
        echo "service-inactive"; return
    fi
    if ! ip link show "$iface" &>/dev/null; then
        echo "interface-missing"; return
    fi

    local conf="${WG_CONFIG_DIR}/${iface}.conf"
    if [[ -f "$conf" ]]; then
        local assigned
        assigned=$(ip -o addr show dev "$iface" 2>/dev/null \
                   | awk '{print $4}')   # both v4 and v6
        local addr
        while read -r addr; do
            [[ -z "$addr" ]] && continue
            if ! grep -Fxq "$addr" <<<"$assigned"; then
                echo "address-missing:${addr}"
                return
            fi
        done < <(awk -F'=' '
            /^[[:space:]]*\[/ { in_iface = ($0 ~ /^\[Interface\]/); next }
            in_iface && /^[[:space:]]*Address[[:space:]]*=/ {
                gsub(/[[:space:]]/, "", $2)
                n = split($2, a, ",")
                for (i=1;i<=n;i++) print a[i]
            }
        ' "$conf")
    fi

    echo "ok"
}


# Per-interface consecutive-reachability-failure counter, persisted beside the
# interface's config so it survives between timer runs. A single integer.
reach_state_file() { echo "${WG_CONFIG_DIR}/.healthcheck-${1}.reachfail"; }

reach_fail_count() {
    local n; n=$(cat "$(reach_state_file "$1")" 2>/dev/null)
    [[ "$n" =~ ^[0-9]+$ ]] && echo "$n" || echo 0
}

reach_fail_set() {
    local f; f=$(reach_state_file "$1")
    mkdir -p "$(dirname "$f")"
    if echo "$2" > "$f" 2>/dev/null; then chmod 600 "$f" 2>/dev/null || true; fi
}

# Timestamp of the last DISRUPTIVE restart of this interface, persisted the same
# way. Used to rate-limit restarts to one per RESTART_COOLDOWN_SECS so a failure
# a restart cannot fix doesn't bounce the tunnel on every tick.
restart_state_file() { echo "${WG_CONFIG_DIR}/.healthcheck-${1}.lastrestart"; }

restart_last_ts() {
    local n; n=$(cat "$(restart_state_file "$1")" 2>/dev/null)
    [[ "$n" =~ ^[0-9]+$ ]] && echo "$n" || echo 0
}

restart_mark() {
    local f; f=$(restart_state_file "$1")
    mkdir -p "$(dirname "$f")"
    if date +%s > "$f" 2>/dev/null; then chmod 600 "$f" 2>/dev/null || true; fi
}

# Seconds remaining before this interface may be restarted again (0 = allowed).
restart_cooldown_left() {
    local last; last=$(restart_last_ts "$1")
    [[ "$last" -eq 0 ]] && { echo 0; return; }
    local elapsed=$(( $(date +%s) - last ))
    (( elapsed < 0 )) && { echo 0; return; }          # clock went backwards
    if (( elapsed >= RESTART_COOLDOWN_SECS )); then
        echo 0
    else
        echo $(( RESTART_COOLDOWN_SECS - elapsed ))
    fi
}

# Resolve this interface's reachability targets, one per line: the --ping-target
# override if given (manual/test runs), otherwise every "# Healthcheck-Reachability ="
# comment in its <iface>.conf. A value may list several targets separated by
# commas or spaces, and each may be an IP or a hostname. Multiple comment lines
# are all collected. Empty result = reachability disabled for this interface —
# the default, and always the case on the main server.
reach_targets() {
    local iface="$1"
    local raw
    if [[ -n "$PING_TARGET" ]]; then
        raw="$PING_TARGET"
    else
        local conf="${WG_CONFIG_DIR}/${iface}.conf"
        [[ -f "$conf" ]] || return 0
        raw=$(awk '
            /^[[:space:]]*#[[:space:]]*Healthcheck-Reachability[[:space:]]*=/ {
                sub(/^[^=]*=/, "", $0); print   # everything after the first =
            }' "$conf")
    fi
    # Split on commas and whitespace into one target per line; blanks dropped.
    local t
    for t in ${raw//,/ }; do echo "$t"; done
}


# Verify the tunnel can actually carry traffic by pinging this interface's
# reachability target(s) (the upstream server's in-tunnel IP, and/or hostnames)
# through it. Only runs when a target is configured for the interface; otherwise
# we keep the original structural-only behavior so a many-peer server never restarts
# on a dead host. The tunnel counts as alive if ANY one target answers — one
# offline upstream host shouldn't bounce a tunnel that's still carrying traffic.
# Invalid targets are warned about and ignored; if none are valid the result is
# "misconfigured" (warned but never restarted — the interface is still healthy).
# Echoes "ok", "skipped", "misconfigured", or "unreachable:<list>". Warnings go
# to stderr so they don't pollute the captured result.
check_reachability() {
    local iface="$1"
    local -a all=() valid=()
    mapfile -t all < <(reach_targets "$iface")
    [[ ${#all[@]} -eq 0 ]] && { echo "skipped"; return; }

    local t
    for t in "${all[@]}"; do
        if looks_like_host "$t"; then
            valid+=("$t")
        else
            print_warning "${iface}: ignoring invalid reachability target '${t}'" >&2
            log_audit "HEALTHCHECK_CONFIG" "interface=${iface} reason=invalid-reach-target value=${t}" >&2
        fi
    done
    [[ ${#valid[@]} -eq 0 ]] && { echo "misconfigured"; return; }
    command -v ping &>/dev/null || { echo "skipped"; return; }

    # -I "$iface" forces each probe through the tunnel; -c succeeds if any one
    # request is answered, so a single dropped packet won't restart us. First
    # target that replies is enough — the tunnel is demonstrably alive.
    for t in "${valid[@]}"; do
        if ping -c "$PING_COUNT" -W "$PING_TIMEOUT" -I "$iface" "$t" &>/dev/null; then
            echo "ok"; return
        fi
    done
    local joined; joined=$(IFS=,; echo "${valid[*]}")
    echo "unreachable:${joined}"
}

# Age in seconds of the newest handshake across all peers on the interface. A
# fresh handshake anywhere means the crypto session is alive, so we take the
# minimum age. Echoes the age, or a large sentinel if no peer has ever
# handshaked (tunnel effectively dead). Used to corroborate a failed ping so we
# don't restart a tunnel that's actually up (the target just happens to be down).
tunnel_handshake_age() {
    local iface="$1" now ts age min=999999
    command -v wg &>/dev/null || { echo 999999; return; }
    now=$(date +%s)
    while read -r _ ts; do
        [[ "$ts" =~ ^[0-9]+$ ]] || continue
        (( ts == 0 )) && continue
        age=$(( now - ts ))
        (( age < min )) && min=$age
    done < <(wg show "$iface" latest-handshakes 2>/dev/null)
    echo "$min"
}

# The off-tunnel "is the internet even up?" anchors for an interface, one per
# line. If a "# Healthcheck-WAN = ..." override is present in the conf we use
# exactly those (comma/space separated). Otherwise we use the peer Endpoint host
# (the server's public address; wg-quick host-routes it via the physical uplink,
# so pinging it does NOT traverse the tunnel) PLUS the public resolvers — the
# endpoint gives the precise "can I reach the server?" signal, the resolvers
# cover the common case where the server drops ICMP on its public IP. WAN counts
# as up if ANY of them answers.
wan_anchors() {
    local iface="$1"
    local conf="${WG_CONFIG_DIR}/${iface}.conf" override="" ep="" t a
    [[ -f "$conf" ]] && override=$(awk '
        /^[[:space:]]*#[[:space:]]*Healthcheck-WAN[[:space:]]*=/ {
            sub(/^[^=]*=/, "", $0); print }' "$conf")
    if [[ -n "$override" ]]; then
        for t in ${override//,/ }; do echo "$t"; done
        return
    fi
    if [[ -f "$conf" ]]; then
        ep=$(awk -F'=' '
            /^[[:space:]]*Endpoint[[:space:]]*=/ { gsub(/[[:space:]]/,"",$2); print $2; exit }' "$conf")
        ep="${ep%:*}"                       # strip trailing :port
        ep="${ep#[}"; ep="${ep%]}"          # strip IPv6 [brackets]
        [[ -n "$ep" ]] && echo "$ep"
    fi
    for a in $WAN_PUBLIC_ANCHORS; do echo "$a"; done
}

# The physical uplink interface (not a wg tunnel), from the default route that
# doesn't go via a wg* device. Lets us ping WAN anchors OFF the tunnel even in a
# full-tunnel (AllowedIPs=0.0.0.0/0) config. Echoes the iface name, or "".
phys_uplink() {
    ip route show default 2>/dev/null | awk '
        { dev=""; for (i=1;i<=NF;i++) if ($i=="dev") dev=$(i+1) }
        dev != "" && dev !~ /^wg/ { print dev; exit }'
}

# Off-tunnel internet status for an interface. Echoes "up:<host>" (the first
# anchor that answered), "down:<list>", or "unknown" (no anchors / no ping). A
# "down" result means restarting wg-quick cannot help — the problem is upstream
# of the tunnel — so the caller logs and holds instead of looping restarts.
# Each anchor is tried bound to the physical uplink (correct for a full-tunnel
# box) and, if that fails, unbound (correct for split-tunnel); we only run this
# when the tunnel is already dead, so an unbound probe can't succeed through it.
wan_status() {
    local iface="$1"
    local -a anchors=(); mapfile -t anchors < <(wan_anchors "$iface")
    [[ ${#anchors[@]} -eq 0 ]] && { echo "unknown"; return; }
    command -v ping &>/dev/null || { echo "unknown"; return; }
    local phys; phys=$(phys_uplink)
    local a
    for a in "${anchors[@]}"; do
        if [[ -n "$phys" ]] && ping -I "$phys" -c 1 -W "$PING_TIMEOUT" "$a" &>/dev/null; then
            echo "up:${a}"; return
        fi
        if ping -c 1 -W "$PING_TIMEOUT" "$a" &>/dev/null; then
            echo "up:${a}"; return
        fi
    done
    local joined; joined=$(IFS=,; echo "${anchors[*]}")
    echo "down:${joined}"
}

# Recovery step short of a full restart: re-resolve every peer Endpoint and push
# it back into the running interface with `wg set`. This fixes the common
# "server's DNS/IP changed but WireGuard cached the old address" case with no
# route flap and without dropping other peers. Returns 0 if it re-set at least
# one endpoint, 1 otherwise.
reresolve_endpoints() {
    local iface="$1"
    local conf="${WG_CONFIG_DIR}/${iface}.conf" did=1 line pub="" ep=""
    [[ -f "$conf" ]] || return 1
    command -v wg &>/dev/null || return 1
    while IFS= read -r line; do
        if [[ "$line" =~ ^\[Peer\] ]]; then
            pub=""; ep=""
        elif [[ "$line" =~ ^[[:space:]]*PublicKey[[:space:]]*=[[:space:]]*(.+) ]]; then
            pub="${BASH_REMATCH[1]// /}"
        elif [[ "$line" =~ ^[[:space:]]*Endpoint[[:space:]]*=[[:space:]]*(.+) ]]; then
            ep="${BASH_REMATCH[1]// /}"
            if [[ -n "$pub" && -n "$ep" ]]; then
                wg set "$iface" peer "$pub" endpoint "$ep" 2>/dev/null && did=0
            fi
        fi
    done < "$conf"
    return $did
}

# Print the peer reachability summary for one interface (informational).
report_peers() {
    local iface="$1"
    command -v wg &>/dev/null || return 0
    local now total stale connected
    now=$(date +%s)
    total=0; stale=0; connected=0

    while IFS=$'\t' read -r pubkey _ _ _ handshake _ _ _; do
        [[ -z "$pubkey" ]] && continue
        ((total++)) || true
        if [[ -z "$handshake" || "$handshake" == 0 ]]; then
            ((stale++)) || true
        elif (( now - handshake > STALE_HANDSHAKE_SECS )); then
            ((stale++)) || true
        else
            ((connected++)) || true
        fi
    done < <(wg show "$iface" dump 2>/dev/null | tail -n +2)

    if (( total == 0 )); then
        echo "  peers: 0 configured"
    else
        echo "  peers: ${connected}/${total} connected (handshake within ${STALE_HANDSHAKE_SECS}s), ${stale} stale"
    fi
}

# An interface's role, from a "# Healthcheck-Role = <role>" comment in its conf.
#   server -> the main VPN server that many peers dial into. NEVER restart its
#             tunnel: a false positive here would drop every connected peer, and
#             a server has no single upstream to test anyway. Monitor + alert only.
#             "hub" is accepted as a synonym so older confs keep working.
#   client -> (default, and any unrecognized/absent value) normal behavior:
#             restart is allowed when --restart is passed.
# This is the strict, explicit opt-out — independent of the --restart flag and
# of whether a Healthcheck-Reachability line exists.
iface_role() {
    local iface="$1"
    local conf="${WG_CONFIG_DIR}/${iface}.conf" role=""
    [[ -f "$conf" ]] || { echo "client"; return; }
    role=$(awk '
        /^[[:space:]]*#[[:space:]]*Healthcheck-Role[[:space:]]*=/ {
            sub(/^[^=]*=/, "", $0); gsub(/[[:space:]]/,"",$0); print tolower($0); exit }' "$conf")
    case "$role" in
        server|hub) echo "server" ;;
        *)          echo "client" ;;
    esac
}

# Check + optionally restart one interface. Returns 0 healthy, 1 unhealthy.
process_interface() {
    local iface="$1"

    # Is a *tunnel* restart permitted on this interface? Requires --restart AND a
    # non-server role. A server is monitored and alerted on but its tunnel is never
    # bounced (dropping all peers).
    local may_restart=false
    local role; role=$(iface_role "$iface")
    if $DO_RESTART && [[ "$role" != "server" ]]; then may_restart=true; fi

    local result; result=$(check_interface "$iface")

    if [[ "$result" != "ok" ]]; then
        print_warning "${iface}: ${result}"
        log_audit "HEALTHCHECK_FAIL" "interface=${iface} reason=${result}"

        if [[ "$role" == "server" ]] && $DO_RESTART; then
            # Server: alert but never bounce the tunnel — a manual restart is a
            # deliberate human decision, not something a timer should do.
            print_error "${iface}: server is unhealthy (${result}) — NOT auto-restarting (Healthcheck-Role = server); restart manually if intended"
            log_audit "HEALTHCHECK_NORESTART" "interface=${iface} role=server reason=${result}"
            return 1
        elif $may_restart; then
            print_info "${iface}: restarting wg-quick@${iface} ..."
            log_audit "HEALTHCHECK_RESTART" "interface=${iface} component=interface reason=${result}"
            if systemctl restart "wg-quick@${iface}"; then
                sleep 2
                local recheck; recheck=$(check_interface "$iface")
                if [[ "$recheck" == "ok" ]]; then
                    print_success "${iface}: recovered after restart"
                    log_audit "HEALTHCHECK_RECOVERY" "interface=${iface}"
                    # fall through to the reachability check
                else
                    print_error "${iface}: still ${recheck} after restart"
                    log_audit "HEALTHCHECK_RESTART_FAILED" "interface=${iface} component=interface reason=${recheck}"
                    return 1
                fi
            else
                print_error "${iface}: systemctl restart failed"
                log_audit "HEALTHCHECK_RESTART_FAILED" "interface=${iface} component=interface reason=systemctl-restart-command-failed"
                return 1
            fi
        else
            return 1
        fi
    fi

    # The interface is healthy. If an upstream target is configured,
    # confirm the tunnel actually carries traffic. A failed ping alone is NOT
    # enough to restart: we corroborate it with the handshake age (is the crypto
    # session really dead?) and the off-tunnel WAN status (is a restart even
    # capable of helping?), and only then across PING_FAIL_THRESHOLD consecutive
    # checks.
    local reach; reach=$(check_reachability "$iface")
    if [[ "$reach" == "skipped" ]]; then
        :   # reachability not enabled for this interface — structural checks only
    elif [[ "$reach" == "ok" ]]; then
        # Good check clears any failure streak.
        [[ "$(reach_fail_count "$iface")" -ne 0 ]] && reach_fail_set "$iface" 0
    elif [[ "$reach" == "misconfigured" ]]; then
        # Reachability is opted in but every target is junk. Warn (the per-target
        # detail already went to the log) but don't restart or touch the streak —
        # the interface itself is healthy; a bad comment shouldn't take it down.
        print_warning "${iface}: reachability configured but no valid target — fix the '# Healthcheck-Reachability' comment in ${iface}.conf"
    else
        # Ping through the tunnel failed. Corroborate before treating it as a
        # tunnel failure: a fresh handshake means the tunnel is alive and it's
        # the target that's down — leave it alone.
        local hs; hs=$(tunnel_handshake_age "$iface")
        if (( hs < SOFT_RECOVERY_SECS )); then
            # Inside WireGuard's own retry window (it retries hard for ~90s and
            # keeps trying every 25s via PersistentKeepalive). Hands off.
            print_warning "${iface}: ${reach}, but handshake is ${hs}s old (< ${SOFT_RECOVERY_SECS}s) — tunnel alive, target likely down; not restarting"
            log_audit "HEALTHCHECK_TARGET_DOWN" "interface=${iface} reason=${reach} handshake_age=${hs}"
            [[ "$(reach_fail_count "$iface")" -ne 0 ]] && reach_fail_set "$iface" 0
        elif (( hs < HANDSHAKE_DEAD_SECS )); then
            # Tier 1 — past WireGuard's 90s give-up but still inside the band
            # where a healthy RESPONDER session legitimately sits (up to ~165s).
            # Only the non-disruptive rung of the ladder is allowed here: fix a
            # moved Endpoint, which WireGuard can never do for itself. No
            # restart, so a false positive in this window costs nothing.
            local wan1; wan1=$(wan_status "$iface")
            if [[ "$wan1" == down:* ]]; then
                print_warning "${iface}: ${reach}, handshake ${hs}s, but internet unreachable off-tunnel (${wan1#down:}) — holding"
                log_audit "HEALTHCHECK_WAN_DOWN" "interface=${iface} reason=${reach} handshake_age=${hs} anchor=${wan1#down:} tier=soft"
                return 1
            fi
            print_info "${iface}: ${reach}, handshake ${hs}s — re-resolving peer endpoint(s) (non-disruptive; no restart before ${HANDSHAKE_DEAD_SECS}s) ..."
            if reresolve_endpoints "$iface"; then
                sleep 2
                local rr1; rr1=$(check_reachability "$iface")
                if [[ "$rr1" == "ok" ]]; then
                    reach_fail_set "$iface" 0
                    print_success "${iface}: recovered by re-resolving endpoint (no restart)"
                    log_audit "HEALTHCHECK_RECOVERY" "interface=${iface} component=reachability method=reresolve tier=soft handshake_age=${hs}"
                    return 0
                fi
            fi
            print_warning "${iface}: re-resolve did not recover it — waiting for the ${HANDSHAKE_DEAD_SECS}s gate before any restart"
            log_audit "HEALTHCHECK_SOFT_RECOVERY_FAILED" "interface=${iface} reason=${reach} handshake_age=${hs}"
            return 1
        else
            # Tunnel is genuinely dead (no traffic AND no recent handshake). Can
            # a restart even help? Check the internet off-tunnel first.
            local wan; wan=$(wan_status "$iface")
            if [[ "$wan" == down:* ]]; then
                # Internet/upstream itself is unreachable off-tunnel. Restarting
                # wg-quick cannot fix that and would just loop, so we hold and
                # log. Recovery happens on its own when the internet returns.
                print_warning "${iface}: tunnel down (${reach}, handshake ${hs}s) AND internet unreachable off-tunnel (${wan#down:}) — NOT restarting; will recover when the internet returns"
                log_audit "HEALTHCHECK_WAN_DOWN" "interface=${iface} reason=${reach} handshake_age=${hs} anchor=${wan#down:}"
                return 1
            fi

            # WAN is up (or unverifiable) but the tunnel is dead → a restart can
            # plausibly help. Accumulate the consecutive-failure streak.
            local fails; fails=$(( $(reach_fail_count "$iface") + 1 ))
            reach_fail_set "$iface" "$fails"
            print_warning "${iface}: tunnel down (${reach}, handshake ${hs}s, WAN ${wan}) — ${fails}/${PING_FAIL_THRESHOLD} consecutive"
            log_audit "HEALTHCHECK_FAIL" "interface=${iface} reason=${reach} handshake_age=${hs} wan=${wan} streak=${fails}/${PING_FAIL_THRESHOLD}"

            if (( fails >= PING_FAIL_THRESHOLD )); then
                if $may_restart; then
                    # Recovery ladder: cheap endpoint re-resolve first (fixes a
                    # changed server DNS/IP with no route flap), full restart
                    # only if that doesn't bring the tunnel back.
                    print_info "${iface}: re-resolving peer endpoint(s) before restart ..."
                    reresolve_endpoints "$iface"; sleep 2
                    local rr; rr=$(check_reachability "$iface")
                    if [[ "$rr" == "ok" ]]; then
                        reach_fail_set "$iface" 0
                        print_success "${iface}: recovered by re-resolving endpoint (no restart)"
                        log_audit "HEALTHCHECK_RECOVERY" "interface=${iface} component=reachability method=reresolve"
                    else
                        # Rate-limit the destructive rung. Without this, a failure
                        # a restart can't fix bounces the tunnel on every tick.
                        local cd; cd=$(restart_cooldown_left "$iface")
                        if (( cd > 0 )); then
                            print_warning "${iface}: re-resolve didn't help, but last restart was < ${RESTART_COOLDOWN_SECS}s ago — holding ${cd}s before restarting again"
                            log_audit "HEALTHCHECK_RESTART_SUPPRESSED" "interface=${iface} component=reachability reason=${reach} handshake_age=${hs} cooldown_left=${cd}"
                            return 1
                        fi
                        print_info "${iface}: re-resolve didn't help — restarting wg-quick@${iface} ..."
                        log_audit "HEALTHCHECK_RESTART" "interface=${iface} component=reachability reason=${reach} handshake_age=${hs} wan=${wan}"
                        restart_mark "$iface"
                        if systemctl restart "wg-quick@${iface}"; then
                            sleep 3
                            local rereach; rereach=$(check_reachability "$iface")
                            if [[ "$rereach" == "ok" ]]; then
                                reach_fail_set "$iface" 0
                                print_success "${iface}: reachability recovered after restart"
                                log_audit "HEALTHCHECK_RECOVERY" "interface=${iface} component=reachability method=restart"
                            else
                                # Restart didn't help. Reset the streak so we
                                # back off and re-accumulate before the next
                                # restart instead of looping every tick.
                                reach_fail_set "$iface" 0
                                print_error "${iface}: still ${rereach} after restart"
                                log_audit "HEALTHCHECK_RESTART_FAILED" "interface=${iface} component=reachability reason=${rereach}"
                                return 1
                            fi
                        else
                            print_error "${iface}: systemctl restart failed"
                            log_audit "HEALTHCHECK_RESTART_FAILED" "interface=${iface} component=reachability reason=systemctl-restart-command-failed"
                            return 1
                        fi
                    fi
                else
                    return 1
                fi
            fi
            # Below threshold: tolerate this gap and stay healthy for now.
        fi
    fi

    if $VERBOSE; then
        print_success "${iface}: healthy"
        report_peers "$iface"
    fi
    return 0
}

main() {
    parse_arguments "$@"
    check_root
    check_systemd   # every check and restart below goes through wg-quick@<iface>

    local -a interfaces
    if [[ -n "$WG_INTERFACE" ]]; then
        interfaces=("$WG_INTERFACE")
    else
        mapfile -t interfaces < <(detect_servers)
    fi
    if [[ ${#interfaces[@]} -eq 0 ]]; then
        $VERBOSE && print_info "No WireGuard interfaces configured — nothing to check"
        exit 0
    fi

    local failures=0
    for iface in "${interfaces[@]}"; do
        process_interface "$iface" || ((failures++)) || true
    done

    exit $(( failures > 0 ? 1 : 0 ))
}

main "$@"
