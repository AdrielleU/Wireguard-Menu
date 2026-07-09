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
#   4. the firewall backend recorded in the per-interface manifest is still
#      effective: firewalld/ufw services active, or nftables rules we wrote
#      at setup time still present in the kernel. Without this, the VPN
#      looks healthy but the UDP port is closed and peers can't connect.
#
# Peer reachability is reported informationally only — peers may legitimately
# be offline, so they don't trigger restarts.
#
# Upstream reachability (optional, per-interface): a site/client box can opt in
# by adding a "# Healthcheck-Reachability = <target>" comment to the [Interface]
# section of its <iface>.conf (or passing --ping-target for a manual run). The
# target may be one or more IPs and/or hostnames (comma/space separated, or on
# several lines); the tunnel is alive if ANY of them answers. When set, the
# interface is pinged through the tunnel after it and the firewall are confirmed
# healthy. The main hub's conf has no such line, so a many-peer server is never
# restarted on an unreachable host.
#
# Hub protection (strict): mark the main VPN server's conf with
#     # Healthcheck-Role = hub
# in its [Interface] section. A hub is monitored and alerted on but its tunnel is
# NEVER auto-restarted — not on a structural failure, not on reachability, not
# even with --restart — because bouncing it would drop every connected peer, and
# a false positive must never do that. (Non-disruptive recovery that does not
# drop peers, i.e. starting a stopped firewall service, is still performed.)
# Client/site boxes omit the line (or set "= client") to keep normal --restart
# behavior. When a hub is unhealthy the run logs HEALTHCHECK_NORESTART and exits
# non-zero so you're alerted; restart it by hand once you've confirmed it's real.
#
# A failed ping is corroborated before any restart, so we don't churn the tunnel
# on a blip or on a restart that can't help:
#   * Handshake age — if the newest WireGuard handshake is younger than
#     HANDSHAKE_DEAD_SECS (240s = WireGuard's own 180s dead time + a 60s buffer,
#     so we always act strictly later than WireGuard's own recovery), the
#     crypto session is demonstrably alive and
#     the failed ping just means the *target* is down. We leave the tunnel alone.
#   * WAN gate — when the tunnel really is dead we ping the server's public
#     endpoint OFF the tunnel (its host route goes via the physical uplink). If
#     the internet itself is unreachable, a restart cannot help, so we LOG and
#     HOLD (never restart-loop) and recover on our own when the internet returns.
#     Override the anchor with a "# Healthcheck-WAN = <host>" conf comment.
#   * Only when ping fails AND the handshake is stale AND the WAN is up, across
#     PING_FAIL_THRESHOLD *consecutive* checks (streak persisted between runs),
#     do we recover: first a cheap endpoint re-resolve (fixes a changed server
#     DNS/IP with no peer drop), then a full wg-quick restart if that's not
#     enough. A restart that doesn't recover resets the streak so we back off.
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
#   * * * * * /home/wireguard-scripts/healthcheck.sh --restart
#
# systemd timer: pair this with a oneshot service that runs the script. Probe
# every 60s (OnUnitActiveSec=60s, see systemd/*.timer); a disruptive restart
# only fires ~4 min into a real outage (WireGuard's 180s dead time + 60s buffer).
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
# the tunnel and restarts wg-quick only when none are reachable. The main hub's
# conf carries no such line, so the hub is never pinged or restarted on
# reachability — there's no single upstream to ping and one offline host must
# not bounce the tunnel for every peer.
PING_TARGET=""             # set only by --ping-target, for one-off manual runs
PING_COUNT=3               # echo requests per check (success = any one replies)
PING_TIMEOUT=2             # seconds to wait per request

# WireGuard's own dead-session time: after ~180s with no successful handshake the
# protocol itself has given up on the session (REJECT_AFTER_TIME). We never want
# to pre-empt WireGuard's own recovery — with keepalive it re-handshakes on its
# own well before this — so our disruptive restart must fire STRICTLY LATER than
# this, never sooner.
WG_REJECT_AFTER_SECS=180

# Safety buffer added on top of WireGuard's dead-session time before we step in
# with a restart. 180 + 60 = 240s (4 min): comfortably longer than WireGuard's
# own checks so we only act once it has definitively failed to self-heal, not
# while it might still recover.
RESTART_BUFFER_SECS=60

# A failed ping only counts as "tunnel down" once the newest handshake on the
# interface is older than this. Younger than this ⇒ the crypto session is alive
# and a failed ping just means the *target* is down (don't restart). This gate
# (240s of continuous dead session) is itself the anti-flap smoothing, so a
# large consecutive-failure streak on top would only push recovery past 4 min.
HANDSHAKE_DEAD_SECS=$(( WG_REJECT_AFTER_SECS + RESTART_BUFFER_SECS ))   # 240s / 4 min

# Consecutive confirmed-down checks required before a restart. Kept at 1 because
# the 240s handshake gate above already guarantees a sustained, corroborated
# failure (ping fail AND WAN up AND 4 min of dead session); requiring more ticks
# would only delay recovery past the intended 4-minute mark. Raise via
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
                sed -n '3,82p' "$0" | sed 's/^# \?//'
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

# Verify the firewall backend(s) recorded in this interface's manifest are
# still effective. For firewalld/ufw we check the service is active (a stopped
# service means no rules are loaded). For nftables the "service" concept
# doesn't apply, so we check that the specific FORWARD rule we wrote at setup
# time is still present in the running kernel — a flush or reboot without
# persistence would silently lose it.
# Returns "ok" or a short failure reason.
check_firewall() {
    local iface="$1"
    local manifest; manifest=$(manifest_path "$iface")
    [[ -f "$manifest" ]] || { echo "ok"; return; }   # no manifest -> can't check

    local backends; backends=$(awk -F'|' '/^FW_/ {print $1}' "$manifest" | sort -u)
    [[ -z "$backends" ]] && { echo "ok"; return; }

    local b
    while read -r b; do
        [[ -z "$b" ]] && continue
        case "$b" in
            FW_FIREWALLD)
                systemctl is-active --quiet firewalld 2>/dev/null \
                    || { echo "firewall-down:firewalld"; return; }
                ;;
            FW_UFW)
                if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -qi "Status: active"; then :
                elif systemctl is-active --quiet ufw 2>/dev/null; then :
                else echo "firewall-down:ufw"; return
                fi
                ;;
            FW_NFT)
                if ! command -v nft &>/dev/null \
                   || ! nft list table inet wireguard 2>/dev/null | grep -q "iifname \"${iface}\""; then
                    echo "firewall-rules-missing:nftables"; return
                fi
                ;;
        esac
    done <<< "$backends"

    echo "ok"
}

# Per-interface consecutive-reachability-failure counter, persisted next to the
# manifest so it survives between timer runs. Stored as a single integer.
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

# Resolve this interface's reachability targets, one per line: the --ping-target
# override if given (manual/test runs), otherwise every "# Healthcheck-Reachability ="
# comment in its <iface>.conf. A value may list several targets separated by
# commas or spaces, and each may be an IP or a hostname. Multiple comment lines
# are all collected. Empty result = reachability disabled for this interface —
# the default, and always the case on the main hub.
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

# True if the argument is a syntactically valid reachability target: an IPv4
# address (octets in range), a loose IPv6 address, or a DNS hostname. Guards the
# "# Healthcheck-Reachability =" comment so a typo (e.g. 10.0.0.999) is caught
# and ignored rather than silently treated as "unreachable" — which, with
# --restart, would turn a config typo into a tunnel-restart loop.
looks_like_host() {
    local h="$1"
    [[ -z "$h" ]] && return 1
    if [[ "$h" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then   # IPv4 shape
        local o; IFS=. read -ra o <<<"$h"
        local n; for n in "${o[@]}"; do (( n <= 255 )) || return 1; done
        return 0
    fi
    [[ "$h" == *:* && "$h" =~ ^[0-9a-fA-F:]+$ ]] && return 0   # IPv6 (loose)
    # Hostname: dot-separated labels of alnum/hyphen, not starting/ending in '-'.
    [[ ${#h} -le 253 && "$h" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$ ]]
}

# Verify the tunnel can actually carry traffic by pinging this interface's
# reachability target(s) (the upstream server's in-tunnel IP, and/or hostnames)
# through it. Only runs when a target is configured for the interface; otherwise
# we keep the original structural-only behavior so a many-peer hub never restarts
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

# The off-tunnel "is the internet even up?" anchor for an interface: a
# "# Healthcheck-WAN = <host>" override in the conf if present, otherwise the
# host of the first peer Endpoint (i.e. the WireGuard server's public address).
# wg-quick installs a host route for the endpoint via the *physical* uplink, so
# pinging it does NOT traverse the tunnel — which is exactly how we tell "our
# internet is down" apart from "the tunnel is down". Echoes the host, or "".
wan_anchor() {
    local iface="$1"
    local conf="${WG_CONFIG_DIR}/${iface}.conf" host=""
    [[ -f "$conf" ]] || { echo ""; return; }
    host=$(awk '
        /^[[:space:]]*#[[:space:]]*Healthcheck-WAN[[:space:]]*=/ {
            sub(/^[^=]*=/, "", $0); gsub(/[[:space:]]/,"",$0); print; exit }' "$conf")
    if [[ -z "$host" ]]; then
        host=$(awk -F'=' '
            /^[[:space:]]*Endpoint[[:space:]]*=/ { gsub(/[[:space:]]/,"",$2); print $2; exit }' "$conf")
        host="${host%:*}"                       # strip trailing :port
        host="${host#[}"; host="${host%]}"      # strip IPv6 [brackets]
    fi
    echo "$host"
}

# Off-tunnel internet status for an interface, via the WAN anchor. Echoes
# "up:<host>", "down:<host>", or "unknown" (no anchor / no ping). A "down"
# result means restarting wg-quick cannot help — the problem is upstream of the
# tunnel — so the caller logs and holds instead of looping restarts.
wan_status() {
    local iface="$1" host; host=$(wan_anchor "$iface")
    [[ -z "$host" ]] && { echo "unknown"; return; }
    command -v ping &>/dev/null || { echo "unknown"; return; }
    if ping -c "$PING_COUNT" -W "$PING_TIMEOUT" "$host" &>/dev/null; then
        echo "up:${host}"
    else
        echo "down:${host}"
    fi
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
#   hub    -> the main server that many peers dial into. NEVER restart its
#             tunnel: a false positive here would drop every connected peer, and
#             a hub has no single upstream to test anyway. Monitor + alert only.
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
    [[ "$role" == "hub" ]] && echo "hub" || echo "client"
}

# Check + optionally restart one interface. Returns 0 healthy, 1 unhealthy.
process_interface() {
    local iface="$1"

    # Is a *tunnel* restart permitted on this interface? Requires --restart AND a
    # non-hub role. A hub is monitored and alerted on but its tunnel is never
    # bounced (dropping all peers). Non-disruptive recovery that does NOT drop
    # peers — starting a stopped firewall service — is still allowed on a hub,
    # since it only restores peer connectivity.
    local may_restart=false
    local role; role=$(iface_role "$iface")
    if $DO_RESTART && [[ "$role" != "hub" ]]; then may_restart=true; fi

    local result; result=$(check_interface "$iface")

    if [[ "$result" != "ok" ]]; then
        print_warning "${iface}: ${result}"
        log_audit "HEALTHCHECK_FAIL" "interface=${iface} reason=${result}"

        if [[ "$role" == "hub" ]] && $DO_RESTART; then
            # Hub: alert but never bounce the tunnel — a manual restart is a
            # deliberate human decision, not something a timer should do.
            print_error "${iface}: hub is unhealthy (${result}) — NOT auto-restarting (Healthcheck-Role = hub); restart manually if intended"
            log_audit "HEALTHCHECK_NORESTART" "interface=${iface} role=hub reason=${result}"
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
                    # fall through to firewall check
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

    # Interface is up — verify the firewall we configured is still effective.
    # A stopped firewalld/ufw silently closes the UDP port; flushed nftables
    # drops FORWARD traffic. Neither shows up in `wg-quick` status.
    local fw_result; fw_result=$(check_firewall "$iface")
    if [[ "$fw_result" != "ok" ]]; then
        print_warning "${iface}: ${fw_result}"
        log_audit "HEALTHCHECK_FAIL" "interface=${iface} reason=${fw_result}"

        if $DO_RESTART; then
            local fw_svc=""
            case "$fw_result" in
                firewall-down:firewalld) fw_svc=firewalld ;;
                firewall-down:ufw)       fw_svc=ufw ;;
            esac
            if [[ -n "$fw_svc" ]]; then
                print_info "${iface}: starting ${fw_svc} ..."
                log_audit "HEALTHCHECK_RESTART" "interface=${iface} component=firewall service=${fw_svc} reason=${fw_result}"
                if systemctl start "$fw_svc" 2>/dev/null; then
                    sleep 2
                    local refw; refw=$(check_firewall "$iface")
                    if [[ "$refw" == "ok" ]]; then
                        print_success "${iface}: ${fw_svc} started"
                        log_audit "HEALTHCHECK_RECOVERY" "interface=${iface} component=firewall service=${fw_svc}"
                    else
                        print_error "${iface}: ${fw_svc} still failing after start (${refw})"
                        log_audit "HEALTHCHECK_RESTART_FAILED" "interface=${iface} component=firewall service=${fw_svc} reason=${refw}"
                        return 1
                    fi
                else
                    print_error "${iface}: failed to start ${fw_svc}"
                    log_audit "HEALTHCHECK_RESTART_FAILED" "interface=${iface} component=firewall service=${fw_svc} reason=systemctl-start-command-failed"
                    return 1
                fi
            else
                # nftables rules vanished — no safe auto-recovery from cron
                print_warning "${iface}: cannot auto-recover ${fw_result}; rerun setup.sh firewall config"
                log_audit "HEALTHCHECK_RESTART_FAILED" "interface=${iface} component=firewall reason=${fw_result} note=no-auto-recovery-manual-fix-required"
                return 1
            fi
        else
            return 1
        fi
    fi

    # Interface + firewall are healthy. If an upstream target is configured,
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
        if (( hs < HANDSHAKE_DEAD_SECS )); then
            print_warning "${iface}: ${reach}, but handshake is ${hs}s old (< ${HANDSHAKE_DEAD_SECS}s) — tunnel alive, target likely down; not restarting"
            log_audit "HEALTHCHECK_TARGET_DOWN" "interface=${iface} reason=${reach} handshake_age=${hs}"
            [[ "$(reach_fail_count "$iface")" -ne 0 ]] && reach_fail_set "$iface" 0
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
                        print_info "${iface}: re-resolve didn't help — restarting wg-quick@${iface} ..."
                        log_audit "HEALTHCHECK_RESTART" "interface=${iface} component=reachability reason=${reach} handshake_age=${hs} wan=${wan}"
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
