#!/bin/bash
################################################################################
# WireGuard Monitoring Integration Test
# Description: Live, on-box validation of healthcheck.sh and log-connections.sh.
#
# This is NOT a mocked unit test — it stands up real, throwaway WireGuard
# interfaces and drives both scripts against actual kernel / systemd / wg /
# nftables / journald state, then asserts the observed behavior.
#
# Safety:
#   - Every test interface name is derived from this script's PID and verified
#     not to already exist (as a kernel link or an /etc/wireguard/*.conf).
#   - healthcheck.sh is ALWAYS invoked with `-i <test-iface>`, so it never
#     touches, restarts, or even inspects your production interfaces.
#   - log-connections.sh is driven with `-i <test-iface>` and an isolated
#     state dir, so it never logs production peers or clobbers the real
#     logger's state.
#   - An EXIT trap tears everything down (services, interfaces, temp files,
#     persisted streak state) even if a test aborts midway.
#
# Requirements: root, and wg, wg-quick, ip, systemctl, ping, logger,
# journalctl on PATH. Uses loopback transport (127.0.0.1) and the otherwise
# unused 10.255.250.0/24 range for the test tunnels.
#
# Usage:
#   sudo ./test-monitoring.sh          # run all tests, tear down, report
#   sudo ./test-monitoring.sh -k       # keep test interfaces up afterwards
#
# Exit codes: 0 = all tests passed, 1 = one or more failed.
################################################################################

set -uo pipefail   # not -e — a failed assertion must not abort the whole run

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/utils.sh"

KEEP=false
[[ "${1:-}" == "-k" || "${1:-}" == "--keep" ]] && KEEP=true
[[ "${1:-}" == "-h" || "${1:-}" == "--help" ]] && { sed -n '3,33p' "$0" | sed 's/^# \?//'; exit 0; }

check_root

for bin in wg wg-quick ip systemctl ping logger journalctl awk; do
    command -v "$bin" &>/dev/null || die "required command not found: $bin"
done

# ---------- test bookkeeping ----------
PASS=0
FAIL=0
section()         { echo; echo -e "${CYAN}== $1 ==${NC}"; }
pass()            { PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} $1"; }
fail()            { FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} $1"; }
assert_rc()       { if [[ "$1" == "$2" ]]; then pass "$3 (rc=$2)"; else fail "$3 (expected rc=$1, got rc=$2)"; fi; }
assert_eq()       { if [[ "$1" == "$2" ]]; then pass "$3"; else fail "$3 (expected '$1', got '$2')"; fi; }
assert_ge()       { if (( $1 >= $2 )); then pass "$3"; else fail "$3 (expected >= $2, got $1)"; fi; }
assert_contains() {
    if [[ "$1" == *"$2"* ]]; then pass "$3"
    else fail "$3 (output did not contain '$2')"; echo "      ---"; echo "      ${1//$'\n'/$'\n      '}"; echo "      ---"; fi
}

# ---------- resource selection ----------
SFX=$(( $$ % 10000 ))
HC="wgt${SFX}h"          # healthcheck test interface (driven via systemd)
LCA="wgt${SFX}a"         # log-connections test interface (logger polls this one)
LCB="wgt${SFX}b"         # its peer, lives in a separate network namespace
NS="wgtns${SFX}"         # netns holding LCB, so its tunnel IP is non-local
VETHH="wgtvh${SFX}"      # veth half in the main ns (encrypted transport)
VETHN="wgtvn${SFX}"      # veth half inside the netns
for n in "$HC" "$LCA" "$LCB" "$VETHH" "$VETHN"; do
    validate_interface_name "$n" || die "generated name '$n' is invalid"
    ip link show "$n" &>/dev/null && die "test interface '$n' already exists — rerun"
done
for n in "$HC" "$LCA" "$LCB"; do
    [[ -e "/etc/wireguard/${n}.conf" ]] && die "/etc/wireguard/${n}.conf already exists — rerun"
done
ip netns list 2>/dev/null | grep -qw "$NS" && die "test netns '$NS' already exists — rerun"

pick_port() {   # echo first free UDP port >= $1
    local p="$1"
    while ss -lun 2>/dev/null | grep -qE "[:.]${p}[[:space:]]"; do p=$((p+1)); done
    echo "$p"
}
HCP=$(pick_port 51950)
AP=$(pick_port $((HCP+1)))
BP=$(pick_port $((AP+1)))

TMPROOT="$(mktemp -d)"
STATE="${TMPROOT}/state"
mkdir -p "$STATE"
HC_CONF="/etc/wireguard/${HC}.conf"
HC_REACH="/etc/wireguard/.healthcheck-${HC}.reachfail"
HC_MANIFEST="/etc/wireguard/.manifest-${HC}"
CONF_A="${TMPROOT}/${LCA}.conf"
B_KEY="${TMPROOT}/${LCB}.key"

# ---------- teardown (invoked via the EXIT trap below) ----------
# shellcheck disable=SC2317  # reached through the trap, not inline
teardown() {
    if $KEEP; then
        echo; echo -e "${YELLOW}[-k] leaving test interfaces up:${NC} $HC $LCA $LCB (state in $TMPROOT)"
        return
    fi
    systemctl stop "wg-quick@${HC}" &>/dev/null || true
    ip link del "$HC" &>/dev/null || true
    rm -f "$HC_CONF" "$HC_REACH" "$HC_MANIFEST"
    [[ -f "$CONF_A" ]] && wg-quick down "$CONF_A" &>/dev/null
    ip link del "$LCA" &>/dev/null || true
    ip netns del "$NS" &>/dev/null || true        # also removes LCB + the veth pair
    ip link del "$VETHH" &>/dev/null || true
    rm -rf "$TMPROOT"
}
trap teardown EXIT

# Invocation helpers (capture combined output + rc into OUT / RC).
hc() { OUT="$("${SCRIPT_DIR}/healthcheck.sh" "$@" 2>&1)"; RC=$?; }
lc() { OUT="$(env WG_CONFIG_DIR="$TMPROOT" WIREGUARD_CONN_STATE_DIR="$STATE" \
                  WIREGUARD_CONN_ACTIVE_WITHIN="$1" \
                  "${SCRIPT_DIR}/log-connections.sh" -i "$LCA" 2>&1)"; RC=$?; }
reachfail() { cat "$HC_REACH" 2>/dev/null || echo MISSING; }

################################################################################
section "healthcheck.sh  (interface: $HC, port $HCP)"
################################################################################
HC_PRIV="$(wg genkey)"
cat > "$HC_CONF" <<EOF
[Interface]
Address = 10.255.251.1/32
ListenPort = ${HCP}
PrivateKey = ${HC_PRIV}
# Pin the off-tunnel WAN anchor to a locally-reachable address so the
# reachability tests below are hermetic: the new WAN gate must read "internet
# up" without this box actually reaching its default anchors (1.1.1.1/8.8.8.8).
# Healthcheck-WAN = 127.0.0.1
EOF
chmod 600 "$HC_CONF"
systemctl start "wg-quick@${HC}" || die "could not start wg-quick@${HC} (is wireguard-tools' wg-quick@ template installed?)"

# 1. Healthy interface reports healthy and exits 0.
hc -i "$HC" -v
assert_rc 0 "$RC" "healthy interface exits 0"
assert_contains "$OUT" "healthy" "healthy interface reports 'healthy'"

# 2. Address assigned in .conf but missing from the kernel link is detected.
ip addr flush dev "$HC"
hc -i "$HC"
assert_rc 1 "$RC" "missing address exits 1"
assert_contains "$OUT" "address-missing" "missing address detected"

# 3. --restart recovers the missing address (wg-quick re-applies it).
hc -i "$HC" --restart
assert_rc 0 "$RC" "restart recovers missing address"
assert_contains "$OUT" "recovered" "restart reports recovery"

# 4. Stopped service is detected as inactive.
systemctl stop "wg-quick@${HC}"
hc -i "$HC"
assert_rc 1 "$RC" "stopped service exits 1"
assert_contains "$OUT" "service-inactive" "stopped service detected"

# 5. --restart brings the stopped service back.
hc -i "$HC" --restart
assert_rc 0 "$RC" "restart recovers stopped service"
assert_contains "$OUT" "recovered" "restart reports recovery (service)"

# 6. Reachability: pinging the interface's own in-tunnel IP through it succeeds.
hc -i "$HC" -v --ping-target 10.255.251.1
assert_rc 0 "$RC" "reachable ping-target exits 0"

# 7. Unreachable target below the failure threshold is tolerated (still 0),
#    and the consecutive-failure streak is persisted.
rm -f "$HC_REACH"
hc -i "$HC" --ping-target 10.255.251.99 --fail-threshold 2
assert_rc 0 "$RC" "1st unreachable check tolerated below threshold"
assert_contains "$OUT" "unreachable" "unreachable target reported"
assert_eq "1" "$(reachfail)" "failure streak persisted as 1"

# 8. Reaching the threshold without --restart is reported as unhealthy.
hc -i "$HC" --ping-target 10.255.251.99 --fail-threshold 2
assert_rc 1 "$RC" "threshold reached exits 1 (no --restart)"
assert_eq "2" "$(reachfail)" "failure streak persisted as 2"

# 9. At/over threshold with --restart: restart runs, target still unreachable,
#    streak resets to 0 (back off rather than restart-loop), exit 1.
hc -i "$HC" --ping-target 10.255.251.99 --fail-threshold 2 --restart
assert_rc 1 "$RC" "restart that does not restore reachability exits 1"
assert_contains "$OUT" "after restart" "reports still-unreachable after restart"
assert_eq "0" "$(reachfail)" "streak reset to 0 after failed-recovery restart"

# 10. A subsequent good reachability check clears the streak.
hc -i "$HC" --ping-target 10.255.251.1
assert_rc 0 "$RC" "recovered reachability exits 0"
assert_eq "0" "$(reachfail)" "streak stays cleared on good check"

# 11. Reachability target read from the conf comment, with NO --ping-target:
#     an unreachable target at threshold 1 must drive the interface unhealthy,
#     proving the "# Healthcheck-Reachability =" line in <iface>.conf is honored
#     (this is how a real site box enables the check). A hub conf has no such
#     line, so the same scheduled run would simply skip reachability.
rm -f "$HC_REACH"
printf '# Healthcheck-Reachability = 10.255.251.99\n' >> "$HC_CONF"
hc -i "$HC" --fail-threshold 1
assert_rc 1 "$RC" "conf-comment reachability target honored (unreachable -> exit 1)"
assert_contains "$OUT" "unreachable" "conf-comment target reported unreachable"

# 12. Multiple comma-separated targets: the tunnel is alive if ANY one answers.
#     List a dead host AND the reachable self IP; the interface stays healthy and
#     the failure streak is never incremented.
rm -f "$HC_REACH"
sed -i '/Healthcheck-Reachability/d' "$HC_CONF"
printf '# Healthcheck-Reachability = 10.255.251.99, 10.255.251.1\n' >> "$HC_CONF"
hc -i "$HC" --fail-threshold 1 -v
assert_rc 0 "$RC" "multiple targets: any-reachable keeps interface healthy"
assert_eq "MISSING" "$(reachfail)" "no failure streak written when a target answers"

# 13. A syntactically invalid target (bad octet) is warned about and ignored; a
#     valid target alongside it still drives the check.
rm -f "$HC_REACH"
sed -i '/Healthcheck-Reachability/d' "$HC_CONF"
printf '# Healthcheck-Reachability = 10.255.251.999, 10.255.251.1\n' >> "$HC_CONF"
hc -i "$HC" --fail-threshold 1
assert_rc 0 "$RC" "invalid target ignored, valid one keeps interface healthy"
assert_contains "$OUT" "invalid reachability target" "invalid target warned about"

# 14. When EVERY target is invalid, reachability is reported misconfigured: the
#     interface stays healthy (exit 0), nothing is restarted, no streak written.
rm -f "$HC_REACH"
sed -i '/Healthcheck-Reachability/d' "$HC_CONF"
printf '# Healthcheck-Reachability = 10.0.0.999, bad_host\n' >> "$HC_CONF"
hc -i "$HC" --fail-threshold 1 --restart
assert_rc 0 "$RC" "all-invalid targets: interface stays healthy, no restart"
assert_contains "$OUT" "no valid target" "all-invalid reachability reported misconfigured"
assert_eq "MISSING" "$(reachfail)" "no failure streak written for misconfigured reachability"

# 15. WAN gate: tunnel dead (no handshake) AND the off-tunnel WAN anchor
#     unreachable => a restart cannot help, so the run HOLDS (logs WAN_DOWN,
#     exit 1) and must NOT restart or write a failure streak. Point the WAN
#     anchor at TEST-NET-3 (198.51.100.0/24, guaranteed unrouted) to force it.
rm -f "$HC_REACH"
sed -i '/Healthcheck-Reachability/d' "$HC_CONF"
sed -i 's/^# Healthcheck-WAN =.*/# Healthcheck-WAN = 198.51.100.254/' "$HC_CONF"
hc -i "$HC" --ping-target 10.255.251.99 --restart
assert_rc 1 "$RC" "WAN down + tunnel dead: exits 1"
assert_contains "$OUT" "internet unreachable" "WAN-down hold reported"
assert_contains "$OUT" "NOT restarting" "WAN down => did not restart"
assert_eq "MISSING" "$(reachfail)" "WAN-down hold writes no failure streak"
sed -i 's/^# Healthcheck-WAN =.*/# Healthcheck-WAN = 127.0.0.1/' "$HC_CONF"   # restore

# 16. Firewall backend staleness: a manifest recording a backend whose tooling
#     is no longer installed is reported as stale (rerun setup) — a warning that
#     does NOT fail interface health (exit 0) or trigger a restart. Pick a
#     backend whose command is genuinely absent on this box.
STALE_BE=""
if   ! command -v ufw          &>/dev/null; then STALE_BE=ufw
elif ! command -v firewall-cmd &>/dev/null; then STALE_BE=firewalld
fi
if [[ -n "$STALE_BE" ]]; then
    rm -f "$HC_REACH"; sed -i '/Healthcheck-Reachability/d' "$HC_CONF"
    if [[ "$STALE_BE" == ufw ]]; then echo 'FW_UFW|added' > "$HC_MANIFEST"
    else echo 'FW_FIREWALLD|added' > "$HC_MANIFEST"; fi
    hc -i "$HC" -v
    assert_rc 0 "$RC" "stale firewall backend: interface stays healthy (exit 0)"
    assert_contains "$OUT" "manifest is stale" "stale firewall backend warned (rerun setup)"
    rm -f "$HC_MANIFEST"
else
    pass "SKIP firewall-staleness test (both ufw and firewalld tooling present)"
fi

# 17. Hub protection: an interface marked "# Healthcheck-Role = hub" is NEVER
#     auto-restarted, even with --restart on a real structural failure — it must
#     alert (NORESTART, exit 1) and leave the tunnel down for a human. (Runs last
#     in this section: it stops the service and does not bring it back.)
printf '# Healthcheck-Role = hub\n' >> "$HC_CONF"
systemctl stop "wg-quick@${HC}"
hc -i "$HC" --restart
assert_rc 1 "$RC" "hub structural failure exits 1"
assert_contains "$OUT" "NOT auto-restarting" "hub is alerted, not auto-restarted"
if systemctl is-active --quiet "wg-quick@${HC}"; then
    fail "hub tunnel was restarted despite Role=hub"
else
    pass "hub tunnel left down (Role=hub blocked the restart)"
fi

# NOTE: two healthcheck paths are not yet covered here because they need a
# systemd-managed interface carrying a *fresh* handshake, which this harness
# doesn't stand up (the handshaking pair below is driven via `wg-quick up`, not
# the wg-quick@ unit healthcheck.sh inspects):
#   - the handshake-age gate's "fresh handshake => TARGET_DOWN, don't restart"
#     branch (its "stale handshake => proceed" branch IS exercised above, since
#     the HC interface has no peer and so no handshake);
#   - endpoint re-resolve recovery (needs a resolvable peer Endpoint to re-push).

################################################################################
section "log-connections.sh  ($LCA in main ns <-> $LCB in netns $NS)"
################################################################################
# A real CONNECT requires a real kernel handshake, which only happens if the
# peer's tunnel IP is *not* local — otherwise the kernel short-circuits traffic
# over loopback and the tunnel is never exercised. So LCB lives in its own
# network namespace, reached over a veth pair (192.0.2.0/24) that carries the
# encrypted transport. LCA stays in the main ns, where the logger polls it.
A_PRIV="$(wg genkey)"; A_PUB="$(wg pubkey <<<"$A_PRIV")"
B_PRIV="$(wg genkey)"; B_PUB="$(wg pubkey <<<"$B_PRIV")"
printf '%s\n' "$B_PRIV" > "$B_KEY"; chmod 600 "$B_KEY"

# LCA: main namespace, transport endpoint is the peer's veth address.
cat > "$CONF_A" <<EOF
[Interface]
Address = 10.255.250.1/32
ListenPort = ${AP}
PrivateKey = ${A_PRIV}

# BEGIN_PEER testpeer
# Peer-to-Peer: testpeer
[Peer]
PublicKey = ${B_PUB}
AllowedIPs = 10.255.250.2/32
Endpoint = 192.0.2.2:${BP}
# END_PEER testpeer
EOF
chmod 600 "$CONF_A"

# netns + veth pair for the encrypted transport path.
ip netns add "$NS" || die "could not create netns $NS"
ip link add "$VETHH" type veth peer name "$VETHN" || die "could not create veth pair"
ip link set "$VETHN" netns "$NS"
ip addr add 192.0.2.1/24 dev "$VETHH"; ip link set "$VETHH" up
ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" ip addr add 192.0.2.2/24 dev "$VETHN"
ip netns exec "$NS" ip link set "$VETHN" up

# LCB: inside the netns, peering back at LCA over the veth.
ip netns exec "$NS" ip link add "$LCB" type wireguard || die "could not create $LCB in $NS"
ip netns exec "$NS" wg set "$LCB" listen-port "$BP" private-key "$B_KEY" \
    peer "$A_PUB" allowed-ips 10.255.250.1/32 endpoint "192.0.2.1:${AP}"
ip netns exec "$NS" ip addr add 10.255.250.2/32 dev "$LCB"
ip netns exec "$NS" ip link set "$LCB" up
ip netns exec "$NS" ip route add 10.255.250.1/32 dev "$LCB"

wg-quick up "$CONF_A" &>/dev/null || die "could not bring up $LCA"

# Drive a real handshake by sending traffic through the tunnel.
handshook=false
for _ in 1 2 3 4 5; do
    ping -c1 -W2 10.255.250.2 &>/dev/null || true
    hs="$(wg show "$LCA" latest-handshakes 2>/dev/null | awk '{print $2}' | sort -rn | head -1)"
    if [[ -n "$hs" && "$hs" != 0 ]]; then handshook=true; break; fi
    sleep 1
done
if $handshook; then pass "real handshake established between $LCA and $LCB"
else fail "could not establish a handshake — CONNECT/DISCONNECT tests will be unreliable"; fi

LC_START="$(date '+%Y-%m-%d %H:%M:%S')"
connects()    { journalctl -t wireguard-connections --since "$LC_START" 2>/dev/null | grep -c "CONNECT peer=testpeer iface=${LCA}"; }
disconnects() { journalctl -t wireguard-connections --since "$LC_START" 2>/dev/null | grep -c "DISCONNECT peer=testpeer iface=${LCA}"; }

# 1. First poll of a freshly-connected peer logs a CONNECT, resolving the
#    peer name from the BEGIN_PEER block in the config.
lc 5
sleep 1
assert_rc 0 "$RC" "logger runs cleanly"
assert_ge "$(connects)" 1 "CONNECT logged with resolved peer name (testpeer)"

# 2. Re-polling an unchanged peer logs no additional event.
before="$(connects)"
lc 5
sleep 1
assert_eq "$before" "$(connects)" "no duplicate CONNECT when state is unchanged"

# 3. With a 1s activity window and no fresh traffic, the peer ages to idle and
#    the connected->idle transition logs a DISCONNECT.
sleep 2
lc 1
sleep 1
assert_ge "$(disconnects)" 1 "DISCONNECT logged when peer goes idle"

################################################################################
echo
TOTAL=$((PASS+FAIL))
if (( FAIL == 0 )); then
    echo -e "${GREEN}All ${TOTAL} checks passed.${NC}"
    exit 0
else
    echo -e "${RED}${FAIL} of ${TOTAL} checks failed.${NC}"
    exit 1
fi
