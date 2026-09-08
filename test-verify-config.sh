#!/bin/bash
################################################################################
# verify-config.sh Test Suite
# Description: Fault-injection tests for the config conformance checker.
#
# Unlike test-monitoring.sh this suite is purely filesystem-based: it builds
# throwaway config trees under a temp dir, injects one defect at a time, and
# asserts that verify-config.sh reports it with the right severity and exit
# code. It never creates an interface, never touches systemd, and never reads
# or writes /etc/wireguard — every run is driven with WG_CONFIG_DIR pointed at
# the fixture, so it is safe to run on a live server.
#
# Method: each test starts from a known-good fixture (built with real
# `wg genkey` material so the key-derivation checks are exercised for real),
# applies exactly one mutation, and asserts on the result. A defect that stops
# being detected therefore fails exactly one test, and names itself.
#
# Requirements: root (verify-config.sh calls check_root), plus wg on PATH.
#
# Usage:
#   sudo ./test-verify-config.sh          # run all tests
#   sudo ./test-verify-config.sh -k       # keep the fixture dir for inspection
#
# Exit codes: 0 = all tests passed, 1 = one or more failed.
################################################################################

set -uo pipefail   # not -e — a failed assertion must not abort the whole run

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/utils.sh"
source "${SCRIPT_DIR}/test-lib.sh"

KEEP=false
[[ "${1:-}" == "-k" || "${1:-}" == "--keep" ]] && KEEP=true
[[ "${1:-}" == "-h" || "${1:-}" == "--help" ]] && { sed -n '3,25p' "$0" | sed 's/^# \?//'; exit 0; }

check_root
for bin in wg awk grep stat; do
    command -v "$bin" &>/dev/null || die "required command not found: $bin"
done
[[ -x "${SCRIPT_DIR}/verify-config.sh" ]] || die "verify-config.sh not found or not executable"


TMPROOT="$(mktemp -d)"
GOLD="${TMPROOT}/gold"      # pristine conformant fixture, never mutated
WORK="${TMPROOT}/work"      # per-test copy that tests mutate

# shellcheck disable=SC2317  # reached through the trap, not inline
teardown() {
    if $KEEP; then
        echo; echo -e "${YELLOW}[-k] fixture kept at:${NC} $TMPROOT"
        return
    fi
    rm -rf "$TMPROOT"
}
trap teardown EXIT

################################################################################
# FIXTURE
################################################################################
# A conformant wg0 exactly as setup.sh + add-peer.sh would leave it: real
# keypairs, marker-wrapped peer blocks with type lines, per-peer configs and
# key files in the interface key dir, a manifest, and 600 on everything.

build_gold() {
    local keys="${GOLD}/wg0"
    mkdir -p "$keys"

    ( umask 077; wg genkey | tee "${keys}/server-privatekey" | wg pubkey > "${keys}/server-publickey" )

    local p
    for p in alpha charlie; do
        ( umask 077; wg genkey | tee "${keys}/${p}-privatekey" | wg pubkey > "${keys}/${p}-publickey" )
        printf '[Interface]\nPrivateKey = %s\nAddress = 10.0.0.9/32\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.0.0.0/24\n' \
            "$(cat "${keys}/${p}-privatekey")" "$(cat "${keys}/server-publickey")" > "${keys}/${p}.conf"
        chmod 600 "${keys}/${p}.conf"
    done

    {
        printf '[Interface]\nAddress = 10.0.0.1/24\nListenPort = 51820\nPrivateKey = %s\n\n' \
            "$(cat "${keys}/server-privatekey")"
        printf '# BEGIN_PEER alpha\n# Client: alpha\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.0.0.2/32\n# END_PEER alpha\n\n' \
            "$(cat "${keys}/alpha-publickey")"
        printf '# BEGIN_PEER charlie\n# Site: charlie\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.0.0.4/32, 192.168.9.0/24\n# END_PEER charlie\n' \
            "$(cat "${keys}/charlie-publickey")"
    } > "${GOLD}/wg0.conf"
    chmod 600 "${GOLD}/wg0.conf"

    printf 'SERVICE|wg-quick@wg0\nFW_NFT|fwd:wg0\nSYSCTL|/etc/sysctl.d/99-wg0.conf\n' > "${GOLD}/.manifest-wg0"
    chmod 600 "${GOLD}/.manifest-wg0"
}

# Reset WORK to the pristine fixture. Every test calls this first, so tests
# are order-independent and a mutation can never leak into the next one.
reset_work() {
    rm -rf "$WORK"
    cp -a "$GOLD" "$WORK"
}

# Run verify-config.sh against WORK. Captures combined output in OUT, rc in RC.
vc() {
    OUT="$(env WG_CONFIG_DIR="$WORK" "${SCRIPT_DIR}/verify-config.sh" "$@" 2>&1)"
    RC=$?
}


################################################################################
build_gold

section "baseline: a conformant config"

reset_work
vc -i wg0
assert_rc 0 "$RC" "clean fixture passes"
assert_contains "$OUT" "Config matches the expected format" "clean fixture reports success"
assert_not_contains "$OUT" "FAIL" "clean fixture raises no errors"
assert_not_contains "$OUT" "warn" "clean fixture raises no warnings"

vc -i wg0 -s
assert_rc 0 "$RC" "clean fixture passes under --strict too"

################################################################################
section "marker coverage  (the drift nothing else catches)"

reset_work
# A hand-added peer: valid WireGuard, no BEGIN_PEER/END_PEER markers.
UNMARKED_KEY="$(wg genkey | wg pubkey)"
printf '\n# Client: bravo\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.0.0.3/32\n' "$UNMARKED_KEY" >> "${WORK}/wg0.conf"
vc -i wg0
assert_rc 1 "$RC" "unmarked peer is an error"
assert_contains "$OUT" "2/3 [Peer] blocks carry BEGIN_PEER markers" "reports the marker/raw ratio"
assert_contains "$OUT" "invisible to list/toggle/remove/rotate" "explains the consequence"
assert_contains "$OUT" "$UNMARKED_KEY" "names the offending peer by public key"

# The premise of the whole check: the scripts really cannot see that peer.
MARKED=$(peer_list "${WORK}/wg0.conf" | grep -c .)
assert_rc 2 "$MARKED" "peer_list sees only the 2 marked peers"

reset_work
# END_PEER present but BEGIN_PEER missing — the other half of the same defect.
sed -i '/^# BEGIN_PEER charlie$/d' "${WORK}/wg0.conf"
vc -i wg0
assert_rc 1 "$RC" "block with END_PEER but no BEGIN_PEER is an error"
assert_contains "$OUT" "1/2 [Peer] blocks carry BEGIN_PEER markers" "counts the half-marked block"

################################################################################
section "peer block structure"

reset_work
sed -i '/^# END_PEER charlie$/d' "${WORK}/wg0.conf"
vc -i wg0
assert_rc 1 "$RC" "unterminated marker block is an error"
assert_contains "$OUT" "BEGIN_PEER with no matching END_PEER" "names the unterminated block"

reset_work
# Duplicate name: peer_select would only ever reach the first.
sed -i 's/^# BEGIN_PEER charlie$/# BEGIN_PEER alpha/; s/^# END_PEER charlie$/# END_PEER alpha/' "${WORK}/wg0.conf"
vc -i wg0
assert_rc 1 "$RC" "duplicate peer name is an error"
assert_contains "$OUT" "declared more than once" "names the duplicated peer"

reset_work
sed -i '/^# BEGIN_PEER alpha$/,/^# END_PEER alpha$/{/^PublicKey/d}' "${WORK}/wg0.conf"
vc -i wg0
assert_rc 1 "$RC" "peer block with no PublicKey is an error"
assert_contains "$OUT" "no PublicKey" "reports the missing field"

reset_work
sed -i '/^# BEGIN_PEER alpha$/,/^# END_PEER alpha$/{/^AllowedIPs/d}' "${WORK}/wg0.conf"
vc -i wg0
assert_rc 1 "$RC" "peer block with no AllowedIPs is an error"
assert_contains "$OUT" "no AllowedIPs" "reports the missing field"

reset_work
# Missing type line degrades list-peers.sh's type column but breaks nothing.
sed -i '/^# Client: alpha$/d' "${WORK}/wg0.conf"
vc -i wg0
assert_rc 0 "$RC" "missing type line is only a warning"
assert_contains "$OUT" "no '# Client:/# Site:/# Peer-to-Peer:' type line" "reports the missing type line"
vc -i wg0 -s
assert_rc 1 "$RC" "--strict promotes that warning to a failure"

################################################################################
section "collisions between peers"

reset_work
sed -i 's|^AllowedIPs = 10.0.0.4/32, 192.168.9.0/24$|AllowedIPs = 10.0.0.2/32|' "${WORK}/wg0.conf"
vc -i wg0
assert_rc 1 "$RC" "two peers claiming the same AllowedIPs is an error"
assert_contains "$OUT" "claimed by more than one peer" "reports the collision"
assert_contains "$OUT" "alpha" "names the first owner"
assert_contains "$OUT" "charlie" "names the second owner"

reset_work
# Same public key on two peers — a copy-paste during a manual add.
DUP_KEY=$(peer_pubkey "${WORK}/wg0.conf" alpha)
sed -i "/^# BEGIN_PEER charlie$/,/^# END_PEER charlie$/{s|^PublicKey = .*|PublicKey = ${DUP_KEY}|}" "${WORK}/wg0.conf"
vc -i wg0
assert_rc 1 "$RC" "two peers sharing a PublicKey is an error"
assert_contains "$OUT" "PublicKey '${DUP_KEY}' is claimed by more than one peer" "reports the shared key"

################################################################################
section "key material on disk"

reset_work
# A rotation that wrote the key file but not the config (or vice versa).
( umask 077; wg genkey > "${WORK}/wg0/server-privatekey" )
vc -i wg0
assert_rc 1 "$RC" "server-privatekey out of sync with the config is an error"
assert_contains "$OUT" "server-privatekey does NOT match" "reports the private key mismatch"
assert_contains "$OUT" "server-publickey is not the public key of server-privatekey" "reports the derived key mismatch"

reset_work
# Public key file no longer matches what the server config accepts.
( umask 077; wg genkey | wg pubkey > "${WORK}/wg0/alpha-publickey" )
vc -i wg0
assert_rc 1 "$RC" "peer pubkey file disagreeing with the config is an error"
assert_contains "$OUT" "alpha-publickey disagrees with the PublicKey" "reports the peer key mismatch"

reset_work
rm -f "${WORK}/wg0/alpha.conf"
vc -i wg0
assert_rc 0 "$RC" "a missing peer .conf is only a warning"
assert_contains "$OUT" "show-qr.sh cannot render it" "explains what the missing peer conf costs"

reset_work
printf '[Interface]\nPrivateKey = x\n' > "${WORK}/wg0/ghost.conf"
chmod 600 "${WORK}/wg0/ghost.conf"
vc -i wg0
assert_rc 0 "$RC" "an orphan peer .conf is only a warning"
assert_contains "$OUT" "orphan ghost.conf" "names the orphan config"

reset_work
chmod 644 "${WORK}/wg0/alpha-privatekey"
vc -i wg0
assert_rc 0 "$RC" "loose permissions are only a warning"
assert_contains "$OUT" "mode 644 (expected 600)" "reports the permission drift"

################################################################################
section "server config structure"

reset_work
printf 'this is not a wireguard config\n' > "${WORK}/wg0.conf"
vc -i wg0
assert_rc 1 "$RC" "garbage is an error"
assert_contains "$OUT" "not a Key = Value line" "reports the malformed line"
assert_contains "$OUT" "no [Interface] section" "reports the missing section"

reset_work
printf '\n[Peerz]\nPublicKey = abc\n' >> "${WORK}/wg0.conf"
vc -i wg0
assert_rc 1 "$RC" "unknown section header is an error"
assert_contains "$OUT" "unknown section header" "names the bad header"

reset_work
sed -i '0,/^\[Interface\]$/! s/^# BEGIN_PEER alpha$/[Interface]\n# BEGIN_PEER alpha/' "${WORK}/wg0.conf"
vc -i wg0
assert_rc 1 "$RC" "a second [Interface] section is an error"
assert_contains "$OUT" "more than one [Interface] section" "reports the duplicate section"

reset_work
sed -i '/^PrivateKey = /d' "${WORK}/wg0.conf"
vc -i wg0
assert_rc 1 "$RC" "missing [Interface] PrivateKey is an error"
assert_contains "$OUT" "[Interface] has no PrivateKey" "reports the missing key"

reset_work
sed -i '/^ListenPort = /d' "${WORK}/wg0.conf"
vc -i wg0
assert_rc 0 "$RC" "missing ListenPort is only a warning (valid for a client config)"
assert_contains "$OUT" "fine for a client config" "explains why ListenPort is not fatal"

################################################################################
section "manifest"

reset_work
rm -f "${WORK}/.manifest-wg0"
vc -i wg0
assert_rc 0 "$RC" "a missing manifest is only a warning"
assert_contains "$OUT" "healthcheck.sh cannot verify the firewall" "explains what the manifest is for"

reset_work
grep -v '^FW_' "${GOLD}/.manifest-wg0" > "${WORK}/.manifest-wg0"
vc -i wg0
assert_contains "$OUT" "manifest records no firewall rules" "reports a manifest with no firewall entries"

################################################################################
section "edge cases and flags"

reset_work
# A server with no peers yet: legal, and must not trip the 0-vs-0 arithmetic.
printf '[Interface]\nAddress = 10.0.0.1/24\nListenPort = 51820\nPrivateKey = %s\n' \
    "$(cat "${WORK}/wg0/server-privatekey")" > "${WORK}/wg0.conf"
chmod 600 "${WORK}/wg0.conf"
vc -i wg0
assert_rc 0 "$RC" "a peerless server config is not an error"
assert_contains "$OUT" "no marker-format peers declared" "reports the empty peer list as a warning"
assert_not_contains "$OUT" "syntax error" "no arithmetic error on an empty peer list"

reset_work
cp -a "${WORK}/wg0.conf" "${WORK}/wg1.conf"
cp -a "${WORK}/wg0" "${WORK}/wg1"
sed 's/wg0/wg1/' "${GOLD}/.manifest-wg0" > "${WORK}/.manifest-wg1"
chmod 600 "${WORK}/.manifest-wg1"
vc --all
assert_rc 0 "$RC" "--all sweeps every interface"
assert_contains "$OUT" "2 interface(s) checked" "reports both interfaces"

reset_work
vc -i wg0 -q
assert_rc 0 "$RC" "--quiet still exits 0 on a clean config"
assert_not_contains "$OUT" "  ok   " "--quiet suppresses per-check ok lines"

reset_work
vc -i nosuchiface
assert_rc 1 "$RC" "an unknown interface fails"

################################################################################
test_summary
