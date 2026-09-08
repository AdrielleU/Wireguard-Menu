#!/bin/bash
################################################################################
# Installer Test Suite
# Description: Tests for install-healthcheck.sh and install-logging.sh — the
#              unit-file rewriting, the split between the two controls, and the
#              journal retention projection.
#
# Safety: unit installation is redirected to a temp dir via UNIT_DST, so this
# never writes to /etc/systemd/system, never runs systemctl against a real
# unit, and never touches the host's journald config (the retention check reads
# a fixture via JOURNALD_CONF_ROOT). Nothing is enabled or started.
#
# The install paths call systemctl, which would act on the real system, so the
# unit-writing functions are exercised directly from utils.sh rather than by
# running the installers end to end. The retention projection — which touches
# nothing — is driven through install-logging.sh itself.
#
# Requirements: root (the installers call check_root).
#
# Usage: sudo ./test-installers.sh
# Exit codes: 0 = all tests passed, 1 = one or more failed.
################################################################################

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/utils.sh"

check_root

PASS=0
FAIL=0
section()         { echo; echo -e "${CYAN}== $1 ==${NC}"; }
pass()            { PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} $1"; }
fail()            { FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} $1"; }
assert_rc()       { if [[ "$1" == "$2" ]]; then pass "$3 (rc=$2)"; else fail "$3 (expected rc=$1, got rc=$2)"; fi; }
assert_contains() {
    if [[ "$1" == *"$2"* ]]; then pass "$3"
    else fail "$3 (output did not contain '$2')"; echo "      ---"; echo "      ${1//$'\n'/$'\n      '}"; echo "      ---"; fi
}
assert_not_contains() {
    if [[ "$1" != *"$2"* ]]; then pass "$3"
    else fail "$3 (output unexpectedly contained '$2')"; fi
}

TMPROOT="$(mktemp -d)"
# shellcheck disable=SC2317  # reached through the trap
teardown() { rm -rf "$TMPROOT"; }
trap teardown EXIT

################################################################################
section "unit rewriting  (ExecStart re-pointed at this repo)"

# UNIT_DST is honoured by the unit_* helpers, so installation lands here.
export UNIT_DST="${TMPROOT}/units"
mkdir -p "$UNIT_DST"

unit_install_service "$SCRIPT_DIR" wireguard-healthcheck >/dev/null 2>&1
unit_install_service "$SCRIPT_DIR" wireguard-log-connections >/dev/null 2>&1

HC_UNIT="${UNIT_DST}/wireguard-healthcheck.service"
LC_UNIT="${UNIT_DST}/wireguard-log-connections.service"

[[ -f "$HC_UNIT" ]] && pass "healthcheck service written" || fail "healthcheck service written"
[[ -f "$LC_UNIT" ]] && pass "log-connections service written" || fail "log-connections service written"

assert_contains "$(cat "$HC_UNIT")" "ExecStart=${SCRIPT_DIR}/healthcheck.sh" \
    "healthcheck ExecStart points at this repo"
assert_contains "$(cat "$LC_UNIT")" "ExecStart=${SCRIPT_DIR}/log-connections.sh" \
    "log-connections ExecStart points at this repo"
assert_not_contains "$(cat "$HC_UNIT")" "/etc/wireguard/scripts/" \
    "shipped placeholder path is gone from the healthcheck unit"
assert_not_contains "$(cat "$LC_UNIT")" "/etc/wireguard/scripts/" \
    "shipped placeholder path is gone from the log-connections unit"

# The --restart argument on the healthcheck ExecStart must survive rewriting;
# losing it would silently turn auto-recovery into a bare check.
assert_contains "$(cat "$HC_UNIT")" "healthcheck.sh --restart" \
    "healthcheck keeps its --restart argument after rewriting"

assert_contains "$(cat "$HC_UNIT")" "Documentation=file://${SCRIPT_DIR}/healthcheck.sh" \
    "Documentation is re-pointed too"

# Re-running must overwrite in place, never append or duplicate.
unit_install_service "$SCRIPT_DIR" wireguard-healthcheck >/dev/null 2>&1
n=$(grep -c '^ExecStart=' "$HC_UNIT")
assert_rc 1 "$n" "re-install leaves exactly one ExecStart line"

################################################################################
section "the two installers stay in their own lane"

# Each installer must touch only its own units — that separation is the whole
# point of the split, and a copy-paste slip would silently break it.
rm -f "$UNIT_DST"/*
unit_install_service "$SCRIPT_DIR" wireguard-healthcheck >/dev/null 2>&1
unit_install_timer   "$SCRIPT_DIR" wireguard-healthcheck >/dev/null 2>&1
installed=$(cd "$UNIT_DST" && echo *)
assert_contains "$installed" "wireguard-healthcheck.service" "healthcheck install writes its service"
assert_contains "$installed" "wireguard-healthcheck.timer"   "healthcheck install writes its timer"
assert_not_contains "$installed" "log-connections" "healthcheck install writes NO logging units"

rm -f "$UNIT_DST"/*
unit_install_service "$SCRIPT_DIR" wireguard-log-connections >/dev/null 2>&1
unit_install_timer   "$SCRIPT_DIR" wireguard-log-connections >/dev/null 2>&1
installed=$(cd "$UNIT_DST" && echo *)
assert_contains "$installed" "wireguard-log-connections.service" "logging install writes its service"
assert_contains "$installed" "wireguard-log-connections.timer"   "logging install writes its timer"
assert_not_contains "$installed" "healthcheck" "logging install writes NO healthcheck units"

################################################################################
section "unit rewriting refuses unsafe repo paths"

OUT=$(unit_install_service "/tmp/has#hash" wireguard-healthcheck 2>&1); RC=$?
assert_rc 1 "$RC" "a repo path containing '#' is rejected"
assert_contains "$OUT" "breaks unit rewriting" "explains why the path is rejected"

OUT=$(unit_install_service "${TMPROOT}/nonexistent" wireguard-healthcheck 2>&1); RC=$?
assert_rc 1 "$RC" "a missing source unit is an error"

################################################################################
section "journal retention projection"

JR="${TMPROOT}/journald"
mkdir -p "${JR}/etc/systemd/journald.conf.d"

lg() {
    OUT="$(env JOURNALD_CONF_ROOT="$JR" RETENTION_TARGET_DAYS="${2:-2192}" \
            "${SCRIPT_DIR}/install-logging.sh" --check-retention 2>&1)"
    RC=$?
}

# The shipped drop-in, whatever it currently says.
cp "${SCRIPT_DIR}/systemd/journald-wireguard-audit.conf" "${JR}/etc/systemd/journald.conf.d/"
lg
assert_contains "$OUT" "target window      2192 days" "defaults to the HIPAA 6-year window"
assert_contains "$OUT" "SystemMaxUse" "reports the effective cap"
assert_contains "$OUT" "achievable window" "projects an achievable window"

# A cap that is obviously too small must fail, and say so in actionable terms.
printf '[Journal]\nSystemMaxUse=1M\n' > "${JR}/etc/systemd/journald.conf.d/journald-wireguard-audit.conf"
lg
assert_rc 1 "$RC" "an undersized cap exits non-zero"
assert_contains "$OUT" "Retention cap is too small" "reports the shortfall"
assert_contains "$OUT" "Raise SystemMaxUse to at least" "says what to do about it"

# A cap that is obviously large enough must pass.
printf '[Journal]\nSystemMaxUse=100T\n' > "${JR}/etc/systemd/journald.conf.d/journald-wireguard-audit.conf"
lg
assert_rc 0 "$RC" "a sufficient cap exits 0"
assert_contains "$OUT" "Retention cap is sufficient" "confirms the window is met"

# Unset cap: journald falls back to 10% of the filesystem, so the window is not
# verifiable from config alone — that must be surfaced, not silently passed.
printf '[Journal]\nStorage=persistent\n' > "${JR}/etc/systemd/journald.conf.d/journald-wireguard-audit.conf"
lg
assert_contains "$OUT" "SystemMaxUse is unset" "flags an unset cap as unverifiable"

# Suffix parsing: K/M/G/T and bare bytes must all be understood.
for pair in "1024K:1.0MB" "5M:5.0MB" "2G:2.0GB" "1T:1.0TB"; do
    val="${pair%%:*}"; want="${pair##*:}"
    printf '[Journal]\nSystemMaxUse=%s\n' "$val" > "${JR}/etc/systemd/journald.conf.d/journald-wireguard-audit.conf"
    lg
    assert_contains "$OUT" "$want" "SystemMaxUse=${val} parses as ${want}"
done

# The target window is configurable for non-HIPAA regimes.
printf '[Journal]\nSystemMaxUse=8G\n' > "${JR}/etc/systemd/journald.conf.d/journald-wireguard-audit.conf"
lg "" 365
assert_contains "$OUT" "target window      365 days" "RETENTION_TARGET_DAYS overrides the window"

# Later drop-ins win, the way systemd merges them.
printf '[Journal]\nSystemMaxUse=1M\n' > "${JR}/etc/systemd/journald.conf.d/00-first.conf"
printf '[Journal]\nSystemMaxUse=100T\n' > "${JR}/etc/systemd/journald.conf.d/99-last.conf"
rm -f "${JR}/etc/systemd/journald.conf.d/journald-wireguard-audit.conf"
lg
assert_contains "$OUT" "100.0TB" "the last drop-in wins, as systemd would merge them"

################################################################################
section "help and argument handling"

for s in install-healthcheck install-logging; do
    OUT=$("${SCRIPT_DIR}/${s}.sh" --nonsense 2>&1); RC=$?
    assert_rc 1 "$RC" "${s}.sh rejects an unknown option"
    assert_contains "$OUT" "Unknown option" "${s}.sh says which option was wrong"
done

################################################################################
echo
echo "=========================================="
if (( FAIL == 0 )); then
    echo -e "${GREEN}All ${PASS} checks passed.${NC}"
else
    echo -e "${RED}${FAIL} of $((PASS + FAIL)) checks failed.${NC}"
fi
echo "=========================================="
(( FAIL == 0 )) || exit 1
exit 0
