#!/bin/bash
################################################################################
# WireGuard Scripts - Shared Test Harness
# Source this from a test script, after utils.sh:
#
#   source "${SCRIPT_DIR}/utils.sh"
#   source "${SCRIPT_DIR}/test-lib.sh"
#
# Provides:
#   - PASS / FAIL counters
#   - section, pass, fail
#   - assert_rc, assert_eq, assert_ge, assert_contains, assert_not_contains
#   - test_summary (prints the tally and exits 0/1)
#
# Deliberately NOT in utils.sh. utils.sh is sourced by every production script,
# including healthcheck.sh and log-connections.sh which run from systemd timers
# every 60s / 2min — those have no business carrying assertion helpers. Keeping
# the harness separate also avoids shadowing verify-config.sh's own section(),
# which reports a section of its findings rather than a block of tests; a
# same-named helper in utils.sh would be silently overridden there, which is
# exactly the drift pattern that was removed from setup.sh and reset.sh.
#
# Colors (CYAN/GREEN/RED/NC) come from utils.sh, so source that first.
################################################################################

PASS=0
FAIL=0

section()         { echo; echo -e "${CYAN}== $1 ==${NC}"; }
pass()            { PASS=$((PASS+1)); echo -e "  ${GREEN}PASS${NC} $1"; }
fail()            { FAIL=$((FAIL+1)); echo -e "  ${RED}FAIL${NC} $1"; }

assert_rc()       { if [[ "$1" == "$2" ]]; then pass "$3 (rc=$2)"; else fail "$3 (expected rc=$1, got rc=$2)"; fi; }
assert_eq()       { if [[ "$1" == "$2" ]]; then pass "$3"; else fail "$3 (expected '$1', got '$2')"; fi; }
assert_ge()       { if (( $1 >= $2 )); then pass "$3"; else fail "$3 (expected >= $2, got $1)"; fi; }

# On failure these dump the offending output, indented, so a broken assertion
# says what it actually saw instead of only what it wanted.
assert_contains() {
    if [[ "$1" == *"$2"* ]]; then pass "$3"
    else fail "$3 (output did not contain '$2')"; echo "      ---"; echo "      ${1//$'\n'/$'\n      '}"; echo "      ---"; fi
}
assert_not_contains() {
    if [[ "$1" != *"$2"* ]]; then pass "$3"
    else fail "$3 (output unexpectedly contained '$2')"; fi
}

# Print the tally and exit: 0 when everything passed, 1 otherwise. Call as the
# last line of a suite.
test_summary() {
    local total=$((PASS + FAIL))
    echo
    echo "=========================================="
    if (( FAIL == 0 )); then
        echo -e "${GREEN}All ${total} checks passed.${NC}"
    else
        echo -e "${RED}${FAIL} of ${total} checks failed.${NC}"
    fi
    echo "=========================================="
    (( FAIL == 0 )) || exit 1
    exit 0
}
