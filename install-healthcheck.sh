#!/bin/bash
################################################################################
# WireGuard healthcheck timer installer
# Description: Install (or refresh) the healthcheck / auto-recovery timer,
#              pointed at wherever THIS repo actually lives. The unit's
#              ExecStart/Documentation paths are rewritten at install time from
#              this script's own location, so nothing is locked to a hardcoded
#              path — move the repo and re-run to re-point the units.
#
# This installs the AVAILABILITY control only (is the tunnel up; restart it if
# not). The audit-logging control is installed separately by
# install-logging.sh — they are split so a compliance install and an
# availability install can be reasoned about, enabled, and verified apart.
#
# Idempotent: systemd identifies units by filename, so re-running overwrites
# them in place and re-enabling is a no-op.
#
# Usage:
#   sudo ./install-healthcheck.sh              # install/refresh + enable
#   sudo ./install-healthcheck.sh --uninstall  # stop, disable, remove units
#   sudo ./install-healthcheck.sh --status     # show timer state
################################################################################

set -uo pipefail

REPO_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
source "${REPO_DIR}/utils.sh"

BASE="wireguard-healthcheck"

install_units() {
    unit_warn_on_cron "healthcheck.sh"
    unit_install_service "$REPO_DIR" "$BASE"
    unit_install_timer   "$REPO_DIR" "$BASE"
    unit_enable_timer    "$BASE"
    print_success "Healthcheck timer enabled — unit points at ${REPO_DIR}"
    echo
    systemctl list-timers "${BASE}.timer" --all --no-pager
}

show_status() {
    systemctl list-timers "${BASE}.timer" --all --no-pager
    echo
    systemctl status "${BASE}.service" --no-pager -n 5 2>/dev/null || true
}

main() {
    check_root
    case "${1:-}" in
        --uninstall) unit_remove "$BASE"
                     print_success "Uninstalled. (Scripts in ${REPO_DIR} are left untouched.)" ;;
        --status)    show_status ;;
        "")          install_units ;;
        *)           die "Unknown option: $1 (use --uninstall, --status, or no args)" ;;
    esac
}

main "$@"
