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
# --dry-run makes every check the install would (the unit's script exists and
# is executable, no cron entry double-runs it) but writes nothing and runs no
# systemctl. It also combines with --uninstall.
#
# Usage:
#   sudo ./install-healthcheck.sh              # install/refresh + enable
#   sudo ./install-healthcheck.sh --dry-run    # show what that would do; change nothing
#   sudo ./install-healthcheck.sh --uninstall  # stop, disable, remove units
#   sudo ./install-healthcheck.sh --status     # show timer state
################################################################################

set -uo pipefail

REPO_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
source "${REPO_DIR}/utils.sh"

BASE="wireguard-healthcheck"
DRY_RUN=false

install_units() {
    unit_warn_on_cron "healthcheck.sh"
    unit_install_service "$REPO_DIR" "$BASE"
    unit_install_timer   "$REPO_DIR" "$BASE"
    unit_enable_timer    "$BASE"
    if $DRY_RUN; then
        print_info "Dry run: checks passed, nothing was changed."
        return
    fi
    print_success "Healthcheck timer enabled — unit points at ${REPO_DIR}"
    echo
    systemctl list-timers "${BASE}.timer" --all --no-pager
}

show_status() {
    systemctl list-timers "${BASE}.timer" --all --no-pager
    echo
    systemctl status "${BASE}.service" --no-pager -n 5 2>/dev/null || true
}

uninstall_units() {
    unit_remove "$BASE"
    if $DRY_RUN; then
        print_info "Dry run: nothing was changed."
    else
        print_success "Uninstalled. (Scripts in ${REPO_DIR} are left untouched.)"
    fi
}

main() {
    check_root
    check_systemd
    local action="install" arg
    for arg in "$@"; do
        case "$arg" in
            --dry-run)   DRY_RUN=true ;;
            --uninstall) action="uninstall" ;;
            --status)    action="status" ;;
            *)           die "Unknown option: $arg (use --dry-run, --uninstall, --status, or no args)" ;;
        esac
    done

    case "$action" in
        install)   install_units ;;
        uninstall) uninstall_units ;;
        status)    show_status ;;
    esac
}

main "$@"
