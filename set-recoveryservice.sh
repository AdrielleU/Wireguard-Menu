#!/bin/bash
################################################################################
# WireGuard recovery-service installer
# Description: Install (or refresh) the WireGuard monitoring services — the
#              healthcheck/auto-recovery timer AND the connection-audit-log
#              timer — pointed at wherever THIS repo actually lives. The unit
#              ExecStart/Documentation paths are rewritten at install time from
#              the script's own location, so you are NOT locked to any hardcoded
#              path — move the repo anywhere and re-run this to update.
#
# Idempotent: systemd identifies units by filename, so re-running overwrites the
# existing units in place (never a duplicate) and re-enabling is a no-op. Safe to
# run after moving the repo or pulling changes.
#
# Usage:
#   sudo ./set-recoveryservice.sh                   # install/refresh + enable
#   sudo ./set-recoveryservice.sh --with-retention  # ... and extend journal retention
#   sudo ./set-recoveryservice.sh --uninstall       # stop, disable, remove units
################################################################################

set -uo pipefail

REPO_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
source "${REPO_DIR}/utils.sh"

UNIT_SRC="${REPO_DIR}/systemd"
UNIT_DST="/etc/systemd/system"
TIMERS=(wireguard-healthcheck.timer wireguard-log-connections.timer)
SERVICES=(wireguard-healthcheck.service wireguard-log-connections.service)
JOURNALD_DROPIN="journald-wireguard-audit.conf"
JOURNALD_DST="/etc/systemd/journald.conf.d"

# Opt-in: this widens retention for the WHOLE journal (it is not per-tag) and
# restarts systemd-journald, so it is never applied by a bare install.
install_retention() {
    [[ -f "${UNIT_SRC}/${JOURNALD_DROPIN}" ]] || die "Missing ${UNIT_SRC}/${JOURNALD_DROPIN}"
    mkdir -p "$JOURNALD_DST"
    install -m 0644 "${UNIT_SRC}/${JOURNALD_DROPIN}" "${JOURNALD_DST}/${JOURNALD_DROPIN}" \
        || die "Failed to install ${JOURNALD_DROPIN}"
    print_success "installed ${JOURNALD_DST}/${JOURNALD_DROPIN}"
    if systemctl restart systemd-journald; then
        print_success "journald restarted — retention now:"
        journalctl --no-pager --header 2>/dev/null | grep -iE '^(Disk usage|Max use)' || true
        journalctl --disk-usage 2>/dev/null || true
    else
        print_warning "journald restart failed — the drop-in applies at next boot"
    fi
}

uninstall() {
    print_info "Removing WireGuard timers/services from ${UNIT_DST} ..."
    systemctl disable --now "${TIMERS[@]}" 2>/dev/null || true
    local u
    for u in "${TIMERS[@]}" "${SERVICES[@]}"; do
        rm -f "${UNIT_DST}/${u}" && print_success "removed ${u}"
    done
    systemctl daemon-reload
    print_success "Uninstalled. (Scripts in ${REPO_DIR} are left untouched.)"
    # Deliberately NOT removed: shrinking retention here would discard existing
    # audit history, which is the opposite of what an uninstall should risk.
    if [[ -f "${JOURNALD_DST}/${JOURNALD_DROPIN}" ]]; then
        print_info "Journal retention drop-in left in place: ${JOURNALD_DST}/${JOURNALD_DROPIN}"
        print_info "Remove it manually (then restart systemd-journald) to revert retention."
    fi
}

install() {
    [[ -d "$UNIT_SRC" ]] || die "No systemd/ directory in ${REPO_DIR}"
    case "$REPO_DIR" in *'#'*) die "Repo path contains '#', which breaks unit rewriting: ${REPO_DIR}";; esac

    # A stray cron entry running the same script would double-execute alongside
    # the timer — the one real double-run trap. Warn, don't fail.
    if { crontab -l 2>/dev/null; cat /etc/cron.d/* /etc/crontab 2>/dev/null; } \
         | grep -Eq '(healthcheck|log-connections)\.sh'; then
        print_warning "A cron entry references these scripts — it will double-run alongside the timer. Remove the cron line or the timer, not both."
    fi

    # Install services, rewriting the ExecStart/Documentation paths to THIS repo
    # so the location is defined by where the repo lives, not a baked-in path.
    local svc
    for svc in "${SERVICES[@]}"; do
        [[ -f "${UNIT_SRC}/${svc}" ]] || die "Missing ${UNIT_SRC}/${svc}"
        sed -E \
            -e "s#^ExecStart=[^ ]*/(healthcheck|log-connections)\.sh#ExecStart=${REPO_DIR}/\1.sh#" \
            -e "s#^Documentation=file://[^ ]*/(healthcheck|log-connections)\.sh#Documentation=file://${REPO_DIR}/\1.sh#" \
            "${UNIT_SRC}/${svc}" > "${UNIT_DST}/${svc}" \
            || die "Failed to write ${UNIT_DST}/${svc}"
        print_success "installed ${svc}"
    done

    # Timers copy verbatim (no paths inside them).
    local t
    for t in "${TIMERS[@]}"; do
        [[ -f "${UNIT_SRC}/${t}" ]] || die "Missing ${UNIT_SRC}/${t}"
        cp "${UNIT_SRC}/${t}" "${UNIT_DST}/${t}" || die "Failed to copy ${t}"
        print_success "installed ${t}"
    done

    systemctl daemon-reload
    systemctl enable "${TIMERS[@]}" >/dev/null 2>&1
    # restart (not just start) so a changed interval takes effect immediately
    systemctl restart "${TIMERS[@]}"

    print_success "Timers enabled and scheduled — units point at ${REPO_DIR}"
    echo
    systemctl list-timers 'wireguard-*' --all --no-pager
}

main() {
    check_root
    case "${1:-}" in
        --uninstall)      uninstall ;;
        --with-retention) install; echo; install_retention ;;
        "")               install ;;
        *)                die "Unknown option: $1 (use --with-retention, --uninstall, or no args)" ;;
    esac
}

main "$@"
