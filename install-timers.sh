#!/bin/bash
################################################################################
# WireGuard timer installer
# Description: Install (or refresh) the healthcheck + connection-log systemd
#              units, pointed at wherever THIS repo actually lives. The unit
#              ExecStart/Documentation paths are rewritten at install time from
#              the script's own location, so you are NOT locked to any hardcoded
#              path — move the repo anywhere and re-run this to update.
#
# Idempotent: systemd identifies units by filename, so re-running overwrites the
# existing units in place (never a duplicate) and re-enabling is a no-op. Safe to
# run after moving the repo or pulling changes.
#
# Usage:
#   sudo ./install-timers.sh              # install/refresh + enable + start
#   sudo ./install-timers.sh --uninstall  # stop, disable, and remove the units
################################################################################

set -uo pipefail

REPO_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
source "${REPO_DIR}/utils.sh"

UNIT_SRC="${REPO_DIR}/systemd"
UNIT_DST="/etc/systemd/system"
TIMERS=(wireguard-healthcheck.timer wireguard-log-connections.timer)
SERVICES=(wireguard-healthcheck.service wireguard-log-connections.service)

uninstall() {
    print_info "Removing WireGuard timers/services from ${UNIT_DST} ..."
    systemctl disable --now "${TIMERS[@]}" 2>/dev/null || true
    local u
    for u in "${TIMERS[@]}" "${SERVICES[@]}"; do
        rm -f "${UNIT_DST}/${u}" && print_success "removed ${u}"
    done
    systemctl daemon-reload
    print_success "Uninstalled. (Scripts in ${REPO_DIR} are left untouched.)"
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
    if [[ "${1:-}" == "--uninstall" ]]; then
        uninstall
    elif [[ -z "${1:-}" ]]; then
        install
    else
        die "Unknown option: $1 (use --uninstall, or no args to install)"
    fi
}

main "$@"
