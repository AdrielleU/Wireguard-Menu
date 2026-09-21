#!/bin/bash
################################################################################
# WireGuard timer installer — availability and audit
# Description: Install (or refresh) both background controls, pointed at
#              wherever THIS repo actually lives. Each unit's ExecStart and
#              Documentation paths are rewritten at install time from this
#              script's own location, so nothing is locked to a hardcoded path
#              — move the repo and re-run to re-point the units.
#
# Two controls, installed together because in practice every deployment wants
# both:
#
#   availability  healthcheck.sh       is the tunnel up; restart it if not
#   audit         log-connections.sh   the connect/disconnect trail, plus the
#                                      rsyslog rule and logrotate policy that
#                                      give it one file and one retention window
#
# They remain separable — --healthcheck-only and --logging-only install one
# without the other, so a compliance install and an availability install can
# still be reasoned about apart. This was two scripts; they shared their whole
# skeleton and every documented procedure ran them back to back.
#
# The trail lands in ONE file, /var/log/wireguard.log, via an rsyslog rule that
# routes this toolkit's single "wireguard" tag there. Its retention is decided
# in ONE place, the logrotate policy written alongside it, and --check-retention
# reports what that policy actually holds.
#
# Idempotent: systemd identifies units by filename, so re-running overwrites
# them in place and re-enabling is a no-op. Re-running is also how you push an
# update after copying newer scripts.
#
# A preflight runs first and stops the install on any error: wireguard-tools
# missing, no WireGuard instance on the host, a tunnel running outside
# wg-quick@<iface> (the healthcheck would read it as dead every minute),
# scripts others can write to (the timers run them as root), or
# verify-config.sh errors. Warnings (tunnel down, not enabled at boot, no ping
# or logrotate) never stop it. --force installs despite errors.
#
# --dry-run makes every check the install would (the preflight, the units
# exist, each unit's script is executable, no cron entry double-runs it) but
# writes nothing and runs no systemctl. It combines with every other flag.
#
# Usage:
#   sudo ./install.sh                     # install/refresh + enable both
#   sudo ./install.sh --dry-run           # show what that would do; change nothing
#   sudo ./install.sh --force             # install even if the preflight fails
#   sudo ./install.sh --healthcheck-only  # availability control only
#   sudo ./install.sh --logging-only      # audit control only
#   sudo ./install.sh --check-retention   # what the trail actually holds
#   sudo ./install.sh --status            # timer state + retention
#   sudo ./install.sh --uninstall         # stop, disable, remove units
################################################################################

set -uo pipefail

REPO_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
source "${REPO_DIR}/utils.sh"

# base name -> the script its unit runs, for the cron double-run warning
HEALTHCHECK_BASE="wireguard-healthcheck"
LOGGING_BASE="wireguard-log-connections"

DRY_RUN=false
FORCE=false
DO_HEALTHCHECK=true
DO_LOGGING=true

# The dedicated log file, its rsyslog rule and its logrotate policy: where the
# trail lives and where its retention is set. All overridable so the install can
# be exercised against throwaway directories.
RSYSLOG_DST="${RSYSLOG_DST:-/etc/rsyslog.d}"
RSYSLOG_DST_NAME="49-wireguard.conf"
LOGROTATE_DST="${LOGROTATE_DST:-/etc/logrotate.d}"
LOGROTATE_DST_NAME="wireguard"
WG_LOG_FILE="${WG_LOG_FILE:-/var/log/wireguard.log}"

# The connection logger's state directory. Not optional: its unit sets
# ProtectSystem=strict with ReadWritePaths pointing here, and systemd REFUSES to
# start a unit whose ReadWritePaths does not exist -- so on a fresh host the
# service fails on every tick, and log-connections.sh can never create the
# directory itself because it never gets to run. Verified with a transient unit:
# missing -> Result=exit-code, present -> Result=success.
CONN_STATE_DIR="${WIREGUARD_CONN_STATE_DIR:-/var/lib/wireguard-connections}"

# The window the audit trail is expected to cover. HIPAA §164.316(b)(2)(i) is
# 6 years; override for a different regime.
RETENTION_TARGET_DAYS="${RETENTION_TARGET_DAYS:-2192}"

################################################################################
# THE TRAIL: ROUTING AND RETENTION
################################################################################

# The rsyslog rule and the logrotate policy are GENERATED, not shipped as files.
#
# They were shipped, in syslog/. But both hardcoded /var/log/wireguard.log while
# the installer also had WG_LOG_FILE, and the logrotate policy hardcoded
# "rotate 320" while the installer also had RETENTION_TARGET_DAYS -- so the log
# path lived in three places and the window in two, free to drift apart. Writing
# them here makes each value have exactly one source. Between them they are 17
# lines of actual configuration; a directory and two files to hold that was more
# structure than it earned.
#
# --dry-run prints both in full, so they can still be read before they land.

# Weekly rotation, so the number of copies IS the window in weeks.
rotate_count() { echo $(( (RETENTION_TARGET_DAYS + 6) / 7 )); }

rsyslog_rule_text() {
    cat <<EOF
# Route everything the WireGuard toolkit logs to one file.
# Generated by install.sh -- edit there, not here; a re-run overwrites this.
#
# The scripts emit a single tag ("wireguard") on facility local0, the range
# syslog reserves for custom applications. Without this rule those records land
# in /var/log/messages alongside every other service.
#
# The trailing "stop" keeps them OUT of the shared logs, so this file is the
# whole trail. Drop it if you would rather have a copy in both. journald keeps
# its own copy either way, so \`journalctl -t wireguard\` works regardless.
if (\$programname == "wireguard") then {
    action(type="omfile" file="${WG_LOG_FILE}" fileCreateMode="0600")
    stop
}
EOF
}

logrotate_policy_text() {
    cat <<EOF
# Retention for the WireGuard audit trail.
# Generated by install.sh -- edit there, not here; a re-run overwrites this.
#
# This is the one place retention is decided. Rotation is weekly, so the number
# of copies is the window in weeks: $(rotate_count) copies ~ ${RETENTION_TARGET_DAYS} days,
# which is where RETENTION_TARGET_DAYS points (HIPAA 164.316(b)(2)(i) is 6 years).
#
# Check what the host actually holds:  install.sh --check-retention
#
# Six years on a single box is optimistic whatever the number says -- disks fail
# and hosts get rebuilt. Treat this as the local buffer and ship the file to a
# central log store if the trail has to outlive the machine.
${WG_LOG_FILE} {
    weekly
    rotate $(rotate_count)
    compress
    delaycompress
    missingok
    notifempty
    create 0600 root root
    sharedscripts
    postrotate
        /usr/bin/systemctl -s HUP kill rsyslog.service >/dev/null 2>&1 || true
    endscript
}
EOF
}

# Write the routing rule and the rotation policy. This changes nothing
# host-wide: one rule for one tag, one policy for one file.
install_log_routing() {
    if $DRY_RUN; then
        echo "  would install ${RSYSLOG_DST}/${RSYSLOG_DST_NAME}:"
        rsyslog_rule_text | sed 's/^/      /'
        echo "  would install ${LOGROTATE_DST}/${LOGROTATE_DST_NAME}:"
        logrotate_policy_text | sed 's/^/      /'
        echo "  would run: systemctl restart rsyslog"
        return 0
    fi

    if ! systemctl list-unit-files rsyslog.service &>/dev/null; then
        print_warning "rsyslog is not installed, so ${WG_LOG_FILE} will not be written. Records still go to the journal — query them with: journalctl -t wireguard"
        return 0
    fi

    mkdir -p "$RSYSLOG_DST" "$LOGROTATE_DST"
    rsyslog_rule_text > "${RSYSLOG_DST}/${RSYSLOG_DST_NAME}" \
        || die "Failed to write ${RSYSLOG_DST}/${RSYSLOG_DST_NAME}"
    chmod 0644 "${RSYSLOG_DST}/${RSYSLOG_DST_NAME}"
    print_success "installed ${RSYSLOG_DST}/${RSYSLOG_DST_NAME}"

    logrotate_policy_text > "${LOGROTATE_DST}/${LOGROTATE_DST_NAME}" \
        || die "Failed to write ${LOGROTATE_DST}/${LOGROTATE_DST_NAME}"
    chmod 0644 "${LOGROTATE_DST}/${LOGROTATE_DST_NAME}"
    print_success "installed ${LOGROTATE_DST}/${LOGROTATE_DST_NAME} (weekly x $(rotate_count) ~ ${RETENTION_TARGET_DAYS} days)"

    # logrotate refuses a config that is group- or world-writable, so check
    # rather than let rotation silently never happen.
    if ! logrotate --debug "${LOGROTATE_DST}/${LOGROTATE_DST_NAME}" &>/dev/null; then
        print_warning "logrotate rejected ${LOGROTATE_DST}/${LOGROTATE_DST_NAME}; check it with: logrotate --debug ${LOGROTATE_DST}/${LOGROTATE_DST_NAME}"
    fi

    if systemctl restart rsyslog; then
        print_success "rsyslog restarted — the trail now goes to ${WG_LOG_FILE}"
    else
        print_warning "rsyslog restart failed; ${WG_LOG_FILE} will not fill until it is restarted"
    fi
}

human() {   # bytes -> human, one decimal
    awk -v b="$1" 'BEGIN{
        split("B KB MB GB TB", u, " "); i=1
        while (b >= 1024 && i < 5) { b /= 1024; i++ }
        printf "%.1f%s", b, u[i]
    }'
}

# Read the rotation window out of the installed logrotate policy: how many
# copies it keeps, and how often it rotates. Echoes "<days> <description>", or
# nothing if the policy is not installed or cannot be read.
#
# This is deliberately the whole retention model now. It used to be derived from
# journald's SystemMaxUse against measured journal growth, which meant reasoning
# about a host-wide setting, a free-disk ceiling, SystemKeepFree, and a
# volatile/persistent distinction -- to answer a question logrotate already
# answers exactly, for this file alone.
logrotate_window() {
    local conf="${LOGROTATE_DST}/${LOGROTATE_DST_NAME}"
    [[ -f "$conf" ]] || return 1

    local count freq per
    count=$(awk '/^[[:space:]]*rotate[[:space:]]+[0-9]+/ { print $2; exit }' "$conf")
    [[ "$count" =~ ^[0-9]+$ ]] || return 1

    freq=$(awk '/^[[:space:]]*(hourly|daily|weekly|monthly|yearly)[[:space:]]*$/ { gsub(/[[:space:]]/,""); print; exit }' "$conf")
    case "$freq" in
        hourly)  per=1;   freq="hourly (counted as daily)" ;;
        daily)   per=1    ;;
        weekly)  per=7    ;;
        monthly) per=30   ;;
        yearly)  per=365  ;;
        *)       return 1 ;;
    esac
    echo "$(( count * per )) ${freq} x ${count}"
}

# Total bytes the trail occupies, current file plus rotated copies.
trail_bytes() {
    local total=0 f sz
    for f in "$WG_LOG_FILE" "$WG_LOG_FILE"-* "$WG_LOG_FILE".*; do
        [[ -f "$f" ]] || continue
        sz=$(stat -c %s "$f" 2>/dev/null) || continue
        total=$(( total + sz ))
    done
    echo "$total"
}

# Days between the oldest rotated copy and now. Echoes nothing when nothing has
# rotated yet, which is the honest answer rather than extrapolating from one
# partial file.
trail_span_days() {
    local oldest ts
    oldest=$(ls -1t "$WG_LOG_FILE"-* "$WG_LOG_FILE".* 2>/dev/null | tail -n1)
    [[ -n "$oldest" ]] || return 1
    ts=$(stat -c %Y "$oldest" 2>/dev/null) || return 1
    echo $(( ( $(date +%s) - ts ) / 86400 ))
}

# What the trail actually holds, and whether that meets the target. One file, one
# rotation policy, no host-wide settings involved.
check_retention() {
    echo
    echo -e "${CYAN}== audit trail retention ==${NC}"

    local bytes; bytes=$(trail_bytes)
    if [[ ! -f "$WG_LOG_FILE" ]]; then
        printf '  %-9s %s\n' "file" "${WG_LOG_FILE} — not created yet"
        if ! systemctl is-active --quiet rsyslog 2>/dev/null; then
            print_warning "rsyslog is not running, so nothing writes ${WG_LOG_FILE}. Records still reach the journal — query them with: journalctl -t wireguard"
        else
            print_info "Nothing has been logged yet. The file appears on the first record; rsyslog polls the journal, so allow a few seconds."
        fi
        return 0
    fi
    printf '  %-9s %-22s %s\n' "file" "$WG_LOG_FILE" "$(human "$bytes") including rotated copies"

    local window days desc
    if window=$(logrotate_window); then
        days=${window%% *}; desc=${window#* }
        printf '  %-9s %-22s %s\n' "keeping" "$desc" "= ~${days} days"
    else
        print_warning "No readable rotate/frequency in ${LOGROTATE_DST}/${LOGROTATE_DST_NAME}, so the window cannot be confirmed. Re-run this installer to reinstall the policy."
        return 1
    fi

    local span rate
    if span=$(trail_span_days) && (( span > 0 )); then
        rate=$(( bytes / span ))
        printf '  %-9s %-22s %s\n' "writing" "~$(human "$rate")/day" "(measured over ${span} days)"
        printf '  %-9s %-22s %s\n' "needs" "~$(human $(( rate * days )))" "to hold the full window"
    else
        printf '  %-9s %-22s %s\n' "writing" "not measurable yet" "(nothing has rotated)"
    fi

    printf '  %-9s %s\n' "target" "${RETENTION_TARGET_DAYS} days"
    echo

    if (( days >= RETENTION_TARGET_DAYS )); then
        print_success "Rotation holds ~${days} days, past the ${RETENTION_TARGET_DAYS}-day target."
        return 0
    fi
    print_error "Rotation holds ~${days} days, short of the ${RETENTION_TARGET_DAYS}-day target."
    echo "    Raise 'rotate' in ${LOGROTATE_DST}/${LOGROTATE_DST_NAME} — at the current"
    echo "    frequency you need about $(( (RETENTION_TARGET_DAYS + 6) / 7 )) weekly copies."
    echo "    Six years on one host is optimistic whatever the number says: ship the"
    echo "    file to a central log store if the trail has to outlive the machine."
    return 1
}

################################################################################
# PREFLIGHT
################################################################################

# Is this a host the timers can do anything useful on? Runs before anything is
# written. The case it exists for: timers installed on a box with no WireGuard
# run every minute forever, check nothing, and look just like a healthy
# install.
#
# pf_fail stops the install (--force installs anyway); a warning never does.
PREFLIGHT_ERRORS=0
pf_fail() { PREFLIGHT_ERRORS=$((PREFLIGHT_ERRORS + 1)); print_error "$1"; }

preflight() {
    echo -e "${CYAN}== preflight ==${NC}"

    # logger is here because _audit_emit skips silently without it: every
    # record, heartbeat included, would vanish with no error anywhere.
    local c missing=()
    for c in wg wg-quick ip logger; do
        command -v "$c" &>/dev/null || missing+=("$c")
    done
    if (( ${#missing[@]} > 0 )); then
        pf_fail "missing command(s): ${missing[*]} — install wireguard-tools, iproute2 and util-linux first"
        return
    fi
    print_success "wg, wg-quick, ip and logger are installed"
    if $DO_HEALTHCHECK && ! command -v ping &>/dev/null; then
        print_warning "ping is not installed, so Healthcheck-Reachability is skipped and a tunnel that is up but passing no traffic goes unnoticed"
    fi
    if $DO_LOGGING && ! command -v logrotate &>/dev/null; then
        print_warning "logrotate is not installed, so ${WG_LOG_FILE} will never rotate"
    fi

    # The timers run these as root, so anyone who can write to them is root.
    local f bad=()
    for f in "$REPO_DIR" "${REPO_DIR}/healthcheck.sh" "${REPO_DIR}/log-connections.sh" "${REPO_DIR}/utils.sh"; do
        [[ -e "$f" ]] || continue
        [[ "$(stat -c %u "$f")" == 0 ]] && (( ( 8#$(stat -c %a "$f") & 8#022 ) == 0 )) || bad+=("$f")
    done
    if (( ${#bad[@]} > 0 )); then
        pf_fail "not root-owned, or writable by group/others: ${bad[*]}. The timers run these as root. Fix: chown root:root and chmod go-w"
    else
        print_success "scripts are root-owned and not writable by others"
    fi

    local -a instances
    mapfile -t instances < <(detect_servers)
    if (( ${#instances[@]} == 0 )); then
        pf_fail "no WireGuard instance on this host: no ${WG_CONFIG_DIR}/*.conf and no interface running. Set up the tunnel first (README: Start Here), then re-run"
        return
    fi

    # The healthcheck judges a tunnel by its wg-quick@<iface> service alone, so
    # anything running outside that service reads to it as dead.
    local iface up svc
    for iface in "${instances[@]}"; do
        up=false;  ip link show "$iface" &>/dev/null && up=true
        svc=false; systemctl is-active --quiet "wg-quick@${iface}" && svc=true

        if [[ ! -f "${WG_CONFIG_DIR}/${iface}.conf" ]]; then
            pf_fail "${iface}: running, but there is no ${WG_CONFIG_DIR}/${iface}.conf, so wg-quick does not manage it. The healthcheck would report it dead every minute and every restart would fail"
        elif $up && ! $svc; then
            pf_fail "${iface}: up, but not through wg-quick@${iface} (started by hand with 'wg-quick up'?). The healthcheck would report it dead every minute, and its restart fails because ${iface} already exists. Fix: wg-quick down ${iface} && systemctl enable --now wg-quick@${iface}"
        elif ! $up; then
            print_warning "${iface}: tunnel is down. Once installed, the healthcheck starts it within a minute on a site/client box, or reports it failed every minute on a server. Bring it up: systemctl enable wg-quick@${iface} && systemctl restart wg-quick@${iface}"
        elif ! systemctl is-enabled --quiet "wg-quick@${iface}" 2>/dev/null; then
            print_warning "${iface}: running, but wg-quick@${iface} is not enabled, so it will not come back after a reboot. Fix: systemctl enable wg-quick@${iface}"
        else
            print_success "${iface}: running under wg-quick@${iface}, enabled at boot"
        fi
    done

    # The healthcheck's restart policy comes from the declarations this checks:
    # an error here can be a server with no Role line, which --restart treats as
    # restartable.
    local vc="${REPO_DIR}/verify-config.sh" report nwarn
    if [[ ! -x "$vc" ]]; then
        print_warning "no executable ${vc}, so the configs were not checked"
    elif report=$("$vc" --all --quiet 2>&1); then
        nwarn=$(grep -c '^ *warn ' <<<"$report")
        if (( nwarn > 0 )); then
            print_success "verify-config.sh: no errors, ${nwarn} warning(s) (run verify-config.sh --all to see them)"
        else
            print_success "verify-config.sh: no errors"
        fi
    else
        sed 's/^/    /' <<<"$report" >&2
        if $DO_HEALTHCHECK; then
            pf_fail "verify-config.sh found errors (above). Fix them before installing the healthcheck: its restart policy comes from these declarations"
        else
            print_warning "verify-config.sh found errors (above)"
        fi
    fi
}

################################################################################
# PATHS
################################################################################

# Create what the units and scripts need, and NEVER touch anything already
# there. Every branch checks first: an existing log file holds the audit trail
# and an existing state directory holds the connection tracking, so recreating
# either would silently destroy live data on a re-run -- and re-running is the
# documented way to apply an update.
ensure_paths() {
    local made=false

    if [[ ! -d "$CONN_STATE_DIR" ]]; then
        if $DRY_RUN; then
            echo "  would create ${CONN_STATE_DIR} (mode 700) — the logger unit cannot start without it"
        else
            mkdir -p "$CONN_STATE_DIR" || die "Failed to create ${CONN_STATE_DIR}"
            chmod 700 "$CONN_STATE_DIR"
            print_success "created ${CONN_STATE_DIR} (mode 700)"
        fi
        made=true
    fi

    # rsyslog creates the log file itself on the first record, but only once one
    # arrives -- on a quiet box that can be a long wait, leaving --check-retention
    # with nothing to report. Creating it empty makes the state deterministic.
    # Guarded by -e, not -f: a symlink or anything else already at that path is
    # somebody's decision, not ours to replace.
    if [[ ! -e "$WG_LOG_FILE" ]]; then
        if $DRY_RUN; then
            echo "  would create empty ${WG_LOG_FILE} (mode 600)"
        else
            install -m 0600 /dev/null "$WG_LOG_FILE" || die "Failed to create ${WG_LOG_FILE}"
            print_success "created ${WG_LOG_FILE} (mode 600)"
        fi
        made=true
    fi

    $made || print_info "Paths already present — nothing created, nothing touched."
}

################################################################################
# UNITS
################################################################################

# One control's units. The two differ only in their base name and which script
# the cron warning names, which is why this is one function and not two scripts.
install_control() {
    local base="$1" script="$2" label="$3"
    unit_warn_on_cron "$script"
    unit_install_service "$REPO_DIR" "$base"
    unit_install_timer   "$REPO_DIR" "$base"
    unit_enable_timer    "$base"
    $DRY_RUN && return 0
    print_success "${label} timer enabled — unit points at ${REPO_DIR}"
}

install_all() {
    preflight
    if (( PREFLIGHT_ERRORS > 0 )); then
        $FORCE || die "Preflight found ${PREFLIGHT_ERRORS} error(s); nothing was installed. Fix them, or re-run with --force to install anyway"
        print_warning "--force: installing despite ${PREFLIGHT_ERRORS} preflight error(s)"
    fi
    echo

    # Before any unit is enabled: the logger's unit will not start at all if its
    # state directory is missing.
    ensure_paths
    echo

    if $DO_HEALTHCHECK; then
        echo -e "${CYAN}== availability (healthcheck) ==${NC}"
        install_control "$HEALTHCHECK_BASE" healthcheck.sh "Healthcheck"
        echo
    fi

    if $DO_LOGGING; then
        echo -e "${CYAN}== audit (connection trail) ==${NC}"
        install_control "$LOGGING_BASE" log-connections.sh "Audit-log"
        # The routing rule and its rotation policy ARE the trail, so they go in
        # with the timer. Neither touches any other service on the host.
        install_log_routing
        echo
    fi

    if $DRY_RUN; then
        print_info "Dry run: checks passed, nothing was changed. (--check-retention reports what the trail holds.)"
        return 0
    fi

    systemctl list-timers 'wireguard-*' --all --no-pager
    $DO_LOGGING && check_retention
    return 0
}

uninstall_all() {
    $DO_HEALTHCHECK && unit_remove "$HEALTHCHECK_BASE"
    $DO_LOGGING     && unit_remove "$LOGGING_BASE"

    if $DRY_RUN; then
        print_info "Dry run: nothing was changed."
        return 0
    fi
    print_success "Uninstalled. (Scripts in ${REPO_DIR} are left untouched.)"
    $DO_LOGGING || return 0

    # The routing rule goes: with it gone nothing new is written to the file and
    # records fall back to the journal. The FILE and its rotated copies stay --
    # deleting an audit trail is not something an uninstall should do on its own
    # -- and the logrotate policy stays with it so what is there keeps rotating
    # rather than growing forever.
    if [[ -f "${RSYSLOG_DST}/${RSYSLOG_DST_NAME}" ]]; then
        if rm -f "${RSYSLOG_DST}/${RSYSLOG_DST_NAME}"; then
            print_success "removed ${RSYSLOG_DST}/${RSYSLOG_DST_NAME}"
            systemctl restart rsyslog 2>/dev/null \
                || print_warning "rsyslog restart failed; it holds the old rule until restarted"
        fi
    fi
    if [[ -f "$WG_LOG_FILE" ]]; then
        print_info "Audit trail left in place: ${WG_LOG_FILE} (${LOGROTATE_DST}/${LOGROTATE_DST_NAME} still rotates it)"
        print_info "Delete both by hand if you really mean to discard the trail."
    fi
}

show_status() {
    systemctl list-timers 'wireguard-*' --all --no-pager
    echo
    local n
    n=$(journalctl -t wireguard --no-pager 2>/dev/null | grep -c . || true)
    print_info "audit records currently in the journal: ${n:-0}"
    [[ -f "$WG_LOG_FILE" ]] && print_info "trail file: ${WG_LOG_FILE} ($(wc -l < "$WG_LOG_FILE") lines)"
    check_retention
}

main() {
    check_root
    check_systemd
    local action="install" arg
    for arg in "$@"; do
        case "$arg" in
            --dry-run)          DRY_RUN=true ;;
            --force)            FORCE=true ;;
            --healthcheck-only) DO_LOGGING=false ;;
            --logging-only)     DO_HEALTHCHECK=false ;;
            --check-retention)  action="check" ;;
            --status)           action="status" ;;
            --uninstall)        action="uninstall" ;;
            *)                  die "Unknown option: $arg (use --dry-run, --force, --healthcheck-only, --logging-only, --check-retention, --status, --uninstall, or no args)" ;;
        esac
    done

    case "$action" in
        check)     check_retention ;;
        status)    show_status ;;
        uninstall) uninstall_all ;;
        install)   install_all ;;
    esac
}

main "$@"
