#!/bin/bash
################################################################################
# WireGuard connection-audit logger installer
# Description: Install (or refresh) the connection audit-log timer, pointed at
#              wherever THIS repo actually lives. The unit's ExecStart/
#              Documentation paths are rewritten at install time from this
#              script's own location, so nothing is locked to a hardcoded path.
#
# This installs the AUDIT control — the connect/disconnect trail that
# §164.312(b) asks for. It is deliberately separate from install-healthcheck.sh
# (the availability control) so a compliance install can be enabled, verified
# and reported on without dragging in auto-restart behaviour, and vice versa.
#
# Retention is the part that actually decides whether the trail survives long
# enough to be worth anything. journald retention is host-wide and SIZE WINS
# OVER AGE: once SystemMaxUse is reached the oldest entries are dropped however
# short of MaxRetentionSec they are. So --check-retention measures this host's
# real journal growth and projects whether the configured cap can hold the
# window you are aiming for. Run it after install, and again whenever the
# host's logging volume changes.
#
# Idempotent: systemd identifies units by filename, so re-running overwrites
# them in place and re-enabling is a no-op.
#
# --dry-run makes every check the install would (the units exist, the unit's
# script is executable, no cron entry double-runs it) but writes nothing, runs
# no systemctl and skips the retention projection. It combines with
# --with-retention and --uninstall.
#
# Usage:
#   sudo ./install-logging.sh                   # install/refresh + enable
#   sudo ./install-logging.sh --with-retention  # ... and widen journal retention
#   sudo ./install-logging.sh --dry-run         # show what an install would do; change nothing
#   sudo ./install-logging.sh --check-retention # project the achievable window
#   sudo ./install-logging.sh --status          # timer state + retention check
#   sudo ./install-logging.sh --uninstall       # stop, disable, remove units
################################################################################

set -uo pipefail

REPO_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
source "${REPO_DIR}/utils.sh"

BASE="wireguard-log-connections"
DRY_RUN=false
JOURNALD_DROPIN="journald-wireguard-audit.conf"
# Overridable like UNIT_DST, so the retention install can be exercised against
# a throwaway directory instead of the host's journald config.
JOURNALD_DST="${JOURNALD_DST:-/etc/systemd/journald.conf.d}"

# The window the audit trail is expected to cover. HIPAA §164.316(b)(2)(i) is
# 6 years; override for a different regime.
RETENTION_TARGET_DAYS="${RETENTION_TARGET_DAYS:-2192}"

################################################################################
# RETENTION
################################################################################

# Opt-in: this widens retention for the WHOLE journal (it is not per-tag) and
# restarts systemd-journald, so it is never applied by a bare install.
install_retention() {
    [[ -f "${REPO_DIR}/systemd/${JOURNALD_DROPIN}" ]] || die "Missing ${REPO_DIR}/systemd/${JOURNALD_DROPIN}"
    if $DRY_RUN; then
        echo "  would install ${JOURNALD_DST}/${JOURNALD_DROPIN} and restart systemd-journald"
        return 0
    fi
    mkdir -p "$JOURNALD_DST"
    install -m 0644 "${REPO_DIR}/systemd/${JOURNALD_DROPIN}" "${JOURNALD_DST}/${JOURNALD_DROPIN}" \
        || die "Failed to install ${JOURNALD_DROPIN}"
    print_success "installed ${JOURNALD_DST}/${JOURNALD_DROPIN}"
    if systemctl restart systemd-journald; then
        print_success "journald restarted"
    else
        print_warning "journald restart failed — the drop-in applies at next boot"
    fi
}

# Echo the effective SystemMaxUse in bytes, or nothing if it cannot be read.
# JOURNALD_CONF_ROOT is env-overridable so the test suite can point this at a
# fixture instead of the host's real journald config.
effective_max_use() {
    local root="${JOURNALD_CONF_ROOT:-}"
    local v=""
    # Later drop-ins win; read them in the order systemd would.
    local f
    for f in "${root}/etc/systemd/journald.conf" "${root}"/etc/systemd/journald.conf.d/*.conf \
             "${root}"/run/systemd/journald.conf.d/*.conf; do
        [[ -f "$f" ]] || continue
        local hit
        hit=$(grep -iE '^[[:space:]]*SystemMaxUse[[:space:]]*=' "$f" | tail -n1 | cut -d= -f2- | tr -d '[:space:]')
        [[ -n "$hit" ]] && v="$hit"
    done
    [[ -n "$v" ]] || return 0

    # systemd suffixes: K M G T (powers of 1024), bare = bytes.
    local num unit
    num="${v%[KMGTkmgt]}"; unit="${v#"$num"}"
    [[ "$num" =~ ^[0-9]+$ ]] || return 0
    case "${unit^^}" in
        K) echo $(( num * 1024 )) ;;
        M) echo $(( num * 1024 * 1024 )) ;;
        G) echo $(( num * 1024 * 1024 * 1024 )) ;;
        T) echo $(( num * 1024 * 1024 * 1024 * 1024 )) ;;
        *) echo "$num" ;;
    esac
}

human() {   # bytes -> human, one decimal
    awk -v b="$1" 'BEGIN{
        split("B KB MB GB TB", u, " "); i=1
        while (b >= 1024 && i < 5) { b /= 1024; i++ }
        printf "%.1f%s", b, u[i]
    }'
}

# journald states its own effective ceiling at every start. It logs TWO kinds of
# line and only one of them is ours:
#
#   Runtime Journal (/run/log/journal/<id>) is 8.0M, max 70.5M, 62.5M free.
#   System  Journal (/var/log/journal/<id>) is 1.8G, max 48.7G, 46.8G free.
#
# The Runtime journal is the volatile one in /run -- a RAM-backed tmpfs, sized by
# RuntimeMaxUse, typically tens of megabytes. SystemMaxUse does not govern it and
# nothing survives a reboot there. Matching it produced a ~32MB "ceiling" on a
# box whose real one was far larger. So anchor on "System Journal" explicitly.
#
# The System figure is authoritative -- SystemMaxUse and SystemKeepFree already
# reconciled -- so prefer it over estimating from df, which cannot know what
# SystemKeepFree reserves. Echoes bytes, or nothing if journald has not said.
journald_reported_max() {
    local line v num unit
    line=$(journalctl -u systemd-journald --no-pager -o cat 2>/dev/null \
           | grep -E '^System Journal ' \
           | grep -oE 'max [0-9]+(\.[0-9]+)?[KMGT]?,' | tail -n1) || return 1
    [[ -n "$line" ]] || return 1
    v=${line#max }; v=${v%,}
    num="${v%[KMGT]}"; unit="${v#"$num"}"
    [[ "$num" =~ ^[0-9]+(\.[0-9]+)?$ ]] || return 1
    awk -v n="$num" -v u="$unit" 'BEGIN{
        m = (u=="K")?1024 : (u=="M")?1048576 : (u=="G")?1073741824 :
            (u=="T")?1099511627776 : 1
        printf "%d", n * m
    }'
}

# Is the journal actually persistent? Storage=persistent only takes effect once
# /var/log/journal exists and is writable; until then journald stays volatile and
# the whole retention question is moot, because a reboot discards everything.
# Worth stating plainly rather than reporting a window that will not survive.
journal_is_persistent() {
    [[ -d /var/log/journal ]]
}


# Bytes of free space on the filesystem holding the journal. journald stops
# short of consuming all of it by SystemKeepFree, so current usage plus this is
# an upper bound on how large the journal can get, not a promise.
journal_fs_free() {
    local dir=/var/log/journal
    [[ -d "$dir" ]] || dir=/var/log
    local avail
    avail=$(df -B1 --output=avail "$dir" 2>/dev/null | tail -n1 | tr -d '[:space:]')
    [[ "$avail" =~ ^[0-9]+$ ]] || return 1
    echo "$avail"
}

# True when the journal still holds entries written before this host's units
# gained LogLevelMax=notice — i.e. when the measured growth rate is inflated by
# per-run timer chatter that is no longer written at all. The unit file's mtime
# is the upgrade point, since that is when install-logging.sh last wrote it.
journal_predates_log_filter() {
    local unit="${UNIT_DST}/${BASE}.service"
    [[ -f "$unit" ]] || return 1
    grep -q '^LogLevelMax=' "$unit" 2>/dev/null || return 1
    _WG_FILTER_SINCE=$(stat -c %Y "$unit" 2>/dev/null) || return 1
    local oldest
    oldest=$(journalctl --no-pager -o short-unix 2>/dev/null | head -1 | cut -d. -f1)
    [[ "$oldest" =~ ^[0-9]+$ ]] || return 1
    (( oldest < _WG_FILTER_SINCE ))
}

# Measure real journal growth and project the achievable retention window.
# This is the check that catches the common failure: a 6-year MaxRetentionSec
# sitting behind a SystemMaxUse that evicts after a few months.
check_retention() {
    echo
    echo -e "${CYAN}== journal retention ==${NC}"

    command -v journalctl &>/dev/null || { print_warning "journalctl not found"; return 1; }

    local usage_raw usage_bytes
    usage_raw=$(journalctl --disk-usage 2>/dev/null)
    usage_bytes=$(grep -oE '[0-9.]+[KMGT]?B?' <<<"$usage_raw" | tail -n1)
    # Reuse the suffix parser by normalising "1.8G" style output.
    usage_bytes=$(awk -v s="$usage_raw" 'BEGIN{
        if (match(s, /[0-9.]+[KMGT]/)) {
            v = substr(s, RSTART, RLENGTH)
            n = v + 0; u = substr(v, length(v), 1)
            m = (u=="K")?1024:(u=="M")?1048576:(u=="G")?1073741824:(u=="T")?1099511627776:1
            printf "%d", n * m
        }
    }')
    [[ -n "$usage_bytes" && "$usage_bytes" -gt 0 ]] || { print_warning "could not read journal disk usage"; return 1; }

    # journalctl streams oldest-first, so head -1 stops early on a big journal.
    local oldest_epoch now_epoch span_days
    oldest_epoch=$(journalctl -o short-unix --no-pager 2>/dev/null | head -n1 | cut -d. -f1)
    [[ "$oldest_epoch" =~ ^[0-9]+$ ]] || { print_warning "could not read the oldest journal entry"; return 1; }
    now_epoch=$(date +%s)
    span_days=$(( (now_epoch - oldest_epoch) / 86400 ))
    (( span_days > 0 )) || { print_info "journal spans under a day — too little history to project"; return 0; }

    local per_day required max_use
    per_day=$(( usage_bytes / span_days ))
    required=$(( per_day * RETENTION_TARGET_DAYS ))
    max_use=$(effective_max_use)

    if ! journal_is_persistent; then
        print_warning "/var/log/journal does not exist, so journald is running VOLATILE: the journal lives in /run (RAM) and every reboot discards it. Storage=persistent takes effect once that directory exists — run 'mkdir -p /var/log/journal && systemctl restart systemd-journald'. Until then the window below is not a retention guarantee."
    fi

    printf '  journal on disk    %s over %s days (~%s/day)\n' \
        "$(human "$usage_bytes")" "$span_days" "$(human "$per_day")"
    printf '  target window      %s days\n' "$RETENTION_TARGET_DAYS"
    printf '  needs about        %s to hold that window\n' "$(human "$required")"

    # Measured backwards over journal that already exists, so on a host upgraded
    # from units without LogLevelMax=notice this rate is dominated by chatter
    # that will not recur. Measured on one such host: 91% of ALL journal entries
    # came from these two units before the filter, so the projection over-sizes
    # the disk until that history rotates away.
    if journal_predates_log_filter; then
        print_warning "This rate includes pre-filter timer chatter and over-estimates future growth; re-check after the journal rotates past $(date -d "@${_WG_FILTER_SINCE}" '+%Y-%m-%d' 2>/dev/null || echo 'the upgrade')."
    fi

    if [[ -z "$max_use" ]]; then
        printf '  SystemMaxUse       not set — journald caps the journal at 10%% of the\n'
        printf '                     filesystem, or 4G, whichever is smaller\n'
        print_warning "Nothing is set, so the journal is capped well below the disk. Run the installer (or --with-retention) to keep everything the disk allows."
        return 0
    fi

    printf '  SystemMaxUse       %s\n' "$(human "$max_use")"

    # A cap set above the filesystem size is the "keep everything" setting: the
    # binding limit is then free disk minus SystemKeepFree, not SystemMaxUse.
    # Reporting the configured number in that case would promise a window
    # hundreds of times longer than the disk can actually deliver.
    local effective="$max_use" free reported unbounded=false
    if free=$(journal_fs_free) && (( max_use > free + usage_bytes )); then
        unbounded=true
        if reported=$(journald_reported_max) && [[ -n "$reported" ]]; then
            # journald's own number: SystemMaxUse and SystemKeepFree already
            # reconciled, so no guessing at the reserve.
            effective="$reported"
            printf '  effective cap      %s — disk, not SystemMaxUse, is the limit\n' "$(human "$effective")"
            printf '                     (journald reports this as its own ceiling)\n'
        else
            effective=$(( free + usage_bytes ))
            printf '  effective cap      ~%s — disk, not SystemMaxUse, is the limit\n' "$(human "$effective")"
            printf '                     (estimated; journald stops short by SystemKeepFree)\n'
        fi
    fi

    local achievable=$(( effective / per_day ))
    printf '  achievable window  ~%s days\n' "$achievable"

    if (( effective >= required )); then
        if $unbounded; then
            print_success "Keeping everything the disk allows: ~${achievable} days at the current rate, against a ${RETENTION_TARGET_DAYS}-day target."
        else
            print_success "Retention cap is sufficient for the ${RETENTION_TARGET_DAYS}-day window."
        fi
        return 0
    fi

    if $unbounded; then
        print_error "Retention is already uncapped and the disk still falls short: ~${achievable} days, not ${RETENTION_TARGET_DAYS}."
        echo "    Nothing can be raised here — SystemMaxUse is already above the"
        echo "    filesystem. Add disk, or ship the audit trail off-box to a log"
        echo "    store sized for the window."
        return 1
    fi
    print_error "Retention cap is too small: it holds ~${achievable} days, not ${RETENTION_TARGET_DAYS}."
    echo "    Size wins over age, so entries are evicted silently well before"
    echo "    MaxRetentionSec elapses. Raise SystemMaxUse to at least $(human "$required") in"
    echo "    ${JOURNALD_DST}/${JOURNALD_DROPIN} (and confirm the filesystem has room),"
    echo "    or ship the audit trail off-box to a log store sized for the window."
    return 1
}

################################################################################
# UNITS
################################################################################

install_units() {
    unit_warn_on_cron "log-connections.sh"
    unit_install_service "$REPO_DIR" "$BASE"
    unit_install_timer   "$REPO_DIR" "$BASE"
    unit_enable_timer    "$BASE"
    $DRY_RUN && return
    print_success "Audit-log timer enabled — unit points at ${REPO_DIR}"
    echo
    systemctl list-timers "${BASE}.timer" --all --no-pager
}

uninstall_units() {
    unit_remove "$BASE"
    if $DRY_RUN; then
        print_info "Dry run: nothing was changed."
        return
    fi
    print_success "Uninstalled. (Scripts in ${REPO_DIR} are left untouched.)"
    # Deliberately NOT removed: shrinking retention here would discard existing
    # audit history, which is the opposite of what an uninstall should risk.
    if [[ -f "${JOURNALD_DST}/${JOURNALD_DROPIN}" ]]; then
        print_info "Journal retention drop-in left in place: ${JOURNALD_DST}/${JOURNALD_DROPIN}"
        print_info "Remove it manually (then restart systemd-journald) to revert retention."
    fi
}

show_status() {
    systemctl list-timers "${BASE}.timer" --all --no-pager
    echo
    local n
    n=$(journalctl -t wireguard-connections --no-pager 2>/dev/null | grep -c . || true)
    print_info "audit records currently in the journal: ${n:-0}"
    check_retention
}

main() {
    check_root
    check_systemd
    local action="install" retention=false arg
    for arg in "$@"; do
        case "$arg" in
            --dry-run)         DRY_RUN=true ;;
            --with-retention)  retention=true ;;
            --check-retention) action="check" ;;
            --status)          action="status" ;;
            --uninstall)       action="uninstall" ;;
            *)                 die "Unknown option: $arg (use --with-retention, --check-retention, --status, --uninstall, --dry-run, or no args)" ;;
        esac
    done

    case "$action" in
        check)     check_retention ;;
        status)    show_status ;;
        uninstall) uninstall_units ;;
        install)
            install_units
            # Retention defaults to "keep everything the disk allows", but only
            # when the host has no SystemMaxUse of its own. An explicit setting
            # is somebody's decision about their disk, so it is never
            # overridden -- --with-retention forces ours on top when that is
            # actually what is wanted.
            if $retention; then
                echo; install_retention
            elif [[ -z "$(effective_max_use)" ]]; then
                echo
                print_info "No SystemMaxUse is set, so journald would cap the journal at 4G. Installing the keep-everything drop-in."
                install_retention
            else
                echo
                print_info "SystemMaxUse is already set to $(human "$(effective_max_use)") — leaving retention alone. Use --with-retention to replace it with the keep-everything drop-in."
            fi
            if $DRY_RUN; then
                print_info "Dry run: checks passed, nothing was changed. (--check-retention projects the retention window.)"
            else
                check_retention
            fi
            ;;
    esac
}

main "$@"
