#!/bin/bash
################################################################################
# WireGuard Scripts - Shared Utility Library
# Source this from other scripts: source "$(dirname "$0")/utils.sh"
#
# Provides:
#   - Color helpers + print_success/error/warning/info
#   - die, check_root, log, confirm, check_deps
#   - peer_* namespace: peer_validate_name, peer_list, peer_select,
#                       peer_pubkey, peer_remove
#   - validate_interface_name, detect_servers
#   - restore_context (SELinux), backup_config (timestamped 600 backup)
#   - peer-block markers (PEER_BEGIN_PREFIX, PEER_END_PREFIX)
#   - log_audit (structured systemd journal entry)
#   - looks_like_host (is this a pingable IP or hostname?)
################################################################################

# ---------- constants ----------
# Several constants/colors below are consumed by scripts that source this file,
# so their use isn't visible here. File-level suppression of the unused warning.
# shellcheck disable=SC2034
WG_CONFIG_DIR="${WG_CONFIG_DIR:-/etc/wireguard}"
LOG_FILE="${LOG_FILE:-/var/log/wireguard-setup.log}"

# Peer-block markers — written around every [Peer] entry in <iface>.conf
# by whatever adds peers, and required by every reader of them: the peer
# actions and verify-config.sh.
# A separate `# Client: name` / `# Site: name` / `# Peer-to-Peer: name`
# line inside the block records what the peer is.
PEER_BEGIN_PREFIX="# BEGIN_PEER "
PEER_END_PREFIX="# END_PEER "

# Pausing a peer keeps its markers and comments out
# every WireGuard line in its block with PEER_PAUSE_PREFIX, so wg-quick strip
# leaves it out and it stays out of the tunnel across restarts. Readers that
# care what a block holds rather than whether it is live read through the
# prefix (strip_pause_prefixes).
PEER_PAUSE_PREFIX="#! "

# ---------- colors ----------
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' CYAN='' NC=''
fi

# All prints go to stderr so scripts that emit data on stdout stay capturable.
print_success() { echo -e "${GREEN}[✓]${NC} $1" >&2; }
print_error()   { echo -e "${RED}[✗]${NC} $1" >&2; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1" >&2; }
print_info()    { echo -e "${BLUE}[i]${NC} $1" >&2; }

# ---------- core helpers ----------
log() {
    local message="$1"
    [[ -w "$(dirname "$LOG_FILE")" ]] 2>/dev/null || return 0
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $message" >> "$LOG_FILE" 2>/dev/null || true
}

die() {
    print_error "$1"
    log "ERROR: $1"
    exit 1
}

check_root() {
    [[ $EUID -eq 0 ]] || die "This script must be run as root (use sudo)"
}

# Die unless this host was booted with systemd, which the timers, `systemctl`
# and wg-quick@<iface> services all need. /run/systemd/system exists only then.
check_systemd() {
    [[ -d /run/systemd/system ]] && command -v systemctl &>/dev/null \
        || die "This needs systemd, and this host is not running it (no /run/systemd/system)"
}

# Ensure required commands are on PATH; die listing any that are missing.
# Usage: check_deps wg wg-quick ip
check_deps() {
    local missing=() c
    for c in "$@"; do
        command -v "$c" &>/dev/null || missing+=("$c")
    done
    (( ${#missing[@]} == 0 )) || die "Missing required command(s): ${missing[*]}"
}

# Standard yes/no confirmation. `confirm "Delete foo?"` defaults to no;
# `confirm "Proceed?" y` defaults to yes. Returns 0 on yes, 1 on no.
confirm() {
    local prompt="$1" default="${2:-n}" reply hint
    hint="[y/N]"; [[ "$default" == "y" ]] && hint="[Y/n]"
    read -r -p "$(echo -e "${YELLOW}${prompt}${NC} ${hint} ")" reply
    reply="${reply:-$default}"
    [[ "$reply" =~ ^[Yy]([Ee][Ss])?$ ]]
}

# Restore the SELinux file context on a path when SELinux is enabled; a no-op
# on systems without SELinux. Used after rewriting a config in place.
restore_context() {
    local path="$1"
    command -v restorecon &>/dev/null || return 0
    command -v sestatus &>/dev/null && sestatus 2>/dev/null | grep -q enabled || return 0
    restorecon "$path" 2>/dev/null || true
}

# Make a timestamped, mode-600 backup of a config before an in-place edit.
# Echoes the backup path (nothing if the source doesn't exist).
backup_config() {
    local f="$1"
    [[ -f "$f" ]] || return 0
    local bak
    bak="${f}.backup.$(date +%Y%m%d_%H%M%S)"
    cp -p "$f" "$bak" || die "Failed to back up $f"
    chmod 600 "$bak"
    echo "$bak"
}

# ---------- audit logging (HIPAA / systemd journal) ----------
# Every audit record this toolkit emits — admin actions, healthcheck results,
# and peer connect/disconnect — uses ONE schema, so an auditor learns a single
# shape instead of one per script:
#
#   MESSAGE      action=<ACTION> user=<u> source_ip=<ip> <k=v> ...
#   WG_SCHEMA    schema version (bump when a field changes meaning)
#   WG_ACTION    the event verb, also exposed as an indexed journald field
#   WG_<KEY>     one indexed field per k=v pair in <details>
#
# The structured fields are what make the journal trackable without grep:
#   journalctl WG_ACTION=CONNECT
#   journalctl WG_PEER=alice --since -30d -o short-iso
# MESSAGE stays human-readable so plain `journalctl -t <tag>` is still useful.
WG_LOG_SCHEMA=1

# Emit one audit record. Internal — callers use log_audit / log_conn_event.
# Usage: _audit_emit <tag> <facility.severity> <action> <details>
# <priority> is the syslog name pair (e.g. authpriv.notice), because the
# fallback path below feeds it straight to `logger -p`, which rejects numbers.
# <details> is a space-separated k=v list; each pair also becomes a WG_<KEY>
# field. Values containing spaces stay intact in MESSAGE but are split across
# fields, so keep detail values space-free (the existing callers all do).
_audit_emit() {
    local tag="$1" priority="$2" action="$3" details="${4:-}"
    local message="action=${action} ${details}"
    command -v logger &>/dev/null || return 0

    # Older util-linux has no --journald; fall back to a plain tagged line so
    # the audit trail never silently disappears on such a host.
    if ! _audit_have_journald; then
        logger -t "$tag" -p "$priority" "$message"
        return 0
    fi

    # journald's native protocol wants the numeric pair instead.
    local facility severity
    case "${priority%%.*}" in
        kern) facility=0 ;;  user)     facility=1  ;;  daemon) facility=3  ;;
        auth) facility=4 ;;  authpriv) facility=10 ;;
        local0) facility=16 ;; local1) facility=17 ;; local2) facility=18 ;;
        local3) facility=19 ;; local4) facility=20 ;; local5) facility=21 ;;
        local6) facility=22 ;; local7) facility=23 ;;
        *)      facility=1  ;;
    esac
    case "${priority##*.}" in
        emerg) severity=0 ;;  alert)   severity=1 ;;  crit)   severity=2 ;;
        err)   severity=3 ;;  warning) severity=4 ;;  notice) severity=5 ;;
        info)  severity=6 ;;  debug)   severity=7 ;;  *)      severity=6 ;;
    esac

    {
        # MESSAGE first: journald's native format ends a field at the newline,
        # and this is the only value that may contain spaces.
        printf 'MESSAGE=%s\n' "$message"
        printf 'PRIORITY=%s\n' "$severity"
        printf 'SYSLOG_FACILITY=%s\n' "$facility"
        printf 'SYSLOG_IDENTIFIER=%s\n' "$tag"
        printf 'WG_SCHEMA=%s\n' "$WG_LOG_SCHEMA"
        printf 'WG_ACTION=%s\n' "$action"

        local pair key val
        for pair in $details; do
            [[ "$pair" == *=* ]] || continue
            key="${pair%%=*}"
            val="${pair#*=}"
            # journald field names are [A-Z0-9_] and cannot lead with a digit
            # or underscore; anything that will not normalize is dropped from
            # the fields but is still readable in MESSAGE.
            key="$(printf '%s' "$key" | tr '[:lower:]' '[:upper:]' | tr -c 'A-Z0-9' '_')"
            [[ -n "$key" && "$key" =~ ^[A-Z] ]] || continue
            printf 'WG_%s=%s\n' "$key" "$val"
        done
    } | logger --journald 2>/dev/null
}

# Cached capability probe — this runs on every logged event.
_audit_have_journald() {
    if [[ -z "${_WG_HAVE_JOURNALD:-}" ]]; then
        if logger --help 2>&1 | grep -q -- '--journald'; then
            _WG_HAVE_JOURNALD=yes
        else
            _WG_HAVE_JOURNALD=no
        fi
    fi
    [[ "$_WG_HAVE_JOURNALD" == yes ]]
}

# One tag and one facility for everything this toolkit emits.
#
# It was two (wireguard-audit/auth and wireguard-connections/authpriv). That
# split claimed to separate admin actions from peer activity, but every caller
# of the "audit" tag was healthcheck.sh, so what it really separated was health
# events from connection events -- while scattering related records across
# /var/log/messages and /var/log/secure, mixed in with sshd and sudo. The
# action= field already distinguishes them, which is what it is for.
#
# local0 rather than auth/authpriv: those belong to the OS's own authentication
# services, while local0-local7 are the range reserved for custom applications.
# Using local0 is what lets rsyslog route this toolkit to its own file instead
# of interleaving it with the system's auth logs.
WG_LOG_TAG="wireguard"
WG_LOG_FACILITY="local0.notice"

# The traffic log (traffic-log.sh) is the exception: its lines come from the
# kernel's nftables `log` statement, not from logger, so they arrive tagged
# "kernel". This prefix labels them the way every other record is labeled, and
# install.sh's rsyslog rule matches on it to put them in the same file.
WG_TRAFFIC_LOG_PREFIX="action=TRAFFIC "

# Operator actions and health events (carries who ran it).
# notice, not info: the units set LogLevelMax=notice to keep systemd's per-run
# "Starting/Finished" lines (info) out of the journal, and an info-level record
# is dropped by that filter — unreliably, which is worse than never.
log_audit() {
    local action="$1"
    local details="$2"
    local user
    local source_ip
    user=$(whoami)
    source_ip=$(who am i 2>/dev/null | awk '{print $5}' | tr -d '()')
    _audit_emit "$WG_LOG_TAG" "$WG_LOG_FACILITY" "$action" \
        "user=$user source_ip=${source_ip:-local} $details"
}

# Peer connect/disconnect events. Same tag and facility as log_audit; kept as a
# separate function because these are observations of the system rather than
# actions by a person, so they carry no user= or source_ip=.
log_conn_event() {
    local action="$1"
    local details="$2"
    _audit_emit "$WG_LOG_TAG" "$WG_LOG_FACILITY" "$action" "$details"
}

# ---------- validation ----------
# Strict peer-name rules (modeled on pivpn):
#   - 1-32 chars
#   - alphanumeric, dot, dash, underscore, at-sign
#   - cannot start with . or -
#   - cannot be the literal "server" or match an interface name pattern
peer_validate_name() {
    local name="$1"
    if [[ -z "$name" ]]; then
        print_error "Peer name cannot be empty"
        return 1
    fi
    if (( ${#name} > 32 )); then
        print_error "Peer name '${name}' too long (max 32 chars)"
        return 1
    fi
    if [[ ! "$name" =~ ^[A-Za-z0-9_@][A-Za-z0-9._@-]*$ ]]; then
        print_error "Peer name '${name}' invalid (allowed: A-Z a-z 0-9 . _ - @, no leading . or -)"
        return 1
    fi
    if [[ "$name" == "server" ]] || [[ "$name" =~ ^wg[0-9]+$ ]]; then
        print_error "Peer name '${name}' is reserved"
        return 1
    fi
    return 0
}

# True if <host> is a syntactically valid ping target: an IPv4 address (octets
# in range), a loose IPv6 address, or a DNS hostname. Guards the
# "# Healthcheck-Reachability =" comment, so a typo (10.0.0.999) is caught
# rather than silently treated as "unreachable" — which, with --restart, would
# turn a config typo into a tunnel-restart loop.
looks_like_host() {
    local h="$1"
    [[ -z "$h" ]] && return 1
    if [[ "$h" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then   # IPv4 shape
        local o; IFS=. read -ra o <<<"$h"
        local n; for n in "${o[@]}"; do (( n <= 255 )) || return 1; done
        return 0
    fi
    [[ "$h" == *:* && "$h" =~ ^[0-9a-fA-F:]+$ ]] && return 0   # IPv6 (loose)
    # Hostname: dot-separated labels of alnum/hyphen, not starting/ending in '-'.
    [[ ${#h} -le 253 && "$h" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$ ]]
}

validate_interface_name() {
    local name="$1"
    [[ "$name" =~ ^[a-zA-Z][a-zA-Z0-9_-]{0,14}$ ]]
}

# ---------- server detection ----------
# Echoes one interface name per line (deduped union of running interfaces and
# .conf files in $WG_CONFIG_DIR).
detect_servers() {
    local -a found=()
    local seen=""
    if command -v wg &>/dev/null; then
        local iface
        while read -r iface; do
            [[ -z "$iface" ]] && continue
            if [[ "$seen" != *"|${iface}|"* ]]; then
                found+=("$iface")
                seen+="|${iface}|"
            fi
        done < <(wg show interfaces 2>/dev/null | tr ' ' '\n')
    fi
    if [[ -d "$WG_CONFIG_DIR" ]]; then
        local conf iface
        shopt -s nullglob
        for conf in "$WG_CONFIG_DIR"/*.conf; do
            iface=$(basename "$conf" .conf)
            if [[ "$seen" != *"|${iface}|"* ]]; then
                found+=("$iface")
                seen+="|${iface}|"
            fi
        done
        shopt -u nullglob
    fi
    # Avoid printf emitting a stray blank line when found is empty
    (( ${#found[@]} > 0 )) && printf '%s\n' "${found[@]}"
}

# Resolve the global $WG_INTERFACE: if already set (e.g. via -i) just validate
# it; if exactly one server exists, pick it silently; otherwise show a numbered
# menu. The menu and prompt go to stderr so callers that emit data on stdout
# stay clean. Dies if none are found or the choice is bad.
select_server() {
    local -a servers
    mapfile -t servers < <(detect_servers)
    (( ${#servers[@]} > 0 )) || die "No WireGuard servers found in ${WG_CONFIG_DIR}"

    if [[ -n "${WG_INTERFACE:-}" ]]; then
        [[ -f "${WG_CONFIG_DIR}/${WG_INTERFACE}.conf" ]] \
            || die "WireGuard interface '${WG_INTERFACE}' not found"
        return 0
    fi
    if (( ${#servers[@]} == 1 )); then
        WG_INTERFACE="${servers[0]}"
        return 0
    fi

    print_info "Multiple WireGuard interfaces detected (use -i <iface> to skip this menu)"
    local i iface status
    for i in "${!servers[@]}"; do
        iface="${servers[$i]}"
        if systemctl is-active --quiet "wg-quick@${iface}" 2>/dev/null; then
            status="${GREEN}●${NC}"
        else
            status="${YELLOW}○${NC}"
        fi
        printf '  %b%d)%b %s %b\n' "$BLUE" "$((i + 1))" "$NC" "$iface" "$status" >&2
    done
    local sel
    read -r -p "Select interface (1-${#servers[@]}): " sel
    [[ "$sel" =~ ^[0-9]+$ ]] && (( sel >= 1 && sel <= ${#servers[@]} )) \
        || die "Invalid selection"
    WG_INTERFACE="${servers[$((sel - 1))]}"
}

# ---------- peer-block marker helpers ----------
# Format written when a peer is added:
#
#   # BEGIN_PEER <name>
#   # <Client|Site|Peer-to-Peer>: <name>
#   [Peer]
#   PublicKey = ...
#   AllowedIPs = ...
#   # END_PEER <name>
#
# BEGIN_PEER / END_PEER are the authoritative block delimiters used by every
# reader below. The Client/Site/Peer-to-Peer line is type metadata that
# records what the peer is.

# Print <file> (or stdin) with PEER_PAUSE_PREFIX removed, so paused peers read
# like active ones.
strip_pause_prefixes() {
    sed -e "s/^${PEER_PAUSE_PREFIX}//" "$@"
}

# List peer names declared in <iface>.conf, one per line, in file order.
# grep -oP (not gawk's 3-arg match) so this also works on Debian/Ubuntu's mawk.
peer_list() {
    local config_file="$1"
    [[ -f "$config_file" ]] || return 0
    grep -oP '^# BEGIN_PEER \K\S+' "$config_file" 2>/dev/null || true
}

# Resolve exactly one peer name from <iface>.conf.
#
#   peer_select <config_file> <preselected|""> <prompt> [annotator]
#
# The chosen name goes to stdout; the menu, prompt and any errors go to stderr,
# so callers capture it: PEER_NAME=$(peer_select ...) || exit 1
#
# <preselected> (e.g. from -n/--name) is validated against the config and
# echoed straight back, skipping the menu. <annotator>, if given, names a
# function invoked as `<annotator> <config_file> <name>`; whatever it echoes is
# shown in brackets beside each name (pause/resume uses it to show
# active / paused). Dies on an empty config or an invalid choice.
#
# Note for callers: `die` here runs inside the command substitution, so it
# exits that subshell — keep the `|| exit 1` so the failure propagates.
peer_select() {
    local config_file="$1" preselected="$2" prompt="$3" annotator="${4:-}"
    local iface
    iface=$(basename "$config_file" .conf)

    local -a peers
    mapfile -t peers < <(peer_list "$config_file")
    (( ${#peers[@]} > 0 )) || die "No peers found in ${iface}. (Peers written before the BEGIN_PEER marker format must be re-added with those markers.)"

    if [[ -n "$preselected" ]]; then
        local p
        for p in "${peers[@]}"; do
            if [[ "$p" == "$preselected" ]]; then
                echo "$preselected"
                return 0
            fi
        done
        die "Peer '${preselected}' not found in ${iface} (or predates the BEGIN_PEER marker format)"
    fi

    echo "" >&2
    print_info "$prompt"
    echo "" >&2
    local i note
    for i in "${!peers[@]}"; do
        note=""
        [[ -n "$annotator" ]] && note=$("$annotator" "$config_file" "${peers[$i]}")
        if [[ -n "$note" ]]; then
            printf '  %b%d)%b %-20s [%s]\n' "$BLUE" "$((i + 1))" "$NC" "${peers[$i]}" "$note" >&2
        else
            printf '  %b%d)%b %s\n' "$BLUE" "$((i + 1))" "$NC" "${peers[$i]}" >&2
        fi
    done
    echo "" >&2
    local sel
    read -r -p "Select peer (1-${#peers[@]}): " sel
    [[ "$sel" =~ ^[0-9]+$ ]] && (( sel >= 1 && sel <= ${#peers[@]} )) \
        || die "Invalid selection"
    echo "${peers[$((sel - 1))]}"
}

# Echo the public key recorded for the given peer in <iface>.conf (or empty).
peer_pubkey() {
    local config_file="$1"
    local name="$2"
    [[ -f "$config_file" ]] || return 0
    # Exact match, not a regex: peer names may contain '.', which as a regex
    # also matches another peer's marker (a.b would match axb).
    # A paused peer still has its key: read through the prefix.
    awk -v begin="${PEER_BEGIN_PREFIX}${name}" -v dp="$PEER_PAUSE_PREFIX" '
        $0 == begin { in_peer=1; next }
        in_peer && /^# END_PEER / { exit }
        in_peer && index($0, dp) == 1 { $0 = substr($0, length(dp) + 1) }
        in_peer && /^PublicKey[[:space:]]*=/ {
            sub(/^PublicKey[[:space:]]*=[[:space:]]*/, "", $0)
            print $0
            exit
        }
    ' "$config_file"
}

# Delete a peer's full block from <iface>.conf in place. Preserves perms/owner.
peer_remove() {
    local config_file="$1"
    local name="$2"
    [[ -f "$config_file" ]] || die "Config not found: $config_file"

    local tmp
    tmp=$(mktemp) || die "mktemp failed"
    trap 'rm -f "$tmp"' RETURN

    local perms owner
    perms=$(stat -c '%a' "$config_file" 2>/dev/null || echo 600)
    owner=$(stat -c '%U:%G' "$config_file" 2>/dev/null || echo root:root)

    # Exact match, not a regex — see peer_pubkey.
    awk -v begin="${PEER_BEGIN_PREFIX}${name}" -v end="${PEER_END_PREFIX}${name}" '
        $0 == begin { skip=1; next }
        skip && $0 == end { skip=0; next }
        skip { next }
        { print }
    ' "$config_file" > "$tmp" || die "Failed to rewrite config"

    # Collapse 3+ blank lines to single blank
    sed -i '/^$/N;/^\n$/D' "$tmp"

    mv -f "$tmp" "$config_file"
    chmod "$perms" "$config_file"
    chown "$owner" "$config_file" 2>/dev/null || true
    restore_context "$config_file"
    trap - RETURN
}

# ---------- systemd unit installation ----------
# Shared by both controls in install.sh, so unit installation stays one
# implementation. Units are identified by filename, so re-installing overwrites
# in place and can never produce a duplicate.
#
# With DRY_RUN=true (install.sh --dry-run) every helper below still makes its
# checks, but only prints what it would write or run.

UNIT_DST="${UNIT_DST:-/etc/systemd/system}"

# Install <base>.service, rewriting ExecStart/Documentation to point at the
# script inside THIS repo rather than whatever path was baked into the shipped
# unit — so the repo can live anywhere and a re-run re-points the units.
unit_install_service() {
    local repo_dir="$1" base="$2"
    # Validate the path before looking at the filesystem: '#' is the sed
    # delimiter used below, so it must be rejected on its own terms rather than
    # being masked by a "missing file" error.
    case "$repo_dir" in *'#'*) die "Repo path contains '#', which breaks unit rewriting: ${repo_dir}";; esac
    local src="${repo_dir}/systemd/${base}.service"
    [[ -f "$src" ]] || die "Missing ${src}"

    local unit
    unit=$(sed -E \
        -e "s#^(ExecStart|ExecStop)=[^ ]*/([A-Za-z0-9_.-]+\.sh)#\1=${repo_dir}/\2#" \
        -e "s#^Documentation=file://[^ ]*/([A-Za-z0-9_.-]+\.sh)#Documentation=file://${repo_dir}/\1#" \
        "$src") || die "Failed to read ${src}"

    # A timer pointed at a script that isn't there fires forever and does
    # nothing, so refuse to install one.
    local exec_line exec_path
    exec_line=$(grep -m1 '^ExecStart=' <<<"$unit")
    exec_path="${exec_line#ExecStart=}"
    exec_path="${exec_path%% *}"
    [[ -x "$exec_path" ]] || die "${base}.service would run '${exec_path}', which is missing or not executable"

    if ${DRY_RUN:-false}; then
        echo "  would write ${UNIT_DST}/${base}.service  (${exec_line})"
        return 0
    fi
    printf '%s\n' "$unit" > "${UNIT_DST}/${base}.service" \
        || die "Failed to write ${UNIT_DST}/${base}.service"
    print_success "installed ${base}.service"
}

# Timers carry no paths, so they copy verbatim.
unit_install_timer() {
    local repo_dir="$1" base="$2"
    local src="${repo_dir}/systemd/${base}.timer"
    [[ -f "$src" ]] || die "Missing ${src}"
    if ${DRY_RUN:-false}; then
        echo "  would copy ${src} -> ${UNIT_DST}/${base}.timer"
        return 0
    fi
    cp "$src" "${UNIT_DST}/${base}.timer" || die "Failed to copy ${base}.timer"
    print_success "installed ${base}.timer"
}

# restart (not just start) so a changed interval takes effect immediately.
unit_enable_timer() {
    local base="$1"
    if ${DRY_RUN:-false}; then
        echo "  would run: systemctl daemon-reload; systemctl enable ${base}.timer; systemctl restart ${base}.timer"
        return 0
    fi
    systemctl daemon-reload || die "systemctl daemon-reload failed"
    systemctl enable "${base}.timer" >/dev/null 2>&1 || die "Failed to enable ${base}.timer"
    systemctl restart "${base}.timer" || die "Failed to start ${base}.timer"
    print_success "systemd reloaded; ${base}.timer enabled and started"

    # A timer can be enabled and active with nothing scheduled — that is how the
    # old OnBootSec units failed silently — so check before claiming success.
    local next
    next=$(systemctl show "${base}.timer" -p NextElapseUSecMonotonic --value 2>/dev/null)
    if [[ -z "$next" || "$next" == "infinity" ]]; then
        print_warning "${base}.timer is enabled and active but has nothing scheduled, so it will never fire — check its OnActiveSec/OnUnitActiveSec"
    fi
    return 0
}

# Stops and disables whichever of <base>.timer and <base>.service exist, timer
# first. Stopping the service matters for a unit with no timer (the traffic
# log): its ExecStop is what unloads what it set up.
unit_remove() {
    local base="$1" f
    if ${DRY_RUN:-false}; then
        for f in "${base}.timer" "${base}.service"; do
            [[ -e "${UNIT_DST}/${f}" ]] || continue
            echo "  would run: systemctl disable --now ${f}"
            echo "  would remove ${UNIT_DST}/${f}"
        done
        echo "  would run: systemctl daemon-reload"
        return 0
    fi
    for f in "${base}.timer" "${base}.service"; do
        [[ -e "${UNIT_DST}/${f}" ]] && { systemctl disable --now "$f" 2>/dev/null || true; }
    done
    for f in "${base}.timer" "${base}.service"; do
        [[ -e "${UNIT_DST}/${f}" ]] || continue
        rm -f "${UNIT_DST}/${f}" && print_success "removed ${f}"
    done
    systemctl daemon-reload
}

# A cron entry running the same script would double-execute alongside the
# timer — the one real double-run trap. Warn, never fail.
unit_warn_on_cron() {
    local script="$1"
    if { crontab -l 2>/dev/null; cat /etc/cron.d/* /etc/crontab 2>/dev/null; } \
         | grep -Fq "$script"; then
        print_warning "A cron entry references ${script} — it will double-run alongside the timer. Remove the cron line or the timer, not both."
    fi
}
