#!/bin/bash
################################################################################
# WireGuard Scripts - Shared Utility Library
# Source this from other scripts: source "$(dirname "$0")/utils.sh"
#
# Provides:
#   - Color helpers + print_success/error/warning/info
#   - die, check_root, log
#   - peer_* namespace: peer_validate_name, peer_list, peer_pubkey, peer_remove
#   - validate_interface_name, detect_servers
#   - peer-block markers (PEER_BEGIN_PREFIX, PEER_END_PREFIX)
#   - log_audit (structured systemd journal entry)
#   - manifest_* namespace: manifest_add, manifest_path, manifest_entries
################################################################################

# ---------- constants ----------
WG_CONFIG_DIR="${WG_CONFIG_DIR:-/etc/wireguard}"
LOG_FILE="${LOG_FILE:-/var/log/wireguard-setup.log}"

# Peer-block markers — written around every [Peer] entry in <iface>.conf
# by add-peer.sh and required by all readers (list/remove/toggle/rotate).
# A separate `# Client: name` / `# Site: name` / `# Peer-to-Peer: name`
# line inside the block carries the peer type for list-peers.sh.
PEER_BEGIN_PREFIX="# BEGIN_PEER "
PEER_END_PREFIX="# END_PEER "

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

# ---------- audit logging (HIPAA / systemd journal) ----------
log_audit() {
    local action="$1"
    local details="$2"
    local user
    local source_ip
    user=$(whoami)
    source_ip=$(who am i 2>/dev/null | awk '{print $5}' | tr -d '()')
    logger -t wireguard-audit -p auth.info \
        "action=$action user=$user source_ip=${source_ip:-local} $details"
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

# ---------- peer-block marker helpers ----------
# Format written by add-peer.sh:
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
# list-peers.sh reads to render the type column.

# List peer names declared in <iface>.conf, one per line, in file order.
peer_list() {
    local config_file="$1"
    [[ -f "$config_file" ]] || return 0
    awk 'match($0, /^# BEGIN_PEER ([^ ]+)/, m) { print m[1] }' "$config_file"
}

# Echo the public key recorded for the given peer in <iface>.conf (or empty).
peer_pubkey() {
    local config_file="$1"
    local name="$2"
    [[ -f "$config_file" ]] || return 0
    awk -v begin="^# BEGIN_PEER ${name}$" '
        $0 ~ begin { in_peer=1; next }
        in_peer && /^# END_PEER / { exit }
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

    awk -v begin_re="^# BEGIN_PEER ${name}$" -v end_re="^# END_PEER ${name}$" '
        $0 ~ begin_re { skip=1; next }
        skip && $0 ~ end_re { skip=0; next }
        skip { next }
        { print }
    ' "$config_file" > "$tmp" || die "Failed to rewrite config"

    # Collapse 3+ blank lines to single blank
    sed -i '/^$/N;/^\n$/D' "$tmp"

    mv -f "$tmp" "$config_file"
    chmod "$perms" "$config_file"
    chown "$owner" "$config_file" 2>/dev/null || true
    if command -v restorecon &>/dev/null && command -v sestatus &>/dev/null \
       && sestatus 2>/dev/null | grep -q enabled; then
        restorecon "$config_file" 2>/dev/null || true
    fi
    trap - RETURN
}

# ---------- install manifest ----------
# One manifest per WireGuard interface, e.g. /etc/wireguard/.manifest-wg0
# Each line: TYPE|VALUE  (so reset.sh can act on them precisely)
#   SYSCTL|/etc/sysctl.d/99-wireguard-wg0.conf
#   SERVICE|wg-quick@wg0
#   FW_FIREWALLD|port:51820/udp
#   FW_FIREWALLD|masquerade
#   FW_UFW|allow:51820/udp
#   FW_UFW|route:wg0
#   FW_NFT|wg0
#   SELINUX_PORT|wireguard_port_t:udp:51820
#   FILE|/etc/wireguard/wg0.conf
#   DIR|/etc/wireguard/wg0
manifest_path() {
    local iface="$1"
    echo "${WG_CONFIG_DIR}/.manifest-${iface}"
}

manifest_add() {
    local iface="$1"
    local type="$2"
    local value="$3"
    local path
    path=$(manifest_path "$iface")
    mkdir -p "$(dirname "$path")"
    touch "$path" && chmod 600 "$path"
    local entry="${type}|${value}"
    grep -Fxq "$entry" "$path" 2>/dev/null || echo "$entry" >> "$path"
}

manifest_entries() {
    local iface="$1"
    local type="$2"
    local path
    path=$(manifest_path "$iface")
    [[ -f "$path" ]] || return 0
    grep "^${type}|" "$path" | cut -d'|' -f2-
}
