#!/bin/bash
################################################################################
# WireGuard Scripts - Shared Utility Library
# Source this from other scripts: source "$(dirname "$0")/utils.sh"
#
# Provides:
#   - Color helpers + print_success/error/warning/info
#   - error_exit, check_root, log
#   - validate_peer_name (strict, pivpn-style)
#   - validate_interface_name
#   - detect_servers
#   - peer-block markers (PEER_BEGIN_RE, PEER_END_RE) and helpers
#   - log_audit (structured systemd journal entry)
#   - manifest_add / manifest_path (install manifest helpers)
################################################################################

# ---------- constants ----------
WG_CONFIG_DIR="${WG_CONFIG_DIR:-/etc/wireguard}"
LOG_FILE="${LOG_FILE:-/var/log/wireguard-setup.log}"

# Peer-block markers — written around every [Peer] entry in <iface>.conf.
# Backwards-compatible reads also accept the legacy `# Client: name` form.
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

error_exit() {
    print_error "$1"
    log "ERROR: $1"
    exit 1
}

check_root() {
    [[ $EUID -eq 0 ]] || error_exit "This script must be run as root (use sudo)"
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
validate_peer_name() {
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
#   # type=<client|site|p2p>
#   [Peer]
#   PublicKey = ...
#   AllowedIPs = ...
#   # END_PEER <name>
#
# All readers MUST also accept the legacy form (no markers, just `# Client: <name>`)
# for configs created before the marker change.

# List peer names declared in <iface>.conf. Returns the union of new-format
# BEGIN_PEER markers and legacy `# Client/Site/Peer-to-Peer:` comments, deduped
# in the order first seen — so mixed-format configs work during migration.
list_config_peers() {
    local config_file="$1"
    [[ -f "$config_file" ]] || return 0
    awk '
        match($0, /^# BEGIN_PEER ([^ ]+)/, m)                              { if (!(m[1] in seen)) { seen[m[1]]=1; print m[1] }; next }
        match($0, /^#[[:space:]]*(Client|Site|Peer-to-Peer):[[:space:]]*([^[:space:]]+)/, m) { if (!(m[2] in seen)) { seen[m[2]]=1; print m[2] }; next }
    ' "$config_file"
}

# Echo the public key recorded for the given peer in <iface>.conf (or empty).
get_peer_pubkey() {
    local config_file="$1"
    local name="$2"
    [[ -f "$config_file" ]] || return 0
    awk -v name="$name" -v begin="^# BEGIN_PEER ${name}$" -v legacy="^#[[:space:]]*(Client|Site|Peer-to-Peer):[[:space:]]*${name}[[:space:]]*$" '
        $0 ~ begin || $0 ~ legacy { in_peer=1; next }
        in_peer && /^# END_PEER / { exit }
        in_peer && /^#[[:space:]]*(Client|Site|Peer-to-Peer):/ { exit }
        in_peer && /^PublicKey[[:space:]]*=/ {
            sub(/^PublicKey[[:space:]]*=[[:space:]]*/, "", $0)
            print $0
            exit
        }
    ' "$config_file"
}

# Delete a peer's full block from <iface>.conf in place. Handles both the new
# marker format and the legacy `# Client: name` form. Preserves perms/owner.
remove_peer_block() {
    local config_file="$1"
    local name="$2"
    [[ -f "$config_file" ]] || error_exit "Config not found: $config_file"

    local tmp
    tmp=$(mktemp) || error_exit "mktemp failed"
    trap 'rm -f "$tmp"' RETURN

    local perms owner
    perms=$(stat -c '%a' "$config_file" 2>/dev/null || echo 600)
    owner=$(stat -c '%U:%G' "$config_file" 2>/dev/null || echo root:root)

    awk -v name="$name" -v begin_re="^# BEGIN_PEER ${name}$" -v end_re="^# END_PEER ${name}$" \
        -v legacy_re="^#[[:space:]]*(Client|Site|Peer-to-Peer):[[:space:]]*${name}[[:space:]]*$" '
        # New format: skip from BEGIN_PEER to END_PEER inclusive
        $0 ~ begin_re { skip=1; next }
        skip && $0 ~ end_re { skip=0; next }
        skip { next }
        # Legacy format: skip from `# Client: name` until blank line / next legacy marker / EOF
        $0 ~ legacy_re { legacy=1; next }
        legacy && /^[[:space:]]*$/ { legacy=0; next }
        legacy && /^#[[:space:]]*(Client|Site|Peer-to-Peer):/ { legacy=0; print; next }
        legacy && /^\[Peer\]$/ { next }
        legacy && /^(PublicKey|AllowedIPs|Endpoint|PersistentKeepalive|PresharedKey)[[:space:]]*=/ { next }
        legacy { legacy=0 }
        { print }
    ' "$config_file" > "$tmp" || error_exit "Failed to rewrite config"

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
# Each line: TYPE|VALUE  (so reset-wireguard.sh can act on them precisely)
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
