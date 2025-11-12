#!/bin/bash
################################################################################
# WireGuard Connection Logger - HIPAA Compliant (All-in-One)
#
# This single script:
#   - Logs VPN connection events (CONNECT/DISCONNECT)
#   - Installs itself as a systemd timer service
#   - Manages installation/uninstallation
#
# Usage:
#   sudo ./wireguard-connection-logger.sh install    # Install logging
#   sudo ./wireguard-connection-logger.sh uninstall  # Remove logging
#   sudo ./wireguard-connection-logger.sh status     # Check status
#   sudo ./wireguard-connection-logger.sh run        # Run logger manually (test)
#
# After installation:
#   journalctl -t wireguard-connections -f           # View logs
#   journalctl -t wireguard-connections ACTION=CONNECT  # Query specific events
#
################################################################################

set -euo pipefail

# Configuration
STATE_DIR="/var/lib/wireguard-connections"
AUDIT_TAG="wireguard-connections"
INSTALL_PATH="/usr/local/bin/wireguard-connection-logger.sh"
SERVICE_PATH="/etc/systemd/system/wireguard-connection-logger.service"
TIMER_PATH="/etc/systemd/system/wireguard-connection-logger.timer"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

################################################################################
# LOGGING FUNCTIONS
################################################################################

#
# Log connection event to systemd journal with structured fields
#
log_connection_event() {
    local action="$1"
    local interface="$2"
    local peer_name="$3"
    local peer_pubkey="$4"
    local endpoint="${5:-unknown}"
    local last_handshake="${6:-never}"
    local transfer_rx="${7:-0}"
    local transfer_tx="${8:-0}"

    systemd-cat -t "$AUDIT_TAG" -p info <<EOF
ACTION=$action
INTERFACE=$interface
PEER_NAME=$peer_name
PEER_PUBKEY=$peer_pubkey
ENDPOINT=$endpoint
LAST_HANDSHAKE=$last_handshake
TRANSFER_RX=$transfer_rx
TRANSFER_TX=$transfer_tx
MESSAGE=$action: $peer_name ($interface) endpoint=$endpoint handshake=$last_handshake
EOF
}

#
# Get peer name from config file comment
#
get_peer_name() {
    local interface="$1"
    local pubkey="$2"
    local config="/etc/wireguard/${interface}.conf"

    if [[ ! -f "$config" ]]; then
        echo "unknown"
        return
    fi

    local name
    name=$(awk -v pubkey="$pubkey" '
        /^# (Client|Peer|Site):/ {
            sub(/^# (Client|Peer|Site): */, "")
            name = $0
        }
        /^PublicKey/ && $3 == pubkey && name != "" {
            print name
            exit
        }
    ' "$config")

    echo "${name:-unknown}"
}

#
# Check if handshake is recent (within 3 minutes = active connection)
#
is_connected() {
    local handshake_seconds="$1"
    [[ "$handshake_seconds" == "0" ]] && return 1
    [[ "$handshake_seconds" -lt 180 ]] && return 0
    return 1
}

#
# Process each WireGuard interface
#
process_interface() {
    local interface="$1"
    local state_file="${STATE_DIR}/${interface}.state"

    touch "$state_file"

    local wg_output
    if ! wg_output=$(wg show "$interface" dump 2>/dev/null); then
        return 0
    fi

    local current_state=()

    while IFS=$'\t' read -r pubkey preshared endpoint allowed_ips handshake_sec rx tx keepalive; do
        [[ -z "$pubkey" ]] && continue

        local peer_name
        peer_name=$(get_peer_name "$interface" "$pubkey")

        local is_active="false"
        if is_connected "$handshake_sec"; then
            is_active="true"
        fi

        local state_key="${pubkey}:${is_active}"
        current_state+=("$state_key")

        local prev_state
        prev_state=$(grep "^${pubkey}:" "$state_file" 2>/dev/null || echo "")

        local endpoint_display="${endpoint:-(none)}"
        local handshake_display
        if [[ "$handshake_sec" == "0" ]]; then
            handshake_display="never"
        else
            handshake_display="${handshake_sec}s ago"
        fi

        # Detect state changes
        if [[ -z "$prev_state" ]]; then
            if [[ "$is_active" == "true" ]]; then
                log_connection_event "CONNECT" "$interface" "$peer_name" "$pubkey" \
                    "$endpoint_display" "$handshake_display" "$rx" "$tx"
                [[ -t 1 ]] && echo -e "${GREEN}[CONNECT]${NC} $peer_name on $interface"
            else
                log_connection_event "PEER_ADDED" "$interface" "$peer_name" "$pubkey" \
                    "$endpoint_display" "$handshake_display" "$rx" "$tx"
                [[ -t 1 ]] && echo -e "${YELLOW}[DISCOVERED]${NC} Peer $peer_name on $interface (not connected)"
            fi
        elif [[ "$prev_state" != "$state_key" ]]; then
            if [[ "$is_active" == "true" ]]; then
                log_connection_event "CONNECT" "$interface" "$peer_name" "$pubkey" \
                    "$endpoint_display" "$handshake_display" "$rx" "$tx"
                [[ -t 1 ]] && echo -e "${GREEN}[CONNECT]${NC} $peer_name on $interface"
            else
                log_connection_event "DISCONNECT" "$interface" "$peer_name" "$pubkey" \
                    "$endpoint_display" "$handshake_display" "$rx" "$tx"
                [[ -t 1 ]] && echo -e "${RED}[DISCONNECT]${NC} $peer_name from $interface"
            fi
        fi

    done < <(echo "$wg_output" | tail -n +2)

    printf "%s\n" "${current_state[@]}" > "$state_file"
}

#
# Run the connection logger
#
run_logger() {
    mkdir -p "$STATE_DIR"

    local interfaces
    mapfile -t interfaces < <(wg show interfaces 2>/dev/null | tr ' ' '\n')

    if [[ ${#interfaces[@]} -eq 0 ]]; then
        [[ -t 1 ]] && echo "No WireGuard interfaces found"
        exit 0
    fi

    for interface in "${interfaces[@]}"; do
        [[ -n "$interface" ]] && process_interface "$interface"
    done
}

################################################################################
# INSTALLATION FUNCTIONS
################################################################################

info() { echo -e "${BLUE}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This command must be run as root"
        echo "Please run: sudo $0 $*"
        exit 1
    fi
}

check_wireguard() {
    if ! command -v wg &>/dev/null; then
        error "WireGuard is not installed"
        exit 1
    fi
}

#
# Install the logger
#
install_logger() {
    info "Installing WireGuard Connection Logger..."

    # Copy this script to install location
    local script_path
    script_path="$(realpath "${BASH_SOURCE[0]}")"

    if [[ "$script_path" != "$INSTALL_PATH" ]]; then
        info "Installing script to $INSTALL_PATH"
        cp "$script_path" "$INSTALL_PATH"
        chmod +x "$INSTALL_PATH"
        success "Script installed"
    else
        info "Script already at install location"
    fi

    # Create systemd service file
    info "Creating systemd service: $SERVICE_PATH"
    cat > "$SERVICE_PATH" <<'EOF'
[Unit]
Description=WireGuard Connection Logger
After=wg-quick.target
Requires=systemd-journald.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/wireguard-connection-logger.sh run

# Performance and security hardening
Nice=19
CPUQuota=10%
MemoryMax=50M
TasksMax=10

# Security
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/wireguard-connections
NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictRealtime=yes
RestrictNamespaces=yes

# Capabilities
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=wireguard-connection-logger

[Install]
WantedBy=multi-user.target
EOF
    success "Service file created"

    # Create systemd timer file
    info "Creating systemd timer: $TIMER_PATH"
    cat > "$TIMER_PATH" <<'EOF'
[Unit]
Description=WireGuard Connection Logger Timer
After=network.target

[Timer]
# Run every 2 minutes (polling for connections)
OnBootSec=1min
OnUnitActiveSec=2min

# Performance optimization
RandomizedDelaySec=30
WakeSystem=false
Persistent=true

[Install]
WantedBy=timers.target
EOF
    success "Timer file created"

    # Create systemd path unit (triggers on config changes)
    local path_file="/etc/systemd/system/wireguard-connection-logger.path"
    info "Creating systemd path unit: $path_file"
    cat > "$path_file" <<'EOF'
[Unit]
Description=WireGuard Connection Logger Path Watcher
Documentation=man:systemd.path(5)

[Path]
# Trigger when any WireGuard config changes
PathModified=/etc/wireguard/
# Also trigger when wg-quick services restart
Unit=wireguard-connection-logger.service

[Install]
WantedBy=multi-user.target
EOF
    success "Path unit created"

    # Create state directory
    info "Creating state directory"
    mkdir -p "$STATE_DIR"
    chmod 700 "$STATE_DIR"
    success "State directory created"

    # Reload systemd
    info "Reloading systemd daemon"
    systemctl daemon-reload
    success "Systemd reloaded"

    # Enable and start timer (periodic polling)
    info "Enabling and starting timer"
    systemctl enable wireguard-connection-logger.timer
    systemctl start wireguard-connection-logger.timer
    success "Timer enabled and started"

    # Enable and start path watcher (event-driven for config changes)
    info "Enabling and starting path watcher"
    systemctl enable wireguard-connection-logger.path
    systemctl start wireguard-connection-logger.path
    success "Path watcher enabled and started"

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    success "WireGuard Connection Logger installed successfully!"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "Logging Mode: Hybrid (Timer + Path Watcher)"
    echo "  ✓ Timer: Checks connections every 2 minutes"
    echo "  ✓ Path watcher: Triggers on config changes (instant)"
    echo ""
    echo "View logs:     journalctl -t wireguard-connections -f"
    echo "Query events:  journalctl -t wireguard-connections ACTION=CONNECT"
    echo "Check status:  systemctl status wireguard-connection-logger.timer"
    echo "               systemctl status wireguard-connection-logger.path"
    echo ""
}

#
# Uninstall the logger
#
uninstall_logger() {
    info "Uninstalling WireGuard Connection Logger..."

    local path_file="/etc/systemd/system/wireguard-connection-logger.path"

    # Stop and disable timer
    if systemctl is-active --quiet wireguard-connection-logger.timer; then
        info "Stopping timer"
        systemctl stop wireguard-connection-logger.timer
    fi

    if systemctl is-enabled --quiet wireguard-connection-logger.timer 2>/dev/null; then
        info "Disabling timer"
        systemctl disable wireguard-connection-logger.timer
    fi

    # Stop and disable path watcher
    if systemctl is-active --quiet wireguard-connection-logger.path 2>/dev/null; then
        info "Stopping path watcher"
        systemctl stop wireguard-connection-logger.path
    fi

    if systemctl is-enabled --quiet wireguard-connection-logger.path 2>/dev/null; then
        info "Disabling path watcher"
        systemctl disable wireguard-connection-logger.path
    fi

    # Remove files
    [[ -f "$SERVICE_PATH" ]] && rm -f "$SERVICE_PATH" && info "Removed service file"
    [[ -f "$TIMER_PATH" ]] && rm -f "$TIMER_PATH" && info "Removed timer file"
    [[ -f "$path_file" ]] && rm -f "$path_file" && info "Removed path watcher file"
    [[ -f "$INSTALL_PATH" ]] && rm -f "$INSTALL_PATH" && info "Removed script"

    systemctl daemon-reload
    success "Systemd reloaded"

    echo ""
    read -rp "Remove state directory $STATE_DIR? [y/N]: " -n 1
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$STATE_DIR"
        success "State directory removed"
    else
        info "State directory preserved"
    fi

    echo ""
    success "WireGuard Connection Logger uninstalled"
}

#
# Show status
#
show_status() {
    local path_file="/etc/systemd/system/wireguard-connection-logger.path"

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo " WireGuard Connection Logger Status"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    if [[ ! -f "$INSTALL_PATH" ]]; then
        error "Not installed"
        echo "Run: sudo $0 install"
        return 1
    fi

    success "Installed: $INSTALL_PATH"

    [[ -f "$SERVICE_PATH" ]] && success "Service: $SERVICE_PATH" || warn "Service: NOT FOUND"
    [[ -f "$TIMER_PATH" ]] && success "Timer: $TIMER_PATH" || warn "Timer: NOT FOUND"
    [[ -f "$path_file" ]] && success "Path watcher: $path_file" || warn "Path watcher: NOT FOUND"

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Timer Status (periodic polling every 2 min):"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    systemctl status wireguard-connection-logger.timer --no-pager || true

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Path Watcher Status (event-driven on config changes):"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    systemctl status wireguard-connection-logger.path --no-pager || true

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Recent Connection Events:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    journalctl -t wireguard-connections -n 10 --no-pager || true

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

#
# Show usage
#
usage() {
    cat <<EOF
WireGuard Connection Logger - HIPAA Compliant (All-in-One)

Usage:
  $0 install      Install connection logger
  $0 uninstall    Uninstall connection logger
  $0 status       Show logger status
  $0 run          Run logger manually (test mode)
  $0 help         Show this help

Description:
  Logs VPN connection/disconnection events for HIPAA compliance.
  Captures: who connected, when, from which IP (before masquerading),
  and data transfer statistics.

Features:
  - Hybrid event model (timer + path watcher)
  - Timer: Polls connections every 2 minutes
  - Path watcher: Instant trigger on config changes
  - Structured logging (efficient querying)
  - Resource-limited (CPU: 10%, Memory: 50MB)
  - Security-hardened systemd service
  - Logs only state changes (reduces noise)

Why Not Pure Event-Driven?
  WireGuard intentionally has no event system for connections.
  The kernel module is silent (for privacy/security).
  Polling 'wg show' is the standard approach for monitoring.

After Installation:
  View logs:     journalctl -t wireguard-connections -f
  Query events:  journalctl -t wireguard-connections ACTION=CONNECT
  By interface:  journalctl -t wireguard-connections INTERFACE=wg0
  By peer:       journalctl -t wireguard-connections PEER_NAME=site1
  Export JSON:   journalctl -t wireguard-connections -o json-pretty
  Check timers:  systemctl list-timers | grep wireguard

EOF
}

################################################################################
# MAIN
################################################################################

main() {
    local command="${1:-help}"

    case "$command" in
        install)
            check_root "$@"
            check_wireguard
            install_logger
            ;;
        uninstall)
            check_root "$@"
            uninstall_logger
            ;;
        status)
            show_status
            ;;
        run)
            run_logger
            ;;
        help|--help|-h)
            usage
            ;;
        *)
            error "Unknown command: $command"
            echo ""
            usage
            exit 1
            ;;
    esac
}

main "$@"
