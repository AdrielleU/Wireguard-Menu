#!/bin/bash
################################################################################
# WireGuard Health Check
# Description: One-shot health check for one or all WireGuard interfaces.
#              Designed to be run from cron or a systemd timer.
#
# Health checks (all must pass):
#   1. wg-quick@<iface> service is active
#   2. the kernel interface exists
#   3. every Address declared in <iface>.conf is actually assigned to the
#      kernel interface — catches the wg-quick race where the service comes
#      up "successfully" but the IP never makes it onto the interface
#   4. the firewall backend recorded in the per-interface manifest is still
#      effective: firewalld/ufw services active, or nftables rules we wrote
#      at setup time still present in the kernel. Without this, the VPN
#      looks healthy but the UDP port is closed and peers can't connect.
#
# Peer reachability is reported informationally only — peers may legitimately
# be offline, so they don't trigger restarts.
#
# Exit codes:
#   0 = all checked interfaces healthy
#   1 = one or more interfaces unhealthy (and --restart did not recover them)
#
# Usage:
#   sudo ./healthcheck.sh                     # check all wg interfaces
#   sudo ./healthcheck.sh -i wg0              # check just wg0
#   sudo ./healthcheck.sh --restart           # restart any unhealthy iface
#   sudo ./healthcheck.sh -v                  # verbose (also report healthy)
#
# Cron example (every 5 min, auto-recover, quiet on success):
#   */5 * * * * /home/wireguard-scripts/healthcheck.sh --restart
#
# systemd timer: pair this with a oneshot service that runs the script.
################################################################################

set -uo pipefail   # not -e — we want the script to keep going across interfaces

source "$(dirname "$0")/utils.sh"

WG_INTERFACE=""
DO_RESTART=false
VERBOSE=false
STALE_HANDSHAKE_SECS=300   # report a peer as "stale" if no handshake in this long

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -i|--interface) WG_INTERFACE="$2"; shift 2 ;;
            -r|--restart)   DO_RESTART=true; shift ;;
            -v|--verbose)   VERBOSE=true; shift ;;
            -h|--help)
                sed -n '3,24p' "$0" | sed 's/^# \?//'
                exit 0
                ;;
            *) error_exit "Unknown option: $1" ;;
        esac
    done
}

# Echoes "ok" or a short failure reason for one interface.
# Health = service active AND kernel interface exists AND every Address
# declared in <iface>.conf is actually assigned to the kernel interface.
# That last check catches the case where wg-quick reports success but the
# IP didn't make it onto the interface — restart usually fixes it.
check_interface() {
    local iface="$1"

    if ! systemctl is-active --quiet "wg-quick@${iface}"; then
        echo "service-inactive"; return
    fi
    if ! ip link show "$iface" &>/dev/null; then
        echo "interface-missing"; return
    fi

    local conf="${WG_CONFIG_DIR}/${iface}.conf"
    if [[ -f "$conf" ]]; then
        local assigned
        assigned=$(ip -o addr show dev "$iface" 2>/dev/null \
                   | awk '{print $4}')   # both v4 and v6
        local addr
        while read -r addr; do
            [[ -z "$addr" ]] && continue
            if ! grep -Fxq "$addr" <<<"$assigned"; then
                echo "address-missing:${addr}"
                return
            fi
        done < <(awk -F'=' '
            /^[[:space:]]*\[/ { in_iface = ($0 ~ /^\[Interface\]/); next }
            in_iface && /^[[:space:]]*Address[[:space:]]*=/ {
                gsub(/[[:space:]]/, "", $2)
                n = split($2, a, ",")
                for (i=1;i<=n;i++) print a[i]
            }
        ' "$conf")
    fi

    echo "ok"
}

# Verify the firewall backend(s) recorded in this interface's manifest are
# still effective. For firewalld/ufw we check the service is active (a stopped
# service means no rules are loaded). For nftables the "service" concept
# doesn't apply, so we check that the specific FORWARD rule we wrote at setup
# time is still present in the running kernel — a flush or reboot without
# persistence would silently lose it.
# Returns "ok" or a short failure reason.
check_firewall() {
    local iface="$1"
    local manifest; manifest=$(manifest_path "$iface")
    [[ -f "$manifest" ]] || { echo "ok"; return; }   # no manifest -> can't check

    local backends; backends=$(awk -F'|' '/^FW_/ {print $1}' "$manifest" | sort -u)
    [[ -z "$backends" ]] && { echo "ok"; return; }

    local b
    while read -r b; do
        [[ -z "$b" ]] && continue
        case "$b" in
            FW_FIREWALLD)
                systemctl is-active --quiet firewalld 2>/dev/null \
                    || { echo "firewall-down:firewalld"; return; }
                ;;
            FW_UFW)
                if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -qi "Status: active"; then :
                elif systemctl is-active --quiet ufw 2>/dev/null; then :
                else echo "firewall-down:ufw"; return
                fi
                ;;
            FW_NFT)
                if ! command -v nft &>/dev/null \
                   || ! nft list table inet wireguard 2>/dev/null | grep -q "iifname \"${iface}\""; then
                    echo "firewall-rules-missing:nftables"; return
                fi
                ;;
        esac
    done <<< "$backends"

    echo "ok"
}

# Print the peer reachability summary for one interface (informational).
report_peers() {
    local iface="$1"
    command -v wg &>/dev/null || return 0
    local now total stale connected
    now=$(date +%s)
    total=0; stale=0; connected=0

    while IFS=$'\t' read -r pubkey _ endpoint _ handshake _ _ _; do
        [[ -z "$pubkey" ]] && continue
        ((total++)) || true
        if [[ -z "$handshake" || "$handshake" == 0 ]]; then
            ((stale++)) || true
        elif (( now - handshake > STALE_HANDSHAKE_SECS )); then
            ((stale++)) || true
        else
            ((connected++)) || true
        fi
    done < <(wg show "$iface" dump 2>/dev/null | tail -n +2)

    if (( total == 0 )); then
        echo "  peers: 0 configured"
    else
        echo "  peers: ${connected}/${total} connected (handshake within ${STALE_HANDSHAKE_SECS}s), ${stale} stale"
    fi
}

# Check + optionally restart one interface. Returns 0 healthy, 1 unhealthy.
process_interface() {
    local iface="$1"
    local result; result=$(check_interface "$iface")

    if [[ "$result" != "ok" ]]; then
        print_warning "${iface}: ${result}"
        log_audit "HEALTHCHECK_FAIL" "interface=${iface} reason=${result}"

        if $DO_RESTART; then
            print_info "${iface}: restarting wg-quick@${iface} ..."
            if systemctl restart "wg-quick@${iface}"; then
                sleep 2
                local recheck; recheck=$(check_interface "$iface")
                if [[ "$recheck" == "ok" ]]; then
                    print_success "${iface}: recovered after restart"
                    log_audit "HEALTHCHECK_RECOVERY" "interface=${iface}"
                    # fall through to firewall check
                else
                    print_error "${iface}: still ${recheck} after restart"
                    log_audit "HEALTHCHECK_RESTART_FAILED" "interface=${iface} reason=${recheck}"
                    return 1
                fi
            else
                print_error "${iface}: systemctl restart failed"
                return 1
            fi
        else
            return 1
        fi
    fi

    # Interface is up — verify the firewall we configured is still effective.
    # A stopped firewalld/ufw silently closes the UDP port; flushed nftables
    # drops FORWARD traffic. Neither shows up in `wg-quick` status.
    local fw_result; fw_result=$(check_firewall "$iface")
    if [[ "$fw_result" != "ok" ]]; then
        print_warning "${iface}: ${fw_result}"
        log_audit "HEALTHCHECK_FAIL" "interface=${iface} reason=${fw_result}"

        if $DO_RESTART; then
            local fw_svc=""
            case "$fw_result" in
                firewall-down:firewalld) fw_svc=firewalld ;;
                firewall-down:ufw)       fw_svc=ufw ;;
            esac
            if [[ -n "$fw_svc" ]]; then
                print_info "${iface}: starting ${fw_svc} ..."
                if systemctl start "$fw_svc" 2>/dev/null; then
                    sleep 2
                    local refw; refw=$(check_firewall "$iface")
                    if [[ "$refw" == "ok" ]]; then
                        print_success "${iface}: ${fw_svc} started"
                        log_audit "HEALTHCHECK_RECOVERY" "interface=${iface} component=firewall"
                    else
                        print_error "${iface}: ${fw_svc} still failing after start (${refw})"
                        return 1
                    fi
                else
                    print_error "${iface}: failed to start ${fw_svc}"
                    return 1
                fi
            else
                # nftables rules vanished — no safe auto-recovery from cron
                print_warning "${iface}: cannot auto-recover ${fw_result}; rerun setup-wireguard.sh firewall config"
                return 1
            fi
        else
            return 1
        fi
    fi

    if $VERBOSE; then
        print_success "${iface}: healthy"
        report_peers "$iface"
    fi
    return 0
}

main() {
    parse_arguments "$@"
    check_root

    local -a interfaces
    if [[ -n "$WG_INTERFACE" ]]; then
        interfaces=("$WG_INTERFACE")
    else
        mapfile -t interfaces < <(detect_servers)
    fi
    if [[ ${#interfaces[@]} -eq 0 ]]; then
        $VERBOSE && print_info "No WireGuard interfaces configured — nothing to check"
        exit 0
    fi

    local failures=0
    for iface in "${interfaces[@]}"; do
        process_interface "$iface" || ((failures++)) || true
    done

    exit $(( failures > 0 ? 1 : 0 ))
}

main "$@"
