#!/bin/bash
################################################################################
# WireGuard Traffic Logger
# Description: Record every new connection that crosses a WireGuard tunnel --
#              which machine on one LAN opened a connection to which machine
#              and port on another -- as one kernel log line per connection.
#
# log-connections.sh records the LINK: when a site came up and went down. This
# records what went THROUGH it. WireGuard itself logs no traffic, and a tunnel
# in firewalld's trusted zone passes everything without a word, so without this
# there is no record anywhere of who on LAN A reached what on LAN B.
#
# How: an nftables table of its own, `inet wireguard_traffic`, whose chains only
# log. Policy accept and no drop/reject, so it cannot block anything, and it is
# a separate table, so firewalld's rules and the tunnel are untouched. Its
# chains sit at priority 100, after firewalld's filter chains, so what it logs
# is what the firewall actually let through.
#
#   forward  connections routed through a tunnel, either direction (LAN to LAN)
#   input    connections to this box itself arriving over a tunnel
#
# One line per connection, not per packet. `ct state new` alone is not enough:
# the kernel counts a flow as new until it sees a reply, so a UDP stream, an
# unanswered ping or a retried SYN matched on EVERY packet (20 lines for one
# 20-packet voice stream). `ct status & confirmed == 0` narrows it to the first
# packet: a connection is confirmed as soon as its first packet has passed, and
# every later one finds it confirmed. Each line is the kernel's standard LOG format, labeled with WG_TRAFFIC_LOG_PREFIX so it
# reads like every other record in /var/log/wireguard.log, where it lands:
#
#   kernel: action=TRAFFIC IN=wg0 OUT=eth1 SRC=192.168.50.23 DST=192.168.10.5 ... PROTO=TCP DPT=443 ...
#
# Tunnels are matched by interface KIND where the kernel supports it, so one
# added later is covered with no reload; otherwise by the names configured when
# this runs (re-run install.sh after adding one).
#
# Not logged: connections to the ports in WG_TRAFFIC_SKIP_PORTS, DNS (53) by
# default. Lookups are usually most of the new connections on a LAN and record
# a name query, not access to anything -- and rsyslog's default intake limit
# (20000 messages per 10 min, shared by the whole host) would drop them and
# every other service's lines alike once exceeded. Set it empty to log DNS too.
#
# Not logged either: connections where EITHER end is on the skip list --
# routers', switches' and printers' own management traffic, and the monitoring
# that polls them. The list is read from two places and merged:
#
#   /etc/wireguard/traffic-log.skip        one entry per line, # comments
#   # TrafficLog-Skip = <entries>          in any <iface>.conf, beside the
#                                          Healthcheck-* lines
#
# An entry is an IPv4/IPv6 address, a first-last range or a CIDR. The list is
# host-wide wherever it is written, since the table covers every tunnel at once.
# Restart the unit to apply a change; the list in force is recorded in each
# TRAFFIC_LOG_START. Never list an address that stands in for a whole site (a
# router translating its LAN into the tunnel): that removes the site from the log.
#
# Usage:
#   traffic-log.sh start       load the table, replacing any earlier version
#   traffic-log.sh stop        remove it
#   traffic-log.sh status      is it loaded, and connections logged since
#   traffic-log.sh --check     validate the ruleset with `nft -c`; load nothing
#   traffic-log.sh --dry-run   print the ruleset `start` would load
################################################################################

set -uo pipefail

source "$(dirname "$0")/utils.sh"

TABLE="wireguard_traffic"
SKIP_PORTS="${WG_TRAFFIC_SKIP_PORTS-53}"   # space-separated; "" logs everything
SKIP_FILE="${WG_TRAFFIC_SKIP_FILE:-${WG_CONFIG_DIR}/traffic-log.skip}"
SKIP_V4=()   # filled from SKIP_FILE by read_skip_hosts
SKIP_V6=()

# Every nft call takes its ruleset as an ARGUMENT, never on stdin. Under SELinux
# (RHEL, enforcing) nft does not run in this script's domain: executing it
# transitions to iptables_t, which then has to be allowed to read whatever this
# script hands it. A pipe or heredoc is one more thing that must be allowed;
# an argument is not. It is how RHEL's own nftables.service runs nft, which is
# the combination the policy is known to permit.

# True if this kernel and nft can match an interface by kind. Check mode, so
# nothing is loaded.
kind_supported() {
    nft -c 'table inet wireguard_kind_probe {
    chain c { type filter hook forward priority 0; policy accept; meta iifkind "wireguard"; }
}' &>/dev/null
}

# True if nft accepts <addr> as an element of a <ipv4_addr|ipv6_addr> set.
# nft itself is the validator, so whatever passes here is exactly what loads.
nft_accepts_addr() {
    nft -c "table inet wireguard_skip_probe {
    set s { type $1; flags interval; elements = { $2 } }
}" &>/dev/null
}

# Add one entry to SKIP_V4 / SKIP_V6, or report <where> (file:line) and drop it.
# A bad entry is IGNORED rather than failing the load: a typo in the list must
# never switch the whole traffic log off, and ignoring it only means logging more.
add_skip_entry() {
    local addr="$1" where="$2"
    # Character check first: nothing but address characters ever reaches nft,
    # and a hostname is never looked up. '-' is a first-last range, which nft
    # takes as it is.
    if [[ "$addr" =~ ^[0-9./-]+$ ]] && nft_accepts_addr ipv4_addr "$addr"; then
        SKIP_V4+=("$addr")
    elif [[ "$addr" == *:* && "$addr" =~ ^[0-9A-Fa-f:./-]+$ ]] && nft_accepts_addr ipv6_addr "$addr"; then
        SKIP_V6+=("$addr")
    else
        print_warning "${where}: '${addr}' is not an IP address, range or CIDR, so it is ignored"
    fi
}

# Entries in <text>, separated by spaces or commas; `#` starts a comment.
add_skip_list() {
    local text="$1" where="$2" addr
    local -a toks
    IFS=$', \t' read -r -a toks <<<"${text%%#*}"
    for addr in "${toks[@]}"; do add_skip_entry "$addr" "$where"; done
}

# Fill SKIP_V4 / SKIP_V6 from both sources: the skip file, and every
# "# TrafficLog-Skip = ..." line in a tunnel's conf. Read the way healthcheck.sh
# reads its Healthcheck-* lines -- everything after the first =, several lines
# allowed -- so the two sit side by side and behave alike.
read_skip_hosts() {
    SKIP_V4=(); SKIP_V6=()
    local line n conf
    if [[ -f "$SKIP_FILE" ]]; then
        n=0
        while IFS= read -r line || [[ -n "$line" ]]; do
            n=$((n + 1))
            add_skip_list "$line" "${SKIP_FILE}:${n}"
        done < "$SKIP_FILE"
    fi
    shopt -s nullglob
    for conf in "${WG_CONFIG_DIR}"/*.conf; do
        n=0
        while IFS= read -r line || [[ -n "$line" ]]; do
            n=$((n + 1))
            [[ "$line" =~ ^[[:space:]]*#[[:space:]]*TrafficLog-Skip[[:space:]]*=(.*)$ ]] || continue
            add_skip_list "${BASH_REMATCH[1]}" "${conf}:${n}"
        done < "$conf"
    done
    shopt -u nullglob
}

# The ruleset `start` loads. Echoes it; dies if there is nothing to match.
ruleset() {
    local iif oif not_iif skip="" names
    if kind_supported; then
        iif='meta iifkind "wireguard"'
        oif='meta oifkind "wireguard"'
        not_iif='meta iifkind != "wireguard"'
    else
        names=$(detect_servers | sed 's/.*/"&"/' | paste -sd, -)
        [[ -n "$names" ]] || die "No WireGuard interfaces to match, and this kernel cannot match them by kind"
        iif="iifname { ${names} }"
        oif="oifname { ${names} }"
        not_iif="iifname != { ${names} }"
    fi
    local -a skip_ports
    read -r -a skip_ports <<<"$SKIP_PORTS"
    if (( ${#skip_ports[@]} > 0 )); then
        local ports; ports=$(IFS=,; echo "${skip_ports[*]}")
        # accept only ends THIS chain; the packet still meets every other table.
        skip="meta l4proto { tcp, udp } th dport { ${ports} } accept"
    fi
    # Skipped hosts: named sets so overlapping entries (an address inside a
    # listed range) merge instead of failing the load. Either end matches.
    local sets="" skip_hosts=""
    if (( ${#SKIP_V4[@]} > 0 )); then
        sets+="set skip_v4 { type ipv4_addr; flags interval; auto-merge; elements = { $(IFS=,; echo "${SKIP_V4[*]}") } }"$'\n'
        skip_hosts+="ip saddr @skip_v4 accept"$'\n'"ip daddr @skip_v4 accept"$'\n'
    fi
    if (( ${#SKIP_V6[@]} > 0 )); then
        sets+="set skip_v6 { type ipv6_addr; flags interval; auto-merge; elements = { $(IFS=,; echo "${SKIP_V6[*]}") } }"$'\n'
        skip_hosts+="ip6 saddr @skip_v6 accept"$'\n'"ip6 daddr @skip_v6 accept"$'\n'
    fi
    local log="ct state new ct status & confirmed == 0 counter log prefix \"${WG_TRAFFIC_LOG_PREFIX}\" level info"
    cat <<EOF
table inet ${TABLE} {
${sets}
    chain forward {
        type filter hook forward priority 100; policy accept;
        ${skip}
${skip_hosts}
        ${iif} ${log}
        ${oif} ${not_iif} ${log}
    }
    chain input {
        type filter hook input priority 100; policy accept;
        ${skip}
${skip_hosts}
        ${iif} ${log}
    }
}
EOF
}

# One transaction: create-if-missing, delete, redefine. Loading is atomic, so a
# reload never leaves a moment with half a table.
cmd_start() {
    local rules match
    rules=$(ruleset) || exit 1
    nft "table inet ${TABLE}
delete table inet ${TABLE}
${rules}" || die "nft refused the ruleset; see: $0 --dry-run"
    match=$(kind_supported && echo kind || echo names)
    local skipped=("${SKIP_V4[@]}" "${SKIP_V6[@]}")
    print_success "traffic logging on (match=${match}${SKIP_PORTS:+, not logging ports ${SKIP_PORTS}}, skipping ${#skipped[@]} address(es))"
    # The exclusions in force belong in the trail: an auditor asking why a
    # connection is missing needs to see that it was excluded, and since when.
    log_audit "TRAFFIC_LOG_START" "table=${TABLE} match=${match} skip_ports=${SKIP_PORTS// /,} skip_hosts=$(IFS=,; echo "${skipped[*]:-none}")"
}

cmd_stop() {
    if nft delete table inet "$TABLE" 2>/dev/null; then
        print_success "traffic logging off"
        # The gap starts here; an auditor will ask when it began.
        log_audit "TRAFFIC_LOG_STOP" "table=${TABLE}"
    fi
    return 0
}

cmd_status() {
    local listing total
    if ! listing=$(nft list table inet "$TABLE" 2>/dev/null); then
        print_warning "traffic logging is OFF: table inet ${TABLE} is not loaded"
        return 1
    fi
    total=$(grep -o 'counter packets [0-9]*' <<<"$listing" | awk '{ s += $3 } END { print s + 0 }')
    print_success "traffic logging is on: ${total} connection(s) logged since the table was loaded"
    local listed
    listed=$(grep -oE 'elements = \{[^}]*\}' <<<"$listing" | sed -E 's/elements = \{ *//; s/ *\}//' | paste -sd, -)
    print_info "not logging connections to or from: ${listed:-nothing (no addresses in ${SKIP_FILE} or any TrafficLog-Skip line)}"
}

case "${1:-}" in
    start)      check_root; read_skip_hosts; cmd_start ;;
    stop)       check_root; cmd_stop ;;
    status)     check_root; cmd_status ;;
    --check)    check_root; read_skip_hosts; rules=$(ruleset) || exit 1; nft -c "$rules" ;;
    --dry-run)  check_root; read_skip_hosts; ruleset ;;
    -h|--help)  sed -n '3,61p' "$0" | sed 's/^# \?//' ;;
    *)          die "Usage: $0 start|stop|status|--check|--dry-run" ;;
esac
