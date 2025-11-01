#!/bin/bash
################################################################################
# WireGuard List Peer Script
# Description: List all peers or view a specific peer's status
# Usage: ./list-peer.sh [OPTIONS]
################################################################################

set -euo pipefail

WG_CONFIG_DIR="/etc/wireguard"
WG_INTERFACE=""
PEER_NAME=""
DETAILED=false

################################################################################
# COLORS
################################################################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

print_success() { echo -e "${GREEN}[✓]${NC} $1"; }
print_error() { echo -e "${RED}[✗]${NC} $1" >&2; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_info() { echo -e "${BLUE}[i]${NC} $1"; }
error_exit() { print_error "$1"; exit 1; }

################################################################################
# PEER TYPE HELPERS
################################################################################

get_type_label() {
    case "$1" in
        Client) echo -e "${CYAN}Client${NC}" ;;
        Site) echo -e "${MAGENTA}Site${NC}" ;;
        Peer-to-Peer) echo -e "${YELLOW}P2P${NC}" ;;
        *) echo "$1" ;;
    esac
}

get_type_icon() {
    case "$1" in
        Client) echo "📱" ;;
        Site) echo "🏢" ;;
        Peer-to-Peer) echo "🔗" ;;
        *) echo "•" ;;
    esac
}

################################################################################
# PEER EXTRACTION
################################################################################

extract_peers() {
    local config_file="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"
    [[ -f "$config_file" ]] || error_exit "Server '${WG_INTERFACE}' not found"

    local in_peer=false
    local peer_type=""
    local peer_name=""
    local peer_pubkey=""
    local peer_allowed_ips=""
    local peer_endpoint=""
    local peers_found=false

    while IFS= read -r line; do
        if [[ "$line" =~ ^#[[:space:]]*(Client|Site|Peer-to-Peer):[[:space:]]*(.+)$ ]]; then
            peer_type="${BASH_REMATCH[1]}"
            peer_name=$(echo "${BASH_REMATCH[2]}" | xargs)
            in_peer=false
            continue
        fi

        if [[ "$line" =~ ^\[Peer\]$ ]]; then
            in_peer=true
            peer_pubkey=""
            peer_allowed_ips=""
            peer_endpoint=""
            continue
        fi

        if [[ "$in_peer" == true ]]; then
            if [[ "$line" =~ ^PublicKey[[:space:]]*=[[:space:]]*(.+)$ ]]; then
                peer_pubkey="${BASH_REMATCH[1]}"
            elif [[ "$line" =~ ^AllowedIPs[[:space:]]*=[[:space:]]*(.+)$ ]]; then
                peer_allowed_ips="${BASH_REMATCH[1]}"
            elif [[ "$line" =~ ^Endpoint[[:space:]]*=[[:space:]]*(.+)$ ]]; then
                peer_endpoint="${BASH_REMATCH[1]}"
            fi

            if [[ -n "$peer_name" && -n "$peer_pubkey" && -n "$peer_allowed_ips" ]]; then
                echo "${peer_type}|${peer_name}|${peer_pubkey}|${peer_allowed_ips}|${peer_endpoint}"
                peers_found=true
                peer_name=""
                peer_type=""
                in_peer=false
            fi
        fi
    done < "$config_file"

    # Fallback: if no commented peers found, list from config files
    if [[ "$peers_found" == false ]]; then
        local peer_dir="${WG_CONFIG_DIR}/${WG_INTERFACE}"
        if [[ -d "$peer_dir" ]]; then
            for conf in "$peer_dir"/*.conf 2>/dev/null; do
                [[ -f "$conf" ]] || continue
                local name=$(basename "$conf" .conf)
                [[ "$name" == "${WG_INTERFACE}" ]] && continue

                # Extract basic info from config file
                local allowed=$(grep -oP '^AllowedIPs\s*=\s*\K.+' "$conf" 2>/dev/null | head -1 | xargs)
                echo "Client|${name}|unknown|${allowed:-unknown}|"
            done
        fi
    fi
}

get_status() {
    local pubkey="$1"
    local handshake=$(wg show "${WG_INTERFACE}" dump 2>/dev/null | grep "^${pubkey}" | awk '{print $5}')

    if [[ -z "$handshake" || "$handshake" == "0" ]]; then
        echo "never"
        return
    fi

    local time_diff=$(($(date +%s) - handshake))
    [[ $time_diff -lt 180 ]] && echo "connected" || echo "idle"
}

get_last_seen() {
    local pubkey="$1"
    local handshake=$(wg show "${WG_INTERFACE}" dump 2>/dev/null | grep "^${pubkey}" | awk '{print $5}')

    if [[ -z "$handshake" || "$handshake" == "0" ]]; then
        echo "Never"
        return
    fi

    local diff=$(($(date +%s) - handshake))
    if [[ $diff -lt 60 ]]; then
        echo "${diff}s ago"
    elif [[ $diff -lt 3600 ]]; then
        echo "$((diff / 60))m ago"
    elif [[ $diff -lt 86400 ]]; then
        echo "$((diff / 3600))h ago"
    else
        echo "$((diff / 86400))d ago"
    fi
}

get_transfer() {
    local pubkey="$1"
    local stats=$(wg show "${WG_INTERFACE}" dump 2>/dev/null | grep "^${pubkey}" | awk '{print $6","$7}')

    if [[ -z "$stats" ]]; then
        echo "0 B / 0 B"
        return
    fi

    local rx=$(echo "$stats" | cut -d',' -f1)
    local tx=$(echo "$stats" | cut -d',' -f2)
    local rx_h=$(numfmt --to=iec-i --suffix=B "$rx" 2>/dev/null || echo "${rx}B")
    local tx_h=$(numfmt --to=iec-i --suffix=B "$tx" 2>/dev/null || echo "${tx}B")
    echo "↓ ${rx_h} / ↑ ${tx_h}"
}

################################################################################
# SERVER SELECTION
################################################################################

detect_servers() {
    local servers=($(ls "${WG_CONFIG_DIR}"/*.conf 2>/dev/null | xargs -n1 basename -s .conf))
    [[ ${#servers[@]} -gt 0 ]] || error_exit "No WireGuard servers found"
    echo "${servers[@]}"
}

select_server() {
    local servers=($(detect_servers))

    if [[ -n "$WG_INTERFACE" ]]; then
        [[ -f "${WG_CONFIG_DIR}/${WG_INTERFACE}.conf" ]] || error_exit "Server '${WG_INTERFACE}' not found"
        return
    fi

    if [[ ${#servers[@]} -eq 1 ]]; then
        WG_INTERFACE="${servers[0]}"
        return
    fi

    echo "" >&2
    print_info "Multiple servers detected" >&2
    print_warning "TIP: Use -i wg0 to skip this menu" >&2
    echo "" >&2

    local i=1
    for iface in "${servers[@]}"; do
        local ip=$(grep -oP '^Address\s*=\s*\K\S+' "${WG_CONFIG_DIR}/${iface}.conf" 2>/dev/null | head -1)
        local count=$(grep -cP '^#\s*(Client|Site|P2P|Peer):' "${WG_CONFIG_DIR}/${iface}.conf" 2>/dev/null || echo "0")
        local status=""
        systemctl is-active --quiet "wg-quick@${iface}" 2>/dev/null && status="${GREEN}●${NC}" || status="${YELLOW}○${NC}"
        printf "  ${BLUE}%d)${NC} %s %b - %s (%d peers)\n" "$i" "$iface" "$status" "$ip" "$count" >&2
        ((i++)) || true
    done

    echo "" >&2
    read -p "Select server (1-${#servers[@]}): " selection >&2
    [[ "$selection" =~ ^[0-9]+$ ]] && [[ $selection -ge 1 ]] && [[ $selection -le ${#servers[@]} ]] || error_exit "Invalid selection"
    WG_INTERFACE="${servers[$((selection-1))]}"
}

################################################################################
# VIEW SINGLE PEER
################################################################################

view_peer() {
    local name="$1"
    local peers=($(extract_peers))
    local found=false
    local peer_data=""

    for p in "${peers[@]}"; do
        IFS='|' read -r type pname pubkey allowed_ips endpoint <<< "$p"
        if [[ "$pname" == "$name" ]]; then
            found=true
            peer_data="$p"
            break
        fi
    done

    [[ "$found" == false ]] && error_exit "Peer '${name}' not found"

    IFS='|' read -r type name pubkey allowed_ips endpoint <<< "$peer_data"

    local status=$(get_status "$pubkey")
    local status_icon=""
    local status_text=""
    case "$status" in
        connected) status_icon="${GREEN}●${NC}"; status_text="${GREEN}Connected${NC}" ;;
        idle) status_icon="${YELLOW}○${NC}"; status_text="${YELLOW}Idle${NC}" ;;
        never) status_icon="${RED}○${NC}"; status_text="${RED}Never${NC}" ;;
    esac

    local type_label=$(get_type_label "$type")
    local type_icon=$(get_type_icon "$type")
    local live_endpoint=$(wg show "${WG_INTERFACE}" dump 2>/dev/null | grep "^${pubkey}" | awk '{print $3}')
    [[ -z "$live_endpoint" || "$live_endpoint" == "(none)" ]] && live_endpoint="N/A"

    echo ""
    echo "=========================================="
    echo -e "${type_icon} ${type_label}: ${name}"
    echo "=========================================="
    echo ""
    echo -e "Status:       ${status_icon} ${status_text}"
    echo "Tunnel IP:    $(echo "$allowed_ips" | cut -d',' -f1)"
    echo "Remote IP:    ${live_endpoint}"

    if [[ "$status" != "never" ]]; then
        echo "Last seen:    $(get_last_seen "$pubkey")"
        echo "Transfer:     $(get_transfer "$pubkey")"
    fi

    # Type-specific info
    case "$type" in
        Site|Peer-to-Peer)
            local remote_net=$(echo "$allowed_ips" | grep -oP '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' | grep -v '/32' | tail -1)
            [[ -n "$remote_net" ]] && echo "Remote LAN:   ${remote_net}"
            ;;
    esac

    [[ "$DETAILED" == true ]] && echo "PublicKey:    ${pubkey}"

    echo ""
    echo "=========================================="
    echo ""
}

################################################################################
# LIST ALL PEERS
################################################################################

list_peers() {
    local peers=($(extract_peers))

    if [[ ${#peers[@]} -eq 0 ]]; then
        print_warning "No peers found in ${WG_INTERFACE}"
        return
    fi

    local server_ip=$(grep -oP '^Address\s*=\s*\K\S+' "${WG_CONFIG_DIR}/${WG_INTERFACE}.conf" 2>/dev/null | head -1)

    echo ""
    echo "=========================================="
    print_success "Peers: ${WG_INTERFACE} (${server_ip})"
    echo "=========================================="
    echo ""

    # Count by type
    local clients=0 sites=0 p2p=0 connected=0
    for peer_data in "${peers[@]}"; do
        IFS='|' read -r type name pubkey _ _ <<< "$peer_data"
        case "$type" in
            Client) ((clients++)) ;;
            Site) ((sites++)) ;;
            Peer-to-Peer) ((p2p++)) ;;
        esac
        local status=$(get_status "$pubkey")
        [[ "$status" == "connected" ]] && ((connected++))
    done

    echo "Total: ${#peers[@]} peers (${connected} connected)"
    echo "  📱 Clients: ${clients}  🏢 Sites: ${sites}  🔗 P2P: ${p2p}"
    echo ""
    echo "=========================================="
    echo ""

    # List each peer
    local i=1
    for peer_data in "${peers[@]}"; do
        IFS='|' read -r type name pubkey allowed_ips endpoint <<< "$peer_data"

        local status=$(get_status "$pubkey")
        local status_icon=""
        case "$status" in
            connected) status_icon="${GREEN}●${NC}" ;;
            idle) status_icon="${YELLOW}○${NC}" ;;
            never) status_icon="${RED}○${NC}" ;;
        esac

        local type_label=$(get_type_label "$type")
        local type_icon=$(get_type_icon "$type")
        local tunnel_ip=$(echo "$allowed_ips" | cut -d',' -f1)

        printf "${BLUE}%2d)${NC} ${type_icon} ${type_label} %b\n" "$i" "$status_icon"
        echo "     ${name}"
        echo "     ${tunnel_ip}"

        # Show extra info for sites/p2p
        if [[ "$type" == "Site" || "$type" == "Peer-to-Peer" ]]; then
            local remote_net=$(echo "$allowed_ips" | grep -oP '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' | grep -v '/32' | tail -1)
            [[ -n "$remote_net" ]] && echo "     LAN: ${remote_net}"
        fi

        if [[ "$status" != "never" && "$DETAILED" == true ]]; then
            echo "     Last: $(get_last_seen "$pubkey")"
        fi

        echo ""
        ((i++)) || true
    done
}

################################################################################
# ARGUMENT PARSING
################################################################################

show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -i, --interface NAME  WireGuard interface (e.g., wg0)"
    echo "  -p, --peer NAME       View specific peer"
    echo "  -d, --detailed        Show more details"
    echo "  -h, --help            Show this help"
    echo ""
    echo "Examples:"
    echo "  $0                    # List all peers"
    echo "  $0 -i wg0             # List peers on wg0"
    echo "  $0 -p laptop          # View specific peer"
    echo "  $0 -d                 # List with details"
    exit 0
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -i|--interface) WG_INTERFACE="$2"; shift 2 ;;
            -p|--peer) PEER_NAME="$2"; shift 2 ;;
            -d|--detailed) DETAILED=true; shift ;;
            -h|--help) show_help ;;
            *) error_exit "Unknown option: $1 (use -h for help)" ;;
        esac
    done

    [[ -z "$WG_INTERFACE" ]] && select_server
}

################################################################################
# MAIN
################################################################################

main() {
    parse_args "$@"

    if [[ -n "$PEER_NAME" ]]; then
        view_peer "$PEER_NAME"
    else
        list_peers
    fi
}

main "$@"
