#!/bin/bash
################################################################################
# WireGuard Rotate Keys Script
# Description: Regenerate encryption keys for server or peers
# Usage: sudo ./rotate-keys.sh [OPTIONS]
################################################################################

set -euo pipefail

################################################################################
# CONFIGURATION
################################################################################

WG_CONFIG_DIR="/etc/wireguard"
WG_INTERFACE=""
ROTATION_TYPE=""  # "server" or "peer"
PEER_NAME=""

################################################################################
# COLORS
################################################################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

print_success() { echo -e "${GREEN}[✓]${NC} $1" >&2; }
print_error() { echo -e "${RED}[✗]${NC} $1" >&2; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1" >&2; }
print_info() { echo -e "${BLUE}[i]${NC} $1" >&2; }
error_exit() { print_error "$1"; exit 1; }

################################################################################
# COMMON HELPERS
################################################################################

check_root() {
    [[ $EUID -eq 0 ]] || error_exit "This script must be run as root (use sudo)"
}

detect_servers() {
    local servers=()
    if [[ -d "$WG_CONFIG_DIR" ]]; then
        shopt -s nullglob
        local conf_files=("$WG_CONFIG_DIR"/*.conf)
        shopt -u nullglob
        for conf in "${conf_files[@]}"; do
            [[ -f "$conf" ]] && servers+=("$(basename "$conf" .conf)")
        done
    fi
    [[ ${#servers[@]} -gt 0 ]] || error_exit "No WireGuard servers found. Run setup-wireguard.sh first."
    echo "${servers[@]}"
}

select_server() {
    local servers=($(detect_servers))

    if [[ -n "$WG_INTERFACE" ]]; then
        [[ -f "${WG_CONFIG_DIR}/${WG_INTERFACE}.conf" ]] || error_exit "WireGuard server '${WG_INTERFACE}' not found."
        return
    fi

    if [[ ${#servers[@]} -eq 1 ]]; then
        WG_INTERFACE="${servers[0]}"
        return
    fi

    print_info "Multiple WireGuard servers detected"
    print_warning "TIP: Use -i wg0 to skip this menu"
    echo ""

    local i=1
    for iface in "${servers[@]}"; do
        local ip=$(grep -oP '^Address\s*=\s*\K\S+' "${WG_CONFIG_DIR}/${iface}.conf" 2>/dev/null | head -1)
        local port=$(grep -oP '^ListenPort\s*=\s*\K\d+' "${WG_CONFIG_DIR}/${iface}.conf" 2>/dev/null | head -1)
        local status=""
        systemctl is-active --quiet "wg-quick@${iface}" && status="${GREEN}●${NC}" || status="${YELLOW}○${NC}"
        printf "  ${BLUE}%d)${NC} %s %b - %s, Port %s\n" "$i" "$iface" "$status" "$ip" "$port"
        ((i++))
    done

    echo ""
    read -p "Select server (1-${#servers[@]}): " selection
    [[ "$selection" =~ ^[0-9]+$ ]] && [[ $selection -ge 1 ]] && [[ $selection -le ${#servers[@]} ]] || error_exit "Invalid selection"
    WG_INTERFACE="${servers[$((selection-1))]}"
}

list_peers() {
    local config_file="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"
    local peers=$(grep -oP '^#\s*(Client|Site|Peer-to-Peer):\s*\K.+' "$config_file" 2>/dev/null | xargs -n1)

    if [[ -z "$peers" ]]; then
        local peer_dir="${WG_CONFIG_DIR}/${WG_INTERFACE}"
        if [[ -d "$peer_dir" ]]; then
            shopt -s nullglob
            local conf_files=("$peer_dir"/*.conf)
            shopt -u nullglob

            local peer_list=()
            for conf in "${conf_files[@]}"; do
                [[ -f "$conf" ]] || continue
                local name=$(basename "$conf" .conf)
                [[ "$name" == "${WG_INTERFACE}" ]] && continue
                peer_list+=("$name")
            done
            peers=$(printf "%s\n" "${peer_list[@]}" 2>/dev/null || true)
        fi
    fi

    echo "$peers"
}

peer_exists() {
    local name="$1"
    local config_file="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"
    grep -qP "^#\s*(Client|Site|Peer-to-Peer):\s*${name}\s*$" "$config_file" 2>/dev/null && return 0
    [[ -f "${WG_CONFIG_DIR}/${WG_INTERFACE}/${name}.conf" ]]
}

################################################################################
# ROTATION TYPE SELECTION
################################################################################

select_rotation_type() {
    [[ -n "$ROTATION_TYPE" ]] && return

    echo ""
    print_info "What would you like to rotate?"
    echo -e "  ${CYAN}1)${NC} Peer keys - Regenerate a single peer's keys"
    echo -e "  ${CYAN}2)${NC} Server keys - Regenerate server keys (ALL peers need new configs)"
    echo ""
    read -p "Choice (1-2): " choice

    case "$choice" in
        1) ROTATION_TYPE="peer" ;;
        2) ROTATION_TYPE="server" ;;
        *) error_exit "Invalid selection" ;;
    esac
}

select_peer() {
    [[ -n "$PEER_NAME" ]] && peer_exists "$PEER_NAME" && return
    [[ -n "$PEER_NAME" ]] && error_exit "Peer '${PEER_NAME}' not found"

    local peers=($(list_peers))
    [[ ${#peers[@]} -gt 0 ]] || error_exit "No peers found in ${WG_INTERFACE}"

    echo ""
    print_info "Select peer to rotate keys for:"
    echo ""

    local i=1
    for peer in "${peers[@]}"; do
        printf "  ${BLUE}%d)${NC} %s\n" "$i" "$peer"
        ((i++))
    done

    echo ""
    read -p "Select peer (1-${#peers[@]}): " selection
    [[ "$selection" =~ ^[0-9]+$ ]] && [[ $selection -ge 1 ]] && [[ $selection -le ${#peers[@]} ]] || error_exit "Invalid selection"
    PEER_NAME="${peers[$((selection-1))]}"
}

################################################################################
# SERVER KEY ROTATION
################################################################################

rotate_server_keys() {
    local keys_dir="${WG_CONFIG_DIR}/${WG_INTERFACE}"
    local config_file="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"
    local peers=($(list_peers))

    echo ""
    print_warning "This will PERMANENTLY regenerate server encryption keys!"
    print_warning "ALL ${#peers[@]} peer(s) will be disconnected!"
    echo ""
    print_info "NOTE: Old keys will be OVERWRITTEN. To backup first:"
    echo "  cp -r ${WG_CONFIG_DIR}/${WG_INTERFACE}/ /tmp/backup-${WG_INTERFACE}/"
    echo ""
    read -p "Type 'yes' to confirm server key rotation: " confirmation

    if [[ "$confirmation" != "yes" ]]; then
        error_exit "Server key rotation cancelled"
    fi

    # Remove old keys
    print_info "Removing old server keys..."
    rm -f "${keys_dir}/server-privatekey" "${keys_dir}/server-publickey"
    print_success "Old server keys removed"

    # Generate new keys
    print_info "Generating new server encryption keys..."
    mkdir -p "$keys_dir"
    cd "$keys_dir" || error_exit "Failed to access ${keys_dir}"
    umask 077
    wg genkey | tee "${keys_dir}/server-privatekey" | wg pubkey > "${keys_dir}/server-publickey" || error_exit "Failed to generate keys"
    chmod 600 "${keys_dir}/server-privatekey" "${keys_dir}/server-publickey"

    local SERVER_PRIVATE_KEY=$(cat "${keys_dir}/server-privatekey")
    local SERVER_PUBLIC_KEY=$(cat "${keys_dir}/server-publickey")
    print_success "New server keys generated"

    # Update server config
    print_info "Updating server configuration..."
    local temp_file=$(mktemp)
    trap "rm -f '$temp_file'" EXIT ERR
    sed "s|^PrivateKey.*|PrivateKey = ${SERVER_PRIVATE_KEY}|" "$config_file" > "$temp_file"
    mv "$temp_file" "$config_file"
    chmod 600 "$config_file"
    trap - EXIT ERR
    print_success "Server config updated"

    # Regenerate all peer configs
    if [[ ${#peers[@]} -gt 0 ]]; then
        print_info "Regenerating configs for ${#peers[@]} peer(s)..."

        local server_port=$(grep -oP '^ListenPort\s*=\s*\K\d+' "$config_file")
        local server_address=$(grep -oP '^Address\s*=\s*\K\S+' "$config_file")
        local network_base=$(echo "$server_address" | cut -d'/' -f1 | awk -F. '{print $1"."$2"."$3".0"}')
        local network_cidr=$(echo "$server_address" | cut -d'/' -f2)
        local vpn_network="${network_base}/${network_cidr}"

        for peer in "${peers[@]}"; do
            local peer_config="${keys_dir}/${peer}.conf"
            local peer_private_key=""
            [[ -f "${keys_dir}/${peer}-privatekey" ]] && peer_private_key=$(cat "${keys_dir}/${peer}-privatekey") || { print_warning "No private key for ${peer}, skipping"; continue; }

            # Get peer IP from server config
            local peer_ip=$(awk -v peer="$peer" '
                /^#[[:space:]]*(Client|Site|Peer-to-Peer):[[:space:]]*'"$peer"'[[:space:]]*$/ {found=1; next}
                found && /^[[:space:]]*AllowedIPs[[:space:]]*=/ {print $3; exit}
            ' "$config_file" | cut -d',' -f1)

            # Get endpoint from existing config
            local endpoint=$(grep -oP '^Endpoint\s*=\s*\K[^:]+' "$peer_config" 2>/dev/null || echo "YOUR_SERVER_IP")

            # Preserve AllowedIPs or default to VPN network
            local allowed_ips=$(grep -oP '^AllowedIPs\s*=\s*\K.+' "$peer_config" 2>/dev/null || echo "$vpn_network")

            cat > "$peer_config" <<EOF
[Interface]
PrivateKey = ${peer_private_key}
Address = ${peer_ip}
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = ${SERVER_PUBLIC_KEY}
Endpoint = ${endpoint}:${server_port}
AllowedIPs = ${allowed_ips}
PersistentKeepalive = 25
EOF
            chmod 600 "$peer_config"
            print_success "Regenerated: ${peer}"
        done
    fi

    # Restart server
    print_info "Restarting WireGuard server..."
    systemctl stop "wg-quick@${WG_INTERFACE}" 2>/dev/null || true
    sleep 1
    systemctl start "wg-quick@${WG_INTERFACE}" || error_exit "Failed to start ${WG_INTERFACE}"
    print_success "WireGuard server restarted with new keys"

    # Summary
    echo ""
    echo "=========================================="
    print_success "Server Keys Rotated Successfully!"
    echo "=========================================="
    echo ""
    print_warning "ALL PEERS MUST UPDATE THEIR CONFIGS!"
    echo ""
    if [[ ${#peers[@]} -gt 0 ]]; then
        print_info "Updated configs:"
        for peer in "${peers[@]}"; do
            echo "  - ${peer}: ${keys_dir}/${peer}.conf"
        done
        echo ""
        print_info "Distribute via SCP or QR code (./qr-show.sh)"
    fi
    echo ""
}

################################################################################
# PEER KEY ROTATION
################################################################################

rotate_peer_keys() {
    local keys_dir="${WG_CONFIG_DIR}/${WG_INTERFACE}"
    local config_file="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"
    local peer_config="${keys_dir}/${PEER_NAME}.conf"

    echo ""
    print_warning "This will PERMANENTLY regenerate encryption keys for '${PEER_NAME}'"
    print_warning "The peer will be disconnected until they get the new config!"
    echo ""
    print_info "NOTE: Old keys will be OVERWRITTEN. To backup first:"
    echo "  cp ${keys_dir}/${PEER_NAME}* /tmp/backup/"
    echo ""
    read -p "Type 'yes' to confirm peer key rotation: " confirmation

    if [[ "$confirmation" != "yes" ]]; then
        error_exit "Peer key rotation cancelled"
    fi

    # Get peer IP from server config
    print_info "Reading peer configuration..."
    local peer_ip=$(awk -v peer="$PEER_NAME" '
        /^#[[:space:]]*(Client|Site|Peer-to-Peer):[[:space:]]*'"$PEER_NAME"'[[:space:]]*$/ {found=1; next}
        found && /^[[:space:]]*AllowedIPs[[:space:]]*=/ {print $3; exit}
    ' "$config_file" | cut -d',' -f1)
    [[ -n "$peer_ip" ]] || error_exit "Could not find IP for peer '${PEER_NAME}'"

    # Get server info
    local server_port=$(grep -oP '^ListenPort\s*=\s*\K\d+' "$config_file")
    local server_pubkey=$(cat "${keys_dir}/server-publickey" 2>/dev/null) || error_exit "Server public key not found"
    local server_endpoint=$(grep -oP '^Endpoint\s*=\s*\K[^:]+' "$peer_config" 2>/dev/null || echo "YOUR_SERVER_IP")

    # Generate new peer keys
    print_info "Generating new encryption keys..."
    umask 077
    wg genkey | tee "${keys_dir}/${PEER_NAME}-privatekey" | wg pubkey > "${keys_dir}/${PEER_NAME}-publickey" || error_exit "Failed to generate keys"
    chmod 600 "${keys_dir}/${PEER_NAME}-privatekey" "${keys_dir}/${PEER_NAME}-publickey"

    local peer_private_key=$(cat "${keys_dir}/${PEER_NAME}-privatekey")
    local peer_public_key=$(cat "${keys_dir}/${PEER_NAME}-publickey")
    print_success "New keys generated"

    # Update server config
    print_info "Updating server configuration..."
    local temp_file=$(mktemp)
    trap "rm -f '$temp_file'" EXIT ERR

    awk -v peer="$PEER_NAME" -v pubkey="$peer_public_key" '
        /^#[[:space:]]*(Client|Site|Peer-to-Peer):[[:space:]]*'"$PEER_NAME"'[[:space:]]*$/ {found=1; print; next}
        found && /^[[:space:]]*PublicKey/ {print "PublicKey = " pubkey; found=0; next}
        {print}
    ' "$config_file" > "$temp_file"

    mv "$temp_file" "$config_file"
    chmod 600 "$config_file"
    trap - EXIT ERR
    print_success "Server config updated"

    # Recreate peer config
    print_info "Creating new peer configuration..."
    local allowed_ips=$(grep -oP '^AllowedIPs\s*=\s*\K.+' "$peer_config" 2>/dev/null || echo "10.0.0.0/24")

    cat > "$peer_config" <<EOF
[Interface]
PrivateKey = ${peer_private_key}
Address = ${peer_ip}
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = ${server_pubkey}
Endpoint = ${server_endpoint}:${server_port}
AllowedIPs = ${allowed_ips}
PersistentKeepalive = 25
EOF
    chmod 600 "$peer_config"
    print_success "New peer config created"

    # Reload server configuration
    print_info "Reloading WireGuard configuration..."

    if wg syncconf "${WG_INTERFACE}" <(wg-quick strip "${WG_INTERFACE}"); then
        print_success "WireGuard configuration reloaded"
        print_info "Other connected peers remain unaffected"
    else
        print_warning "Hot reload failed, attempting full restart..."

        systemctl stop "wg-quick@${WG_INTERFACE}" 2>/dev/null || true
        sleep 1

        if systemctl start "wg-quick@${WG_INTERFACE}"; then
            print_success "WireGuard server restarted successfully"
            print_warning "All peers were briefly disconnected during restart"
        else
            error_exit "Failed to start ${WG_INTERFACE}"
        fi
    fi

    # Summary
    echo ""
    echo "=========================================="
    print_success "Peer Keys Rotated Successfully!"
    echo "=========================================="
    echo ""
    print_info "Peer: ${PEER_NAME}"
    print_info "Config: ${peer_config}"
    echo ""
    print_warning "IMPORTANT: Peer must update their configuration!"
    echo ""
    print_info "Distribute new config:"
    echo "  scp root@server:${peer_config} ~/"
    echo "  sudo ./qr-show.sh -i ${WG_INTERFACE} -c ${PEER_NAME}"
    echo ""
}

################################################################################
# ARGUMENT PARSING
################################################################################

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --server|-s) ROTATION_TYPE="server"; shift ;;
            --peer|-p) ROTATION_TYPE="peer"; PEER_NAME="$2"; shift 2 ;;
            --interface|-i) WG_INTERFACE="$2"; shift 2 ;;
            -h|--help)
                echo "Usage: sudo $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  -s, --server            Rotate server keys"
                echo "  -p, --peer NAME         Rotate peer keys"
                echo "  -i, --interface NAME    WireGuard interface (e.g., wg0)"
                echo "  -h, --help             Show this help"
                echo ""
                echo "Examples:"
                echo "  sudo $0                        # Interactive mode"
                echo "  sudo $0 -s -i wg0              # Rotate server keys"
                echo "  sudo $0 -p laptop -i wg0       # Rotate peer keys"
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                exit 1
                ;;
        esac
    done
}

################################################################################
# MAIN
################################################################################

main() {
    echo "=========================================="
    echo "  WireGuard Key Rotation"
    echo "=========================================="
    echo ""

    parse_arguments "$@"
    check_root
    select_server
    select_rotation_type

    if [[ "$ROTATION_TYPE" == "server" ]]; then
        rotate_server_keys
    else
        select_peer
        rotate_peer_keys
    fi
}

main "$@"
