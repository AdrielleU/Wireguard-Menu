#!/bin/bash
################################################################################
# WireGuard Rotate Keys Script
# Description: Regenerate encryption keys for existing client
# Usage: sudo ./rotate-keys.sh [OPTIONS]
################################################################################

set -euo pipefail

################################################################################
# CONFIGURATION
################################################################################

WG_CONFIG_DIR="/etc/wireguard"
CLIENT_NAME=""
WG_INTERFACE=""
CLIENT_IP=""
SERVER_PUBLIC_KEY=""
SERVER_ENDPOINT=""
SERVER_PORT=""

################################################################################
# COLORS
################################################################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[i]${NC} $1"
}

################################################################################
# HELPER FUNCTIONS
################################################################################

error_exit() {
    print_error "$1"
    exit 1
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root (use sudo)"
    fi
}

detect_servers() {
    local servers=()

    if [[ -d "$WG_CONFIG_DIR" ]]; then
        # Use nullglob to handle case where no .conf files exist
        shopt -s nullglob
        local conf_files=("$WG_CONFIG_DIR"/*.conf)
        shopt -u nullglob

        for conf in "${conf_files[@]}"; do
            [[ ! -f "$conf" ]] && continue
            local iface_name=$(basename "$conf" .conf)
            servers+=("$iface_name")
        done
    fi

    if [[ ${#servers[@]} -eq 0 ]]; then
        error_exit "No WireGuard servers found. Run setup-wireguard.sh first."
    fi

    echo "${servers[@]}"
}

select_server() {
    local servers=($(detect_servers))
    local server_count=${#servers[@]}

    # If interface specified via argument, validate it
    if [[ -n "$WG_INTERFACE" ]]; then
        if [[ ! -f "${WG_CONFIG_DIR}/${WG_INTERFACE}.conf" ]]; then
            error_exit "WireGuard server '${WG_INTERFACE}' not found."
        fi
        print_success "Using server: ${WG_INTERFACE}"
        return
    fi

    # If only one server exists, use it automatically (silently)
    if [[ $server_count -eq 1 ]]; then
        WG_INTERFACE="${servers[0]}"
        return
    fi

    # Multiple servers - show selection menu
    print_info "Multiple WireGuard servers detected"
    print_warning "TIP: Use --interface wg0 to skip this menu"
    echo ""
    echo "Available servers:"
    echo ""

    local i=1
    for iface in "${servers[@]}"; do
        local conf_ip=$(grep -E "^Address\s*=" "${WG_CONFIG_DIR}/${iface}.conf" | head -n1 | awk '{print $3}')
        local conf_port=$(grep -E "^ListenPort\s*=" "${WG_CONFIG_DIR}/${iface}.conf" | head -n1 | awk '{print $3}')
        local is_running=""

        if systemctl is-active --quiet "wg-quick@${iface}"; then
            is_running="${GREEN}[RUNNING]${NC}"
        else
            is_running="${YELLOW}[STOPPED]${NC}"
        fi

        printf "  ${BLUE}%d)${NC} %s %b - %s, Port %s\n" "$i" "$iface" "$is_running" "$conf_ip" "$conf_port"
        ((i++))
    done

    echo ""
    read -p "Select server (1-${server_count}): " selection

    # Validate selection
    if ! [[ "$selection" =~ ^[0-9]+$ ]] || [ "$selection" -lt 1 ] || [ "$selection" -gt "$server_count" ]; then
        error_exit "Invalid selection"
    fi

    WG_INTERFACE="${servers[$((selection-1))]}"
    print_success "Selected server: ${WG_INTERFACE}"
}

list_clients() {
    # Use list-clients.sh if available, otherwise fallback
    if [[ -x "./list-clients.sh" ]]; then
        local clients=$(./list-clients.sh "${WG_INTERFACE}" --format array 2>/dev/null)
    else
        # Fallback: extract from config directly (both Client and Site entries)
        local config_file="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"
        local clients=()
        while IFS= read -r line; do
            # Match both "# Client: name" and "# Site: name"
            if [[ "$line" =~ ^#[[:space:]]*(Client|Site):[[:space:]]*(.+)$ ]]; then
                clients+=("${BASH_REMATCH[2]}")
            fi
        done < "$config_file"
        clients="${clients[@]}"
    fi

    echo "$clients"
}

select_client() {
    local clients=($(list_clients))
    local client_count=${#clients[@]}

    # Check if any clients exist
    if [[ $client_count -eq 0 ]]; then
        error_exit "No clients found in ${WG_INTERFACE}"
    fi

    # If client specified via argument, validate it
    if [[ -n "$CLIENT_NAME" ]]; then
        if [[ -x "./list-clients.sh" ]]; then
            if ! ./list-clients.sh "${WG_INTERFACE}" --check "${CLIENT_NAME}" 2>/dev/null; then
                error_exit "Client '${CLIENT_NAME}' not found in ${WG_INTERFACE}"
            fi
        fi
        print_success "Using client: ${CLIENT_NAME}"
        return
    fi

    # Show client selection menu
    echo ""
    print_info "Select a client to regenerate encryption keys for security"
    echo ""
    echo "Clients in ${WG_INTERFACE}:"
    echo ""

    local i=1
    for client in "${clients[@]}"; do
        printf "  ${BLUE}%d)${NC} %s\n" "$i" "$client"
        ((i++))
    done

    echo ""
    read -p "Select client (1-${client_count}): " selection

    # Validate selection
    if ! [[ "$selection" =~ ^[0-9]+$ ]] || [ "$selection" -lt 1 ] || [ "$selection" -gt "$client_count" ]; then
        error_exit "Invalid selection"
    fi

    CLIENT_NAME="${clients[$((selection-1))]}"
    print_success "Selected client: ${CLIENT_NAME}"
}

get_current_client_info() {
    local config_file="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"
    local keys_dir="${WG_CONFIG_DIR}/${WG_INTERFACE}"

    print_info "Reading current client configuration..."

    # Get client IP from server config (match both Client and Site entries)
    local found_client=0
    while IFS= read -r line; do
        # Match both "# Client: name" and "# Site: name"
        if [[ "$line" =~ ^#[[:space:]]*(Client|Site):[[:space:]]*${CLIENT_NAME}[[:space:]]*$ ]]; then
            found_client=1
        elif [[ $found_client -eq 1 ]] && [[ "$line" =~ ^[[:space:]]*AllowedIPs[[:space:]]*=[[:space:]]*(.+)$ ]]; then
            CLIENT_IP="${BASH_REMATCH[1]}"
            # Extract only the first IP (tunnel IP), ignore additional networks
            # For sites: "10.0.0.5/32, 192.168.50.0/24" -> get "10.0.0.5/32"
            CLIENT_IP=$(echo "$CLIENT_IP" | cut -d',' -f1 | xargs)
            break
        fi
    done < "$config_file"

    if [[ -z "$CLIENT_IP" ]]; then
        print_error "Could not find IP address for client ${CLIENT_NAME}"
        echo ""
        print_info "Debugging information:"
        echo "  Config file: ${config_file}"
        echo "  Looking for client: ${CLIENT_NAME}"
        echo ""
        print_info "Clients/Sites found in config:"
        grep -E "^#[[:space:]]*(Client|Site):" "$config_file" || echo "  (none)"
        echo ""
        error_exit "Client/Site '${CLIENT_NAME}' not found or missing AllowedIPs configuration"
    fi

    # Get server info
    SERVER_PORT=$(grep -E "^ListenPort\s*=" "$config_file" | head -n1 | awk '{print $3}')

    if [[ -f "${keys_dir}/server-publickey" ]]; then
        SERVER_PUBLIC_KEY=$(cat "${keys_dir}/server-publickey")
    else
        error_exit "Server public key not found"
    fi

    # Get server endpoint from existing client config if it exists
    local client_config="${keys_dir}/${CLIENT_NAME}.conf"
    if [[ -f "$client_config" ]]; then
        SERVER_ENDPOINT=$(grep -E "^Endpoint\s*=" "$client_config" | awk '{print $3}' | cut -d':' -f1)
    fi

    if [[ -z "$SERVER_ENDPOINT" ]]; then
        print_warning "Could not determine server endpoint from existing config"
        echo ""
        echo "Server Endpoint: Your server's public IP or domain name"
        echo "  Examples: 203.0.113.50, vpn.example.com"
        read -p "Enter server public IP/domain: " SERVER_ENDPOINT
    fi

    print_success "Current client IP: ${CLIENT_IP}"
    print_success "Server endpoint: ${SERVER_ENDPOINT}:${SERVER_PORT}"
}


generate_new_keys() {
    local keys_dir="${WG_CONFIG_DIR}/${WG_INTERFACE}"

    print_info "Generating new encryption keys..."

    cd "$keys_dir" || error_exit "Failed to access ${keys_dir}"

    umask 077

    local private_key_file="${keys_dir}/${CLIENT_NAME}-privatekey"
    local public_key_file="${keys_dir}/${CLIENT_NAME}-publickey"

    # Store old public key for comparison
    local old_public_key=""
    if [[ -f "$public_key_file" ]]; then
        old_public_key=$(cat "$public_key_file")
    fi

    # Generate NEW keys (this OVERWRITES the old ones)
    wg genkey | tee "$private_key_file" | wg pubkey > "$public_key_file" || error_exit "Failed to generate keys"
    chmod 600 "$private_key_file" "$public_key_file"

    CLIENT_PRIVATE_KEY=$(cat "$private_key_file")
    CLIENT_PUBLIC_KEY=$(cat "$public_key_file")

    print_success "New keys generated"

    if [[ -n "$old_public_key" ]] && [[ "$old_public_key" == "$CLIENT_PUBLIC_KEY" ]]; then
        print_error "WARNING: New public key matches old key (this should never happen!)"
        echo "  Old: ${old_public_key}"
        echo "  New: ${CLIENT_PUBLIC_KEY}"
    elif [[ -n "$old_public_key" ]]; then
        print_info "Old public key: ${old_public_key:0:20}..."
        print_info "New public key: ${CLIENT_PUBLIC_KEY:0:20}..."
    fi
}

update_server_config() {
    local config_file="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"

    print_info "Updating server configuration with new public key..."

    # Backup original permissions
    local original_perms=$(stat -c '%a' "$config_file" 2>/dev/null || echo "600")
    local original_owner=$(stat -c '%U:%G' "$config_file" 2>/dev/null || echo "root:root")

    # Find and update the client's public key
    local temp_file=$(mktemp)
    # Ensure temp file is cleaned up on exit or error
    trap "rm -f '$temp_file'" EXIT ERR

    local in_client_section=0

    while IFS= read -r line; do
        # Check if this is our client/site comment
        if [[ "$line" =~ ^#[[:space:]]*(Client|Site):[[:space:]]*${CLIENT_NAME}[[:space:]]*$ ]]; then
            in_client_section=1
            echo "$line" >> "$temp_file"
        # Update PublicKey if we're in this client's section
        elif [[ $in_client_section -eq 1 ]] && [[ "$line" =~ ^[[:space:]]*PublicKey ]]; then
            echo "PublicKey = ${CLIENT_PUBLIC_KEY}" >> "$temp_file"
            in_client_section=0
        else
            echo "$line" >> "$temp_file"
        fi
    done < "$config_file"

    # Replace original config with proper permissions and ownership
    mv "$temp_file" "$config_file"
    chmod "$original_perms" "$config_file"
    chown "$original_owner" "$config_file"

    # Clear the trap since we successfully moved the file
    trap - EXIT ERR

    print_success "Server config updated"
}

create_new_client_config() {
    print_info "Starting create_new_client_config function..."

    local keys_dir="${WG_CONFIG_DIR}/${WG_INTERFACE}"
    local client_config_file="${keys_dir}/${CLIENT_NAME}.conf"

    print_info "Config file path: ${client_config_file}"

    # Try to preserve ALL settings from existing config
    local allowed_ips=""
    local dns_servers=""
    local persistent_keepalive=""

    if [[ -f "$client_config_file" ]]; then
        print_info "Existing config file found, extracting settings..."
        # Extract AllowedIPs (everything after "AllowedIPs = ")
        allowed_ips=$(grep -E "^[[:space:]]*AllowedIPs[[:space:]]*=" "$client_config_file" | sed -E 's/^[[:space:]]*AllowedIPs[[:space:]]*=[[:space:]]*//' | sed -E 's/[[:space:]]*,?[[:space:]]*$//' || echo "")

        # Extract DNS if present
        dns_servers=$(grep -E "^[[:space:]]*DNS[[:space:]]*=" "$client_config_file" | sed -E 's/^[[:space:]]*DNS[[:space:]]*=[[:space:]]*//' | sed -E 's/[[:space:]]*$//' || echo "")

        # Extract PersistentKeepalive if present
        persistent_keepalive=$(grep -E "^[[:space:]]*PersistentKeepalive[[:space:]]*=" "$client_config_file" | sed -E 's/^[[:space:]]*PersistentKeepalive[[:space:]]*=[[:space:]]*//' | sed -E 's/[[:space:]]*$//' || echo "")
    else
        print_info "No existing config file found"
    fi

    # If no existing config or AllowedIPs not found, default to VPN network only
    if [[ -z "$allowed_ips" ]]; then
        local config_file="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"
        local server_address=$(grep -E "^Address\s*=" "$config_file" | head -n1 | awk '{print $3}' || echo "")

        if [[ -n "$server_address" ]]; then
            local network_base=$(echo "$server_address" | cut -d'/' -f1 | awk -F. '{print $1"."$2"."$3".0"}')
            local network_cidr=$(echo "$server_address" | cut -d'/' -f2)
            allowed_ips="${network_base}/${network_cidr}"
            print_warning "No existing routing config found, defaulting to VPN network only: ${allowed_ips}"
        else
            # Fallback if server config can't be read
            allowed_ips="10.0.0.0/24"
            print_warning "Could not determine VPN network, using default: ${allowed_ips}"
        fi
    else
        print_info "Preserving existing routing configuration: ${allowed_ips}"
    fi

    # Default DNS if not found
    if [[ -z "$dns_servers" ]]; then
        dns_servers="8.8.8.8"
    fi

    # Default PersistentKeepalive if not found
    if [[ -z "$persistent_keepalive" ]]; then
        persistent_keepalive="25"
    fi

    print_info "Creating new client configuration..."
    print_info "Writing to: ${client_config_file}"

    # Store old private key for verification
    local old_private_key=""
    if [[ -f "$client_config_file" ]]; then
        old_private_key=$(grep -E "^[[:space:]]*PrivateKey[[:space:]]*=" "$client_config_file" | sed -E 's/^[[:space:]]*PrivateKey[[:space:]]*=[[:space:]]*//')
        print_info "Removing old config file..."
        rm -f "$client_config_file"
        if [[ -f "$client_config_file" ]]; then
            print_error "Failed to remove old config file! Permission issue?"
            ls -la "$client_config_file"
            error_exit "Cannot overwrite config file"
        fi
        print_success "Old config removed"
    fi

    # Write new config file
    cat > "$client_config_file" <<EOF
[Interface]
PrivateKey = ${CLIENT_PRIVATE_KEY}
Address = ${CLIENT_IP}
DNS = ${dns_servers}

[Peer]
PublicKey = ${SERVER_PUBLIC_KEY}
Endpoint = ${SERVER_ENDPOINT}:${SERVER_PORT}
AllowedIPs = ${allowed_ips}
PersistentKeepalive = ${persistent_keepalive}
EOF

    chmod 600 "$client_config_file"

    print_success "New client config created: ${client_config_file}"

    # Verify the file was actually written
    if [[ -f "$client_config_file" ]]; then
        local new_private_key=$(grep -E "^[[:space:]]*PrivateKey[[:space:]]*=" "$client_config_file" | sed -E 's/^[[:space:]]*PrivateKey[[:space:]]*=[[:space:]]*//')
        if [[ "$new_private_key" == "$CLIENT_PRIVATE_KEY" ]]; then
            print_success "Verified: New private key written to config"
            if [[ -n "$old_private_key" ]] && [[ "$old_private_key" != "$new_private_key" ]]; then
                print_info "Old private key: ${old_private_key:0:20}..."
                print_info "New private key: ${new_private_key:0:20}..."
            fi
        else
            print_error "WARNING: Private key in config doesn't match generated key!"
        fi
    else
        print_error "WARNING: Config file was not created at ${client_config_file}"
    fi
}

reload_server() {
    print_info "Reloading WireGuard configuration without dropping connections..."

    # Use wg syncconf to reload config without disrupting active connections
    if ! wg syncconf "${WG_INTERFACE}" <(wg-quick strip "${WG_INTERFACE}"); then
        print_error "Failed to reload ${WG_INTERFACE} with wg syncconf"
        echo ""
        print_warning "Attempting full restart instead..."

        systemctl stop "wg-quick@${WG_INTERFACE}" 2>/dev/null || true
        sleep 1

        if ! systemctl start "wg-quick@${WG_INTERFACE}"; then
            print_error "Failed to restart ${WG_INTERFACE}"
            echo ""
            print_info "Service status:"
            systemctl status "wg-quick@${WG_INTERFACE}" --no-pager -l || true
            echo ""
            print_info "Check logs with:"
            echo "  journalctl -xeu wg-quick@${WG_INTERFACE}.service"
            error_exit "Could not reload/restart WireGuard service"
        fi

        print_success "WireGuard server restarted (all connections were reset)"
    else
        print_success "WireGuard configuration reloaded for ${WG_INTERFACE}"
        print_info "Other active connections remain intact"
    fi
}

show_summary() {
    local keys_dir="${WG_CONFIG_DIR}/${WG_INTERFACE}"
    local client_config_file="${keys_dir}/${CLIENT_NAME}.conf"

    echo ""
    echo "=========================================="
    print_success "Keys Rotated Successfully!"
    echo "=========================================="
    echo ""
    print_info "Client: ${CLIENT_NAME}"
    print_info "Server: ${WG_INTERFACE}"
    echo ""
    print_warning "IMPORTANT: Client must update their configuration!"
    echo ""
    print_info "New Client Configuration:"
    echo "  ${client_config_file}"
    echo ""
    print_info "Distribute new config to client:"
    echo "  1. Copy config to client device:"
    echo "     scp root@server:${client_config_file} ~/"
    echo ""
    echo "  2. Or display as QR code:"
    echo "     sudo ./qr-show.sh --interface ${WG_INTERFACE} --client ${CLIENT_NAME}"
    echo ""
    print_warning "Client is now disconnected and needs the new config to reconnect!"
    echo ""
    echo "=========================================="
    echo ""
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --interface|-i)
                WG_INTERFACE="$2"
                shift 2
                ;;
            --client|-c)
                CLIENT_NAME="$2"
                shift 2
                ;;
            -h|--help)
                echo "Usage: sudo $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  -i, --interface NAME    WireGuard interface (e.g., wg0)"
                echo "  -c, --client NAME       Client name"
                echo "  -h, --help             Show this help"
                echo ""
                echo "Example:"
                echo "  sudo $0 --interface wg0 --client laptop"
                echo "  sudo $0  # Interactive mode"
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
    echo "  WireGuard Rotate Client Keys"
    echo "=========================================="
    echo ""

    parse_arguments "$@"

    check_root
    select_server
    select_client
    get_current_client_info

    echo ""
    print_warning "This will PERMANENTLY regenerate encryption keys for '${CLIENT_NAME}'"
    print_warning "The client will be disconnected until they get the new config!"
    echo ""
    print_info "NOTE: Old keys will be OVERWRITTEN. To backup first:"
    echo "  cp -r /etc/wireguard/${WG_INTERFACE}/${CLIENT_NAME}* /tmp/backup/"
    echo ""
    read -p "Continue? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        error_exit "Key rotation cancelled"
    fi

    generate_new_keys
    update_server_config
    create_new_client_config
    reload_server
    show_summary
}

main "$@"
