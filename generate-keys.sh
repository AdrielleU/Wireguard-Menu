#!/bin/bash

# ============================================
# WireGuard Client/Peer Generator
# ============================================
# Adds new client/peer to existing WireGuard server
# Generates client keys and configuration
# Does NOT modify server keys

# Configuration - Modify these values as needed
INTERFACE="wg0"
CONFIG_DIR="/etc/wireguard"
SERVER_ENDPOINT=""  # Set server endpoint IP:PORT (e.g., "1.2.3.4:51820") - if set, skips prompt
SERVER_PORT=""  # Set custom port (e.g., "51820") or leave empty to use port from config

# ============================================
# Colors
# ============================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ============================================
# Functions
# ============================================

# Audit logging function for HIPAA compliance - logs to systemd journal
log_audit() {
    local action="$1"
    local details="$2"
    local user=$(whoami)
    local source_ip=$(who am i | awk '{print $5}' | tr -d '()')

    # Log to systemd journal with structured metadata
    logger -t wireguard-audit -p auth.info \
        "action=$action user=$user source_ip=${source_ip:-local} $details"
}

# ============================================
# Main Script
# ============================================

CONFIG_FILE="$CONFIG_DIR/$INTERFACE.conf"
KEY_DIR="$CONFIG_DIR/$INTERFACE"
PUBLIC_KEY_FILE="$KEY_DIR/server_public_key"

echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}WireGuard Client Generator${NC}"
echo -e "${CYAN}============================================${NC}"
echo -e "Adding new client to interface: ${BLUE}$INTERFACE${NC}"
echo ""

# Check if config exists
if [ ! -f "$CONFIG_FILE" ]; then
    echo -e "${RED}Error: Config file not found: $CONFIG_FILE${NC}"
    echo "Please set up WireGuard server first."
    exit 1
fi

# Create key directory if it doesn't exist
mkdir -p "$KEY_DIR"

# Read existing server public key
if [ ! -f "$PUBLIC_KEY_FILE" ]; then
    echo -e "${RED}Error: Server public key not found: $PUBLIC_KEY_FILE${NC}"
    echo "Please set up WireGuard server first."
    exit 1
fi

PUBLIC_KEY=$(cat "$PUBLIC_KEY_FILE")
echo -e "Using existing server public key: ${GREEN}$PUBLIC_KEY${NC}"
echo ""

# ============================================
# Client Configuration
# ============================================

# Get server network and port from config
SERVER_ADDRESS=$(grep "^Address" "$CONFIG_FILE" | awk '{print $3}')
CONFIG_PORT=$(grep "^ListenPort" "$CONFIG_FILE" | awk '{print $3}')

# Use custom port if set, otherwise use config port
if [ -n "$SERVER_PORT" ]; then
    ACTUAL_PORT="$SERVER_PORT"
else
    ACTUAL_PORT="$CONFIG_PORT"
fi

SERVER_NETWORK=$(echo "$SERVER_ADDRESS" | cut -d'/' -f1 | cut -d'.' -f1-3)
VPN_NETWORK_CIDR=$(echo "$SERVER_ADDRESS" | sed 's/\.[0-9]*\//.0\//')

# Detect server's internal network from eth0 or primary interface
INTERNAL_NETWORK=$(ip -4 addr show eth0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}/\d+' | sed 's/\.[0-9]*\//.0\//' | head -1)
if [ -z "$INTERNAL_NETWORK" ]; then
    # Fallback to any non-loopback interface if eth0 not found
    INTERNAL_NETWORK=$(ip -4 addr show | grep -v "127.0.0.1" | grep -oP '(?<=inet\s)\d+(\.\d+){3}/\d+' | sed 's/\.[0-9]*\//.0\//' | head -1)
fi

# Find next available IP (only from active peers, not disabled/commented)
USED_IPS=$(grep "^AllowedIPs" "$CONFIG_FILE" | awk '{print $3}' | cut -d'/' -f1 | cut -d'.' -f4 | sort -n)
NEXT_IP=2
for ip in $USED_IPS; do
    # Skip empty or non-numeric values
    if [[ "$ip" =~ ^[0-9]+$ ]] && [ "$ip" -ge "$NEXT_IP" ]; then
        NEXT_IP=$((ip + 1))
    fi
done
CLIENT_IP="$SERVER_NETWORK.$NEXT_IP"

# Show existing clients
echo ""
echo -e "${YELLOW}Existing clients:${NC}"
# Match only client name lines (no = or [ characters)
if grep -qE "^#\s*[a-zA-Z0-9_-]+\s*$" "$CONFIG_FILE"; then
    # List clients and check if they're active or disabled
    while IFS= read -r line; do
        CLIENT=$(echo "$line" | sed 's/^#\s*//' | sed 's/\s*$//')
        LINE_NUM=$(grep -nE "^#\s*${CLIENT}\s*$" "$CONFIG_FILE" | cut -d: -f1 | head -1)
        NEXT_LINE=$(sed -n "$((LINE_NUM + 1))p" "$CONFIG_FILE")

        if echo "$NEXT_LINE" | grep -qE "^#\s+\[Peer\]"; then
            echo -e "  - $CLIENT ${YELLOW}(DISABLED)${NC}"
        else
            echo -e "  - $CLIENT ${GREEN}(ACTIVE)${NC}"
        fi
    done < <(grep -E "^#\s*[a-zA-Z0-9_-]+\s*$" "$CONFIG_FILE")
else
    echo "  None configured yet"
fi

# Prompt for client name
echo ""
while true; do
    read -p "Enter client name (e.g., laptop, phone, remote-site): " CLIENT_NAME
    if [ -z "$CLIENT_NAME" ]; then
        echo "No client name provided. Skipping client config generation."
        exit 0
    fi

    # Check if client name already exists (must be alphanumeric/dash/underscore only)
    if ! [[ "$CLIENT_NAME" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        echo -e "${RED}Error: Client name can only contain letters, numbers, dashes, and underscores${NC}"
        continue
    fi

    # Check if client name already exists in comments
    if grep -qE "^#\s*${CLIENT_NAME}\s*$" "$CONFIG_FILE"; then
        # Check if the peer is active or commented out (disabled)
        LINE_NUM=$(grep -nE "^#\s*${CLIENT_NAME}\s*$" "$CONFIG_FILE" | cut -d: -f1 | head -1)
        NEXT_LINE=$(sed -n "$((LINE_NUM + 1))p" "$CONFIG_FILE")

        if echo "$NEXT_LINE" | grep -qE "^#\s+\[Peer\]"; then
            # Peer is disabled (commented out)
            echo -e "${YELLOW}Warning: Client '$CLIENT_NAME' exists but is DISABLED${NC}"
            echo ""
            echo "Options:"
            echo "  1) Remove disabled peer and create new one (recommended)"
            echo "  2) Keep disabled peer and create new one (will have duplicate name)"
            echo "  3) Cancel and choose different name"
            echo ""
            read -p "Choose option [1-3]: " DISABLED_OPTION

            case "${DISABLED_OPTION:-3}" in
                1)
                    # Remove the disabled peer (find dynamic line count)
                    START_LINE=$(grep -nE "^#\s*${CLIENT_NAME}\s*$" "$CONFIG_FILE" | cut -d: -f1 | head -1)
                    PEER_LINE_START=$((START_LINE + 1))
                    LINES_TO_DELETE=1
                    CURRENT_LINE=$PEER_LINE_START

                    while true; do
                        LINE_CONTENT=$(sed -n "${CURRENT_LINE}p" "$CONFIG_FILE")
                        if [ -z "$LINE_CONTENT" ] || [[ "$LINE_CONTENT" =~ ^#[[:space:]]*[a-zA-Z0-9_-]+[[:space:]]*$ ]] || [ $CURRENT_LINE -gt $((START_LINE + 10)) ]; then
                            break
                        fi
                        LINES_TO_DELETE=$((LINES_TO_DELETE + 1))
                        CURRENT_LINE=$((CURRENT_LINE + 1))
                    done

                    sed -i "/^#\s*${CLIENT_NAME}\s*$/,+$((LINES_TO_DELETE - 1))d" "$CONFIG_FILE"
                    echo -e "${GREEN}✓ Removed disabled peer ($LINES_TO_DELETE lines)${NC}"
                    ;;
                2)
                    echo -e "${YELLOW}⚠ Creating new peer with duplicate name${NC}"
                    ;;
                3|*)
                    continue
                    ;;
            esac
        else
            # Peer is active
            echo -e "${RED}Error: Client '$CLIENT_NAME' already exists and is ACTIVE in $CONFIG_FILE${NC}"
            echo "Please choose a different name or remove the existing client first."
            continue
        fi
    fi

    # Also check if config file already exists
    if [ -f "$KEY_DIR/$CLIENT_NAME.conf" ]; then
        echo -e "${YELLOW}Warning: Client config file already exists: $KEY_DIR/$CLIENT_NAME.conf${NC}"
        read -p "Overwrite existing client? (y/N): " OVERWRITE
        if [[ "$OVERWRITE" =~ ^[Yy]$ ]]; then
            break
        fi
        continue
    fi

    break
done

# Show detected networks
echo ""
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}Client Routing Configuration${NC}"
echo -e "${CYAN}============================================${NC}"
echo -e "${YELLOW}Detected networks:${NC}"
echo -e "  - VPN network:      ${BLUE}$VPN_NETWORK_CIDR${NC} (WireGuard peers)"

# Check if internal network is outside VPN range
INTERNAL_NETWORK_OUTSIDE=false
if [ -n "$INTERNAL_NETWORK" ]; then
    INTERNAL_PREFIX=$(echo "$INTERNAL_NETWORK" | cut -d'.' -f1-3)
    VPN_PREFIX=$(echo "$VPN_NETWORK_CIDR" | cut -d'.' -f1-3)
    if [ "$INTERNAL_PREFIX" != "$VPN_PREFIX" ]; then
        echo -e "  - Internal network: ${BLUE}$INTERNAL_NETWORK${NC} (Server's LAN)"
        INTERNAL_NETWORK_OUTSIDE=true
    fi
fi
echo ""

# ASK ABOUT ADDITIONAL LANs FIRST (Site-to-Site networks the CLIENT is advertising)
echo "Site-to-Site Configuration (Optional)"
echo "----------------------------------------------------"
echo "Is this client advertising additional networks (site-to-site VPN)?"
echo "These are networks BEHIND the client that other peers should access."
echo ""
echo "Examples:"
echo "  - Remote office LAN:      192.168.1.0/24"
echo "  - Cloud VPC:              172.16.0.0/16"
echo "  - Multiple sites:         192.168.1.0/24, 10.20.0.0/16"
echo ""
read -p "Enter networks this client is advertising (comma-separated) or press Enter for none: " ADDITIONAL_NETWORKS

# Build CLIENT AllowedIPs - always start with VPN CIDR /24
# Client needs to route TO the VPN and server's networks (NOT its own advertised networks)
CLIENT_ALLOWED_IPS="$VPN_NETWORK_CIDR"

# Add internal network only if it's outside VPN range
if [ "$INTERNAL_NETWORK_OUTSIDE" = true ]; then
    CLIENT_ALLOWED_IPS="$CLIENT_ALLOWED_IPS, $INTERNAL_NETWORK"
fi

echo ""
echo "Client will route through VPN to:"
echo "  $CLIENT_ALLOWED_IPS"

if [ -n "$ADDITIONAL_NETWORKS" ]; then
    echo ""
    echo "Client will advertise these networks to other peers:"
    echo "  $ADDITIONAL_NETWORKS"
fi
echo ""

# Prompt for server endpoint if not set
if [ -z "$SERVER_ENDPOINT" ]; then
    echo ""
    echo "Server Endpoint Configuration"
    echo "This is the public IP and port clients use to connect to this server."
    echo ""

    # Try to detect external IP
    DETECTED_IP=$(curl -s ifconfig.me 2>/dev/null || curl -s icanhazip.com 2>/dev/null || echo "")

    if [ -n "$DETECTED_IP" ]; then
        DEFAULT_ENDPOINT="${DETECTED_IP}:${ACTUAL_PORT}"
        echo "Detected external IP: $DETECTED_IP"
    else
        DEFAULT_ENDPOINT="<external-ip>:${ACTUAL_PORT}"
    fi

    read -p "Enter server endpoint [default: $DEFAULT_ENDPOINT]: " INPUT_ENDPOINT

    if [ -z "$INPUT_ENDPOINT" ]; then
        if [ -n "$DETECTED_IP" ]; then
            SERVER_ENDPOINT="$DEFAULT_ENDPOINT"
        else
            echo "No endpoint provided. Skipping client config generation."
            exit 0
        fi
    else
        SERVER_ENDPOINT="$INPUT_ENDPOINT"
    fi
fi

# Prompt for client VPN IP address (LAST)
echo ""
while true; do
    read -p "Enter VPN IP for this client [default: $CLIENT_IP]: " INPUT_CLIENT_IP

    # Use default if empty
    if [ -z "$INPUT_CLIENT_IP" ]; then
        INPUT_CLIENT_IP="$CLIENT_IP"
        break
    fi

    # Check if IP is already in use in config file
    if grep -q "AllowedIPs.*$INPUT_CLIENT_IP/32" "$CONFIG_FILE" || grep -q "AllowedIPs.*$INPUT_CLIENT_IP/24" "$CONFIG_FILE"; then
        echo "Error: IP $INPUT_CLIENT_IP is already in use. Please choose another."
        continue
    fi

    # Validate it's in the same network
    INPUT_NETWORK=$(echo "$INPUT_CLIENT_IP" | cut -d'.' -f1-3)
    if [ "$INPUT_NETWORK" != "$SERVER_NETWORK" ]; then
        echo "Warning: IP $INPUT_CLIENT_IP is not in the VPN network ($SERVER_NETWORK.0/24)"
        read -p "Use it anyway? (y/N): " CONFIRM
        if [[ "$CONFIRM" =~ ^[Yy]$ ]]; then
            break
        fi
        continue
    fi

    break
done
CLIENT_IP="$INPUT_CLIENT_IP"

# Generate client keypair
CLIENT_PRIVATE_KEY=$(wg genkey)
CLIENT_PUBLIC_KEY=$(echo "$CLIENT_PRIVATE_KEY" | wg pubkey)

# Save client keys to files
CLIENT_PRIVATE_KEY_FILE="$KEY_DIR/${CLIENT_NAME}_private_key"
CLIENT_PUBLIC_KEY_FILE="$KEY_DIR/${CLIENT_NAME}_public_key"
echo "$CLIENT_PRIVATE_KEY" > "$CLIENT_PRIVATE_KEY_FILE"
echo "$CLIENT_PUBLIC_KEY" > "$CLIENT_PUBLIC_KEY_FILE"
chmod 600 "$CLIENT_PRIVATE_KEY_FILE"
chmod 644 "$CLIENT_PUBLIC_KEY_FILE"

# Create client config file
CLIENT_CONFIG="$KEY_DIR/$CLIENT_NAME.conf"
cat > "$CLIENT_CONFIG" <<EOF
[Interface]
Address = $CLIENT_IP/32
PrivateKey = $CLIENT_PRIVATE_KEY
MTU = 1420

[Peer]
PublicKey = $PUBLIC_KEY
Endpoint = $SERVER_ENDPOINT
AllowedIPs = $CLIENT_ALLOWED_IPS
PersistentKeepalive = 25
EOF

chmod 600 "$CLIENT_CONFIG"

# Add peer to server config (ensure clean spacing)
# Clean up multiple consecutive blank lines first
sed -i '/^$/N;/^\n$/D' "$CONFIG_FILE"

# Remove trailing blank lines
sed -i -e :a -e '/^\n*$/{$d;N;ba' -e '}' "$CONFIG_FILE"

# Build server-side AllowedIPs
# This determines what traffic the server will route TO this peer
SERVER_ALLOWED_IPS="$CLIENT_IP/32"

# If additional networks were specified, add them to server config too
# This is critical for site-to-site VPN functionality
if [ -n "$ADDITIONAL_NETWORKS" ]; then
    SERVER_ALLOWED_IPS="$SERVER_ALLOWED_IPS, $ADDITIONAL_NETWORKS"
fi

# Add peer with single blank line separator and client name comment
echo "" >> "$CONFIG_FILE"
echo "# $CLIENT_NAME" >> "$CONFIG_FILE"
echo "[Peer]" >> "$CONFIG_FILE"
echo "PublicKey = $CLIENT_PUBLIC_KEY" >> "$CONFIG_FILE"
echo "AllowedIPs = $SERVER_ALLOWED_IPS" >> "$CONFIG_FILE"

echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}Client Config Generated${NC}"
echo -e "${GREEN}============================================${NC}"
echo -e "Client Name:           ${BLUE}$CLIENT_NAME${NC}"
echo -e "Client IP:             ${BLUE}$CLIENT_IP/32${NC}"
echo -e "Public Key:            ${CYAN}$CLIENT_PUBLIC_KEY${NC}"
echo ""
echo -e "Client AllowedIPs:     ${YELLOW}$CLIENT_ALLOWED_IPS${NC}"
echo -e "Server AllowedIPs:     ${YELLOW}$SERVER_ALLOWED_IPS${NC}"
echo ""
echo -e "${GREEN}Files created:${NC}"
echo "  Config:        $CLIENT_CONFIG"
echo "  Private Key:   $CLIENT_PRIVATE_KEY_FILE"
echo "  Public Key:    $CLIENT_PUBLIC_KEY_FILE"
echo ""
echo "Peer added to:   $CONFIG_FILE"
echo ""

# Audit log entry
log_audit "ADD_PEER" "client=$CLIENT_NAME ip=$CLIENT_IP/32 server_allowed_ips=$SERVER_ALLOWED_IPS client_allowed_ips=$CLIENT_ALLOWED_IPS interface=$INTERFACE"

# Check if additional networks were added - requires restart for routes
if [ -n "$ADDITIONAL_NETWORKS" ]; then
    echo -e "${YELLOW}============================================${NC}"
    echo -e "${YELLOW}RESTART REQUIRED${NC}"
    echo -e "${YELLOW}============================================${NC}"
    echo -e "Additional networks were configured: ${CYAN}$ADDITIONAL_NETWORKS${NC}"
    echo ""
    echo "Route updates require a full interface restart."
    echo -e "${YELLOW}This will briefly disconnect all connected clients.${NC}"
    echo ""
    read -p "Type 'restart' to restart interface now (or anything else to skip): " RESTART_CONFIRM
    echo ""

    if [ "$RESTART_CONFIRM" = "restart" ]; then
        echo -e "${BLUE}Restarting WireGuard interface: $INTERFACE${NC}"
        systemctl restart wg-quick@$INTERFACE
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✓ Interface restarted successfully${NC}"
            echo -e "${GREEN}✓ Routes updated${NC}"
        else
            echo -e "${RED}✗ Failed to restart interface${NC}"
            echo "  Manual restart required: systemctl restart wg-quick@$INTERFACE"
        fi
    else
        echo -e "${YELLOW}Restart skipped.${NC}"
        echo ""
        echo "To apply route changes later, run:"
        echo "  systemctl restart wg-quick@$INTERFACE"
    fi
else
    # No additional networks - hot reload is safe
    echo -e "${BLUE}Applying configuration (hot reload - no disconnections)...${NC}"
    wg syncconf $INTERFACE <(wg-quick strip $INTERFACE)
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Configuration reloaded successfully${NC}"
        echo -e "${GREEN}✓ Client can now connect${NC}"
    else
        echo -e "${RED}✗ Hot reload failed${NC}"
        echo ""
        echo "To apply changes manually, run:"
        echo "  wg syncconf $INTERFACE <(wg-quick strip $INTERFACE)"
        echo "  OR"
        echo "  systemctl restart wg-quick@$INTERFACE"
    fi
fi
echo ""

echo -e "${GREEN}Done!${NC}"
