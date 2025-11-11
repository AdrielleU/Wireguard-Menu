#!/bin/bash

# ============================================
# WireGuard Client/Peer Removal Tool
# ============================================
# Removes client/peer from WireGuard server
# Deletes client config, keys, and peer section from server config
# Does NOT modify server keys

# Configuration - Modify these values as needed
INTERFACE="wg0"
CONFIG_DIR="/etc/wireguard"

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

echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}WireGuard Client Removal Tool${NC}"
echo -e "${CYAN}============================================${NC}"
echo -e "Removing client from interface: ${BLUE}$INTERFACE${NC}"
echo ""

# Check if config exists
if [ ! -f "$CONFIG_FILE" ]; then
    echo -e "${RED}Error: Config file not found: $CONFIG_FILE${NC}"
    echo "Please set up WireGuard server first."
    exit 1
fi

# List existing clients
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
    echo ""
else
    echo "  None configured yet"
    echo ""
    echo "No clients to remove."
    exit 0
fi

# Prompt for client name to remove
read -p "Enter client name to remove: " CLIENT_NAME

if [ -z "$CLIENT_NAME" ]; then
    echo "No client name provided. Exiting."
    exit 0
fi

# Validate client name format
if ! [[ "$CLIENT_NAME" =~ ^[a-zA-Z0-9_-]+$ ]]; then
    echo -e "${RED}Error: Invalid client name format${NC}"
    echo "Client name can only contain letters, numbers, dashes, and underscores"
    exit 1
fi

# Check if client exists in config
if ! grep -qE "^#\s*${CLIENT_NAME}\s*$" "$CONFIG_FILE"; then
    echo -e "${RED}Error: Client '$CLIENT_NAME' not found in $CONFIG_FILE${NC}"
    exit 1
fi

# Check if peer is active or disabled (commented out)
LINE_NUM=$(grep -nE "^#\s*${CLIENT_NAME}\s*$" "$CONFIG_FILE" | cut -d: -f1 | head -1)
NEXT_LINE=$(sed -n "$((LINE_NUM + 1))p" "$CONFIG_FILE")

if echo "$NEXT_LINE" | grep -qE "^#.*\[Peer\]"; then
    echo -e "${YELLOW}Note: This peer is currently DISABLED (commented out)${NC}"
    PEER_DISABLED=true
else
    PEER_DISABLED=false
fi

# Confirm removal
echo ""
echo -e "${RED}This will remove:${NC}"
echo "  - Client config: $KEY_DIR/$CLIENT_NAME.conf"
echo "  - Client keys:   $KEY_DIR/${CLIENT_NAME}_private_key"
echo "  - Client keys:   $KEY_DIR/${CLIENT_NAME}_public_key"
echo "  - Peer section from: $CONFIG_FILE"
echo ""
read -p "Type 'remove' to confirm deletion: " CONFIRM

if [ "$CONFIRM" != "remove" ]; then
    echo -e "${YELLOW}Removal cancelled.${NC}"
    exit 0
fi

echo ""
echo -e "${BLUE}Removing client: $CLIENT_NAME${NC}"

# Remove peer section from server config
# Need to find how many lines this peer has (could be 3 or 4+ lines)
START_LINE=$(grep -nE "^#\s*${CLIENT_NAME}\s*$" "$CONFIG_FILE" | cut -d: -f1 | head -1)
PEER_LINE_START=$((START_LINE + 1))

# Find the end of this peer section
LINES_TO_DELETE=1  # Start with 1 for the client name comment
CURRENT_LINE=$PEER_LINE_START

while true; do
    LINE_CONTENT=$(sed -n "${CURRENT_LINE}p" "$CONFIG_FILE")

    # Stop at blank line, next client comment, or EOF
    if [ -z "$LINE_CONTENT" ] || [[ "$LINE_CONTENT" =~ ^#[[:space:]]*[a-zA-Z0-9_-]+[[:space:]]*$ ]] || [ $CURRENT_LINE -gt $((START_LINE + 10)) ]; then
        break
    fi

    LINES_TO_DELETE=$((LINES_TO_DELETE + 1))
    CURRENT_LINE=$((CURRENT_LINE + 1))
done

# Remove the peer section (client comment + all peer lines)
sed -i "/^#\s*${CLIENT_NAME}\s*$/,+$((LINES_TO_DELETE - 1))d" "$CONFIG_FILE"

# Clean up multiple consecutive blank lines (reduce to single blank line)
# This handles cases where removal leaves extra spacing
sed -i '/^$/N;/^\n$/D' "$CONFIG_FILE"

# Remove trailing blank lines at end of file
sed -i -e :a -e '/^\n*$/{$d;N;ba' -e '}' "$CONFIG_FILE"

echo -e "${GREEN}✓ Removed peer section from server config${NC}"

# Remove client config file
if [ -f "$KEY_DIR/$CLIENT_NAME.conf" ]; then
    rm "$KEY_DIR/$CLIENT_NAME.conf"
    echo -e "${GREEN}✓ Removed client config file${NC}"
fi

# Remove client private key
if [ -f "$KEY_DIR/${CLIENT_NAME}_private_key" ]; then
    rm "$KEY_DIR/${CLIENT_NAME}_private_key"
    echo -e "${GREEN}✓ Removed client private key${NC}"
fi

# Remove client public key
if [ -f "$KEY_DIR/${CLIENT_NAME}_public_key" ]; then
    rm "$KEY_DIR/${CLIENT_NAME}_public_key"
    echo -e "${GREEN}✓ Removed client public key${NC}"
fi

# Audit log entry
log_audit "REMOVE_PEER" "client=$CLIENT_NAME status=$([ "$PEER_DISABLED" = true ] && echo "disabled" || echo "active") interface=$INTERFACE"

echo ""
echo -e "${BLUE}Applying configuration (hot reload - no disconnections)...${NC}"
wg syncconf $INTERFACE <(wg-quick strip $INTERFACE)
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Configuration reloaded successfully${NC}"
    echo -e "${GREEN}✓ Client removed from server${NC}"
else
    echo -e "${RED}✗ Hot reload failed${NC}"
    echo ""
    echo "To apply changes manually, run:"
    echo "  wg syncconf $INTERFACE <(wg-quick strip $INTERFACE)"
    echo "  OR"
    echo "  systemctl restart wg-quick@$INTERFACE"
fi

echo ""
echo -e "${GREEN}Done!${NC}"
