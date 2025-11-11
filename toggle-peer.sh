#!/bin/bash

# ============================================
# WireGuard Peer Toggle Tool
# ============================================
# Enables or disables a peer by commenting/uncommenting
# the peer block in the server config
# Does NOT delete any files

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

echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}WireGuard Peer Toggle Tool${NC}"
echo -e "${CYAN}============================================${NC}"
echo -e "Enable or disable peers on interface: ${BLUE}$INTERFACE${NC}"
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
    echo "No clients to toggle."
    exit 0
fi

# Prompt for client name to toggle
read -p "Enter client name to toggle: " CLIENT_NAME

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

# Check if peer is active or disabled
LINE_NUM=$(grep -nE "^#\s*${CLIENT_NAME}\s*$" "$CONFIG_FILE" | cut -d: -f1 | head -1)
NEXT_LINE=$(sed -n "$((LINE_NUM + 1))p" "$CONFIG_FILE")

if echo "$NEXT_LINE" | grep -qE "^#.*\[Peer\]"; then
    PEER_DISABLED=true
    ACTION="enable"
    CURRENT_STATUS="${YELLOW}DISABLED${NC}"
else
    PEER_DISABLED=false
    ACTION="disable"
    CURRENT_STATUS="${GREEN}ACTIVE${NC}"
fi

echo ""
echo -e "Client '${BLUE}$CLIENT_NAME${NC}' is currently: $CURRENT_STATUS"
echo -e "This will ${YELLOW}$ACTION${NC} the client."
echo ""
read -p "Type '$ACTION' to confirm: " CONFIRM

if [ "$CONFIRM" != "$ACTION" ]; then
    echo -e "${YELLOW}Toggle cancelled.${NC}"
    exit 0
fi

echo ""

# Toggle the peer
# Find all lines in the peer section (until next blank line or next [Peer] or EOF)
PEER_START=$((LINE_NUM + 1))

# Find the end of this peer section
PEER_END=$PEER_START
while true; do
    LINE_CONTENT=$(sed -n "${PEER_END}p" "$CONFIG_FILE")

    # Stop at blank line, next comment (potential next peer), or EOF
    if [ -z "$LINE_CONTENT" ] || [[ "$LINE_CONTENT" =~ ^#[[:space:]]*[a-zA-Z0-9_-]+[[:space:]]*$ ]] || [ $PEER_END -gt $((LINE_NUM + 10)) ]; then
        PEER_END=$((PEER_END - 1))
        break
    fi

    PEER_END=$((PEER_END + 1))
done

if [ "$PEER_DISABLED" = true ]; then
    # Enable: Remove comment from all peer config lines
    echo -e "${BLUE}Enabling peer (lines $PEER_START to $PEER_END)...${NC}"
    for i in $(seq $PEER_START $PEER_END); do
        sed -i "${i}s/^#\s\+//" "$CONFIG_FILE"
    done

    echo -e "${GREEN}✓ Peer enabled in server config${NC}"

else
    # Disable: Add comment to all peer config lines
    echo -e "${BLUE}Disabling peer (lines $PEER_START to $PEER_END)...${NC}"
    for i in $(seq $PEER_START $PEER_END); do
        sed -i "${i}s/^/# /" "$CONFIG_FILE"
    done

    echo -e "${GREEN}✓ Peer disabled in server config${NC}"
fi

# Clean up multiple consecutive blank lines (reduce to single blank line)
sed -i '/^$/N;/^\n$/D' "$CONFIG_FILE"

# Remove trailing blank lines at end of file
sed -i -e :a -e '/^\n*$/{$d;N;ba' -e '}' "$CONFIG_FILE"

echo -e "${GREEN}✓ Server config updated${NC}"

# Audit log entry
NEW_STATUS=$([ "$PEER_DISABLED" = true ] && echo "enabled" || echo "disabled")
log_audit "TOGGLE_PEER" "client=$CLIENT_NAME action=$ACTION new_status=$NEW_STATUS interface=$INTERFACE"

echo ""
echo -e "${BLUE}Applying configuration (hot reload)...${NC}"
wg syncconf $INTERFACE <(wg-quick strip $INTERFACE)
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Configuration reloaded successfully${NC}"
    NEW_STATUS_COLOR=$([ "$PEER_DISABLED" = true ] && echo "${GREEN}ENABLED${NC}" || echo "${YELLOW}DISABLED${NC}")
    echo -e "${GREEN}✓${NC} Client is now $NEW_STATUS_COLOR"
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
