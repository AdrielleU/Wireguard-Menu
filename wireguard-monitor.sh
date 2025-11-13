#!/bin/bash

# Configuration
WG_INTERFACE="wg0"
TUNNEL_IP="10.0.0.1"  # Replace with actual peer tunnel IP
CHECK_INTERVAL=60

while true; do
    # First, check if WireGuard interface exists
    if ! ip link show "$WG_INTERFACE" &> /dev/null; then
        echo "$(date): Cannot detect WireGuard interface $WG_INTERFACE - service may not be running"
        sleep $CHECK_INTERVAL
        continue
    fi
    
    # Interface exists, now check if tunnel is working
    if ! ping -c 1 -W 2 "$TUNNEL_IP" > /dev/null 2>&1; then
        echo "$(date): WireGuard tunnel dead (interface exists but no connectivity), restarting..."
        systemctl restart wg-quick@"$WG_INTERFACE"
        sleep 30  # Give it time to reconnect
    else
        echo "$(date): WireGuard tunnel is healthy"
    fi
    
    sleep $CHECK_INTERVAL
done