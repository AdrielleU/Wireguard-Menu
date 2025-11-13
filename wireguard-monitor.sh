#!/bin/bash
while true; do
    # Check if tunnel is alive by pinging peer through tunnel
    if ! ping -c 1 -W 2 <tunnel-peer-ip> > /dev/null 2>&1; then
        echo "WireGuard tunnel dead, restarting..."
        systemctl restart wg-quick@wg0
        sleep 30  # Give it time to reconnect
    fi
    sleep 60  # Check every minute
done