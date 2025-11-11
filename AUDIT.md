# WireGuard Audit Log - HIPAA Compliance

All WireGuard configuration changes are logged to the systemd journal with the tag `wireguard-audit`.

## Viewing Audit Logs

### Configuration Change Audit Logs

### View all WireGuard audit entries (config changes)
```bash
journalctl -t wireguard-audit
```

### View recent entries (last 50)
```bash
journalctl -t wireguard-audit -n 50
```

### Follow audit log in real-time
```bash
journalctl -t wireguard-audit -f
```

### Search by specific client
```bash
journalctl -t wireguard-audit | grep "client=laptop"
```

### Search by action type
```bash
journalctl -t wireguard-audit | grep "action=ADD_PEER"
journalctl -t wireguard-audit | grep "action=REMOVE_PEER"
journalctl -t wireguard-audit | grep "action=TOGGLE_PEER"
```

### Search by date/time
```bash
# Today's entries
journalctl -t wireguard-audit --since today

# Yesterday's entries
journalctl -t wireguard-audit --since yesterday --until today

# Specific date
journalctl -t wireguard-audit --since "2025-11-10" --until "2025-11-11"

# Specific time range
journalctl -t wireguard-audit --since "2025-11-10 14:00:00" --until "2025-11-10 16:00:00"
```

### Search by user
```bash
journalctl -t wireguard-audit | grep "user=root"
```

### Export audit logs
```bash
# Export to file
journalctl -t wireguard-audit > wireguard-audit-export.log

# Export in JSON format (for compliance reporting)
journalctl -t wireguard-audit -o json > wireguard-audit-export.json

# Export in JSON-pretty format (human readable JSON)
journalctl -t wireguard-audit -o json-pretty > wireguard-audit-export-pretty.json
```

---

## WireGuard Connection Status Logging

WireGuard logs connection events to the kernel/system logs. These are separate from configuration change audits.

### View WireGuard Connection Logs

#### View all WireGuard kernel messages
```bash
# All WireGuard-related kernel messages
journalctl -k | grep -i wireguard

# Or use dmesg
dmesg | grep -i wireguard
```

#### View WireGuard interface logs (wg-quick service)
```bash
# View logs for specific interface
journalctl -u wg-quick@wg0

# Follow in real-time
journalctl -u wg-quick@wg0 -f

# Last 50 entries
journalctl -u wg-quick@wg0 -n 50
```

#### View connection events (handshakes, peer connections)
```bash
# Filter for handshake messages (indicates successful connection)
journalctl -k | grep -i "wireguard.*handshake"

# View peer-related messages
journalctl -k | grep -i "wireguard.*peer"

# Today's connection events
journalctl -k --since today | grep -i wireguard
```

### Real-Time Connection Monitoring

#### Watch active connections
```bash
# Show current status (handshakes, data transfer)
sudo wg show

# Continuously monitor
watch -n 2 'sudo wg show'

# Show only specific interface
sudo wg show wg0
```

#### Monitor handshakes (indicates active connection)
```bash
# Watch for new handshakes in real-time
sudo journalctl -kf | grep --line-buffered "handshake"
```

### Connection Status Information

WireGuard logs show:
- **Interface up/down** events
- **Handshake completion** (successful connection establishment)
- **Peer connection** status
- **Configuration reloads**
- **Errors** (authentication failures, etc.)

### Example Connection Log Entries

```
Nov 10 15:30:45 server kernel: wireguard: wg0: Interface created
Nov 10 15:30:45 server kernel: wireguard: wg0: Peer added: abc123...
Nov 10 15:31:02 server kernel: wireguard: wg0: Handshake for peer abc123... succeeded
Nov 10 15:35:12 server kernel: wireguard: wg0: Handshake for peer abc123... succeeded
```

### Check Last Connection Time

```bash
# Show last handshake time for each peer
sudo wg show wg0 latest-handshakes

# Show full status including last handshake
sudo wg show wg0 dump
```

### Enable More Verbose Logging (Optional)

WireGuard logs at kernel level. To increase verbosity:

```bash
# Increase kernel log level (temporary)
echo 7 > /proc/sys/kernel/printk

# View kernel messages in real-time
dmesg -w | grep -i wireguard
```

**Note:** This creates a LOT of output. Only use for debugging.

### Automated Connection Logging Script

Create a script to periodically log connection status:

```bash
#!/bin/bash
# /usr/local/bin/wireguard-connection-logger.sh

INTERFACE="wg0"
LOG_FILE="/var/log/wireguard-connections.log"

while true; do
    TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

    # Get current connections
    wg show $INTERFACE | while read -r line; do
        if [[ "$line" =~ ^peer: ]]; then
            echo "$TIMESTAMP | $line" >> "$LOG_FILE"
        elif [[ "$line" =~ latest\ handshake: ]]; then
            echo "$TIMESTAMP | $line" >> "$LOG_FILE"
        fi
    done

    sleep 300  # Log every 5 minutes
done
```

Run as systemd service:

```bash
# Create service file
sudo tee /etc/systemd/system/wireguard-connection-logger.service <<EOF
[Unit]
Description=WireGuard Connection Logger
After=wg-quick@wg0.service

[Service]
Type=simple
ExecStart=/usr/local/bin/wireguard-connection-logger.sh
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Enable and start
sudo chmod +x /usr/local/bin/wireguard-connection-logger.sh
sudo systemctl daemon-reload
sudo systemctl enable wireguard-connection-logger
sudo systemctl start wireguard-connection-logger
```

## Audit Log Format

Each entry contains:
- **Timestamp**: Automatic from systemd journal
- **User**: Who made the change (username)
- **Source IP**: Where the change was made from
- **Action**: Type of change (ADD_PEER, REMOVE_PEER, TOGGLE_PEER)
- **Details**: Specific information about the change

### Example Entry
```
Nov 10 21:30:45 server1 wireguard-audit[12345]: action=ADD_PEER user=root source_ip=192.168.1.100 client=laptop ip=10.0.0.2/32 server_allowed_ips=10.0.0.2/32 client_allowed_ips=10.0.0.0/24 interface=wg0
```

## HIPAA Compliance Features

### Built-in Benefits of systemd Journal:
- ✅ **Tamper-evident**: Journal is cryptographically sealed
- ✅ **Automatic rotation**: Configurable retention policies
- ✅ **Remote logging**: Forward to central logging server
- ✅ **Searchable**: Full text search and filtering
- ✅ **Timestamped**: Precise timestamps with timezone
- ✅ **Persistent**: Survives reboots (if configured)
- ✅ **Access control**: Requires root or systemd-journal group

### Configuration for HIPAA

#### 1. Enable Persistent Logging
```bash
# Ensure journal persists across reboots
mkdir -p /var/log/journal
systemctl restart systemd-journald
```

#### 2. Set Retention Policy
Edit `/etc/systemd/journald.conf`:
```ini
[Journal]
Storage=persistent
MaxRetentionSec=2years
SystemMaxUse=10G
```

Then restart:
```bash
systemctl restart systemd-journald
```

#### 3. Forward to Remote Syslog (recommended for HIPAA)
Install rsyslog:
```bash
dnf install rsyslog
systemctl enable rsyslog
systemctl start rsyslog
```

Edit `/etc/rsyslog.conf` and add:
```
# Forward wireguard-audit logs to remote server
:programname, isequal, "wireguard-audit" @@remote-log-server.example.com:514
```

Restart rsyslog:
```bash
systemctl restart rsyslog
```

## Actions Logged

### ADD_PEER
Logged when a new client/peer is added to the server.
```
action=ADD_PEER client=<name> ip=<vpn-ip> server_allowed_ips=<routes> client_allowed_ips=<routes> interface=<interface>
```

### REMOVE_PEER
Logged when a client/peer is removed from the server.
```
action=REMOVE_PEER client=<name> status=<active|disabled> interface=<interface>
```

### TOGGLE_PEER
Logged when a client/peer is enabled or disabled.
```
action=TOGGLE_PEER client=<name> action=<enable|disable> new_status=<enabled|disabled> interface=<interface>
```

## Compliance Reporting

### Generate Monthly Report
```bash
#!/bin/bash
# Generate monthly audit report
MONTH=$(date +%Y-%m)
journalctl -t wireguard-audit --since "${MONTH}-01" --until "${MONTH}-31" \
    -o json-pretty > "wireguard-audit-${MONTH}.json"
```

### Count Actions by Type
```bash
echo "ADD_PEER:    $(journalctl -t wireguard-audit --since today | grep -c 'action=ADD_PEER')"
echo "REMOVE_PEER: $(journalctl -t wireguard-audit --since today | grep -c 'action=REMOVE_PEER')"
echo "TOGGLE_PEER: $(journalctl -t wireguard-audit --since today | grep -c 'action=TOGGLE_PEER')"
```

### List All Users Who Made Changes
```bash
journalctl -t wireguard-audit | grep -oP 'user=\K\w+' | sort -u
```

## Security Recommendations

1. **Restrict journal access**: Only root and systemd-journal group
2. **Enable SELinux**: Protects journal from tampering
3. **Remote logging**: Forward to immutable/write-once storage
4. **Regular backups**: Backup journal files for long-term retention
5. **Monitor access**: Alert on journal access patterns
6. **Encrypt at rest**: Use LUKS for /var/log/journal

## Troubleshooting

### Check if logging is working
```bash
logger -t wireguard-audit "TEST: Audit logging test"
journalctl -t wireguard-audit -n 5
```

### Verify journal persistence
```bash
ls -lh /var/log/journal/
journalctl --disk-usage
```

### Check journal integrity
```bash
journalctl --verify
```
