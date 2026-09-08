# WireGuard Menu

Complete suite of automated CLI tools for deploying and managing WireGuard VPN servers on Linux.

## Goal

Provide a comprehensive command-line interface for WireGuard server and client management that:
- Eliminates manual configuration complexity
- Works across multiple Linux distributions automatically
- Supports running multiple WireGuard servers on a single VM
- Includes comprehensive safety checks and conflict detection
- Provides easy client lifecycle management (add, remove, rotate keys)
- Makes WireGuard server management accessible through simple commands and an interactive menu

## Features

### Automatic Detection & Configuration
- **OS Detection**: Automatically detects and configures for RHEL, CentOS, Rocky, AlmaLinux, Fedora, Ubuntu, and Debian
- **Package Manager**: Auto-selects dnf/yum (RHEL-based) or apt (Debian-based)
- **Firewall Detection**: Automatically detects and configures firewalld, ufw, iptables, or nftables
- **Kernel Checking**: Verifies kernel version compatibility for WireGuard support
- **SELinux Support**: Handles SELinux contexts automatically on RHEL-based systems

### Safety & Conflict Prevention
- **Network Conflict Detection**: Checks for IP address range conflicts with existing interfaces
- **Port Conflict Detection**: Verifies UDP ports are available before use
- **Interface Conflict Detection**: Prevents duplicate interface names
- **Configuration Backup**: Automatically backs up existing configs with timestamps
- **Service Management**: Safely stops/starts services when needed

### Multiple Server Support
Run multiple independent WireGuard servers on the same VM, each with:
- Unique interface names (wg0, wg1, wg2, etc.)
- Separate UDP ports (51820, 51821, 51822, etc.)
- Isolated network ranges (10.0.0.0/24, 10.0.1.0/24, etc.)

## Supported Operating Systems

| OS | Kernel Version | Status |
|---|---|---|
| RHEL 9 | 5.14+ | ✓ Native support |
| RHEL 8 | 4.18+ | ✓ Backported support |
| CentOS Stream 8/9 | 4.18+/5.14+ | ✓ Supported |
| Rocky Linux 8/9 | 4.18+/5.14+ | ✓ Supported |
| AlmaLinux 8/9 | 4.18+/5.14+ | ✓ Supported |
| Fedora 35+ | 5.6+ | ✓ Native support |
| Ubuntu 20.04 | 5.4+ | ✓ Backported support |
| Ubuntu 22.04/24.04 | 5.15+/6.8+ | ✓ Native support |
| Debian 11/12 | 5.10+/6.1+ | ✓ Native support |

## Kernel Requirements

- **Recommended**: Linux kernel 5.6+ (native WireGuard support)
- **Minimum**: Linux kernel 3.10+ (with wireguard-dkms module)

WireGuard has been included in the mainline Linux kernel since version 5.6 (March 2020). Older kernels may require the `wireguard-dkms` package.

## Quick Start

> Curious what these scripts actually do? Skip to
> [Manual Setup (no scripts)](#manual-setup-no-scripts) below — it walks
> through the same setup command-by-command, mirroring the official
> [WireGuard QuickStart](https://www.wireguard.com/quickstart/).

### Prerequisites
- Root/sudo access
- Supported Linux distribution
- Kernel 3.10+ (5.6+ recommended)

### Interactive Menu (Recommended)

The easiest way to manage your WireGuard servers:

```bash
./menu.sh
```

This displays a clean menu with all available management operations:
- Peer Management (add, remove, list, toggle enable/disable)
- Peer Configuration (QR codes)
- Server Setup & Management (initial setup, restart/reload, rotate keys, reset)
- Auditing (connection logging)

### Quick Setup (Command Line)

Set up your first WireGuard server with defaults:
```bash
sudo ./setup.sh
```

You'll be prompted for:
- Interface name (default: wg0)
- Listen port (default: 51820)
- Server IP address (default: 10.0.0.1/24)
- VPN network range (default: 10.0.0.0/24)

Press Enter to accept defaults, or type custom values.

### Command-Line Arguments

Provide configuration via command-line arguments:
```bash
sudo ./setup.sh \
  --interface wg0 \
  --port 51820 \
  --server-ip 10.0.0.1/24 \
  --network 10.0.0.0/24
```

### Mixed Mode

Provide some arguments, get prompted for others:
```bash
sudo ./setup.sh --port 51820
# Will prompt for interface name, server IP, and network
```

### Running Multiple Servers

First server (uses defaults):
```bash
sudo ./setup.sh
```

Second server (different interface, port, and network):
```bash
sudo ./setup.sh \
  --interface wg1 \
  --port 51821 \
  --server-ip 10.0.1.1/24 \
  --network 10.0.1.0/24
```

Third server:
```bash
sudo ./setup.sh \
  --interface wg2 \
  --port 51822 \
  --server-ip 10.0.2.1/24 \
  --network 10.0.2.0/24
```

### Help

View all options:
```bash
./setup.sh --help
```

## Command-Line Options

| Option | Description | Default |
|---|---|---|
| `--interface NAME` | Interface name | wg0 |
| `--port PORT` | UDP listen port | 51820 |
| `--server-ip IP` | Server IP with CIDR | 10.0.0.1/24 |
| `--network CIDR` | VPN network range | 10.0.0.0/24 |
| `-h, --help` | Show help message | - |

## What the Script Does

1. **Checks Prerequisites**
   - Root privileges
   - Kernel version compatibility
   - OS detection
   - WireGuard kernel module availability

2. **Validates Configuration**
   - Lists existing WireGuard servers
   - Checks for interface conflicts
   - Checks for port conflicts
   - Checks for network conflicts
   - Shows configuration summary for approval

3. **Installs & Configures**
   - Installs wireguard-tools (if needed)
   - Generates server keys
   - Creates WireGuard configuration
   - Enables IP forwarding
   - Configures firewall rules
   - Handles SELinux (on RHEL)

4. **Starts Services**
   - Enables WireGuard service
   - Starts WireGuard interface
   - Verifies service is running

5. **Provides Summary**
   - Server public key
   - Configuration file location
   - Useful management commands
   - Next steps for adding clients

## Managing WireGuard Servers

### View All Servers
```bash
wg show all
```

### View Specific Server
```bash
wg show wg0
```

### Start/Stop/Restart
```bash
systemctl start wg-quick@wg0
systemctl stop wg-quick@wg0
systemctl restart wg-quick@wg0
```

### View Logs
```bash
journalctl -u wg-quick@wg0 -f
```

### Check Status
```bash
systemctl status wg-quick@wg0
```

## Configuration Files

### Server Configuration
- **WireGuard server config**: `/etc/wireguard/wg0.conf` (or wg1.conf, wg2.conf, etc.)
- **Server keys**: `/etc/wireguard/wg0/server-privatekey` and `server-publickey`
- **Setup log**: `/var/log/wireguard-setup.log`
- **Config backups**: `/etc/wireguard/wg0.conf.backup.YYYYMMDD_HHMMSS`

### Client Configuration (per interface)
- **Client configs**: `/etc/wireguard/wg0/client-name.conf`
- **Client keys**: `/etc/wireguard/wg0/client-name-privatekey` and `client-name-publickey`

### File Structure Example
```
/etc/wireguard/
├── wg0.conf                    # Server config
├── wg0/                        # Interface-specific directory
│   ├── server-privatekey
│   ├── server-publickey
│   ├── laptop-privatekey
│   ├── laptop-publickey
│   ├── laptop.conf             # Client config
│   ├── phone-privatekey
│   ├── phone-publickey
│   └── phone.conf
├── wg1.conf                    # Second server config
└── wg1/                        # Isolated from wg0
    └── [similar structure]
```

## Available Scripts

### 1. menu.sh
**Interactive menu for all WireGuard operations**

```bash
./menu.sh
```

Displays a clean, organized menu of all available scripts. Best for interactive use.

### 2. setup.sh
**Initial WireGuard server setup**

```bash
sudo ./setup.sh [OPTIONS]
```

**Options:**
- `--interface NAME` - Interface name (default: wg0)
- `--port PORT` - UDP listen port (default: 51820)
- `--server-ip IP` - Server IP with CIDR (default: 10.0.0.1/24)
- `--network CIDR` - VPN network range (default: 10.0.0.0/24)
- `-h, --help` - Show help message

**Example:**
```bash
# Interactive mode
sudo ./setup.sh

# With arguments
sudo ./setup.sh --interface wg1 --port 51821 --server-ip 10.0.1.1/24 --network 10.0.1.0/24
```

### 3. add-peer.sh
**Add a new peer (client, site, or peer-to-peer) to a WireGuard server**

```bash
sudo ./add-peer.sh [OPTIONS]
```

**Options:**
- `-i, --interface NAME` - WireGuard interface (e.g., wg0)
- `-n, --name NAME` - Peer name
- `-t, --type TYPE` - Peer type: `client`, `site`, or `p2p`
- `--ip IP` - Peer tunnel IP (auto-suggested if not provided)
- `-h, --help` - Show help

**Features:**
- Auto-detects single server or shows selection menu
- Suggests the next available IP in the VPN subnet
- Generates the peer keypair automatically
- Writes the peer config file to `/etc/wireguard/<iface>/<name>.conf`
- Hot-reloads the server with `wg syncconf` (other peers stay connected)

**Example:**
```bash
# Interactive mode
sudo ./add-peer.sh

# With arguments
sudo ./add-peer.sh --interface wg0 --name laptop --type client
```

### 4. remove-peer.sh
**Remove a peer from a WireGuard server**

```bash
sudo ./remove-peer.sh [OPTIONS]
```

**Options:**
- `-i, --interface NAME` - WireGuard interface (e.g., wg0)
- `-n, --name NAME` - Peer name to remove
- `-h, --help` - Show help

**Features:**
- Removes the peer block from the server configuration
- Deletes the peer's config file and keys
- Hot-reloads the server (other peers stay connected)
- Creates a timestamped backup of the server config first

**Example:**
```bash
# Interactive mode
sudo ./remove-peer.sh

# With arguments
sudo ./remove-peer.sh --interface wg0 --name old-laptop
```

### 5. list-peers.sh
**List all peers or view specific peer status**

```bash
./list-peers.sh [OPTIONS]
```

**Options:**
- `-i, --interface NAME` - WireGuard interface (e.g., wg0)
- `-p, --peer NAME` - View specific peer details
- `-d, --detailed` - Show more details (public keys, etc.)
- `-h, --help` - Show help

**What it shows:**
- All peers (Clients, Sites, P2P) with type indicators
- Connection status (Connected/Idle/Never)
- Tunnel IP addresses
- Remote LANs (for Sites and P2P peers)
- Last seen time and data transfer (with -d flag)
- Live connection status with auto-refresh

**Example:**
```bash
# List all peers
./list-peers.sh

# List peers on specific interface
./list-peers.sh -i wg0

# View specific peer details
./list-peers.sh -p laptop

# List with detailed info
./list-peers.sh -d
```

### 6. rotate-keys.sh
**Regenerate encryption keys for server or peers (unified key rotation)**

```bash
sudo ./rotate-keys.sh [OPTIONS]
```

**Options:**
- `-s, --server` - Rotate server keys
- `-p, --peer NAME` - Rotate peer keys
- `-i, --interface NAME` - WireGuard interface (e.g., wg0)
- `-h, --help` - Show help

**Server Key Rotation:**
- Removes old server keys (prevents conflicts)
- Generates new server keypair
- Updates server configuration
- Regenerates ALL peer configs with new server public key
- Restarts server (all peers disconnected until they update)
- **WARNING:** Disconnects ALL peers. They need new configs to reconnect.

**Peer Key Rotation:**
- Generates new peer keypair
- Updates server config with new public key
- Creates new peer config file
- Restarts server to apply changes
- Peer must update their config to reconnect

**Examples:**
```bash
# Interactive mode
sudo ./rotate-keys.sh

# Rotate server keys
sudo ./rotate-keys.sh -s -i wg0

# Rotate peer keys
sudo ./rotate-keys.sh -p laptop -i wg0
```

### 7. show-qr.sh
**Display client config as QR code for mobile devices**

```bash
sudo ./show-qr.sh [OPTIONS]
```

**Options:**
- `-i, --interface NAME` - WireGuard interface (e.g., wg0)
- `-c, --client NAME` - Client name
- `-h, --help` - Show help

**Requires:** `qrencode` package
```bash
# Install on RHEL/CentOS/Rocky/AlmaLinux
dnf install qrencode

# Install on Ubuntu/Debian
apt install qrencode
```

**Example:**
```bash
# Interactive mode
sudo ./show-qr.sh

# With arguments
sudo ./show-qr.sh --interface wg0 --client phone
```

## Typical Workflows

### First-time Setup
1. Run server setup:
   ```bash
   sudo ./setup.sh
   ```

2. Add your first peer:
   ```bash
   sudo ./add-peer.sh
   ```

3. Show QR code for mobile:
   ```bash
   sudo ./show-qr.sh
   ```

### Daily Operations
Use the interactive menu for convenience:
```bash
./menu.sh
```

Or use individual scripts:
```bash
# Add new peer
sudo ./add-peer.sh --interface wg0 --name new-phone --type client

# View peer status
./list-peers.sh -i wg0 -p laptop

# Remove old peer
sudo ./remove-peer.sh --interface wg0 --name old-device
```

### Security Maintenance
Periodically rotate keys:
```bash
# Rotate individual peer keys
sudo ./rotate-keys.sh -p laptop -i wg0

# Rotate server keys (affects all peers!)
sudo ./rotate-keys.sh -s -i wg0
```

## Multi-Site (Hub-and-Spoke) Topology

The most common production layout: one site acts as the VPN **hub** (the
WireGuard server) and the other sites connect to it as **spokes**. Spokes
talk to each other by routing through the hub, so you don't need a direct
tunnel from every site to every other site.

This is the right shape when you have, e.g., a cloud VPS as Site A and
multiple clinic offices (Sites B, C, …) that need to reach each other's
LANs.

### Example: 3 sites

```
                   ┌─────────────────────────────────┐
                   │  Site A — VPN hub (cloud VPS)   │
                   │  WG tunnel: 10.0.0.1/24         │
                   │  Public DNS: vpn.example.com    │
                   └────────────────┬────────────────┘
                                    │  WireGuard (UDP 51820)
                  ┌─────────────────┴─────────────────┐
                  │                                   │
   ┌──────────────▼──────────────┐     ┌──────────────▼──────────────┐
   │  Site B — clinic            │     │  Site C — clinic            │
   │  WG tunnel: 10.0.0.2/24     │     │  WG tunnel: 10.0.0.3/24     │
   │  LAN:       192.168.20.0/24 │     │  LAN:       192.168.30.0/24 │
   └─────────────────────────────┘     └─────────────────────────────┘
```

### CIDR plan

| Component         | CIDR                | Purpose                         |
| ----------------- | ------------------- | ------------------------------- |
| WG tunnel overlay | `10.0.0.0/24`       | tunnel IPs across all sites     |
| Site A tunnel IP  | `10.0.0.1/24`       | hub                             |
| Site B tunnel IP  | `10.0.0.2/24`       | spoke                           |
| Site C tunnel IP  | `10.0.0.3/24`       | spoke                           |
| Site B LAN        | `192.168.20.0/24`   | clinic B internal network       |
| Site C LAN        | `192.168.30.0/24`   | clinic C internal network       |

Pick non-overlapping subnets. Avoid `192.168.0.0/24` and `192.168.1.0/24`
for site LANs — they are the default at most home routers, so the moment a
remote user connects from their house it will collide with another site's
LAN and routing will break.

### 1. Set up Site A (the hub)

On the hub server:

```bash
sudo ./setup.sh \
  --interface wg0 \
  --port 51820 \
  --server-ip 10.0.0.1/24 \
  --network 10.0.0.0/24
```

This installs WireGuard, opens UDP 51820 in firewalld, places `wg0` in the
`trusted` zone, and starts the service. **Do not** enable exit-node mode —
hub-only routing between sites does not need MASQUERADE.

### 2. Add each spoke as a `site` peer on the hub

```bash
# Site B
sudo ./add-peer.sh --interface wg0 --name siteB --type site \
  --ip 10.0.0.2 --remote-network 192.168.20.0/24

# Site C
sudo ./add-peer.sh --interface wg0 --name siteC --type site \
  --ip 10.0.0.3 --remote-network 192.168.30.0/24
```

Each invocation writes a `[Peer]` block on the hub with
`AllowedIPs = <tunnel_ip>/32, <remote_lan>` — telling the hub which traffic
to push into which tunnel. It also generates a peer config file at
`/etc/wireguard/wg0/siteB.conf` and `/etc/wireguard/wg0/siteC.conf` that
you copy to the respective spoke servers.

### 3. Edit each spoke so it can reach the *other* spoke's LAN

The auto-generated spoke config only knows about the hub. To let Site B
reach Site C (and vice versa), each spoke's `[Peer Site A]` block needs the
other spokes' LANs added to `AllowedIPs`.

`/etc/wireguard/wg0.conf` on **Site B**:

```ini
[Interface]
Address    = 10.0.0.2/24
PrivateKey = <SITE_B_PRIVATE_KEY>

[Peer]
# Site A (hub)
PublicKey           = <SITE_A_PUBLIC_KEY>
Endpoint            = vpn.example.com:51820
AllowedIPs          = 10.0.0.0/24, 192.168.30.0/24
PersistentKeepalive = 25
```

`AllowedIPs = 10.0.0.0/24, 192.168.30.0/24` is the load-bearing line — it
routes the WG overlay **plus Site C's LAN** into the tunnel to the hub.

`/etc/wireguard/wg0.conf` on **Site C** (mirror image):

```ini
[Interface]
Address    = 10.0.0.3/24
PrivateKey = <SITE_C_PRIVATE_KEY>

[Peer]
# Site A (hub)
PublicKey           = <SITE_A_PUBLIC_KEY>
Endpoint            = vpn.example.com:51820
AllowedIPs          = 10.0.0.0/24, 192.168.20.0/24
PersistentKeepalive = 25
```

After editing each spoke:

```bash
sudo systemctl restart wg-quick@wg0
```

### 4. Hub: forwarding between spokes

`setup.sh` already places `wg0` in firewalld's `trusted` zone, and
firewalld permits forwarding between interfaces in the same trusted zone by
default — so no extra rules are needed for `wg0 → wg0` spoke-to-spoke
traffic. IP forwarding is enabled persistently in step 6 of the script.

If you've moved away from the default firewalld policy or are using a
different backend, make sure FORWARD `wg0 → wg0` is permitted on the hub.

### Verify spoke-to-spoke routing

From a host on Site B's LAN, ping a host on Site C's LAN:

```bash
ping 192.168.30.10
traceroute 192.168.30.10
# expected:
#   1. 192.168.20.1   ← Site B's LAN gateway / WG box
#   2. 10.0.0.1       ← hub (Site A) over the tunnel
#   3. 192.168.30.10  ← target host on Site C
```

On the hub, `wg show wg0` should show recent handshakes for both spokes and
counters going up on both `[Peer]` blocks while the ping is running.

### Adding a fourth site later

To add Site D with LAN `192.168.40.0/24`:

1. **On the hub**, add the new spoke peer:
   ```bash
   sudo ./add-peer.sh --interface wg0 --name siteD --type site \
     --ip 10.0.0.4 --remote-network 192.168.40.0/24
   ```
2. **On Site D**, install the generated `siteD.conf`, then edit
   `AllowedIPs` on its `[Peer Site A]` block to include every other spoke's
   LAN: `10.0.0.0/24, 192.168.20.0/24, 192.168.30.0/24`. Start the service.
3. **On every existing spoke (B, C)**, append `192.168.40.0/24` to the
   `AllowedIPs` line, then `systemctl restart wg-quick@wg0`.

That's the manual cost of full mesh-via-hub: each new spoke is one edit on
every existing spoke. Up to ~10 sites this stays manageable. Past that,
manage the spoke configs with Ansible (or similar) so a single re-run
pushes the new `AllowedIPs` everywhere.

## Firewall Support

The script automatically detects and configures:
- **firewalld** (RHEL, CentOS, Fedora default)
- **ufw** (Ubuntu default)
- **iptables** (legacy systems)
- **nftables** (modern systems)

## Security Features

- Automatic SELinux context configuration (RHEL-based)
- Restrictive file permissions (600) on config files
- Secure key generation with proper umask
- Firewall rules with NAT masquerading
- IP forwarding enabled safely and persistently

## Troubleshooting

### WireGuard module not loading
```bash
# Check if kernel supports WireGuard
modinfo wireguard

# Try loading module manually
modprobe wireguard

# On older kernels, install DKMS module
# RHEL: dnf install wireguard-dkms
# Ubuntu: apt install wireguard-dkms
```

### Port already in use
The script checks for port conflicts automatically. If you see this error:
```bash
# Check what's using the port
ss -ulnp | grep 51820

# Choose a different port
sudo ./setup.sh --port 51821
```

### Network conflicts
The script warns about network conflicts. Use a different network range:
```bash
sudo ./setup.sh --server-ip 10.0.1.1/24 --network 10.0.1.0/24
```

## Project Structure

```
/etc/wireguard/scripts/
├── menu.sh                # Interactive menu (start here!)
├── setup.sh               # Initial server setup
├── add-peer.sh                      # Add a new peer (client/site/p2p)
├── remove-peer.sh                   # Remove a peer
├── toggle-peer.sh                   # Enable/disable a peer without removing it
├── list-peers.sh                     # List/view all peers with status
├── rotate-keys.sh                   # Rotate server or peer keys
├── show-qr.sh                       # Display peer config as QR code
├── reset.sh               # Cleanup / reset WireGuard state
├── healthcheck.sh                   # One-shot runtime health check (cron / systemd timer)
├── verify-config.sh                 # Config conformance check (does it match our format?)
├── test-verify-config.sh            # Fault-injection tests for verify-config.sh
├── log-connections.sh                # Connection logger for systemd journal
├── install-healthcheck.sh           # Install/enable the healthcheck timer (availability)
├── install-logging.sh               # Install/enable the audit-log timer + retention (compliance)
├── systemd/
│   ├── journald-wireguard-audit.conf       # Journal retention drop-in (opt-in)
│   ├── wireguard-log-connections.service   # Oneshot service for the connection logger
│   └── wireguard-log-connections.timer     # Fires the service every 2 min
├── utils.sh                         # Shared helpers (sourced by other scripts)
├── README.md                        # All user documentation (you are here)
├── CHANGELOG.md                     # Version history
├── LICENSE                          # MIT License
└── .gitignore                       # Git ignore patterns
```

## Manual Setup (no scripts)

Mirrors the official [WireGuard QuickStart](https://www.wireguard.com/quickstart/).
Read this section to understand exactly what `setup.sh` and
`add-peer.sh` are doing under the hood, or to deploy WireGuard somewhere the
scripts cannot run.

### 0. Install WireGuard

| Distro | Install command |
| ------ | --------------- |
| RHEL / CentOS / Rocky / Alma 9 | `sudo dnf install -y wireguard-tools` |
| RHEL 8 (EPEL) | `sudo dnf install -y epel-release && sudo dnf install -y wireguard-tools` |
| Fedora | `sudo dnf install -y wireguard-tools` |
| Ubuntu / Debian | `sudo apt update && sudo apt install -y wireguard` |

```bash
sudo modprobe wireguard && lsmod | grep wireguard
```

### 1. Create the interface

```bash
sudo ip link add dev wg0 type wireguard
```

### 2. Assign an IP

```bash
sudo ip address add dev wg0 10.0.0.1/24
```

### 3. Generate keys

```bash
umask 077
wg genkey | tee server-privatekey | wg pubkey > server-publickey
```

### 4. Write `/etc/wireguard/wg0.conf`

```ini
[Interface]
Address    = 10.0.0.1/24
ListenPort = 51820
PrivateKey = <SERVER_PRIVATE_KEY>

# NAT for VPN clients reaching the internet is configured by the firewall
# (firewalld / nftables / iptables) in step 7, not via PostUp/PostDown here.
# Putting MASQUERADE in both places creates duplicate / conflicting NAT rules.

[Peer]
# laptop
PublicKey  = <LAPTOP_PUBLIC_KEY>
AllowedIPs = 10.0.0.2/32
```

### 5. Bring it up

```bash
sudo wg-quick up wg0
sudo systemctl enable --now wg-quick@wg0   # auto-start on boot
```

### 6. Forwarding (server only)

```bash
sudo sysctl -w net.ipv4.ip_forward=1
echo 'net.ipv4.ip_forward = 1' | sudo tee /etc/sysctl.d/99-wireguard.conf
```

### 7. Open the firewall

```bash
# firewalld (RHEL / Fedora)
sudo firewall-cmd --permanent --add-port=51820/udp
sudo firewall-cmd --permanent --add-masquerade
sudo firewall-cmd --reload

# ufw (Ubuntu)
sudo ufw allow 51820/udp

# iptables
sudo iptables -A INPUT -p udp --dport 51820 -j ACCEPT
sudo iptables -A FORWARD -i wg0 -j ACCEPT
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```

### 8. The client side

`/etc/wireguard/wg0.conf` on the client:

```ini
[Interface]
Address    = 10.0.0.2/32
PrivateKey = <LAPTOP_PRIVATE_KEY>
DNS        = 1.1.1.1                 # optional

[Peer]
PublicKey           = <SERVER_PUBLIC_KEY>
Endpoint            = vpn.example.com:51820
AllowedIPs          = 10.0.0.0/24    # tunnel only the VPN subnet
# AllowedIPs        = 0.0.0.0/0      # …or route ALL traffic through the VPN
PersistentKeepalive = 25             # required if the peer is behind NAT
```

```bash
sudo wg-quick up wg0
```

### 9. Verify and tear down

```bash
sudo wg show              # live status (handshakes, bytes, endpoints)
sudo wg-quick down wg0    # tear down
```

### Mapping to the scripts

| Manual step | Script equivalent |
| ----------- | ----------------- |
| Install + create iface + keys + conf | `sudo ./setup.sh` |
| Add a `[Peer]` block + client config | `sudo ./add-peer.sh` |
| Remove a `[Peer]` block | `sudo ./remove-peer.sh` |
| Disable a peer without deleting it | `sudo ./toggle-peer.sh` |
| Inspect peers / handshakes | `./list-peers.sh` |
| Show config as a QR code | `./show-qr.sh` |
| Rotate server or peer keys | `sudo ./rotate-keys.sh` |
| Import an existing `.conf` file | `sudo ./setup.sh --config <file>` |
| Tear everything down | `sudo ./reset.sh` |
| Check the config matches this toolkit's format | `sudo ./verify-config.sh` |
| Check the tunnel is up and working | `sudo ./healthcheck.sh` |

## Verifying the config

There are two different questions, and two different scripts:

| Question | Script |
| -------- | ------ |
| Is the tunnel working *right now*? | `healthcheck.sh` — runtime state |
| Is the config shaped the way these scripts expect? | `verify-config.sh` — on-disk format |

```bash
sudo ./verify-config.sh              # verify one interface (prompts if several)
sudo ./verify-config.sh -i wg0       # verify wg0
sudo ./verify-config.sh --all        # sweep every interface
sudo ./verify-config.sh -q --strict  # problems only; warnings fail too (CI / timers)
```

Errors exit 1, warnings exit 0 unless `--strict`. `verify-config.sh` is
read-only — it never touches the running tunnel.

The check worth knowing about is **marker coverage**. Every peer block this
toolkit writes is wrapped in `# BEGIN_PEER <name>` / `# END_PEER <name>`, and
`list-peers.sh`, `toggle-peer.sh`, `remove-peer.sh` and `rotate-keys.sh` all
find peers through those markers. WireGuard itself does not care about them —
so a `[Peer]` block added by hand, or restored from a config written before the
marker format, will connect perfectly well while being **invisible to every
management script here**. `verify-config.sh` is the only thing that reports it:

```
FAIL 2/3 [Peer] blocks carry BEGIN_PEER markers — 1 peer(s) are invisible to list/toggle/remove/rotate
    unmarked peer, PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
    fix: re-add these with add-peer.sh, or wrap each block in
         '# BEGIN_PEER <name>' / '# END_PEER <name>' by hand
```

It also catches unterminated marker blocks, duplicate peer names, duplicate
`PublicKey` or `AllowedIPs` across peers, a `server-privatekey` that no longer
matches the config's `PrivateKey` (a rotation that half-completed), peer public
keys on disk that disagree with the server config, orphan peer `.conf` files,
key material that is not mode 600, and a missing setup manifest.

> Note: `wg-quick strip` is sometimes suggested as a config validator. It is
> not one — it is a filter that prints the config with comments removed, and it
> exits 0 on arbitrary garbage. `verify-config.sh` parses the structure itself.

`test-verify-config.sh` covers it, one injected defect at a time:

```bash
sudo ./test-verify-config.sh         # 62 checks
sudo ./test-verify-config.sh -k      # keep the fixture dir for inspection
```

It is purely filesystem-based — it builds throwaway config trees under a temp
dir and drives every run with `WG_CONFIG_DIR` pointed at them, so unlike
`test-monitoring.sh` it creates no interfaces, touches no systemd units, and
never reads or writes `/etc/wireguard`. Safe to run on a live server.

## Health Check

`healthcheck.sh` is a one-shot probe — designed for cron or a systemd timer.
For each WireGuard interface it verifies:

1. `wg-quick@<iface>` service is active
2. the kernel interface exists
3. every `Address = …` declared in `<iface>.conf` is actually assigned to
   the interface — catches the wg-quick race where the service comes up
   "successfully" but the IP never makes it onto the interface
4. the firewall backend recorded in the per-interface manifest is still
   effective — firewalld/ufw services active, or the nftables rules we
   wrote at setup time still present in the kernel. Without this, the
   VPN looks healthy but the UDP port is closed and peers can't connect.
5. *(optional)* with a ping target configured, that the tunnel can actually
   reach the upstream server — see [Upstream reachability](#upstream-reachability-site--client-boxes).

If any check fails, `--restart` will `systemctl restart wg-quick@<iface>`
(or `systemctl start firewalld|ufw` for the firewall case) and re-verify.

```bash
sudo ./healthcheck.sh                # check all interfaces, exit 1 if any fail
sudo ./healthcheck.sh -i wg0         # check just wg0
sudo ./healthcheck.sh --restart      # auto-recover anything unhealthy
sudo ./healthcheck.sh -v             # verbose (also report healthy)
```

Exit codes: `0` = all healthy, `1` = at least one unhealthy and `--restart`
did not recover it. Failures and recoveries are also logged to the systemd
journal under the `wireguard-audit` tag.

### The goal: set-and-forget stability

`healthcheck.sh`, the connection logger, and `test-monitoring.sh` together aim
to make a WireGuard box something you **configure once and trust to keep itself
up** — not something you babysit. The design choices all serve that:

- **Self-healing, not just alerting.** On a timer with `--restart`, the box
  detects *and repairs* the failure modes that leave a tunnel "up" but dead — a
  missing address after a wg-quick race, a stopped firewall silently closing the
  port, or (on a site box) a tunnel that no longer carries traffic. You don't get
  paged at 3am; the box fixes itself and leaves an audit trail.
- **Safe by default, opt-in for the risky parts.** The structural checks are
  always on. The one action that could disrupt many peers — restarting on
  reachability — is **off unless a single interface explicitly opts in** via its
  own `.conf`, so the main hub can never be bounced by one offline host. Config
  lives next to the thing it controls, with nothing global to misconfigure.
- **Restraint built in.** Reachability rides out transient internet gaps
  (consecutive-failure threshold, persisted streak) and backs off instead of
  restart-looping during a real outage — stability under failure, not just on a
  good day.
- **Proven, not assumed.** `test-monitoring.sh` stands up throwaway interfaces
  and *actually breaks them* — flushes the address, stops the service, makes the
  upstream unreachable, ages a peer to idle — then asserts the box detects and
  recovers each. The safety guarantees above are tested, not just documented.

The result is a small, dependency-free set of shell scripts that give you the
hands-off reliability you'd otherwise reach for a much heavier orchestration
stack to get — control over a WireGuard instance with minimal ongoing effort.

### Install as a systemd timer (recommended)

There are **two installers**, because these are two different controls and you
should be able to enable, verify and report on them independently:

| Installer | Control | Installs |
| --------- | ------- | -------- |
| `install-healthcheck.sh` | Availability — is the tunnel up, restart it if not | `wireguard-healthcheck.{service,timer}` |
| `install-logging.sh` | Audit — the connect/disconnect trail | `wireguard-log-connections.{service,timer}`, and the journal retention drop-in with `--with-retention` |

Both rewrite the unit's `ExecStart`/`Documentation` to wherever this repo
actually lives, so you are not locked to a hardcoded path, and both are
idempotent — re-run after moving the repo or pulling changes:

```bash
sudo ./install-healthcheck.sh              # install/refresh + enable + start
sudo ./install-healthcheck.sh --status     # timer state
sudo ./install-healthcheck.sh --uninstall  # stop, disable, remove units

sudo ./install-logging.sh                  # install/refresh + enable + start
sudo ./install-logging.sh --with-retention # ... and widen journal retention
sudo ./install-logging.sh --check-retention # project the achievable window
sudo ./install-logging.sh --status         # timer state + record count + retention
```

> Don't `cp` the units by hand — the copies in `systemd/` carry a placeholder
> path (`/etc/wireguard/scripts/…`). Installing them verbatim gives you a timer
> that fires forever against a script that isn't there.

The healthcheck runs **every 60s**; the connection logger every 2 min.

### Verifying it's actually working

Four layers, each answering a different question. All four matter — the first
two can read perfectly green while the thing is doing nothing useful:

```bash
# 1. Armed, and will it survive a reboot?  ("enabled" is the one that matters)
systemctl is-enabled wireguard-healthcheck.timer
systemctl is-active  wireguard-healthcheck.timer
systemctl list-timers 'wireguard-*' --all

# 2. Is the service succeeding, not just firing?
systemctl status wireguard-healthcheck.service
journalctl -u wireguard-healthcheck.service --since -1h

# 3. Is it actually DECIDING anything? (the layer people skip)
journalctl -t wireguard-audit --since -24h
journalctl -t wireguard-audit -f          # live, during an incident

# 4. End-to-end proof on demand
sudo ./healthcheck.sh -v
sudo ./test-monitoring.sh                 # full harness
```

Two things that look like problems but aren't, and one that looks fine but isn't:

* The service is `Type=oneshot`, so its healthy steady state is
  **`inactive (dead)` with `status=0/SUCCESS`**. That is correct, not a failure.
* **Silence under `wireguard-audit` is healthy** — it only logs failures and
  actions, never routine success.
* **Unit drift is the failure mode that hides best.** If the installed units
  fall out of sync with the repo, every layer above still reports green while
  the live cadence and paths are whatever you installed months ago:

```bash
for u in wireguard-healthcheck.{timer,service} wireguard-log-connections.{timer,service}; do
  diff -q "systemd/$u" "/etc/systemd/system/$u" >/dev/null || echo "DRIFT: $u"
done
```

(The `.service` files legitimately differ in their rewritten paths — re-running
`install-healthcheck.sh` is the fix either way.)

### Or cron (if you prefer)

```
* * * * * /etc/wireguard/scripts/healthcheck.sh --restart
```

Peer reachability is reported for context only (with `-v`) but does NOT
trigger restarts — peers can legitimately be offline.

### Upstream reachability (site / client boxes)

On a box with a single upstream (a site-to-site or client connection), an
unreachable server *is* the signal the tunnel is dead. Give the healthcheck
a **ping target** — usually the server's in-tunnel IP — and it will, after the
interface and firewall are confirmed healthy, ping that target *through* the
tunnel and restart `wg-quick` if it can't reach it.

To ride out transient gaps it does **not** react to a single bad run. Each check
sends a few pings (success = any one replies), and recovery is a **two-tier
ladder keyed on handshake age**, so the cheap fix and the destructive one are
held to very different standards of proof:

| Handshake age | What happens | Why |
|---|---|---|
| **< 120s** | nothing — logged as `TARGET_DOWN` | WireGuard is still retrying on its own (every 5s for ~90s, then every 25s via `PersistentKeepalive`). Never pre-empt it. |
| **120s – 180s** | **re-resolve endpoints only** (`wg set`), no restart | Past WireGuard's own give-up, and fixes the one failure it *cannot* fix itself — a moved server IP. Drops no peers, so a false positive here is free. |
| **≥ 180s** | re-resolve, then **restart `wg-quick`** | 180s is `REJECT_AFTER_TIME`: WireGuard itself has declared the session dead. This is the floor — handshake ages up to ~165s are normal on a healthy *responder* session. |

Disruptive restarts are additionally **rate-limited to one per 15 minutes per
interface** (`RESTART_COOLDOWN_SECS`). Without that, a failure a restart can't
fix would bounce the tunnel on every single tick. Suppressed attempts are logged
as `HEALTHCHECK_RESTART_SUPPRESSED`.

The failure streak (`--fail-threshold`, default `1`) is persisted per interface
and cleared by any good check; after a restart that doesn't recover, the streak
resets so it backs off. All three gates can be overridden by environment
variable (`SOFT_RECOVERY_SECS`, `HANDSHAKE_DEAD_SECS`, `RESTART_COOLDOWN_SECS`)
for testing or for an unusually conservative box.

> **`PersistentKeepalive` is load-bearing.** After ~90s of failed handshakes the
> kernel purges staged packets and stops retrying (`MAX_TIMER_HANDSHAKES`). It
> only keeps trying at all because the keepalive re-triggers a handshake every
> 25s. A peer conf without it goes permanently dead until something in userspace
> intervenes. `setup.sh` and `add-peer.sh` set `25` by default — don't remove it.

You enable it **per interface**, by adding a comment line to the `[Interface]`
section of that box's `/etc/wireguard/<iface>.conf` (the `.1` is your server's
in-tunnel IP):

```ini
[Interface]
# Healthcheck-Reachability = 10.0.0.1
Address = 10.0.0.2/24
PrivateKey = ...
```

`wg`/`wg-quick` ignore `#` comments, so the line is inert config — but
`healthcheck.sh` reads it and, on the timer, pings that target through the
tunnel. Because it lives in each tunnel's own conf, **the main server is never
pinged or restarted on reachability**: its conf simply has no such line. That's
one safeguard — there's no single upstream to ping on a many-peer server, and
one offline host must not bounce the tunnel for everyone. (The other, and the
one that actually protects it, is `# Healthcheck-Role = server` — see below.) Never point it at a
roaming peer's IP for the same reason.

**Multiple targets and hostnames.** You can list several targets — IPs and/or
hostnames — comma- or space-separated, or across several comment lines. The
tunnel counts as alive if **any one** of them answers, so a single offline
upstream host won't trigger a restart:

```ini
[Interface]
# Healthcheck-Reachability = 10.0.0.1, 10.0.0.2, vpn.hub.example.com
Address = 10.0.0.2/24
```

Hostnames are resolved by the box's normal resolver, so prefer at least one
in-tunnel **IP** in the list — that way reachability still works if DNS itself
is the thing that's down.

Each target is validated before use. A malformed entry (e.g. a typo'd
`10.0.0.999`) is logged and ignored rather than silently treated as
"unreachable" — so a stray character can't quietly turn into a restart loop. If
*every* target is invalid, reachability is reported as misconfigured: the
interface is still considered healthy and is **never restarted** on that basis,
but the run warns you to fix the comment.

For a one-off manual run (or to try it before editing the conf) you can override
the target with a flag, which takes precedence over the conf line:

```bash
# Restart the tunnel only after 3 consecutive checks can't reach 10.0.0.1
sudo ./healthcheck.sh --ping-target 10.0.0.1 --restart

# Ride out longer gaps — require 5 consecutive failures
sudo ./healthcheck.sh --ping-target 10.0.0.1 --fail-threshold 5 --restart
```

### Never auto-restart the server

Add one line to the `[Interface]` section of the **server's** conf:

```ini
[Interface]
# Healthcheck-Role = server
Address = 10.0.0.1/24
ListenPort = 51820
PrivateKey = ...
```

Or as a one-liner (run it **once** — running it twice adds the line twice):

```bash
sudo sed -i '/^\[Interface\]/a # Healthcheck-Role = server' /etc/wireguard/wg0.conf
grep Healthcheck-Role /etc/wireguard/wg0.conf      # verify
```

`wg` ignores `#` lines, so this is inert config — no restart needed, it takes
effect on the next healthcheck run. `# Healthcheck-Role = hub` is accepted as a
synonym for older configs.

With it set, the server is **monitored and alerted on but its tunnel is never
bounced** — not on a structural failure, not on reachability, not even with
`--restart`. A false positive there would drop every connected peer, so that
decision stays with a human. Failures log `HEALTHCHECK_NORESTART` and exit
non-zero; watch with `journalctl -t wireguard-audit -f`.

**This line is what protects the server.** Reachability being unset only stops
the *ping-based* restart path — the structural checks (service dead, interface
missing, address missing) run on every interface regardless and will restart an
unmarked server. Set the role explicitly.

| | Server (`Role = server`) | Client / site |
|---|---|---|
| Detects + alerts | ✅ | ✅ |
| Restarts the tunnel | ❌ never | ✅ at 180s |
| Re-resolves endpoints | ❌ | ✅ at 120s |
| Starts a stopped firewalld/ufw | ✅ | ✅ |

The last row is deliberate: starting a stopped firewall drops nobody, it
*restores* peer connectivity. A server with its firewall down looks healthy
while the UDP port is closed and no peer can connect.

## Connection Logging

`log-connections.sh` is a small one-shot poller that diffs `wg show dump`
against a state file and writes connect/disconnect events to the systemd
journal under the `wireguard-connections` tag. Pair it with the included
systemd timer and you get a "who connected when, from what IP" audit trail
that journald rotates and retains for you.

### Install (one-time)

From the repo root, copy the unit files, reload, and enable the timer:

```bash
sudo cp systemd/wireguard-log-connections.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now wireguard-log-connections.timer
```

The timer fires every 2 minutes (matching WireGuard's handshake interval).
The units expect the repo at `/etc/wireguard/scripts/` and run
the script in place from there — no copy to `/usr/local/bin/` needed. (systemd
still loads the unit files themselves only from `/etc/systemd/system/`, so those
must be copied/symlinked there regardless of where the scripts live.)

> **If your repo lives somewhere other than `/etc/wireguard/scripts/`**,
> rewrite the `ExecStart=` path before copying:
>
> ```bash
> sudo sed "s|/etc/wireguard/scripts|$(pwd)|g" systemd/wireguard-log-connections.service \
>   > /etc/systemd/system/wireguard-log-connections.service
> sudo cp systemd/wireguard-log-connections.timer /etc/systemd/system/
> sudo systemctl daemon-reload
> sudo systemctl enable --now wireguard-log-connections.timer
> ```

### Verify it's working

```bash
systemctl list-timers wireguard-log-connections.timer    # next/previous fire time
sudo systemctl start wireguard-log-connections.service   # fire it once now
journalctl -t wireguard-connections -n 10               # see any events yet?
```

If `journalctl` is empty, that's normal — events are only logged on state
*changes*. To force every current peer to show as a fresh `CONNECT`, wipe
the state file and re-run:

```bash
sudo rm -rf /var/lib/wireguard-connections
sudo systemctl start wireguard-log-connections.service
journalctl -t wireguard-connections -n 20
```

### Uninstall

```bash
sudo systemctl disable --now wireguard-log-connections.timer
sudo rm /etc/systemd/system/wireguard-log-connections.{service,timer}
sudo systemctl daemon-reload
sudo rm -rf /var/lib/wireguard-connections    # optional: drop state
```

### View logs

Every audit record this toolkit writes — peer connects, admin actions, and
healthcheck results — shares one schema, so an audit is a **field query**
rather than a grep:

```bash
journalctl WG_ACTION=CONNECT -o short-iso             # every connect, with the year
journalctl WG_PEER=remote-clinic --since -30d         # one peer, last 30 days
journalctl WG_SESSION=abc12345-1788209278             # one session, both ends
journalctl WG_INTERFACE=wg0 -o short-iso              # everything on wg0, all tags
journalctl WG_ACTION=CONNECT -o json > vpn-audit.json # machine-readable export
```

Use `-o short-iso` for anything an auditor will read: the default format omits
the year, which is useless across a multi-year retention window.

The human-readable form is still there when you just want to watch:

```bash
journalctl -t wireguard-connections -f     # follow peer activity live
journalctl -t wireguard-audit -f           # follow admin/healthcheck activity
```

Each line looks like:

```
action=CONNECT peer=remote-clinic interface=wg0 endpoint=203.0.113.45:51820 allowed_ips=10.0.10.1/32,192.168.10.0/24 session=abc12345-1788209278 pubkey=abc...=
action=DISCONNECT peer=remote-clinic interface=wg0 endpoint=203.0.113.45:51820 allowed_ips=10.0.10.1/32,192.168.10.0/24 session=abc12345-1788209278 duration_sec=1847 pubkey=abc...=
```

Every `k=v` pair in the message is also an indexed journald field named
`WG_<KEY>` (`WG_PEER`, `WG_INTERFACE`, `WG_ENDPOINT`, `WG_SESSION`, …), plus
`WG_ACTION` for the verb and `WG_SCHEMA` for the schema version. That is what
makes the queries above work without parsing text.

- `session` — ties a `CONNECT` to its matching `DISCONNECT`. Sessions are how
  you answer "how long was this peer on?" without pairing lines by hand. A
  mid-session endpoint change (roaming) logs a second `CONNECT` reusing the
  same session id, so a roam reads as one session, not two.
- `duration_sec` — on `DISCONNECT` only: how long that session lasted.
  Resolution is bounded by the 2-minute poll and the 180 s activity window, so
  treat it as accurate to a few minutes, not to the second. A session shorter
  than one poll interval can be missed entirely — that is inherent to polling,
  and worth stating plainly in an audit response.
- `reason=peer-removed` — on `DISCONNECT` when a peer was deleted from the
  config while still connected, so an open session is closed rather than left
  dangling.

- `endpoint` — the real public IP:port WireGuard saw (pre-NAT, captured before
  any masquerading on the server side). For site-to-site, that's the remote
  site's WAN IP.
- `allowed_ips` — what this peer is. For a client peer it's just the tunnel IP
  (e.g. `10.0.10.5/32`). For a site-to-site peer it's the tunnel IP plus any
  LAN subnets routed behind that site (e.g. `10.0.10.1/32,192.168.10.0/24`).
- `pubkey` — the cryptographic identity. Stable even if you rename the peer.

### Retention (HIPAA: 6 years)

**Retention is not configured by default.** A stock journal keeps only what
fits its default disk budget — often well under a year — so the audit trail
silently ages out long before a 6-year requirement. Install the drop-in shipped
with this repo:

```bash
sudo ./install-logging.sh --with-retention
```

That installs `systemd/journald-wireguard-audit.conf` to
`/etc/systemd/journald.conf.d/` and restarts journald. Doing it by hand is the
same thing:

```ini
[Journal]
Storage=persistent
SystemMaxUse=8G
MaxRetentionSec=6year
```

```bash
sudo mkdir -p /var/log/journal
sudo systemctl restart systemd-journald
```

Two caveats worth knowing before you rely on the number:

- **Retention is host-wide, not per-tag.** These limits govern the entire
  journal, so a chatty neighbour (a container runtime, a web server) competes
  for the same budget and can evict WireGuard history early. Check what you
  actually have with `journalctl --disk-usage` and by looking at the oldest
  retained entry.
- **Size wins over age.** Once `SystemMaxUse` is reached the oldest entries are
  dropped even if `MaxRetentionSec` has not elapsed. On a busy host, raise
  `SystemMaxUse` rather than trusting the time limit alone.

`Storage=persistent` ensures logs survive reboots (`/var/log/journal/` instead
of `/run/log/journal/`). `SystemMaxUse` caps disk usage; `MaxRetentionSec`
caps age.

**Do not trust the shipped number — measure.** The two caveats above combine
into the failure that actually bites: a `MaxRetentionSec=6year` sitting behind
a `SystemMaxUse` that evicts after a few months, with nothing to tell you. The
achievable window is `SystemMaxUse ÷ the host's real journal growth rate`, and
that rate is entirely host-specific. So measure it:

```bash
sudo ./install-logging.sh --check-retention
```

```
  journal on disk    1.8GB over 652 days (~2.8MB/day)
  target window      2192 days
  needs about        6.1GB to hold that window
  SystemMaxUse       2.0GB
  achievable window  ~724 days
[✗] Retention cap is too small: it holds ~724 days, not 2192.
```

That is a real reading from a modest server — a 2 GB cap held under two years,
not six. It exits non-zero when the cap is short, so it can gate a compliance
check. Set `RETENTION_TARGET_DAYS` for a window other than HIPAA's 6 years.

A large cap is safe to set: journald also honours `SystemKeepFree` (15% of the
filesystem by default) and stops before filling the disk, so the effective
limit is whichever binds first.

### Config-change audit (separate tag)

`add-peer.sh` / `remove-peer.sh` / `toggle-peer.sh` log admin actions under
the `wireguard-audit` tag (different from `wireguard-connections`):

```bash
journalctl -t wireguard-audit                                  # admin actions
journalctl -t wireguard-audit -t wireguard-connections         # combined timeline
```

## Contributing

PRs welcome. Fork, branch, change, test on at least one supported distro,
open a PR. For security issues, please email the maintainer instead of
opening a public issue.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### MIT License Summary

- ✓ Free to use, modify, and distribute
- ✓ Commercial use allowed
- ✓ Private use allowed
- ✓ Modification allowed
- ✓ Distribution allowed
- ⚠ Provided "as is" without warranty
- ⚠ License and copyright notice must be included

## Additional Resources

### Project Documentation

- [CHANGELOG.md](CHANGELOG.md) - Version history and release notes
- [LICENSE](LICENSE) - MIT License details

### External Resources

- [WireGuard Official Documentation](https://www.wireguard.com/)
- [WireGuard QuickStart](https://www.wireguard.com/quickstart/)
- [WireGuard Protocol Whitepaper](https://www.wireguard.com/papers/wireguard.pdf)

---

## Project Information

**Author:** Adrielle U.
**AI Assistant:** Anthropic Claude (Sonnet 4.5)
**Created:** October 23, 2025
**License:** MIT License - See [LICENSE](LICENSE) for details
