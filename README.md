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
/home/wireguard-scripts/
├── menu.sh                # Interactive menu (start here!)
├── setup.sh               # Initial server setup
├── add-peer.sh                      # Add a new peer (client/site/p2p)
├── remove-peer.sh                   # Remove a peer
├── toggle-peer.sh                   # Enable/disable a peer without removing it
├── list-peers.sh                     # List/view all peers with status
├── rotate-keys.sh                   # Rotate server or peer keys
├── show-qr.sh                       # Display peer config as QR code
├── reset.sh               # Cleanup / reset WireGuard state
├── healthcheck.sh                   # One-shot health check (cron / systemd timer)
├── log-connections.sh                # Connection logger for systemd journal
├── systemd/
│   ├── wireguard-connection-log.service   # Oneshot service for the connection logger
│   └── wireguard-connection-log.timer     # Fires the service every 2 min
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

## Health Check

`healthcheck.sh` is a one-shot probe — designed for cron or a systemd timer.
For each WireGuard interface it verifies:

1. `wg-quick@<iface>` service is active
2. the kernel interface exists
3. every `Address = …` declared in `<iface>.conf` is actually assigned to
   the interface — catches the wg-quick race where the service comes up
   "successfully" but the IP never makes it onto the interface

If any check fails, `--restart` will `systemctl restart wg-quick@<iface>`
and re-verify.

```bash
sudo ./healthcheck.sh                # check all interfaces, exit 1 if any fail
sudo ./healthcheck.sh -i wg0         # check just wg0
sudo ./healthcheck.sh --restart      # auto-restart anything unhealthy
sudo ./healthcheck.sh -v             # verbose (also report healthy)
```

Exit codes: `0` = all healthy, `1` = at least one unhealthy and `--restart`
did not recover it. Failures and recoveries are also logged to the systemd
journal under the `wireguard-audit` tag.

Cron example (every 5 minutes, auto-recover, quiet on success):

```
*/5 * * * * /home/wireguard-scripts/healthcheck.sh --restart
```

Peer reachability is reported for context only (with `-v`) but does NOT
trigger restarts — peers can legitimately be offline.

## Connection Logging

`log-connections.sh` is a small one-shot poller that diffs `wg show dump`
against a state file and writes connect/disconnect events to the systemd
journal under the `wireguard-connections` tag. Pair it with the included
systemd timer and you get a "who connected when, from what IP" audit trail
that journald rotates and retains for you.

### Install (one-time)

From the repo root, copy the unit files, reload, and enable the timer:

```bash
sudo cp systemd/wireguard-connection-log.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now wireguard-connection-log.timer
```

The timer fires every 2 minutes (matching WireGuard's handshake interval).
The script runs in place from `/home/wireguard-scripts/` — no copy to
`/usr/local/bin/` needed.

> **If your repo lives somewhere other than `/home/wireguard-scripts/`**,
> rewrite the `ExecStart=` path before copying:
>
> ```bash
> sudo sed "s|/home/wireguard-scripts|$(pwd)|g" systemd/wireguard-connection-log.service \
>   > /etc/systemd/system/wireguard-connection-log.service
> sudo cp systemd/wireguard-connection-log.timer /etc/systemd/system/
> sudo systemctl daemon-reload
> sudo systemctl enable --now wireguard-connection-log.timer
> ```

### Verify it's working

```bash
systemctl list-timers wireguard-connection-log.timer    # next/previous fire time
sudo systemctl start wireguard-connection-log.service   # fire it once now
journalctl -t wireguard-connections -n 10               # see any events yet?
```

If `journalctl` is empty, that's normal — events are only logged on state
*changes*. To force every current peer to show as a fresh `CONNECT`, wipe
the state file and re-run:

```bash
sudo rm -rf /var/lib/wireguard-connections
sudo systemctl start wireguard-connection-log.service
journalctl -t wireguard-connections -n 20
```

### Uninstall

```bash
sudo systemctl disable --now wireguard-connection-log.timer
sudo rm /etc/systemd/system/wireguard-connection-log.{service,timer}
sudo systemctl daemon-reload
sudo rm -rf /var/lib/wireguard-connections    # optional: drop state
```

### View logs

```bash
journalctl -t wireguard-connections -f                       # follow live
journalctl -t wireguard-connections -n 50                    # last 50
journalctl -t wireguard-connections | grep peer=remote-clinic
journalctl -t wireguard-connections --since "1 week ago"
journalctl -t wireguard-connections -o json-pretty > vpn-audit.json
```

Each line looks like:

```
CONNECT peer=remote-clinic iface=wg0 endpoint=203.0.113.45:51820 allowed_ips=10.0.10.1/32,192.168.10.0/24 pubkey=abc...=
DISCONNECT peer=remote-clinic iface=wg0 endpoint=203.0.113.45:51820 allowed_ips=10.0.10.1/32,192.168.10.0/24 pubkey=abc...=
```

- `endpoint` — the real public IP:port WireGuard saw (pre-NAT, captured before
  any masquerading on the server side). For site-to-site, that's the remote
  site's WAN IP.
- `allowed_ips` — what this peer is. For a client peer it's just the tunnel IP
  (e.g. `10.0.10.5/32`). For a site-to-site peer it's the tunnel IP plus any
  LAN subnets routed behind that site (e.g. `10.0.10.1/32,192.168.10.0/24`).
- `pubkey` — the cryptographic identity. Stable even if you rename the peer.

### Retention (HIPAA: 6 years)

journald handles rotation, compression, and purging — you just tell it how
long to keep things. Edit `/etc/systemd/journald.conf`:

```ini
[Journal]
Storage=persistent
SystemMaxUse=2G
MaxRetentionSec=6year
```

Then:

```bash
sudo mkdir -p /var/log/journal
sudo systemctl restart systemd-journald
```

`Storage=persistent` ensures logs survive reboots (`/var/log/journal/` instead
of `/run/log/journal/`). `SystemMaxUse` caps disk usage; `MaxRetentionSec`
caps age. Tune to your environment — 2 GB is plenty for a small VPN's worth
of connection events.

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
