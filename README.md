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

### Prerequisites
- Root/sudo access
- Supported Linux distribution
- Kernel 3.10+ (5.6+ recommended)

### Interactive Menu (Recommended)

The easiest way to manage your WireGuard servers:

```bash
./wireguard-menu.sh
```

This displays a clean menu with all available management operations:
- Client Management (add, remove, list, status, rotate keys)
- Client Configuration (QR codes)
- Server Setup & Management (initial setup, rotate server keys)

### Quick Setup (Command Line)

Set up your first WireGuard server with defaults:
```bash
sudo ./setup-wireguard.sh
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
sudo ./setup-wireguard.sh \
  --interface wg0 \
  --port 51820 \
  --server-ip 10.0.0.1/24 \
  --network 10.0.0.0/24
```

### Mixed Mode

Provide some arguments, get prompted for others:
```bash
sudo ./setup-wireguard.sh --port 51820
# Will prompt for interface name, server IP, and network
```

### Running Multiple Servers

First server (uses defaults):
```bash
sudo ./setup-wireguard.sh
```

Second server (different interface, port, and network):
```bash
sudo ./setup-wireguard.sh \
  --interface wg1 \
  --port 51821 \
  --server-ip 10.0.1.1/24 \
  --network 10.0.1.0/24
```

Third server:
```bash
sudo ./setup-wireguard.sh \
  --interface wg2 \
  --port 51822 \
  --server-ip 10.0.2.1/24 \
  --network 10.0.2.0/24
```

### Help

View all options:
```bash
./setup-wireguard.sh --help
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

### 1. wireguard-menu.sh
**Interactive menu for all WireGuard operations**

```bash
./wireguard-menu.sh
```

Displays a clean, organized menu of all available scripts. Best for interactive use.

### 2. setup-wireguard.sh
**Initial WireGuard server setup**

```bash
sudo ./setup-wireguard.sh [OPTIONS]
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
sudo ./setup-wireguard.sh

# With arguments
sudo ./setup-wireguard.sh --interface wg1 --port 51821 --server-ip 10.0.1.1/24 --network 10.0.1.0/24
```

### 3. add-client.sh
**Add new clients to WireGuard server**

```bash
sudo ./add-client.sh [OPTIONS]
```

**Options:**
- `-i, --interface NAME` - WireGuard interface (e.g., wg0)
- `-c, --client NAME` - Client name
- `--ip IP` - Client IP address (auto-suggested if not provided)
- `-h, --help` - Show help

**Features:**
- Auto-detects single server or shows selection menu
- Suggests next available IP address
- Generates client keys automatically
- Creates client config file
- Hot-reloads server without dropping connections

**Example:**
```bash
# Interactive mode
sudo ./add-client.sh

# With arguments
sudo ./add-client.sh --interface wg0 --client laptop --ip 10.0.0.2/32
```

### 4. remove-client.sh
**Remove clients from WireGuard server**

```bash
sudo ./remove-client.sh [OPTIONS]
```

**Options:**
- `-i, --interface NAME` - WireGuard interface (e.g., wg0)
- `-c, --client NAME` - Client name to remove
- `-h, --help` - Show help

**Features:**
- Removes peer from server configuration
- Deletes client config files and keys
- Hot-reloads server without dropping other connections
- Creates timestamped backup of server config

**Example:**
```bash
# Interactive mode
sudo ./remove-client.sh

# With arguments
sudo ./remove-client.sh --interface wg0 --client old-laptop
```

### 5. list-clients.sh
**List clients for a WireGuard server**

```bash
./list-clients.sh <interface> [OPTIONS]
```

**Options:**
- `--format FORMAT` - Output format: interactive, names-only, array, detailed
- `--check NAME` - Check if client exists (exit 0 if yes, 1 if no)
- `--count` - Return client count only
- `-h, --help` - Show help

**Example:**
```bash
# Interactive list
./list-clients.sh wg0

# Just names (for scripting)
./list-clients.sh wg0 --format names-only

# Detailed info with public keys
./list-clients.sh wg0 --format detailed

# Check if client exists
./list-clients.sh wg0 --check laptop && echo "Client exists"

# Count clients
./list-clients.sh wg0 --count
```

### 6. client-status.sh
**Show detailed live status for a specific client**

```bash
sudo ./client-status.sh [OPTIONS]
```

**Options:**
- `-i, --interface NAME` - WireGuard interface (e.g., wg0)
- `-c, --client NAME` - Client name
- `-h, --help` - Show help

**Shows:**
- Connection status (Connected/Idle/Never Connected)
- Client IP address
- Remote endpoint IP
- Last handshake time
- Data transfer (upload/download)

**Example:**
```bash
# Interactive mode
sudo ./client-status.sh

# With arguments
sudo ./client-status.sh --interface wg0 --client laptop
```

### 7. rotate-keys.sh
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

### 8. qr-show.sh
**Display client config as QR code for mobile devices**

```bash
sudo ./qr-show.sh [OPTIONS]
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
sudo ./qr-show.sh

# With arguments
sudo ./qr-show.sh --interface wg0 --client phone
```

## Typical Workflows

### First-time Setup
1. Run server setup:
   ```bash
   sudo ./setup-wireguard.sh
   ```

2. Add your first client:
   ```bash
   sudo ./add-client.sh
   ```

3. Show QR code for mobile:
   ```bash
   sudo ./qr-show.sh
   ```

### Daily Operations
Use the interactive menu for convenience:
```bash
./wireguard-menu.sh
```

Or use individual scripts:
```bash
# Add new client
sudo ./add-client.sh --interface wg0 --client new-phone

# Check client status
sudo ./client-status.sh --interface wg0 --client laptop

# Remove old client
sudo ./remove-client.sh --interface wg0 --client old-device
```

### Security Maintenance
Periodically rotate keys:
```bash
# Rotate individual peer keys
sudo ./rotate-keys.sh -p laptop -i wg0

# Rotate server keys (affects all peers!)
sudo ./rotate-keys.sh -s -i wg0
```

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
sudo ./setup-wireguard.sh --port 51821
```

### Network conflicts
The script warns about network conflicts. Use a different network range:
```bash
sudo ./setup-wireguard.sh --server-ip 10.0.1.1/24 --network 10.0.1.0/24
```

## Project Structure

```
/home/wireguard-menu/
├── wireguard-menu.sh         # Interactive menu (start here!)
├── setup-wireguard.sh        # Initial server setup
├── add-client.sh             # Add new client
├── remove-client.sh          # Remove client
├── list-clients.sh           # List clients (utility)
├── client-status.sh          # Show client connection status
├── rotate-keys.sh            # Rotate server or peer keys
├── qr-show.sh                # Display client QR code
├── README.md                 # User documentation (you are here)
├── CLAUDE.md                 # Development documentation
├── CONTRIBUTING.md           # Contribution guidelines
├── CONTRIBUTORS.md           # List of contributors
├── CODE_OF_CONDUCT.md        # Code of conduct
├── SECURITY.md               # Security policy
├── CHANGELOG.md              # Version history
├── LICENSE                   # MIT License
├── .gitignore                # Git ignore patterns
└── .github/                  # GitHub templates
    ├── ISSUE_TEMPLATE/
    │   ├── bug_report.md
    │   └── feature_request.md
    └── PULL_REQUEST_TEMPLATE.md
```

## Contributing

We welcome contributions from the community! Whether you're fixing bugs, adding features, improving documentation, or testing on different platforms, your help is appreciated.

### How to Contribute

1. Read our [Contributing Guidelines](CONTRIBUTING.md)
2. Check existing [Issues](../../issues) and [Pull Requests](../../pulls)
3. Fork the repository and create a feature branch
4. Make your changes following our coding standards
5. Test thoroughly on supported platforms
6. Submit a pull request with clear description

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

### Code of Conduct

We are committed to providing a welcoming and inclusive environment. Please be respectful and considerate in all interactions.

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold this code.

### Recognition

All contributors are recognized in [CONTRIBUTORS.md](CONTRIBUTORS.md). Your contributions help make WireGuard more accessible to everyone!

## Security

Security is a top priority. If you discover a security vulnerability:

- **DO NOT** create a public issue
- **DO** report it privately following our [Security Policy](SECURITY.md)
- We will respond within 48 hours and work with you on disclosure

See [SECURITY.md](SECURITY.md) for complete security information.

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
- [CONTRIBUTING.md](CONTRIBUTING.md) - How to contribute to this project
- [CONTRIBUTORS.md](CONTRIBUTORS.md) - List of project contributors
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) - Community guidelines and standards
- [SECURITY.md](SECURITY.md) - Security policy and vulnerability reporting
- [CLAUDE.md](CLAUDE.md) - Development notes and AI assistance details
- [LICENSE](LICENSE) - MIT License details

### External Resources

- [WireGuard Official Documentation](https://www.wireguard.com/)
- [WireGuard QuickStart](https://www.wireguard.com/quickstart/)
- [WireGuard Protocol Whitepaper](https://www.wireguard.com/papers/wireguard.pdf)

### Community

- Report bugs: [Issues](../../issues)
- Request features: [Feature Requests](../../issues/new?template=feature_request.md)
- Contribute code: [Pull Requests](../../pulls)
- Security issues: See [SECURITY.md](SECURITY.md)

---

## Project Information

**Author:** Adrielle U.
**AI Assistant:** Anthropic Claude (Sonnet 4.5)
**Created:** October 23, 2025
**License:** MIT License - See [LICENSE](LICENSE) for details
