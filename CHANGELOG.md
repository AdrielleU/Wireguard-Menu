# Changelog

All notable changes to WireGuard Menu will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial public release preparation
- Standard open source project files (LICENSE, CONTRIBUTING, SECURITY, etc.)

## [2.0.0] - 2025-10-23

### Added
- **Interactive Menu System** (`wireguard-menu.sh`)
  - Clean terminal interface for all operations
  - Organized categories: Client Management, Client Configuration, Server Setup
  - Auto-detects script availability
  - Returns to menu after each operation

- **Client Management Scripts**
  - `add-client.sh` - Add new clients with auto IP suggestion
  - `remove-client.sh` - Remove clients with timestamped backups
  - `list-clients.sh` - List clients in multiple formats (interactive, names-only, array, detailed)

- **Client Monitoring**
  - `client-status.sh` - Show live connection status
    - Connection state (Connected/Idle/Never Connected)
    - Last handshake time
    - Data transfer statistics
    - Remote endpoint information

- **Mobile Support**
  - `qr-show.sh` - Display client configs as QR codes for mobile devices
  - Easy onboarding for iOS/Android WireGuard apps

- **Security - Key Rotation**
  - `rotate-keys-client.sh` - Rotate individual client keys
  - `rotate-keys-server.sh` - Rotate server keys and update all clients
  - Hot reload support (no connection drops for other clients)

- **Interface-Specific Key Isolation**
  - Server keys stored per interface (`/etc/wireguard/wg0/server-privatekey`)
  - Client keys stored per interface (`/etc/wireguard/wg0/client-privatekey`)
  - Prevents key conflicts when running multiple servers

### Changed
- **BREAKING**: Server keys moved from `/etc/wireguard/privatekey` to `/etc/wireguard/{interface}/server-privatekey`
- **BREAKING**: Client keys now stored in interface-specific directories
- Improved hot reload using `wg syncconf` instead of service restart
- All scripts now follow consistent server/client selection pattern
- Simplified backup strategy (no automatic backups, just warnings with backup commands)

### Fixed
- **CRITICAL**: Fixed key overwriting bug when creating multiple servers
- Server creation no longer affects existing servers' keys

### Documentation
- Comprehensive README.md with all script documentation
- CLAUDE.md documenting AI-assisted development process
- Updated examples and usage patterns

## [1.7.0] - 2025-10-22

### Added
- README.md with comprehensive user documentation
- CLAUDE.md documenting development process
- Usage examples for all features
- Troubleshooting guide

## [1.6.0] - 2025-10-22

### Added
- Kernel version documentation
- Runtime kernel version checking
- Warnings for older kernels requiring DKMS
- Kernel compatibility matrix in documentation

## [1.5.0] - 2025-10-22

### Changed
- Clarified cross-platform support (RHEL and Debian-based systems)
- Verified automatic OS detection works correctly
- Updated documentation to reflect multi-distro support

## [1.4.0] - 2025-10-22

### Added
- Support for multiple WireGuard servers on same VM
- Network conflict detection
- Port conflict detection
- Interface conflict detection
- Existing server listing with status indicators
- Configuration backups with timestamps

## [1.3.0] - 2025-10-22

### Added
- Safety checks before configuration changes
- Backup creation before overwriting existing configs
- User confirmation prompts for destructive operations

## [1.2.0] - 2025-10-21

### Added
- Interactive prompts with default values
- Press Enter to accept defaults
- Helpful value hints in brackets

## [1.1.0] - 2025-10-21

### Added
- Command-line argument support
- `--interface`, `--port`, `--server-ip`, `--network` options
- Arguments override interactive prompts
- Hybrid input model (arguments + prompts)

## [1.0.0] - 2025-10-21

### Added
- Initial WireGuard server setup script
- Automatic OS detection (RHEL-based systems)
- Automatic firewall detection and configuration
- Package installation (wireguard-tools)
- Server key generation
- Configuration file creation
- IP forwarding enablement
- SELinux support
- Service management
- Color-coded output
- Logging to `/var/log/wireguard-setup.log`

### Features
- Works on RHEL, CentOS, Rocky, AlmaLinux, Fedora
- Detects and configures firewalld, ufw, iptables, or nftables
- Safe permission handling (600 on config files)
- Comprehensive error handling

---

## Version Numbering

- **Major version** (X.0.0): Breaking changes, significant new features
- **Minor version** (0.X.0): New features, backward compatible
- **Patch version** (0.0.X): Bug fixes, documentation updates

## Upgrade Notes

### Upgrading to 2.0.0

**IMPORTANT**: Version 2.0.0 changes the key storage structure.

**For existing installations:**

If you have servers created with version 1.x, the keys are in:
- `/etc/wireguard/privatekey`
- `/etc/wireguard/publickey`

Version 2.0.0 expects keys in:
- `/etc/wireguard/wg0/server-privatekey`
- `/etc/wireguard/wg0/server-publickey`

**Migration steps:**

```bash
# For each existing interface (wg0, wg1, etc.)
sudo mkdir -p /etc/wireguard/wg0/
sudo mv /etc/wireguard/privatekey /etc/wireguard/wg0/server-privatekey
sudo mv /etc/wireguard/publickey /etc/wireguard/wg0/server-publickey

# If you have multiple servers
sudo mkdir -p /etc/wireguard/wg1/
sudo mv /etc/wireguard/wg1-privatekey /etc/wireguard/wg1/server-privatekey
sudo mv /etc/wireguard/wg1-publickey /etc/wireguard/wg1/server-publickey
```

**Or** simply keep using 1.x for existing servers and use 2.0+ for new servers only.

---

## Links

- [Repository](https://github.com/yourusername/wireguard-menu) (update when public)
- [Issues](https://github.com/yourusername/wireguard-menu/issues)
- [Pull Requests](https://github.com/yourusername/wireguard-menu/pulls)
