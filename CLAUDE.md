# CLAUDE.md - Development Documentation

This file documents the development process and AI assistance used in creating this WireGuard server setup tool.

## Project Overview

**Project Name**: WireGuard Menu

**Goal**: Create a simple, user-friendly CLI tool for deploying WireGuard VPN servers that eliminates manual configuration complexity and works across multiple Linux distributions.

**Development Approach**: Iterative development with Claude Code AI assistance, focusing on automation, safety, and cross-platform compatibility.

## Development Timeline

### Initial Requirements
- Create a WireGuard server setup script
- Make it work for RHEL-based systems
- Provide simple CLI interface

### Iterative Enhancements

#### Phase 1: Configuration Flexibility
**Request**: Support both command-line arguments and interactive prompts with defaults

**Implementation**:
- Added argument parsing with `--server-ip`, `--network`, `--port`, `--interface`
- Created interactive prompt system with default values shown in brackets
- Implemented validation for IP/CIDR format and port ranges
- Hybrid approach: arguments override prompts, prompt for missing values

**Files Modified**: `setup-wireguard.sh`
- Added `parse_arguments()` function (lines 106-136)
- Added `prompt_user_config()` function (lines 302-421)
- Added validation functions (lines 138-165)

#### Phase 2: Safety & Conflict Detection
**Request**: Add safety checks for network conflicts and support multiple servers on same VM

**Implementation**:
- Network conflict detection (checks existing interfaces and configs)
- Port conflict detection (UDP port availability check)
- Interface name conflict detection
- Existing server listing with status indicators
- Automatic configuration backup with timestamps
- Safe service stop/start handling

**Files Modified**: `setup-wireguard.sh`
- Added `check_network_conflicts()` (lines 167-218)
- Added `check_port_conflicts()` (lines 220-247)
- Added `check_interface_conflicts()` (lines 249-269)
- Added `list_existing_wireguard_servers()` (lines 271-300)
- Updated `check_existing_config()` with backup logic (lines 496-530)

**Multiple Server Support**: YES - Each server needs unique interface, port, and network range.

#### Phase 3: Cross-Platform Support
**Request**: Clarify OS support and ensure it works on Debian-based systems too

**Implementation**:
- Already had OS detection built in
- Updated documentation to clarify RHEL and Debian support
- Verified package manager selection (dnf/yum vs apt)
- Confirmed firewall detection (firewalld vs ufw vs iptables vs nftables)

**Files Modified**: `setup-wireguard.sh`
- Updated header documentation (lines 1-55)
- OS detection was already present (lines 503-531)
- Package installation logic verified (lines 588-605)
- Firewall detection verified (lines 669-719)

#### Phase 4: Kernel Version Documentation
**Request**: Document kernel requirements for WireGuard

**Implementation**:
- Added comprehensive kernel version documentation in header
- Created runtime kernel version check function
- Added warning/success messages based on kernel version
- Documented native support (5.6+) vs backported/DKMS requirements

**Files Modified**: `setup-wireguard.sh`
- Added kernel requirements section to header (lines 15-30)
- Added `check_kernel()` function (lines 478-501)
- Integrated kernel check into main flow (line 1029)

#### Phase 5: Documentation
**Request**: Create README.md and CLAUDE.md

**Implementation**:
- Comprehensive README with usage examples, features, troubleshooting
- CLAUDE.md documenting the AI-assisted development process

**Files Created**:
- `README.md` - User-facing documentation
- `CLAUDE.md` - This file

#### Phase 6: Key Isolation Fix (CRITICAL BUG)
**Request**: Fix key overwriting when creating multiple servers

**Problem**: Running setup script multiple times would overwrite server keys in shared `/etc/wireguard/privatekey`, breaking the first server when creating a second.

**Implementation**:
- Changed from shared key files to interface-specific subdirectories
- `/etc/wireguard/wg0/server-privatekey` (isolated per interface)
- Each server completely independent with its own key storage
- Prevented catastrophic key conflicts

**Files Modified**: `setup-wireguard.sh`
- Updated key directory structure
- Modified key generation functions
- Updated all key file references

#### Phase 7: Client Management Scripts
**Request**: Add client lifecycle management capabilities

**Implementation**:

**add-client.sh** - Client creation
- Auto-detects single server or shows selection menu
- Suggests next available IP address automatically
- Generates client keypair
- Creates client config file ready for distribution
- Uses `wg syncconf` for hot reload (no connection drops)

**remove-client.sh** - Client removal
- Same server selection pattern as add-client
- Removes peer from server config
- Deletes all client files (config, keys)
- Timestamped backup before removal
- Hot reload preserves other connections

**list-clients.sh** - Utility for other scripts
- Multiple output formats: interactive, names-only, array, detailed
- `--check NAME` for client existence verification (exit code)
- `--count` for getting client count
- Used by other scripts for validation and listing

**Files Created**:
- `add-client.sh` - Client creation script
- `remove-client.sh` - Client removal script
- `list-clients.sh` - Client listing utility

#### Phase 8: Mobile Support & Monitoring
**Request**: QR code generation and client status monitoring

**Implementation**:

**qr-show.sh** (renamed from show-qr.sh)
- Displays client config as QR code in terminal
- Uses qrencode package (optional install, not forced)
- Perfect for mobile device onboarding
- Same selection pattern as other scripts

**client-status.sh** - Live monitoring
- Separated from list-clients.sh to keep that script simple
- Shows connection status: Connected/Idle/Never Connected
- Displays last handshake time
- Shows data transfer (upload/download)
- Parses live `wg show` output
- Color-coded status indicators

**Files Created**:
- `qr-show.sh` - QR code generator
- `client-status.sh` - Live status monitor

#### Phase 9: Security - Key Rotation
**Request**: Key rotation for security maintenance

**Implementation**:

**rotate-keys-client.sh** - Individual client rotation
- Regenerates client keypair only
- Updates server config with new public key
- Creates new client config file
- Hot reload (other clients unaffected)
- NO automatic backups (just warning with backup command)

**rotate-keys-server.sh** - Full server rotation
- Removes old server keys first (prevents conflicts)
- Generates new server keypair
- Updates ALL client configs with new server public key
- Restarts server (all clients disconnected)
- Shows distribution commands for all client configs

**Files Created**:
- `rotate-keys-client.sh` - Client key rotation
- `rotate-keys-server.sh` - Server key rotation

#### Phase 10: Interactive Menu System
**Request**: Create unified menu interface

**Implementation**:

**wireguard-menu.sh** - Main menu
- Clean terminal interface with organized categories
- Client Management (1-5): add, remove, list, status, rotate keys
- Client Configuration (6): QR codes
- Server Setup & Management (7-8): setup, rotate server keys
- System (9): exit
- Auto-detects script existence
- Makes scripts executable if needed
- Shows completion status after each script
- Returns to menu for next operation

**Files Created**:
- `wireguard-menu.sh` - Interactive menu system

## Key Design Decisions

### 1. Automatic Detection Over Manual Configuration
**Decision**: Auto-detect OS, firewall, kernel version instead of requiring user input
**Rationale**: Reduces user burden, prevents misconfiguration, makes script truly portable

### 2. Hybrid Input Model (Arguments + Prompts)
**Decision**: Support both command-line arguments and interactive prompts
**Rationale**:
- Arguments for automation/scripting
- Prompts for interactive use with helpful defaults
- Best of both worlds

### 3. Safety-First Approach
**Decision**: Check for conflicts before making changes, backup before overwriting
**Rationale**:
- Prevents accidental service disruption
- Makes script safe to run multiple times
- Supports multiple servers on same host

### 4. Cross-Platform from Day One
**Decision**: Build OS detection and multi-distro support from the start
**Rationale**:
- WireGuard is cross-platform
- Many users run mixed environments
- Better than maintaining separate scripts

### 5. Comprehensive Logging
**Decision**: Log all actions to `/var/log/wireguard-setup.log`
**Rationale**: Debugging, audit trail, troubleshooting support

## AI Assistance Details

### Anthropic Claude
- Model: Claude Sonnet 4.5 (claude-sonnet-4-5-20250929)
- Development Date: October 23, 2025
- Platform: Claude Code CLI
- Developer: Anthropic
- Original Author: Adrielle U.

### AI-Assisted Tasks

#### Code Generation
- Argument parsing logic
- Network/port/interface conflict detection
- Kernel version checking
- Multiple server detection and listing

#### Code Enhancement
- Input validation (IP/CIDR, port ranges)
- Error handling and user confirmations
- Backup functionality
- Color-coded output

#### Documentation
- Script header comments
- Usage examples
- README.md structure and content
- Kernel compatibility matrix
- Troubleshooting guide

#### Testing Scenarios
- Suggested edge cases for validation
- Multiple server workflows
- Cross-platform considerations

### Human Decisions (Adrielle U.)
- Overall project goal and scope
- Feature prioritization
- Default values (10.0.0.0/24, port 51820)
- Multi-server support requirement
- Safety check requirements
- Design direction and user experience

## Script Features

### What Works Well
✓ Automatic OS and firewall detection
✓ Comprehensive conflict detection
✓ Multiple server support
✓ Helpful default values
✓ Clear error messages and warnings
✓ Configuration backups
✓ Cross-platform compatibility

### Implemented Enhancements
✓ Client configuration generation script (add-client.sh)
✓ Automated client key generation (add-client.sh, rotate-keys-client.sh)
✓ QR code generation for mobile clients (qr-show.sh)
✓ Client connection monitoring (client-status.sh)
✓ Client lifecycle management (add, remove, list, status)
✓ Key rotation for security (client and server)
✓ Interactive menu system (wireguard-menu.sh)
✓ Interface-specific key isolation (prevents key conflicts)
✓ Hot reload support (no connection drops)

### Potential Future Enhancements
- Web UI for management
- Automatic updates/patches
- Bandwidth statistics and graphs
- Configuration migration tool
- Email notifications for client connections
- Automated client expiration/renewal

## Technical Challenges Solved

### Challenge 1: Multiple Firewall Systems
**Problem**: Different Linux distros use different firewalls (firewalld, ufw, iptables, nftables)
**Solution**: Runtime detection and distro-specific configuration scripts

### Challenge 2: Network Overlap Detection
**Problem**: Detecting if a new VPN network conflicts with existing interfaces
**Solution**: Parse `ip addr show` output and compare network prefixes

### Challenge 3: Multiple WireGuard Instances
**Problem**: Running multiple independent WireGuard servers on same host
**Solution**: Separate interfaces, configs, ports, and networks with conflict checks

### Challenge 4: SELinux on RHEL
**Problem**: SELinux can block WireGuard without proper contexts
**Solution**: Automatic SELinux context restoration and port labeling

### Challenge 5: Kernel Version Variance
**Problem**: Different distros ship different kernel versions with varying WireGuard support
**Solution**: Runtime kernel check with helpful warnings about DKMS requirements

## File Structure

```
/home/wireguard-menu/
├── wireguard-menu.sh            # Interactive menu interface
│   ├── Menu display
│   ├── Script execution wrapper
│   ├── Error handling
│   └── Clean terminal navigation
├── setup-wireguard.sh           # Main setup script (1046 lines)
│   ├── Configuration variables
│   ├── Helper functions (colors, logging, checks)
│   ├── Argument parsing
│   ├── Validation functions
│   ├── Conflict detection
│   ├── OS/kernel/firewall detection
│   ├── Installation functions
│   ├── Firewall configuration
│   ├── Service management
│   └── Summary/help output
├── add-client.sh                # Client creation script
│   ├── Server auto-detection
│   ├── IP address suggestion
│   ├── Key generation
│   ├── Config file creation
│   └── Hot reload (wg syncconf)
├── remove-client.sh             # Client removal script
│   ├── Client selection
│   ├── Config cleanup
│   ├── Timestamped backups
│   └── Hot reload
├── list-clients.sh              # Client listing utility
│   ├── Multiple output formats
│   ├── Client existence checking
│   └── Client counting
├── client-status.sh             # Live client monitoring
│   ├── Connection status parsing
│   ├── Handshake time analysis
│   ├── Data transfer tracking
│   └── Formatted status display
├── rotate-keys-client.sh        # Client key rotation
│   ├── Key regeneration
│   ├── Server config update
│   ├── Client config recreation
│   └── Hot reload
├── rotate-keys-server.sh        # Server key rotation
│   ├── Old key removal
│   ├── New key generation
│   ├── All client config updates
│   └── Server restart
├── qr-show.sh                   # QR code generator
│   ├── Config file reading
│   ├── QR code encoding
│   └── Terminal display
├── README.md                    # User documentation
└── CLAUDE.md                    # This file - development documentation
```

## Code Statistics

- **Total Scripts**: 9
- **Total Lines**: ~3000+ lines across all scripts
- **Functions**: 100+
- **Supported OSes**: 9 (RHEL, CentOS, Rocky, AlmaLinux, Fedora, Ubuntu, Debian variants)
- **Supported Firewalls**: 4 (firewalld, ufw, iptables, nftables)
- **Command-line Options**: 30+ across all scripts
- **Validation Checks**: 10+ (IP/CIDR, port, interface, client existence, etc.)
- **Conflict Checks**: 3 (network, port, interface)
- **Output Formats**: 4 (interactive, names-only, array, detailed)

## Testing Recommendations

### Manual Testing Scenarios
1. Fresh install on RHEL 9
2. Fresh install on Ubuntu 24.04
3. Second server on same VM
4. Overwriting existing configuration
5. Network conflict scenario
6. Port conflict scenario
7. Interface conflict scenario

### Automated Testing (Future)
- Unit tests for validation functions
- Integration tests for OS detection
- Mock tests for firewall configuration
- CI/CD pipeline for multiple distros

## Lessons Learned

1. **Start with detection, not assumptions**: OS/firewall/kernel detection makes script portable
2. **Safety checks are worth the complexity**: Prevents breaking existing setups
3. **Helpful defaults reduce friction**: Most users can just hit Enter repeatedly
4. **Clear output is crucial**: Color-coded messages help users understand what's happening
5. **Backup before modifying**: Timestamped backups give users confidence
6. **Log everything**: Helps with debugging and provides audit trail

## Resources Used

- WireGuard official documentation
- Linux kernel documentation for WireGuard
- systemd service management best practices
- firewalld/ufw/iptables/nftables documentation
- RHEL/Ubuntu/Debian package repositories

## Acknowledgments

- **Adrielle U.**: Original author, requirements, iterative feedback, and project direction
- **Anthropic Claude (AI)**: Code generation, documentation, and enhancement suggestions
- **WireGuard Project**: For creating a simple, modern VPN solution
- **Linux Kernel Team**: For mainlining WireGuard into kernel 5.6+
- **Anthropic**: For developing Claude AI technology

## Development Environment

- **OS**: RHEL 9 (Linux 5.14.0-522.el9.x86_64)
- **Shell**: Bash
- **Tools**: Claude Code CLI, standard Linux utilities
- **Location**: `/home/wireguard-menu/`

## Version History

### Phase 1: Initial Setup Script
- **v1.0** (Initial): Basic setup script for RHEL
- **v1.1** (Arguments): Added command-line argument support
- **v1.2** (Interactive): Added interactive prompts with defaults
- **v1.3** (Safety): Added conflict detection and safety checks
- **v1.4** (Multi-server): Added support for multiple WireGuard servers
- **v1.5** (Cross-platform): Clarified and verified RHEL/Debian support
- **v1.6** (Kernel docs): Added kernel version documentation and checking
- **v1.7** (Documentation): Added README.md and CLAUDE.md

### Phase 2: Client Management Suite
- **v2.0** (Key isolation): Fixed key conflicts with interface-specific subdirectories
- **v2.1** (Add clients): Created add-client.sh with auto IP suggestion
- **v2.2** (Remove clients): Created remove-client.sh with hot reload
- **v2.3** (List utility): Created list-clients.sh with multiple output formats
- **v2.4** (QR codes): Created qr-show.sh for mobile device setup
- **v2.5** (Key rotation): Created rotate-keys-client.sh for security
- **v2.6** (Server rotation): Created rotate-keys-server.sh for full key refresh
- **v2.7** (Client status): Created client-status.sh for live monitoring
- **v2.8** (Interactive menu): Created wireguard-menu.sh for easy navigation
- **v2.9** (Documentation): Updated README.md and CLAUDE.md with full suite

## Contact & Support

This is a community tool. For issues or enhancements:
1. Check logs: `/var/log/wireguard-setup.log`
2. Verify system requirements
3. Review README.md troubleshooting section

---

**Note**: This document serves as a development log and technical reference for understanding how this tool was created and evolved. It demonstrates the effective collaboration between human direction (Adrielle U.) and AI assistance (Anthropic Claude) in creating practical system administration tools. Created October 23, 2025.
