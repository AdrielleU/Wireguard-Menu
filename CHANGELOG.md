# Changelog

All notable changes to WireGuard Menu will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Split `set-recoveryservice.sh` into `install-healthcheck.sh` and
  `install-logging.sh`.** The old script installed both timers *and* the
  journal retention drop-in under a name that described none of it. These are
  two different controls — availability (is the tunnel up, restart it if not)
  and audit (the connect/disconnect trail §164.312(b) asks for) — and they are
  now installable, verifiable and removable independently, so a compliance
  install does not drag in auto-restart behaviour or vice versa. The unit
  rewriting they shared lives in `utils.sh` (`unit_install_service`,
  `unit_install_timer`, `unit_enable_timer`, `unit_remove`), so the split cost
  no duplication. Unit filenames are unchanged, so existing installs are
  re-pointed rather than orphaned.
- **`install-logging.sh --check-retention`** — measures the host's real journal
  growth and projects the retention window the current `SystemMaxUse` can
  actually hold, exiting non-zero when it falls short of the target (default
  2192 days per HIPAA §164.316(b)(2)(i); set `RETENTION_TARGET_DAYS` to
  change). This exists because journald retention is host-wide and **size wins
  over age**: a `MaxRetentionSec=6year` sitting behind an undersized
  `SystemMaxUse` evicts silently, and nothing reported it. Measured on a modest
  server, the previously shipped 2G cap held ~724 days — under two years, not
  six.
- `test-installers.sh` — 37 checks covering unit-path rewriting (including that
  the healthcheck's `--restart` argument survives it), that each installer
  touches only its own units, rejection of unsafe repo paths, and the retention
  projection across suffix parsing, drop-in merge order, undersized/sufficient/
  unset caps and a configurable target window. Unit writes are redirected via
  `UNIT_DST` and retention reads a fixture via `JOURNALD_CONF_ROOT`, so the
  suite never writes to `/etc/systemd/system` or reads the host's journald
  config.

- **`verify-config.sh` (`wireguardmenu verify`)** — asserts that an interface's
  on-disk state matches the conventions these scripts write and read. It is a
  conformance check, not a health check, and never touches the running tunnel:
  `healthcheck.sh` answers "is the tunnel working now?", `verify-config.sh`
  answers "is this config shaped the way our scripts expect?".

  The check that motivated it is **marker coverage**. WireGuard loads a
  `[Peer]` block with no `# BEGIN_PEER` markers perfectly happily, but
  list/toggle/remove/rotate all read peers through those markers — so a
  hand-edited or pre-marker-format peer connects fine while being invisible to,
  and unmanageable by, every script here. Nothing else in the toolkit reported
  that. It also catches unterminated marker blocks, duplicate peer names,
  duplicate `PublicKey`/`AllowedIPs` across peers, a `server-privatekey` that
  no longer matches the config's `PrivateKey` (a rotation that half-completed),
  peer public keys on disk that disagree with the server config, orphan peer
  `.conf` files, non-600 key material, and a missing setup manifest.
  Errors exit 1; warnings exit 0 unless `--strict`. `--all` sweeps every
  interface.

  Note that `wg-quick strip` is *not* a validator — it is a filter that exits 0
  on arbitrary garbage — so the structural check is done here directly rather
  than delegated to it.
- `test-verify-config.sh` — 62 fault-injection checks for the above. Each test
  starts from a conformant fixture built with real `wg genkey` material, injects
  exactly one defect, and asserts both the message and the exit code, so a check
  that stops working fails one named test. Verified by mutation: disabling the
  marker-coverage check, the server-key comparison, the unterminated-block
  check, the warning/error split, or the exit code each makes the suite fail.
  Purely filesystem-based (everything runs under `WG_CONFIG_DIR` in a temp dir),
  so it needs no interfaces or systemd units and is safe on a live server.
- `menu.sh` grew a **Diagnostics** section exposing both `verify-config.sh` and
  `healthcheck.sh`; the latter was previously reachable only via
  `wireguardmenu healthcheck`, never from the interactive menu.
- **Session tracking in `log-connections.sh`.** Each connected period gets a
  `session` id shared by its `CONNECT` and `DISCONNECT`, and the `DISCONNECT`
  reports `duration_sec`, so "how long was this peer on?" no longer requires
  pairing lines by hand. A mid-session endpoint change (roaming) reuses the
  same session id, so a roam reads as one session rather than two.
- `systemd/journald-wireguard-audit.conf` — journal retention drop-in
  (`Storage=persistent`, `SystemMaxUse=8G`, `MaxRetentionSec=6year`), installed
  by `install-logging.sh --with-retention`. Retention was previously a
  documented manual step that was easy to skip, leaving the audit trail to age
  out well before the 6-year HIPAA window. Left in place on `--uninstall`,
  since shrinking retention would discard existing history.

### Changed
- **`setup.sh` and `reset.sh` now use the shared helpers they were already
  sourcing.** Both scripts sourced `utils.sh` and then redefined `print_*`,
  `log`, `die`, `check_root` and the colour variables, so they silently ran on
  private copies that had drifted: prints went to stdout instead of stderr,
  colour escapes were emitted unconditionally (leaking ANSI into redirected
  output and log files), `log()` had no guard for an unwritable log directory,
  and hardcoded `WG_CONFIG_DIR` / `LOG_FILE` assignments defeated the
  environment overrides in `utils.sh` — which is why these two scripts could
  not be driven against a throwaway config dir the way the rest of the suite
  can. The duplicates are gone; `reset.sh` keeps its own
  `/var/log/wireguard-reset.log` default, and `setup.sh` keeps its narrating
  `check_root()` as a deliberate, documented override.
- **One `peer_select()` in `utils.sh` replaces three near-identical
  implementations** in `remove-peer.sh`, `toggle-peer.sh` and `rotate-keys.sh`.
  It handles both the `-n/--name` preselect path and the numbered menu, emits
  the chosen name on stdout with all prompts on stderr, and takes an optional
  annotator function so `toggle-peer.sh` can still show `[enabled]` /
  `[disabled]` beside each peer. `toggle-peer.sh` also stops re-implementing
  `peer_list()` with its own `grep`. Peer-not-found and empty-config messages
  are now identical across the three scripts and mention the marker format.
- **Standardized audit log schema across every script.** `log-connections.sh`
  previously bypassed `log_audit()` and emitted its own shape (bare
  `CONNECT ...`, key `iface=`, no `user`/`source_ip`) under its own tag, so an
  auditor had to learn two formats. All records now route through one emitter
  in `utils.sh` and share the form
  `action=<VERB> [user= source_ip=] <k=v> ...`, with `WG_SCHEMA=1` marking the
  version. **Breaking for saved queries:** connection events now read
  `action=CONNECT` (was `CONNECT`) and `interface=` (was `iface=`).
- Every audit record now also carries **indexed journald fields** — `WG_ACTION`
  for the verb and `WG_<KEY>` per `k=v` pair — so auditing is a field query
  (`journalctl WG_PEER=alice --since -30d`) instead of a grep. Messages stay
  human-readable, and hosts whose `logger` lacks `--journald` fall back to the
  previous plain tagged line rather than losing the record.

### Fixed
- `unit_install_service()` checked the source file's existence before
  validating the repo path, so a path containing `#` (which breaks the `sed`
  delimiter used for unit rewriting) reported a misleading "missing file"
  error instead of the real cause. Caught by `test-installers.sh`.
- The shipped journal retention drop-in paired `MaxRetentionSec=6year` with
  `SystemMaxUse=2G`. Since size wins over age, that silently capped the audit
  trail at roughly two years on a typical host — well short of the six-year
  window it advertised. Raised to 8G, and `--check-retention` now verifies the
  figure per host rather than asking anyone to trust it.
- `log-connections.sh`: a peer deleted from the config while connected left a
  `CONNECT` with no matching `DISCONNECT`, dangling forever — removed peers
  are now swept and closed with `reason=peer-removed`.
- `log-connections.sh`: a failed `wg show` dump truncated the state file,
  which discarded every open session and re-logged the whole peer set as fresh
  `CONNECT`s on the next successful poll. A failed dump now leaves state
  untouched and logs nothing.
- `test-monitoring.sh`: the connect counter matched a substring that
  `DISCONNECT` also contains, so disconnects were counted as connects. It now
  counts via indexed journald fields.
- Initial public release preparation
- Standard open source project files (LICENSE, CONTRIBUTING, SECURITY, etc.)
- `healthcheck.sh`: optional **upstream reachability check** for site/client
  boxes. After the interface and firewall are confirmed healthy, it pings the
  upstream server's in-tunnel IP *through* the tunnel and restarts `wg-quick`
  once the target is unreachable for `--fail-threshold` consecutive checks
  (default 3; streak persisted per interface, cleared by any good check, and
  reset after a non-recovering restart so it backs off instead of looping).
  Enabled **per interface** by a `# Healthcheck-Reachability = <target>` comment
  in that interface's `<iface>.conf`, so the main hub (no such line) is never
  pinged or restarted on reachability. The target may be several IPs and/or
  hostnames (comma/space separated, or multiple lines); the tunnel counts as
  alive if any one answers. Targets are validated (IPv4/IPv6/hostname): a
  malformed entry is logged and ignored instead of being treated as
  unreachable, and an all-invalid comment is flagged as misconfigured without
  ever restarting the tunnel. `--ping-target` overrides for manual runs.
- **`test-monitoring.sh`**: live, on-box integration test for `healthcheck.sh`
  and `log-connections.sh`. Stands up isolated throwaway interfaces (the logger
  peer runs in its own network namespace so a real handshake can occur),
  exercises every code path against real kernel/systemd/wg/journald state, and
  tears everything down via an `EXIT` trap. Never touches production interfaces.
- `log-connections.sh`: `-i <iface>` to log a single interface, plus
  `WIREGUARD_CONN_STATE_DIR` / `WIREGUARD_CONN_ACTIVE_WITHIN` env overrides
  (used by the integration test; defaults unchanged).

### Fixed
- `log-connections.sh`: peers were never recorded as connected — the code
  compared the absolute `latest handshake` unix timestamp against the
  180-second activity window instead of `now - handshake`, so no `CONNECT`
  event was ever emitted. Now compares elapsed time correctly.
- `log-connections.sh`: connect/disconnect diff never matched across runs
  because the state file used `=` as its key/value separator, but base64
  public keys end in `=` padding — keys were truncated on read, producing
  duplicate `CONNECT`s and suppressing `DISCONNECT`s. Switched to a tab
  separator.

### Changed
- **Code Consolidation**: Merged `rotate-keys-client.sh` and `rotate-keys-server.sh` into unified `rotate-keys.sh`
  - 62% code reduction (1126 lines → 429 lines)
  - Interactive menu for selecting server or peer rotation
  - Maintains all functionality from both previous scripts
  - Updated menu.sh to reflect single key rotation option

## [2.0.0] - 2025-10-23

### Added
- **Interactive Menu System** (`menu.sh`)
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
  - `show-qr.sh` - Display client configs as QR codes for mobile devices
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
