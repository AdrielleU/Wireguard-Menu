# Changelog

All notable changes to WireGuard Menu will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **`menu.sh` rewritten** — the menu does the work itself instead of launching a
  script per action, built on `utils.sh`. The actions are deliberately minimal.
  *Setup WireGuard Server* writes `<iface>.conf` and the server keypair
  (reusing existing keys) and marks it `# Healthcheck-Role = server` so the
  healthcheck never bounces it; an existing config is left alone and checked
  with `verify-config.sh` instead. *Add Peer* generates a client keypair and adds the
  peer to the config in the `BEGIN_PEER` format the peer scripts read. *Remove
  Peer* deletes the peer's block and key files. *Toggle Peer* pauses a peer —
  its WireGuard lines commented out with `#! ` — or resumes it. *Rotate Keys*
  gives one peer or the server a new keypair, swaps the key in the config
  (paused peers included) and updates client configs kept in `<iface>/`. *List
  Peers* runs `wg show all`. Each
  then syncs a running interface from the file with
  `wg syncconf <iface> <(wg-quick strip <conf>)`, however it was started, so
  unchanged peers stay connected. The strip runs on its own first: a strip that
  fails inside the pipe hands syncconf an empty config, which drops every peer
  and clears the private key. Remove, Toggle and Rotate finish with
  `verify-config.sh`. Each action runs in a subshell, so a failure returns to
  the menu.
- **`verify-config.sh` site-box profile.** A spoke's config — one bare
  `[Peer]`, no markers, no key directory, no manifest — failed marker coverage
  on every run, so the check was useless on exactly the boxes that now receive
  it. An interface with a `# Healthcheck-Reachability` line or
  `# Healthcheck-Role = site|client`, or any interface under `--site`, is now
  checked for what a site box needs instead: `Endpoint` (or `ListenPort`),
  `PersistentKeepalive`, and a reachability target, plus the manifest if one
  exists. `Role = server` still gets the full checks.
- **`--dry-run` on `install-healthcheck.sh` and `install-logging.sh`**, so the
  installers test themselves: every check a real run makes, but nothing
  written and no `systemctl`. The unit helpers in
  `utils.sh` now refuse to install a unit whose `ExecStart` script is missing or
  not executable, on real runs too — that is a timer firing forever against
  nothing. These replace the separate installer and verify-config test suites;
  `verify-config.sh` only reads, so running it is its own check.
- **`wireguardmenu test [--fast|--all]`** — one entry point for the suites,
  which previously had none. `--fast` (default) runs the installers' and the
  deploy's `--dry-run` in a few seconds; `--all` adds the live integration suite. The split is by system
  impact rather than by subject, since "does this create interfaces and drive
  systemd" is the thing worth knowing before running one. Exits non-zero if any
  suite fails, so it can gate a commit.
- `test-lib.sh` — the assertion harness (`section`, `pass`, `fail`, `assert_rc`,
  `assert_eq`, `assert_ge`, `assert_contains`, `assert_not_contains`,
  `test_summary`), previously copy-pasted byte-for-byte into all three test
  scripts along with three near-identical summary blocks. Kept out of `utils.sh`
  on purpose: every production script sources that, including two that run from
  systemd timers every 60s and 2min, and none of them should be carrying
  assertion helpers. It would also have shadowed `verify-config.sh`'s own
  `section()` — the same silent-override pattern just removed from `setup.sh`
  and `reset.sh`.

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
- **The timer units no longer fill the journal with their own start/stop
  lines.** A 60s healthcheck and a 2min logger made systemd write
  "Starting/Finished/Deactivated" on every run — 105,164 entries in 30 days on
  this host, against 2,700 from everything else combined, or roughly 3.5MB/day
  of journal that was almost entirely our own timers announcing themselves.
  Both units now set `LogLevelMax=notice`, which drops those (systemd logs them
  at info), with `SyslogLevel=notice` so the scripts' own output is kept, and
  `log_audit()` writes at `auth.notice` instead of `auth.info` — an info-level
  record survives that filter only sometimes, which is worse than never. A
  healthy healthcheck run now writes 0 journal lines instead of 2; failures,
  script output and every audit record still land. Connect/disconnect records
  were already written only on state change, so nothing there needed narrowing.
- **The setup manifest is gone.** Nothing had written one since `setup.sh` was
  removed, so `healthcheck.sh`'s firewall check was a no-op on every server
  built with `menu.sh`. Removed: `manifest_path/add/entries` from
  `utils.sh`, the firewall check and its auto-start of a stopped firewalld/ufw
  from `healthcheck.sh` (~90 lines), and the manifest section from
  `verify-config.sh`. On an old `setup.sh` box the healthcheck no longer
  notices a stopped firewall closing the UDP port.
- `verify-config.sh` now checks the two comment lines `healthcheck.sh` acts on,
  which nothing else reported: a config with neither line is an error (nothing
  says whether the box is a server or a client, and the healthcheck assumes
  client), a server missing `# Healthcheck-Role = server` is an error (without
  it `--restart` bounces the server on a structural failure, dropping every
  peer), a role value it does not know is an error, a reachability target that is not a valid IP or hostname is an
  error (the healthcheck silently ignores it), and a target that is the box's
  own address is flagged because pinging it never tests the tunnel.
  `looks_like_host()` moved from `healthcheck.sh` to `utils.sh` so both use one
  implementation.
- `healthcheck.sh`, `log-connections.sh`, `verify-config.sh` and `utils.sh` no
  longer name `menu.sh` in anything they print: they are deployed to remote
  boxes without it, where a message telling the operator to run it would be a
  dead end.
- `wireguardmenu test` runs each script's `--dry-run` rather than a suite list;
  `--fast` / `--all` are gone with the live suite.
- `verify-config.sh` reports a paused peer as `paused` instead of saying
  nothing, and fails a block that is only half paused — some WireGuard lines
  commented out, some not. `wg-quick strip` keeps comments, so WireGuard applies
  the live lines to the `[Peer]` above: in testing, a stray live `PublicKey`
  replaced the previous peer's key, and that peer disappeared while the stray
  key inherited its `AllowedIPs`.
- The installers say when systemd was reloaded and the timer enabled and
  started, rather than only naming the unit files, and warn when a timer ends up
  enabled and active with nothing scheduled.
- The installers and `healthcheck.sh` check that the host runs systemd
  (`/run/systemd/system`) and stop straight away if it does not. The installers
  also stop with an error when `systemctl daemon-reload`, `enable` or starting the timer
  fails, instead of printing success.
- `verify-config.sh` no longer warns about a peer without a client config
  (`<name>.conf`) or an interface without a setup manifest. Both warnings
  existed for `show-qr.sh` and `reset.sh`, and fired on every server set up by
  `menu.sh`. A manifest that does exist is still checked.
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
- **The healthcheck and connection-logger timers could stop running for good
  after a reboot.** They started from `OnBootSec=1min`, which counts from kernel
  boot. On a host whose boot took about 30 minutes to reach the timers, that
  trigger had already passed, and `OnUnitActiveSec` had no earlier run to count
  from, so nothing was ever scheduled again, while `systemctl` still showed both
  timers `enabled` and `active`. Found on a server where neither had run for 11
  days. They now use `OnActiveSec=1min`, which counts from when the timer
  starts. Re-run the installers to pick it up.
- `verify-config.sh` failed any config holding a peer disabled by
  `toggle-peer.sh`: the commented-out block made marker coverage report
  "2/1 … -1 peer(s) are invisible" and the block "no PublicKey, no AllowedIPs".
  Disabled and paused blocks (`#! ` lines) are now read through that prefix, and
  `peer_pubkey()` finds their key.
- `peer_remove()` and `peer_pubkey()` in `utils.sh` matched a peer's markers as
  a regex, and peer names may contain `.` — so removing `a.b` also deleted a
  peer named `axb`, and `peer_pubkey a.b` could return `axb`'s key (which
  `remove-peer.sh` then used to disconnect the live peer). Marker lines are now
  compared exactly.
- `unit_install_service()` checked the source file's existence before
  validating the repo path, so a path containing `#` (which breaks the `sed`
  delimiter used for unit rewriting) reported a misleading "missing file"
  error instead of the real cause.
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

### Removed
- **`setup.sh`.** Server setup is now *Setup WireGuard Server* in
  `menu.sh`, which only writes the config and keys. The rest of what
  `setup.sh` did is not done anywhere now: installing packages, IP forwarding,
  firewall rules, SELinux, the setup manifest (which `reset.sh` and the
  healthcheck's firewall check read), starting `wg-quick@<iface>`, importing a
  config (`--config`) and client mode (`--peer-of`). `wireguardmenu setup` opens the menu.
- **`add-peer.sh` and `remove-peer.sh`.** Adding and removing peers is now
  *Add Peer* / *Remove Peer* in `menu.sh`. Not carried over: site and p2p
  peers, the peer's own client config file (so `show-qr.sh` has nothing to show
  for a new peer until one is written by hand), the DNS, routing and keepalive
  options, non-interactive flags (`-i`, `-n`, …), and the `REMOVE_PEER` audit
  record `remove-peer.sh` wrote. `wireguardmenu add-peer` / `remove-peer` open the menu.
- **`toggle-peer.sh`.** Pausing and resuming a peer is now *Toggle Peer* in
  `menu.sh`, which comments a peer out with the same `#! ` prefix, so peers
  it disabled show as paused there. Not carried over: the non-interactive flags
  and the `TOGGLE_PEER` audit record. `wireguardmenu toggle-peer` opens the menu.
- **`rotate-keys.sh`.** Key rotation is now *Rotate Keys* in `menu.sh`. Not
  carried over: the `-s` / `-p` flags and the `KEY_ROTATION` audit record.
  `wireguardmenu rotate-keys` opens the menu.
- **`reset.sh`.** Nothing replaces it. Taking a server down — `wg-quick down`,
  then deleting its config and key directory — is manual, and the firewall
  rules, IP forwarding and packages an old `setup.sh` install set up are no
  longer undone by any script. Removed from the menu and `wireguardmenu`.
- **`show-qr.sh`.** Nothing writes peer client configs any more, so there was
  nothing for it to show. Removed from the menu and `wireguardmenu`, along with the `qr` alias.
- **`test-monitoring.sh` and `test-lib.sh`.** The live integration suite (62
  checks that stood up throwaway interfaces, a netns and veth pairs, and drove
  real systemd units against healthcheck.sh and log-connections.sh) and its
  assertion harness are gone, in favour of each script testing itself:
  `log-connections.sh` gains a `--dry-run` that prints the connect/disconnect
  records it would write without logging or writing state, joining the two
  installers' dry runs in `wireguardmenu test`.
  `healthcheck.sh` without `--restart` already reports without changing
  anything. What is no longer checked automatically is the healthcheck's
  recovery behaviour — the restart ladder, the WAN gate, the cooldown — and the
  logger's session and duration tracking.
- **The old `menu.sh`** — the menu that launched a script per action — is gone;
  the rewrite above took its name, and a bare `wireguardmenu` (or
  `wireguardmenu menu`) opens it. Not carried over: the interactive
  *Restart / Reload Server* action — `wg syncconf` already runs after every
  action in `menu.sh`, and an interface-level change still needs
  `sudo systemctl restart wg-quick@<iface>` by hand — and the `RELOAD` /
  `RESTART` audit records it wrote, which leaves `healthcheck.sh` as the only
  writer of the `wireguard-audit` tag.
- **`list-peers.sh`.** Listing is now *List Peers* in `menu.sh`, which runs
  `wg show all` — the kernel's own view, rather than a rendering of the config.
  Not carried over: the per-peer and detailed views, the type column, and the
  fallback listing of peers that have no markers. `wireguardmenu list-peers` opens the menu.

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
