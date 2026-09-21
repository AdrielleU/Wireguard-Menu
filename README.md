# WireGuard Menu

Complete suite of automated CLI tools for deploying and managing WireGuard VPN servers on Linux.

## Start Here: Adopting a Config You Didn't Generate

**If you pasted a WireGuard config off a blog, a vendor portal, or the official
quick-start, it will connect fine and still be wrong for these tools.** A stock
config carries no comment telling this toolkit what the box *is*, so
`verify-config.sh` judges every config as a **server** by default. On a
site-to-site box that is the wrong standard, and the consequences are real:
`healthcheck.sh --restart` treats a server as never-restartable, so a site
tunnel that has silently died is never brought back — and the menu's Remove
Peer, Toggle Peer and Rotate Keys cannot see a peer block they have no markers
for.

Nothing below changes how WireGuard routes packets. It declares intent that a
`.conf` has no native field for, which is why it lives in comments.

### 1. Put the config where the tools look, with the right mode

```bash
sudo install -m 600 wg0.conf /etc/wireguard/wg0.conf
```

The name before `.conf` is the interface name (`wg0` → `wg0.conf`). Mode `600`
matters: the file holds a private key, and `verify-config.sh` warns on anything
looser.

### 2. Run the checker first, before changing anything

```bash
sudo ./verify-config.sh -i wg0
```

On an untouched config off the internet, expect roughly this:

```
== server config  (/etc/wireguard/wg0.conf) ==
  ok   structure is valid (one [Interface], well-formed Key = Value lines)
  ok   [Interface] has PrivateKey
  ok   [Interface] has Address
  warn [Interface] has no ListenPort (fine for a client config, not for a server)

== peer marker coverage ==
  FAIL 0/1 [Peer] blocks carry BEGIN_PEER markers — 1 peer(s) are invisible to
       Remove Peer, Toggle Peer and Rotate Keys

== healthcheck comments ==
  FAIL nothing declares what this box is: add '# Healthcheck-Role = server' to
       [Interface] on a server (never auto-restarted), or '# Healthcheck-Role =
       client' plus '# Healthcheck-Reachability = <upstream tunnel IP>' on a
       client or site box

2 error(s), 3 warning(s) across 1 interface(s)
```

Note the heading says **server config** — that is the misclassification, and it
is what produces most of the noise. Fixing step 3 fixes the heading too.

### 3. Declare what this box is — the one edit that is always required

Add **two comment lines** inside `[Interface]`. Which pair depends on the role,
and this is the only decision in this whole procedure that needs thought:

**A site-to-site endpoint** — a spoke, a branch box, anything that dials a far
end and should be revived automatically if the tunnel dies:

```ini
[Interface]
# Healthcheck-Role = site
# Healthcheck-Reachability = 10.10.0.1
```

`Healthcheck-Reachability` is **the far end's tunnel IP**, not this box's own
address and not a public IP — `healthcheck.sh` pings it *through* the tunnel to
prove traffic actually passes. Point it at your own address and the check
always succeeds while proving nothing; `verify-config.sh` warns when it catches
that.

**A box other sites depend on** — the listening end, which must never be
bounced out from under connected peers:

```ini
[Interface]
# Healthcheck-Role = server
```

`server` means *never auto-restart this tunnel*. Choose it for the hub even
when the hub is also one half of a site-to-site pair.

### 4. Wrap each peer in markers — required on a server, recommended everywhere

```ini
# BEGIN_PEER site-b
# Site: site-b
[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
AllowedIPs = 10.10.0.2/32, 192.168.50.0/24
# END_PEER site-b
```

The name after `BEGIN_PEER` is how the menu refers to that peer, and it must
match on the `END_PEER` line. The `# Site:` line records what the peer is
(`# Client:` and `# Peer-to-Peer:` are the other two).

On a box with `Role = server` this is an **error** if missing. On a box with
`Role = site` it is not checked at all — but add it anyway if you ever intend
to remove, pause or rotate that peer from the menu, because those actions find
peers only by marker.

### 5. Add `PersistentKeepalive` on the end that dials out

```ini
PersistentKeepalive = 25
```

Only on a peer block that has an `Endpoint`. Without it, the kernel gives up
retrying after ~90s of failed handshakes and the tunnel cannot recover on its
own — `verify-config.sh` warns about exactly this. The listening end does not
need it.

### 6. Re-run until it is clean

```bash
sudo ./verify-config.sh -i wg0
```

```
########  wg0  (site box)  ########

== site config  (/etc/wireguard/wg0.conf) ==
  ok   structure is valid (one [Interface], well-formed Key = Value lines)
  ok   [Interface] has PrivateKey
  ok   [Interface] has Address
  ok   mode 600 /etc/wireguard/wg0.conf

== site peers ==
  ok   [Peer] #1 (vpn.example.com:51820): Endpoint set, PersistentKeepalive = 25

== healthcheck comments ==
  ok   Healthcheck-Role = site
  ok   Healthcheck-Reachability: 10.10.0.1 — pinged through the tunnel

Config matches the expected format. (1 interface(s) checked)
```

The heading is now **site box** and the marker and key-directory checks are
gone — those apply to servers. It exits non-zero while any error remains, so it
works in a script: `verify-config.sh -i wg0 || exit 1`.

Not every warning must reach zero. A hub legitimately warns `no key directory`
when it was never used to hand out client configs. **Errors** are the bar.

### 7. Bring it up and hand it to the timers

```bash
sudo wg-quick up wg0
sudo systemctl enable wg-quick@wg0

sudo ./install.sh
```

Then confirm the timers are actually scheduled — `enabled` and `active` are not
sufficient, see [Verifying it's actually working](#verifying-its-actually-working):

```bash
systemctl list-timers 'wireguard-*'
```

A populated `NEXT` column means it is really running.

### 8. Run the check by hand before the timer does

```bash
sudo ./healthcheck.sh          # every interface; silent unless something is wrong
sudo ./healthcheck.sh -i wg0 -v   # itemize every check
```

`-v` ticks off each check individually, so you can see what actually passed:

```
[✓] wg0: 1/3 wg-quick@wg0 service is active
[✓] wg0: 2/3 kernel interface exists
[✓] wg0: 3/3 all 1 declared address(es) assigned to the interface
[✓] wg0: 4/4 reachability — 10.10.0.1 answered through the tunnel
[i] wg0: server-peer handshake is 58s old
[✓] wg0: healthy
  peers: 1/1 connected (handshake within 300s), 0 stale
```

A failing check ends the list rather than marking the rest — the checks after it
genuinely never run:

```
[✓] wg0: 1/3 wg-quick@wg0 service is active
[✓] wg0: 2/3 kernel interface exists
[!] wg0: address-missing:10.10.0.1/24
```

That third check is the one worth knowing about: it catches the wg-quick race
where the service reports success but the IP never reaches the interface.

**A bare run never restarts anything.** Restarting requires `--restart`, stated
explicitly — there is no flag that turns it on as a side effect. The run reports
what it found and exits non-zero if any interface is unhealthy, so it is safe to
run on a live box at any time.

The timer is what passes `--restart`. Whether that can bounce *this* tunnel was
decided back in step 3:

| `# Healthcheck-Role` | with `--restart` |
| -------------------- | ---------------- |
| `server` (or `hub`)  | **never restarted** — alerted on only |
| `site` / `client`    | restarted on a structural failure |
| **line absent**      | **treated as `client` — restarted** |

That last row is the one to check. **An unmarked config defaults to
restartable**, so a server that never got its marker is quietly enrolled in
auto-restart, and you find out when a false positive drops every connected peer.
`verify-config.sh` makes it an error rather than leaving it to be discovered
that way:

```
FAIL nothing declares what this box is: add '# Healthcheck-Role = server' to
     [Interface] on a server (never auto-restarted), or '# Healthcheck-Role =
     client' plus '# Healthcheck-Reachability = <upstream tunnel IP>' on a
     client or site box
```

So step 6 passing clean is what confirms the restart policy is the one you meant.

## Goal

Provide a comprehensive command-line interface for WireGuard server and client management that:
- Eliminates manual configuration complexity
- Works across multiple Linux distributions automatically
- Supports running multiple WireGuard servers on a single VM
- Includes comprehensive safety checks and conflict detection
- Provides easy client lifecycle management (add, remove, rotate keys)
- Makes WireGuard server management accessible through simple commands and an interactive menu

## Features

### Safety
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
sudo ./menu.sh
```

It does the work itself rather than launching other scripts:
- Peer Management (add, remove, pause/resume, list)
- Server Setup & Management (initial setup, rotate keys)

Every action ends by checking the config with `verify-config.sh`.

### Set up a server

```bash
sudo ./menu.sh      # then: 5) Setup WireGuard Server
```

You'll be prompted for the interface name (default `wg0`), listen port (default
`51820`) and server address (default `10.0.0.1/24`); press Enter to accept a
default. It generates the server keypair into `/etc/wireguard/<iface>/`, writes
`/etc/wireguard/<iface>.conf`, and checks the result with `verify-config.sh`.
The config gets a `# Healthcheck-Role = server` line, which is what stops
`healthcheck.sh` from ever auto-restarting it — see
[Never auto-restart the server](#never-auto-restart-the-server).
An existing config is never overwritten — it is checked instead. For another
server on the same box, pick a different interface, port and address (e.g.
`wg1`, `51821`, `10.0.1.1/24`).

Setup only writes the config and keys. Installing `wireguard-tools`, IP
forwarding and opening the UDP port are up to you — see
[Manual Setup](#manual-setup-no-scripts), steps 0, 6 and 7 — and then start it:

```bash
sudo systemctl enable --now wg-quick@wg0
```

### Add a peer

```bash
sudo ./menu.sh      # then: 1) Add Peer (Client)
```

It asks for the interface (if there are several), a peer name and a tunnel IP
(the next free one is suggested). It generates the peer's keypair into
`/etc/wireguard/<iface>/<name>-privatekey` and `-publickey`, adds the peer to
`<iface>.conf`, and if the interface is up, syncs it from the file with
`wg syncconf <iface> <(wg-quick strip <conf>)`, so connected peers stay up. It
adds client peers only (for site
peers, see [Multi-Site](#multi-site-hub-and-spoke-topology)) and does not write
the peer's own config file: build that from the private key and the server
public key it prints ([Manual Setup, step 8](#8-the-client-side)). Kept as
`/etc/wireguard/<iface>/<name>.conf`, Rotate Keys updates it for you.

### Remove a peer

```bash
sudo ./menu.sh      # then: 2) Remove Peer
```

Pick the peer and confirm. It deletes the peer's block from `<iface>.conf` —
everything from its `# BEGIN_PEER <name>` line through `# END_PEER <name>` —
along with its key files, backing the config up first. If the interface is up —
however it was started — it syncs it from the file (`wg syncconf` with
`wg-quick strip`), which drops just that peer; the others stay connected. It
always finishes by checking the config with `verify-config.sh`.

### Pause or resume a peer

```bash
sudo ./menu.sh      # then: 3) Toggle Peer (pause/resume)
```

The list shows each peer as `[active]` or `[paused]`; pick one and confirm.
Pausing comments out the peer's WireGuard lines with `#! `. If the interface is
up it is then synced from the file (`wg syncconf` with `wg-quick strip`), which
leaves the commented lines out and so drops the peer:

```
# BEGIN_PEER bob
# Client: bob
#! [Peer]
#! PublicKey = …
#! AllowedIPs = 10.0.0.3/32
# END_PEER bob
```

The markers stay, so the peer keeps its name and IP and stays paused across
restarts. Resuming uncomments the lines, and the same sync adds the peer back
with everything in its block — Endpoint, keepalive, preshared key. Both finish
by checking the config with `verify-config.sh`, which reports the peer as
`paused` and fails a block left half commented out.

### List peers

```bash
sudo ./menu.sh      # then: 4) List Peers (wg show all)
```

Runs `wg show all`: every interface with its peers, endpoints, last handshake
and transfer. It is the kernel's own view, so a paused peer is not in it —
`verify-config.sh` is what reports those as `paused`.

### Rotate keys

```bash
sudo ./menu.sh      # then: 6) Rotate Keys (server or peer)
```

Choose one peer's keys or the server's, and confirm. It backs up the config,
replaces the key files with a new keypair, and swaps the key where it sits in
the config — the peer's `PublicKey` in its block (paused peers included), or the
server's `PrivateKey` in `[Interface]`. If the interface is up it is synced from
the file, and the config is then checked with `verify-config.sh`.

- **Peer keys:** only that peer is cut off, until it has its new private key
  (`/etc/wireguard/<iface>/<name>-privatekey`).
- **Server keys:** every peer is cut off until its config has the new server
  public key, which is printed at the end.

Client configs kept as `/etc/wireguard/<iface>/<name>.conf` get the new key
automatically.

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
**Menu that does the work itself: server setup, adding, removing and pausing peers, and key rotation**

```bash
sudo ./menu.sh
```

See [Set up a server](#set-up-a-server), [Add a peer](#add-a-peer), [Remove a peer](#remove-a-peer), [Pause or resume a peer](#pause-or-resume-a-peer), [List peers](#list-peers) and [Rotate keys](#rotate-keys).

## Typical Workflows

### First-time Setup
1. Run server setup:
   ```bash
   sudo ./menu.sh      # 5) Setup WireGuard Server, then start wg-quick@wg0
   ```

2. Add your first peer:
   ```bash
   sudo ./menu.sh      # 1) Add Peer (Client)
   ```

3. Build the peer's client config ([Manual Setup, step 8](#8-the-client-side))
   from the private key and server public key Add Peer printed, and put it on
   the device.

### Daily Operations
Use the interactive menu for convenience:
```bash
sudo ./menu.sh
```

Add and remove peers with `sudo ./menu.sh` (options 1 and 2); *4) List
Peers* shows what the kernel has:
```bash
sudo wg show all
```

### Security Maintenance
Periodically rotate keys with `sudo ./menu.sh` → *6) Rotate Keys*: one peer
at a time, or the server's keys (which cuts off every peer until it has the new
server public key). See [Rotate keys](#rotate-keys).

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

On the hub server, run `sudo ./menu.sh` → *Setup WireGuard Server* with
interface `wg0`, port `51820` and address `10.0.0.1/24`. Then open UDP 51820,
put `wg0` in firewalld's `trusted` zone, enable IP forwarding, and start it:

```bash
sudo firewall-cmd --permanent --add-port=51820/udp
sudo firewall-cmd --permanent --zone=trusted --add-interface=wg0
sudo firewall-cmd --reload
sudo systemctl enable --now wg-quick@wg0
```

Forwarding is [Manual Setup, step 6](#6-forwarding-server-only). Hub-only
routing between sites does not need MASQUERADE.

### 2. Add each spoke as a `site` peer on the hub

Site peers route a whole LAN, so they are added by hand (`menu.sh`'s Add
Peer does client peers only). On the hub, generate each spoke's keypair:

```bash
cd /etc/wireguard/wg0
umask 077
wg genkey | tee siteB-privatekey | wg pubkey > siteB-publickey
wg genkey | tee siteC-privatekey | wg pubkey > siteC-publickey
```

Then append a block per spoke to `/etc/wireguard/wg0.conf`. Keep the
`BEGIN_PEER`/`END_PEER` markers — they are how Remove Peer, Toggle Peer and
`verify-config.sh` find the peer:

```ini
# BEGIN_PEER siteB
# Site: siteB
[Peer]
PublicKey = <contents of siteB-publickey>
AllowedIPs = 10.0.0.2/32, 192.168.20.0/24
# END_PEER siteB

# BEGIN_PEER siteC
# Site: siteC
[Peer]
PublicKey = <contents of siteC-publickey>
AllowedIPs = 10.0.0.3/32, 192.168.30.0/24
# END_PEER siteC
```

`AllowedIPs = <tunnel_ip>/32, <remote_lan>` tells the hub which traffic to push
into which tunnel. Restart (not reload) the hub, so `wg-quick` adds routes for
those LANs:

```bash
sudo systemctl restart wg-quick@wg0
```

### 3. Write each spoke's config so it can reach the *other* spoke's LAN

Each spoke's `/etc/wireguard/wg0.conf` holds its private key (`siteB-privatekey`
from step 2) and one `[Peer]` block for the hub, using the hub's
`/etc/wireguard/wg0/server-publickey`. To let Site B reach Site C (and vice
versa), that block's `AllowedIPs` lists the WG overlay plus the other spokes'
LANs.

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

With `wg0` in firewalld's `trusted` zone (step 1), firewalld permits
forwarding between interfaces in the same trusted zone by default — so no extra
rules are needed for `wg0 → wg0` spoke-to-spoke traffic. IP forwarding must be
enabled persistently ([Manual Setup, step 6](#6-forwarding-server-only)).

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

1. **On the hub**, generate `siteD`'s keys and add its block as in step 2, with
   `AllowedIPs = 10.0.0.4/32, 192.168.40.0/24`, then restart `wg-quick@wg0`.
2. **On Site D**, write its `wg0.conf` as in step 3, with `AllowedIPs` on the
   hub block listing every other spoke's LAN:
   `10.0.0.0/24, 192.168.20.0/24, 192.168.30.0/24`. Start the service.
3. **On every existing spoke (B, C)**, append `192.168.40.0/24` to the
   `AllowedIPs` line, then `systemctl restart wg-quick@wg0`.

That's the manual cost of full mesh-via-hub: each new spoke is one edit on
every existing spoke. Up to ~10 sites this stays manageable. Past that,
manage the spoke configs with Ansible (or similar) so a single re-run
pushes the new `AllowedIPs` everywhere.

## Firewall Support

Nothing here configures or checks the firewall: open the UDP port yourself
([Manual Setup, step 7](#7-open-the-firewall)).

## Security Features

- Restrictive file permissions (600) on configs and keys
- Keys generated under `umask 077`, so a private key is never briefly readable
- Server config backed up before each peer add or remove

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
Setup does not check for port conflicts, so `wg-quick@<iface>` fails to start.
Find what holds the port, then set a different `ListenPort` in
`/etc/wireguard/<iface>.conf`:
```bash
ss -ulnp | grep 51820
```

### Network conflicts
Setup does not check whether the address overlaps another interface's network.
Check with `ip -br addr` and pick a range nothing else uses (e.g. `10.0.1.1/24`)
when running setup.

## Project Structure

```
/etc/wireguard/scripts/
├── menu.sh                      # Menu that does the work itself: setup, peers, key rotation
├── healthcheck.sh                   # One-shot runtime health check (cron / systemd timer)
├── verify-config.sh                 # Config conformance check (does it match our format?)
├── log-connections.sh                # Connection logger for systemd journal
├── install.sh                          # Install/enable both timers, the trail's routing and its retention
├── systemd/
│   ├── wireguard-healthcheck.service       # Oneshot service for the healthcheck
│   ├── wireguard-healthcheck.timer         # Fires the service every 60s
│   ├── wireguard-log-connections.service   # Oneshot service for the connection logger
│   └── wireguard-log-connections.timer     # Fires the service every 2 min
├── utils.sh                         # Shared helpers (sourced by other scripts)
├── README.md                        # All user documentation (you are here)
├── CHANGELOG.md                     # Version history
├── LICENSE                          # MIT License
└── .gitignore                       # Git ignore patterns
```

## Running the tests

```bash
sudo ./wireguardmenu test          # every script's --dry-run (a few seconds)
sudo ./wireguardmenu test --help   # what it runs
```

Each script tests itself: `--dry-run` makes every check a real run would and
prints what it would do, but writes nothing.

| Dry run | Checks | Touches |
| ------- | ------ | ------- |
| `install.sh --dry-run` | both units' scripts exist and are executable, no cron entry double-runs them, plus the exact rsyslog and logrotate files it would write | nothing |
| `log-connections.sh --dry-run` | reads `wg show dump` and the state file, prints the connect/disconnect records it would write | nothing — no journal entries, no state file |

Two more need no flag, because they only read:

- **`verify-config.sh`** — running it *is* the check.
- **`healthcheck.sh` without `--restart`** — it reports what it finds and
  changes nothing. Add `-i <iface>` to look at one interface only.

## Manual Setup (no scripts)

Mirrors the official [WireGuard QuickStart](https://www.wireguard.com/quickstart/).
Read this section to understand what `menu.sh` does under the
hood — including the install, forwarding and firewall steps that setup
leaves to you — or to deploy WireGuard somewhere the scripts cannot run.

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
| Keys + conf | `sudo ./menu.sh` → Setup WireGuard Server |
| Add a `[Peer]` block (client peers; the client config is step 8) | `sudo ./menu.sh` → Add Peer |
| Remove a `[Peer]` block | `sudo ./menu.sh` → Remove Peer |
| Disable a peer without deleting it | `sudo ./menu.sh` → Toggle Peer |
| Inspect peers / handshakes | `sudo ./menu.sh` → List Peers (`wg show all`) |
| Rotate server or peer keys | `sudo ./menu.sh` → Rotate Keys |
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
sudo ./verify-config.sh --site       # check as a site box (spoke), not a server
```

Errors exit 1, warnings exit 0 unless `--strict`. `verify-config.sh` is
read-only — it never touches the running tunnel.

The check worth knowing about is **marker coverage**. Every peer block this
toolkit writes is wrapped in `# BEGIN_PEER <name>` / `# END_PEER <name>`, and
Remove Peer, Toggle Peer and Rotate Keys all find peers through those
markers. WireGuard itself does not care about them —
so a `[Peer]` block added by hand, or restored from a config written before the
marker format, will connect perfectly well while being **invisible to every
management script here**. `verify-config.sh` is the only thing that reports it:

```
FAIL 2/3 [Peer] blocks carry BEGIN_PEER markers — 1 peer(s) are invisible to Remove Peer, Toggle Peer and Rotate Keys
    unmarked peer, PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
    fix: re-add these with menu.sh (Add Peer), or wrap each block in
         '# BEGIN_PEER <name>' / '# END_PEER <name>' by hand
```

It also catches unterminated marker blocks, duplicate peer names, duplicate
`PublicKey` or `AllowedIPs` across peers, a `server-privatekey` that no longer
matches the config's `PrivateKey` (a rotation that half-completed), peer public
keys on disk that disagree with the server config, orphan peer `.conf` files,
and key material that is not mode 600. Paused peers are reported as `paused`,
and a block that is only *half* paused — some WireGuard lines commented out,
some not — is an error: `wg-quick strip` keeps comments, so WireGuard applies
the live lines to the `[Peer]` above, silently replacing that peer's key.

It also checks the two comment lines `healthcheck.sh` acts on, which nothing
else reports:

- **Neither line set** is an error: nothing says whether this is a server (never
  auto-restarted) or a client/site box, and the healthcheck falls back to
  treating it as a client — so `--restart` would bounce a server.
- **A server without `# Healthcheck-Role = server`** is an error, because
  `healthcheck.sh --restart` would bounce it on a structural failure and drop
  every peer.
- **A role value it doesn't know** (`= sever`) is an error; use `server`, `hub`,
  `client` or `site`.
- **`# Healthcheck-Reachability` targets** have to be valid IPs or hostnames — a
  typo is an error, since the healthcheck ignores it — and not the box's own
  address, which would never test the tunnel. A client/site box with no target
  gets a warning: only a dead service or a missing address is caught.

> Note: `wg-quick strip` is sometimes suggested as a config validator. It is
> not one — it is a filter that prints the config with comments removed, and it
> exits 0 on arbitrary garbage. `verify-config.sh` parses the structure itself.

### Site boxes

A spoke's config is not one these scripts wrote — one bare `[Peer]`, no
markers and no key directory — so the checks above would fail it on every run. Instead it is checked as a **site box**, for what such a box needs
to connect and heal itself:

- each `[Peer]` has `PublicKey`, `AllowedIPs`, and an `Endpoint` (or the box has
  a `ListenPort` and waits to be dialled)
- `PersistentKeepalive` is set — without it the tunnel cannot come back on its
  own after an outage
- there is a `# Healthcheck-Reachability` target for the healthcheck, it is a
  valid IP or hostname, and it is not this box's own address

An interface gets the site profile when its conf has a
`# Healthcheck-Reachability` line or `# Healthcheck-Role = site`, or when you
pass `--site`. `# Healthcheck-Role = server` always gets the full checks. The
header says which one ran:

```
########  wg0  (site box)  ########
```

## Health Check

`healthcheck.sh` is a one-shot probe — designed for cron or a systemd timer.
For each WireGuard interface it verifies:

1. `wg-quick@<iface>` service is active
2. the kernel interface exists
3. every `Address = …` declared in `<iface>.conf` is actually assigned to
   the interface — catches the wg-quick race where the service comes up
   "successfully" but the IP never makes it onto the interface
4. *(optional)* with a ping target configured, that the tunnel can actually
   reach the upstream server — see [Upstream reachability](#upstream-reachability-site--client-boxes).

If any check fails, `--restart` will `systemctl restart wg-quick@<iface>` and
re-verify. The firewall is not checked: nothing here configures it, so there is
nothing recorded to check it against.

```bash
sudo ./healthcheck.sh                # check all interfaces, exit 1 if any fail
sudo ./healthcheck.sh -i wg0         # check just wg0
sudo ./healthcheck.sh --restart      # auto-recover anything unhealthy
sudo ./healthcheck.sh -v             # verbose (also report healthy)
```

Exit codes: `0` = all healthy, `1` = at least one unhealthy and `--restart`
did not recover it. Failures and recoveries are also logged to the systemd
journal under the `wireguard` tag.

### The goal: set-and-forget stability

`healthcheck.sh` and the connection logger aim to make a WireGuard box
something you **configure once and trust to keep itself up** — not something
you babysit. The design choices all serve that:

- **Self-healing, not just alerting.** On a timer with `--restart`, the box
  detects *and repairs* the failure modes that leave a tunnel "up" but dead — a
  missing address after a wg-quick race, or (on a site box) a tunnel that no
  longer carries traffic. You don't get
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

The result is a small, dependency-free set of shell scripts that give you the
hands-off reliability you'd otherwise reach for a much heavier orchestration
stack to get — control over a WireGuard instance with minimal ongoing effort.

### Install as a systemd timer (recommended)

**One installer, two controls.** `install.sh` puts in both, because every real
deployment wants both — but they stay separable, since they answer to different
questions and you may want to enable, verify or report on them apart:

| Control | Answers | Installs | On its own |
| ------- | ------- | -------- | ---------- |
| Availability | is the tunnel up; restart it if not | `wireguard-healthcheck.{service,timer}` | `--healthcheck-only` |
| Audit | the connect/disconnect trail | `wireguard-log-connections.{service,timer}`, the rsyslog rule routing the trail to `/var/log/wireguard.log`, and its logrotate policy | `--logging-only` |

It rewrites each unit's `ExecStart`/`Documentation` to wherever this repo
actually lives, so you are not locked to a hardcoded path, and it is idempotent
— re-run after moving the repo or pulling changes:

```bash
sudo ./install.sh                     # install/refresh + enable both
sudo ./install.sh --dry-run           # show what that would do; change nothing
sudo ./install.sh --healthcheck-only  # availability control only
sudo ./install.sh --logging-only      # audit control only

sudo ./install.sh --check-retention   # what the trail actually holds
sudo ./install.sh --status            # timer state + record count + retention
sudo ./install.sh --uninstall         # stop, disable, remove units
```

> Don't `cp` the units by hand — the copies in `systemd/` carry a placeholder
> path (`/etc/wireguard/scripts/…`). Installing them verbatim gives you a timer
> that fires forever against a script that isn't there.

> **Remote site boxes** that don't carry this repo: copy the monitoring files
> across and run these installers there — see
> [Remote site boxes](#remote-site-boxes-monitoring-only).

The healthcheck runs **every 60s**; the connection logger every 2 min. Both
units set `LogLevelMax=notice`, which keeps systemd's per-run
"Starting/Finished/Deactivated" lines out of the journal — at those intervals
they come to ~6,500 lines a day, far more than the records the units exist to
write. `SyslogLevel=notice` keeps what the scripts themselves print, and the
audit records are notice level, so both survive the filter. Both
installers, and `healthcheck.sh` itself, need a host running systemd and stop
straight away without it. Each install prints the units it wrote and says when
systemd was reloaded and the timer enabled and started, then warns if the timer
ends up with nothing scheduled.

### Verifying it's actually working

Four layers, each answering a different question. All four matter — the first
two can read perfectly green while the thing is doing nothing useful:

```bash
# 1. Armed, and will it survive a reboot?  ("enabled" is the one that matters)
systemctl is-enabled wireguard-healthcheck.timer
systemctl is-active  wireguard-healthcheck.timer
systemctl list-timers 'wireguard-*' --all      # NEXT must be a time, not "-"

# 2. Is the service succeeding, not just firing?
systemctl status wireguard-healthcheck.service
journalctl -u wireguard-healthcheck.service --since -1h

# 3. Is it actually DECIDING anything? (the layer people skip)
journalctl -t wireguard --since -24h
journalctl -t wireguard -f          # live, during an incident

# 4. End-to-end proof on demand
sudo ./healthcheck.sh -v                  # every check, changes nothing
sudo ./log-connections.sh --dry-run       # the records it would write
```

Two things that look like problems but aren't, and three that look fine but aren't:

* The service is `Type=oneshot`, so its healthy steady state is
  **`inactive (dead)` with `status=0/SUCCESS`**. That is correct, not a failure.
* **An empty unit journal is also healthy.** `journalctl -u
  wireguard-healthcheck.service` shows nothing for a clean run, because the unit
  filters systemd's per-run chatter (see above). Failures, the scripts' own
  output, and every audit record still land — check
  `journalctl -t wireguard`.
* **Silence under `wireguard` is NOT healthy.** Each interface logs a
  `HEALTHCHECK_OK` heartbeat every ~50 min, so the last hour always holds at
  least one record per interface:

  ```
  action=HEALTHCHECK_OK user=root source_ip=local interface=wg0 reach=ok peers=1/1
  ```

  `reach=skipped` means no `Healthcheck-Reachability` line, so only the
  structural checks ran. `journalctl -t wireguard --since -1h` coming back
  `-- No entries --` means the timer is not running, or it is running as a user
  who cannot read the system journal (use `sudo`). A box with no configs in
  `/etc/wireguard` logs `HEALTHCHECK_NO_INTERFACES` at the same rate.
  Set `HEARTBEAT_SECS` in the unit's environment to change the interval, or to
  `0` to turn it off.
* **A timer can be `enabled` and `active` and still never fire.** Check the
  `NEXT` column of `systemctl list-timers`: `-` means nothing is scheduled.
  Timers that start from `OnBootSec` are skipped for good when a slow boot
  starts them more than a minute in; these units use `OnActiveSec=1min`, so
  re-run the installers if yours still say `OnBootSec`. This went unnoticed for
  12 days on the development host.

  **But `NEXT -` has a harmless twin:** it also shows blank for the moment the
  service is actually running, because the next elapse is not computed until
  the run finishes. Tell them apart by `LAST` — recent means mid-run, days ago
  means dead.
* **Unit drift is the failure mode that hides best.** If the installed units
  fall out of sync with the repo, every layer above still reports green while
  the live cadence and paths are whatever you installed months ago:

```bash
for u in wireguard-healthcheck.{timer,service} wireguard-log-connections.{timer,service}; do
  diff -q "systemd/$u" "/etc/systemd/system/$u" >/dev/null || echo "DRIFT: $u"
done
```

(The `.service` files legitimately differ in their rewritten paths — re-running
`install.sh` is the fix either way.)

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
> intervenes. Put `PersistentKeepalive = 25` in every peer's own config — Add
> Peer does not write peer configs, so nothing sets it for you.

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
non-zero; watch with `journalctl -t wireguard -f`.

**This line is what protects the server.** Reachability being unset only stops
the *ping-based* restart path — the structural checks (service dead, interface
missing, address missing) run on every interface regardless and will restart an
unmarked server. Set the role explicitly — *Setup WireGuard Server* writes the
line into every config it creates, and `verify-config.sh` reports a server
without it as an error.

| | Server (`Role = server`) | Client / site |
|---|---|---|
| Detects + alerts | ✅ | ✅ |
| Restarts the tunnel | ❌ never | ✅ at 180s |
| Re-resolves endpoints | ❌ | ✅ at 120s |

## Connection Logging

`log-connections.sh` is a small one-shot poller that diffs `wg show dump`
against a state file and writes connect/disconnect events to the systemd
journal under the `wireguard` tag. Pair it with the included
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
journalctl -t wireguard -n 10               # see any events yet?
```

If `journalctl` is empty, that's normal — events are only logged on state
*changes*. To force every current peer to show as a fresh `CONNECT`, wipe
the state file and re-run:

```bash
sudo rm -rf /var/lib/wireguard-connections
sudo systemctl start wireguard-log-connections.service
journalctl -t wireguard -n 20
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
tail -f /var/log/wireguard.log        # the whole trail, one file
journalctl -t wireguard -f            # same records, structured and filterable
journalctl WG_ACTION=DISCONNECT       # query by indexed field
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

### Where the trail lives

Everything this toolkit logs — peer added/removed, keys rotated, healthcheck
failures, connect/disconnect — goes out under **one tag, `wireguard`, on
facility `local0`**, and lands in two places:

```bash
tail -f /var/log/wireguard.log     # the whole trail, one plain file
journalctl -t wireguard -f         # the same records, structured
journalctl WG_ACTION=PEER_REMOVED  # query by indexed field
```

`install.sh` writes the rsyslog rule that routes the tag to that file,
and the logrotate policy that decides how long it is kept. Both are generated
rather than shipped, so the log path and the retention window each have exactly
one source; `--dry-run` prints them in full before anything is written. The rule ends with
`stop`, so these records stay out of `/var/log/messages` — the file is the whole
trail, and the shared logs stay readable. journald keeps its own copy either
way, so `journalctl -t wireguard` works even if rsyslog is not installed.

One tag, not two: an earlier version split `wireguard-audit` (facility `auth`)
from `wireguard-connections` (`authpriv`), which scattered related records
across `/var/log/messages` and `/var/log/secure`, interleaved with sshd and
sudo. The `action=` field already distinguishes them. `local0` is the facility
range syslog reserves for custom applications; `auth`/`authpriv` belong to the
OS's own authentication services.

### Retention (HIPAA: 6 years)

**Retention is one number, in one file.** `install.sh` installs
`/etc/logrotate.d/wireguard`, and `rotate` decides the window:

```
/var/log/wireguard.log {
    weekly
    rotate 320        # 320 weeks = ~6.1 years
    compress
    delaycompress
    missingok
    notifempty
    create 0600 root root
}
```

Weeks are the unit, so `rotate 52` is a year and `rotate 320` is six. Check what
the host actually holds:

```bash
sudo ./install.sh --check-retention
```

```
== audit trail retention ==
  file      /var/log/wireguard.log 4.1MB including rotated copies
  keeping   weekly x 320           = ~2240 days
  writing   ~0.2MB/day             (measured over 21 days)
  needs     ~448MB                 to hold the full window
  target    2192 days

[✓] Rotation holds ~2240 days, past the 2192-day target.
```

It exits non-zero when the window is short of the target, so it can gate a
compliance check, and it names the `rotate` value that would fix it. The
`writing` and `needs` lines appear once something has rotated — before that
there is no honest way to measure a rate, and it says so rather than
extrapolating from one partial file.

**This used to be done with journald.** The drop-in set `SystemMaxUse=100T` and
`MaxRetentionSec=0` to stop journald evicting at its 4G default. It worked, but
it meant changing retention **for every service on the box** to solve a
WireGuard problem, and then reasoning about a free-disk ceiling, `SystemKeepFree`,
whether storage was persistent or volatile, and rsyslog's own separate copy —
four moving parts to answer a question logrotate answers exactly, for one file.
That drop-in is gone. If you installed an earlier version, remove the leftover:

```bash
rm /etc/systemd/journald.conf.d/journald-wireguard-audit.conf
systemctl restart systemd-journald
```

journald keeps its own copy of these records under whatever policy the host
already had, which is what `journalctl -t wireguard` reads. That copy is a
convenience; **the file is the trail.**

**Six years on a single box is optimistic whatever the number says.** Disks fail
and hosts get rebuilt. Treat the file as the local buffer and ship it to a
central log store if the trail genuinely has to outlive the machine — one path
to point a shipper at is exactly why the trail is one file.

### Config-change audit (separate tag)

`healthcheck.sh` is the only thing that writes to the `wireguard` tag now
(failures, restarts, recoveries), under the same `wireguard` tag as peer
activity — the `action=` field tells them apart. Nothing
done through `menu.sh` is logged.

```bash
journalctl -t wireguard                                  # admin actions
journalctl -t wireguard                                 # the whole timeline
```

## Remote Site Boxes (monitoring only)

A remote site-to-site box — a spoke in the
[hub-and-spoke layout](#multi-site-hub-and-spoke-topology), or either end of a
1:1 link — doesn't need the whole toolkit. It needs the two controls and the
config check:

| Files | For |
| ----- | --- |
| `healthcheck.sh` | Availability — restart the tunnel when it dies |
| `log-connections.sh` | Audit — the connect/disconnect trail |
| `install.sh` | Installs both, plus the trail's routing and retention |
| `verify-config.sh` | Is this box's config shaped right? |
| `utils.sh` | Sourced by all of the above |
| `systemd/` | The timer and service units |

The site box needs Linux with systemd and `wireguard-tools`, with the tunnel
running as `wg-quick@<iface>` — that is the service the healthcheck checks and
restarts.

### 0. Upgrading a box that already ran an earlier version

Do these in order. Step 3 is the one that is easy to forget, because nothing
fails without it — the old setting simply sits there unmanaged.

**1. Replace the scripts.** The file list is unchanged — the rsyslog rule and
logrotate policy are written by the installer, not shipped.

```bash
cd /etc/wireguard/scripts && git pull
```

or, copying from your workstation:

```bash
rsync -a healthcheck.sh log-connections.sh verify-config.sh \
         install.sh utils.sh systemd \
         root@site-b:/etc/wireguard/scripts/
```

**2. Re-run both installers.** They overwrite the units in place, and
`install.sh` adds the rsyslog rule and logrotate policy that the earlier
version did not have.

```bash
sudo /etc/wireguard/scripts/install.sh
```

**3. Remove the journald drop-in the old version installed.** Nothing manages it
any more, and left alone it keeps `SystemMaxUse=100T` applied to the whole host.

```bash
sudo rm -f /etc/systemd/journald.conf.d/journald-wireguard-audit.conf
sudo systemctl restart systemd-journald
```

**4. Check it took.**

```bash
sudo /etc/wireguard/scripts/install.sh --check-retention
systemctl list-timers 'wireguard-*'
sudo /etc/wireguard/scripts/verify-config.sh --all
tail /var/log/wireguard.log
```

`--check-retention` should report the file and `weekly x 320`, `NEXT` must show a
time for both timers, and `verify-config.sh` must report 0 errors. The log file
appears on the first record after step 2 — rsyslog polls the journal, so give it
a few seconds.

**What happens to records written before the upgrade.** They stay exactly where
they were, under the old tags: `journalctl -t wireguard-audit`,
`journalctl -t wireguard-connections`, and in `/var/log/messages` and
`/var/log/secure`. Nothing is migrated or deleted. New records use the single
`wireguard` tag and go to `/var/log/wireguard.log`, so for a while you will read
the old history and the new trail in different places.

**If journald was volatile on that host, it stays volatile.** The installer no
longer manages journald at all. That is no longer a data-loss problem, because
`/var/log/wireguard.log` is an ordinary file on disk and survives reboots on its
own — it only means `journalctl -t wireguard` shows records since the last boot.
If you want the structured view to persist too, that is now an ordinary host
decision, unrelated to this toolkit:

```bash
sudo mkdir -p /var/log/journal
sudo systemd-tmpfiles --create --prefix /var/log/journal
sudo systemctl restart systemd-journald && sudo journalctl --flush
```

### 1. Copy the files over

```bash
rsync -a healthcheck.sh log-connections.sh verify-config.sh \
         install.sh utils.sh systemd \
         root@site-b:/etc/wireguard/scripts/
```

`scp -r` does the same job, and a `tar` piped over `ssh` works where neither is
installed. Wherever you put them, the timers run these as root, so they must end
up root-owned, executable, and not writable by anyone else:

```bash
ssh root@site-b 'chown -R root:root /etc/wireguard/scripts &&
                 chmod 755 /etc/wireguard/scripts/*.sh'
```

### 2. Run the two installers there

```bash
ssh root@site-b '
  /etc/wireguard/scripts/install.sh
'
```

Each installer copies its own unit files out of `systemd/` into
`/etc/systemd/system/`, rewrites `ExecStart` to wherever you put the scripts,
reloads systemd, and enables and starts the timer. They stop straight away if
the host isn't running systemd, refuse to install a unit whose script is missing
or not executable, and warn if a timer ends up with nothing scheduled.

`install.sh` also installs the rsyslog rule that routes the trail to
`/var/log/wireguard.log` and the logrotate policy that decides how long it is
kept. Add `--dry-run` to either installer to see what it would do first.

Re-running them is also how you push an update after copying newer files: they
overwrite the units in place.

### 3. Check it took

```bash
ssh root@site-b '
  /etc/wireguard/scripts/verify-config.sh --all
  systemctl list-timers "wireguard-*"
'
```

`verify-config.sh` should report 0 errors, and it is what tells you whether this
box declares itself properly (see the next section). In `list-timers`, `NEXT`
must show a time — `-` means nothing is scheduled.

### Configure each site box — one line

Deployed as-is, the healthcheck catches structural failures only: a dead
service, a missing address. To also catch a tunnel that is up but passing no
traffic, give it the hub's in-tunnel IP in the `[Interface]` section of the
site box's `/etc/wireguard/wg0.conf`:

```ini
[Interface]
# Healthcheck-Reachability = 10.0.0.1
Address    = 10.0.0.2/24
PrivateKey = <SITE_B_PRIVATE_KEY>
```

No restart needed. The same line makes `verify-config.sh` check the box as a
[site box](#site-boxes). How the restart ladder then behaves is under
[Upstream reachability](#upstream-reachability-site--client-boxes).

If a remote box is itself a **server** that other peers dial into, mark it
`# Healthcheck-Role = server` instead, so the healthcheck never bounces it — see
[Never auto-restart the server](#never-auto-restart-the-server).

### Checking on a site box later

```bash
ssh root@site-b 'systemctl list-timers "wireguard-*"; /etc/wireguard/scripts/verify-config.sh --all'
ssh root@site-b 'journalctl -t wireguard --since -1h -o short-iso'
```

The logs live on each box, not on the machine you run `ssh` from. Expect at
least one `HEALTHCHECK_OK` per interface in that hour. If it prints
`-- No entries --`, the healthcheck timer on that box is not running.

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
