# Security Policy

## Supported Versions

We actively support the latest version of WireGuard Management Scripts. Security updates are applied to the main branch.

| Version | Supported          |
| ------- | ------------------ |
| Latest  | :white_check_mark: |
| Older   | :x:                |

## Security Best Practices

### When Using These Scripts

1. **Run with appropriate privileges**
   - Only use `sudo` when necessary
   - Review scripts before running with elevated privileges
   - Never run untrusted modifications

2. **Protect your keys**
   - Server and client private keys are stored in `/etc/wireguard/`
   - These files have restrictive permissions (600) set automatically
   - Never share private keys
   - Rotate keys periodically using the provided rotation scripts

3. **Secure your server**
   - Keep your system updated
   - Use firewall rules (automatically configured by scripts)
   - Monitor client connections regularly
   - Remove unused clients promptly

4. **Client configuration distribution**
   - Use secure channels to distribute client configs (SCP, encrypted email, etc.)
   - Delete client configs from server after distribution
   - Use QR codes only in secure environments

5. **Regular maintenance**
   - Rotate server keys periodically (affects all clients)
   - Rotate individual client keys as needed
   - Review client list regularly
   - Monitor logs for suspicious activity

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please follow responsible disclosure practices:

### How to Report

1. **DO NOT** create a public GitHub issue for security vulnerabilities
2. **DO** report privately using one of these methods:
   - Create a private security advisory on GitHub (if repository is on GitHub)
   - Email the maintainers directly with details
   - Use encrypted communication when possible

### What to Include

Please provide the following information:

- **Type of vulnerability**: Authentication bypass, privilege escalation, information disclosure, etc.
- **Affected components**: Which script(s) and function(s)
- **Impact**: What an attacker could achieve
- **Steps to reproduce**: Clear reproduction steps
- **Proposed fix**: If you have suggestions (optional)
- **Your contact information**: For follow-up questions

### What to Expect

- **Initial Response**: Within 48 hours acknowledging receipt
- **Assessment**: Within 7 days with preliminary assessment
- **Fix Timeline**: Critical issues within 14 days, others within 30 days
- **Credit**: You will be credited in the security advisory (unless you prefer anonymity)

## Security Considerations by Component

### setup-wireguard.sh
- Creates server private keys with restrictive permissions
- Configures firewall rules
- Enables IP forwarding (required for VPN functionality)
- Handles SELinux contexts on RHEL systems

**Potential Risks:**
- IP forwarding enables routing (intended for VPN)
- Firewall rules allow NAT masquerading (intended for VPN)

### add-client.sh / remove-client.sh
- Manages client access to VPN
- Creates/removes client private keys
- Updates server configuration

**Potential Risks:**
- Unauthorized client addition could grant VPN access
- Improper client removal could leave orphaned keys

### rotate-keys.sh
- Regenerates encryption keys (server or peer)
- Requires elevated privileges

**Potential Risks:**
- Server key rotation disconnects all peers
- Peer key rotation disconnects that specific peer
- Old keys are permanently deleted

### list-peer.sh
- Lists all peers or views specific peer details
- Reads WireGuard interface status
- Shows peer connection information

**Potential Risks:**
- May expose peer IP addresses and connection metadata
- Read-only operation (safe)

### qr-show.sh
- Displays client configuration as QR code
- Contains sensitive private key information

**Potential Risks:**
- QR codes contain private keys
- Screen capture or shoulder-surfing could compromise keys
- Only use in secure, private environments

## Secure Deployment Checklist

- [ ] Run on updated Linux distribution
- [ ] Firewall is active and configured
- [ ] SELinux/AppArmor is enabled (if applicable)
- [ ] SSH access is secured (key-based auth, non-standard port)
- [ ] Regular system updates are applied
- [ ] Logs are monitored
- [ ] Unused clients are removed promptly
- [ ] Keys are rotated periodically
- [ ] Backups are secured and encrypted
- [ ] Access to `/etc/wireguard/` is restricted

## Known Security Limitations

1. **No built-in authentication for script execution**
   - Scripts rely on system-level access controls
   - Anyone with sudo can add/remove clients
   - Mitigation: Restrict sudo access appropriately

2. **Keys stored on filesystem**
   - Private keys are stored in `/etc/wireguard/`
   - Encrypted at rest only if filesystem encryption is used
   - Mitigation: Use filesystem encryption (LUKS, etc.)

3. **No audit logging within scripts**
   - System logs capture script execution
   - No detailed audit trail of client operations
   - Mitigation: Review system logs regularly

4. **Client config distribution is manual**
   - Scripts create configs but don't distribute them
   - Distribution security is user's responsibility
   - Mitigation: Use secure channels (SCP, encrypted methods)

## Security Updates

Security updates will be released as soon as possible after discovery and verification. Updates will be announced via:

- GitHub Security Advisories (if on GitHub)
- Git commit messages with `[SECURITY]` prefix
- Release notes

Subscribe to repository notifications to stay informed.

## Acknowledgments

We appreciate the security research community and will acknowledge reporters of valid security issues (unless they prefer to remain anonymous) in:

- Security advisories
- Release notes
- CONTRIBUTORS.md file

Thank you for helping keep WireGuard Management Scripts secure!
