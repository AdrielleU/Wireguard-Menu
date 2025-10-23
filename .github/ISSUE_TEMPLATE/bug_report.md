---
name: Bug Report
about: Report a bug to help us improve
title: '[BUG] '
labels: bug
assignees: ''
---

## Bug Description

A clear and concise description of what the bug is.

## To Reproduce

Steps to reproduce the behavior:

1. Run command '...'
2. Enter values '...'
3. See error '...'

## Expected Behavior

A clear and concise description of what you expected to happen.

## Actual Behavior

What actually happened.

## Environment

- **OS**: (e.g., Rocky Linux 9.3, Ubuntu 24.04)
- **Kernel Version**: (output of `uname -r`)
- **WireGuard Version**: (output of `wg --version`)
- **Script Version**: (git commit hash or version number)
- **Firewall**: (firewalld, ufw, iptables, nftables)

## Error Messages

```
Paste any error messages here
```

## Log Files

```
Paste relevant portions of /var/log/wireguard-setup.log here
```

## Configuration

<details>
<summary>Server Configuration (redact sensitive data)</summary>

```
Paste /etc/wireguard/wg0.conf here (remove private keys!)
```
</details>

## Additional Context

Add any other context about the problem here. Include:

- Is this a fresh installation or existing setup?
- Did this work before? When did it break?
- Have you made any system changes recently?
- Are there multiple WireGuard servers on this system?

## Possible Solution

(Optional) If you have an idea of what might fix this, describe it here.

## Screenshots

If applicable, add screenshots to help explain your problem.
