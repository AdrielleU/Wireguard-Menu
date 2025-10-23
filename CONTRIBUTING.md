# Contributing to WireGuard Menu

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Pull Request Process](#pull-request-process)
- [Issue Guidelines](#issue-guidelines)
- [Recognition](#recognition)

## Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

### Summary

- Be respectful and considerate
- Welcome newcomers and help them learn
- Accept constructive criticism gracefully
- Focus on what's best for the project and community
- Show empathy towards other community members

Please read the full [Code of Conduct](CODE_OF_CONDUCT.md) for detailed guidelines and enforcement procedures.

## How to Contribute

### Ways to Contribute

1. **Report Bugs**: Found a bug? Create an issue with detailed reproduction steps
2. **Suggest Features**: Have an idea? Open an issue to discuss it
3. **Improve Documentation**: Fix typos, clarify instructions, add examples
4. **Write Code**: Fix bugs, implement features, improve existing functionality
5. **Test**: Test on different Linux distributions and report results
6. **Review**: Review pull requests and provide constructive feedback

### Getting Started

1. **Fork the repository** (if hosted on GitHub/GitLab)
2. **Clone your fork** locally
3. **Create a branch** for your changes
4. **Make your changes** following our guidelines
5. **Test thoroughly** on supported platforms
6. **Submit a pull request** with clear description

## Development Setup

### Prerequisites

- Linux system (RHEL, CentOS, Rocky, AlmaLinux, Fedora, Ubuntu, or Debian)
- Bash 4.0 or higher
- Root/sudo access for testing
- Git for version control

### Setting Up Development Environment

```bash
# Clone the repository
git clone https://github.com/your-username/wireguard-menu.git
cd wireguard-menu

# Make scripts executable
chmod +x *.sh

# Create a test environment (recommended)
# Use a VM or container to avoid affecting your main system
```

### Testing Your Changes

Before submitting:

1. **Test on multiple distributions** if possible:
   - RHEL-based: Rocky Linux 9, AlmaLinux 9, or Fedora
   - Debian-based: Ubuntu 24.04 or Debian 12

2. **Test different scenarios**:
   - Fresh installation
   - Upgrading existing setup
   - Multiple servers on same host
   - Error conditions and edge cases

3. **Verify backward compatibility**: Ensure changes don't break existing setups

## Coding Standards

### Bash Script Guidelines

#### General Style

```bash
# Use set for error handling
set -euo pipefail

# Use meaningful variable names (UPPER_CASE for globals)
WG_CONFIG_DIR="/etc/wireguard"
CLIENT_NAME=""

# Use local variables in functions
function example_function() {
    local param="$1"
    local result=""
    # ...
}

# Add comments for complex logic
# This loop processes each client and updates configuration
for client in "${clients[@]}"; do
    # ...
done
```

#### Function Naming

- Use lowercase with underscores: `check_client_exists()`
- Use descriptive names: `get_next_available_ip()` not `get_ip()`
- Prefix utility functions: `print_error()`, `print_success()`

#### Error Handling

```bash
# Always check command success
if ! command -v wireguard &> /dev/null; then
    error_exit "WireGuard not found"
fi

# Use error_exit for fatal errors
error_exit() {
    print_error "$1"
    exit 1
}

# Validate user input
if [[ ! "$port" =~ ^[0-9]+$ ]]; then
    error_exit "Invalid port: $port"
fi
```

#### Output Formatting

```bash
# Use consistent color-coded output
print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[i]${NC} $1"
}
```

#### File Operations

```bash
# Always use absolute paths
config_file="${WG_CONFIG_DIR}/${WG_INTERFACE}.conf"

# Set proper permissions
chmod 600 "$private_key_file"

# Create backups before modifications
backup_file="${config_file}.backup.$(date +%Y%m%d_%H%M%S)"
cp "$config_file" "$backup_file"
```

### Documentation Standards

#### Script Headers

Every script should have:

```bash
#!/bin/bash
################################################################################
# Script Name
# Description: Brief description of what the script does
# Usage: ./script-name.sh [OPTIONS]
################################################################################
```

#### Function Comments

```bash
# Function: get_client_ip
# Description: Retrieves the IP address for a specific client
# Arguments:
#   $1 - client_name: Name of the client
# Returns:
#   Client IP address or empty string if not found
get_client_ip() {
    local client_name="$1"
    # ...
}
```

#### In-line Comments

- Explain **why**, not **what** (code shows what)
- Comment complex logic or non-obvious solutions
- Keep comments up-to-date with code changes

## Testing Guidelines

### Manual Testing Checklist

Before submitting a PR, test these scenarios:

#### For setup-wireguard.sh
- [ ] Fresh installation on RHEL-based system
- [ ] Fresh installation on Debian-based system
- [ ] Creating second server (different interface, port, network)
- [ ] Network conflict detection
- [ ] Port conflict detection
- [ ] Interface conflict detection
- [ ] Interactive mode with defaults
- [ ] Command-line arguments mode
- [ ] Mixed mode (some args, some prompts)

#### For add-client.sh
- [ ] Adding first client
- [ ] Adding multiple clients
- [ ] Auto IP suggestion works correctly
- [ ] Custom IP assignment
- [ ] Client name validation
- [ ] Duplicate client detection
- [ ] Hot reload (other clients stay connected)

#### For remove-client.sh
- [ ] Removing existing client
- [ ] Client removal from config
- [ ] Key file deletion
- [ ] Config file deletion
- [ ] Backup creation
- [ ] Hot reload

#### For other scripts
- Test similar scenarios appropriate to each script

### Test Results

Include test results in your PR:

```
Tested on:
- Rocky Linux 9.3 (kernel 5.14.0) - ✓ All tests passed
- Ubuntu 24.04 (kernel 6.8.0) - ✓ All tests passed
```

## Pull Request Process

### Before Submitting

1. **Update documentation** if adding features or changing behavior
2. **Test thoroughly** on at least one RHEL and one Debian-based distro
3. **Follow coding standards** outlined above
4. **Check for conflicts** with main branch
5. **Ensure scripts are executable**: `chmod +x *.sh`

### PR Description Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update
- [ ] Code refactoring

## Testing
- [ ] Tested on RHEL-based system (specify version)
- [ ] Tested on Debian-based system (specify version)
- [ ] All existing functionality still works
- [ ] New functionality works as expected

## Test Details
Describe your testing environment and results:
- OS: Rocky Linux 9.3
- Kernel: 5.14.0
- Test scenarios: (list what you tested)
- Results: All tests passed

## Checklist
- [ ] My code follows the project's coding standards
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have updated the documentation accordingly
- [ ] My changes generate no new warnings or errors
- [ ] I have tested on multiple Linux distributions
```

### Review Process

1. **Automated checks** (if configured): Linting, shellcheck
2. **Manual review**: Maintainers review code and test
3. **Feedback**: Address any requested changes
4. **Approval**: Once approved, PR will be merged
5. **Recognition**: You'll be added to CONTRIBUTORS.md

### Commit Messages

Use clear, descriptive commit messages:

```
Good examples:
- "Add client IP suggestion in add-client.sh"
- "Fix key conflict when creating multiple servers"
- "Update README with new menu system"

Bad examples:
- "Update"
- "Fix bug"
- "Changes"
```

Format:
```
Short summary (50 chars or less)

More detailed explanation if needed. Wrap at 72 characters.
Explain the problem this commit solves and why this approach.

- Bullet points are okay
- Use present tense: "Add feature" not "Added feature"
```

## Issue Guidelines

### Reporting Bugs

Use this template:

```markdown
**Description**
Clear description of the bug

**To Reproduce**
Steps to reproduce:
1. Run command '...'
2. Enter values '...'
3. See error

**Expected Behavior**
What you expected to happen

**Actual Behavior**
What actually happened

**Environment**
- OS: Rocky Linux 9.3
- Kernel: 5.14.0-522.el9.x86_64
- WireGuard version: 1.0.x
- Script version/commit: (if known)

**Error Messages**
```
Paste error messages here
```

**Additional Context**
Any other relevant information
```

### Suggesting Features

Use this template:

```markdown
**Problem Statement**
What problem does this feature solve?

**Proposed Solution**
How would you like it to work?

**Alternatives Considered**
What other solutions did you consider?

**Use Cases**
Who would use this and how?

**Additional Context**
Screenshots, examples, references
```

## Recognition

### Contributors

All contributors will be recognized in:

1. **CONTRIBUTORS.md**: Your name/handle and contribution
2. **Release notes**: Mentioned in relevant release notes
3. **Git history**: Your commits are permanent record

### Types of Contributions Recognized

- Code contributions (features, bug fixes)
- Documentation improvements
- Testing and bug reports
- Feature suggestions and design input
- Code reviews
- Community support

### Adding Yourself to CONTRIBUTORS.md

When submitting your first PR, add yourself to CONTRIBUTORS.md:

```markdown
## Contributors

- **Your Name** (@github-handle)
  - Description of contribution (e.g., "Added client status monitoring")
  - Date: 2025-01
```

## Questions?

- **General questions**: Open a discussion or issue
- **Security issues**: See SECURITY.md for responsible disclosure
- **Private inquiries**: Contact maintainers directly (if contact info available)

## License

By contributing, you agree that your contributions will be licensed under the MIT License (see LICENSE file).

---

**Thank you for contributing to WireGuard Menu!**

Your contributions help make WireGuard more accessible to everyone.
