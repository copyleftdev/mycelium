# Mycelium User Guide

> A comprehensive guide to using Mycelium for zero-knowledge secrets management

## Table of Contents

1. [Getting Started](#getting-started)
2. [Core Concepts](#core-concepts)
3. [Common Workflows](#common-workflows)
4. [Team Collaboration](#team-collaboration)
5. [CI/CD Integration](#cicd-integration)
6. [Key Recovery](#key-recovery)
7. [Security Best Practices](#security-best-practices)
8. [Troubleshooting](#troubleshooting)

## Getting Started

### Installation

### Installation

#### From Release (Recommended)
```bash
# Linux x86_64
curl -L https://github.com/copyleftdev/mycelium/releases/latest/download/myc-linux-x64.tar.gz | tar xz
sudo mv myc /usr/local/bin/

# macOS x86_64
curl -L https://github.com/copyleftdev/mycelium/releases/latest/download/myc-macos-x64.tar.gz | tar xz
sudo mv myc /usr/local/bin/

# macOS ARM64 (Apple Silicon)
curl -L https://github.com/copyleftdev/mycelium/releases/latest/download/myc-macos-arm64.tar.gz | tar xz
sudo mv myc /usr/local/bin/

# Windows (PowerShell)
Invoke-WebRequest -Uri "https://github.com/copyleftdev/mycelium/releases/latest/download/myc-windows-x64.zip" -OutFile "myc.zip"
Expand-Archive -Path "myc.zip" -DestinationPath "."
# Move myc.exe to a directory in your PATH

# Verify installation
myc --version
```

#### From Source
```bash
# Prerequisites: Rust 1.70+ (see rust-toolchain.toml)
git clone https://github.com/copyleftdev/mycelium.git
cd mycelium

# Build optimized binary
cargo build --release --bin myc

# Install to system PATH
sudo cp target/release/myc /usr/local/bin/
# Or install to user PATH
cp target/release/myc ~/.local/bin/

# Verify installation
myc --version
```

#### Package Managers (Coming Soon)
```bash
# Homebrew (macOS/Linux)
brew install copyleftdev/tap/mycelium

# Cargo
cargo install myc-cli

# Arch Linux (AUR)
yay -S mycelium-cli
```

### First Steps

1. **Create your first profile:**
   ```bash
   myc profile add personal
   ```
   This will:
   - Generate Ed25519 and X25519 keypairs
   - Optionally encrypt them with a passphrase
   - Set up GitHub OAuth authentication

2. **Initialize a vault:**
   ```bash
   myc org init my-secrets-vault
   ```
   This creates a private GitHub repository to store your encrypted secrets.

3. **Create your first project:**
   ```bash
   myc project create my-app
   ```

4. **Add some secrets:**
   ```bash
   echo "DATABASE_URL=postgres://localhost/myapp" > .env
   echo "API_KEY=sk_test_123456789" >> .env
   myc push my-app production .env
   ```

5. **Pull secrets:**
   ```bash
   myc pull my-app production
   ```

## Core Concepts

### Profiles
Profiles manage different identities and vaults. Each profile has:
- A unique device keypair (Ed25519 + X25519)
- GitHub OAuth credentials
- Access to specific vaults

### Organizations (Vaults)
An organization represents a GitHub repository that stores encrypted secrets. Multiple teams can share the same vault.

### Projects
Projects group related secrets and define access control. Each project has:
- Members with roles (Owner, Admin, Member, Reader)
- Encryption keys (PDKs) that are rotated when members are removed
- Multiple secret sets

### Secret Sets
Secret sets are collections of key-value pairs (environment variables). Each set has:
- Versioned history
- Cryptographic integrity protection
- Support for multiple export formats

### Envelope Encryption
Mycelium uses envelope encryption for scalability:
- Each project has a Project Data Key (PDK)
- PDKs are wrapped (encrypted) to each member's device keys
- Secrets are encrypted with the PDK
- When members are removed, only the PDK needs rotation

## Common Workflows

### Daily Development

1. **Pull secrets for development:**
   ```bash
   myc pull my-app development --format dotenv --output .env
   ```

2. **Run your application:**
   ```bash
   myc run my-app development -- npm start
   # or
   source .env && npm start
   ```

3. **Update secrets:**
   ```bash
   # Edit .env file
   myc push my-app development .env
   ```

### Project Configuration

Create a `.myc.yaml` file in your project root:

```yaml
vault: my-company-vault
project: my-app
set: development
export_format: dotenv
output_file: .env
```

Then use simplified commands:
```bash
myc pull          # Uses config defaults
myc push .env     # Uses config defaults
myc run -- npm start  # Uses config defaults
```

### Managing Multiple Environments

```bash
# Development secrets
myc push my-app development .env.development

# Staging secrets  
myc push my-app staging .env.staging

# Production secrets (restricted access)
myc push my-app production .env.production
```

### Version Management

```bash
# List versions
myc versions list my-app production

# Show specific version
myc versions show my-app production --version 5

# Compare versions
myc diff my-app production --from 4 --to 5

# Pull specific version
myc pull my-app production --version 4
```

## Team Collaboration

### Adding Team Members

1. **Member enrolls their device:**
   ```bash
   # New member creates profile
   myc profile add work-laptop
   ```

2. **Admin adds member to project:**
   ```bash
   myc share add my-app alice@company.com --role member
   ```

3. **Member can now access secrets:**
   ```bash
   myc pull my-app production
   ```

### Role-Based Access Control

- **Owner**: Full control, can transfer ownership
- **Admin**: Manage members, rotate keys, read/write secrets
- **Member**: Read and write secrets
- **Reader**: Read-only access to secrets

```bash
# Change member role
myc share set-role my-app alice@company.com --role admin

# Remove member (triggers key rotation)
myc share remove my-app alice@company.com

# List project members
myc share list my-app
```

### Key Rotation

```bash
# Manual rotation
myc rotate my-app --reason "quarterly-rotation" --note "Q4 2024 rotation"

# Emergency rotation
myc rotate my-app --reason "security-incident" --note "Suspected key compromise"
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Deploy
on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write  # Required for OIDC
      contents: read
    steps:
      - uses: actions/checkout@v4
      
      - name: Install Mycelium
        run: |
          curl -L https://github.com/copyleftdev/mycelium/releases/latest/download/myc-linux-x64.tar.gz | tar xz
          sudo mv myc /usr/local/bin/
      
      - name: Deploy with secrets
        run: |
          myc ci pull my-app production --format shell > secrets.env
          source secrets.env
          ./deploy.sh
        env:
          MYC_NON_INTERACTIVE: "1"
```

### CI Device Enrollment

1. **Admin enrolls CI device:**
   ```bash
   myc ci enroll my-app production \
     --repo my-org/my-app \
     --workflow deploy.yml \
     --environment production
   ```

2. **CI automatically authenticates via OIDC:**
   - No secrets stored in GitHub Actions
   - Authentication via GitHub's OIDC tokens
   - Scoped access to specific projects/sets

## Key Recovery

### Multi-Device Setup

Enroll multiple devices for redundancy:

```bash
# On laptop
myc profile add laptop

# On desktop  
myc profile add desktop

# On phone (for emergency access)
myc profile add phone
```

### Recovery Contacts

Set up trusted contacts who can help recover access:

```bash
# Set recovery contacts
myc recovery set-contacts alice@company.com bob@company.com

# View recovery status
myc recovery status
```

### Recovery Process

If you lose access to all devices:

1. **Enroll new device:**
   ```bash
   myc profile add new-laptop
   ```

2. **Request recovery:**
   ```bash
   myc recovery request --contact alice@company.com
   ```

3. **Contact assists recovery:**
   ```bash
   # Alice runs this command
   myc recovery assist charlie@company.com --device new-device-id
   ```

### Organization Recovery Keys

For enterprise scenarios, set up organization recovery:

```bash
# Generate organization recovery key (requires multiple admins)
myc recovery org-key generate --threshold 3 --shares 5

# Contribute recovery share (when needed)
myc recovery org-key contribute --user charlie@company.com
```

## Security Best Practices

### Device Security

1. **Use strong passphrases** for device key encryption
2. **Enroll multiple devices** for redundancy
3. **Revoke compromised devices** immediately:
   ```bash
   myc device revoke old-laptop-id
   ```

### Access Management

1. **Use least privilege** - assign minimal necessary roles
2. **Regular access reviews** - audit project membership
3. **Rotate keys regularly**:
   ```bash
   myc rotate my-app --reason "quarterly-rotation"
   ```

### Audit and Monitoring

1. **Review audit logs** regularly:
   ```bash
   myc audit list --project my-app --last 30d
   ```

2. **Verify vault integrity**:
   ```bash
   myc verify my-app --all-sets
   ```

3. **Export audit logs** for compliance:
   ```bash
   myc audit export --format csv --output audit-2024.csv
   ```

### Environment Separation

1. **Separate projects** for different environments
2. **Restrict production access** to essential personnel
3. **Use different vaults** for different security domains

## Troubleshooting

### Installation Issues

#### Binary Not Found
```bash
# Error: "myc: command not found"
# Check if binary is in PATH
which myc
echo $PATH

# Solutions:
# 1. Add to PATH in shell profile
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

# 2. Install to system directory
sudo cp myc /usr/local/bin/

# 3. Use full path
/path/to/myc --version
```

#### Permission Denied
```bash
# Error: "Permission denied" when running myc
# Solution: Make binary executable
chmod +x /path/to/myc

# Or if installed via curl/tar
chmod +x myc && sudo mv myc /usr/local/bin/
```

### Authentication Problems

#### GitHub Token Issues
```bash
# Error: "GITHUB_TOKEN environment variable not set"
# Solutions:

# 1. Set environment variable (temporary)
export GITHUB_TOKEN="ghp_your_token_here"

# 2. Add to shell profile (permanent)
echo 'export GITHUB_TOKEN="ghp_your_token_here"' >> ~/.bashrc
source ~/.bashrc

# 3. Use profile-based OAuth (recommended)
myc profile add work-profile
# Follow OAuth flow in browser
```

#### OAuth Flow Problems
```bash
# Error: "OAuth device flow failed"
# Solutions:

# 1. Check internet connection
curl -I https://github.com

# 2. Check GitHub status
curl -I https://api.github.com

# 3. Clear browser cache and retry
# 4. Use incognito/private browsing mode
# 5. Try different browser
```

#### Repository Access Denied
```bash
# Error: "Cannot access repository owner/repo"
# Solutions:

# 1. Check repository exists
curl -H "Authorization: token $GITHUB_TOKEN" \
  https://api.github.com/repos/owner/repo

# 2. Verify token permissions
# Token needs 'repo' scope for private repositories

# 3. Check if you're a collaborator
# Repository owner must add you as collaborator

# 4. Initialize new vault if needed
myc org init my-new-vault
```

### Device and Key Issues

#### Device Keys Not Found
```bash
# Error: "Device keys not found for profile 'name'"
# Solutions:

# 1. Re-enroll device
myc profile add profile-name

# 2. Check profile exists
myc profile list

# 3. Check key files exist
ls ~/.config/mycelium/profiles/profile-name/keys/

# 4. Use different profile
myc --profile other-profile command
```

#### Passphrase Problems
```bash
# Error: "Failed to decrypt device keys"
# Solutions:

# 1. Check passphrase is correct
# Try empty passphrase if none was set

# 2. Set environment variable for CI
export MYC_KEY_PASSPHRASE="your_passphrase"

# 3. Use non-interactive mode
export MYC_NON_INTERACTIVE=1
export MYC_KEY_PASSPHRASE=""

# 4. Re-enroll with new passphrase
myc profile remove old-profile
myc profile add new-profile
```

#### Multiple Device Issues
```bash
# Error: "Only one device enrolled"
# Solutions:

# 1. Enroll additional devices
myc device enroll laptop-backup

# 2. Set up recovery contacts
myc recovery set-contacts alice@company.com

# 3. Check recovery status
myc recovery status
```

### Vault and Project Issues

#### Vault Not Found
```bash
# Error: "This may not be a valid Mycelium vault"
# Solutions:

# 1. Initialize vault
myc org init organization-name

# 2. Check correct repository
myc profile show
# Verify github_owner and github_repo

# 3. Switch to correct profile
myc profile use correct-profile

# 4. Check repository structure
# Should contain .mycelium/ directory
```

#### Project Access Denied
```bash
# Error: "Permission denied: You need write permission"
# Solutions:

# 1. Check your role
myc share list project-name

# 2. Request access from admin
# Contact project owner or admin

# 3. Verify project exists
myc project list

# 4. Check correct profile
myc profile show
```

#### Secret Set Not Found
```bash
# Error: "Secret set not found"
# Solutions:

# 1. List available sets
myc set list project-name

# 2. Create secret set
myc set create project-name set-name

# 3. Check spelling and case
# Names are case-sensitive

# 4. Use set ID instead of name
myc versions list project-name set-id
```

### CI/CD Integration Issues

#### OIDC Token Problems
```bash
# Error: "OIDC token validation failed"
# Solutions:

# 1. Check GitHub Actions permissions
# Add to workflow:
permissions:
  id-token: write
  contents: read

# 2. Verify environment variables
echo $ACTIONS_ID_TOKEN_REQUEST_URL
echo $ACTIONS_ID_TOKEN_REQUEST_TOKEN

# 3. Check CI device enrollment
myc ci enroll ci-device --token $ACTIONS_ID_TOKEN

# 4. Verify repository/workflow match
# CI device must be enrolled for specific repo/workflow
```

#### Non-Interactive Mode Issues
```bash
# Error: "Cannot prompt in non-interactive mode"
# Solutions:

# 1. Set required environment variables
export MYC_NON_INTERACTIVE=1
export MYC_KEY_PASSPHRASE="passphrase"
export MYC_PROFILE="ci-profile"

# 2. Use --force flag where available
myc command --force

# 3. Pre-configure via .myc.yaml
vault: my-vault
project: my-project
set: production
```

### Performance Issues

#### Slow Operations
```bash
# Symptoms: Commands take a long time
# Solutions:

# 1. Clear cache
myc cache clear

# 2. Check cache status
myc cache status

# 3. Check network connectivity
ping api.github.com

# 4. Use verbose mode to diagnose
myc -vv pull project set
```

#### Rate Limiting
```bash
# Error: "GitHub API rate limit exceeded"
# Solutions:

# 1. Check rate limit status
myc status

# 2. Wait for reset (shown in status)
# Rate limits reset every hour

# 3. Use authenticated requests
# Authenticated: 5000/hour vs unauthenticated: 60/hour

# 4. Reduce API calls
# Use caching, avoid frequent operations
```

### Data Integrity Issues

#### Verification Failures
```bash
# Error: "Integrity verification failed"
# Solutions:

# 1. Run comprehensive verification
myc verify --all-projects

# 2. Check specific components
myc verify project-name --signatures-only
myc verify project-name --chains-only

# 3. Check audit log integrity
myc audit verify-index

# 4. Report corruption
# If verification consistently fails, report to maintainers
```

#### Hash Chain Breaks
```bash
# Error: "Hash chain verification failed"
# Solutions:

# 1. Identify break point
myc audit list --project project-name

# 2. Check for tampering
# Hash chain breaks indicate potential tampering

# 3. Rebuild audit index
myc audit rebuild-index

# 4. Contact security team
# Report potential security incident
```

### Recovery Scenarios

#### Complete Device Loss
```bash
# Scenario: Lost all devices, no recovery contacts
# Solutions:

# 1. If you have GitHub access:
#    - Create new profile
#    - Contact project admins to add new device
#    - Remove old devices

# 2. If organization has recovery keys:
#    - Contact organization admins
#    - Request organization recovery process

# 3. Last resort:
#    - Create new vault
#    - Migrate secrets manually
#    - Update team access
```

#### Forgotten Passphrase
```bash
# Scenario: Can't decrypt device keys
# Solutions:

# 1. If you have other devices:
myc device list  # Check for other active devices
myc --profile other-device-profile device revoke old-device

# 2. If you have recovery contacts:
myc recovery request new-device-name
# Contact will receive recovery request

# 3. If organization recovery is set up:
# Contact organization admins for recovery
```

#### Corrupted Profile
```bash
# Scenario: Profile data corrupted
# Solutions:

# 1. Create new profile
myc profile add new-profile-name

# 2. Remove corrupted profile
myc profile remove corrupted-profile --force

# 3. Re-enroll device
# Follow normal enrollment process

# 4. Update project access
# Contact admins to add new device to projects
```

### Getting Additional Help

#### Enable Debug Output
```bash
# Basic verbose output
myc -v command

# More detailed output
myc -vv command

# Maximum verbosity
myc -vvv command

# JSON output for parsing
myc --json command | jq '.'
```

#### Collect Diagnostic Information
```bash
# System information
myc --version
myc status

# Profile information
myc profile list
myc profile show

# Recovery status
myc recovery status

# Cache information
myc cache status

# Environment variables (sanitize before sharing)
env | grep MYC
```

#### Community Resources
- **GitHub Issues**: [Report bugs](https://github.com/copyleftdev/mycelium/issues)
- **Discussions**: [Community Q&A](https://github.com/copyleftdev/mycelium/discussions)
- **Documentation**: [Complete user guide](https://github.com/copyleftdev/mycelium/blob/main/USER_GUIDE.md)
- **Security**: Email security@mycelium.dev for security issues

#### Before Reporting Issues
1. **Search existing issues** for similar problems
2. **Try latest version** - update if possible
3. **Collect logs** with verbose output
4. **Sanitize sensitive data** before sharing
5. **Provide minimal reproduction** steps

## Quick Reference

### Essential Commands
```bash
# Setup
myc profile add <name>              # Create profile and enroll device
myc org init <name>                 # Initialize vault in GitHub
myc project create <name>           # Create project
myc set create <project> <name>     # Create secret set

# Daily usage
myc pull <project> <set>            # Pull secrets
myc push <project> <set> <file>     # Push secrets
myc run <project> <set> -- <cmd>    # Run with secrets

# Team management
myc share add <proj> <user> --role <role>  # Add member
myc share list <project>            # List members
myc device list                     # List devices
myc rotate <project>                # Rotate keys

# Troubleshooting
myc status                          # System status
myc verify <project>                # Verify integrity
myc cache clear                     # Clear cache
myc -vv <command>                   # Verbose output
```

### Configuration File (.myc.yaml)
```yaml
# Place in project root for defaults
vault: my-company-vault
project: my-app
set: development
export_format: dotenv
output_file: .env
```

### Environment Variables
```bash
# Authentication
export GITHUB_TOKEN="ghp_..."
export MYC_KEY_PASSPHRASE="passphrase"

# CI/CD
export MYC_NON_INTERACTIVE=1
export MYC_PROFILE="ci-profile"

# Debugging
export RUST_LOG=debug
```

### Exit Codes
- `0` - Success
- `1` - General error
- `2` - Invalid arguments
- `3` - Authentication error
- `4` - Permission denied
- `5` - Cryptographic error
- `6` - Network error
- `7` - Conflict (concurrent modification)
- `8` - Not found
- `10` - User cancelled/non-interactive prompt

## Advanced Usage

### Shell Completions

Mycelium supports shell completions for bash, zsh, fish, elvish, and PowerShell:

```bash
# Generate completions for your shell
myc completions bash > ~/.local/share/bash-completion/completions/myc
myc completions zsh > ~/.zfunc/_myc
myc completions fish > ~/.config/fish/completions/myc.fish

# For bash (add to ~/.bashrc)
source ~/.local/share/bash-completion/completions/myc

# For zsh (add to ~/.zshrc)
fpath=(~/.zfunc $fpath)
autoload -U compinit && compinit

# For fish (completions auto-load from ~/.config/fish/completions/)
# No additional setup required

# Test completions
myc <TAB><TAB>  # Should show available commands
myc profile <TAB><TAB>  # Should show profile subcommands
```

### Custom Formats

Export secrets in different formats:

```bash
# Shell export format
myc pull my-app prod --format shell > exports.sh

# YAML format
myc pull my-app prod --format yaml > config.yaml

# JSON format  
myc pull my-app prod --format json > config.json
```

### Scripting and Automation

```bash
# Non-interactive mode (for scripts)
export MYC_NON_INTERACTIVE=1
export MYC_PROFILE=ci-profile

# JSON output for parsing
myc pull my-app prod --json | jq '.secrets.DATABASE_URL'

# Batch operations
for project in $(myc project list --json | jq -r '.projects[].name'); do
    myc rotate "$project" --reason "quarterly-rotation"
done

# Error handling in scripts
if ! myc pull my-app prod --quiet; then
    echo "Failed to pull secrets" >&2
    exit 1
fi
```

### Multiple Vaults

```bash
# Create profiles for different organizations
myc profile add personal-vault
myc profile add work-vault
myc profile add client-vault

# Switch between them
myc profile use work-vault
myc pull work-project production

myc profile use client-vault  
myc pull client-project staging
```

This guide covers the essential workflows and best practices for using Mycelium effectively. For more detailed information, see the CLI help (`myc --help`) and the technical documentation.