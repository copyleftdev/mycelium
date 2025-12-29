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

#### From Source
```bash
git clone https://github.com/copyleftdev/mycelium.git
cd mycelium
cargo build --release --bin myc
cp target/release/myc ~/.local/bin/
```

#### From Release (Coming Soon)
```bash
curl -L https://github.com/copyleftdev/mycelium/releases/latest/download/myc-linux-x64.tar.gz | tar xz
sudo mv myc /usr/local/bin/
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

### Common Issues

#### "Permission denied" errors
```bash
# Check your role in the project
myc share list my-app

# Verify device is enrolled and active
myc device list
```

#### "Failed to decrypt" errors
```bash
# Check if PDK rotation excluded your device
myc recovery status

# Re-enroll device if necessary
myc device enroll
```

#### GitHub API rate limits
```bash
# Check rate limit status
myc status

# Use caching to reduce API calls
myc cache status
```

#### Profile issues
```bash
# List profiles
myc profile list

# Switch to correct profile
myc profile use work-profile

# Check profile details
myc profile show
```

### Getting Help

1. **Check command help:**
   ```bash
   myc --help
   myc pull --help
   ```

2. **Enable verbose output:**
   ```bash
   myc -vv pull my-app production
   ```

3. **Check system status:**
   ```bash
   myc status
   ```

### Recovery Scenarios

#### Lost passphrase
If you forget your device passphrase but have recovery contacts:
1. Enroll new device with new passphrase
2. Request recovery from contacts
3. Revoke old device

#### Compromised device
If a device is compromised:
1. Immediately revoke the device: `myc device revoke <device-id>`
2. This triggers automatic PDK rotation
3. Compromised device can no longer decrypt new secrets

#### Lost access to GitHub
If you lose access to your GitHub account:
1. Contact organization admins
2. They can remove your old identity and add your new one
3. Use organization recovery keys if available

### Performance Tips

1. **Use local caching** (enabled by default)
2. **Batch operations** when possible
3. **Use specific versions** to avoid fetching latest metadata
4. **Clear cache** if experiencing issues: `myc cache clear`

## Advanced Usage

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