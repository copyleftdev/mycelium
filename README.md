# Mycelium

<p align="center">
  <img src="mycelium-logo/png/logo.png" alt="Mycelium Logo" width="200">
</p>

> A living, zero-knowledge secrets mesh
[![DeepScan grade](https://deepscan.io/api/teams/28760/projects/30879/branches/995004/badge/grade.svg)](https://deepscan.io/dashboard#view=project&tid=28760&pid=30879&bid=995004)

Mycelium is a CLI-only secrets management system that uses GitHub as its complete backend. GitHub stores only ciphertext—it never sees plaintext secrets. All cryptographic operations happen locally on the client.

## Status

🚀 **Production Ready** 🚀

Mycelium is a fully functional, production-ready secrets management system with:
- ✅ Complete cryptographic primitives and envelope encryption
- ✅ Device identity and key management with passphrase protection
- ✅ GitHub backend integration with OAuth and OIDC authentication
- ✅ Secret set encryption, versioning, and integrity verification
- ✅ Role-based membership and access control
- ✅ Automatic key rotation and revocation with forward secrecy
- ✅ Cryptographically signed audit logging with hash chains
- ✅ Multi-format import/export (dotenv, JSON, shell, YAML)
- ✅ Comprehensive CLI with 60+ commands and subcommands
- ✅ Multi-device key recovery mechanisms
- ✅ GitHub Actions CI/CD integration via OIDC
- ✅ Extensive property-based testing (55+ correctness properties)
- ✅ Network beacon telemetry for ecosystem discovery
- ✅ Shell completions and project configuration files

**Ready for**: Production deployments, team collaboration, CI/CD integration.

## Quick Start

### Installation

#### From Release (Recommended)
```bash
# Download latest release for your platform
curl -L https://github.com/copyleftdev/mycelium/releases/latest/download/myc-linux-x64.tar.gz | tar xz
sudo mv myc /usr/local/bin/

# Or for macOS
curl -L https://github.com/copyleftdev/mycelium/releases/latest/download/myc-macos-x64.tar.gz | tar xz
sudo mv myc /usr/local/bin/

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

# Install to PATH
sudo cp target/release/myc /usr/local/bin/
# Or add to your local bin
cp target/release/myc ~/.local/bin/
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

### Getting Started

1. **Create your first profile:**
   ```bash
   myc profile add personal
   ```

2. **Initialize a vault in GitHub:**
   ```bash
   myc org init my-secrets-vault
   ```

3. **Create a project:**
   ```bash
   myc project create my-app
   ```

4. **Create and push secrets:**
   ```bash
   echo "API_KEY=secret123" > .env
   myc push my-app production .env
   ```

5. **Pull secrets:**
   ```bash
   myc pull my-app production
   ```

### Configuration

Create a `.myc.yaml` file in your project root:

```yaml
vault: my-secrets-vault
project: my-app
set: production
export_format: dotenv
output_file: .env
```

### GitHub Actions Integration

Mycelium supports zero-secret CI/CD using GitHub Actions OIDC:

```yaml
# .github/workflows/deploy.yml
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
      
      - name: Pull secrets and deploy
        run: |
          myc ci pull my-app production --format shell > secrets.env
          source secrets.env
          # Your deployment commands here
        env:
          MYC_NON_INTERACTIVE: "1"
```

No secrets stored in GitHub Actions - authentication happens via OIDC tokens!

## CLI Commands

### Core Operations
- `myc pull <project> <set>` - Pull secrets from a set
- `myc push <project> <set> <file>` - Push secrets to a set  
- `myc run <project> <set> -- <command>` - Run commands with secrets injected as environment variables

### Profile Management
- `myc profile add <name>` - Add a new profile with device enrollment
- `myc profile list` - List all profiles
- `myc profile use <name>` - Switch to a profile
- `myc profile remove <name>` - Remove a profile
- `myc profile show [name]` - Show profile details

### Organization & Vault Management
- `myc org init <name>` - Initialize a new vault in GitHub
- `myc org show` - Show organization details
- `myc org settings` - Manage organization settings

### Project & Secret Set Management
- `myc project create <name>` - Create a new project
- `myc project list` - List projects
- `myc project show <project>` - Show project details
- `myc project delete <project>` - Delete a project
- `myc set create <project> <name>` - Create a secret set
- `myc set list <project>` - List secret sets
- `myc set show <project> <set>` - Show secret set details
- `myc set delete <project> <set>` - Delete a secret set

### Team Collaboration
- `myc share add <project> <user> --role <role>` - Add member to project
- `myc share remove <project> <user>` - Remove member from project
- `myc share list <project>` - List project members
- `myc share set-role <project> <user> <role>` - Change member role

### Device Management
- `myc device list` - List devices
- `myc device show <device-id>` - Show device details
- `myc device enroll <name>` - Enroll a new device
- `myc device revoke <device-id>` - Revoke a device
- `myc device approve <device-id>` - Approve a pending device

### Key Recovery
- `myc recovery set-contacts <contacts...>` - Set recovery contacts
- `myc recovery show-contacts` - Show current recovery contacts
- `myc recovery status` - Show recovery status
- `myc recovery request <device-name>` - Request recovery assistance
- `myc recovery assist <request-id>` - Assist with recovery

### Security & Auditing
- `myc rotate <project>` - Rotate project encryption keys
- `myc verify [project] [set]` - Verify vault integrity
- `myc audit list` - List audit events
- `myc audit show <event-id>` - Show audit event details
- `myc audit export --format <format>` - Export audit logs
- `myc audit note <message>` - Add manual audit note

### Version Management
- `myc versions list <project> <set>` - List secret set versions
- `myc versions show <project> <set> <version>` - Show version details
- `myc diff <project> <set> <v1> <v2>` - Compare versions

### CI/CD Integration
- `myc ci enroll <name>` - Enroll CI device using OIDC
- `myc ci pull <project> <set>` - Pull secrets for CI (non-interactive)

### Utilities
- `myc status` - Show system status and information
- `myc cache clear` - Clear local cache
- `myc cache status` - Show cache status
- `myc completions <shell>` - Generate shell completions
- `myc gitignore` - Add secret file patterns to .gitignore

### Global Options
- `--profile <name>` - Use specific profile
- `--json` - Output in JSON format
- `--quiet` - Suppress non-essential output
- `--verbose` - Enable verbose output (use multiple times for more detail)
- `--no-color` - Disable colored output

## Features

- **Zero-knowledge storage**: Plaintext never leaves clients; GitHub sees only ciphertext
- **GitHub-native**: Leverages GitHub API, OAuth, Actions OIDC—no custom infrastructure
- **Instant adoption**: Anyone with a GitHub account can start immediately
- **Envelope encryption**: Scales to thousands of developers without N×secret re-encryption
- **Cryptographic integrity**: Signed mutations, verified reads, hash-chained audit logs
- **Native CI support**: GitHub Actions OIDC for zero-secret CI authentication
- **Multi-vault profiles**: Manage multiple vaults across GitHub accounts/orgs
- **Key recovery**: Multiple recovery mechanisms including recovery contacts and organization keys
- **Format support**: Import/export in dotenv, JSON, shell, and YAML formats
- **Comprehensive audit**: Immutable, signed audit logs with hash chain integrity
- **Ecosystem discovery**: Optional telemetry beacon for tracking adoption across GitHub (can be disabled)

## Architecture

The project is organized as a Cargo workspace with focused, single-responsibility crates:

```
mycelium/
├── crates/
│   ├── myc-crypto/      # Pure cryptographic operations (no I/O)
│   ├── myc-core/        # Domain types and business logic
│   ├── myc-github/      # GitHub API client and OAuth
│   ├── myc-cli/         # CLI binary (composition root)
│   └── myc-test-utils/  # Shared test utilities
```

### Cryptographic Primitives

- **AEAD**: ChaCha20-Poly1305 (12-byte nonce, 16-byte tag)
- **Key Agreement**: X25519 (ECDH)
- **Signatures**: Ed25519
- **KDF**: HKDF-SHA256
- **Hash Chains**: BLAKE3
- **Password Hashing**: Argon2id (for local key storage)

## Building from Source

### Prerequisites

- **Rust**: 1.70+ (automatically managed via `rust-toolchain.toml`)
- **Git**: For cloning the repository
- **GitHub Account**: For OAuth authentication and vault storage

### Development Tools (Optional)
```bash
# Security audit tools
cargo install cargo-audit cargo-deny cargo-vet

# Code quality tools  
cargo install cargo-clippy rustfmt

# Testing tools
cargo install cargo-nextest  # Faster test runner
```

### Build Process

```bash
# Clone repository
git clone https://github.com/copyleftdev/mycelium.git
cd mycelium

# Build all workspace crates
cargo build --workspace

# Build optimized release binary
cargo build --release --bin myc

# Run comprehensive test suite
cargo test --workspace

# Run property-based tests (may take longer)
cargo test --workspace --release -- --ignored

# Check code formatting
cargo fmt --check

# Run linter
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Security audit
cargo audit

# License and dependency checks
cargo deny check
```

### Common Build Issues

#### Rust Version Compatibility
```bash
# Error: "package requires Rust 1.70+"
# Solution: Update Rust toolchain
rustup update stable
rustup default stable

# Check version
rustc --version  # Should be 1.70+
```

#### Missing System Dependencies
```bash
# Linux: Install build essentials
sudo apt update && sudo apt install build-essential pkg-config libssl-dev

# macOS: Install Xcode command line tools
xcode-select --install

# Windows: Install Visual Studio Build Tools
# Download from: https://visualstudio.microsoft.com/visual-cpp-build-tools/
```

#### Compilation Errors
```bash
# Clean build artifacts
cargo clean

# Update dependencies
cargo update

# Build with verbose output
cargo build --verbose

# Check for conflicting global installations
cargo install --list | grep myc
```

### Development Workflow

```bash
# Run tests continuously during development
cargo watch -x "test --workspace"

# Run specific test
cargo test test_name

# Run with verbose output
cargo test --workspace -- --nocapture

# Generate documentation
cargo doc --workspace --no-deps --open

# Profile performance
cargo build --release --bin myc
perf record ./target/release/myc --help
```

## Troubleshooting

### Common Issues

#### Installation Problems
```bash
# Error: "myc: command not found"
# Solution: Ensure binary is in PATH
echo $PATH
which myc
# Add to ~/.bashrc or ~/.zshrc:
export PATH="$HOME/.local/bin:$PATH"
```

#### Authentication Issues
```bash
# Error: "GITHUB_TOKEN environment variable not set"
# Solution: Set up GitHub authentication
export GITHUB_TOKEN="your_github_token"
# Or run: myc profile add <name> to set up OAuth
```

#### Permission Errors
```bash
# Error: "Cannot access repository owner/repo"
# Solutions:
1. Check repository exists and is accessible
2. Verify GitHub token has 'repo' scope
3. Ensure you're a collaborator on private repos
4. Run: myc org init <name> to create a new vault
```

#### Device Key Issues
```bash
# Error: "Device keys not found for profile"
# Solution: Re-enroll device
myc profile add <profile-name>

# Error: "Failed to decrypt device keys"
# Solutions:
1. Check passphrase is correct
2. Set MYC_KEY_PASSPHRASE environment variable
3. Use empty passphrase if none was set during enrollment
```

#### Vault Access Problems
```bash
# Error: "This may not be a valid Mycelium vault"
# Solutions:
1. Initialize vault: myc org init <name>
2. Check you're using correct profile: myc profile list
3. Verify repository contains .mycelium/ directory
```

#### CI/CD Integration Issues
```bash
# Error: "OIDC token validation failed"
# Solutions:
1. Ensure GitHub Actions has id-token: write permission
2. Check workflow is running on correct repository
3. Verify CI device enrollment matches repository/workflow
4. Set MYC_NON_INTERACTIVE=1 for CI environments
```

### Performance Issues

#### Slow Operations
```bash
# Clear cache if operations are slow
myc cache clear

# Check cache status
myc cache status

# Use verbose mode to diagnose
myc -vv pull project set
```

#### Rate Limiting
```bash
# Check GitHub API rate limit status
myc status

# Wait for rate limit reset or use authenticated requests
# Rate limits: 5000/hour (authenticated), 60/hour (unauthenticated)
```

### Recovery Scenarios

#### Lost Device Access
```bash
# If you have recovery contacts set up:
1. Enroll new device: myc profile add recovery-device
2. Request recovery: myc recovery request new-device-name
3. Contact assists: myc recovery assist <request-id>

# If you have multiple devices:
1. Use another enrolled device
2. Revoke lost device: myc device revoke <device-id>
```

#### Forgotten Passphrase
```bash
# If you have other devices or recovery contacts:
1. Use another device to add new device
2. Set up recovery: myc recovery set-contacts user@example.com
3. Remove old device: myc device revoke <old-device-id>
```

#### Corrupted Vault
```bash
# Verify vault integrity
myc verify --all-projects

# Check audit log integrity
myc audit verify-index

# If corruption detected, contact repository administrators
```

### Getting Help

#### Enable Debug Output
```bash
# Verbose output (multiple levels)
myc -v command      # Basic verbose
myc -vv command     # More verbose  
myc -vvv command    # Maximum verbose

# JSON output for parsing
myc --json command | jq '.'
```

#### Check System Status
```bash
# Overall system status
myc status

# Profile information
myc profile show

# Recovery status
myc recovery status

# Cache status
myc cache status
```

#### Community Support
- **GitHub Issues**: [Report bugs and feature requests](https://github.com/copyleftdev/mycelium/issues)
- **Discussions**: [Community discussions and Q&A](https://github.com/copyleftdev/mycelium/discussions)
- **Security Issues**: Email security@mycelium.dev for security-related concerns



## Security Model

**Threat Model**: System remains secure even if GitHub is fully compromised. Attackers cannot decrypt secrets without authorized device keys.

**Cryptographic Guarantees**:
- Confidentiality: ChaCha20-Poly1305 AEAD encryption
- Integrity: Ed25519 signatures and BLAKE3 hash chains
- Authenticity: All mutations signed by device keys
- Forward Secrecy: PDK rotation on member removal

## Documentation

- [Product Overview](prd.json)
- [RFCs](rfcs/) - Detailed design documents
- [Architecture Diagrams](diagrams/)
- [Spec](.kiro/specs/mycelium-cli/) - Implementation specification
- [Network Beacon Documentation](docs/telemetry-breadcrumbs.md) - Ecosystem discovery system

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contributing

Contributions are welcome! Please ensure all CI checks pass before submitting a pull request.

### Development Setup

```bash
# Clone repository
git clone https://github.com/copyleftdev/mycelium.git
cd mycelium

# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Install development tools
cargo install cargo-audit cargo-deny cargo-vet
cargo install cargo-watch cargo-nextest

# Build and test
cargo build --workspace
cargo test --workspace
```

### Code Quality

```bash
# Format code
cargo fmt

# Run linter
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Security audit
cargo audit

# License and dependency checks
cargo deny check

# Run property-based tests
cargo test --workspace --release -- --ignored
```

### Submitting Changes

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes and add tests
4. Ensure all CI checks pass locally
5. Commit with descriptive messages
6. Push to your fork and create a pull request

### Reporting Issues

- **Bugs**: Use GitHub Issues with detailed reproduction steps
- **Security**: Email security@mycelium.dev for security vulnerabilities
- **Features**: Discuss in GitHub Discussions before implementing

## Supply Chain Security

All dependencies are vetted using cargo-vet. See `supply-chain/` for audit records.
