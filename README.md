# Mycelium

<p align="center">
  <img src="mycelium-logo/png/logo.png" alt="Mycelium Logo" width="200">
</p>

> A living, zero-knowledge secrets mesh
[![DeepScan grade](https://deepscan.io/api/teams/28760/projects/30879/branches/995004/badge/grade.svg)](https://deepscan.io/dashboard#view=project&tid=28760&pid=30879&bid=995004)

Mycelium is a CLI-only secrets management system that uses GitHub as its complete backend. GitHub stores only ciphertext—it never sees plaintext secrets. All cryptographic operations happen locally on the client.

## Status

🔧 **Core Implementation Complete - Glue Code Phase** 🔧

Mycelium has completed its core implementation including:
- ✅ Cryptographic primitives and envelope encryption
- ✅ Device identity and key management
- ✅ GitHub backend integration with OAuth and OIDC
- ✅ Secret set encryption and versioning
- ✅ Membership and access control
- ✅ Key rotation and revocation
- ✅ Audit logging with hash chains
- ✅ Import/export in multiple formats
- ✅ CLI with comprehensive commands
- ✅ Key recovery mechanisms
- ✅ Comprehensive property-based testing
- ✅ Network beacon telemetry system

**Currently working on**: Critical glue code to connect components (audit chain hash integration, vault metadata loading, signature verification).

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/copyleftdev/mycelium.git
cd mycelium

# Build the CLI
cargo build --release --bin myc

# Add to PATH (optional)
cp target/release/myc ~/.local/bin/
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
- `myc pull` - Pull secrets from a set
- `myc push` - Push secrets to a set  
- `myc run` - Run commands with secrets injected as environment variables

### Management
- `myc profile` - Manage profiles (add, list, use, remove, show)
- `myc org` - Manage organization (init, show, settings)
- `myc project` - Manage projects (create, list, show, delete)
- `myc set` - Manage secret sets (create, list, show, delete)

### Collaboration
- `myc share` - Manage project sharing (add, remove, list, set-role)
- `myc device` - Manage devices (list, show, enroll, revoke, approve)
- `myc recovery` - Manage key recovery (set-contacts, show-contacts, request, assist)

### Security
- `myc rotate` - Rotate project encryption keys
- `myc verify` - Verify vault integrity
- `myc audit` - Manage audit logs (list, show, export, note)

### Utilities
- `myc versions` - Manage secret set versions (list, show)
- `myc diff` - Compare secret set versions
- `myc status` - Show system status and information
- `myc cache` - Manage local cache (clear, status)
- `myc ci` - CI/CD integration commands
- `myc completions` - Generate shell completions
- `myc gitignore` - Add common secret file patterns to .gitignore

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

## Building

```bash
# Build all crates
cargo build --workspace

# Run tests
cargo test --workspace

# Check formatting
cargo fmt --check

# Run linter
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Build release binary
cargo build --release --bin myc
```

## Development

### Prerequisites

- Rust stable toolchain (see `rust-toolchain.toml`)
- cargo-audit: `cargo install cargo-audit`
- cargo-deny: `cargo install cargo-deny`
- cargo-vet: `cargo install cargo-vet`

### Running CI Checks Locally

```bash
# Format check
cargo fmt --check

# Clippy
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Tests
cargo test --workspace

# Security audit
cargo audit

# License and dependency checks
cargo deny check
```

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

## Supply Chain Security

All dependencies are vetted using cargo-vet. See `supply-chain/` for audit records.
