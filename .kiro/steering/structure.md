# Project Structure

## Repository Layout

```
mycelium/
├── Cargo.toml                    # Workspace root
├── Cargo.lock
├── rust-toolchain.toml           # Pin Rust version
├── deny.toml                     # cargo-deny config
├── .cargo/
│   └── config.toml              # Workspace-wide cargo settings
├── .github/
│   └── workflows/
│       └── ci.yml               # CI pipeline
├── crates/                      # All Rust code
│   ├── myc-crypto/              # Cryptographic primitives
│   ├── myc-core/                # Domain types and business logic
│   ├── myc-github/              # GitHub API client
│   ├── myc-cli/                 # CLI binary
│   └── myc-test-utils/          # Shared test utilities
├── rfcs/                        # Design documents (JSON)
├── diagrams/                    # Architecture diagrams (PNG)
├── scripts/                     # Utility scripts
│   ├── architecture_diagram.py
│   ├── requirements.txt
│   └── README.md
├── prd.json                     # Product requirements document
└── README.md
```

## Crate Organization

### myc-crypto/
Pure cryptographic operations with zero external I/O.

**Modules**:
- `aead` - ChaCha20-Poly1305 encryption/decryption
- `kex` - X25519 key exchange
- `sign` - Ed25519 signatures
- `kdf` - HKDF key derivation
- `hash` - BLAKE3 hashing and hash chains
- `random` - Secure random byte generation
- `error` - Crypto error types

**Key Types**:
- `AeadKey`, `Nonce`
- `X25519SecretKey`, `X25519PublicKey`, `SharedSecret`
- `Ed25519SecretKey`, `Ed25519PublicKey`, `Signature`
- `HashOutput`, `Hasher`

**Rules**:
- No dependencies on other workspace crates
- All secret keys implement `Zeroize` and `ZeroizeOnDrop`
- No logging or printing of key material
- All functions are pure (no I/O)

### myc-core/
Domain types, serialization, and business logic.

**Modules**:
- `ids` - Type-safe identifiers (OrgId, ProjectId, etc.)
- `org` - Organization types
- `project` - Project and membership types
- `secret_set` - Secret set and version types
- `device` - Device identity types
- `pdk` - PDK versioning and wrapping
- `policy` - Rotation policies
- `canonical` - Canonical JSON for signing
- `error` - Core error types

**Key Types**:
- `Org`, `OrgSettings`
- `Project`, `ProjectMember`, `Role`
- `SecretSet`, `SecretSetVersion`
- `Device`, `DeviceType`, `DeviceStatus`
- `PdkVersion`, `WrappedPdk`

**Rules**:
- Depends on `myc-crypto` for crypto types
- No I/O operations (all I/O injected or handled by CLI)
- All types have `schema_version` field for evolution
- Serialization via `serde` with JSON format

### myc-github/
GitHub API client and authentication.

**Modules**:
- `auth` - OAuth device flow
- `api` - GitHub REST API operations
- `oidc` - GitHub Actions OIDC validation
- `repo` - Repository operations
- `error` - GitHub error types

**Key Operations**:
- Read/write files via GitHub API
- OAuth authentication
- OIDC token validation
- Rate limit handling
- Conflict resolution (SHA-based optimistic concurrency)

**Rules**:
- Does NOT depend on `myc-crypto` (handles only ciphertext bytes)
- All operations are async (tokio)
- Handles GitHub API errors and rate limiting

### myc-cli/
CLI binary that orchestrates all components.

**Structure**:
- `main.rs` - Entry point, argument parsing
- `commands/` - Command implementations
- `profile.rs` - Profile management
- `output.rs` - Output formatting (human/JSON)
- `config.rs` - Configuration loading
- `error.rs` - CLI error handling

**Key Responsibilities**:
- Parse command-line arguments (clap)
- Load profiles and configuration
- Orchestrate crypto, core, and GitHub operations
- Format output (human-readable or JSON)
- Handle interactive prompts
- Manage local cache

**Rules**:
- Composition root for all dependencies
- Uses `anyhow` for error handling
- Converts library errors to user-friendly messages

### myc-test-utils/
Shared test utilities and fixtures.

**Contents**:
- Mock GitHub responses
- Test key generation helpers
- Fixture data builders
- Property test generators

## GitHub Vault Structure

When Mycelium creates a vault in a GitHub repository, it uses this structure:

```
<vault-repo>/
└── .mycelium/
    ├── vault.json                           # Vault metadata
    ├── devices/
    │   └── <device-id>.json                # Device records (pubkeys)
    ├── projects/
    │   └── <project-id>/
    │       ├── project.json                # Project metadata
    │       ├── members.json                # Membership and roles
    │       ├── pdk/
    │       │   └── v<N>.json              # PDK versions (wrapped keys)
    │       └── sets/
    │           └── <set-id>/
    │               ├── set.json           # Secret set metadata
    │               ├── v<N>.enc           # Encrypted secret data
    │               └── v<N>.meta.json     # Version metadata (hash, sig)
    └── audit/
        └── <YYYY-MM>/
            └── <event-id>.json            # Audit events
```

**Key Points**:
- All secret values are in `.enc` files (ciphertext only)
- Metadata is plaintext JSON but signed
- PDKs are wrapped (encrypted) to device public keys
- Structure is append-only for versions and audit logs

## Local Storage Structure

User's local configuration and cache:

```
~/.config/mycelium/
├── profiles/
│   └── <profile-name>/
│       ├── device_keys.enc              # Encrypted device keypair
│       ├── github_token.enc             # Encrypted OAuth token
│       ├── config.json                  # Profile configuration
│       └── cache/                       # Local cache
│           ├── devices/
│           ├── projects/
│           └── pdk/
└── global_config.json                   # Global settings
```

**Security**:
- Device keys encrypted at rest with Argon2id-derived key
- OAuth tokens encrypted
- Cache can be cleared with `myc cache clear`

## Documentation Structure

### RFCs (rfcs/)
Detailed design documents in JSON format:
- `rfc-0000-index.json` - Index of all RFCs
- `rfc-0001-project-structure.json` - Workspace and crate architecture
- `rfc-0002-crypto-primitives.json` - Cryptographic layer
- `rfc-0003-data-model.json` - Domain types and serialization
- `rfc-0004-device-identity.json` - Device keys and local storage
- `rfc-0005-github-backend.json` - GitHub integration
- `rfc-0006-envelope-encryption.json` - PDK lifecycle
- `rfc-0007-secret-set-encryption.json` - Secret encryption
- `rfc-0008-membership.json` - Access control
- `rfc-0009-rotation-revocation.json` - Key rotation
- `rfc-0010-cli-architecture.json` - CLI structure
- `rfc-0011-ci-headless.json` - GitHub Actions integration
- `rfc-0012-audit-integrity.json` - Audit logs
- `rfc-0013-key-recovery.json` - Recovery mechanisms
- `rfc-0014-cli-ux.json` - User experience

### Diagrams (diagrams/)
Architecture visualizations generated by Python scripts:
- `01_high_level_architecture.png` - System overview
- `02_envelope_encryption.png` - PDK wrapping
- `03_data_flow.png` - Pull/push operations
- `04_github_actions_oidc.png` - CI authentication
- `05_pdk_rotation.png` - Key rotation flow
- `06_repo_structure.png` - Vault layout

### Specs (.kiro/specs/mycelium-cli/)
Implementation specification:
- `README.md` - Spec overview
- `requirements.md` - Detailed requirements with acceptance criteria
- `design.md` - Architecture, components, 55 correctness properties
- `tasks.md` - 17 phases, 150+ implementation tasks

## File Naming Conventions

- **Rust files**: Snake case (`secret_set.rs`, `device_identity.rs`)
- **Types**: Pascal case (`SecretSet`, `DeviceId`)
- **Functions**: Snake case (`encrypt_secret`, `verify_signature`)
- **Constants**: Screaming snake case (`NONCE_SIZE`, `MAX_RETRIES`)
- **JSON files**: Kebab case (`vault.json`, `rfc-0001-project-structure.json`)
- **Directories**: Kebab case or snake case (`myc-crypto`, `secret_sets`)

## Import Organization

Within Rust files, organize imports:
1. Standard library (`std::*`)
2. External crates (alphabetical)
3. Workspace crates (`myc_crypto::*`, `myc_core::*`)
4. Local modules (`crate::*`, `super::*`, `self::*`)

Separate groups with blank lines.
