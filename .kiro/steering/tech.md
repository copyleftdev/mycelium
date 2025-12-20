# Technology Stack

## Language & Toolchain

- **Language**: Rust (stable channel)
- **Build System**: Cargo workspace with multiple crates
- **Minimum Rust Version**: TBD (will be pinned in rust-toolchain.toml)

## Crate Architecture

The project is organized as a Cargo workspace with focused, single-responsibility crates:

```
mycelium/
├── crates/myc-crypto/      # Pure cryptographic operations (no I/O)
├── crates/myc-core/        # Domain types and business logic
├── crates/myc-github/      # GitHub API client and OAuth
├── crates/myc-cli/         # CLI binary (composition root)
└── crates/myc-test-utils/  # Shared test utilities
```

**Dependency Rules**:
- `myc-crypto` has zero dependencies on other workspace crates
- `myc-github` does NOT depend on `myc-crypto` (handles only ciphertext bytes)
- `myc-core` does NOT perform I/O; all I/O is handled by CLI
- `myc-cli` is the composition root that wires everything together

## Core Dependencies

### Cryptography
- `chacha20poly1305` - AEAD encryption
- `x25519-dalek` - Key agreement
- `ed25519-dalek` - Signatures
- `hkdf` - Key derivation
- `sha2` - HKDF hash function
- `blake3` - Hash chains and checksums
- `argon2` - Key derivation for local storage
- `rand_core`, `getrandom` - Secure randomness
- `zeroize` - Secure memory clearing
- `secrecy` - Secret-holding wrapper types

### CLI & I/O
- `tokio` - Async runtime
- `clap` v4 - Argument parsing (derive macros)
- `dialoguer` - Interactive prompts
- `console` - Terminal styling
- `dirs` - Platform directories
- `tracing`, `tracing-subscriber` - Logging

### GitHub Integration
- `reqwest` - HTTP client (with rustls-tls)
- `octocrab` - GitHub API client
- `jsonwebtoken` - JWT validation for OIDC

### Serialization & Data
- `serde`, `serde_json` - Serialization
- `uuid` - Identifiers (v4)
- `time` - Timestamps
- `base64` - Encoding

### Error Handling
- `thiserror` - Typed errors in libraries
- `anyhow` - Error handling in CLI binary

### Testing
- `proptest` - Property-based testing

## Supply Chain Security

**Policy**: No unvetted crates. Prefer RustCrypto ecosystem, dalek, and well-audited foundational crates.

**CI Checks**:
- `cargo-vet` - All dependencies must be vetted or exempted with rationale
- `cargo-audit` - Block on known vulnerabilities
- `cargo-deny` - Block duplicate versions and unwanted licenses

## Common Commands

### Development
```bash
# Build all crates
cargo build --workspace

# Run all tests
cargo test --workspace

# Run tests with verbose output
cargo test --workspace -- --nocapture

# Run property-based tests with more iterations
cargo test --workspace -- --ignored

# Check formatting
cargo fmt --check

# Run linter
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

### Testing
```bash
# Run unit tests only
cargo test --lib

# Run integration tests
cargo test --test '*'

# Run specific test
cargo test test_name

# Run with release optimizations (for crypto benchmarks)
cargo test --release
```

### Supply Chain
```bash
# Audit dependencies for vulnerabilities
cargo audit

# Check licenses and duplicates
cargo deny check

# Vet dependencies (requires cargo-vet setup)
cargo vet
```

### Building Release Binary
```bash
# Build optimized binary
cargo build --release --bin myc

# Binary location
./target/release/myc
```

### Documentation
```bash
# Generate and open documentation
cargo doc --workspace --no-deps --open

# Check for missing docs
cargo doc --workspace --no-deps
```

## Coding Conventions

- **Formatting**: `rustfmt` with default settings (enforced in CI)
- **Linting**: `clippy` with `#![deny(clippy::all)]` in each crate root
- **Documentation**: All public items MUST have doc comments; `#![deny(missing_docs)]` in library crates
- **Error Handling**: 
  - Libraries use `thiserror` for typed errors; no panics except for impossible states
  - Binaries use `anyhow` for CLI; convert library errors at boundaries
- **Testing**:
  - Unit tests in `#[cfg(test)]` modules
  - Integration tests in `tests/` directory
  - Property tests using `proptest` for crypto and serialization
- **Unsafe Policy**: No unsafe in application code; audit any unsafe in dependencies

## GitHub Backend

All remote operations use GitHub API (not local Git/libgit2):
- **Authentication**: GitHub OAuth Device Flow
- **Storage**: Private GitHub repositories
- **CI Identity**: GitHub Actions OIDC tokens
- **API**: REST API v3 (5000 requests/hour authenticated)

## Cryptographic Primitives

- **AEAD**: ChaCha20-Poly1305 (12-byte nonce, 16-byte tag)
- **Key Agreement**: X25519 (ECDH)
- **Signatures**: Ed25519
- **KDF**: HKDF-SHA256
- **Hash Chains**: BLAKE3
- **Password Hashing**: Argon2id (for local key storage)

All secret key types implement `Zeroize` and `ZeroizeOnDrop`. Nonces are randomly generated per encryption and never reused.
