# Product Overview

## Mycelium (myc CLI)

**Tagline**: A living, zero-knowledge secrets mesh.

**What it is**: A CLI-only secrets management system that uses GitHub as its complete backend. GitHub stores only ciphertext—it never sees plaintext secrets. All cryptographic operations happen locally on the client.

**Core Value Proposition**: Teams can store, share, and rotate environment variables (secrets) across developers and CI/CD systems without trusting the cloud provider with plaintext. No servers to run, no infrastructure to maintain—just the CLI and GitHub.

## Key Features

- **Zero-knowledge storage**: Plaintext never leaves clients; GitHub sees only ciphertext
- **GitHub-native**: Leverages GitHub API, OAuth, Actions OIDC—no custom infrastructure
- **Instant adoption**: Anyone with a GitHub account can start immediately
- **Envelope encryption**: Scales to thousands of developers without N×secret re-encryption
- **Cryptographic integrity**: Signed mutations, verified reads, hash-chained audit logs
- **Native CI support**: GitHub Actions OIDC for zero-secret CI authentication
- **Multi-vault profiles**: Manage multiple vaults across GitHub accounts/orgs

## Security Model

**Threat Model**: System remains secure even if GitHub is fully compromised. Attackers cannot decrypt secrets without authorized device keys.

**Cryptographic Guarantees**:
- Confidentiality: ChaCha20-Poly1305 AEAD encryption
- Integrity: Ed25519 signatures and BLAKE3 hash chains
- Authenticity: All mutations signed by device keys
- Forward Secrecy: PDK rotation on member removal

## User Personas

- **Developers**: Pull/push secrets locally, manage multiple profiles
- **Project Admins**: Create projects, manage membership, rotate keys
- **CI/CD**: Authenticate via GitHub Actions OIDC without stored credentials
- **Org Owners**: Define governance, audit compliance without seeing plaintext
- **Auditors**: Verify signed audit trails and policy compliance

## Non-Goals

- GUI/web console (CLI-first)
- Full metadata hiding (limited metadata leakage is acceptable)
- Custom server infrastructure
- Non-GitHub backends (GitLab, self-hosted Git, etc.)
