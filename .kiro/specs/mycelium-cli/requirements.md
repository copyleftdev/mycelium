# Requirements Document

## Introduction

Mycelium is a CLI-only, zero-knowledge secrets management system that uses GitHub as its complete backend. The system enables teams to store, share, and rotate environment variables (secrets) across developers and CI/CD systems without trusting the cloud provider with plaintext. All cryptographic operations occur client-side, with GitHub storing only ciphertext and signed metadata.

## Glossary

- **Mycelium**: The secrets management system
- **myc**: The CLI binary name
- **Vault**: A GitHub repository containing encrypted secrets and metadata
- **PDK (Project Data Key)**: A symmetric key used to encrypt all secrets within a project
- **Device**: A physical machine or CI runner with enrolled cryptographic keys
- **Secret Set**: A collection of environment variables (e.g., "production", "staging")
- **Version**: An immutable snapshot of a secret set at a point in time
- **Envelope Encryption**: A two-level encryption scheme where PDKs encrypt data, and PDKs are wrapped to device keys
- **AEAD**: Authenticated Encryption with Associated Data (ChaCha20-Poly1305)
- **Hash Chain**: A cryptographic chain linking versions for tamper detection
- **OIDC**: OpenID Connect, used for GitHub OAuth and Actions authentication
- **Wrapped PDK**: A PDK encrypted to a specific device's public key

## Requirements

### Requirement 1: Zero-Knowledge Architecture

**User Story:** As a security-conscious organization, I want all secret encryption to happen client-side, so that GitHub never sees plaintext secrets even if compromised.

#### Acceptance Criteria

1. WHEN THE system encrypts secrets, THEN THE myc CLI SHALL perform all encryption operations locally using device keys
2. WHEN THE system stores data in GitHub, THEN THE system SHALL store only ciphertext blobs and signed metadata
3. WHEN THE system transmits data to GitHub, THEN THE plaintext secrets SHALL never be included in any API request
4. WHEN a GitHub employee accesses the vault repository, THEN they SHALL only see encrypted ciphertext without ability to decrypt
5. WHEN THE system generates or uses cryptographic keys, THEN THE keys SHALL be zeroized from memory after use

### Requirement 2: Cargo Workspace Structure

**User Story:** As a Rust developer, I want a well-organized crate structure with clear separation of concerns, so that the codebase is maintainable and auditable.

#### Acceptance Criteria

1. WHEN THE project is built, THEN THE system SHALL organize code into five workspace crates: myc-crypto, myc-core, myc-github, myc-cli, and myc-test-utils
2. WHEN myc-crypto is compiled, THEN it SHALL have zero dependencies on other workspace crates
3. WHEN myc-github is compiled, THEN it SHALL have zero dependencies on myc-crypto or myc-core
4. WHEN myc-core is compiled, THEN it SHALL depend only on myc-crypto and SHALL NOT perform any I/O operations
5. WHEN THE workspace is built, THEN all crates SHALL compile with no warnings using clippy and rustfmt
6. WHEN library crates are compiled, THEN they SHALL enforce #![deny(missing_docs)] for all public items

### Requirement 3: Cryptographic Primitives

**User Story:** As a security engineer, I want well-tested cryptographic primitives with proper key management, so that the system is secure against cryptographic attacks.

#### Acceptance Criteria

1. WHEN THE system encrypts data, THEN it SHALL use ChaCha20-Poly1305 AEAD with randomly generated 12-byte nonces
2. WHEN THE system performs key agreement, THEN it SHALL use X25519 Diffie-Hellman followed by HKDF-SHA256 key derivation
3. WHEN THE system signs data, THEN it SHALL use Ed25519 signatures over canonical JSON representations
4. WHEN THE system hashes data, THEN it SHALL use BLAKE3 for content hashing and hash chain construction
5. WHEN secret key types are dropped, THEN they SHALL implement Zeroize and ZeroizeOnDrop to clear memory
6. WHEN THE system generates random bytes, THEN it SHALL use the OS CSPRNG via getrandom
7. WHEN THE system derives keys from shared secrets, THEN it SHALL use HKDF with domain separation in the info parameter

### Requirement 4: Core Data Model

**User Story:** As a developer, I want strongly-typed domain models with versioned serialization, so that data is validated and future schema changes are manageable.

#### Acceptance Criteria

1. WHEN THE system creates entities, THEN each entity SHALL have a unique UUIDv4 identifier (OrgId, ProjectId, SecretSetId, DeviceId)
2. WHEN THE system serializes data, THEN all types SHALL include a schema_version field set to 1
3. WHEN THE system serializes data, THEN timestamps SHALL be RFC 3339 strings and binary data SHALL be base64-encoded
4. WHEN THE system signs data, THEN it SHALL use canonical JSON with sorted keys and no whitespace
5. WHEN THE system validates entities, THEN names SHALL be non-empty, max 256 characters, and timestamps SHALL not be in the future
6. WHEN THE system stores versions, THEN version numbers SHALL be u64 starting at 1 and monotonically increasing

### Requirement 5: Device Identity and Local Storage

**User Story:** As a user, I want my device to have a unique cryptographic identity stored securely on disk, so that I can authenticate and decrypt secrets.

#### Acceptance Criteria

1. WHEN a device is enrolled, THEN THE system SHALL generate both Ed25519 signing keys and X25519 encryption keys locally
2. WHEN THE system stores device keys, THEN they SHALL be encrypted at rest using Argon2id-derived keys from user passphrase
3. WHEN THE system stores device keys, THEN file permissions SHALL be 0600 (rw-------) on Unix systems
4. WHEN a user enrolls a device, THEN THE system SHALL authenticate via GitHub OAuth Device Authorization Grant
5. WHEN THE system stores profile data, THEN it SHALL use platform-appropriate config directories (~/.config/mycelium on Linux)
6. WHEN a user has multiple vaults, THEN THE system SHALL support multiple named profiles with independent device keys
7. WHEN THE system decrypts device keys, THEN it SHALL fail with a clear error if the passphrase is incorrect

### Requirement 6: GitHub Backend Integration

**User Story:** As a user, I want to use GitHub as my secrets backend without running any servers, so that I can leverage GitHub's infrastructure and availability.

#### Acceptance Criteria

1. WHEN THE system initializes a vault, THEN it SHALL create a private GitHub repository via the GitHub API
2. WHEN THE system reads or writes data, THEN all operations SHALL use GitHub REST API v3 endpoints
3. WHEN THE system authenticates users, THEN it SHALL use GitHub OAuth with repo, read:user, and user:email scopes
4. WHEN THE system handles concurrent modifications, THEN it SHALL use optimistic concurrency with SHA-based ETags
5. WHEN THE system encounters GitHub API rate limits, THEN it SHALL track rate limit headers and back off appropriately
6. WHEN THE system caches data locally, THEN it SHALL invalidate cache after 5 minutes or on write operations
7. WHEN THE system stores vault data, THEN it SHALL organize files under .mycelium/ directory with defined structure

### Requirement 7: Envelope Encryption and PDK Lifecycle

**User Story:** As a project admin, I want to add or remove members without re-encrypting all secrets, so that membership changes are efficient and scalable.

#### Acceptance Criteria

1. WHEN a project is created, THEN THE system SHALL generate a 32-byte random PDK and assign it version 1
2. WHEN THE system wraps a PDK, THEN it SHALL use ECIES-style encryption with ephemeral X25519 keys and HKDF key derivation
3. WHEN a member is added, THEN THE system SHALL wrap the current PDK to all of the member's active devices
4. WHEN a member is removed, THEN THE system SHALL rotate the PDK and wrap the new version only to remaining members
5. WHEN THE system unwraps a PDK, THEN it SHALL fail with AccessDenied if no wrapped PDK exists for the device
6. WHEN THE system stores PDK versions, THEN each version SHALL be immutable and stored at .mycelium/projects/<id>/pdk/v<N>.json
7. WHEN THE system caches unwrapped PDKs, THEN they SHALL be stored only in memory and cleared on profile switch

### Requirement 8: Secret Set Encryption and Versioning

**User Story:** As a developer, I want to store and version my environment variables with integrity verification, so that I can track changes and detect tampering.

#### Acceptance Criteria

1. WHEN THE system encrypts secrets, THEN it SHALL serialize entries as canonical JSON sorted by key
2. WHEN THE system creates a version, THEN it SHALL compute content_hash = BLAKE3(plaintext) and chain_hash = BLAKE3(previous_chain_hash || content_hash)
3. WHEN THE system encrypts a version, THEN it SHALL use the current PDK with AAD = project_id || set_id || version_number || pdk_version
4. WHEN THE system signs a version, THEN it SHALL sign the canonical JSON of metadata using the device's Ed25519 key
5. WHEN THE system decrypts a version, THEN it SHALL verify the content hash, hash chain, and signature before returning plaintext
6. WHEN THE system stores versions, THEN ciphertext SHALL be stored at .mycelium/projects/<pid>/sets/<sid>/v<N>.enc
7. WHEN THE system enforces size limits, THEN it SHALL reject secret sets exceeding 10MB total plaintext

### Requirement 9: Membership and Access Control

**User Story:** As a project owner, I want fine-grained role-based access control, so that I can manage who can read, write, and administer secrets.

#### Acceptance Criteria

1. WHEN THE system assigns roles, THEN it SHALL support four roles: Owner (level 4), Admin (level 3), Member (level 2), Reader (level 1)
2. WHEN an Owner performs operations, THEN they SHALL have all permissions: read, write, share, rotate, delete_project, transfer_ownership
3. WHEN an Admin performs operations, THEN they SHALL have permissions: read, write, share, rotate
4. WHEN a Member performs operations, THEN they SHALL have permissions: read, write
5. WHEN a Reader performs operations, THEN they SHALL have permission: read only
6. WHEN THE system adds a member, THEN the actor SHALL have share permission and target role SHALL be <= actor's role level
7. WHEN THE system removes a member, THEN it SHALL trigger PDK rotation and exclude the removed member's devices from the new PDK version
8. WHEN THE system stores membership, THEN it SHALL sign the members.json file with the actor's device key

### Requirement 10: Key Rotation and Revocation

**User Story:** As a security lead, I want to rotate encryption keys when members leave or devices are compromised, so that revoked entities cannot access future secrets.

#### Acceptance Criteria

1. WHEN a member is removed, THEN THE system SHALL automatically rotate the PDK if rotate_on_member_remove policy is true
2. WHEN a device is revoked, THEN THE system SHALL mark it as Revoked and trigger PDK rotation for all affected projects
3. WHEN THE system rotates a PDK, THEN it SHALL generate a new 32-byte key, increment the version number, and wrap to authorized devices only
4. WHEN THE system rotates a PDK, THEN it SHALL create an audit record with reason, excluded devices, and timestamp
5. WHEN a PDK age exceeds max_age_days policy, THEN THE system SHALL require rotation before allowing new secret versions
6. WHEN THE system rotates a PDK, THEN revoked entities SHALL NOT be able to decrypt versions encrypted with the new PDK
7. WHEN THE system rotates a PDK, THEN historical versions SHALL remain decryptable with old PDK versions

### Requirement 11: CLI Architecture and Commands

**User Story:** As a user, I want an intuitive CLI with consistent commands and helpful output, so that I can efficiently manage secrets in my daily workflow.

#### Acceptance Criteria

1. WHEN THE system provides commands, THEN it SHALL organize them hierarchically: profile, org, device, project, set, pull, push, share, rotate, versions, diff, verify, audit, ci, cache
2. WHEN THE system accepts global options, THEN it SHALL support --profile, --json, --quiet, --verbose, --no-color, --help, --version
3. WHEN THE system outputs data, THEN it SHALL provide human-readable format by default and JSON format with --json flag
4. WHEN THE system encounters errors, THEN it SHALL use consistent exit codes: 0=success, 1=general error, 2=invalid args, 3=auth error, 4=permission denied, 5=crypto error, 6=network error, 7=conflict, 8=not found, 10=user cancelled
5. WHEN THE system performs destructive actions, THEN it SHALL prompt for confirmation unless in non-interactive mode
6. WHEN THE system runs in CI mode (MYC_NON_INTERACTIVE=1), THEN it SHALL fail with exit code 10 if user input is required
7. WHEN THE system parses arguments, THEN it SHALL use clap v4 with derive macros for consistent help and validation

### Requirement 12: GitHub Actions CI Integration

**User Story:** As a DevOps engineer, I want CI workflows to pull secrets using GitHub OIDC tokens without storing credentials, so that CI access is secure and auditable.

#### Acceptance Criteria

1. WHEN a GitHub Actions workflow requests secrets, THEN THE system SHALL validate OIDC tokens from ACTIONS_ID_TOKEN_REQUEST_URL
2. WHEN THE system validates OIDC tokens, THEN it SHALL extract claims: repository, workflow, ref, actor, environment
3. WHEN THE system authorizes CI access, THEN admins SHALL pre-authorize identity patterns like "github:repo:myorg/api:ref:refs/heads/main"
4. WHEN a CI device enrolls, THEN it SHALL be marked as DeviceType::CI with optional expires_at timestamp
5. WHEN a CI device pulls secrets, THEN it SHALL support output formats: shell, dotenv, json for easy integration
6. WHEN a CI device is expired, THEN THE system SHALL reject pull requests with a distinct error code
7. WHEN THE system audits CI operations, THEN it SHALL log ci_enrolled, ci_pull, ci_expired, ci_revoked events

### Requirement 13: Audit Log and Integrity Verification

**User Story:** As a compliance officer, I want cryptographically verifiable audit logs of all operations, so that I can prove who did what and detect tampering.

#### Acceptance Criteria

1. WHEN THE system performs a mutating operation, THEN it SHALL create a signed audit event with event_id, event_type, timestamp, actor, and details
2. WHEN THE system creates audit events, THEN it SHALL compute chain_hash = BLAKE3(previous_chain_hash || canonical_json(event_data))
3. WHEN THE system signs audit events, THEN it SHALL use the actor's Ed25519 device key to sign the canonical JSON
4. WHEN THE system stores audit events, THEN they SHALL be organized by month at .mycelium/audit/<YYYY-MM>/<event-id>.json
5. WHEN THE system verifies audit integrity, THEN it SHALL recompute hash chains and verify signatures for all events
6. WHEN THE system detects tampering, THEN it SHALL report the specific event where the chain breaks
7. WHEN THE system exports audit logs, THEN it SHALL support JSON, CSV, and syslog formats with filtering by date, project, user, and event type

### Requirement 14: Key Recovery and Account Continuity

**User Story:** As a user, I want multiple recovery options if I lose my device, so that I don't permanently lose access to all my secrets.

#### Acceptance Criteria

1. WHEN a user enrolls their first device, THEN THE system SHALL recommend enrolling a second device for recovery
2. WHEN a user has only one device, THEN THE system SHALL display warnings on each command execution
3. WHEN a user sets recovery contacts, THEN THE system SHALL store the relationship signed by the user's device
4. WHEN a recovery contact assists recovery, THEN they SHALL only be able to wrap PDKs for projects they have access to
5. WHEN an organization initializes recovery, THEN THE system SHALL support Shamir Secret Sharing with configurable threshold (e.g., 3-of-5)
6. WHEN admins contribute recovery shares, THEN THE system SHALL reconstruct the org recovery key, re-wrap PDKs, and immediately discard the assembled key
7. WHEN THE system performs recovery operations, THEN it SHALL create audit events logging who assisted and which projects were recovered

### Requirement 15: CLI User Experience

**User Story:** As a new user, I want to go from zero to encrypted secrets in under 5 minutes with helpful guidance, so that adoption is frictionless.

#### Acceptance Criteria

1. WHEN a new user runs myc init, THEN THE system SHALL complete GitHub OAuth, create a vault repo, generate device keys, and initialize vault structure in under 60 seconds
2. WHEN THE system displays errors, THEN each error SHALL include what went wrong, why it matters, and how to fix it
3. WHEN THE system performs long operations, THEN it SHALL display progress spinners for network and crypto operations
4. WHEN a user creates a .myc.yaml config file, THEN THE system SHALL use it to provide defaults for vault, project, set, and export format
5. WHEN a user runs myc run <command>, THEN THE system SHALL inject secrets as environment variables without writing to disk
6. WHEN THE system generates shell completions, THEN it SHALL support bash, zsh, fish, and powershell
7. WHEN a user pushes secrets, THEN THE system SHALL show a diff of changes and prompt for confirmation before pushing

### Requirement 16: Secret Import and Export

**User Story:** As a developer, I want to import existing .env files and export secrets in various formats, so that I can integrate with existing tools and workflows.

#### Acceptance Criteria

1. WHEN THE system imports from dotenv format, THEN it SHALL parse KEY=value lines, handle quotes, and skip comments
2. WHEN THE system imports from JSON format, THEN it SHALL parse objects with string keys and values
3. WHEN THE system exports to dotenv format, THEN it SHALL produce KEY=value lines with proper escaping for special characters
4. WHEN THE system exports to JSON format, THEN it SHALL produce {"KEY": "value"} objects
5. WHEN THE system exports to shell format, THEN it SHALL produce export KEY='value' lines for eval
6. WHEN THE system exports to YAML format, THEN it SHALL produce KEY: value lines
7. WHEN THE system detects export format, THEN it SHALL auto-detect based on file extension or accept explicit --format flag

### Requirement 17: Version History and Diffing

**User Story:** As a developer, I want to view version history and diff changes between versions, so that I can understand what changed and when.

#### Acceptance Criteria

1. WHEN THE system lists versions, THEN it SHALL display version number, timestamp, author, and commit message
2. WHEN THE system shows a version, THEN it SHALL display metadata including content hash, chain hash, and signature status
3. WHEN THE system diffs two versions, THEN it SHALL show added keys, removed keys, and changed keys
4. WHEN THE system diffs versions, THEN it SHALL optionally show value changes or hide values for security
5. WHEN THE system verifies a secret set, THEN it SHALL check all version signatures, content hashes, and hash chain integrity
6. WHEN THE system detects version tampering, THEN it SHALL report which version failed verification and why
7. WHEN THE system displays version history, THEN it SHALL support --json output for programmatic access

### Requirement 18: Profile Management

**User Story:** As a consultant, I want to manage multiple vault profiles for different clients, so that I can easily switch between contexts.

#### Acceptance Criteria

1. WHEN THE system lists profiles, THEN it SHALL show profile name, vault repository, and whether it's the default
2. WHEN THE system adds a profile, THEN it SHALL enroll a new device with independent keys for that vault
3. WHEN THE system switches profiles, THEN it SHALL update the default profile and clear any cached PDKs
4. WHEN THE system removes a profile, THEN it SHALL delete all local keys and cache after confirmation
5. WHEN THE system uses a profile, THEN it SHALL accept --profile flag to override the default for a single command
6. WHEN THE system stores profiles, THEN each SHALL have independent directories under ~/.config/mycelium/profiles/
7. WHEN THE system displays profile details, THEN it SHALL show GitHub user, device ID, enrollment date, and vault URL

### Requirement 19: Integrity Verification

**User Story:** As a security auditor, I want to verify the cryptographic integrity of all vault data, so that I can detect any tampering or corruption.

#### Acceptance Criteria

1. WHEN THE system verifies a project, THEN it SHALL check membership signatures, PDK version signatures, and secret set integrity
2. WHEN THE system verifies a secret set, THEN it SHALL validate all version signatures, content hashes, and hash chain links
3. WHEN THE system verifies audit logs, THEN it SHALL recompute hash chains and verify signatures for all events
4. WHEN THE system verifies membership, THEN it SHALL confirm signers had appropriate permissions at signing time
5. WHEN THE system detects integrity failures, THEN it SHALL report specific files, versions, or events that failed
6. WHEN THE system verifies successfully, THEN it SHALL report total items verified and confirmation of integrity
7. WHEN THE system runs verification, THEN it SHALL support --json output for automated monitoring

### Requirement 20: Error Handling and Resilience

**User Story:** As a user, I want the system to handle errors gracefully with clear guidance, so that I can resolve issues without frustration.

#### Acceptance Criteria

1. WHEN GitHub API returns 401, THEN THE system SHALL prompt for re-authentication with clear instructions
2. WHEN GitHub API returns 403 rate limit, THEN THE system SHALL display time until reset and suggest waiting
3. WHEN GitHub API returns 404, THEN THE system SHALL check if the vault exists and suggest verifying access permissions
4. WHEN GitHub API returns 409 conflict, THEN THE system SHALL suggest pulling latest changes and retrying
5. WHEN decryption fails, THEN THE system SHALL distinguish between missing PDK, wrong key, and corrupted data
6. WHEN signature verification fails, THEN THE system SHALL report which signature failed and suggest verifying vault integrity
7. WHEN THE system encounters network errors, THEN it SHALL retry with exponential backoff up to 3 times before failing

### Requirement 21: Testing and Quality

**User Story:** As a maintainer, I want comprehensive test coverage with property-based tests for crypto operations, so that the system is reliable and correct.

#### Acceptance Criteria

1. WHEN crypto operations are tested, THEN THE system SHALL use property-based tests with proptest for roundtrip properties
2. WHEN serialization is tested, THEN THE system SHALL verify roundtrip: serialize then deserialize produces identical values
3. WHEN encryption is tested, THEN THE system SHALL verify tampering with ciphertext causes decryption failure
4. WHEN signatures are tested, THEN THE system SHALL verify tampering with messages causes verification failure
5. WHEN hash chains are tested, THEN THE system SHALL verify tampering with any version breaks the chain
6. WHEN THE system runs tests, THEN all tests SHALL pass in both debug and release modes
7. WHEN THE system is built, THEN CI SHALL enforce cargo fmt, clippy, cargo audit, and cargo deny checks

### Requirement 22: Supply Chain Security

**User Story:** As a security engineer, I want all dependencies vetted and audited, so that the supply chain is secure.

#### Acceptance Criteria

1. WHEN THE system uses dependencies, THEN all SHALL be from RustCrypto, dalek, or well-audited foundational crates
2. WHEN THE system builds, THEN cargo-vet SHALL verify all dependencies are vetted or exempted with rationale
3. WHEN THE system builds, THEN cargo-audit SHALL block on known vulnerabilities
4. WHEN THE system builds, THEN cargo-deny SHALL block duplicate versions and unwanted licenses
5. WHEN THE system uses crypto crates, THEN it SHALL pin specific versions: chacha20poly1305 0.10, x25519-dalek 2, ed25519-dalek 2
6. WHEN THE system uses unsafe code, THEN it SHALL be explicitly audited and documented
7. WHEN THE system updates dependencies, THEN changes SHALL be reviewed and re-vetted

### Requirement 23: Documentation

**User Story:** As a developer, I want comprehensive documentation for all public APIs, so that I can understand and use the system correctly.

#### Acceptance Criteria

1. WHEN library crates are compiled, THEN all public items SHALL have doc comments enforced by #![deny(missing_docs)]
2. WHEN THE system provides CLI commands, THEN each SHALL have --help text with usage examples
3. WHEN THE system provides error messages, THEN each SHALL include context and suggested remediation
4. WHEN THE system provides examples, THEN they SHALL be tested as part of CI
5. WHEN THE system provides RFCs, THEN they SHALL be kept in sync with implementation
6. WHEN THE system provides a README, THEN it SHALL include quick start, architecture overview, and security model
7. WHEN THE system provides API docs, THEN they SHALL be generated with cargo doc and published

### Requirement 24: Performance

**User Story:** As a user, I want operations to complete quickly, so that the CLI doesn't slow down my workflow.

#### Acceptance Criteria

1. WHEN THE system encrypts secrets, THEN operations SHALL complete in under 100ms for typical secret sets (< 100 entries)
2. WHEN THE system pulls secrets, THEN it SHALL use local cache to avoid redundant GitHub API calls
3. WHEN THE system wraps PDKs, THEN it SHALL parallelize wrapping to multiple devices
4. WHEN THE system verifies integrity, THEN it SHALL support incremental verification from last checkpoint
5. WHEN THE system handles large secret sets, THEN it SHALL stream processing to avoid loading entire sets in memory
6. WHEN THE system performs crypto operations, THEN it SHALL use release mode optimizations
7. WHEN THE system tracks performance, THEN it SHALL log operation timings with --verbose flag

### Requirement 25: Secrets Lifecycle Management

**User Story:** As a platform engineer, I want to manage the full lifecycle of secrets from creation to rotation to deletion, so that secrets are properly maintained.

#### Acceptance Criteria

1. WHEN THE system creates a secret set, THEN it SHALL initialize with version 1 and empty entries
2. WHEN THE system updates a secret set, THEN it SHALL create a new immutable version with incremented version number
3. WHEN THE system deletes a secret set, THEN it SHALL require confirmation and create an audit event
4. WHEN THE system rotates actual secret values, THEN it SHALL preserve version history for audit purposes
5. WHEN THE system expires secrets, THEN it SHALL support optional expiry metadata on individual entries
6. WHEN THE system archives old versions, THEN it SHALL support compaction while preserving hash chain integrity
7. WHEN THE system migrates secrets, THEN it SHALL support bulk import/export operations with validation
