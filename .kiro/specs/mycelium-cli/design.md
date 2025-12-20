# Design Document

## Overview

Mycelium is a zero-knowledge secrets management system implemented as a Rust CLI that uses GitHub as its complete backend. The system provides end-to-end encrypted secret storage, sharing, and rotation without requiring any server infrastructure. All cryptographic operations occur client-side, with GitHub storing only ciphertext and signed metadata.

The architecture follows a layered approach:
1. **Cryptographic Primitives Layer** (myc-crypto): Pure cryptographic operations
2. **Core Domain Layer** (myc-core): Business logic and data models
3. **GitHub Integration Layer** (myc-github): API client and transport
4. **CLI Layer** (myc-cli): User interface and orchestration

Key design principles:
- **Zero-trust storage**: GitHub never sees plaintext secrets or decryption keys
- **Client-side crypto**: All encryption, signing, and verification happens locally
- **Envelope encryption**: Symmetric PDKs encrypt secrets; PDKs are wrapped to device keys
- **Immutable versioning**: All changes create new versions; history is append-only
- **Cryptographic integrity**: Signatures and hash chains detect tampering
- **Separation of concerns**: Clear boundaries between crypto, domain logic, and I/O

## Architecture

### System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         myc CLI                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   Commands   │  │   Profiles   │  │    Output    │      │
│  │   (clap)     │  │   Manager    │  │   Formatter  │      │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘      │
│         │                  │                  │              │
│         └──────────────────┼──────────────────┘              │
│                            │                                 │
│  ┌─────────────────────────┴──────────────────────────┐     │
│  │              Core Orchestration                     │     │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────┐ │     │
│  │  │  Vault Ops   │  │  Secret Ops  │  │ Member   │ │     │
│  │  │              │  │              │  │ Ops      │ │     │
│  │  └──────┬───────┘  └──────┬───────┘  └────┬─────┘ │     │
│  └─────────┼──────────────────┼───────────────┼───────┘     │
└────────────┼──────────────────┼───────────────┼─────────────┘
             │                  │               │
    ┌────────┴────────┐  ┌──────┴──────┐  ┌────┴─────┐
    │   myc-core      │  │  myc-crypto │  │ myc-     │
    │                 │  │             │  │ github   │
    │  ┌───────────┐  │  │ ┌─────────┐ │  │          │
    │  │ Domain    │  │  │ │ AEAD    │ │  │ ┌──────┐ │
    │  │ Types     │  │  │ │ KEX     │ │  │ │ API  │ │
    │  │           │  │  │ │ Sign    │ │  │ │Client│ │
    │  ├───────────┤  │  │ ├─────────┤ │  │ ├──────┤ │
    │  │ PDK       │  │  │ │ KDF     │ │  │ │OAuth │ │
    │  │ Manager   │  │  │ │ Hash    │ │  │ │Flow  │ │
    │  │           │  │  │ │ Random  │ │  │ │      │ │
    │  ├───────────┤  │  │ └─────────┘ │  │ ├──────┤ │
    │  │ Canonical │  │  │             │  │ │OIDC  │ │
    │  │ JSON      │  │  │             │  │ │Valid │ │
    │  └───────────┘  │  │             │  │ └──────┘ │
    └─────────────────┘  └─────────────┘  └──────────┘
             │                  │               │
             └──────────────────┴───────────────┘
                            │
                    ┌───────┴────────┐
                    │  Local Storage │
                    │  ~/.config/    │
                    │  mycelium/     │
                    └───────┬────────┘
                            │
                    ┌───────┴────────┐
                    │  GitHub API    │
                    │  (Backend)     │
                    └────────────────┘
```

### Crate Architecture

**myc-crypto** (Pure cryptographic operations)
- No external I/O, no dependencies on other workspace crates
- Wraps RustCrypto and dalek primitives with opinionated APIs
- All secret types implement Zeroize and ZeroizeOnDrop
- Modules: aead, kex, sign, kdf, hash, random, error

**myc-core** (Domain logic and data models)
- Depends only on myc-crypto
- No I/O operations (all I/O injected or handled by CLI)
- Defines all domain types with serde serialization
- Modules: ids, org, project, secret_set, device, pdk, canonical, error

**myc-github** (GitHub API client)
- Independent of myc-crypto and myc-core (handles only ciphertext bytes)
- Implements OAuth device flow and OIDC validation
- Provides high-level operations: read_file, write_file, list_directory
- Handles rate limiting, retries, and error translation

**myc-cli** (CLI binary)
- Composition root that wires together all crates
- Implements command handlers using clap v4
- Manages profiles, output formatting, and user interaction
- Handles async runtime (tokio) and error presentation

**myc-test-utils** (Test utilities)
- Shared test fixtures and mock implementations
- Key generation helpers for tests
- Mock GitHub API responses

### Data Flow

**Secret Push Flow:**
```
User → myc push → Read .env file → Parse entries
                                      ↓
                              Sort by key (canonical)
                                      ↓
                              Serialize to JSON
                                      ↓
                              Compute content_hash (BLAKE3)
                                      ↓
                              Get current PDK → Unwrap with device key
                                      ↓
                              Encrypt with PDK (ChaCha20-Poly1305)
                                      ↓
                              Compute chain_hash
                                      ↓
                              Sign metadata (Ed25519)
                                      ↓
                              Write to GitHub API
                                      ↓
                              Create audit event
```

**Secret Pull Flow:**
```
User → myc pull → Read version metadata from GitHub
                                      ↓
                              Get PDK version number
                                      ↓
                              Read PDK version → Find wrapped PDK for device
                                      ↓
                              Unwrap PDK (X25519 + HKDF + AEAD)
                                      ↓
                              Read ciphertext from GitHub
                                      ↓
                              Decrypt with PDK
                                      ↓
                              Verify content_hash
                                      ↓
                              Verify signature
                                      ↓
                              Verify hash chain
                                      ↓
                              Parse JSON → Return entries
```

**Member Add Flow:**
```
Admin → myc share add → Verify actor has share permission
                                      ↓
                              Get target user's devices
                                      ↓
                              Get current PDK version
                                      ↓
                              Unwrap PDK with admin's device key
                                      ↓
                              For each target device:
                                Generate ephemeral X25519 keypair
                                Compute shared secret
                                Derive wrap key (HKDF)
                                Encrypt PDK (AEAD)
                                      ↓
                              Append wrapped PDKs to PdkVersion
                                      ↓
                              Add member to members.json
                                      ↓
                              Sign both files
                                      ↓
                              Write to GitHub
                                      ↓
                              Create audit event
```

## Components and Interfaces

### Cryptographic Primitives (myc-crypto)

**AEAD Module**
```rust
pub fn encrypt(key: &AeadKey, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>>;
pub fn decrypt(key: &AeadKey, ciphertext_with_nonce: &[u8], aad: &[u8]) -> Result<Vec<u8>>;

pub struct AeadKey(SecretBox<[u8; 32]>); // Zeroized on drop
pub struct Nonce([u8; 12]);
```

**Key Exchange Module**
```rust
pub fn generate_x25519_keypair() -> (X25519SecretKey, X25519PublicKey);
pub fn diffie_hellman(secret: &X25519SecretKey, public: &X25519PublicKey) -> SharedSecret;

pub struct X25519SecretKey(StaticSecret); // Zeroized, no Clone
pub struct X25519PublicKey(PublicKey); // 32 bytes, Copy
pub struct SharedSecret([u8; 32]); // Zeroized, must use KDF
```

**Signature Module**
```rust
pub fn generate_ed25519_keypair() -> (Ed25519SecretKey, Ed25519PublicKey);
pub fn sign(key: &Ed25519SecretKey, message: &[u8]) -> Signature;
pub fn verify(key: &Ed25519PublicKey, message: &[u8], signature: &Signature) -> Result<()>;

pub struct Ed25519SecretKey(SigningKey); // Zeroized, no Clone
pub struct Ed25519PublicKey(VerifyingKey); // 32 bytes, Copy
pub struct Signature([u8; 64]); // Copy
```

**KDF Module**
```rust
pub fn derive_key(ikm: &[u8], salt: &[u8], info: &[u8], len: usize) -> Vec<u8>;
pub fn derive_aead_key(shared_secret: &SharedSecret, context: &[u8]) -> AeadKey;
```

**Hash Module**
```rust
pub fn hash(data: &[u8]) -> HashOutput;
pub fn chain_hash(previous: &HashOutput, current: &[u8]) -> HashOutput;

pub struct HashOutput([u8; 32]); // BLAKE3 output
pub struct Hasher(blake3::Hasher); // Streaming hasher
```

**Random Module**
```rust
pub fn fill_random(dest: &mut [u8]);
pub fn generate_random_bytes<const N: usize>() -> [u8; N];
```

### Core Domain Types (myc-core)

**Identifiers**
```rust
pub struct OrgId(Uuid);
pub struct ProjectId(Uuid);
pub struct SecretSetId(Uuid);
pub struct DeviceId(Uuid);
pub struct UserId(String); // OIDC subject
pub struct VersionNumber(u64); // Starts at 1
```

**Organization**
```rust
pub struct Org {
    pub schema_version: u32,
    pub id: OrgId,
    pub name: String,
    pub created_at: OffsetDateTime,
    pub settings: OrgSettings,
}

pub struct OrgSettings {
    pub require_device_approval: bool,
    pub github_org: Option<String>,
    pub default_rotation_policy: Option<RotationPolicy>,
}
```

**Project**
```rust
pub struct Project {
    pub schema_version: u32,
    pub id: ProjectId,
    pub org_id: OrgId,
    pub name: String,
    pub created_at: OffsetDateTime,
    pub created_by: DeviceId,
    pub current_pdk_version: VersionNumber,
}

pub struct ProjectMember {
    pub user_id: UserId,
    pub role: Role,
    pub added_at: OffsetDateTime,
    pub added_by: DeviceId,
}

pub enum Role {
    Owner,   // Level 4: all permissions
    Admin,   // Level 3: read, write, share, rotate
    Member,  // Level 2: read, write
    Reader,  // Level 1: read
}
```

**Secret Set**
```rust
pub struct SecretSet {
    pub schema_version: u32,
    pub id: SecretSetId,
    pub project_id: ProjectId,
    pub name: String,
    pub created_at: OffsetDateTime,
    pub created_by: DeviceId,
    pub current_version: VersionNumber,
}

pub struct SecretSetVersion {
    pub schema_version: u32,
    pub set_id: SecretSetId,
    pub version: VersionNumber,
    pub pdk_version: VersionNumber,
    pub created_at: OffsetDateTime,
    pub created_by: DeviceId,
    pub message: Option<String>,
    pub content_hash: HashOutput,
    pub previous_hash: Option<HashOutput>,
    pub ciphertext: Vec<u8>,
    pub signature: Signature,
}

pub struct SecretEntry {
    pub key: String,
    pub value: String,
    pub metadata: Option<EntryMetadata>,
}

pub struct EntryMetadata {
    pub description: Option<String>,
    pub created_at: Option<OffsetDateTime>,
    pub updated_at: Option<OffsetDateTime>,
    pub tags: Vec<String>,
}
```

**Device**
```rust
pub struct Device {
    pub schema_version: u32,
    pub id: DeviceId,
    pub user_id: UserId,
    pub name: String,
    pub device_type: DeviceType,
    pub signing_pubkey: Ed25519PublicKey,
    pub encryption_pubkey: X25519PublicKey,
    pub enrolled_at: OffsetDateTime,
    pub status: DeviceStatus,
    pub expires_at: Option<OffsetDateTime>,
}

pub enum DeviceType {
    Interactive,
    CI,
}

pub enum DeviceStatus {
    Active,
    PendingApproval,
    Revoked,
}
```

**PDK Management**
```rust
pub struct PdkVersion {
    pub version: VersionNumber,
    pub created_at: OffsetDateTime,
    pub created_by: DeviceId,
    pub reason: Option<String>,
    pub wrapped_keys: Vec<WrappedPdk>,
}

pub struct WrappedPdk {
    pub device_id: DeviceId,
    pub ephemeral_pubkey: X25519PublicKey,
    pub ciphertext: Vec<u8>, // 12 (nonce) + 32 (PDK) + 16 (tag)
}
```

**Canonical Serialization**
```rust
pub fn to_canonical_json<T: Serialize>(value: &T) -> Result<String>;
pub fn sign_payload<T: Serialize>(value: &T, key: &Ed25519SecretKey) -> Result<Signature>;
pub fn verify_payload<T: Serialize>(value: &T, signature: &Signature, key: &Ed25519PublicKey) -> Result<()>;
```

### GitHub Integration (myc-github)

**GitHub Client**
```rust
pub struct GitHubClient {
    octocrab: Octocrab,
    owner: String,
    repo: String,
}

impl GitHubClient {
    pub async fn new(token: &str, owner: String, repo: String) -> Result<Self>;
    
    pub async fn read_file(&self, path: &str) -> Result<Vec<u8>>;
    pub async fn write_file(&self, path: &str, content: &[u8], message: &str, sha: Option<&str>) -> Result<String>;
    pub async fn list_directory(&self, path: &str) -> Result<Vec<FileEntry>>;
    pub async fn create_repository(&self, name: &str, private: bool) -> Result<Repository>;
    pub async fn check_access(&self) -> Result<bool>;
}
```

**OAuth Device Flow**
```rust
pub struct OAuthDeviceFlow {
    client_id: String,
}

impl OAuthDeviceFlow {
    pub async fn start(&self) -> Result<DeviceCodeResponse>;
    pub async fn poll(&self, device_code: &str) -> Result<Option<AccessToken>>;
    pub async fn get_user_info(&self, token: &AccessToken) -> Result<GitHubUser>;
}

pub struct DeviceCodeResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub expires_in: u64,
    pub interval: u64,
}
```

**OIDC Validation**
```rust
pub struct OidcValidator {
    jwks_uri: String,
}

impl OidcValidator {
    pub async fn validate_token(&self, token: &str) -> Result<OidcClaims>;
}

pub struct OidcClaims {
    pub repository: String,
    pub workflow: String,
    pub ref_: String,
    pub actor: String,
    pub environment: Option<String>,
}
```

### CLI Layer (myc-cli)

**Command Structure**
```rust
#[derive(Parser)]
#[command(name = "myc", about = "A living, zero-knowledge secrets mesh")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    
    #[arg(long, short = 'p', global = true)]
    profile: Option<String>,
    
    #[arg(long, short = 'j', global = true)]
    json: bool,
    
    #[arg(long, short = 'q', global = true)]
    quiet: bool,
    
    #[arg(long, short = 'v', global = true, action = ArgAction::Count)]
    verbose: u8,
    
    #[arg(long, global = true)]
    no_color: bool,
}

#[derive(Subcommand)]
enum Commands {
    Profile(ProfileCommands),
    Org(OrgCommands),
    Device(DeviceCommands),
    Project(ProjectCommands),
    Set(SetCommands),
    Pull(PullArgs),
    Push(PushArgs),
    Share(ShareCommands),
    Rotate(RotateArgs),
    Versions(VersionsCommands),
    Diff(DiffArgs),
    Verify(VerifyArgs),
    Audit(AuditCommands),
    Ci(CiCommands),
    Cache(CacheCommands),
}
```

**Profile Manager**
```rust
pub struct ProfileManager {
    config_dir: PathBuf,
}

impl ProfileManager {
    pub fn list_profiles(&self) -> Result<Vec<String>>;
    pub fn get_profile(&self, name: &str) -> Result<Profile>;
    pub fn create_profile(&self, profile: &Profile) -> Result<()>;
    pub fn delete_profile(&self, name: &str) -> Result<()>;
    pub fn get_default_profile(&self) -> Result<Option<String>>;
    pub fn set_default_profile(&self, name: &str) -> Result<()>;
    
    pub fn load_signing_key(&self, profile: &str, passphrase: &str) -> Result<Ed25519SecretKey>;
    pub fn load_encryption_key(&self, profile: &str, passphrase: &str) -> Result<X25519SecretKey>;
    pub fn save_keypair(&self, profile: &str, signing: &Ed25519SecretKey, encryption: &X25519SecretKey, passphrase: &str) -> Result<()>;
}
```

**Vault Operations**
```rust
pub struct VaultOps {
    github: GitHubClient,
    profile: Profile,
}

impl VaultOps {
    pub async fn init_vault(&self, name: &str) -> Result<Org>;
    pub async fn create_project(&self, name: &str) -> Result<Project>;
    pub async fn create_secret_set(&self, project_id: &ProjectId, name: &str) -> Result<SecretSet>;
    
    pub async fn push_secrets(&self, set_id: &SecretSetId, entries: Vec<SecretEntry>, message: Option<&str>) -> Result<VersionNumber>;
    pub async fn pull_secrets(&self, set_id: &SecretSetId, version: Option<VersionNumber>) -> Result<Vec<SecretEntry>>;
    
    pub async fn add_member(&self, project_id: &ProjectId, user_id: &UserId, role: Role) -> Result<()>;
    pub async fn remove_member(&self, project_id: &ProjectId, user_id: &UserId) -> Result<()>;
    
    pub async fn rotate_pdk(&self, project_id: &ProjectId, reason: RotationReason) -> Result<VersionNumber>;
}
```

## Data Models

### GitHub Repository Structure

```
.mycelium/
├── vault.json                                    # Org metadata
├── devices/
│   ├── <device-id-1>.json                       # Device records
│   └── <device-id-2>.json
├── projects/
│   └── <project-id>/
│       ├── project.json                         # Project metadata
│       ├── members.json                         # Membership & roles (signed)
│       ├── pdk/
│       │   ├── v1.json                         # PDK version 1 (wrapped keys)
│       │   └── v2.json                         # PDK version 2
│       └── sets/
│           └── <set-id>/
│               ├── set.json                    # Set metadata
│               ├── v1.enc                      # Encrypted version 1
│               ├── v1.meta.json                # Version 1 metadata (signed)
│               ├── v2.enc
│               └── v2.meta.json
├── audit/
│   ├── index.json                              # Audit index
│   ├── 2025-12/
│   │   ├── <event-id-1>.json                  # Audit events (signed)
│   │   └── <event-id-2>.json
│   └── 2025-11/
└── recovery/
    ├── org_recovery.json                       # Org recovery key config
    └── requests/
        └── <request-id>.json                   # Recovery requests
```

### Local Storage Structure

```
~/.config/mycelium/
├── config.json                                  # Global config
└── profiles/
    └── <profile-name>/
        ├── profile.json                        # Profile metadata
        ├── device.json                         # Device metadata
        ├── keys/
        │   ├── signing.key                     # Ed25519 secret (encrypted)
        │   ├── signing.pub                     # Ed25519 public
        │   ├── encryption.key                  # X25519 secret (encrypted)
        │   └── encryption.pub                  # X25519 public
        ├── github_token.enc                    # OAuth token (encrypted)
        └── cache/
            ├── devices.json                    # Cached device registry
            ├── projects.json                   # Cached project list
            └── pdks/
                └── <project-id>-v<N>.json     # Cached PDK versions
```

### Serialization Formats

**Vault Metadata (vault.json)**
```json
{
  "schema_version": 1,
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "My Organization",
  "created_at": "2025-12-05T14:30:00Z",
  "settings": {
    "require_device_approval": false,
    "github_org": "myorg",
    "default_rotation_policy": {
      "rotate_on_member_remove": true,
      "max_age_days": 90
    }
  }
}
```

**Device Record (devices/<device-id>.json)**
```json
{
  "schema_version": 1,
  "id": "660e8400-e29b-41d4-a716-446655440001",
  "user_id": "github|12345678",
  "name": "MacBook Pro",
  "device_type": "interactive",
  "signing_pubkey": "base64...",
  "encryption_pubkey": "base64...",
  "enrolled_at": "2025-12-05T14:30:00Z",
  "status": "active",
  "expires_at": null
}
```

**PDK Version (pdk/v1.json)**
```json
{
  "version": 1,
  "created_at": "2025-12-05T14:30:00Z",
  "created_by": "660e8400-e29b-41d4-a716-446655440001",
  "reason": null,
  "wrapped_keys": [
    {
      "device_id": "660e8400-e29b-41d4-a716-446655440001",
      "ephemeral_pubkey": "base64...",
      "ciphertext": "base64..."
    }
  ]
}
```

**Secret Set Version Metadata (v1.meta.json)**
```json
{
  "schema_version": 1,
  "type": "secret_set_version_meta",
  "data": {
    "set_id": "770e8400-e29b-41d4-a716-446655440002",
    "version": 1,
    "pdk_version": 1,
    "created_at": "2025-12-05T14:30:00Z",
    "created_by": "660e8400-e29b-41d4-a716-446655440001",
    "message": "Initial version",
    "content_hash": "base64...",
    "chain_hash": "base64...",
    "previous_chain_hash": null
  },
  "signature": "base64...",
  "signed_by": "660e8400-e29b-41d4-a716-446655440001"
}
```

**Audit Event (audit/2025-12/<event-id>.json)**
```json
{
  "schema_version": 1,
  "type": "audit_event",
  "data": {
    "event_id": "880e8400-e29b-41d4-a716-446655440003",
    "event_type": "member_added",
    "timestamp": "2025-12-05T14:30:00Z",
    "actor_device_id": "660e8400-e29b-41d4-a716-446655440001",
    "actor_user_id": "github|12345678",
    "org_id": "550e8400-e29b-41d4-a716-446655440000",
    "project_id": "990e8400-e29b-41d4-a716-446655440004",
    "details": {
      "user_id": "github|87654321",
      "role": "member"
    },
    "chain_hash": "base64...",
    "previous_event_id": "870e8400-e29b-41d4-a716-446655440002"
  },
  "signature": "base64...",
  "signed_by": "660e8400-e29b-41d4-a716-446655440001"
}
```

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system—essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*


### Property 1: Encryption Roundtrip
*For any* plaintext data and AEAD key, encrypting then decrypting SHALL recover the original plaintext.
**Validates: Requirements 3.1, 3.3**

### Property 2: Encryption Produces Correct Structure
*For any* plaintext data, encrypted output SHALL have structure: 12-byte nonce || ciphertext || 16-byte tag.
**Validates: Requirements 3.1**

### Property 3: Signature Roundtrip
*For any* message and Ed25519 keypair, signing then verifying SHALL succeed.
**Validates: Requirements 3.3**

### Property 4: Tampering Detection
*For any* signed message, modifying the message or signature SHALL cause verification to fail.
**Validates: Requirements 3.3**

### Property 5: KDF Determinism
*For any* input key material, salt, and info, HKDF SHALL produce the same output on repeated calls.
**Validates: Requirements 3.2, 3.7**

### Property 6: KDF Domain Separation
*For any* shared secret, different info parameters SHALL produce different derived keys.
**Validates: Requirements 3.7**

### Property 7: Hash Determinism
*For any* input data, BLAKE3 SHALL produce the same hash on repeated calls.
**Validates: Requirements 3.4**

### Property 8: Hash Chain Integrity
*For any* sequence of versions, the hash chain SHALL link correctly: chain_hash(n) = BLAKE3(chain_hash(n-1) || content_hash(n)).
**Validates: Requirements 3.4, 8.2**

### Property 9: UUID Uniqueness
*For any* two entity creations, generated UUIDs SHALL be different.
**Validates: Requirements 4.1**

### Property 10: Schema Version Presence
*For any* serialized entity, the JSON SHALL contain "schema_version": 1.
**Validates: Requirements 4.2**

### Property 11: Serialization Format Compliance
*For any* entity with timestamps and binary data, serialized JSON SHALL use RFC 3339 for timestamps and base64 for binary.
**Validates: Requirements 4.3**

### Property 12: Canonical JSON Determinism
*For any* data structure, canonical JSON serialization SHALL be deterministic with sorted keys and no whitespace.
**Validates: Requirements 4.4, 8.1**

### Property 13: Validation Rejects Invalid Names
*For any* name that is empty or exceeds 256 characters, validation SHALL reject it.
**Validates: Requirements 4.5**

### Property 14: Validation Rejects Future Timestamps
*For any* timestamp in the future, validation SHALL reject it.
**Validates: Requirements 4.5**

### Property 15: Version Number Monotonicity
*For any* sequence of version creations, version numbers SHALL start at 1 and increment by 1.
**Validates: Requirements 4.6**

### Property 16: Device Key Encryption Roundtrip
*For any* device keys and passphrase, encrypting then decrypting with the same passphrase SHALL recover the original keys.
**Validates: Requirements 5.2**

### Property 17: Wrong Passphrase Fails Decryption
*For any* encrypted device keys, decrypting with a different passphrase SHALL fail with an error.
**Validates: Requirements 5.7**

### Property 18: Profile Isolation
*For any* two profiles, they SHALL have independent device keys and cannot access each other's keys.
**Validates: Requirements 5.6**

### Property 19: Concurrent Modification Detection
*For any* two concurrent writes to the same file, the second write SHALL detect the conflict via SHA mismatch.
**Validates: Requirements 6.4**

### Property 20: Cache Invalidation on Write
*For any* cached data, performing a write operation SHALL invalidate the cache for affected paths.
**Validates: Requirements 6.6**

### Property 21: PDK Wrap-Unwrap Roundtrip
*For any* PDK and device public key, wrapping then unwrapping with the corresponding private key SHALL recover the original PDK.
**Validates: Requirements 7.2**

### Property 22: Member Addition Wraps to All Devices
*For any* member addition, the current PDK SHALL be wrapped to all of the member's active devices.
**Validates: Requirements 7.3**

### Property 23: Member Removal Excludes Devices
*For any* member removal, the new PDK version SHALL NOT contain wrapped PDKs for the removed member's devices.
**Validates: Requirements 7.4**

### Property 24: Unwrap Without Wrapped PDK Fails
*For any* device without a wrapped PDK in a PDK version, attempting to unwrap SHALL fail with AccessDenied.
**Validates: Requirements 7.5**

### Property 25: Profile Switch Clears PDK Cache
*For any* cached PDK, switching profiles SHALL clear the cache.
**Validates: Requirements 7.7**

### Property 26: Secret Serialization Key Sorting
*For any* secret entries, serialization SHALL sort entries by key alphabetically.
**Validates: Requirements 8.1**

### Property 27: Content Hash Verification
*For any* encrypted version, the content_hash SHALL equal BLAKE3(plaintext).
**Validates: Requirements 8.2**

### Property 28: AAD Construction
*For any* version encryption, AAD SHALL be constructed as project_id || set_id || version_number || pdk_version.
**Validates: Requirements 8.3**

### Property 29: Version Signature Verification
*For any* version, the signature SHALL verify using the creator's Ed25519 public key.
**Validates: Requirements 8.4**

### Property 30: Tampering Breaks Verification
*For any* version, tampering with ciphertext, content_hash, chain_hash, or signature SHALL cause verification to fail.
**Validates: Requirements 8.5**

### Property 31: Size Limit Enforcement
*For any* secret set exceeding 10MB plaintext, the system SHALL reject it.
**Validates: Requirements 8.7**

### Property 32: Owner Has All Permissions
*For any* operation, a user with Owner role SHALL have all permissions.
**Validates: Requirements 9.2**

### Property 33: Admin Permission Set
*For any* operation, a user with Admin role SHALL have read, write, share, rotate permissions and NOT delete_project or transfer_ownership.
**Validates: Requirements 9.3**

### Property 34: Member Permission Set
*For any* operation, a user with Member role SHALL have read, write permissions and NOT share, rotate, delete_project, or transfer_ownership.
**Validates: Requirements 9.4**

### Property 35: Reader Permission Set
*For any* operation, a user with Reader role SHALL have read permission only.
**Validates: Requirements 9.5**

### Property 36: Add Member Permission Check
*For any* member addition, the actor SHALL have share permission and target role level SHALL be <= actor's role level.
**Validates: Requirements 9.6**

### Property 37: Remove Member Triggers Rotation
*For any* member removal, the system SHALL rotate the PDK and exclude the removed member's devices.
**Validates: Requirements 9.7**

### Property 38: Membership Signature Verification
*For any* members.json file, the signature SHALL verify using the signer's Ed25519 public key.
**Validates: Requirements 9.8**

### Property 39: Policy-Based Rotation Trigger
*For any* member removal when rotate_on_member_remove is true, the system SHALL automatically rotate the PDK.
**Validates: Requirements 10.1**

### Property 40: Device Revocation Triggers Rotation
*For any* device revocation, the system SHALL mark it as Revoked and trigger PDK rotation for affected projects.
**Validates: Requirements 10.2**

### Property 41: PDK Rotation Increments Version
*For any* PDK rotation, the new version number SHALL be previous version + 1.
**Validates: Requirements 10.3**

### Property 42: Rotation Creates Audit Record
*For any* PDK rotation, an audit event SHALL be created with reason, excluded devices, and timestamp.
**Validates: Requirements 10.4**

### Property 43: Age-Based Rotation Enforcement
*For any* PDK older than max_age_days, the system SHALL require rotation before creating new secret versions.
**Validates: Requirements 10.5**

### Property 44: Revoked Entities Cannot Decrypt New Versions
*For any* revoked device, it SHALL NOT be able to unwrap PDKs from versions created after revocation.
**Validates: Requirements 10.6**

### Property 45: Historical Versions Remain Decryptable
*For any* old secret version, it SHALL remain decryptable using the PDK version it was encrypted with.
**Validates: Requirements 10.7**

### Property 46: Mutating Operations Create Audit Events
*For any* mutating operation, a signed audit event SHALL be created.
**Validates: Requirements 13.1**

### Property 47: Audit Hash Chain Computation
*For any* audit event, chain_hash SHALL equal BLAKE3(previous_chain_hash || canonical_json(event_data)).
**Validates: Requirements 13.2**

### Property 48: Audit Event Signature Verification
*For any* audit event, the signature SHALL verify using the actor's Ed25519 public key.
**Validates: Requirements 13.3**

### Property 49: Audit Verification Detects Tampering
*For any* tampered audit event, verification SHALL detect the tampering and report the specific event.
**Validates: Requirements 13.5, 13.6**

### Property 50: Audit Export Format Validity
*For any* audit export, the output SHALL be valid JSON, CSV, or syslog format as specified.
**Validates: Requirements 13.7**

### Property 51: Dotenv Parse Roundtrip
*For any* valid dotenv file, parsing then formatting SHALL produce equivalent key-value pairs.
**Validates: Requirements 16.1**

### Property 52: JSON Parse Roundtrip
*For any* valid JSON secret object, parsing then formatting SHALL produce equivalent key-value pairs.
**Validates: Requirements 16.2**

### Property 53: Export Format Validity
*For any* secret entries, exporting to dotenv, JSON, shell, or YAML SHALL produce valid output in that format.
**Validates: Requirements 16.3, 16.4, 16.5, 16.6**

### Property 54: Format Auto-Detection
*For any* file with extension .env, .json, .sh, or .yaml, the system SHALL correctly detect the format.
**Validates: Requirements 16.7**

### Property 55: Integrity Verification Completeness
*For any* project, verification SHALL check all signatures, content hashes, and hash chains.
**Validates: Requirements 19.1, 19.2, 19.3, 19.4, 19.5, 19.6**

## Error Handling

### Error Types

**CryptoError** (myc-crypto)
- `DecryptionFailed`: AEAD authentication failed or PDK unwrap failed
- `InvalidSignature`: Ed25519 signature verification failed
- `InvalidKeyLength`: Key material has wrong size
- `RandomnessFailure`: OS RNG unavailable (fatal)

**CoreError** (myc-core)
- `ValidationError`: Entity validation failed (invalid name, future timestamp, etc.)
- `SerializationError`: JSON serialization/deserialization failed
- `HashMismatch`: Content hash doesn't match computed hash
- `ChainBroken`: Hash chain verification failed
- `SignatureInvalid`: Signature verification failed
- `VersionNotFound`: Requested version doesn't exist
- `SizeLimitExceeded`: Plaintext exceeds maximum size

**GitHubError** (myc-github)
- `Unauthorized`: Token expired or revoked (401)
- `Forbidden`: Rate limited or insufficient permissions (403)
- `NotFound`: Repository or file not found (404)
- `Conflict`: SHA mismatch, concurrent modification (409)
- `ValidationError`: GitHub API validation error (422)
- `NetworkError`: Connection failed or timeout

**VaultError** (myc-cli)
- `AccessDenied`: User lacks required permission
- `DeviceNotAuthorized`: No wrapped PDK for device
- `ProfileNotFound`: Profile doesn't exist
- `VaultNotInitialized`: Vault structure not found
- `ConcurrentModification`: Conflict detected, retry needed

### Error Handling Strategy

**Crypto Errors**: Never expose key material in error messages. Use constant-time comparisons for MACs and signatures. Zeroize sensitive data even in error paths.

**Network Errors**: Implement exponential backoff with jitter for retries. Track GitHub rate limits and proactively back off. Provide clear guidance on transient vs permanent failures.

**Validation Errors**: Provide specific feedback on what failed validation and how to fix it. Include examples of valid input.

**Conflict Errors**: Detect concurrent modifications via SHA mismatches. Suggest pulling latest changes and retrying. Support automatic retry with fresh SHA for idempotent operations.

**Permission Errors**: Clearly state which permission is required and which role has it. Suggest who can grant access (e.g., "Ask a project admin to run: myc share add project yourname").

## Testing Strategy

### Unit Testing

Unit tests verify specific examples, edge cases, and error conditions. They complement property tests by catching concrete bugs.

**Crypto Module Tests**:
- Test vectors for AEAD, signatures, KDF, hashing
- Edge cases: empty input, maximum size input
- Error cases: wrong key, tampered ciphertext, invalid signature
- Zeroization: verify types implement Zeroize traits

**Core Module Tests**:
- Serialization roundtrips for all types
- Validation edge cases: empty names, max length, future timestamps
- Canonical JSON: verify determinism and key sorting
- Error cases: invalid UUIDs, negative version numbers

**GitHub Module Tests**:
- Mock API responses for success and error cases
- OAuth flow state machine
- OIDC token validation with test JWTs
- Rate limit tracking and backoff

**CLI Module Tests**:
- Command parsing with clap
- Profile management operations
- Output formatting (human and JSON)
- Error message generation

### Property-Based Testing

Property tests verify universal properties that should hold across all inputs. We use `proptest` for Rust.

**Configuration**: Each property test runs a minimum of 100 iterations to ensure good coverage of the input space.

**Tagging**: Each property test is tagged with a comment explicitly referencing the correctness property in the design document:
```rust
// Feature: mycelium-cli, Property 1: Encryption Roundtrip
#[proptest]
fn test_encryption_roundtrip(plaintext: Vec<u8>) {
    // ...
}
```

**Key Properties to Test**:
- Encryption/decryption roundtrips (Property 1)
- Signature roundtrips (Property 3)
- Serialization roundtrips (Properties 10, 11, 12)
- Hash chain integrity (Property 8)
- PDK wrap/unwrap roundtrips (Property 21)
- Validation rejects invalid inputs (Properties 13, 14)
- Permission checks enforce constraints (Properties 32-37)

**Generators**: Write smart generators that constrain to valid input spaces:
- Valid UUIDs, not arbitrary strings
- Timestamps in reasonable ranges, not far future
- Names within length limits
- Keys with correct sizes

### Integration Testing

Integration tests verify end-to-end flows with real components (but mocked GitHub):

**Vault Lifecycle**:
- Initialize vault → create project → create secret set → push secrets → pull secrets
- Verify all files created with correct structure
- Verify signatures and hash chains

**Membership Flows**:
- Add member → verify PDK wrapped to their devices
- Remove member → verify PDK rotated and excluded
- Change role → verify permissions updated

**Recovery Flows**:
- Enroll multiple devices → lose one → still access secrets
- Set recovery contacts → lose all devices → recover via contact

**CI Flows**:
- Mock OIDC token → enroll CI device → pull secrets
- Verify CI device has correct permissions and expiry

### Test Organization

```
crates/
├── myc-crypto/
│   ├── src/
│   │   ├── aead.rs
│   │   └── aead/tests.rs          # Unit tests
│   └── tests/
│       └── crypto_properties.rs    # Property tests
├── myc-core/
│   ├── src/
│   │   ├── secret_set.rs
│   │   └── secret_set/tests.rs    # Unit tests
│   └── tests/
│       └── core_properties.rs      # Property tests
├── myc-github/
│   └── tests/
│       └── github_integration.rs   # Integration tests with mocks
└── myc-cli/
    └── tests/
        ├── vault_lifecycle.rs      # End-to-end integration tests
        ├── membership_flows.rs
        └── recovery_flows.rs
```

## Security Considerations

### Threat Model

**Threat: GitHub Insider or Breach**
- Mitigation: All secrets encrypted client-side; GitHub sees only ciphertext
- Residual Risk: Metadata leakage (project names, member count, access patterns)

**Threat: Network MITM**
- Mitigation: TLS to GitHub API; signed mutations; client verification
- Residual Risk: None if TLS is secure

**Threat: Malicious Collaborator**
- Mitigation: Signature verification; hash chains; unsigned data rejected
- Residual Risk: Collaborator can delete repository (GitHub-level access control)

**Threat: Removed Member**
- Mitigation: PDK rotation; new versions use new PDK
- Residual Risk: Historical access (they already decrypted old versions)

**Threat: Stolen OAuth Token**
- Mitigation: Token alone insufficient—need device private key for decryption
- Residual Risk: Can read ciphertext and metadata

**Threat: Device Compromise**
- Mitigation: Device revocation; PDK rotation; forward secrecy
- Residual Risk: Attacker has access to secrets decrypted before revocation

**Threat: Weak Passphrase**
- Mitigation: Argon2id with high cost parameters; warn on empty passphrase
- Residual Risk: User chooses weak passphrase despite warnings

**Threat: Memory Disclosure**
- Mitigation: Zeroize all secret types on drop; minimize key lifetime
- Residual Risk: Memory dumps before zeroization; swap to disk

### Security Properties

**Confidentiality**: Secrets are confidential against GitHub, network observers, and unauthorized vault members. Confidentiality relies on:
- AEAD encryption (ChaCha20-Poly1305)
- Key wrapping (X25519 + HKDF + AEAD)
- Device key protection (Argon2id + AEAD)

**Integrity**: All data has cryptographic integrity protection:
- Signatures (Ed25519) on all metadata
- AEAD authentication tags on all ciphertext
- Hash chains (BLAKE3) linking versions and audit events

**Authenticity**: All mutations are authenticated:
- Device signatures prove who performed the operation
- Signature verification before accepting any data
- Audit trail of all signed operations

**Forward Secrecy**: Revoked entities cannot access future secrets:
- PDK rotation on member removal or device revocation
- New PDK not wrapped to revoked entities
- Historical access unavoidable (they already had the key)

**Auditability**: All operations are auditable:
- Signed audit events for all mutations
- Hash-chained audit log detects tampering
- Export for compliance systems

### Cryptographic Assumptions

- ChaCha20-Poly1305 is IND-CCA2 secure
- X25519 provides 128-bit security against ECDLP
- Ed25519 provides 128-bit security against forgery
- HKDF-SHA256 is a secure KDF
- BLAKE3 is collision-resistant
- OS CSPRNG provides secure randomness

### Key Management

**Device Keys**:
- Generated locally, never transmitted
- Encrypted at rest with Argon2id-derived key
- Zeroized on drop
- Revocable via device revocation

**PDKs**:
- Generated with OS CSPRNG
- Never stored unwrapped on disk
- Cached in memory only
- Rotated on membership changes

**Passphrases**:
- User-chosen, optional
- Used to derive key encryption key via Argon2id
- Not stored anywhere
- Prompted on each operation (or from env var in CI)

## Performance Considerations

### Optimization Strategies

**Caching**: Cache device registry, project metadata, and PDK versions locally. Invalidate on write or after TTL (5 minutes).

**Parallelization**: Wrap PDKs to multiple devices in parallel. Verify signatures in parallel.

**Streaming**: Stream large secret sets during encryption/decryption to avoid loading entire set in memory.

**Incremental Verification**: Support verifying only new versions since last checkpoint.

**Lazy Loading**: Load PDK versions and secret versions on demand, not eagerly.

### Performance Targets

- Encrypt/decrypt typical secret set (< 100 entries): < 100ms
- Pull secrets with warm cache: < 500ms
- Pull secrets with cold cache: < 2s (network dependent)
- Push secrets: < 3s (network dependent)
- Add member (wrap to 5 devices): < 500ms
- Rotate PDK (wrap to 20 devices): < 2s
- Verify project integrity: < 5s for typical project

### Scalability Limits

- Max secret set size: 10MB plaintext
- Max entries per set: 10,000
- Max devices per user: 100
- Max members per project: 1,000
- Max projects per org: 10,000
- Max versions per set: unlimited (append-only)

## Deployment and Operations

### Installation

**Binary Distribution**:
- Pre-built binaries for Linux, macOS, Windows
- Distributed via GitHub Releases
- Install script: `curl -sSL https://get.mycelium.dev | sh`

**Package Managers**:
- Homebrew: `brew install mycelium`
- Cargo: `cargo install myc`
- APT/YUM: Future consideration

### Configuration

**Global Config** (`~/.config/mycelium/config.json`):
```json
{
  "default_profile": "work",
  "json_output": false,
  "color": "auto"
}
```

**Profile Config** (`~/.config/mycelium/profiles/<name>/profile.json`):
```json
{
  "name": "work",
  "github_owner": "myorg",
  "github_repo": "secrets-vault",
  "github_user_id": 12345678,
  "github_username": "alice",
  "device_id": "660e8400-e29b-41d4-a716-446655440001",
  "created_at": "2025-12-05T14:30:00Z"
}
```

**Project Config** (`.myc.yaml` in repo root):
```yaml
vault: myorg/secrets-vault
project: api
set: production
export_format: dotenv
output_file: .env
```

### Monitoring

**Metrics to Track**:
- GitHub API rate limit usage
- Cache hit/miss rates
- Operation latencies
- Error rates by type

**Logging**:
- Use `tracing` crate for structured logging
- Log levels: ERROR, WARN, INFO, DEBUG, TRACE
- Controlled by `--verbose` flag or `RUST_LOG` env var
- Never log secret values or key material

### Backup and Recovery

**Backup Strategy**:
- Vault data is in Git: use Git backup strategies
- Device keys: user responsible for backup (or multi-device enrollment)
- Recommend org-level GitHub repository backup policies

**Recovery Scenarios**:
- Lost device: Use second device or recovery contacts
- Lost all devices: Use recovery contacts or org recovery key
- Corrupted vault: Restore from Git history
- Deleted repository: Restore from GitHub backup or local clone

## Future Enhancements

### Phase 2 Features

**GitHub Organizations & Teams Integration** (RFC-0020):
- Map GitHub Teams to Mycelium project membership
- Automatic membership sync
- Org-level OAuth Apps

**GitHub Webhooks & Notifications** (RFC-0021):
- Real-time notifications on secret changes
- Webhook-triggered rotation
- Slack/email notifications

**Cross-Repository Secret Sharing** (RFC-0022):
- Share secrets across multiple repos
- Centralized secret management
- Namespace isolation

### Long-Term Vision

**Hardware Security Key Support**:
- YubiKey, TPM, Secure Enclave integration
- Hardware-backed device keys
- FIDO2 authentication

**Metadata Privacy**:
- Encrypt project names, set names
- Obfuscate access patterns
- PIR/ORAM for metadata queries

**Advanced Rotation Policies**:
- Time-based rotation schedules
- Compliance-driven rotation
- Multi-party approval for rotation

**Secret Templating**:
- Template secrets with variables
- Environment-specific overrides
- Inheritance and composition

**Web UI**:
- Read-only web interface for viewing secrets
- Audit log visualization
- Membership management UI

## Appendix

### Glossary

See Requirements Document for complete glossary.

### References

- RFC-0001: Project Structure & Crate Architecture
- RFC-0002: Cryptographic Primitives Layer
- RFC-0003: Core Data Model & Serialization
- RFC-0004: Device Identity & Local Key Storage
- RFC-0005: GitHub Backend Protocol
- RFC-0006: Envelope Encryption & PDK Lifecycle
- RFC-0007: Secret Set Encryption & Versioning
- RFC-0008: Membership & Access Control
- RFC-0009: Key Rotation & Revocation
- RFC-0010: CLI Architecture & Command Surface
- RFC-0011: GitHub Actions CI Integration
- RFC-0012: Audit Log & Integrity Verification
- RFC-0013: Key Recovery & Account Continuity
- RFC-0014: CLI User Experience & Quick Start

### Cryptographic Specifications

- ChaCha20-Poly1305: RFC 8439
- X25519: RFC 7748
- Ed25519: RFC 8032
- HKDF: RFC 5869
- BLAKE3: https://github.com/BLAKE3-team/BLAKE3-specs
- Argon2: RFC 9106

### External Dependencies

See RFC-0001 for complete dependency list and versions.
