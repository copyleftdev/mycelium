# Implementation Plan

## Phase 1: Foundation - Project Structure and Crypto Primitives

- [x] 1. Set up Cargo workspace and project structure
  - Create workspace root Cargo.toml with member crates
  - Set up crate directories: myc-crypto, myc-core, myc-github, myc-cli, myc-test-utils
  - Configure workspace-wide dependencies and settings
  - Set up CI configuration (.github/workflows/ci.yml)
  - Configure cargo-deny, cargo-audit, and cargo-vet
  - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 22.1, 22.2, 22.3, 22.4_

- [x] 2. Implement cryptographic primitives layer (myc-crypto)
- [x] 2.1 Implement AEAD module (ChaCha20-Poly1305)
  - Define AeadKey type with Zeroize and ZeroizeOnDrop
  - Implement encrypt function with random nonce generation
  - Implement decrypt function with nonce parsing
  - Define Nonce type and constants (NONCE_SIZE, TAG_SIZE)
  - _Requirements: 3.1, 3.5_

- [x] 2.2 Write property test for AEAD encryption
  - **Property 1: Encryption Roundtrip**
  - **Validates: Requirements 3.1, 3.3**

- [x] 2.3 Write property test for AEAD structure
  - **Property 2: Encryption Produces Correct Structure**
  - **Validates: Requirements 3.1**

- [x] 2.4 Implement key exchange module (X25519)
  - Define X25519SecretKey and X25519PublicKey types
  - Implement generate_x25519_keypair function
  - Implement diffie_hellman function
  - Define SharedSecret type with Zeroize
  - _Requirements: 3.2_

- [x] 2.5 Implement signature module (Ed25519)
  - Define Ed25519SecretKey and Ed25519PublicKey types
  - Implement generate_ed25519_keypair function
  - Implement sign function
  - Implement verify function
  - _Requirements: 3.3_

- [x] 2.6 Write property tests for signatures
  - **Property 3: Signature Roundtrip**
  - **Property 4: Tampering Detection**
  - **Validates: Requirements 3.3**

- [x] 2.7 Implement KDF module (HKDF-SHA256)
  - Implement derive_key function
  - Implement derive_aead_key convenience function
  - _Requirements: 3.2, 3.7_

- [x] 2.8 Write property tests for KDF
  - **Property 5: KDF Determinism**
  - **Property 6: KDF Domain Separation**
  - **Validates: Requirements 3.2, 3.7**

- [x] 2.9 Implement hash module (BLAKE3)
  - Implement hash function
  - Implement chain_hash function
  - Define HashOutput type
  - Implement Hasher for streaming
  - _Requirements: 3.4_

- [x] 2.10 Write property tests for hashing
  - **Property 7: Hash Determinism**
  - **Property 8: Hash Chain Integrity**
  - **Validates: Requirements 3.4, 8.2**

- [x] 2.11 Implement random module
  - Implement fill_random function using getrandom
  - Implement generate_random_bytes function
  - _Requirements: 3.6_

- [x] 2.12 Implement crypto error types
  - Define CryptoError enum with variants
  - Implement Display and Error traits
  - _Requirements: 3.1, 3.2, 3.3_

- [x] 2.13 Write unit tests for crypto error cases
  - Test decryption with wrong key
  - Test signature verification with tampered message
  - Test invalid key lengths
  - _Requirements: 3.1, 3.3_


## Phase 2: Core Domain Model and Serialization

- [x] 3. Implement core data model (myc-core)
- [x] 3.1 Implement identifier types
  - Define OrgId, ProjectId, SecretSetId, DeviceId as UUID wrappers
  - Define UserId as String wrapper
  - Define VersionNumber as u64 wrapper
  - Implement serde serialization for all ID types
  - _Requirements: 4.1_

- [x] 3.2 Write property test for UUID uniqueness
  - **Property 9: UUID Uniqueness**
  - **Validates: Requirements 4.1**

- [x] 3.3 Implement Org and OrgSettings types
  - Define Org struct with schema_version, id, name, created_at, settings
  - Define OrgSettings struct
  - Implement serde serialization
  - Implement validation methods
  - _Requirements: 4.2, 4.3, 4.5_

- [x] 3.4 Implement Project and ProjectMember types
  - Define Project struct
  - Define ProjectMember struct
  - Define Role enum (Owner, Admin, Member, Reader)
  - Implement permission checking logic
  - _Requirements: 4.2, 4.3, 9.1_

- [x] 3.5 Implement SecretSet and SecretSetVersion types
  - Define SecretSet struct
  - Define SecretSetVersion struct
  - Define SecretEntry and EntryMetadata structs
  - Implement serde serialization
  - _Requirements: 4.2, 4.3_

- [x] 3.6 Implement Device types
  - Define Device struct
  - Define DeviceType enum (Interactive, CI)
  - Define DeviceStatus enum (Active, PendingApproval, Revoked)
  - Implement serde serialization
  - _Requirements: 4.2, 4.3_

- [x] 3.7 Implement PDK types
  - Define PdkVersion struct
  - Define WrappedPdk struct
  - Define RotationPolicy struct
  - Implement serde serialization
  - _Requirements: 4.2, 4.3_

- [x] 3.8 Implement canonical JSON serialization
  - Implement to_canonical_json function with sorted keys
  - Implement sign_payload function
  - Implement verify_payload function
  - _Requirements: 4.4_

- [x] 3.9 Write property tests for serialization
  - **Property 10: Schema Version Presence**
  - **Property 11: Serialization Format Compliance**
  - **Property 12: Canonical JSON Determinism**
  - **Validates: Requirements 4.2, 4.3, 4.4, 8.1**

- [x] 3.10 Implement validation logic
  - Implement validate methods for all types
  - Check name length and character constraints
  - Check timestamp validity (not in future)
  - Check version number constraints
  - _Requirements: 4.5_

- [x] 3.11 Write property tests for validation
  - **Property 13: Validation Rejects Invalid Names**
  - **Property 14: Validation Rejects Future Timestamps**
  - **Validates: Requirements 4.5**

- [x] 3.12 Implement version number management
  - Implement version increment logic
  - Ensure monotonicity
  - _Requirements: 4.6_

- [x] 3.13 Write property test for version monotonicity
  - **Property 15: Version Number Monotonicity**
  - **Validates: Requirements 4.6**

- [x] 3.14 Implement core error types
  - Define CoreError enum
  - Define ValidationError enum
  - Implement Display and Error traits
  - _Requirements: 4.5_


## Phase 3: Device Identity and Local Storage

- [x] 4. Implement device identity and local key storage
- [x] 4.1 Implement key encryption at rest
  - Implement Argon2id key derivation from passphrase
  - Define encrypted key file format (magic, version, salt, nonce, ciphertext)
  - Implement save_encrypted_key function
  - Implement load_encrypted_key function
  - _Requirements: 5.2_

- [x] 4.2 Write property test for key encryption roundtrip
  - **Property 16: Device Key Encryption Roundtrip**
  - **Validates: Requirements 5.2**

- [x]* 4.3 Write property test for wrong passphrase
  - **Property 17: Wrong Passphrase Fails Decryption**
  - **Validates: Requirements 5.7**

- [x] 4.4 Implement profile management
  - Define Profile struct
  - Implement ProfileManager with list, get, create, delete operations
  - Implement default profile management
  - Ensure proper file permissions (0600 for keys, 0700 for directories)
  - _Requirements: 5.5, 5.6_

- [x] 4.5 Write property test for profile isolation
  - **Property 18: Profile Isolation**
  - **Validates: Requirements 5.6**

- [x] 4.6 Implement device key operations
  - Implement load_signing_key function
  - Implement load_encryption_key function
  - Implement save_keypair function
  - Ensure keys are zeroized after use
  - _Requirements: 5.1, 5.2_

- [x] 4.7 Implement device enrollment flow
  - Generate Ed25519 and X25519 keypairs
  - Prompt for optional passphrase
  - Encrypt and save keys to disk
  - Create profile and device metadata files
  - _Requirements: 5.1, 5.2, 5.3_

- [x] 4.8 Implement global configuration
  - Define GlobalConfig struct
  - Implement load and save functions
  - Support default_profile, json_output, color settings
  - _Requirements: 5.5_

- [x] 4.9 Implement CI headless mode support
  - Read MYC_KEY_PASSPHRASE from environment
  - Support MYC_NON_INTERACTIVE mode
  - Support MYC_PROFILE environment variable
  - _Requirements: 5.4_

- [x] 4.10 Write unit tests for profile operations
  - Test profile creation and deletion
  - Test default profile switching
  - Test file permission setting on Unix
  - _Requirements: 5.3, 5.5, 5.6_


## Phase 4: GitHub Backend Integration

- [ ] 5. Implement GitHub API client (myc-github)
- [x] 5.1 Implement GitHub client core
  - Set up octocrab client with authentication
  - Implement read_file operation
  - Implement write_file operation with SHA-based concurrency
  - Implement list_directory operation
  - _Requirements: 6.2, 6.4_

- [x] 5.2 Write property test for concurrent modification detection
  - **Property 19: Concurrent Modification Detection**
  - **Validates: Requirements 6.4**

- [x] 5.3 Implement repository operations
  - Implement create_repository operation
  - Implement check_access operation
  - Handle repository not found errors
  - _Requirements: 6.1_

- [x] 5.4 Implement rate limiting
  - Track rate limit headers from GitHub responses
  - Implement backoff when approaching limit
  - Provide clear error messages when rate limited
  - _Requirements: 6.5_

- [x] 5.5 Implement OAuth device flow
  - Define OAuthDeviceFlow struct
  - Implement start function (request device code)
  - Implement poll function (poll for access token)
  - Implement get_user_info function
  - _Requirements: 6.3_

- [x] 5.6 Implement OIDC validation for GitHub Actions
  - Define OidcValidator struct
  - Implement validate_token function
  - Parse and validate JWT claims
  - Extract repository, workflow, ref, actor, environment
  - _Requirements: 12.1, 12.2_

- [x] 5.7 Implement GitHub error handling
  - Define GitHubError enum
  - Map HTTP status codes to error types
  - Provide actionable error messages
  - _Requirements: 20.1, 20.2, 20.3, 20.4_

- [x] 5.8 Implement local caching
  - Implement cache storage in profile directory
  - Implement cache invalidation on write
  - Implement TTL-based invalidation (5 minutes)
  - _Requirements: 6.6_

- [x] 5.9 Write property test for cache invalidation
  - **Property 20: Cache Invalidation on Write**
  - **Validates: Requirements 6.6**

- [x] 5.10 Write unit tests for GitHub client
  - Mock GitHub API responses
  - Test error handling for each status code
  - Test rate limit tracking
  - _Requirements: 6.2, 6.4, 6.5_


## Phase 5: Envelope Encryption and PDK Management

- [x] 6. Implement PDK lifecycle management
- [x] 6.1 Implement PDK generation
  - Generate 32-byte random PDK
  - Wrap in AeadKey type
  - Assign version number
  - _Requirements: 7.1_

- [x] 6.2 Implement PDK wrapping (ECIES-style)
  - Generate ephemeral X25519 keypair
  - Compute shared secret via Diffie-Hellman
  - Derive wrap key using HKDF with domain separation
  - Encrypt PDK with derived key
  - Return WrappedPdk with ephemeral pubkey and ciphertext
  - _Requirements: 7.2_

- [x] 6.3 Write property test for PDK wrap-unwrap roundtrip
  - **Property 21: PDK Wrap-Unwrap Roundtrip**
  - **Validates: Requirements 7.2**

- [x] 6.4 Implement PDK unwrapping
  - Find WrappedPdk for device
  - Compute shared secret using device secret key and ephemeral pubkey
  - Derive wrap key using HKDF
  - Decrypt PDK
  - Return AeadKey
  - _Requirements: 7.2, 7.5_

- [x] 6.5 Write property test for unwrap without wrapped PDK
  - **Property 24: Unwrap Without Wrapped PDK Fails**
  - **Validates: Requirements 7.5**

- [x] 6.6 Implement PDK versioning
  - Create PdkVersion records
  - Store at .mycelium/projects/<id>/pdk/v<N>.json
  - Track current_pdk_version in Project
  - _Requirements: 7.6_

- [x] 6.7 Implement member addition with PDK wrapping
  - Get current PDK version
  - Unwrap PDK using admin's device key
  - Get new member's active devices
  - Wrap PDK to each device
  - Append wrapped PDKs to PdkVersion
  - Update members.json
  - Sign and commit
  - _Requirements: 7.3_

- [x] 6.8 Write property test for member addition
  - **Property 22: Member Addition Wraps to All Devices**
  - **Validates: Requirements 7.3**

- [x] 6.9 Implement PDK rotation
  - Generate new PDK
  - Increment version number
  - Get authorized devices (excluding removed members)
  - Wrap new PDK to authorized devices
  - Create PdkVersion record with reason
  - Update project.current_pdk_version
  - Sign and commit
  - _Requirements: 7.4, 10.3_

- [x] 6.10 Write property test for member removal
  - **Property 23: Member Removal Excludes Devices**
  - **Validates: Requirements 7.4**

- [x] 6.11 Implement PDK caching
  - Cache unwrapped PDKs in memory only
  - Clear cache on profile switch
  - Ensure PDKs are zeroized
  - _Requirements: 7.7_

- [x] 6.12 Write property test for cache clearing
  - **Property 25: Profile Switch Clears PDK Cache**
  - **Validates: Requirements 7.7**


## Phase 6: Secret Set Encryption and Versioning

- [x] 7. Implement secret set operations
- [x] 7.1 Implement secret serialization
  - Sort entries by key alphabetically
  - Serialize to canonical JSON
  - _Requirements: 8.1_

- [x] 7.2 Write property test for key sorting
  - **Property 26: Secret Serialization Key Sorting**
  - **Validates: Requirements 8.1**

- [x] 7.3 Implement secret encryption
  - Serialize entries to canonical JSON
  - Compute content_hash = BLAKE3(plaintext)
  - Compute chain_hash = BLAKE3(previous_chain_hash || content_hash)
  - Get current PDK
  - Generate random nonce
  - Construct AAD = project_id || set_id || version_number || pdk_version
  - Encrypt with PDK using AEAD
  - _Requirements: 8.2, 8.3_

- [x] 7.4 Write property tests for hashing and AAD
  - **Property 27: Content Hash Verification**
  - **Property 28: AAD Construction**
  - **Validates: Requirements 8.2, 8.3**

- [x] 7.5 Implement version metadata signing
  - Create metadata structure
  - Serialize to canonical JSON
  - Sign with device Ed25519 key
  - Store signature in metadata
  - _Requirements: 8.4_

- [x] 7.6 Write property test for signature verification
  - **Property 29: Version Signature Verification**
  - **Validates: Requirements 8.4**

- [x] 7.7 Implement secret decryption
  - Read version metadata
  - Get PDK version number
  - Unwrap PDK
  - Parse nonce from ciphertext
  - Construct AAD
  - Decrypt with PDK
  - Verify content_hash
  - Verify hash chain
  - Verify signature
  - Parse JSON and return entries
  - _Requirements: 8.5_

- [x] 7.8 Write property test for tampering detection
  - **Property 30: Tampering Breaks Verification**
  - **Validates: Requirements 8.5**

- [x] 7.9 Implement size limit enforcement
  - Check total plaintext size before encryption
  - Reject if exceeds 10MB
  - Check entry count (max 10,000)
  - Check key and value lengths
  - _Requirements: 8.7_

- [x] 7.10 Write property test for size limits
  - **Property 31: Size Limit Enforcement**
  - **Validates: Requirements 8.7**

- [x] 7.11 Implement version storage
  - Store ciphertext at .mycelium/projects/<pid>/sets/<sid>/v<N>.enc
  - Store metadata at .mycelium/projects/<pid>/sets/<sid>/v<N>.meta.json
  - Update set.current_version
  - _Requirements: 8.6_

- [x] 7.12 Implement version operations
  - Implement create_version function
  - Implement read_version function
  - Implement read_latest function
  - Implement list_versions function
  - Implement verify_chain function
  - _Requirements: 8.2, 8.5_


## Phase 7: Membership and Access Control

- [x] 8. Implement membership and permission system
- [x] 8.1 Implement role permission mapping
  - Define permission sets for each role
  - Owner: all permissions
  - Admin: read, write, share, rotate
  - Member: read, write
  - Reader: read
  - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5_

- [x] 8.2 Write property tests for role permissions
  - **Property 32: Owner Has All Permissions**
  - **Property 33: Admin Permission Set**
  - **Property 34: Member Permission Set**
  - **Property 35: Reader Permission Set**
  - **Validates: Requirements 9.2, 9.3, 9.4, 9.5**

- [x] 8.3 Implement permission checking
  - Implement check_permission function
  - Read members.json
  - Verify signature
  - Find actor's membership entry
  - Check if required permission is in role's permission set
  - _Requirements: 9.6_

- [x] 8.4 Write property test for add member permission check
  - **Property 36: Add Member Permission Check**
  - **Validates: Requirements 9.6**

- [x] 8.4 Implement add member operation
  - Verify actor has share permission
  - Verify target role level <= actor's role level
  - Look up target user's active devices
  - Get current PDK version
  - Unwrap PDK using actor's device key
  - Wrap PDK to each target device
  - Append wrapped PDKs to PdkVersion
  - Add member entry to members.json
  - Sign both files
  - Commit to GitHub
  - Create audit event
  - _Requirements: 9.6, 9.7_

- [x] 8.5 Implement remove member operation
  - Verify actor has share permission
  - Verify target role level < actor's role level
  - Remove member entry from members.json
  - Trigger PDK rotation
  - Wrap new PDK only to remaining members
  - Sign and commit
  - Create audit event
  - _Requirements: 9.7_

- [x] 8.6 Write property test for remove member
  - **Property 37: Remove Member Triggers Rotation**
  - **Validates: Requirements 9.7**

- [x] 8.7 Implement change role operation
  - Verify preconditions
  - Update role in members.json
  - Sign and commit
  - Create audit event
  - _Requirements: 9.6_

- [x] 8.8 Implement transfer ownership operation
  - Verify actor is current owner
  - Verify target is current admin
  - Set target's role to owner
  - Set actor's role to admin
  - Sign and commit
  - Create audit event
  - _Requirements: 9.2_

- [x] 8.9 Implement membership signature verification
  - Verify signature on members.json
  - Check signer had share permission at signing time
  - _Requirements: 9.8_

- [x] 8.10 Write property test for membership signatures
  - **Property 38: Membership Signature Verification**
  - **Validates: Requirements 9.8**


## Phase 8: Key Rotation and Revocation

- [x] 9. Implement rotation and revocation
- [x] 9.1 Implement rotation policy checking
  - Check rotate_on_member_remove policy
  - Check rotate_on_device_revoke policy
  - Check max_age_days policy
  - _Requirements: 10.1, 10.2, 10.5_

- [x] 9.2 Write property tests for policy-based rotation
  - **Property 39: Policy-Based Rotation Trigger**
  - **Property 43: Age-Based Rotation Enforcement**
  - **Validates: Requirements 10.1, 10.5**

- [x] 9.3 Implement PDK rotation operation
  - Determine authorized devices
  - Generate new PDK
  - Increment version number
  - Wrap to authorized devices
  - Create PdkVersion record with reason
  - Update project.current_pdk_version
  - Sign and commit
  - Create audit event
  - _Requirements: 10.3, 10.4_

- [x]* 9.4 Write property tests for rotation
  - **Property 40: Device Revocation Triggers Rotation**
  - **Property 41: PDK Rotation Increments Version**
  - **Property 42: Rotation Creates Audit Record**
  - **Validates: Requirements 10.2, 10.3, 10.4**

- [x] 9.5 Implement device revocation
  - Mark device status as Revoked
  - For each project the device's owner is member of: trigger PDK rotation
  - New PDK versions exclude revoked device
  - Create audit event
  - _Requirements: 10.2_

- [x] 9.6 Implement forward secrecy verification
  - Verify revoked entities cannot unwrap new PDK versions
  - Verify historical versions remain decryptable with old PDKs
  - _Requirements: 10.6, 10.7_

- [x]* 9.7 Write property tests for forward secrecy
  - **Property 44: Revoked Entities Cannot Decrypt New Versions**
  - **Property 45: Historical Versions Remain Decryptable**
  - **Validates: Requirements 10.6, 10.7**

- [x] 9.8 Implement rotation reason tracking
  - Support member_removed, device_revoked, policy, manual reasons
  - Store reason in PdkVersion
  - Include in audit events
  - _Requirements: 10.4_

- [x] 9.9 Implement emergency rotation
  - Support immediate rotation regardless of policy
  - Support custom reason and note
  - _Requirements: 10.3_

- [x] 9.10 Implement bulk rotation
  - Iterate all projects
  - Rotate each
  - Report successes and failures
  - _Requirements: 10.3_


## Phase 9: Audit Log and Integrity Verification

- [x] 10. Implement audit logging
- [x] 10.1 Implement audit event structure
  - Define AuditEvent type
  - Support all event types (org, device, project, membership, secret, key, admin)
  - Include event_id, event_type, timestamp, actor, details
  - _Requirements: 13.1_

- [x] 10.2 Write property test for audit event creation
  - **Property 46: Mutating Operations Create Audit Events**
  - **Validates: Requirements 13.1**

- [x] 10.3 Implement audit hash chaining
  - Compute chain_hash = BLAKE3(previous_chain_hash || canonical_json(event_data))
  - Link events via previous_event_id
  - _Requirements: 13.2_

- [x] 10.4 Write property test for audit hash chain
  - **Property 47: Audit Hash Chain Computation**
  - **Validates: Requirements 13.2**

- [x] 10.5 Implement audit event signing
  - Sign canonical JSON of event data
  - Use actor's Ed25519 device key
  - Store signature in event
  - _Requirements: 13.3_

- [x] 10.6 Write property test for audit signatures
  - **Property 48: Audit Event Signature Verification**
  - **Validates: Requirements 13.3**

- [x] 10.7 Implement audit event storage
  - Organize by month: .mycelium/audit/<YYYY-MM>/<event-id>.json
  - Maintain index file with latest event and chain hash
  - _Requirements: 13.4_

- [x] 10.8 Implement audit verification
  - Read all events in order
  - Verify each signature
  - Recompute hash chains
  - Compare with stored hashes
  - Report any mismatches
  - _Requirements: 13.5, 13.6_

- [x] 10.9 Write property tests for audit verification
  - **Property 49: Audit Verification Detects Tampering**
  - **Validates: Requirements 13.5, 13.6**

- [x] 10.10 Implement audit export
  - Support JSON format
  - Support CSV format
  - Support syslog format
  - Support filtering by date, project, user, event type
  - _Requirements: 13.7_

- [x] 10.11 Write property test for audit export
  - **Property 50: Audit Export Format Validity**
  - **Validates: Requirements 13.7**

- [x] 10.12 Implement audit notes
  - Allow manual audit entries
  - Sign with device key
  - Store immutably
  - _Requirements: 13.7_


## Phase 10: Import/Export and Format Support

- [x] 11. Implement secret import and export
- [x] 11.1 Implement dotenv parser
  - Parse KEY=value lines
  - Handle quoted values
  - Skip comments (#)
  - Handle escape sequences
  - _Requirements: 16.1_

- [x] 11.2 Write property test for dotenv roundtrip
  - **Property 51: Dotenv Parse Roundtrip**
  - **Validates: Requirements 16.1**

- [x] 11.3 Implement JSON parser
  - Parse {"KEY": "value"} objects
  - Validate string keys and values
  - _Requirements: 16.2_

- [x] 11.4 Write property test for JSON roundtrip
  - **Property 52: JSON Parse Roundtrip**
  - **Validates: Requirements 16.2**

- [x] 11.5 Implement dotenv formatter
  - Format as KEY=value lines
  - Quote values with spaces or special characters
  - _Requirements: 16.3_

- [x] 11.6 Implement JSON formatter
  - Format as {"KEY": "value"} object
  - Pretty print with indentation
  - _Requirements: 16.4_

- [x] 11.7 Implement shell formatter
  - Format as export KEY='value' lines
  - Proper escaping for shell
  - _Requirements: 16.5_

- [x] 11.8 Implement YAML formatter
  - Format as KEY: value lines
  - Proper YAML escaping
  - _Requirements: 16.6_

- [x]* 11.9 Write property test for export formats
  - **Property 53: Export Format Validity**
  - **Validates: Requirements 16.3, 16.4, 16.5, 16.6**

- [x] 11.10 Implement format auto-detection
  - Detect based on file extension
  - Support .env, .json, .sh, .yaml
  - Allow explicit --format override
  - _Requirements: 16.7_

- [x] 11.11 Write property test for format detection
  - **Property 54: Format Auto-Detection**
  - **Validates: Requirements 16.7**


## Phase 11: CLI Implementation

- [x] 12. Implement CLI structure and commands (myc-cli)
- [x] 12.1 Set up CLI framework with clap
  - Define Cli struct with global options
  - Define Commands enum with all subcommands
  - Implement argument parsing
  - _Requirements: 11.1, 11.2_

- [x] 12.2 Implement profile commands
  - Implement profile add (with device enrollment)
  - Implement profile list
  - Implement profile use
  - Implement profile remove
  - Implement profile show
  - _Requirements: 18.1, 18.2, 18.3, 18.4, 18.7_

- [x] 12.3 Implement org commands
  - Implement org init (vault initialization)
  - Implement org show
  - Implement org settings
  - _Requirements: 6.1_

- [x] 12.4 Implement device commands
  - Implement device list
  - Implement device show
  - Implement device enroll
  - Implement device revoke
  - Implement device approve
  - _Requirements: 10.2_

- [x] 12.5 Implement project commands
  - Implement project create
  - Implement project list
  - Implement project show
  - Implement project delete
  - _Requirements: 7.1_

- [x] 12.6 Implement secret set commands
  - Implement set create
  - Implement set list
  - Implement set show
  - Implement set delete
  - _Requirements: 8.1_

- [x] 12.7 Implement pull command
  - Parse arguments (project, set, options)
  - Read and decrypt secret version
  - Export in specified format
  - Write to file or stdout
  - _Requirements: 8.5, 16.3, 16.4, 16.5, 16.6_

- [x] 12.8 Implement push command
  - Parse arguments (project, set, file, options)
  - Read and parse input file
  - Encrypt and create new version
  - Write to GitHub
  - _Requirements: 8.2, 8.3, 8.4, 16.1, 16.2_

- [x] 12.9 Implement share commands
  - Implement share add
  - Implement share remove
  - Implement share list
  - Implement share set-role
  - _Requirements: 9.6, 9.7_

- [x] 12.10 Implement rotate command
  - Parse arguments (project, reason, note)
  - Trigger PDK rotation
  - Display result
  - _Requirements: 10.3_

- [x] 12.11 Implement versions commands
  - Implement versions list
  - Implement versions show
  - _Requirements: 17.1, 17.2_

- [x] 12.12 Implement diff command
  - Parse arguments (project, set, v1, v2)
  - Decrypt both versions
  - Compute diff (added, removed, changed keys)
  - Display diff
  - _Requirements: 17.3_

- [x] 12.13 Implement verify command
  - Parse arguments (project, set, options)
  - Verify signatures, hashes, chains
  - Report results
  - _Requirements: 19.1, 19.2, 19.3, 19.4, 19.5, 19.6_

- [x] 12.14 Write property test for integrity verification
  - **Property 55: Integrity Verification Completeness**
  - **Validates: Requirements 19.1-19.6**

- [x] 12.15 Implement audit commands
  - Implement audit list
  - Implement audit show
  - Implement audit export
  - Implement audit note
  - _Requirements: 13.7_

- [x] 12.16 Implement CI commands
  - Implement ci enroll (with OIDC support)
  - Implement ci pull
  - _Requirements: 12.1, 12.2, 12.5_

- [x] 12.17 Implement cache commands
  - Implement cache clear
  - Implement cache status
  - _Requirements: 6.6_


## Phase 12: Output Formatting and Error Handling

- [x] 13. Implement output formatting and error handling
- [x] 13.1 Implement human-readable output formatter
  - Colored output with console crate
  - Tables for lists
  - Progress indicators with indicatif
  - Respect NO_COLOR environment variable
  - _Requirements: 11.3, 15.3_

- [x] 13.2 Implement JSON output formatter
  - Format success responses
  - Format error responses
  - Ensure valid JSON
  - _Requirements: 11.3_

- [x] 13.3 Implement interactive prompts
  - Confirmation prompts for destructive actions
  - Password input for passphrases (hidden)
  - Selection lists
  - Progress bars
  - _Requirements: 11.5_

- [x] 13.4 Implement non-interactive mode
  - Check MYC_NON_INTERACTIVE environment variable
  - Fail with exit code 10 if prompt needed
  - _Requirements: 11.6_

- [x] 13.5 Implement error message formatting
  - Actionable error messages (what, why, how to fix)
  - Specific guidance for each error type
  - Examples of correct usage
  - _Requirements: 15.2, 20.1, 20.2, 20.3, 20.4, 20.5, 20.6_

- [x] 13.6 Implement exit code handling
  - Map error types to exit codes
  - Ensure consistent exit codes
  - _Requirements: 11.4_

- [x] 13.7 Implement retry logic with backoff
  - Exponential backoff for network errors
  - Maximum retry attempts
  - Clear feedback on retries
  - _Requirements: 20.7_


## Phase 13: User Experience Enhancements

- [x] 14. Implement UX enhancements
- [x] 14.1 Implement .myc.yaml project config support
  - Define config schema (vault, project, set, export_format, output_file)
  - Implement config file discovery (walk up directory tree)
  - Apply defaults from config
  - Allow command-line overrides
  - _Requirements: 15.4_

- [x] 14.2 Implement myc run subprocess injection
  - Parse command arguments
  - Pull secrets from configured project/set
  - Inject as environment variables
  - Execute subprocess
  - Ensure secrets never written to disk
  - _Requirements: 15.5_

- [x] 14.3 Implement shell completions
  - Generate completions for bash, zsh, fish, powershell
  - Use clap's built-in completion generation
  - Provide installation instructions
  - _Requirements: 15.6_

- [x] 14.4 Implement diff before push
  - Fetch current version
  - Compute diff
  - Display changes
  - Prompt for confirmation
  - _Requirements: 15.7_

- [x] 14.5 Implement status command
  - Display profile information
  - Display recovery status
  - Display projects with access
  - Display last pull information
  - Display GitHub API rate limit
  - _Requirements: 15.4_

- [x] 14.6 Implement gitignore helper
  - Offer to add .env to .gitignore on init
  - Implement gitignore command
  - Add common secret file patterns
  - _Requirements: 15.7_

- [x] 14.7 Implement recovery status warnings
  - Warn after first device enrollment
  - Warn on each command if only 1 device
  - Display recovery status in status command
  - _Requirements: 14.1, 14.2_


## Phase 14: Key Recovery Implementation

- [x] 15. Implement key recovery mechanisms
- [x] 15.1 Implement multi-device enrollment
  - Support enrolling multiple devices
  - Each device has independent keypair
  - PDKs wrapped to each device independently
  - _Requirements: 14.1_

- [x] 15.2 Implement device wrap-from operation
  - Existing device wraps PDK to new device
  - Used for adding devices without admin
  - _Requirements: 14.1_

- [x] 15.3 Implement recovery contacts
  - Define recovery contact relationship
  - Implement set-contacts command
  - Implement show-contacts command
  - Store relationship signed by user
  - _Requirements: 14.3, 14.4_

- [x] 15.4 Implement recovery assist operation
  - Recovery contact wraps PDKs to new device
  - Only for projects contact has access to
  - Create audit event
  - _Requirements: 14.4_

- [x] 15.5 Implement recovery request flow
  - User enrolls new device
  - User requests recovery
  - System notifies recovery contacts
  - Contact assists recovery
  - _Requirements: 14.4_

- [x] 15.6 Implement organization recovery key (Shamir)
  - Generate org recovery key (ORK)
  - Split ORK using Shamir's Secret Sharing
  - Encrypt shares to admin device keys
  - Distribute shares
  - _Requirements: 14.5, 14.6_

- [x] 15.7 Implement recovery share contribution
  - Admin contributes share
  - Collect threshold shares
  - Reconstruct ORK
  - Re-wrap PDKs to user's new device
  - Immediately discard assembled ORK
  - Create audit event
  - _Requirements: 14.6_

- [x] 15.8 Implement recovery status command
  - Display devices enrolled
  - Display recovery contacts
  - Display org recovery key status
  - _Requirements: 14.7_


## Phase 15: Testing and Quality Assurance

- [x] 16. Comprehensive testing and quality checks
- [x] 16.1 Set up property-based testing framework
  - Add proptest dependency
  - Configure to run 100 iterations per test
  - Create test utilities for generators
  - _Requirements: 21.1_

- [x] 16.2 Implement crypto property tests
  - Encryption/decryption roundtrips
  - Signature roundtrips
  - Tampering detection
  - KDF determinism and domain separation
  - Hash determinism and chain integrity
  - _Requirements: 21.2, 21.3, 21.4, 21.5_

- [x] 16.3 Implement serialization property tests
  - Serialization roundtrips for all types
  - Canonical JSON determinism
  - Format compliance
  - _Requirements: 21.2_

- [x] 16.4 Implement PDK property tests
  - Wrap/unwrap roundtrips
  - Member addition/removal
  - Rotation properties
  - _Requirements: 21.2_

- [x] 16.5 Implement permission property tests
  - Role permission sets
  - Permission checks
  - Membership operations
  - _Requirements: 21.2_

- [x] 16.6 Implement audit property tests
  - Hash chain integrity
  - Signature verification
  - Tampering detection
  - _Requirements: 21.5_

- [x] 16.7 Implement integration tests
  - Vault lifecycle tests
  - Membership flow tests
  - Recovery flow tests
  - CI flow tests
  - _Requirements: 21.2_

- [x] 16.8 Set up CI pipeline
  - Configure GitHub Actions workflow
  - Run cargo fmt --check
  - Run cargo clippy with deny warnings
  - Run cargo test --all
  - Run cargo audit
  - Run cargo deny check
  - _Requirements: 21.6, 22.2, 22.3, 22.4_

- [x] 16.9 Set up supply chain security
  - Configure cargo-vet
  - Vet all dependencies
  - Document exemptions with rationale
  - _Requirements: 22.1, 22.2_

- [x] 16.10 Ensure test coverage
  - All property tests pass
  - All unit tests pass
  - All integration tests pass
  - Tests pass in both debug and release modes
  - _Requirements: 21.6_


## Phase 16: Documentation and Polish

- [x] 17. Documentation and final polish
- [x] 17.1 Write API documentation
  - Add doc comments to all public items in library crates
  - Ensure #![deny(missing_docs)] passes
  - Include examples in doc comments
  - Generate cargo doc
  - _Requirements: 23.1, 23.2_

- [x] 17.2 Write CLI help text
  - Add help text to all commands
  - Include usage examples
  - Document all options and flags
  - _Requirements: 23.2_

- [x] 17.3 Write README
  - Quick start guide
  - Architecture overview
  - Security model explanation
  - Installation instructions
  - _Requirements: 23.6_

- [x] 17.4 Write user guide
  - Getting started tutorial
  - Common workflows
  - Troubleshooting guide
  - Best practices
  - _Requirements: 23.2_

- [x] 17.5 Write security documentation
  - Threat model
  - Cryptographic design
  - Key management practices
  - Incident response procedures
  - _Requirements: 23.6_

- [x] 17.6 Sync RFCs with implementation
  - Update RFCs to reflect implementation decisions
  - Document any deviations from original design
  - _Requirements: 23.5_

- [x] 17.7 Create example workflows
  - Example .myc.yaml configs
  - Example GitHub Actions workflows
  - Example recovery scenarios
  - _Requirements: 23.4_

- [x] 17.8 Polish error messages
  - Review all error messages for clarity
  - Ensure all errors include remediation steps
  - Test error messages with users
  - _Requirements: 23.3_

- [x] 17.9 Performance optimization
  - Profile critical paths
  - Optimize hot loops
  - Implement caching where beneficial
  - Verify performance targets met
  - _Requirements: 24.1, 24.2, 24.3, 24.4, 24.5, 24.6_

- [x] 17.10 Final integration testing
  - Test complete workflows end-to-end
  - Test error scenarios
  - Test recovery scenarios
  - Test CI integration
  - _Requirements: 21.7_

## Phase 17: Checkpoint - Ensure All Tests Pass

- [x] 18. Final checkpoint
  - [x] Ensure all tests pass
  - [x] Ensure all property tests pass with 100+ iterations
  - [x] Ensure CI pipeline passes
  - [x] Ensure cargo audit shows no vulnerabilities
  - [x] Ensure cargo deny passes
  - [x] Ensure all documentation is complete
  - [x] Ask the user if questions arise

