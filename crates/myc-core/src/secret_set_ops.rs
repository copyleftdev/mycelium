//! Secret set operations for encryption, decryption, and versioning.
//!
//! This module provides functions for:
//! - Serializing secret entries to canonical JSON
//! - Encrypting and decrypting secret versions
//! - Computing content hashes and hash chains
//! - Signing and verifying version metadata
//! - Enforcing size limits

use crate::canonical::to_canonical_json;
use crate::error::{CoreError, Result};
use crate::ids::{DeviceId, ProjectId, SecretSetId, VersionNumber};
use crate::secret_set::{SecretEntry, SecretSetVersion};
use myc_crypto::aead::{decrypt, encrypt, AeadKey};
use myc_crypto::hash::{chain_hash, hash, HashOutput};
use myc_crypto::sign::{sign, verify, Ed25519PublicKey, Ed25519SecretKey, Signature};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Maximum plaintext size in bytes (10MB).
pub const MAX_PLAINTEXT_SIZE: usize = 10 * 1024 * 1024;

/// Maximum number of entries per secret set.
pub const MAX_ENTRIES: usize = 10_000;

/// Maximum key length in characters.
pub const MAX_KEY_LENGTH: usize = 256;

/// Maximum value length in bytes.
pub const MAX_VALUE_LENGTH: usize = 1024 * 1024; // 1MB per value

/// Serializes secret entries to canonical JSON.
///
/// This function:
/// 1. Sorts entries by key alphabetically
/// 2. Serializes to canonical JSON (sorted keys, no whitespace)
///
/// # Arguments
///
/// * `entries` - The secret entries to serialize
///
/// # Returns
///
/// A canonical JSON string
///
/// # Errors
///
/// Returns `CoreError::SerializationError` if serialization fails
///
/// # Examples
///
/// ```
/// use myc_core::secret_set::SecretEntry;
/// use myc_core::secret_set_ops::serialize_secrets;
///
/// let entries = vec![
///     SecretEntry::new("DATABASE_URL".to_string(), "postgres://...".to_string()),
///     SecretEntry::new("API_KEY".to_string(), "secret123".to_string()),
/// ];
///
/// let json = serialize_secrets(&entries).unwrap();
/// // Keys are sorted: API_KEY comes before DATABASE_URL
/// ```
pub fn serialize_secrets(entries: &[SecretEntry]) -> Result<String> {
    // Sort entries by key alphabetically
    let mut sorted_entries = entries.to_vec();
    sorted_entries.sort_by(|a, b| a.key.cmp(&b.key));

    // Serialize to canonical JSON
    to_canonical_json(&sorted_entries)
}

/// Constructs AAD (Additional Authenticated Data) for secret encryption.
///
/// AAD format: project_id || set_id || version_number || pdk_version
///
/// # Arguments
///
/// * `project_id` - The project ID
/// * `set_id` - The secret set ID
/// * `version` - The version number
/// * `pdk_version` - The PDK version used for encryption
///
/// # Returns
///
/// A byte vector containing the AAD
fn construct_aad(
    project_id: &ProjectId,
    set_id: &SecretSetId,
    version: &VersionNumber,
    pdk_version: &VersionNumber,
) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(project_id.as_uuid().as_bytes());
    aad.extend_from_slice(set_id.as_uuid().as_bytes());
    aad.extend_from_slice(&version.as_u64().to_le_bytes());
    aad.extend_from_slice(&pdk_version.as_u64().to_le_bytes());
    aad
}

/// Encrypts secret entries to create a new version.
///
/// This function:
/// 1. Serializes entries to canonical JSON
/// 2. Computes content_hash = BLAKE3(plaintext)
/// 3. Computes chain_hash = BLAKE3(previous_chain_hash || content_hash)
/// 4. Constructs AAD = project_id || set_id || version_number || pdk_version
/// 5. Encrypts with PDK using AEAD
///
/// # Arguments
///
/// * `entries` - The secret entries to encrypt
/// * `project_id` - The project ID
/// * `set_id` - The secret set ID
/// * `version` - The version number for this version
/// * `pdk_version` - The PDK version to use for encryption
/// * `pdk` - The PDK (Project Data Key) to encrypt with
/// * `previous_chain_hash` - The chain hash from the previous version (None for version 1)
///
/// # Returns
///
/// A tuple containing:
/// - The ciphertext (nonce || encrypted_data || tag)
/// - The content hash
/// - The chain hash
///
/// # Errors
///
/// Returns `CoreError::CryptoError` if encryption fails
///
/// # Examples
///
/// ```
/// use myc_core::secret_set::SecretEntry;
/// use myc_core::secret_set_ops::encrypt_secrets;
/// use myc_core::ids::{ProjectId, SecretSetId, VersionNumber};
/// use myc_core::pdk_ops::generate_pdk;
///
/// let entries = vec![
///     SecretEntry::new("API_KEY".to_string(), "secret123".to_string()),
/// ];
///
/// let project_id = ProjectId::new();
/// let set_id = SecretSetId::new();
/// let pdk = generate_pdk().unwrap();
///
/// let (ciphertext, content_hash, chain_hash) = encrypt_secrets(
///     &entries,
///     &project_id,
///     &set_id,
///     &VersionNumber::FIRST,
///     &VersionNumber::FIRST,
///     &pdk,
///     None,
/// ).unwrap();
/// ```
pub fn encrypt_secrets(
    entries: &[SecretEntry],
    project_id: &ProjectId,
    set_id: &SecretSetId,
    version: &VersionNumber,
    pdk_version: &VersionNumber,
    pdk: &AeadKey,
    previous_chain_hash: Option<&HashOutput>,
) -> Result<(Vec<u8>, HashOutput, HashOutput)> {
    // Serialize entries to canonical JSON
    let plaintext = serialize_secrets(entries)?;
    let plaintext_bytes = plaintext.as_bytes();

    // Compute content_hash = BLAKE3(plaintext)
    let content_hash = hash(plaintext_bytes);

    // Compute chain_hash = BLAKE3(previous_chain_hash || content_hash)
    let chain_hash_value = match previous_chain_hash {
        Some(prev_hash) => chain_hash(prev_hash, content_hash.as_bytes()),
        None => content_hash, // For version 1, chain_hash = content_hash
    };

    // Construct AAD = project_id || set_id || version_number || pdk_version
    let aad = construct_aad(project_id, set_id, version, pdk_version);

    // Encrypt with PDK using AEAD
    let ciphertext = encrypt(pdk, plaintext_bytes, &aad)?;

    Ok((ciphertext, content_hash, chain_hash_value))
}

/// Metadata structure for signing.
///
/// This structure contains all the metadata about a secret set version
/// that needs to be signed for integrity verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct VersionMetadataForSigning {
    set_id: SecretSetId,
    version: VersionNumber,
    pdk_version: VersionNumber,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    created_by: DeviceId,
    message: Option<String>,
    content_hash: String,          // Base64-encoded
    chain_hash: String,            // Base64-encoded
    previous_hash: Option<String>, // Base64-encoded
}

/// Signs version metadata with a device key.
///
/// This function:
/// 1. Creates a metadata structure
/// 2. Serializes to canonical JSON
/// 3. Signs with device Ed25519 key
///
/// # Arguments
///
/// * `set_id` - The secret set ID
/// * `version` - The version number
/// * `pdk_version` - The PDK version used for encryption
/// * `created_at` - The creation timestamp
/// * `created_by` - The device ID that created this version
/// * `message` - Optional commit message
/// * `content_hash` - The content hash
/// * `chain_hash` - The chain hash
/// * `previous_hash` - The previous version's chain hash (None for version 1)
/// * `device_key` - The device's Ed25519 secret key
///
/// # Returns
///
/// An Ed25519 signature over the canonical JSON of the metadata
///
/// # Errors
///
/// Returns `CoreError::SerializationError` if serialization fails
///
/// # Examples
///
/// ```
/// use myc_core::secret_set_ops::sign_version_metadata;
/// use myc_core::ids::{SecretSetId, DeviceId, VersionNumber};
/// use myc_crypto::hash::hash;
/// use myc_crypto::sign::generate_ed25519_keypair;
/// use time::OffsetDateTime;
///
/// let (device_key, _) = generate_ed25519_keypair().unwrap();
/// let set_id = SecretSetId::new();
/// let device_id = DeviceId::new();
/// let content_hash = hash(b"test content");
/// let chain_hash = content_hash;
///
/// let signature = sign_version_metadata(
///     &set_id,
///     &VersionNumber::FIRST,
///     &VersionNumber::FIRST,
///     OffsetDateTime::now_utc(),
///     &device_id,
///     Some("Initial version".to_string()),
///     &content_hash,
///     &chain_hash,
///     None,
///     &device_key,
/// ).unwrap();
/// ```
#[allow(clippy::too_many_arguments)]
pub fn sign_version_metadata(
    set_id: &SecretSetId,
    version: &VersionNumber,
    pdk_version: &VersionNumber,
    created_at: OffsetDateTime,
    created_by: &DeviceId,
    message: Option<String>,
    content_hash: &HashOutput,
    chain_hash: &HashOutput,
    previous_hash: Option<&HashOutput>,
    device_key: &Ed25519SecretKey,
) -> Result<Signature> {
    // Create metadata structure
    let metadata = VersionMetadataForSigning {
        set_id: *set_id,
        version: *version,
        pdk_version: *pdk_version,
        created_at,
        created_by: *created_by,
        message,
        content_hash: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            content_hash.as_bytes(),
        ),
        chain_hash: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            chain_hash.as_bytes(),
        ),
        previous_hash: previous_hash.map(|h| {
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, h.as_bytes())
        }),
    };

    // Serialize to canonical JSON and sign
    let canonical_json = to_canonical_json(&metadata)?;
    Ok(sign(device_key, canonical_json.as_bytes()))
}

/// Verifies a version metadata signature.
///
/// This function:
/// 1. Reconstructs the metadata structure
/// 2. Serializes to canonical JSON
/// 3. Verifies the signature with the device's public key
///
/// # Arguments
///
/// * `set_id` - The secret set ID
/// * `version` - The version number
/// * `pdk_version` - The PDK version used for encryption
/// * `created_at` - The creation timestamp
/// * `created_by` - The device ID that created this version
/// * `message` - Optional commit message
/// * `content_hash` - The content hash
/// * `chain_hash` - The chain hash
/// * `previous_hash` - The previous version's chain hash (None for version 1)
/// * `signature` - The signature to verify
/// * `device_pubkey` - The device's Ed25519 public key
///
/// # Returns
///
/// `Ok(())` if the signature is valid
///
/// # Errors
///
/// Returns `CoreError::SignatureInvalid` if verification fails
/// Returns `CoreError::SerializationError` if serialization fails
///
/// # Examples
///
/// ```
/// use myc_core::secret_set_ops::{sign_version_metadata, verify_version_metadata};
/// use myc_core::ids::{SecretSetId, DeviceId, VersionNumber};
/// use myc_crypto::hash::hash;
/// use myc_crypto::sign::generate_ed25519_keypair;
/// use time::OffsetDateTime;
///
/// let (device_key, device_pubkey) = generate_ed25519_keypair().unwrap();
/// let set_id = SecretSetId::new();
/// let device_id = DeviceId::new();
/// let content_hash = hash(b"test content");
/// let chain_hash = content_hash;
/// let created_at = OffsetDateTime::now_utc();
///
/// let signature = sign_version_metadata(
///     &set_id,
///     &VersionNumber::FIRST,
///     &VersionNumber::FIRST,
///     created_at,
///     &device_id,
///     None,
///     &content_hash,
///     &chain_hash,
///     None,
///     &device_key,
/// ).unwrap();
///
/// assert!(verify_version_metadata(
///     &set_id,
///     &VersionNumber::FIRST,
///     &VersionNumber::FIRST,
///     created_at,
///     &device_id,
///     None,
///     &content_hash,
///     &chain_hash,
///     None,
///     &signature,
///     &device_pubkey,
/// ).is_ok());
/// ```
#[allow(clippy::too_many_arguments)]
pub fn verify_version_metadata(
    set_id: &SecretSetId,
    version: &VersionNumber,
    pdk_version: &VersionNumber,
    created_at: OffsetDateTime,
    created_by: &DeviceId,
    message: Option<String>,
    content_hash: &HashOutput,
    chain_hash: &HashOutput,
    previous_hash: Option<&HashOutput>,
    signature: &Signature,
    device_pubkey: &Ed25519PublicKey,
) -> Result<()> {
    // Create metadata structure
    let metadata = VersionMetadataForSigning {
        set_id: *set_id,
        version: *version,
        pdk_version: *pdk_version,
        created_at,
        created_by: *created_by,
        message,
        content_hash: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            content_hash.as_bytes(),
        ),
        chain_hash: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            chain_hash.as_bytes(),
        ),
        previous_hash: previous_hash.map(|h| {
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, h.as_bytes())
        }),
    };

    // Serialize to canonical JSON and verify
    let canonical_json = to_canonical_json(&metadata)?;
    verify(device_pubkey, canonical_json.as_bytes(), signature)
        .map_err(|_| CoreError::SignatureInvalid)
}

/// Creates a complete secret set version with encryption and signing.
///
/// This is a high-level function that:
/// 1. Validates size limits
/// 2. Encrypts the secrets
/// 3. Signs the metadata
/// 4. Returns a complete SecretSetVersion
///
/// # Arguments
///
/// * `entries` - The secret entries to encrypt
/// * `set_id` - The secret set ID
/// * `version` - The version number for this version
/// * `pdk_version` - The PDK version to use for encryption
/// * `project_id` - The project ID
/// * `pdk` - The PDK (Project Data Key) to encrypt with
/// * `device_id` - The device ID creating this version
/// * `device_key` - The device's Ed25519 secret key for signing
/// * `message` - Optional commit message
/// * `previous_chain_hash` - The previous version's chain hash (None for version 1)
///
/// # Returns
///
/// A complete `SecretSetVersion` ready to be stored
///
/// # Errors
///
/// Returns errors if validation, encryption, or signing fails
///
/// # Examples
///
/// ```
/// use myc_core::secret_set::SecretEntry;
/// use myc_core::secret_set_ops::create_version;
/// use myc_core::ids::{ProjectId, SecretSetId, DeviceId, VersionNumber};
/// use myc_core::pdk_ops::generate_pdk;
/// use myc_crypto::sign::generate_ed25519_keypair;
///
/// let entries = vec![
///     SecretEntry::new("API_KEY".to_string(), "secret123".to_string()),
/// ];
///
/// let project_id = ProjectId::new();
/// let set_id = SecretSetId::new();
/// let device_id = DeviceId::new();
/// let pdk = generate_pdk().unwrap();
/// let (device_key, _) = generate_ed25519_keypair().unwrap();
///
/// let version = create_version(
///     &entries,
///     &set_id,
///     &VersionNumber::FIRST,
///     &VersionNumber::FIRST,
///     &project_id,
///     &pdk,
///     &device_id,
///     &device_key,
///     Some("Initial version".to_string()),
///     None,
/// ).unwrap();
/// ```
#[allow(clippy::too_many_arguments)]
pub fn create_version(
    entries: &[SecretEntry],
    set_id: &SecretSetId,
    version: &VersionNumber,
    pdk_version: &VersionNumber,
    project_id: &ProjectId,
    pdk: &AeadKey,
    device_id: &DeviceId,
    device_key: &Ed25519SecretKey,
    message: Option<String>,
    previous_chain_hash: Option<&HashOutput>,
) -> Result<SecretSetVersion> {
    // Validate size limits
    validate_size_limits(entries)?;

    // Encrypt secrets
    let (ciphertext, content_hash, chain_hash) = encrypt_secrets(
        entries,
        project_id,
        set_id,
        version,
        pdk_version,
        pdk,
        previous_chain_hash,
    )?;

    // Sign metadata
    let created_at = OffsetDateTime::now_utc();
    let signature = sign_version_metadata(
        set_id,
        version,
        pdk_version,
        created_at,
        device_id,
        message.clone(),
        &content_hash,
        &chain_hash,
        previous_chain_hash,
        device_key,
    )?;

    // Create version
    // Note: previous_hash stores the previous version's chain_hash
    // The current chain_hash is computed as BLAKE3(previous_hash || content_hash)
    // but is not stored in the structure - it's recomputed when needed
    Ok(SecretSetVersion {
        schema_version: SecretSetVersion::SCHEMA_VERSION,
        set_id: *set_id,
        version: *version,
        pdk_version: *pdk_version,
        created_at,
        created_by: *device_id,
        message,
        content_hash,
        previous_hash: previous_chain_hash.copied(),
        ciphertext,
        signature,
    })
}

/// Reads and decrypts a secret set version.
///
/// This is a high-level function that:
/// 1. Decrypts the ciphertext
/// 2. Verifies the signature
/// 3. Returns the decrypted entries
///
/// # Arguments
///
/// * `version` - The SecretSetVersion to read
/// * `project_id` - The project ID
/// * `pdk` - The PDK (Project Data Key) to decrypt with
/// * `device_pubkey` - The device's Ed25519 public key for signature verification
/// * `previous_chain_hash` - The previous version's chain hash (None for version 1)
///
/// # Returns
///
/// A vector of decrypted secret entries
///
/// # Errors
///
/// Returns errors if decryption or verification fails
///
/// # Examples
///
/// ```
/// use myc_core::secret_set::SecretEntry;
/// use myc_core::secret_set_ops::{create_version, read_version};
/// use myc_core::ids::{ProjectId, SecretSetId, DeviceId, VersionNumber};
/// use myc_core::pdk_ops::generate_pdk;
/// use myc_crypto::sign::generate_ed25519_keypair;
///
/// let entries = vec![
///     SecretEntry::new("API_KEY".to_string(), "secret123".to_string()),
/// ];
///
/// let project_id = ProjectId::new();
/// let set_id = SecretSetId::new();
/// let device_id = DeviceId::new();
/// let pdk = generate_pdk().unwrap();
/// let (device_key, device_pubkey) = generate_ed25519_keypair().unwrap();
///
/// // Create version
/// let version = create_version(
///     &entries,
///     &set_id,
///     &VersionNumber::FIRST,
///     &VersionNumber::FIRST,
///     &project_id,
///     &pdk,
///     &device_id,
///     &device_key,
///     None,
///     None,
/// ).unwrap();
///
/// // Read version
/// let decrypted = read_version(&version, &project_id, &pdk, &device_pubkey, None).unwrap();
/// ```
pub fn read_version(
    version: &SecretSetVersion,
    project_id: &ProjectId,
    pdk: &AeadKey,
    device_pubkey: &Ed25519PublicKey,
    previous_chain_hash: Option<&HashOutput>,
) -> Result<Vec<SecretEntry>> {
    // Compute the chain hash for this version
    let chain_hash_value = match previous_chain_hash {
        Some(prev) => chain_hash(prev, version.content_hash.as_bytes()),
        None => version.content_hash, // For version 1, chain_hash = content_hash
    };

    // Verify signature
    verify_version_metadata(
        &version.set_id,
        &version.version,
        &version.pdk_version,
        version.created_at,
        &version.created_by,
        version.message.clone(),
        &version.content_hash,
        &chain_hash_value,
        previous_chain_hash,
        &version.signature,
        device_pubkey,
    )?;

    // Decrypt secrets
    decrypt_secrets(
        &version.ciphertext,
        project_id,
        &version.set_id,
        &version.version,
        &version.pdk_version,
        pdk,
        &version.content_hash,
        &chain_hash_value,
        previous_chain_hash,
    )
}

/// Computes the chain hash for a version.
///
/// The chain hash is computed as:
/// - For version 1 (no previous_hash): chain_hash = content_hash
/// - For version N (with previous_hash): chain_hash = BLAKE3(previous_hash || content_hash)
///
/// # Arguments
///
/// * `version` - The version to compute the chain hash for
///
/// # Returns
///
/// The computed chain hash
pub fn compute_chain_hash(version: &SecretSetVersion) -> HashOutput {
    match &version.previous_hash {
        Some(prev_hash) => chain_hash(prev_hash, version.content_hash.as_bytes()),
        None => version.content_hash,
    }
}

/// Verifies the integrity of a hash chain across multiple versions.
///
/// This function verifies that each version's chain_hash correctly links
/// to the previous version, ensuring the chain hasn't been tampered with.
///
/// # Arguments
///
/// * `versions` - A slice of SecretSetVersion in order (oldest to newest)
///
/// # Returns
///
/// `Ok(())` if the chain is valid
///
/// # Errors
///
/// Returns `CoreError::ChainBroken` if any link in the chain is invalid
///
/// # Examples
///
/// ```
/// use myc_core::secret_set::SecretEntry;
/// use myc_core::secret_set_ops::{create_version, verify_chain};
/// use myc_core::ids::{ProjectId, SecretSetId, DeviceId, VersionNumber};
/// use myc_core::pdk_ops::generate_pdk;
/// use myc_crypto::sign::generate_ed25519_keypair;
///
/// let project_id = ProjectId::new();
/// let set_id = SecretSetId::new();
/// let device_id = DeviceId::new();
/// let pdk = generate_pdk().unwrap();
/// let (device_key, _) = generate_ed25519_keypair().unwrap();
///
/// // Create version 1
/// let entries1 = vec![SecretEntry::new("KEY1".to_string(), "value1".to_string())];
/// let v1 = create_version(
///     &entries1, &set_id, &VersionNumber::FIRST, &VersionNumber::FIRST,
///     &project_id, &pdk, &device_id, &device_key, None, None,
/// ).unwrap();
///
/// // Create version 2 with chain
/// let entries2 = vec![SecretEntry::new("KEY2".to_string(), "value2".to_string())];
/// let chain_hash1 = v1.previous_hash.as_ref().unwrap_or(&v1.content_hash);
/// let v2 = create_version(
///     &entries2, &set_id, &VersionNumber::new(2), &VersionNumber::FIRST,
///     &project_id, &pdk, &device_id, &device_key, None, Some(chain_hash1),
/// ).unwrap();
///
/// // Verify chain
/// assert!(verify_chain(&[v1, v2]).is_ok());
/// ```
pub fn verify_chain(versions: &[SecretSetVersion]) -> Result<()> {
    if versions.is_empty() {
        return Ok(());
    }

    // Compute chain hash for each version and verify links
    let mut prev_chain_hash: Option<HashOutput> = None;

    for version in versions {
        // Compute this version's chain hash
        let computed_chain_hash = match prev_chain_hash {
            Some(prev) => chain_hash(&prev, version.content_hash.as_bytes()),
            None => version.content_hash, // For version 1, chain_hash = content_hash
        };

        // Verify that the stored previous_hash matches what we expect
        match (&version.previous_hash, &prev_chain_hash) {
            (None, None) => {
                // First version - OK
            }
            (Some(stored), Some(expected)) => {
                if stored != expected {
                    return Err(CoreError::ChainBroken {
                        version: version.version.as_u64(),
                    });
                }
            }
            _ => {
                // Mismatch: either previous_hash is Some when it should be None, or vice versa
                return Err(CoreError::ChainBroken {
                    version: version.version.as_u64(),
                });
            }
        }

        // Update for next iteration
        prev_chain_hash = Some(computed_chain_hash);
    }

    Ok(())
}

/// Validates secret entries against size limits.
///
/// This function checks:
/// 1. Total plaintext size doesn't exceed MAX_PLAINTEXT_SIZE (10MB)
/// 2. Entry count doesn't exceed MAX_ENTRIES (10,000)
/// 3. Each key length doesn't exceed MAX_KEY_LENGTH (256 characters)
/// 4. Each value length doesn't exceed MAX_VALUE_LENGTH (1MB)
///
/// # Arguments
///
/// * `entries` - The secret entries to validate
///
/// # Returns
///
/// `Ok(())` if all size limits are satisfied
///
/// # Errors
///
/// Returns `CoreError::SizeLimitExceeded` if any limit is exceeded
///
/// # Examples
///
/// ```
/// use myc_core::secret_set::SecretEntry;
/// use myc_core::secret_set_ops::validate_size_limits;
///
/// let entries = vec![
///     SecretEntry::new("API_KEY".to_string(), "secret123".to_string()),
/// ];
///
/// assert!(validate_size_limits(&entries).is_ok());
/// ```
pub fn validate_size_limits(entries: &[SecretEntry]) -> Result<()> {
    // Check entry count
    if entries.len() > MAX_ENTRIES {
        return Err(CoreError::SizeLimitExceeded {
            size: entries.len(),
            max: MAX_ENTRIES,
        });
    }

    // Validate individual entries
    for entry in entries {
        // Check key length
        if entry.key.len() > MAX_KEY_LENGTH {
            return Err(CoreError::SizeLimitExceeded {
                size: entry.key.len(),
                max: MAX_KEY_LENGTH,
            });
        }

        // Check value length
        if entry.value.len() > MAX_VALUE_LENGTH {
            return Err(CoreError::SizeLimitExceeded {
                size: entry.value.len(),
                max: MAX_VALUE_LENGTH,
            });
        }
    }

    // Check total plaintext size (approximate)
    // We serialize to get exact size
    let json = serialize_secrets(entries)?;
    let actual_size = json.len();

    if actual_size > MAX_PLAINTEXT_SIZE {
        return Err(CoreError::SizeLimitExceeded {
            size: actual_size,
            max: MAX_PLAINTEXT_SIZE,
        });
    }

    Ok(())
}

/// Decrypts secret entries from a version.
///
/// This function:
/// 1. Constructs AAD from metadata
/// 2. Decrypts with PDK using AEAD
/// 3. Verifies content_hash matches BLAKE3(plaintext)
/// 4. Verifies hash chain (if previous_chain_hash provided)
/// 5. Parses JSON and returns entries
///
/// # Arguments
///
/// * `ciphertext` - The encrypted data (nonce || ciphertext || tag)
/// * `project_id` - The project ID
/// * `set_id` - The secret set ID
/// * `version` - The version number
/// * `pdk_version` - The PDK version used for encryption
/// * `pdk` - The PDK (Project Data Key) to decrypt with
/// * `content_hash` - The expected content hash
/// * `chain_hash` - The expected chain hash
/// * `previous_chain_hash` - The previous version's chain hash (None for version 1)
///
/// # Returns
///
/// A vector of decrypted secret entries
///
/// # Errors
///
/// Returns `CoreError::CryptoError` if decryption fails
/// Returns `CoreError::HashMismatch` if content hash doesn't match
/// Returns `CoreError::ChainBroken` if hash chain verification fails
/// Returns `CoreError::SerializationError` if JSON parsing fails
///
/// # Examples
///
/// ```
/// use myc_core::secret_set::SecretEntry;
/// use myc_core::secret_set_ops::{encrypt_secrets, decrypt_secrets};
/// use myc_core::ids::{ProjectId, SecretSetId, VersionNumber};
/// use myc_core::pdk_ops::generate_pdk;
///
/// let entries = vec![
///     SecretEntry::new("API_KEY".to_string(), "secret123".to_string()),
/// ];
///
/// let project_id = ProjectId::new();
/// let set_id = SecretSetId::new();
/// let pdk = generate_pdk().unwrap();
///
/// // Encrypt
/// let (ciphertext, content_hash, chain_hash) = encrypt_secrets(
///     &entries,
///     &project_id,
///     &set_id,
///     &VersionNumber::FIRST,
///     &VersionNumber::FIRST,
///     &pdk,
///     None,
/// ).unwrap();
///
/// // Decrypt
/// let decrypted = decrypt_secrets(
///     &ciphertext,
///     &project_id,
///     &set_id,
///     &VersionNumber::FIRST,
///     &VersionNumber::FIRST,
///     &pdk,
///     &content_hash,
///     &chain_hash,
///     None,
/// ).unwrap();
///
/// assert_eq!(entries, decrypted);
/// ```
#[allow(clippy::too_many_arguments)]
pub fn decrypt_secrets(
    ciphertext: &[u8],
    project_id: &ProjectId,
    set_id: &SecretSetId,
    version: &VersionNumber,
    pdk_version: &VersionNumber,
    pdk: &AeadKey,
    expected_content_hash: &HashOutput,
    expected_chain_hash: &HashOutput,
    previous_chain_hash: Option<&HashOutput>,
) -> Result<Vec<SecretEntry>> {
    // Construct AAD = project_id || set_id || version_number || pdk_version
    let aad = construct_aad(project_id, set_id, version, pdk_version);

    // Decrypt with PDK using AEAD
    let plaintext = decrypt(pdk, ciphertext, &aad)?;

    // Verify content_hash = BLAKE3(plaintext)
    let computed_content_hash = hash(&plaintext);
    if computed_content_hash != *expected_content_hash {
        return Err(CoreError::HashMismatch {
            expected: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                expected_content_hash.as_bytes(),
            ),
            actual: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                computed_content_hash.as_bytes(),
            ),
        });
    }

    // Verify hash chain
    let computed_chain_hash = match previous_chain_hash {
        Some(prev_hash) => chain_hash(prev_hash, expected_content_hash.as_bytes()),
        None => *expected_content_hash, // For version 1, chain_hash = content_hash
    };

    if computed_chain_hash != *expected_chain_hash {
        return Err(CoreError::ChainBroken {
            version: version.as_u64(),
        });
    }

    // Parse JSON and return entries
    let plaintext_str = String::from_utf8(plaintext).map_err(|e| {
        CoreError::SerializationError(serde_json::Error::io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            e,
        )))
    })?;
    let entries: Vec<SecretEntry> = serde_json::from_str(&plaintext_str)?;

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_secrets_empty() {
        let entries: Vec<SecretEntry> = vec![];
        let json = serialize_secrets(&entries).unwrap();
        assert_eq!(json, "[]");
    }

    #[test]
    fn test_serialize_secrets_single() {
        let entries = vec![SecretEntry::new(
            "API_KEY".to_string(),
            "secret123".to_string(),
        )];
        let json = serialize_secrets(&entries).unwrap();
        assert!(json.contains("API_KEY"));
        assert!(json.contains("secret123"));
    }

    #[test]
    fn test_serialize_secrets_sorted() {
        let entries = vec![
            SecretEntry::new("ZEBRA".to_string(), "value1".to_string()),
            SecretEntry::new("APPLE".to_string(), "value2".to_string()),
            SecretEntry::new("MANGO".to_string(), "value3".to_string()),
        ];

        let json = serialize_secrets(&entries).unwrap();

        // Find positions of keys in the JSON string
        let apple_pos = json.find("APPLE").unwrap();
        let mango_pos = json.find("MANGO").unwrap();
        let zebra_pos = json.find("ZEBRA").unwrap();

        // Keys should appear in alphabetical order
        assert!(apple_pos < mango_pos);
        assert!(mango_pos < zebra_pos);
    }

    #[test]
    fn test_serialize_secrets_determinism() {
        let entries = vec![
            SecretEntry::new("KEY1".to_string(), "value1".to_string()),
            SecretEntry::new("KEY2".to_string(), "value2".to_string()),
        ];

        let json1 = serialize_secrets(&entries).unwrap();
        let json2 = serialize_secrets(&entries).unwrap();

        assert_eq!(json1, json2);
    }

    #[test]
    fn test_serialize_secrets_no_whitespace() {
        let entries = vec![SecretEntry::new("KEY".to_string(), "value".to_string())];

        let json = serialize_secrets(&entries).unwrap();

        // Should not contain whitespace
        assert!(!json.contains(' '));
        assert!(!json.contains('\n'));
        assert!(!json.contains('\t'));
    }

    #[test]
    fn test_encrypt_secrets_basic() {
        use crate::ids::{ProjectId, SecretSetId, VersionNumber};
        use crate::pdk_ops::generate_pdk;

        let entries = vec![SecretEntry::new(
            "API_KEY".to_string(),
            "secret123".to_string(),
        )];

        let project_id = ProjectId::new();
        let set_id = SecretSetId::new();
        let pdk = generate_pdk().unwrap();

        let (ciphertext, content_hash, chain_hash) = encrypt_secrets(
            &entries,
            &project_id,
            &set_id,
            &VersionNumber::FIRST,
            &VersionNumber::FIRST,
            &pdk,
            None,
        )
        .unwrap();

        // Ciphertext should be non-empty
        assert!(!ciphertext.is_empty());

        // Content hash should be 32 bytes
        assert_eq!(content_hash.as_bytes().len(), 32);

        // Chain hash should be 32 bytes
        assert_eq!(chain_hash.as_bytes().len(), 32);

        // For version 1, chain_hash should equal content_hash
        assert_eq!(content_hash, chain_hash);
    }

    #[test]
    fn test_encrypt_secrets_chain_hash() {
        use crate::ids::{ProjectId, SecretSetId, VersionNumber};
        use crate::pdk_ops::generate_pdk;

        let entries1 = vec![SecretEntry::new("KEY1".to_string(), "value1".to_string())];
        let entries2 = vec![SecretEntry::new("KEY2".to_string(), "value2".to_string())];

        let project_id = ProjectId::new();
        let set_id = SecretSetId::new();
        let pdk = generate_pdk().unwrap();

        // Encrypt version 1
        let (_, content_hash1, chain_hash1) = encrypt_secrets(
            &entries1,
            &project_id,
            &set_id,
            &VersionNumber::FIRST,
            &VersionNumber::FIRST,
            &pdk,
            None,
        )
        .unwrap();

        // Encrypt version 2 with previous chain hash
        let (_, content_hash2, chain_hash2) = encrypt_secrets(
            &entries2,
            &project_id,
            &set_id,
            &VersionNumber::new(2),
            &VersionNumber::FIRST,
            &pdk,
            Some(&chain_hash1),
        )
        .unwrap();

        // Chain hashes should be different
        assert_ne!(chain_hash1, chain_hash2);

        // Content hashes should be different
        assert_ne!(content_hash1, content_hash2);

        // For version 1, chain_hash should equal content_hash
        assert_eq!(content_hash1, chain_hash1);

        // For version 2, chain_hash should NOT equal content_hash
        assert_ne!(content_hash2, chain_hash2);
    }

    #[test]
    fn test_encrypt_secrets_different_aad() {
        use crate::ids::{ProjectId, SecretSetId, VersionNumber};
        use crate::pdk_ops::generate_pdk;

        let entries = vec![SecretEntry::new("KEY".to_string(), "value".to_string())];

        let project_id1 = ProjectId::new();
        let project_id2 = ProjectId::new();
        let set_id = SecretSetId::new();
        let pdk = generate_pdk().unwrap();

        // Encrypt with different project IDs (different AAD)
        let (ciphertext1, _, _) = encrypt_secrets(
            &entries,
            &project_id1,
            &set_id,
            &VersionNumber::FIRST,
            &VersionNumber::FIRST,
            &pdk,
            None,
        )
        .unwrap();

        let (ciphertext2, _, _) = encrypt_secrets(
            &entries,
            &project_id2,
            &set_id,
            &VersionNumber::FIRST,
            &VersionNumber::FIRST,
            &pdk,
            None,
        )
        .unwrap();

        // Ciphertexts should be different due to different AAD
        assert_ne!(ciphertext1, ciphertext2);
    }

    #[test]
    fn test_encrypt_secrets_deterministic_hashes() {
        use crate::ids::{ProjectId, SecretSetId, VersionNumber};
        use crate::pdk_ops::generate_pdk;

        let entries = vec![SecretEntry::new("KEY".to_string(), "value".to_string())];

        let project_id = ProjectId::new();
        let set_id = SecretSetId::new();
        let pdk = generate_pdk().unwrap();

        // Encrypt twice with same inputs
        let (_, content_hash1, _) = encrypt_secrets(
            &entries,
            &project_id,
            &set_id,
            &VersionNumber::FIRST,
            &VersionNumber::FIRST,
            &pdk,
            None,
        )
        .unwrap();

        let (_, content_hash2, _) = encrypt_secrets(
            &entries,
            &project_id,
            &set_id,
            &VersionNumber::FIRST,
            &VersionNumber::FIRST,
            &pdk,
            None,
        )
        .unwrap();

        // Content hashes should be the same (deterministic)
        assert_eq!(content_hash1, content_hash2);
    }

    #[test]
    fn test_sign_and_verify_version_metadata() {
        use crate::ids::{DeviceId, SecretSetId, VersionNumber};
        use myc_crypto::hash::hash;
        use myc_crypto::sign::generate_ed25519_keypair;
        use time::OffsetDateTime;

        let (device_key, device_pubkey) = generate_ed25519_keypair().unwrap();
        let set_id = SecretSetId::new();
        let device_id = DeviceId::new();
        let content_hash = hash(b"test content");
        let chain_hash = content_hash;
        let created_at = OffsetDateTime::now_utc();

        // Sign metadata
        let signature = sign_version_metadata(
            &set_id,
            &VersionNumber::FIRST,
            &VersionNumber::FIRST,
            created_at,
            &device_id,
            Some("Initial version".to_string()),
            &content_hash,
            &chain_hash,
            None,
            &device_key,
        )
        .unwrap();

        // Verify signature
        assert!(verify_version_metadata(
            &set_id,
            &VersionNumber::FIRST,
            &VersionNumber::FIRST,
            created_at,
            &device_id,
            Some("Initial version".to_string()),
            &content_hash,
            &chain_hash,
            None,
            &signature,
            &device_pubkey,
        )
        .is_ok());
    }

    #[test]
    fn test_verify_fails_with_wrong_key() {
        use crate::ids::{DeviceId, SecretSetId, VersionNumber};
        use myc_crypto::hash::hash;
        use myc_crypto::sign::generate_ed25519_keypair;
        use time::OffsetDateTime;

        let (device_key1, _) = generate_ed25519_keypair().unwrap();
        let (_, device_pubkey2) = generate_ed25519_keypair().unwrap();
        let set_id = SecretSetId::new();
        let device_id = DeviceId::new();
        let content_hash = hash(b"test content");
        let chain_hash = content_hash;
        let created_at = OffsetDateTime::now_utc();

        // Sign with key 1
        let signature = sign_version_metadata(
            &set_id,
            &VersionNumber::FIRST,
            &VersionNumber::FIRST,
            created_at,
            &device_id,
            None,
            &content_hash,
            &chain_hash,
            None,
            &device_key1,
        )
        .unwrap();

        // Verify with key 2 should fail
        assert!(verify_version_metadata(
            &set_id,
            &VersionNumber::FIRST,
            &VersionNumber::FIRST,
            created_at,
            &device_id,
            None,
            &content_hash,
            &chain_hash,
            None,
            &signature,
            &device_pubkey2,
        )
        .is_err());
    }

    #[test]
    fn test_verify_fails_with_modified_metadata() {
        use crate::ids::{DeviceId, SecretSetId, VersionNumber};
        use myc_crypto::hash::hash;
        use myc_crypto::sign::generate_ed25519_keypair;
        use time::OffsetDateTime;

        let (device_key, device_pubkey) = generate_ed25519_keypair().unwrap();
        let set_id = SecretSetId::new();
        let device_id = DeviceId::new();
        let content_hash = hash(b"test content");
        let chain_hash = content_hash;
        let created_at = OffsetDateTime::now_utc();

        // Sign metadata
        let signature = sign_version_metadata(
            &set_id,
            &VersionNumber::FIRST,
            &VersionNumber::FIRST,
            created_at,
            &device_id,
            Some("Original message".to_string()),
            &content_hash,
            &chain_hash,
            None,
            &device_key,
        )
        .unwrap();

        // Verify with modified message should fail
        assert!(verify_version_metadata(
            &set_id,
            &VersionNumber::FIRST,
            &VersionNumber::FIRST,
            created_at,
            &device_id,
            Some("Modified message".to_string()),
            &content_hash,
            &chain_hash,
            None,
            &signature,
            &device_pubkey,
        )
        .is_err());
    }

    #[test]
    fn test_sign_metadata_with_previous_hash() {
        use crate::ids::{DeviceId, SecretSetId, VersionNumber};
        use myc_crypto::hash::hash;
        use myc_crypto::sign::generate_ed25519_keypair;
        use time::OffsetDateTime;

        let (device_key, device_pubkey) = generate_ed25519_keypair().unwrap();
        let set_id = SecretSetId::new();
        let device_id = DeviceId::new();
        let content_hash = hash(b"test content");
        let previous_hash = hash(b"previous content");
        let chain_hash = hash(b"chained");
        let created_at = OffsetDateTime::now_utc();

        // Sign metadata with previous hash
        let signature = sign_version_metadata(
            &set_id,
            &VersionNumber::new(2),
            &VersionNumber::FIRST,
            created_at,
            &device_id,
            None,
            &content_hash,
            &chain_hash,
            Some(&previous_hash),
            &device_key,
        )
        .unwrap();

        // Verify signature
        assert!(verify_version_metadata(
            &set_id,
            &VersionNumber::new(2),
            &VersionNumber::FIRST,
            created_at,
            &device_id,
            None,
            &content_hash,
            &chain_hash,
            Some(&previous_hash),
            &signature,
            &device_pubkey,
        )
        .is_ok());
    }

    #[test]
    fn test_decrypt_secrets_roundtrip() {
        use crate::ids::{ProjectId, SecretSetId, VersionNumber};
        use crate::pdk_ops::generate_pdk;

        let entries = vec![
            SecretEntry::new("API_KEY".to_string(), "secret123".to_string()),
            SecretEntry::new("DATABASE_URL".to_string(), "postgres://...".to_string()),
        ];

        let project_id = ProjectId::new();
        let set_id = SecretSetId::new();
        let pdk = generate_pdk().unwrap();

        // Encrypt
        let (ciphertext, content_hash, chain_hash) = encrypt_secrets(
            &entries,
            &project_id,
            &set_id,
            &VersionNumber::FIRST,
            &VersionNumber::FIRST,
            &pdk,
            None,
        )
        .unwrap();

        // Decrypt
        let decrypted = decrypt_secrets(
            &ciphertext,
            &project_id,
            &set_id,
            &VersionNumber::FIRST,
            &VersionNumber::FIRST,
            &pdk,
            &content_hash,
            &chain_hash,
            None,
        )
        .unwrap();

        // Should match original entries (sorted by key)
        let mut expected = entries.clone();
        expected.sort_by(|a, b| a.key.cmp(&b.key));
        assert_eq!(expected, decrypted);
    }

    #[test]
    fn test_decrypt_with_wrong_pdk() {
        use crate::ids::{ProjectId, SecretSetId, VersionNumber};
        use crate::pdk_ops::generate_pdk;

        let entries = vec![SecretEntry::new("KEY".to_string(), "value".to_string())];

        let project_id = ProjectId::new();
        let set_id = SecretSetId::new();
        let pdk1 = generate_pdk().unwrap();
        let pdk2 = generate_pdk().unwrap();

        // Encrypt with pdk1
        let (ciphertext, content_hash, chain_hash) = encrypt_secrets(
            &entries,
            &project_id,
            &set_id,
            &VersionNumber::FIRST,
            &VersionNumber::FIRST,
            &pdk1,
            None,
        )
        .unwrap();

        // Try to decrypt with pdk2
        let result = decrypt_secrets(
            &ciphertext,
            &project_id,
            &set_id,
            &VersionNumber::FIRST,
            &VersionNumber::FIRST,
            &pdk2,
            &content_hash,
            &chain_hash,
            None,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_with_tampered_ciphertext() {
        use crate::ids::{ProjectId, SecretSetId, VersionNumber};
        use crate::pdk_ops::generate_pdk;

        let entries = vec![SecretEntry::new("KEY".to_string(), "value".to_string())];

        let project_id = ProjectId::new();
        let set_id = SecretSetId::new();
        let pdk = generate_pdk().unwrap();

        // Encrypt
        let (mut ciphertext, content_hash, chain_hash) = encrypt_secrets(
            &entries,
            &project_id,
            &set_id,
            &VersionNumber::FIRST,
            &VersionNumber::FIRST,
            &pdk,
            None,
        )
        .unwrap();

        // Tamper with ciphertext
        if ciphertext.len() > 20 {
            ciphertext[20] ^= 0xFF;
        }

        // Try to decrypt
        let result = decrypt_secrets(
            &ciphertext,
            &project_id,
            &set_id,
            &VersionNumber::FIRST,
            &VersionNumber::FIRST,
            &pdk,
            &content_hash,
            &chain_hash,
            None,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_with_wrong_content_hash() {
        use crate::ids::{ProjectId, SecretSetId, VersionNumber};
        use crate::pdk_ops::generate_pdk;
        use myc_crypto::hash::hash;

        let entries = vec![SecretEntry::new("KEY".to_string(), "value".to_string())];

        let project_id = ProjectId::new();
        let set_id = SecretSetId::new();
        let pdk = generate_pdk().unwrap();

        // Encrypt
        let (ciphertext, _, chain_hash) = encrypt_secrets(
            &entries,
            &project_id,
            &set_id,
            &VersionNumber::FIRST,
            &VersionNumber::FIRST,
            &pdk,
            None,
        )
        .unwrap();

        // Use wrong content hash
        let wrong_content_hash = hash(b"wrong content");

        // Try to decrypt
        let result = decrypt_secrets(
            &ciphertext,
            &project_id,
            &set_id,
            &VersionNumber::FIRST,
            &VersionNumber::FIRST,
            &pdk,
            &wrong_content_hash,
            &chain_hash,
            None,
        );

        assert!(result.is_err());
        assert!(matches!(result, Err(CoreError::HashMismatch { .. })));
    }

    #[test]
    fn test_validate_size_limits_ok() {
        let entries = vec![
            SecretEntry::new("API_KEY".to_string(), "secret123".to_string()),
            SecretEntry::new("DATABASE_URL".to_string(), "postgres://...".to_string()),
        ];

        assert!(validate_size_limits(&entries).is_ok());
    }

    #[test]
    fn test_validate_size_limits_too_many_entries() {
        // Create more than MAX_ENTRIES
        let mut entries = Vec::new();
        for i in 0..MAX_ENTRIES + 1 {
            entries.push(SecretEntry::new(format!("KEY_{}", i), "value".to_string()));
        }

        let result = validate_size_limits(&entries);
        assert!(result.is_err());
        assert!(matches!(result, Err(CoreError::SizeLimitExceeded { .. })));
    }

    #[test]
    fn test_validate_size_limits_key_too_long() {
        let long_key = "A".repeat(MAX_KEY_LENGTH + 1);
        let entries = vec![SecretEntry::new(long_key, "value".to_string())];

        let result = validate_size_limits(&entries);
        assert!(result.is_err());
        assert!(matches!(result, Err(CoreError::SizeLimitExceeded { .. })));
    }

    #[test]
    fn test_validate_size_limits_value_too_long() {
        let long_value = "A".repeat(MAX_VALUE_LENGTH + 1);
        let entries = vec![SecretEntry::new("KEY".to_string(), long_value)];

        let result = validate_size_limits(&entries);
        assert!(result.is_err());
        assert!(matches!(result, Err(CoreError::SizeLimitExceeded { .. })));
    }

    #[test]
    fn test_validate_size_limits_total_size_too_large() {
        // Create entries that together exceed MAX_PLAINTEXT_SIZE
        let large_value = "A".repeat(MAX_VALUE_LENGTH); // 1MB each
        let mut entries = Vec::new();

        // Add 11 entries of 1MB each = 11MB > 10MB limit
        for i in 0..11 {
            entries.push(SecretEntry::new(format!("KEY_{}", i), large_value.clone()));
        }

        let result = validate_size_limits(&entries);
        assert!(result.is_err());
        assert!(matches!(result, Err(CoreError::SizeLimitExceeded { .. })));
    }

    #[test]
    fn test_validate_size_limits_at_boundary() {
        // Test with exactly MAX_KEY_LENGTH
        let key_at_limit = "A".repeat(MAX_KEY_LENGTH);
        let entries = vec![SecretEntry::new(key_at_limit, "value".to_string())];

        assert!(validate_size_limits(&entries).is_ok());
    }

    #[test]
    fn test_decrypt_chain_hash_verification() {
        use crate::ids::{ProjectId, SecretSetId, VersionNumber};
        use crate::pdk_ops::generate_pdk;

        let entries1 = vec![SecretEntry::new("KEY1".to_string(), "value1".to_string())];
        let entries2 = vec![SecretEntry::new("KEY2".to_string(), "value2".to_string())];

        let project_id = ProjectId::new();
        let set_id = SecretSetId::new();
        let pdk = generate_pdk().unwrap();

        // Encrypt version 1
        let (ciphertext1, content_hash1, chain_hash1) = encrypt_secrets(
            &entries1,
            &project_id,
            &set_id,
            &VersionNumber::FIRST,
            &VersionNumber::FIRST,
            &pdk,
            None,
        )
        .unwrap();

        // Encrypt version 2 with chain
        let (ciphertext2, content_hash2, chain_hash2) = encrypt_secrets(
            &entries2,
            &project_id,
            &set_id,
            &VersionNumber::new(2),
            &VersionNumber::FIRST,
            &pdk,
            Some(&chain_hash1),
        )
        .unwrap();

        // Decrypt version 1
        let decrypted1 = decrypt_secrets(
            &ciphertext1,
            &project_id,
            &set_id,
            &VersionNumber::FIRST,
            &VersionNumber::FIRST,
            &pdk,
            &content_hash1,
            &chain_hash1,
            None,
        )
        .unwrap();

        assert_eq!(decrypted1.len(), 1);

        // Decrypt version 2 with correct previous hash
        let decrypted2 = decrypt_secrets(
            &ciphertext2,
            &project_id,
            &set_id,
            &VersionNumber::new(2),
            &VersionNumber::FIRST,
            &pdk,
            &content_hash2,
            &chain_hash2,
            Some(&chain_hash1),
        )
        .unwrap();

        assert_eq!(decrypted2.len(), 1);

        // Try to decrypt version 2 with wrong previous hash
        let result = decrypt_secrets(
            &ciphertext2,
            &project_id,
            &set_id,
            &VersionNumber::new(2),
            &VersionNumber::FIRST,
            &pdk,
            &content_hash2,
            &chain_hash2,
            None, // Wrong: should have previous hash
        );

        assert!(result.is_err());
        assert!(matches!(result, Err(CoreError::ChainBroken { .. })));
    }

    #[test]
    fn test_create_version() {
        use crate::ids::{DeviceId, ProjectId, SecretSetId, VersionNumber};
        use crate::pdk_ops::generate_pdk;
        use myc_crypto::sign::generate_ed25519_keypair;

        let entries = vec![SecretEntry::new(
            "API_KEY".to_string(),
            "secret123".to_string(),
        )];

        let project_id = ProjectId::new();
        let set_id = SecretSetId::new();
        let device_id = DeviceId::new();
        let pdk = generate_pdk().unwrap();
        let (device_key, _) = generate_ed25519_keypair().unwrap();

        let version = create_version(
            &entries,
            &set_id,
            &VersionNumber::FIRST,
            &VersionNumber::FIRST,
            &project_id,
            &pdk,
            &device_id,
            &device_key,
            Some("Initial version".to_string()),
            None,
        )
        .unwrap();

        assert_eq!(version.set_id, set_id);
        assert_eq!(version.version, VersionNumber::FIRST);
        assert_eq!(version.created_by, device_id);
        assert_eq!(version.message, Some("Initial version".to_string()));
    }

    #[test]
    fn test_read_version() {
        use crate::ids::{DeviceId, ProjectId, SecretSetId, VersionNumber};
        use crate::pdk_ops::generate_pdk;
        use myc_crypto::sign::generate_ed25519_keypair;

        let entries = vec![
            SecretEntry::new("API_KEY".to_string(), "secret123".to_string()),
            SecretEntry::new("DATABASE_URL".to_string(), "postgres://...".to_string()),
        ];

        let project_id = ProjectId::new();
        let set_id = SecretSetId::new();
        let device_id = DeviceId::new();
        let pdk = generate_pdk().unwrap();
        let (device_key, device_pubkey) = generate_ed25519_keypair().unwrap();

        // Create version
        let version = create_version(
            &entries,
            &set_id,
            &VersionNumber::FIRST,
            &VersionNumber::FIRST,
            &project_id,
            &pdk,
            &device_id,
            &device_key,
            None,
            None,
        )
        .unwrap();

        // Read version
        let decrypted = read_version(&version, &project_id, &pdk, &device_pubkey, None).unwrap();

        // Should match original entries (sorted by key)
        let mut expected = entries.clone();
        expected.sort_by(|a, b| a.key.cmp(&b.key));
        assert_eq!(expected, decrypted);
    }

    #[test]
    fn test_verify_chain_single_version() {
        use crate::ids::{DeviceId, ProjectId, SecretSetId, VersionNumber};
        use crate::pdk_ops::generate_pdk;
        use myc_crypto::sign::generate_ed25519_keypair;

        let project_id = ProjectId::new();
        let set_id = SecretSetId::new();
        let device_id = DeviceId::new();
        let pdk = generate_pdk().unwrap();
        let (device_key, _) = generate_ed25519_keypair().unwrap();

        let entries = vec![SecretEntry::new("KEY".to_string(), "value".to_string())];
        let v1 = create_version(
            &entries,
            &set_id,
            &VersionNumber::FIRST,
            &VersionNumber::FIRST,
            &project_id,
            &pdk,
            &device_id,
            &device_key,
            None,
            None,
        )
        .unwrap();

        assert!(verify_chain(&[v1]).is_ok());
    }

    #[test]
    fn test_verify_chain_multiple_versions() {
        use crate::ids::{DeviceId, ProjectId, SecretSetId, VersionNumber};
        use crate::pdk_ops::generate_pdk;
        use myc_crypto::sign::generate_ed25519_keypair;

        let project_id = ProjectId::new();
        let set_id = SecretSetId::new();
        let device_id = DeviceId::new();
        let pdk = generate_pdk().unwrap();
        let (device_key, _) = generate_ed25519_keypair().unwrap();

        // Create version 1
        let entries1 = vec![SecretEntry::new("KEY1".to_string(), "value1".to_string())];
        let v1 = create_version(
            &entries1,
            &set_id,
            &VersionNumber::FIRST,
            &VersionNumber::FIRST,
            &project_id,
            &pdk,
            &device_id,
            &device_key,
            None,
            None,
        )
        .unwrap();

        // Create version 2 with chain
        let entries2 = vec![SecretEntry::new("KEY2".to_string(), "value2".to_string())];
        let chain_hash1 = compute_chain_hash(&v1);
        let v2 = create_version(
            &entries2,
            &set_id,
            &VersionNumber::new(2),
            &VersionNumber::FIRST,
            &project_id,
            &pdk,
            &device_id,
            &device_key,
            None,
            Some(&chain_hash1),
        )
        .unwrap();

        // Create version 3 with chain
        let entries3 = vec![SecretEntry::new("KEY3".to_string(), "value3".to_string())];
        let chain_hash2 = compute_chain_hash(&v2);
        let v3 = create_version(
            &entries3,
            &set_id,
            &VersionNumber::new(3),
            &VersionNumber::FIRST,
            &project_id,
            &pdk,
            &device_id,
            &device_key,
            None,
            Some(&chain_hash2),
        )
        .unwrap();

        // Verify chain
        assert!(verify_chain(&[v1, v2, v3]).is_ok());
    }

    #[test]
    fn test_verify_chain_broken() {
        use crate::ids::{DeviceId, ProjectId, SecretSetId, VersionNumber};
        use crate::pdk_ops::generate_pdk;
        use myc_crypto::sign::generate_ed25519_keypair;

        let project_id = ProjectId::new();
        let set_id = SecretSetId::new();
        let device_id = DeviceId::new();
        let pdk = generate_pdk().unwrap();
        let (device_key, _) = generate_ed25519_keypair().unwrap();

        // Create version 1
        let entries1 = vec![SecretEntry::new("KEY1".to_string(), "value1".to_string())];
        let v1 = create_version(
            &entries1,
            &set_id,
            &VersionNumber::FIRST,
            &VersionNumber::FIRST,
            &project_id,
            &pdk,
            &device_id,
            &device_key,
            None,
            None,
        )
        .unwrap();

        // Create version 2 WITHOUT proper chain (using None instead of v1's chain hash)
        let entries2 = vec![SecretEntry::new("KEY2".to_string(), "value2".to_string())];
        let v2 = create_version(
            &entries2,
            &set_id,
            &VersionNumber::new(2),
            &VersionNumber::FIRST,
            &project_id,
            &pdk,
            &device_id,
            &device_key,
            None,
            None, // Wrong: should have previous hash
        )
        .unwrap();

        // Verify chain should fail
        let result = verify_chain(&[v1, v2]);
        assert!(result.is_err());
        assert!(matches!(result, Err(CoreError::ChainBroken { .. })));
    }

    #[test]
    fn test_create_version_with_size_limit_exceeded() {
        use crate::ids::{DeviceId, ProjectId, SecretSetId, VersionNumber};
        use crate::pdk_ops::generate_pdk;
        use myc_crypto::sign::generate_ed25519_keypair;

        // Create entries that exceed size limit
        let large_value = "A".repeat(MAX_VALUE_LENGTH + 1);
        let entries = vec![SecretEntry::new("KEY".to_string(), large_value)];

        let project_id = ProjectId::new();
        let set_id = SecretSetId::new();
        let device_id = DeviceId::new();
        let pdk = generate_pdk().unwrap();
        let (device_key, _) = generate_ed25519_keypair().unwrap();

        let result = create_version(
            &entries,
            &set_id,
            &VersionNumber::FIRST,
            &VersionNumber::FIRST,
            &project_id,
            &pdk,
            &device_id,
            &device_key,
            None,
            None,
        );

        assert!(result.is_err());
        assert!(matches!(result, Err(CoreError::SizeLimitExceeded { .. })));
    }
}
