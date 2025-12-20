//! Secret set and version types.

use crate::error::{Result, ValidationError};
use crate::ids::{DeviceId, ProjectId, SecretSetId, VersionNumber};
use myc_crypto::hash::HashOutput;
use myc_crypto::sign::Signature;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Secret set metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretSet {
    /// Schema version for forward compatibility.
    pub schema_version: u32,

    /// Unique secret set identifier.
    pub id: SecretSetId,

    /// Project this secret set belongs to.
    pub project_id: ProjectId,

    /// Secret set name (e.g., "production", "staging").
    pub name: String,

    /// Creation timestamp (RFC 3339).
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,

    /// Device that created this secret set.
    pub created_by: DeviceId,

    /// Current version number.
    pub current_version: VersionNumber,
}

impl SecretSet {
    /// The current schema version.
    pub const SCHEMA_VERSION: u32 = 1;

    /// Maximum name length in characters.
    pub const MAX_NAME_LENGTH: usize = 256;

    /// Create a new secret set.
    pub fn new(project_id: ProjectId, name: String, created_by: DeviceId) -> Self {
        Self {
            schema_version: Self::SCHEMA_VERSION,
            id: SecretSetId::new(),
            project_id,
            name,
            created_at: OffsetDateTime::now_utc(),
            created_by,
            current_version: VersionNumber::FIRST,
        }
    }

    /// Validate the secret set.
    pub fn validate(&self) -> Result<()> {
        // Validate name
        if self.name.is_empty() {
            return Err(ValidationError::InvalidName {
                reason: "name cannot be empty".to_string(),
            }
            .into());
        }

        if self.name.len() > Self::MAX_NAME_LENGTH {
            return Err(ValidationError::InvalidName {
                reason: format!(
                    "name exceeds maximum length of {} characters",
                    Self::MAX_NAME_LENGTH
                ),
            }
            .into());
        }

        // Validate timestamp is not in the future
        let now = OffsetDateTime::now_utc();
        if self.created_at > now {
            return Err(ValidationError::FutureTimestamp {
                timestamp: self.created_at.to_string(),
            }
            .into());
        }

        Ok(())
    }
}

/// Secret set version metadata.
///
/// This contains metadata about a specific version of a secret set,
/// including cryptographic hashes and signatures for integrity verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretSetVersion {
    /// Schema version for forward compatibility.
    pub schema_version: u32,

    /// Secret set identifier.
    pub set_id: SecretSetId,

    /// Version number.
    pub version: VersionNumber,

    /// PDK version used to encrypt this version.
    pub pdk_version: VersionNumber,

    /// Creation timestamp (RFC 3339).
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,

    /// Device that created this version.
    pub created_by: DeviceId,

    /// Optional commit message.
    pub message: Option<String>,

    /// BLAKE3 hash of the plaintext content.
    #[serde(with = "hash_serde")]
    pub content_hash: HashOutput,

    /// BLAKE3 hash of the previous version's chain hash (None for version 1).
    #[serde(with = "option_hash_serde")]
    pub previous_hash: Option<HashOutput>,

    /// Ciphertext (encrypted secret entries).
    #[serde(with = "base64_serde")]
    pub ciphertext: Vec<u8>,

    /// Ed25519 signature over canonical JSON of metadata.
    #[serde(with = "signature_serde")]
    pub signature: Signature,
}

impl SecretSetVersion {
    /// The current schema version.
    pub const SCHEMA_VERSION: u32 = 1;

    /// Maximum plaintext size in bytes (10MB).
    pub const MAX_PLAINTEXT_SIZE: usize = 10 * 1024 * 1024;

    /// Maximum number of entries per secret set.
    pub const MAX_ENTRIES: usize = 10_000;

    /// Validate the version.
    pub fn validate(&self) -> Result<()> {
        // Validate timestamp is not in the future
        let now = OffsetDateTime::now_utc();
        if self.created_at > now {
            return Err(ValidationError::FutureTimestamp {
                timestamp: self.created_at.to_string(),
            }
            .into());
        }

        Ok(())
    }
}

/// A single secret entry (key-value pair).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretEntry {
    /// Secret key (environment variable name).
    pub key: String,

    /// Secret value.
    pub value: String,

    /// Optional metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<EntryMetadata>,
}

impl SecretEntry {
    /// Create a new secret entry.
    pub fn new(key: String, value: String) -> Self {
        Self {
            key,
            value,
            metadata: None,
        }
    }

    /// Create a new secret entry with metadata.
    pub fn with_metadata(key: String, value: String, metadata: EntryMetadata) -> Self {
        Self {
            key,
            value,
            metadata: Some(metadata),
        }
    }
}

/// Metadata for a secret entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct EntryMetadata {
    /// Optional description of the secret.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// When the entry was created (RFC 3339).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "option_rfc3339")]
    pub created_at: Option<OffsetDateTime>,

    /// When the entry was last updated (RFC 3339).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "option_rfc3339")]
    pub updated_at: Option<OffsetDateTime>,

    /// Optional tags for categorization.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub tags: Vec<String>,
}

// Serde helpers for HashOutput
mod hash_serde {
    use myc_crypto::hash::HashOutput;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(hash: &HashOutput, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, hash.as_bytes());
        serializer.serialize_str(&encoded)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<HashOutput, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &s)
            .map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("invalid hash length"));
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(HashOutput::from_bytes(array))
    }
}

mod option_hash_serde {
    use myc_crypto::hash::HashOutput;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(hash: &Option<HashOutput>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match hash {
            Some(h) => {
                let encoded = base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    h.as_bytes(),
                );
                serializer.serialize_some(&encoded)
            }
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<HashOutput>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt = Option::<String>::deserialize(deserializer)?;
        match opt {
            Some(s) => {
                let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &s)
                    .map_err(serde::de::Error::custom)?;
                if bytes.len() != 32 {
                    return Err(serde::de::Error::custom("invalid hash length"));
                }
                let mut array = [0u8; 32];
                array.copy_from_slice(&bytes);
                Ok(Some(HashOutput::from_bytes(array)))
            }
            None => Ok(None),
        }
    }
}

// Serde helpers for Signature
mod signature_serde {
    use myc_crypto::sign::Signature;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(sig: &Signature, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sig.as_bytes());
        serializer.serialize_str(&encoded)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Signature, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &s)
            .map_err(serde::de::Error::custom)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::custom("invalid signature length"));
        }
        let mut array = [0u8; 64];
        array.copy_from_slice(&bytes);
        Ok(Signature::from_bytes(array))
    }
}

// Serde helpers for Vec<u8> as base64
mod base64_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes);
        serializer.serialize_str(&encoded)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &s)
            .map_err(serde::de::Error::custom)
    }
}

// Serde helpers for Option<OffsetDateTime>
mod option_rfc3339 {
    use serde::{Deserialize, Deserializer, Serializer};
    use time::OffsetDateTime;

    pub fn serialize<S>(dt: &Option<OffsetDateTime>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match dt {
            Some(dt) => time::serde::rfc3339::serialize(dt, serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<OffsetDateTime>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<String>::deserialize(deserializer)?
            .map(|s| {
                OffsetDateTime::parse(&s, &time::format_description::well_known::Rfc3339)
                    .map_err(serde::de::Error::custom)
            })
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use myc_crypto::hash::hash;
    use myc_crypto::sign::{generate_ed25519_keypair, sign};

    #[test]
    fn test_secret_set_creation() {
        let project_id = ProjectId::new();
        let device_id = DeviceId::new();
        let set = SecretSet::new(project_id, "production".to_string(), device_id);

        assert_eq!(set.schema_version, SecretSet::SCHEMA_VERSION);
        assert_eq!(set.name, "production");
        assert_eq!(set.project_id, project_id);
        assert_eq!(set.created_by, device_id);
        assert_eq!(set.current_version, VersionNumber::FIRST);
        assert!(set.validate().is_ok());
    }

    #[test]
    fn test_secret_set_validation_empty_name() {
        let project_id = ProjectId::new();
        let device_id = DeviceId::new();
        let mut set = SecretSet::new(project_id, "production".to_string(), device_id);
        set.name = String::new();
        assert!(set.validate().is_err());
    }

    #[test]
    fn test_secret_set_serialization() {
        let project_id = ProjectId::new();
        let device_id = DeviceId::new();
        let set = SecretSet::new(project_id, "production".to_string(), device_id);

        let json = serde_json::to_string(&set).unwrap();
        let deserialized: SecretSet = serde_json::from_str(&json).unwrap();
        assert_eq!(set, deserialized);
    }

    #[test]
    fn test_secret_entry_creation() {
        let entry = SecretEntry::new("API_KEY".to_string(), "secret123".to_string());
        assert_eq!(entry.key, "API_KEY");
        assert_eq!(entry.value, "secret123");
        assert!(entry.metadata.is_none());
    }

    #[test]
    fn test_secret_entry_with_metadata() {
        let metadata = EntryMetadata {
            description: Some("API key for service".to_string()),
            created_at: Some(OffsetDateTime::now_utc()),
            updated_at: None,
            tags: vec!["api".to_string(), "production".to_string()],
        };

        let entry = SecretEntry::with_metadata(
            "API_KEY".to_string(),
            "secret123".to_string(),
            metadata.clone(),
        );

        assert_eq!(entry.key, "API_KEY");
        assert_eq!(entry.value, "secret123");
        assert_eq!(entry.metadata, Some(metadata));
    }

    #[test]
    fn test_secret_entry_serialization() {
        let entry = SecretEntry::new("API_KEY".to_string(), "secret123".to_string());
        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: SecretEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, deserialized);
    }

    #[test]
    fn test_secret_set_version_serialization() {
        let (secret_key, _) = generate_ed25519_keypair().unwrap();
        let set_id = SecretSetId::new();
        let device_id = DeviceId::new();
        let content_hash = hash(b"test content");
        let signature = sign(&secret_key, b"test message");

        let version = SecretSetVersion {
            schema_version: SecretSetVersion::SCHEMA_VERSION,
            set_id,
            version: VersionNumber::FIRST,
            pdk_version: VersionNumber::FIRST,
            created_at: OffsetDateTime::now_utc(),
            created_by: device_id,
            message: Some("Initial version".to_string()),
            content_hash,
            previous_hash: None,
            ciphertext: vec![1, 2, 3, 4, 5],
            signature,
        };

        let json = serde_json::to_string(&version).unwrap();
        let deserialized: SecretSetVersion = serde_json::from_str(&json).unwrap();
        assert_eq!(version, deserialized);
    }

    #[test]
    fn test_entry_metadata_default() {
        let metadata = EntryMetadata::default();
        assert!(metadata.description.is_none());
        assert!(metadata.created_at.is_none());
        assert!(metadata.updated_at.is_none());
        assert!(metadata.tags.is_empty());
    }
}
