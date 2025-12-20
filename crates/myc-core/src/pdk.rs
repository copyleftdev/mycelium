//! PDK (Project Data Key) versioning and wrapping types.

use crate::ids::{DeviceId, VersionNumber};
use myc_crypto::kex::X25519PublicKey;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// PDK version metadata.
///
/// Each PDK version contains the wrapped PDK encrypted to authorized devices.
/// PDK versions are immutable and stored permanently for audit purposes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PdkVersion {
    /// Version number of this PDK.
    pub version: VersionNumber,

    /// Creation timestamp (RFC 3339).
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,

    /// Device that created this PDK version.
    pub created_by: DeviceId,

    /// Optional reason for PDK creation/rotation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,

    /// List of wrapped PDKs, one per authorized device.
    pub wrapped_keys: Vec<WrappedPdk>,
}

impl PdkVersion {
    /// Create a new PDK version.
    pub fn new(
        version: VersionNumber,
        created_by: DeviceId,
        reason: Option<String>,
        wrapped_keys: Vec<WrappedPdk>,
    ) -> Self {
        Self {
            version,
            created_at: OffsetDateTime::now_utc(),
            created_by,
            reason,
            wrapped_keys,
        }
    }

    /// Find a wrapped PDK for a specific device.
    pub fn find_wrapped_pdk(&self, device_id: &DeviceId) -> Option<&WrappedPdk> {
        self.wrapped_keys.iter().find(|w| &w.device_id == device_id)
    }

    /// Check if a device has access to this PDK version.
    pub fn has_device_access(&self, device_id: &DeviceId) -> bool {
        self.find_wrapped_pdk(device_id).is_some()
    }

    /// Get the number of devices with access to this PDK.
    pub fn device_count(&self) -> usize {
        self.wrapped_keys.len()
    }
}

/// A PDK wrapped (encrypted) to a specific device's public key.
///
/// This uses ECIES-style encryption: ephemeral X25519 keypair is generated,
/// shared secret is derived via Diffie-Hellman, wrap key is derived via HKDF,
/// and PDK is encrypted with the wrap key using AEAD.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedPdk {
    /// Device this PDK is wrapped to.
    pub device_id: DeviceId,

    /// Ephemeral X25519 public key used for key agreement.
    #[serde(with = "x25519_pubkey_serde")]
    pub ephemeral_pubkey: X25519PublicKey,

    /// Encrypted PDK (nonce || ciphertext || tag).
    ///
    /// Structure: 12 bytes nonce + 32 bytes PDK + 16 bytes auth tag = 60 bytes total.
    #[serde(with = "base64_serde")]
    pub ciphertext: Vec<u8>,
}

impl WrappedPdk {
    /// Expected size of wrapped PDK ciphertext (nonce + PDK + tag).
    pub const CIPHERTEXT_SIZE: usize = 12 + 32 + 16; // 60 bytes

    /// Create a new wrapped PDK.
    pub fn new(
        device_id: DeviceId,
        ephemeral_pubkey: X25519PublicKey,
        ciphertext: Vec<u8>,
    ) -> Self {
        Self {
            device_id,
            ephemeral_pubkey,
            ciphertext,
        }
    }
}

// Serde helpers for X25519PublicKey
mod x25519_pubkey_serde {
    use myc_crypto::kex::X25519PublicKey;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(key: &X25519PublicKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, key.as_bytes());
        serializer.serialize_str(&encoded)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<X25519PublicKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &s)
            .map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("invalid X25519 public key length"));
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(X25519PublicKey::from_bytes(array))
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

#[cfg(test)]
mod tests {
    use super::*;
    use myc_crypto::kex::generate_x25519_keypair;

    #[test]
    fn test_pdk_version_creation() {
        let device_id = DeviceId::new();
        let version = VersionNumber::FIRST;

        let pdk_version =
            PdkVersion::new(version, device_id, Some("Initial PDK".to_string()), vec![]);

        assert_eq!(pdk_version.version, version);
        assert_eq!(pdk_version.created_by, device_id);
        assert_eq!(pdk_version.reason, Some("Initial PDK".to_string()));
        assert_eq!(pdk_version.device_count(), 0);
    }

    #[test]
    fn test_pdk_version_find_wrapped_pdk() {
        let device_id1 = DeviceId::new();
        let device_id2 = DeviceId::new();
        let device_id3 = DeviceId::new();

        let (_, ephemeral_pubkey1) = generate_x25519_keypair().unwrap();
        let (_, ephemeral_pubkey2) = generate_x25519_keypair().unwrap();

        let wrapped1 = WrappedPdk::new(device_id1, ephemeral_pubkey1, vec![1, 2, 3]);
        let wrapped2 = WrappedPdk::new(device_id2, ephemeral_pubkey2, vec![4, 5, 6]);

        let pdk_version = PdkVersion::new(
            VersionNumber::FIRST,
            device_id1,
            None,
            vec![wrapped1.clone(), wrapped2.clone()],
        );

        // Should find device 1
        assert!(pdk_version.find_wrapped_pdk(&device_id1).is_some());
        assert_eq!(
            pdk_version.find_wrapped_pdk(&device_id1).unwrap(),
            &wrapped1
        );

        // Should find device 2
        assert!(pdk_version.find_wrapped_pdk(&device_id2).is_some());
        assert_eq!(
            pdk_version.find_wrapped_pdk(&device_id2).unwrap(),
            &wrapped2
        );

        // Should not find device 3
        assert!(pdk_version.find_wrapped_pdk(&device_id3).is_none());
    }

    #[test]
    fn test_pdk_version_has_device_access() {
        let device_id1 = DeviceId::new();
        let device_id2 = DeviceId::new();
        let device_id3 = DeviceId::new();

        let (_, ephemeral_pubkey) = generate_x25519_keypair().unwrap();
        let wrapped = WrappedPdk::new(device_id1, ephemeral_pubkey, vec![1, 2, 3]);

        let pdk_version = PdkVersion::new(VersionNumber::FIRST, device_id1, None, vec![wrapped]);

        assert!(pdk_version.has_device_access(&device_id1));
        assert!(!pdk_version.has_device_access(&device_id2));
        assert!(!pdk_version.has_device_access(&device_id3));
    }

    #[test]
    fn test_pdk_version_device_count() {
        let device_id = DeviceId::new();

        let (_, ephemeral_pubkey1) = generate_x25519_keypair().unwrap();
        let (_, ephemeral_pubkey2) = generate_x25519_keypair().unwrap();
        let (_, ephemeral_pubkey3) = generate_x25519_keypair().unwrap();

        let wrapped1 = WrappedPdk::new(DeviceId::new(), ephemeral_pubkey1, vec![1, 2, 3]);
        let wrapped2 = WrappedPdk::new(DeviceId::new(), ephemeral_pubkey2, vec![4, 5, 6]);
        let wrapped3 = WrappedPdk::new(DeviceId::new(), ephemeral_pubkey3, vec![7, 8, 9]);

        let pdk_version = PdkVersion::new(
            VersionNumber::FIRST,
            device_id,
            None,
            vec![wrapped1, wrapped2, wrapped3],
        );

        assert_eq!(pdk_version.device_count(), 3);
    }

    #[test]
    fn test_wrapped_pdk_creation() {
        let device_id = DeviceId::new();
        let (_, ephemeral_pubkey) = generate_x25519_keypair().unwrap();
        let ciphertext = vec![1, 2, 3, 4, 5];

        let wrapped = WrappedPdk::new(device_id, ephemeral_pubkey, ciphertext.clone());

        assert_eq!(wrapped.device_id, device_id);
        assert_eq!(wrapped.ephemeral_pubkey, ephemeral_pubkey);
        assert_eq!(wrapped.ciphertext, ciphertext);
    }

    #[test]
    fn test_pdk_version_serialization() {
        let device_id = DeviceId::new();
        let (_, ephemeral_pubkey) = generate_x25519_keypair().unwrap();
        let wrapped = WrappedPdk::new(device_id, ephemeral_pubkey, vec![1, 2, 3]);

        let pdk_version = PdkVersion::new(
            VersionNumber::FIRST,
            device_id,
            Some("Test rotation".to_string()),
            vec![wrapped],
        );

        let json = serde_json::to_string(&pdk_version).unwrap();
        let deserialized: PdkVersion = serde_json::from_str(&json).unwrap();
        assert_eq!(pdk_version, deserialized);
    }

    #[test]
    fn test_wrapped_pdk_serialization() {
        let device_id = DeviceId::new();
        let (_, ephemeral_pubkey) = generate_x25519_keypair().unwrap();
        let wrapped = WrappedPdk::new(device_id, ephemeral_pubkey, vec![1, 2, 3, 4, 5]);

        let json = serde_json::to_string(&wrapped).unwrap();
        let deserialized: WrappedPdk = serde_json::from_str(&json).unwrap();
        assert_eq!(wrapped, deserialized);
    }
}
