//! Device identity types.

use crate::error::{Result, ValidationError};
use crate::ids::{DeviceId, UserId};
use myc_crypto::kex::X25519PublicKey;
use myc_crypto::sign::Ed25519PublicKey;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Device metadata.
///
/// A device represents a physical machine or CI runner with enrolled
/// cryptographic keys. Each device has both signing and encryption keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    /// Schema version for forward compatibility.
    pub schema_version: u32,

    /// Unique device identifier.
    pub id: DeviceId,

    /// User this device belongs to.
    pub user_id: UserId,

    /// Human-readable device name.
    pub name: String,

    /// Type of device (interactive or CI).
    pub device_type: DeviceType,

    /// Ed25519 public key for signature verification.
    #[serde(with = "ed25519_pubkey_serde")]
    pub signing_pubkey: Ed25519PublicKey,

    /// X25519 public key for key wrapping.
    #[serde(with = "x25519_pubkey_serde")]
    pub encryption_pubkey: X25519PublicKey,

    /// Enrollment timestamp (RFC 3339).
    #[serde(with = "time::serde::rfc3339")]
    pub enrolled_at: OffsetDateTime,

    /// Current device status.
    pub status: DeviceStatus,

    /// Optional expiration timestamp for CI devices (RFC 3339).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    #[serde(with = "option_rfc3339")]
    pub expires_at: Option<OffsetDateTime>,
}

impl Device {
    /// The current schema version.
    pub const SCHEMA_VERSION: u32 = 1;

    /// Maximum name length in characters.
    pub const MAX_NAME_LENGTH: usize = 256;

    /// Create a new device.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        user_id: UserId,
        name: String,
        device_type: DeviceType,
        signing_pubkey: Ed25519PublicKey,
        encryption_pubkey: X25519PublicKey,
        status: DeviceStatus,
        expires_at: Option<OffsetDateTime>,
    ) -> Self {
        Self {
            schema_version: Self::SCHEMA_VERSION,
            id: DeviceId::new(),
            user_id,
            name,
            device_type,
            signing_pubkey,
            encryption_pubkey,
            enrolled_at: OffsetDateTime::now_utc(),
            status,
            expires_at,
        }
    }

    /// Validate the device.
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
        if self.enrolled_at > now {
            return Err(ValidationError::FutureTimestamp {
                timestamp: self.enrolled_at.to_string(),
            }
            .into());
        }

        // Validate expiration timestamp if present
        if let Some(expires_at) = self.expires_at {
            if expires_at < self.enrolled_at {
                return Err(ValidationError::InvalidVersion {
                    reason: "expiration timestamp cannot be before enrollment timestamp"
                        .to_string(),
                }
                .into());
            }
        }

        Ok(())
    }

    /// Check if the device is expired.
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            OffsetDateTime::now_utc() > expires_at
        } else {
            false
        }
    }

    /// Check if the device is active (not revoked and not expired).
    pub fn is_active(&self) -> bool {
        self.status == DeviceStatus::Active && !self.is_expired()
    }
}

/// Type of device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceType {
    /// Interactive device (developer workstation).
    Interactive,

    /// CI/CD device (GitHub Actions runner).
    CI,
}

/// Device status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceStatus {
    /// Device is active and can be used.
    Active,

    /// Device enrollment is pending approval.
    PendingApproval,

    /// Device has been revoked and cannot be used.
    Revoked,
}

// Serde helpers for Ed25519PublicKey
mod ed25519_pubkey_serde {
    use myc_crypto::sign::Ed25519PublicKey;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(key: &Ed25519PublicKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, key.as_bytes());
        serializer.serialize_str(&encoded)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Ed25519PublicKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &s)
            .map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom(
                "invalid Ed25519 public key length",
            ));
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ed25519PublicKey::from_bytes(array).map_err(serde::de::Error::custom)
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
    use myc_crypto::kex::generate_x25519_keypair;
    use myc_crypto::sign::generate_ed25519_keypair;

    #[test]
    fn test_device_creation() {
        let user_id = UserId::from("github|12345678");
        let (_, signing_pubkey) = generate_ed25519_keypair().unwrap();
        let (_, encryption_pubkey) = generate_x25519_keypair().unwrap();

        let device = Device::new(
            user_id.clone(),
            "MacBook Pro".to_string(),
            DeviceType::Interactive,
            signing_pubkey,
            encryption_pubkey,
            DeviceStatus::Active,
            None,
        );

        assert_eq!(device.schema_version, Device::SCHEMA_VERSION);
        assert_eq!(device.user_id, user_id);
        assert_eq!(device.name, "MacBook Pro");
        assert_eq!(device.device_type, DeviceType::Interactive);
        assert_eq!(device.status, DeviceStatus::Active);
        assert!(device.expires_at.is_none());
        assert!(device.validate().is_ok());
    }

    #[test]
    fn test_device_validation_empty_name() {
        let user_id = UserId::from("github|12345678");
        let (_, signing_pubkey) = generate_ed25519_keypair().unwrap();
        let (_, encryption_pubkey) = generate_x25519_keypair().unwrap();

        let mut device = Device::new(
            user_id,
            "MacBook Pro".to_string(),
            DeviceType::Interactive,
            signing_pubkey,
            encryption_pubkey,
            DeviceStatus::Active,
            None,
        );

        device.name = String::new();
        assert!(device.validate().is_err());
    }

    #[test]
    fn test_device_validation_name_too_long() {
        let user_id = UserId::from("github|12345678");
        let (_, signing_pubkey) = generate_ed25519_keypair().unwrap();
        let (_, encryption_pubkey) = generate_x25519_keypair().unwrap();

        let long_name = "a".repeat(Device::MAX_NAME_LENGTH + 1);
        let mut device = Device::new(
            user_id,
            "MacBook Pro".to_string(),
            DeviceType::Interactive,
            signing_pubkey,
            encryption_pubkey,
            DeviceStatus::Active,
            None,
        );

        device.name = long_name;
        assert!(device.validate().is_err());
    }

    #[test]
    fn test_device_is_expired() {
        let user_id = UserId::from("github|12345678");
        let (_, signing_pubkey) = generate_ed25519_keypair().unwrap();
        let (_, encryption_pubkey) = generate_x25519_keypair().unwrap();

        // Device without expiration
        let device = Device::new(
            user_id.clone(),
            "MacBook Pro".to_string(),
            DeviceType::Interactive,
            signing_pubkey,
            encryption_pubkey,
            DeviceStatus::Active,
            None,
        );
        assert!(!device.is_expired());

        // Device with future expiration
        let (_, signing_pubkey2) = generate_ed25519_keypair().unwrap();
        let (_, encryption_pubkey2) = generate_x25519_keypair().unwrap();
        let future = OffsetDateTime::now_utc() + time::Duration::days(30);
        let device2 = Device::new(
            user_id.clone(),
            "CI Runner".to_string(),
            DeviceType::CI,
            signing_pubkey2,
            encryption_pubkey2,
            DeviceStatus::Active,
            Some(future),
        );
        assert!(!device2.is_expired());

        // Device with past expiration
        let (_, signing_pubkey3) = generate_ed25519_keypair().unwrap();
        let (_, encryption_pubkey3) = generate_x25519_keypair().unwrap();
        let past = OffsetDateTime::now_utc() - time::Duration::days(1);
        let device3 = Device::new(
            user_id,
            "Old CI Runner".to_string(),
            DeviceType::CI,
            signing_pubkey3,
            encryption_pubkey3,
            DeviceStatus::Active,
            Some(past),
        );
        assert!(device3.is_expired());
    }

    #[test]
    fn test_device_is_active() {
        let user_id = UserId::from("github|12345678");
        let (_, signing_pubkey) = generate_ed25519_keypair().unwrap();
        let (_, encryption_pubkey) = generate_x25519_keypair().unwrap();

        // Active device
        let device = Device::new(
            user_id.clone(),
            "MacBook Pro".to_string(),
            DeviceType::Interactive,
            signing_pubkey,
            encryption_pubkey,
            DeviceStatus::Active,
            None,
        );
        assert!(device.is_active());

        // Revoked device
        let (_, signing_pubkey2) = generate_ed25519_keypair().unwrap();
        let (_, encryption_pubkey2) = generate_x25519_keypair().unwrap();
        let device2 = Device::new(
            user_id.clone(),
            "Old Device".to_string(),
            DeviceType::Interactive,
            signing_pubkey2,
            encryption_pubkey2,
            DeviceStatus::Revoked,
            None,
        );
        assert!(!device2.is_active());

        // Pending approval device
        let (_, signing_pubkey3) = generate_ed25519_keypair().unwrap();
        let (_, encryption_pubkey3) = generate_x25519_keypair().unwrap();
        let device3 = Device::new(
            user_id,
            "New Device".to_string(),
            DeviceType::Interactive,
            signing_pubkey3,
            encryption_pubkey3,
            DeviceStatus::PendingApproval,
            None,
        );
        assert!(!device3.is_active());
    }

    #[test]
    fn test_device_serialization() {
        let user_id = UserId::from("github|12345678");
        let (_, signing_pubkey) = generate_ed25519_keypair().unwrap();
        let (_, encryption_pubkey) = generate_x25519_keypair().unwrap();

        let device = Device::new(
            user_id,
            "MacBook Pro".to_string(),
            DeviceType::Interactive,
            signing_pubkey,
            encryption_pubkey,
            DeviceStatus::Active,
            None,
        );

        let json = serde_json::to_string(&device).unwrap();
        let deserialized: Device = serde_json::from_str(&json).unwrap();
        assert_eq!(device, deserialized);
    }

    #[test]
    fn test_device_type_serialization() {
        let interactive = DeviceType::Interactive;
        let json = serde_json::to_string(&interactive).unwrap();
        assert_eq!(json, "\"interactive\"");

        let ci = DeviceType::CI;
        let json = serde_json::to_string(&ci).unwrap();
        assert_eq!(json, "\"ci\"");
    }

    #[test]
    fn test_device_status_serialization() {
        let active = DeviceStatus::Active;
        let json = serde_json::to_string(&active).unwrap();
        assert_eq!(json, "\"active\"");

        let pending = DeviceStatus::PendingApproval;
        let json = serde_json::to_string(&pending).unwrap();
        assert_eq!(json, "\"pending_approval\"");

        let revoked = DeviceStatus::Revoked;
        let json = serde_json::to_string(&revoked).unwrap();
        assert_eq!(json, "\"revoked\"");
    }
}
