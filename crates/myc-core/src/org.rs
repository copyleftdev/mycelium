//! Organization types and settings.

use crate::error::{Result, ValidationError};
use crate::ids::OrgId;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Organization metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Org {
    /// Schema version for forward compatibility.
    pub schema_version: u32,

    /// Unique organization identifier.
    pub id: OrgId,

    /// Organization name.
    pub name: String,

    /// Creation timestamp (RFC 3339).
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,

    /// Organization settings.
    pub settings: OrgSettings,
}

impl Org {
    /// The current schema version.
    pub const SCHEMA_VERSION: u32 = 1;

    /// Maximum name length in characters.
    pub const MAX_NAME_LENGTH: usize = 256;

    /// Create a new organization.
    pub fn new(name: String, settings: OrgSettings) -> Self {
        Self {
            schema_version: Self::SCHEMA_VERSION,
            id: OrgId::new(),
            name,
            created_at: OffsetDateTime::now_utc(),
            settings,
        }
    }

    /// Validate the organization.
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

/// Organization settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct OrgSettings {
    /// Whether device enrollment requires approval.
    #[serde(default)]
    pub require_device_approval: bool,

    /// Optional GitHub organization name.
    pub github_org: Option<String>,

    /// Default rotation policy for new projects.
    pub default_rotation_policy: Option<RotationPolicy>,
}

/// PDK rotation policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationPolicy {
    /// Automatically rotate PDK when a member is removed.
    pub rotate_on_member_remove: bool,

    /// Automatically rotate PDK when a device is revoked.
    pub rotate_on_device_revoke: bool,

    /// Maximum age of PDK in days before rotation is required.
    pub max_age_days: Option<u32>,
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self {
            rotate_on_member_remove: true,
            rotate_on_device_revoke: true,
            max_age_days: Some(90),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_org_creation() {
        let org = Org::new("Test Org".to_string(), OrgSettings::default());
        assert_eq!(org.schema_version, Org::SCHEMA_VERSION);
        assert_eq!(org.name, "Test Org");
        assert!(org.validate().is_ok());
    }

    #[test]
    fn test_org_validation_empty_name() {
        let mut org = Org::new("Test Org".to_string(), OrgSettings::default());
        org.name = String::new();
        assert!(org.validate().is_err());
    }

    #[test]
    fn test_org_validation_name_too_long() {
        let long_name = "a".repeat(Org::MAX_NAME_LENGTH + 1);
        let mut org = Org::new("Test Org".to_string(), OrgSettings::default());
        org.name = long_name;
        assert!(org.validate().is_err());
    }

    #[test]
    fn test_org_validation_future_timestamp() {
        let mut org = Org::new("Test Org".to_string(), OrgSettings::default());
        org.created_at = OffsetDateTime::now_utc() + time::Duration::days(1);
        assert!(org.validate().is_err());
    }

    #[test]
    fn test_org_serialization() {
        let org = Org::new("Test Org".to_string(), OrgSettings::default());
        let json = serde_json::to_string(&org).unwrap();
        let deserialized: Org = serde_json::from_str(&json).unwrap();
        assert_eq!(org, deserialized);
    }

    #[test]
    fn test_org_settings_default() {
        let settings = OrgSettings::default();
        assert!(!settings.require_device_approval);
        assert!(settings.github_org.is_none());
        assert!(settings.default_rotation_policy.is_none());
    }

    #[test]
    fn test_rotation_policy_default() {
        let policy = RotationPolicy::default();
        assert!(policy.rotate_on_member_remove);
        assert!(policy.rotate_on_device_revoke);
        assert_eq!(policy.max_age_days, Some(90));
    }
}
