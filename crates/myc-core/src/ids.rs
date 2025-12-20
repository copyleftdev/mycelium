//! Type-safe identifiers for domain entities.
//!
//! All identifiers are UUIDv4 wrappers except UserId which is a string wrapper
//! for OIDC subject identifiers.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Organization identifier (UUIDv4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OrgId(Uuid);

impl OrgId {
    /// Create a new random organization ID.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Create an organization ID from a UUID.
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Get the inner UUID.
    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for OrgId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for OrgId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Project identifier (UUIDv4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProjectId(Uuid);

impl ProjectId {
    /// Create a new random project ID.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Create a project ID from a UUID.
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Get the inner UUID.
    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for ProjectId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ProjectId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Secret set identifier (UUIDv4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretSetId(Uuid);

impl SecretSetId {
    /// Create a new random secret set ID.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Create a secret set ID from a UUID.
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Get the inner UUID.
    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for SecretSetId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for SecretSetId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Device identifier (UUIDv4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DeviceId(Uuid);

impl DeviceId {
    /// Create a new random device ID.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Create a device ID from a UUID.
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Get the inner UUID.
    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for DeviceId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for DeviceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// User identifier (OIDC subject).
///
/// This is a string wrapper for OIDC subject identifiers like "github|12345678".
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UserId(String);

impl UserId {
    /// Create a new user ID from a string.
    pub fn new(id: String) -> Self {
        Self(id)
    }

    /// Get the inner string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for UserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for UserId {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl From<&str> for UserId {
    fn from(s: &str) -> Self {
        Self::new(s.to_string())
    }
}

/// Version number for versioned entities.
///
/// Version numbers start at 1 and increment monotonically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct VersionNumber(u64);

impl VersionNumber {
    /// The first version number.
    pub const FIRST: Self = Self(1);

    /// Create a new version number.
    ///
    /// # Panics
    ///
    /// Panics if the version number is 0.
    pub fn new(version: u64) -> Self {
        assert!(version > 0, "version number must be greater than 0");
        Self(version)
    }

    /// Get the inner u64 value.
    pub fn as_u64(&self) -> u64 {
        self.0
    }

    /// Increment the version number by 1.
    pub fn increment(&self) -> Self {
        Self(self.0 + 1)
    }
}

impl Default for VersionNumber {
    fn default() -> Self {
        Self::FIRST
    }
}

impl std::fmt::Display for VersionNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_org_id_creation() {
        let id1 = OrgId::new();
        let id2 = OrgId::new();
        assert_ne!(id1, id2, "UUIDs should be unique");
    }

    #[test]
    fn test_org_id_serialization() {
        let id = OrgId::new();
        let json = serde_json::to_string(&id).unwrap();
        let deserialized: OrgId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, deserialized);
    }

    #[test]
    fn test_user_id_creation() {
        let id = UserId::new("github|12345678".to_string());
        assert_eq!(id.as_str(), "github|12345678");
    }

    #[test]
    fn test_version_number_increment() {
        let v1 = VersionNumber::FIRST;
        let v2 = v1.increment();
        assert_eq!(v1.as_u64(), 1);
        assert_eq!(v2.as_u64(), 2);
    }

    #[test]
    fn test_version_number_ordering() {
        let v1 = VersionNumber::new(1);
        let v2 = VersionNumber::new(2);
        assert!(v1 < v2);
    }

    #[test]
    #[should_panic(expected = "version number must be greater than 0")]
    fn test_version_number_zero_panics() {
        VersionNumber::new(0);
    }
}
