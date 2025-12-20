//! Recovery mechanisms for Mycelium.
//!
//! This module defines types and operations for key recovery, including
//! recovery contacts, organization recovery keys, and recovery requests.

use crate::ids::{DeviceId, OrgId, ProjectId, UserId};
use myc_crypto::{
    kex::X25519PublicKey,
    sign::{Ed25519PublicKey, Signature},
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// Recovery contact relationship between users
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryContact {
    /// Schema version for evolution
    pub schema_version: u32,
    /// Unique identifier for this relationship
    pub id: RecoveryContactId,
    /// User who can be recovered
    pub user_id: UserId,
    /// User who can assist with recovery
    pub contact_user_id: UserId,
    /// When this relationship was established
    pub created_at: OffsetDateTime,
    /// Device that created this relationship
    pub created_by: DeviceId,
    /// Optional expiration date
    pub expires_at: Option<OffsetDateTime>,
    /// Whether this relationship is active
    pub active: bool,
}

/// Unique identifier for recovery contact relationships
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RecoveryContactId(pub Uuid);

impl RecoveryContactId {
    /// Generate a new random recovery contact ID
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for RecoveryContactId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for RecoveryContactId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Recovery request when a user needs to recover access
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryRequest {
    /// Schema version for evolution
    pub schema_version: u32,
    /// Unique identifier for this request
    pub id: RecoveryRequestId,
    /// User requesting recovery
    pub user_id: UserId,
    /// New device being enrolled for recovery
    pub new_device_id: DeviceId,
    /// Public signing key for the new device
    pub new_device_signing_key: Ed25519PublicKey,
    /// Public encryption key for the new device
    pub new_device_encryption_key: X25519PublicKey,
    /// When this request was created
    pub created_at: OffsetDateTime,
    /// Status of the recovery request
    pub status: RecoveryRequestStatus,
    /// Projects that need recovery assistance
    pub projects: Vec<ProjectId>,
    /// Recovery contacts who have been notified
    pub notified_contacts: Vec<UserId>,
    /// Recovery contacts who have assisted
    pub assisted_by: Vec<RecoveryAssistance>,
}

/// Unique identifier for recovery requests
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RecoveryRequestId(pub Uuid);

impl RecoveryRequestId {
    /// Generate a new random recovery request ID
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for RecoveryRequestId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for RecoveryRequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Status of a recovery request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecoveryRequestStatus {
    /// Request is pending assistance
    Pending,
    /// Request is in progress (some contacts have assisted)
    InProgress,
    /// Request has been completed successfully
    Completed,
    /// Request was cancelled by the user
    Cancelled,
    /// Request expired without completion
    Expired,
}

/// Record of recovery assistance provided by a contact
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryAssistance {
    /// Contact who provided assistance
    pub contact_user_id: UserId,
    /// Device used to provide assistance
    pub contact_device_id: DeviceId,
    /// When assistance was provided
    pub assisted_at: OffsetDateTime,
    /// Projects for which PDKs were wrapped
    pub projects_assisted: Vec<ProjectId>,
    /// Signature of the assistance record
    pub signature: Signature,
}

/// Organization recovery key configuration using Shamir's Secret Sharing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgRecoveryKey {
    /// Schema version for evolution
    pub schema_version: u32,
    /// Organization this recovery key belongs to
    pub org_id: OrgId,
    /// Threshold required to reconstruct the key (e.g., 3 of 5)
    pub threshold: u32,
    /// Total number of shares created
    pub total_shares: u32,
    /// When this recovery key was created
    pub created_at: OffsetDateTime,
    /// Device that created this recovery key
    pub created_by: DeviceId,
    /// Encrypted shares distributed to admins
    pub shares: Vec<RecoveryShare>,
    /// Whether this recovery key is active
    pub active: bool,
}

/// A single share of the organization recovery key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryShare {
    /// Share number (1-based)
    pub share_number: u32,
    /// Admin device this share is encrypted to
    pub device_id: DeviceId,
    /// Encrypted share data (encrypted to device's X25519 key)
    pub encrypted_share: Vec<u8>,
    /// When this share was created
    pub created_at: OffsetDateTime,
}

/// Recovery share contribution during recovery process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareContribution {
    /// Share number being contributed
    pub share_number: u32,
    /// Admin device contributing the share
    pub device_id: DeviceId,
    /// Decrypted share data
    pub share_data: Vec<u8>,
    /// When this contribution was made
    pub contributed_at: OffsetDateTime,
    /// Signature of the contribution
    pub signature: Signature,
}

impl RecoveryContact {
    /// Create a new recovery contact relationship
    pub fn new(user_id: UserId, contact_user_id: UserId, created_by: DeviceId) -> Self {
        Self {
            schema_version: 1,
            id: RecoveryContactId::new(),
            user_id,
            contact_user_id,
            created_at: OffsetDateTime::now_utc(),
            created_by,
            expires_at: None,
            active: true,
        }
    }

    /// Check if this recovery contact is currently valid
    pub fn is_valid(&self) -> bool {
        if !self.active {
            return false;
        }

        if let Some(expires_at) = self.expires_at {
            if OffsetDateTime::now_utc() > expires_at {
                return false;
            }
        }

        true
    }
}

impl RecoveryRequest {
    /// Create a new recovery request
    pub fn new(
        user_id: UserId,
        new_device_id: DeviceId,
        new_device_signing_key: Ed25519PublicKey,
        new_device_encryption_key: X25519PublicKey,
        projects: Vec<ProjectId>,
    ) -> Self {
        Self {
            schema_version: 1,
            id: RecoveryRequestId::new(),
            user_id,
            new_device_id,
            new_device_signing_key,
            new_device_encryption_key,
            created_at: OffsetDateTime::now_utc(),
            status: RecoveryRequestStatus::Pending,
            projects,
            notified_contacts: Vec::new(),
            assisted_by: Vec::new(),
        }
    }

    /// Check if this recovery request is still active
    pub fn is_active(&self) -> bool {
        matches!(
            self.status,
            RecoveryRequestStatus::Pending | RecoveryRequestStatus::InProgress
        )
    }

    /// Add assistance from a recovery contact
    pub fn add_assistance(&mut self, assistance: RecoveryAssistance) {
        self.assisted_by.push(assistance);
        if matches!(self.status, RecoveryRequestStatus::Pending) {
            self.status = RecoveryRequestStatus::InProgress;
        }
    }

    /// Mark the recovery request as completed
    pub fn complete(&mut self) {
        self.status = RecoveryRequestStatus::Completed;
    }
}

impl OrgRecoveryKey {
    /// Create a new organization recovery key configuration
    pub fn new(
        org_id: OrgId,
        threshold: u32,
        total_shares: u32,
        created_by: DeviceId,
        shares: Vec<RecoveryShare>,
    ) -> Self {
        Self {
            schema_version: 1,
            org_id,
            threshold,
            total_shares,
            created_at: OffsetDateTime::now_utc(),
            created_by,
            shares,
            active: true,
        }
    }

    /// Check if enough shares have been contributed for recovery
    pub fn has_sufficient_shares(&self, contributions: &[ShareContribution]) -> bool {
        contributions.len() >= self.threshold as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{DeviceId, OrgId, ProjectId, UserId};

    #[test]
    fn test_recovery_contact_creation() {
        let user_id = UserId::new("user1".to_string());
        let contact_id = UserId::new("contact1".to_string());
        let device_id = DeviceId::new();

        let contact = RecoveryContact::new(user_id.clone(), contact_id.clone(), device_id);

        assert_eq!(contact.schema_version, 1);
        assert_eq!(contact.user_id, user_id);
        assert_eq!(contact.contact_user_id, contact_id);
        assert_eq!(contact.created_by, device_id);
        assert!(contact.active);
        assert!(contact.expires_at.is_none());
        assert!(contact.is_valid());
    }

    #[test]
    fn test_recovery_request_creation() {
        let user_id = UserId::new("user1".to_string());
        let device_id = DeviceId::new();
        let signing_key = Ed25519PublicKey::from_bytes([0u8; 32]).unwrap();
        let encryption_key = X25519PublicKey::from_bytes([0u8; 32]);
        let projects = vec![ProjectId::new()];

        let request = RecoveryRequest::new(
            user_id.clone(),
            device_id,
            signing_key,
            encryption_key,
            projects.clone(),
        );

        assert_eq!(request.schema_version, 1);
        assert_eq!(request.user_id, user_id);
        assert_eq!(request.new_device_id, device_id);
        assert_eq!(request.projects, projects);
        assert!(request.is_active());
        assert!(matches!(request.status, RecoveryRequestStatus::Pending));
    }

    #[test]
    fn test_org_recovery_key_creation() {
        let org_id = OrgId::new();
        let device_id = DeviceId::new();
        let shares = vec![RecoveryShare {
            share_number: 1,
            device_id: DeviceId::new(),
            encrypted_share: vec![1, 2, 3],
            created_at: OffsetDateTime::now_utc(),
        }];

        let recovery_key = OrgRecoveryKey::new(org_id, 3, 5, device_id, shares);

        assert_eq!(recovery_key.schema_version, 1);
        assert_eq!(recovery_key.org_id, org_id);
        assert_eq!(recovery_key.threshold, 3);
        assert_eq!(recovery_key.total_shares, 5);
        assert!(recovery_key.active);
    }

    #[test]
    fn test_sufficient_shares_check() {
        let org_id = OrgId::new();
        let device_id = DeviceId::new();
        let recovery_key = OrgRecoveryKey::new(org_id, 3, 5, device_id, vec![]);

        let contributions = vec![
            ShareContribution {
                share_number: 1,
                device_id: DeviceId::new(),
                share_data: vec![1, 2, 3],
                contributed_at: OffsetDateTime::now_utc(),
                signature: Signature::from_bytes([0u8; 64]),
            },
            ShareContribution {
                share_number: 2,
                device_id: DeviceId::new(),
                share_data: vec![4, 5, 6],
                contributed_at: OffsetDateTime::now_utc(),
                signature: Signature::from_bytes([0u8; 64]),
            },
        ];

        assert!(!recovery_key.has_sufficient_shares(&contributions));

        let mut sufficient_contributions = contributions;
        sufficient_contributions.push(ShareContribution {
            share_number: 3,
            device_id: DeviceId::new(),
            share_data: vec![7, 8, 9],
            contributed_at: OffsetDateTime::now_utc(),
            signature: Signature::from_bytes([0u8; 64]),
        });

        assert!(recovery_key.has_sufficient_shares(&sufficient_contributions));
    }
}
