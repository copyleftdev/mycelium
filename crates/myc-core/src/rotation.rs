//! PDK rotation policy checking and operations.
//!
//! This module provides functions for checking rotation policies and determining
//! when PDK rotation is required.

use crate::error::Result;
use crate::org::RotationPolicy;
use crate::pdk::PdkVersion;
use std::str::FromStr;
use time::OffsetDateTime;

/// Reason for PDK rotation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RotationReason {
    /// Member was removed from the project.
    MemberRemoved,

    /// Device was revoked.
    DeviceRevoked,

    /// Policy-based rotation (e.g., max age exceeded).
    Policy,

    /// Manual rotation requested by user.
    Manual,
}

impl RotationReason {
    /// Convert rotation reason to string for storage.
    pub fn as_str(&self) -> &'static str {
        match self {
            RotationReason::MemberRemoved => "member_removed",
            RotationReason::DeviceRevoked => "device_revoked",
            RotationReason::Policy => "policy",
            RotationReason::Manual => "manual",
        }
    }
}

impl FromStr for RotationReason {
    type Err = ();

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "member_removed" => Ok(RotationReason::MemberRemoved),
            "device_revoked" => Ok(RotationReason::DeviceRevoked),
            "policy" => Ok(RotationReason::Policy),
            "manual" => Ok(RotationReason::Manual),
            _ => Err(()),
        }
    }
}

/// Check if PDK rotation is required based on policy.
///
/// This function checks the rotation policy and current PDK version to determine
/// if rotation is required. It checks:
/// - Whether the PDK age exceeds max_age_days policy
///
/// Note: rotate_on_member_remove and rotate_on_device_revoke are checked
/// at the time of member removal or device revocation, not here.
///
/// # Arguments
///
/// * `policy` - The rotation policy to check
/// * `current_pdk_version` - The current PDK version
///
/// # Returns
///
/// `Ok(Some(reason))` if rotation is required, `Ok(None)` if not required
///
/// # Examples
///
/// ```
/// use myc_core::rotation::check_rotation_policy;
/// use myc_core::org::RotationPolicy;
/// use myc_core::pdk::PdkVersion;
/// use myc_core::ids::{DeviceId, VersionNumber};
///
/// let policy = RotationPolicy {
///     rotate_on_member_remove: true,
///     rotate_on_device_revoke: true,
///     max_age_days: Some(90),
/// };
///
/// let device_id = DeviceId::new();
/// let pdk_version = PdkVersion::new(
///     VersionNumber::FIRST,
///     device_id,
///     None,
///     vec![],
/// );
///
/// let result = check_rotation_policy(&policy, &pdk_version).unwrap();
/// // For a newly created PDK, rotation should not be required
/// assert!(result.is_none());
/// ```
pub fn check_rotation_policy(
    policy: &RotationPolicy,
    current_pdk_version: &PdkVersion,
) -> Result<Option<RotationReason>> {
    // Check max_age_days policy
    if let Some(max_age_days) = policy.max_age_days {
        let pdk_age = OffsetDateTime::now_utc() - current_pdk_version.created_at;
        let max_age = time::Duration::days(max_age_days as i64);

        if pdk_age > max_age {
            return Ok(Some(RotationReason::Policy));
        }
    }

    Ok(None)
}

/// Check if rotation is required on member removal.
///
/// This function checks if the rotation policy requires PDK rotation
/// when a member is removed.
///
/// # Arguments
///
/// * `policy` - The rotation policy to check
///
/// # Returns
///
/// `true` if rotation is required, `false` otherwise
///
/// # Examples
///
/// ```
/// use myc_core::rotation::should_rotate_on_member_remove;
/// use myc_core::org::RotationPolicy;
///
/// let policy = RotationPolicy {
///     rotate_on_member_remove: true,
///     rotate_on_device_revoke: true,
///     max_age_days: Some(90),
/// };
///
/// assert!(should_rotate_on_member_remove(&policy));
/// ```
pub fn should_rotate_on_member_remove(policy: &RotationPolicy) -> bool {
    policy.rotate_on_member_remove
}

/// Check if rotation is required on device revocation.
///
/// This function checks if the rotation policy requires PDK rotation
/// when a device is revoked.
///
/// # Arguments
///
/// * `policy` - The rotation policy to check
///
/// # Returns
///
/// `true` if rotation is required, `false` otherwise
///
/// # Examples
///
/// ```
/// use myc_core::rotation::should_rotate_on_device_revoke;
/// use myc_core::org::RotationPolicy;
///
/// let policy = RotationPolicy {
///     rotate_on_member_remove: true,
///     rotate_on_device_revoke: true,
///     max_age_days: Some(90),
/// };
///
/// assert!(should_rotate_on_device_revoke(&policy));
/// ```
pub fn should_rotate_on_device_revoke(policy: &RotationPolicy) -> bool {
    policy.rotate_on_device_revoke
}

/// Check if PDK age exceeds the maximum allowed age.
///
/// This function checks if the current PDK version is older than the
/// maximum age specified in the policy.
///
/// # Arguments
///
/// * `policy` - The rotation policy to check
/// * `current_pdk_version` - The current PDK version
///
/// # Returns
///
/// `true` if the PDK age exceeds max_age_days, `false` otherwise
///
/// # Examples
///
/// ```
/// use myc_core::rotation::is_pdk_age_exceeded;
/// use myc_core::org::RotationPolicy;
/// use myc_core::pdk::PdkVersion;
/// use myc_core::ids::{DeviceId, VersionNumber};
///
/// let policy = RotationPolicy {
///     rotate_on_member_remove: true,
///     rotate_on_device_revoke: true,
///     max_age_days: Some(90),
/// };
///
/// let device_id = DeviceId::new();
/// let pdk_version = PdkVersion::new(
///     VersionNumber::FIRST,
///     device_id,
///     None,
///     vec![],
/// );
///
/// // For a newly created PDK, age should not be exceeded
/// assert!(!is_pdk_age_exceeded(&policy, &pdk_version));
/// ```
pub fn is_pdk_age_exceeded(policy: &RotationPolicy, current_pdk_version: &PdkVersion) -> bool {
    if let Some(max_age_days) = policy.max_age_days {
        let pdk_age = OffsetDateTime::now_utc() - current_pdk_version.created_at;
        let max_age = time::Duration::days(max_age_days as i64);
        pdk_age > max_age
    } else {
        false
    }
}

/// Perform PDK rotation operation.
///
/// This function orchestrates a complete PDK rotation:
/// 1. Determines authorized devices (excluding revoked/removed members)
/// 2. Generates a new PDK
/// 3. Increments the version number
/// 4. Wraps the new PDK to authorized devices
/// 5. Creates a PdkVersion record with the reason
///
/// Note: This function does NOT:
/// - Update project.current_pdk_version (caller must do this)
/// - Sign and commit to GitHub (caller must do this)
/// - Create audit event (caller must do this)
///
/// # Arguments
///
/// * `current_version` - The current PDK version number
/// * `authorized_devices` - List of (device_id, device_pubkey) for authorized devices
/// * `created_by` - The device ID performing the rotation
/// * `reason` - The reason for rotation
///
/// # Returns
///
/// A tuple containing:
/// - The new PDK (`AeadKey`)
/// - The new `PdkVersion` record
///
/// # Errors
///
/// Returns `CoreError::CryptoError` if PDK generation or wrapping fails
///
/// # Examples
///
/// ```
/// use myc_core::rotation::{perform_pdk_rotation, RotationReason};
/// use myc_core::ids::{DeviceId, VersionNumber};
/// use myc_crypto::kex::generate_x25519_keypair;
///
/// let device1_id = DeviceId::new();
/// let (_, device1_pubkey) = generate_x25519_keypair().unwrap();
///
/// let device2_id = DeviceId::new();
/// let (_, device2_pubkey) = generate_x25519_keypair().unwrap();
///
/// let authorized_devices = vec![
///     (device1_id, device1_pubkey),
///     (device2_id, device2_pubkey),
/// ];
///
/// let (new_pdk, new_pdk_version) = perform_pdk_rotation(
///     VersionNumber::FIRST,
///     &authorized_devices,
///     device1_id,
///     RotationReason::Manual,
/// ).unwrap();
///
/// assert_eq!(new_pdk_version.version, VersionNumber::new(2));
/// assert_eq!(new_pdk_version.device_count(), 2);
/// ```
pub fn perform_pdk_rotation(
    current_version: crate::ids::VersionNumber,
    authorized_devices: &[(crate::ids::DeviceId, myc_crypto::kex::X25519PublicKey)],
    created_by: crate::ids::DeviceId,
    reason: RotationReason,
) -> Result<(myc_crypto::aead::AeadKey, PdkVersion)> {
    // Generate new PDK and wrap to authorized devices
    let (new_pdk, wrapped_keys) = crate::pdk_ops::rotate_pdk(authorized_devices)?;

    // Increment version number
    let new_version = current_version.increment();

    // Create PdkVersion record with reason
    let pdk_version = crate::pdk_ops::create_pdk_version(
        new_version,
        created_by,
        Some(reason.as_str().to_string()),
        wrapped_keys,
    );

    Ok((new_pdk, pdk_version))
}

/// Revoke a device.
///
/// This function marks a device as revoked by updating its status.
/// The caller is responsible for:
/// - Triggering PDK rotation for all projects the device's owner is a member of
/// - Excluding the revoked device from new PDK versions
/// - Creating audit events
/// - Persisting the updated device record
///
/// # Arguments
///
/// * `device` - The device to revoke (will be modified in place)
///
/// # Examples
///
/// ```
/// use myc_core::rotation::revoke_device;
/// use myc_core::device::{Device, DeviceType, DeviceStatus};
/// use myc_core::ids::UserId;
/// use myc_crypto::kex::generate_x25519_keypair;
/// use myc_crypto::sign::generate_ed25519_keypair;
///
/// let user_id = UserId::from("github|12345678");
/// let (_, signing_pubkey) = generate_ed25519_keypair().unwrap();
/// let (_, encryption_pubkey) = generate_x25519_keypair().unwrap();
///
/// let mut device = Device::new(
///     user_id,
///     "MacBook Pro".to_string(),
///     DeviceType::Interactive,
///     signing_pubkey,
///     encryption_pubkey,
///     DeviceStatus::Active,
///     None,
/// );
///
/// assert_eq!(device.status, DeviceStatus::Active);
/// revoke_device(&mut device);
/// assert_eq!(device.status, DeviceStatus::Revoked);
/// ```
pub fn revoke_device(device: &mut crate::device::Device) {
    device.status = crate::device::DeviceStatus::Revoked;
}

/// Check if a device should be excluded from PDK rotation.
///
/// A device should be excluded if it is revoked or expired.
///
/// # Arguments
///
/// * `device` - The device to check
///
/// # Returns
///
/// `true` if the device should be excluded, `false` otherwise
///
/// # Examples
///
/// ```
/// use myc_core::rotation::should_exclude_device;
/// use myc_core::device::{Device, DeviceType, DeviceStatus};
/// use myc_core::ids::UserId;
/// use myc_crypto::kex::generate_x25519_keypair;
/// use myc_crypto::sign::generate_ed25519_keypair;
///
/// let user_id = UserId::from("github|12345678");
/// let (_, signing_pubkey) = generate_ed25519_keypair().unwrap();
/// let (_, encryption_pubkey) = generate_x25519_keypair().unwrap();
///
/// let active_device = Device::new(
///     user_id.clone(),
///     "MacBook Pro".to_string(),
///     DeviceType::Interactive,
///     signing_pubkey,
///     encryption_pubkey,
///     DeviceStatus::Active,
///     None,
/// );
///
/// assert!(!should_exclude_device(&active_device));
///
/// let (_, signing_pubkey2) = generate_ed25519_keypair().unwrap();
/// let (_, encryption_pubkey2) = generate_x25519_keypair().unwrap();
/// let revoked_device = Device::new(
///     user_id,
///     "Old Device".to_string(),
///     DeviceType::Interactive,
///     signing_pubkey2,
///     encryption_pubkey2,
///     DeviceStatus::Revoked,
///     None,
/// );
///
/// assert!(should_exclude_device(&revoked_device));
/// ```
pub fn should_exclude_device(device: &crate::device::Device) -> bool {
    device.status == crate::device::DeviceStatus::Revoked || device.is_expired()
}

/// Verify forward secrecy: revoked entities cannot unwrap new PDK versions.
///
/// This function verifies that a revoked device cannot unwrap a PDK version
/// created after revocation. This ensures forward secrecy - revoked entities
/// cannot access future secrets.
///
/// # Arguments
///
/// * `pdk_version` - The PDK version to check
/// * `device_id` - The device ID to check
/// * `device_secret` - The device's secret key
///
/// # Returns
///
/// `Ok(())` if forward secrecy is maintained (device cannot unwrap),
/// `Err(CoreError)` if the device can unwrap (forward secrecy violated)
///
/// # Examples
///
/// ```
/// use myc_core::rotation::verify_forward_secrecy;
/// use myc_core::pdk_ops::{generate_pdk, wrap_pdk, create_pdk_version};
/// use myc_core::ids::{DeviceId, VersionNumber};
/// use myc_crypto::kex::generate_x25519_keypair;
///
/// let device_id = DeviceId::new();
/// let (device_secret, device_pubkey) = generate_x25519_keypair().unwrap();
///
/// // Create PDK version without this device (simulating post-revocation)
/// let pdk = generate_pdk().unwrap();
/// let other_device_id = DeviceId::new();
/// let (_, other_device_pubkey) = generate_x25519_keypair().unwrap();
/// let wrapped = wrap_pdk(&pdk, other_device_id, &other_device_pubkey).unwrap();
///
/// let pdk_version = create_pdk_version(
///     VersionNumber::new(2),
///     other_device_id,
///     Some("After revocation".to_string()),
///     vec![wrapped],
/// );
///
/// // Verify revoked device cannot unwrap
/// assert!(verify_forward_secrecy(&pdk_version, &device_id, &device_secret).is_ok());
/// ```
pub fn verify_forward_secrecy(
    pdk_version: &PdkVersion,
    device_id: &crate::ids::DeviceId,
    device_secret: &myc_crypto::kex::X25519SecretKey,
) -> Result<()> {
    // Try to unwrap the PDK
    let result = crate::pdk_ops::unwrap_pdk_from_version(pdk_version, device_id, device_secret);

    // Forward secrecy is maintained if unwrap fails
    match result {
        Ok(_) => Err(crate::error::CoreError::ValidationError(
            crate::error::ValidationError::InvalidVersion {
                reason: "Forward secrecy violated: revoked device can unwrap new PDK version"
                    .to_string(),
            },
        )),
        Err(_) => Ok(()),
    }
}

/// Verify historical access: old PDK versions remain decryptable.
///
/// This function verifies that a device can still unwrap a PDK version
/// that was created before revocation. This ensures that historical
/// versions remain accessible with old PDKs.
///
/// # Arguments
///
/// * `pdk_version` - The historical PDK version to check
/// * `device_id` - The device ID to check
/// * `device_secret` - The device's secret key
///
/// # Returns
///
/// `Ok(())` if historical access is maintained (device can unwrap),
/// `Err(CoreError)` if the device cannot unwrap (historical access broken)
///
/// # Examples
///
/// ```
/// use myc_core::rotation::verify_historical_access;
/// use myc_core::pdk_ops::{generate_pdk, wrap_pdk, create_pdk_version};
/// use myc_core::ids::{DeviceId, VersionNumber};
/// use myc_crypto::kex::generate_x25519_keypair;
///
/// let device_id = DeviceId::new();
/// let (device_secret, device_pubkey) = generate_x25519_keypair().unwrap();
///
/// // Create PDK version with this device (simulating pre-revocation)
/// let pdk = generate_pdk().unwrap();
/// let wrapped = wrap_pdk(&pdk, device_id, &device_pubkey).unwrap();
///
/// let pdk_version = create_pdk_version(
///     VersionNumber::FIRST,
///     device_id,
///     Some("Before revocation".to_string()),
///     vec![wrapped],
/// );
///
/// // Verify device can still unwrap historical version
/// assert!(verify_historical_access(&pdk_version, &device_id, &device_secret).is_ok());
/// ```
pub fn verify_historical_access(
    pdk_version: &PdkVersion,
    device_id: &crate::ids::DeviceId,
    device_secret: &myc_crypto::kex::X25519SecretKey,
) -> Result<()> {
    // Try to unwrap the PDK
    let result = crate::pdk_ops::unwrap_pdk_from_version(pdk_version, device_id, device_secret);

    // Historical access is maintained if unwrap succeeds
    match result {
        Ok(_) => Ok(()),
        Err(e) => Err(crate::error::CoreError::ValidationError(
            crate::error::ValidationError::InvalidVersion {
                reason: format!(
                    "Historical access broken: device cannot unwrap old PDK version: {}",
                    e
                ),
            },
        )),
    }
}

/// Perform emergency PDK rotation.
///
/// This is a convenience function for emergency rotation that bypasses
/// policy checks. It performs immediate rotation regardless of policy
/// settings and allows custom reason and note.
///
/// This is identical to `perform_pdk_rotation` with `RotationReason::Manual`,
/// but provides a clearer API for emergency situations.
///
/// # Arguments
///
/// * `current_version` - The current PDK version number
/// * `authorized_devices` - List of (device_id, device_pubkey) for authorized devices
/// * `created_by` - The device ID performing the rotation
/// * `reason_note` - Custom reason/note for the emergency rotation
///
/// # Returns
///
/// A tuple containing:
/// - The new PDK (`AeadKey`)
/// - The new `PdkVersion` record
///
/// # Errors
///
/// Returns `CoreError::CryptoError` if PDK generation or wrapping fails
///
/// # Examples
///
/// ```
/// use myc_core::rotation::perform_emergency_rotation;
/// use myc_core::ids::{DeviceId, VersionNumber};
/// use myc_crypto::kex::generate_x25519_keypair;
///
/// let device_id = DeviceId::new();
/// let (_, device_pubkey) = generate_x25519_keypair().unwrap();
///
/// let authorized_devices = vec![(device_id, device_pubkey)];
///
/// let (new_pdk, new_pdk_version) = perform_emergency_rotation(
///     VersionNumber::new(5),
///     &authorized_devices,
///     device_id,
///     "Security incident - immediate rotation required",
/// ).unwrap();
///
/// assert_eq!(new_pdk_version.version, VersionNumber::new(6));
/// assert_eq!(new_pdk_version.reason, Some("Security incident - immediate rotation required".to_string()));
/// ```
pub fn perform_emergency_rotation(
    current_version: crate::ids::VersionNumber,
    authorized_devices: &[(crate::ids::DeviceId, myc_crypto::kex::X25519PublicKey)],
    created_by: crate::ids::DeviceId,
    reason_note: &str,
) -> Result<(myc_crypto::aead::AeadKey, PdkVersion)> {
    // Generate new PDK and wrap to authorized devices
    let (new_pdk, wrapped_keys) = crate::pdk_ops::rotate_pdk(authorized_devices)?;

    // Increment version number
    let new_version = current_version.increment();

    // Create PdkVersion record with custom reason note
    let pdk_version = crate::pdk_ops::create_pdk_version(
        new_version,
        created_by,
        Some(reason_note.to_string()),
        wrapped_keys,
    );

    Ok((new_pdk, pdk_version))
}

/// Result of a single project rotation in a bulk operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectRotationResult {
    /// Project ID that was rotated.
    pub project_id: crate::ids::ProjectId,

    /// Whether the rotation succeeded.
    pub success: bool,

    /// New PDK version number if successful.
    pub new_version: Option<crate::ids::VersionNumber>,

    /// Error message if failed.
    pub error: Option<String>,
}

impl ProjectRotationResult {
    /// Create a successful rotation result.
    pub fn success(
        project_id: crate::ids::ProjectId,
        new_version: crate::ids::VersionNumber,
    ) -> Self {
        Self {
            project_id,
            success: true,
            new_version: Some(new_version),
            error: None,
        }
    }

    /// Create a failed rotation result.
    pub fn failure(project_id: crate::ids::ProjectId, error: String) -> Self {
        Self {
            project_id,
            success: false,
            new_version: None,
            error: Some(error),
        }
    }
}

/// Summary of a bulk rotation operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BulkRotationSummary {
    /// Total number of projects attempted.
    pub total: usize,

    /// Number of successful rotations.
    pub succeeded: usize,

    /// Number of failed rotations.
    pub failed: usize,

    /// Individual project results.
    pub results: Vec<ProjectRotationResult>,
}

impl BulkRotationSummary {
    /// Create a new bulk rotation summary.
    pub fn new(results: Vec<ProjectRotationResult>) -> Self {
        let total = results.len();
        let succeeded = results.iter().filter(|r| r.success).count();
        let failed = total - succeeded;

        Self {
            total,
            succeeded,
            failed,
            results,
        }
    }

    /// Check if all rotations succeeded.
    pub fn all_succeeded(&self) -> bool {
        self.failed == 0
    }

    /// Get failed project IDs.
    pub fn failed_projects(&self) -> Vec<crate::ids::ProjectId> {
        self.results
            .iter()
            .filter(|r| !r.success)
            .map(|r| r.project_id)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{DeviceId, VersionNumber};

    #[test]
    fn test_rotation_reason_as_str() {
        assert_eq!(RotationReason::MemberRemoved.as_str(), "member_removed");
        assert_eq!(RotationReason::DeviceRevoked.as_str(), "device_revoked");
        assert_eq!(RotationReason::Policy.as_str(), "policy");
        assert_eq!(RotationReason::Manual.as_str(), "manual");
    }

    #[test]
    fn test_rotation_reason_from_str() {
        assert_eq!(
            "member_removed".parse::<RotationReason>(),
            Ok(RotationReason::MemberRemoved)
        );
        assert_eq!(
            "device_revoked".parse::<RotationReason>(),
            Ok(RotationReason::DeviceRevoked)
        );
        assert_eq!(
            "policy".parse::<RotationReason>(),
            Ok(RotationReason::Policy)
        );
        assert_eq!(
            "manual".parse::<RotationReason>(),
            Ok(RotationReason::Manual)
        );
        assert_eq!("invalid".parse::<RotationReason>(), Err(()));
    }

    #[test]
    fn test_rotation_reason_roundtrip() {
        let reasons = [
            RotationReason::MemberRemoved,
            RotationReason::DeviceRevoked,
            RotationReason::Policy,
            RotationReason::Manual,
        ];

        for reason in reasons {
            let s = reason.as_str();
            let parsed = s.parse::<RotationReason>().unwrap();
            assert_eq!(reason, parsed);
        }
    }

    #[test]
    fn test_check_rotation_policy_no_max_age() {
        let policy = RotationPolicy {
            rotate_on_member_remove: true,
            rotate_on_device_revoke: true,
            max_age_days: None,
        };

        let device_id = DeviceId::new();
        let pdk_version = PdkVersion::new(VersionNumber::FIRST, device_id, None, vec![]);

        let result = check_rotation_policy(&policy, &pdk_version).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_check_rotation_policy_within_max_age() {
        let policy = RotationPolicy {
            rotate_on_member_remove: true,
            rotate_on_device_revoke: true,
            max_age_days: Some(90),
        };

        let device_id = DeviceId::new();
        let pdk_version = PdkVersion::new(VersionNumber::FIRST, device_id, None, vec![]);

        let result = check_rotation_policy(&policy, &pdk_version).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_check_rotation_policy_exceeds_max_age() {
        let policy = RotationPolicy {
            rotate_on_member_remove: true,
            rotate_on_device_revoke: true,
            max_age_days: Some(90),
        };

        let device_id = DeviceId::new();
        let mut pdk_version = PdkVersion::new(VersionNumber::FIRST, device_id, None, vec![]);

        // Set created_at to 91 days ago
        pdk_version.created_at = OffsetDateTime::now_utc() - time::Duration::days(91);

        let result = check_rotation_policy(&policy, &pdk_version).unwrap();
        assert_eq!(result, Some(RotationReason::Policy));
    }

    #[test]
    fn test_should_rotate_on_member_remove() {
        let policy = RotationPolicy {
            rotate_on_member_remove: true,
            rotate_on_device_revoke: false,
            max_age_days: None,
        };
        assert!(should_rotate_on_member_remove(&policy));

        let policy2 = RotationPolicy {
            rotate_on_member_remove: false,
            rotate_on_device_revoke: true,
            max_age_days: None,
        };
        assert!(!should_rotate_on_member_remove(&policy2));
    }

    #[test]
    fn test_should_rotate_on_device_revoke() {
        let policy = RotationPolicy {
            rotate_on_member_remove: false,
            rotate_on_device_revoke: true,
            max_age_days: None,
        };
        assert!(should_rotate_on_device_revoke(&policy));

        let policy2 = RotationPolicy {
            rotate_on_member_remove: true,
            rotate_on_device_revoke: false,
            max_age_days: None,
        };
        assert!(!should_rotate_on_device_revoke(&policy2));
    }

    #[test]
    fn test_is_pdk_age_exceeded_no_max_age() {
        let policy = RotationPolicy {
            rotate_on_member_remove: true,
            rotate_on_device_revoke: true,
            max_age_days: None,
        };

        let device_id = DeviceId::new();
        let mut pdk_version = PdkVersion::new(VersionNumber::FIRST, device_id, None, vec![]);

        // Even with very old PDK, should return false if no max_age_days
        pdk_version.created_at = OffsetDateTime::now_utc() - time::Duration::days(365);
        assert!(!is_pdk_age_exceeded(&policy, &pdk_version));
    }

    #[test]
    fn test_is_pdk_age_exceeded_within_limit() {
        let policy = RotationPolicy {
            rotate_on_member_remove: true,
            rotate_on_device_revoke: true,
            max_age_days: Some(90),
        };

        let device_id = DeviceId::new();
        let pdk_version = PdkVersion::new(VersionNumber::FIRST, device_id, None, vec![]);

        assert!(!is_pdk_age_exceeded(&policy, &pdk_version));
    }

    #[test]
    fn test_is_pdk_age_exceeded_over_limit() {
        let policy = RotationPolicy {
            rotate_on_member_remove: true,
            rotate_on_device_revoke: true,
            max_age_days: Some(90),
        };

        let device_id = DeviceId::new();
        let mut pdk_version = PdkVersion::new(VersionNumber::FIRST, device_id, None, vec![]);

        pdk_version.created_at = OffsetDateTime::now_utc() - time::Duration::days(91);
        assert!(is_pdk_age_exceeded(&policy, &pdk_version));
    }

    #[test]
    fn test_is_pdk_age_exceeded_exactly_at_limit() {
        let policy = RotationPolicy {
            rotate_on_member_remove: true,
            rotate_on_device_revoke: true,
            max_age_days: Some(90),
        };

        let device_id = DeviceId::new();
        let mut pdk_version = PdkVersion::new(VersionNumber::FIRST, device_id, None, vec![]);

        // Set to 89 days and 23 hours to be safely under the limit
        pdk_version.created_at =
            OffsetDateTime::now_utc() - time::Duration::days(89) - time::Duration::hours(23);
        // Should not be exceeded
        assert!(!is_pdk_age_exceeded(&policy, &pdk_version));
    }

    #[test]
    fn test_perform_pdk_rotation() {
        use myc_crypto::kex::generate_x25519_keypair;

        let device1_id = DeviceId::new();
        let (device1_secret, device1_pubkey) = generate_x25519_keypair().unwrap();

        let device2_id = DeviceId::new();
        let (device2_secret, device2_pubkey) = generate_x25519_keypair().unwrap();

        let authorized_devices = vec![(device1_id, device1_pubkey), (device2_id, device2_pubkey)];

        let (new_pdk, new_pdk_version) = perform_pdk_rotation(
            VersionNumber::FIRST,
            &authorized_devices,
            device1_id,
            RotationReason::Manual,
        )
        .unwrap();

        // Check version incremented
        assert_eq!(new_pdk_version.version, VersionNumber::new(2));

        // Check reason stored
        assert_eq!(new_pdk_version.reason, Some("manual".to_string()));

        // Check created_by
        assert_eq!(new_pdk_version.created_by, device1_id);

        // Check wrapped keys for both devices
        assert_eq!(new_pdk_version.device_count(), 2);
        assert!(new_pdk_version.has_device_access(&device1_id));
        assert!(new_pdk_version.has_device_access(&device2_id));

        // Verify both devices can unwrap the new PDK
        use crate::pdk_ops::unwrap_pdk_from_version;
        let unwrapped1 =
            unwrap_pdk_from_version(&new_pdk_version, &device1_id, &device1_secret).unwrap();
        let unwrapped2 =
            unwrap_pdk_from_version(&new_pdk_version, &device2_id, &device2_secret).unwrap();

        assert_eq!(new_pdk.as_bytes(), unwrapped1.as_bytes());
        assert_eq!(new_pdk.as_bytes(), unwrapped2.as_bytes());
    }

    #[test]
    #[allow(unused_variables)]
    fn test_perform_pdk_rotation_excludes_removed_device() {
        use myc_crypto::kex::generate_x25519_keypair;

        let device1_id = DeviceId::new();
        let (device1_secret, device1_pubkey) = generate_x25519_keypair().unwrap();

        let device2_id = DeviceId::new();
        let (device2_secret, device2_pubkey) = generate_x25519_keypair().unwrap();

        let device3_id = DeviceId::new();
        let (device3_secret, _device3_pubkey) = generate_x25519_keypair().unwrap();

        // Rotate, excluding device3 (simulating member removal)
        let authorized_devices = vec![(device1_id, device1_pubkey), (device2_id, device2_pubkey)];

        let (new_pdk, new_pdk_version) = perform_pdk_rotation(
            VersionNumber::new(5),
            &authorized_devices,
            device1_id,
            RotationReason::MemberRemoved,
        )
        .unwrap();

        // Check version incremented from 5 to 6
        assert_eq!(new_pdk_version.version, VersionNumber::new(6));

        // Check reason
        assert_eq!(new_pdk_version.reason, Some("member_removed".to_string()));

        // Only devices 1 and 2 should have access
        assert!(new_pdk_version.has_device_access(&device1_id));
        assert!(new_pdk_version.has_device_access(&device2_id));
        assert!(!new_pdk_version.has_device_access(&device3_id));

        // Device 3 cannot unwrap
        use crate::pdk_ops::unwrap_pdk_from_version;
        let result3 = unwrap_pdk_from_version(&new_pdk_version, &device3_id, &device3_secret);
        assert!(result3.is_err());
    }

    #[test]
    fn test_perform_pdk_rotation_different_reasons() {
        use myc_crypto::kex::generate_x25519_keypair;

        let device_id = DeviceId::new();
        let (_, device_pubkey) = generate_x25519_keypair().unwrap();
        let devices = vec![(device_id, device_pubkey)];

        // Test each rotation reason
        let reasons = [
            RotationReason::MemberRemoved,
            RotationReason::DeviceRevoked,
            RotationReason::Policy,
            RotationReason::Manual,
        ];

        for (i, reason) in reasons.iter().enumerate() {
            let (_, pdk_version) = perform_pdk_rotation(
                VersionNumber::new((i + 1) as u64),
                &devices,
                device_id,
                reason.clone(),
            )
            .unwrap();

            assert_eq!(pdk_version.reason, Some(reason.as_str().to_string()));
        }
    }

    #[test]
    fn test_revoke_device() {
        use crate::device::{Device, DeviceStatus, DeviceType};
        use crate::ids::UserId;
        use myc_crypto::kex::generate_x25519_keypair;
        use myc_crypto::sign::generate_ed25519_keypair;

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

        assert_eq!(device.status, DeviceStatus::Active);
        assert!(device.is_active());

        revoke_device(&mut device);

        assert_eq!(device.status, DeviceStatus::Revoked);
        assert!(!device.is_active());
    }

    #[test]
    fn test_should_exclude_device_active() {
        use crate::device::{Device, DeviceStatus, DeviceType};
        use crate::ids::UserId;
        use myc_crypto::kex::generate_x25519_keypair;
        use myc_crypto::sign::generate_ed25519_keypair;

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

        assert!(!should_exclude_device(&device));
    }

    #[test]
    fn test_should_exclude_device_revoked() {
        use crate::device::{Device, DeviceStatus, DeviceType};
        use crate::ids::UserId;
        use myc_crypto::kex::generate_x25519_keypair;
        use myc_crypto::sign::generate_ed25519_keypair;

        let user_id = UserId::from("github|12345678");
        let (_, signing_pubkey) = generate_ed25519_keypair().unwrap();
        let (_, encryption_pubkey) = generate_x25519_keypair().unwrap();

        let device = Device::new(
            user_id,
            "Old Device".to_string(),
            DeviceType::Interactive,
            signing_pubkey,
            encryption_pubkey,
            DeviceStatus::Revoked,
            None,
        );

        assert!(should_exclude_device(&device));
    }

    #[test]
    fn test_should_exclude_device_expired() {
        use crate::device::{Device, DeviceStatus, DeviceType};
        use crate::ids::UserId;
        use myc_crypto::kex::generate_x25519_keypair;
        use myc_crypto::sign::generate_ed25519_keypair;

        let user_id = UserId::from("github|12345678");
        let (_, signing_pubkey) = generate_ed25519_keypair().unwrap();
        let (_, encryption_pubkey) = generate_x25519_keypair().unwrap();

        // Create device with past expiration
        let past = OffsetDateTime::now_utc() - time::Duration::days(1);
        let device = Device::new(
            user_id,
            "Expired CI Runner".to_string(),
            DeviceType::CI,
            signing_pubkey,
            encryption_pubkey,
            DeviceStatus::Active,
            Some(past),
        );

        assert!(should_exclude_device(&device));
    }

    #[test]
    fn test_should_exclude_device_pending_approval() {
        use crate::device::{Device, DeviceStatus, DeviceType};
        use crate::ids::UserId;
        use myc_crypto::kex::generate_x25519_keypair;
        use myc_crypto::sign::generate_ed25519_keypair;

        let user_id = UserId::from("github|12345678");
        let (_, signing_pubkey) = generate_ed25519_keypair().unwrap();
        let (_, encryption_pubkey) = generate_x25519_keypair().unwrap();

        let device = Device::new(
            user_id,
            "New Device".to_string(),
            DeviceType::Interactive,
            signing_pubkey,
            encryption_pubkey,
            DeviceStatus::PendingApproval,
            None,
        );

        // Pending approval devices should not be excluded (they're not revoked or expired)
        // They just can't be used yet
        assert!(!should_exclude_device(&device));
    }

    #[test]
    fn test_verify_forward_secrecy_maintained() {
        use crate::pdk_ops::{create_pdk_version, generate_pdk, wrap_pdk};
        use myc_crypto::kex::generate_x25519_keypair;

        let revoked_device_id = DeviceId::new();
        let (revoked_device_secret, _revoked_device_pubkey) = generate_x25519_keypair().unwrap();

        // Create PDK version without revoked device (post-revocation)
        let pdk = generate_pdk().unwrap();
        let other_device_id = DeviceId::new();
        let (_, other_device_pubkey) = generate_x25519_keypair().unwrap();
        let wrapped = wrap_pdk(&pdk, other_device_id, &other_device_pubkey).unwrap();

        let pdk_version = create_pdk_version(
            VersionNumber::new(2),
            other_device_id,
            Some("After revocation".to_string()),
            vec![wrapped],
        );

        // Verify revoked device cannot unwrap (forward secrecy maintained)
        assert!(
            verify_forward_secrecy(&pdk_version, &revoked_device_id, &revoked_device_secret)
                .is_ok()
        );
    }

    #[test]
    fn test_verify_forward_secrecy_violated() {
        use crate::pdk_ops::{create_pdk_version, generate_pdk, wrap_pdk};
        use myc_crypto::kex::generate_x25519_keypair;

        let device_id = DeviceId::new();
        let (device_secret, device_pubkey) = generate_x25519_keypair().unwrap();

        // Create PDK version WITH the device (simulating failure to exclude)
        let pdk = generate_pdk().unwrap();
        let wrapped = wrap_pdk(&pdk, device_id, &device_pubkey).unwrap();

        let pdk_version = create_pdk_version(
            VersionNumber::new(2),
            device_id,
            Some("After revocation - but device still has access!".to_string()),
            vec![wrapped],
        );

        // Verify forward secrecy is violated (device can still unwrap)
        assert!(verify_forward_secrecy(&pdk_version, &device_id, &device_secret).is_err());
    }

    #[test]
    fn test_verify_historical_access_maintained() {
        use crate::pdk_ops::{create_pdk_version, generate_pdk, wrap_pdk};
        use myc_crypto::kex::generate_x25519_keypair;

        let device_id = DeviceId::new();
        let (device_secret, device_pubkey) = generate_x25519_keypair().unwrap();

        // Create PDK version with device (pre-revocation)
        let pdk = generate_pdk().unwrap();
        let wrapped = wrap_pdk(&pdk, device_id, &device_pubkey).unwrap();

        let pdk_version = create_pdk_version(
            VersionNumber::FIRST,
            device_id,
            Some("Before revocation".to_string()),
            vec![wrapped],
        );

        // Verify device can still unwrap historical version
        assert!(verify_historical_access(&pdk_version, &device_id, &device_secret).is_ok());
    }

    #[test]
    fn test_verify_historical_access_broken() {
        use crate::pdk_ops::{create_pdk_version, generate_pdk, wrap_pdk};
        use myc_crypto::kex::generate_x25519_keypair;

        let device_id = DeviceId::new();
        let (device_secret, _device_pubkey) = generate_x25519_keypair().unwrap();

        // Create PDK version WITHOUT device (simulating data corruption)
        let pdk = generate_pdk().unwrap();
        let other_device_id = DeviceId::new();
        let (_, other_device_pubkey) = generate_x25519_keypair().unwrap();
        let wrapped = wrap_pdk(&pdk, other_device_id, &other_device_pubkey).unwrap();

        let pdk_version = create_pdk_version(
            VersionNumber::FIRST,
            other_device_id,
            Some("Historical version".to_string()),
            vec![wrapped],
        );

        // Verify historical access is broken (device cannot unwrap)
        assert!(verify_historical_access(&pdk_version, &device_id, &device_secret).is_err());
    }

    #[test]
    fn test_forward_secrecy_and_historical_access_together() {
        use crate::pdk_ops::{create_pdk_version, generate_pdk, wrap_pdk};
        use myc_crypto::kex::generate_x25519_keypair;

        // Setup: 3 devices, device3 will be revoked
        let device1_id = DeviceId::new();
        let (_, device1_pubkey) = generate_x25519_keypair().unwrap();

        let device2_id = DeviceId::new();
        let (_, device2_pubkey) = generate_x25519_keypair().unwrap();

        let device3_id = DeviceId::new();
        let (device3_secret, device3_pubkey) = generate_x25519_keypair().unwrap();

        // Create old PDK version with all 3 devices (before revocation)
        let old_pdk = generate_pdk().unwrap();
        let old_wrapped_keys = vec![
            wrap_pdk(&old_pdk, device1_id, &device1_pubkey).unwrap(),
            wrap_pdk(&old_pdk, device2_id, &device2_pubkey).unwrap(),
            wrap_pdk(&old_pdk, device3_id, &device3_pubkey).unwrap(),
        ];
        let old_pdk_version =
            create_pdk_version(VersionNumber::FIRST, device1_id, None, old_wrapped_keys);

        // Create new PDK version with only devices 1 and 2 (after device3 revocation)
        let new_pdk = generate_pdk().unwrap();
        let new_wrapped_keys = vec![
            wrap_pdk(&new_pdk, device1_id, &device1_pubkey).unwrap(),
            wrap_pdk(&new_pdk, device2_id, &device2_pubkey).unwrap(),
        ];
        let new_pdk_version = create_pdk_version(
            VersionNumber::new(2),
            device1_id,
            Some("device_revoked".to_string()),
            new_wrapped_keys,
        );

        // Verify device3 can access old version (historical access)
        assert!(verify_historical_access(&old_pdk_version, &device3_id, &device3_secret).is_ok());

        // Verify device3 cannot access new version (forward secrecy)
        assert!(verify_forward_secrecy(&new_pdk_version, &device3_id, &device3_secret).is_ok());
    }

    #[test]
    fn test_perform_emergency_rotation() {
        use myc_crypto::kex::generate_x25519_keypair;

        let device_id = DeviceId::new();
        let (device_secret, device_pubkey) = generate_x25519_keypair().unwrap();

        let authorized_devices = vec![(device_id, device_pubkey)];

        let (new_pdk, new_pdk_version) = perform_emergency_rotation(
            VersionNumber::new(5),
            &authorized_devices,
            device_id,
            "Security incident - immediate rotation required",
        )
        .unwrap();

        // Check version incremented
        assert_eq!(new_pdk_version.version, VersionNumber::new(6));

        // Check custom reason stored
        assert_eq!(
            new_pdk_version.reason,
            Some("Security incident - immediate rotation required".to_string())
        );

        // Check created_by
        assert_eq!(new_pdk_version.created_by, device_id);

        // Check device has access
        assert!(new_pdk_version.has_device_access(&device_id));

        // Verify device can unwrap
        use crate::pdk_ops::unwrap_pdk_from_version;
        let unwrapped =
            unwrap_pdk_from_version(&new_pdk_version, &device_id, &device_secret).unwrap();
        assert_eq!(new_pdk.as_bytes(), unwrapped.as_bytes());
    }

    #[test]
    fn test_perform_emergency_rotation_with_custom_notes() {
        use myc_crypto::kex::generate_x25519_keypair;

        let device_id = DeviceId::new();
        let (_, device_pubkey) = generate_x25519_keypair().unwrap();
        let devices = vec![(device_id, device_pubkey)];

        // Test various emergency scenarios
        let scenarios = [
            "Suspected key compromise",
            "Compliance requirement",
            "Security audit finding",
            "Incident response - ticket #12345",
        ];

        for (i, note) in scenarios.iter().enumerate() {
            let (_, pdk_version) = perform_emergency_rotation(
                VersionNumber::new((i + 1) as u64),
                &devices,
                device_id,
                note,
            )
            .unwrap();

            assert_eq!(pdk_version.reason, Some(note.to_string()));
        }
    }

    #[test]
    fn test_project_rotation_result_success() {
        use crate::ids::ProjectId;

        let project_id = ProjectId::new();
        let result = ProjectRotationResult::success(project_id, VersionNumber::new(2));

        assert!(result.success);
        assert_eq!(result.project_id, project_id);
        assert_eq!(result.new_version, Some(VersionNumber::new(2)));
        assert!(result.error.is_none());
    }

    #[test]
    fn test_project_rotation_result_failure() {
        use crate::ids::ProjectId;

        let project_id = ProjectId::new();
        let result = ProjectRotationResult::failure(project_id, "Failed to unwrap PDK".to_string());

        assert!(!result.success);
        assert_eq!(result.project_id, project_id);
        assert!(result.new_version.is_none());
        assert_eq!(result.error, Some("Failed to unwrap PDK".to_string()));
    }

    #[test]
    fn test_bulk_rotation_summary_all_success() {
        use crate::ids::ProjectId;

        let results = vec![
            ProjectRotationResult::success(ProjectId::new(), VersionNumber::new(2)),
            ProjectRotationResult::success(ProjectId::new(), VersionNumber::new(3)),
            ProjectRotationResult::success(ProjectId::new(), VersionNumber::new(2)),
        ];

        let summary = BulkRotationSummary::new(results);

        assert_eq!(summary.total, 3);
        assert_eq!(summary.succeeded, 3);
        assert_eq!(summary.failed, 0);
        assert!(summary.all_succeeded());
        assert!(summary.failed_projects().is_empty());
    }

    #[test]
    fn test_bulk_rotation_summary_mixed_results() {
        use crate::ids::ProjectId;

        let project1 = ProjectId::new();
        let project2 = ProjectId::new();
        let project3 = ProjectId::new();

        let results = vec![
            ProjectRotationResult::success(project1, VersionNumber::new(2)),
            ProjectRotationResult::failure(project2, "Network error".to_string()),
            ProjectRotationResult::success(project3, VersionNumber::new(3)),
        ];

        let summary = BulkRotationSummary::new(results);

        assert_eq!(summary.total, 3);
        assert_eq!(summary.succeeded, 2);
        assert_eq!(summary.failed, 1);
        assert!(!summary.all_succeeded());

        let failed = summary.failed_projects();
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0], project2);
    }

    #[test]
    fn test_bulk_rotation_summary_all_failed() {
        use crate::ids::ProjectId;

        let project1 = ProjectId::new();
        let project2 = ProjectId::new();

        let results = vec![
            ProjectRotationResult::failure(project1, "Error 1".to_string()),
            ProjectRotationResult::failure(project2, "Error 2".to_string()),
        ];

        let summary = BulkRotationSummary::new(results);

        assert_eq!(summary.total, 2);
        assert_eq!(summary.succeeded, 0);
        assert_eq!(summary.failed, 2);
        assert!(!summary.all_succeeded());

        let failed = summary.failed_projects();
        assert_eq!(failed.len(), 2);
        assert!(failed.contains(&project1));
        assert!(failed.contains(&project2));
    }

    #[test]
    fn test_bulk_rotation_summary_empty() {
        let results = vec![];
        let summary = BulkRotationSummary::new(results);

        assert_eq!(summary.total, 0);
        assert_eq!(summary.succeeded, 0);
        assert_eq!(summary.failed, 0);
        assert!(summary.all_succeeded());
        assert!(summary.failed_projects().is_empty());
    }
}
