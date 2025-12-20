//! Membership and permission operations.
//!
//! This module provides functions for managing project membership, checking permissions,
//! and performing membership-related operations like adding/removing members and changing roles.

use crate::canonical::{sign_payload, verify_payload};
use crate::error::{CoreError, Result};
use crate::ids::{DeviceId, ProjectId, UserId};
use crate::pdk::{PdkVersion, WrappedPdk};
use crate::pdk_ops::{add_member_wrapped_pdks, rotate_pdk, unwrap_pdk_from_version};
use crate::project::{Permission, ProjectMember, Role};
use myc_crypto::aead::AeadKey;
use myc_crypto::kex::{X25519PublicKey, X25519SecretKey};
use myc_crypto::sign::{Ed25519PublicKey, Ed25519SecretKey, Signature, SIGNATURE_SIZE};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Membership list with signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipList {
    /// Schema version for forward compatibility.
    pub schema_version: u32,

    /// Project identifier.
    pub project_id: ProjectId,

    /// List of project members.
    pub members: Vec<ProjectMember>,

    /// Last updated timestamp (RFC 3339).
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,

    /// Device that last updated this list.
    pub updated_by: DeviceId,

    /// Signature over the canonical JSON of this structure (excluding signature field).
    /// Stored as base64-encoded bytes.
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_signature",
        deserialize_with = "deserialize_signature"
    )]
    pub signature: Option<Signature>,
}

/// Serialize a signature as base64.
fn serialize_signature<S>(
    sig: &Option<Signature>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match sig {
        Some(s) => {
            let encoded =
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, s.as_bytes());
            serializer.serialize_some(&encoded)
        }
        None => serializer.serialize_none(),
    }
}

/// Deserialize a signature from base64.
fn deserialize_signature<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<Signature>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt: Option<String> = Option::deserialize(deserializer)?;
    match opt {
        Some(s) => {
            let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &s)
                .map_err(serde::de::Error::custom)?;
            if bytes.len() != SIGNATURE_SIZE {
                return Err(serde::de::Error::custom(format!(
                    "invalid signature length: expected {}, got {}",
                    SIGNATURE_SIZE,
                    bytes.len()
                )));
            }
            let mut arr = [0u8; SIGNATURE_SIZE];
            arr.copy_from_slice(&bytes);
            Ok(Some(Signature::from_bytes(arr)))
        }
        None => Ok(None),
    }
}

impl MembershipList {
    /// The current schema version.
    pub const SCHEMA_VERSION: u32 = 1;

    /// Create a new membership list.
    pub fn new(project_id: ProjectId, members: Vec<ProjectMember>, updated_by: DeviceId) -> Self {
        Self {
            schema_version: Self::SCHEMA_VERSION,
            project_id,
            members,
            updated_at: OffsetDateTime::now_utc(),
            updated_by,
            signature: None,
        }
    }

    /// Sign the membership list.
    pub fn sign(&mut self, key: &Ed25519SecretKey) -> Result<()> {
        // Create a copy without signature for signing
        let mut unsigned = self.clone();
        unsigned.signature = None;

        let signature = sign_payload(&unsigned, key)?;
        self.signature = Some(signature);
        Ok(())
    }

    /// Verify the membership list signature.
    pub fn verify(&self, key: &Ed25519PublicKey) -> Result<()> {
        let signature = self.signature.ok_or(CoreError::SignatureInvalid)?;

        // Create a copy without signature for verification
        let mut unsigned = self.clone();
        unsigned.signature = None;

        verify_payload(&unsigned, &signature, key)
    }

    /// Find a member by user ID.
    pub fn find_member(&self, user_id: &UserId) -> Option<&ProjectMember> {
        self.members.iter().find(|m| &m.user_id == user_id)
    }

    /// Find a member by user ID (mutable).
    pub fn find_member_mut(&mut self, user_id: &UserId) -> Option<&mut ProjectMember> {
        self.members.iter_mut().find(|m| &m.user_id == user_id)
    }

    /// Check if a user has a specific permission.
    pub fn has_permission(&self, user_id: &UserId, permission: Permission) -> bool {
        self.find_member(user_id)
            .map(|member| member.role.has_permission(permission))
            .unwrap_or(false)
    }

    /// Get a user's role.
    pub fn get_role(&self, user_id: &UserId) -> Option<Role> {
        self.find_member(user_id).map(|member| member.role)
    }
}

/// Check if an actor has a specific permission in a project.
///
/// This function reads the membership list and verifies that the actor
/// has the required permission based on their role.
///
/// # Arguments
///
/// * `membership_list` - The project's membership list
/// * `actor_user_id` - The user ID of the actor performing the operation
/// * `required_permission` - The permission required for the operation
///
/// # Returns
///
/// `Ok(())` if the actor has the required permission
///
/// # Errors
///
/// Returns an error if:
/// - The actor is not a member of the project
/// - The actor's role doesn't have the required permission
///
/// # Examples
///
/// ```
/// use myc_core::membership_ops::{check_permission, MembershipList};
/// use myc_core::project::{Permission, ProjectMember, Role};
/// use myc_core::ids::{DeviceId, ProjectId, UserId};
///
/// let project_id = ProjectId::new();
/// let device_id = DeviceId::new();
/// let user_id = UserId::from("github|12345678");
///
/// let member = ProjectMember::new(user_id.clone(), Role::Admin, device_id);
/// let membership_list = MembershipList::new(project_id, vec![member], device_id);
///
/// // Admin has share permission
/// assert!(check_permission(&membership_list, &user_id, Permission::Share).is_ok());
///
/// // Admin doesn't have delete_project permission
/// assert!(check_permission(&membership_list, &user_id, Permission::DeleteProject).is_err());
/// ```
pub fn check_permission(
    membership_list: &MembershipList,
    actor_user_id: &UserId,
    required_permission: Permission,
) -> Result<()> {
    let member = membership_list.find_member(actor_user_id).ok_or_else(|| {
        CoreError::ValidationError(crate::error::ValidationError::InvalidName {
            reason: format!(
                "user {} is not a member of this project",
                actor_user_id.as_str()
            ),
        })
    })?;

    if !member.role.has_permission(required_permission) {
        return Err(CoreError::ValidationError(
            crate::error::ValidationError::InvalidName {
                reason: format!(
                    "user {} with role {:?} does not have {:?} permission",
                    actor_user_id.as_str(),
                    member.role,
                    required_permission
                ),
            },
        ));
    }

    Ok(())
}

/// Result of an add member operation.
#[derive(Debug)]
pub struct AddMemberResult {
    /// Updated membership list.
    pub membership_list: MembershipList,

    /// New wrapped PDKs for the added member's devices.
    pub new_wrapped_pdks: Vec<WrappedPdk>,
}

/// Add a member to a project.
///
/// This function:
/// 1. Verifies the actor has share permission
/// 2. Verifies the target role level <= actor's role level
/// 3. Unwraps the current PDK using the actor's device key
/// 4. Wraps the PDK to each of the new member's devices
/// 5. Adds the member to the membership list
/// 6. Signs the updated membership list
///
/// # Arguments
///
/// * `membership_list` - The current membership list
/// * `pdk_version` - The current PDK version
/// * `actor_user_id` - The user ID of the actor adding the member
/// * `actor_device_id` - The device ID of the actor
/// * `actor_device_secret` - The actor's X25519 secret key
/// * `actor_signing_key` - The actor's Ed25519 signing key
/// * `target_user_id` - The user ID of the member to add
/// * `target_role` - The role to assign to the new member
/// * `target_devices` - The new member's devices (device_id, pubkey pairs)
///
/// # Returns
///
/// An `AddMemberResult` containing the updated membership list and new wrapped PDKs
///
/// # Errors
///
/// Returns an error if:
/// - The actor doesn't have share permission
/// - The target role level > actor's role level
/// - PDK unwrapping or wrapping fails
/// - Signing fails
#[allow(clippy::too_many_arguments)]
pub fn add_member(
    membership_list: &MembershipList,
    pdk_version: &PdkVersion,
    actor_user_id: &UserId,
    actor_device_id: DeviceId,
    actor_device_secret: &X25519SecretKey,
    actor_signing_key: &Ed25519SecretKey,
    target_user_id: UserId,
    target_role: Role,
    target_devices: &[(DeviceId, X25519PublicKey)],
) -> Result<AddMemberResult> {
    // Verify actor has share permission
    check_permission(membership_list, actor_user_id, Permission::Share)?;

    // Get actor's role
    let actor_role = membership_list.get_role(actor_user_id).ok_or_else(|| {
        CoreError::ValidationError(crate::error::ValidationError::InvalidName {
            reason: "actor not found in membership list".to_string(),
        })
    })?;

    // Verify target role level <= actor's role level
    if target_role.level() > actor_role.level() {
        return Err(CoreError::ValidationError(
            crate::error::ValidationError::InvalidName {
                reason: format!(
                    "cannot assign role {:?} (level {}) higher than actor's role {:?} (level {})",
                    target_role,
                    target_role.level(),
                    actor_role,
                    actor_role.level()
                ),
            },
        ));
    }

    // Unwrap current PDK using actor's device key
    let pdk = unwrap_pdk_from_version(pdk_version, &actor_device_id, actor_device_secret)?;

    // Wrap PDK to new member's devices
    let new_wrapped_pdks = add_member_wrapped_pdks(&pdk, target_devices)?;

    // Add member to membership list
    let mut updated_list = membership_list.clone();
    let new_member = ProjectMember::new(target_user_id, target_role, actor_device_id);
    updated_list.members.push(new_member);
    updated_list.updated_at = OffsetDateTime::now_utc();
    updated_list.updated_by = actor_device_id;

    // Sign the updated membership list
    updated_list.sign(actor_signing_key)?;

    Ok(AddMemberResult {
        membership_list: updated_list,
        new_wrapped_pdks,
    })
}

/// Result of a remove member operation.
pub struct RemoveMemberResult {
    /// Updated membership list.
    pub membership_list: MembershipList,

    /// New PDK (rotated).
    pub new_pdk: AeadKey,

    /// New wrapped PDKs for remaining members.
    pub new_wrapped_pdks: Vec<WrappedPdk>,
}

/// Remove a member from a project.
///
/// This function:
/// 1. Verifies the actor has share permission
/// 2. Verifies the target role level < actor's role level
/// 3. Removes the member from the membership list
/// 4. Rotates the PDK (generates new PDK and wraps to remaining members only)
/// 5. Signs the updated membership list
///
/// # Arguments
///
/// * `membership_list` - The current membership list
/// * `actor_user_id` - The user ID of the actor removing the member
/// * `actor_device_id` - The device ID of the actor
/// * `actor_signing_key` - The actor's Ed25519 signing key
/// * `target_user_id` - The user ID of the member to remove
/// * `remaining_devices` - Devices of remaining members (excluding removed member)
///
/// # Returns
///
/// A `RemoveMemberResult` containing the updated membership list, new PDK, and wrapped PDKs
///
/// # Errors
///
/// Returns an error if:
/// - The actor doesn't have share permission
/// - The target role level >= actor's role level
/// - The target member is not found
/// - PDK rotation fails
/// - Signing fails
pub fn remove_member(
    membership_list: &MembershipList,
    actor_user_id: &UserId,
    actor_device_id: DeviceId,
    actor_signing_key: &Ed25519SecretKey,
    target_user_id: &UserId,
    remaining_devices: &[(DeviceId, X25519PublicKey)],
) -> Result<RemoveMemberResult> {
    // Verify actor has share permission
    check_permission(membership_list, actor_user_id, Permission::Share)?;

    // Get actor's role
    let actor_role = membership_list.get_role(actor_user_id).ok_or_else(|| {
        CoreError::ValidationError(crate::error::ValidationError::InvalidName {
            reason: "actor not found in membership list".to_string(),
        })
    })?;

    // Get target's role
    let target_role = membership_list.get_role(target_user_id).ok_or_else(|| {
        CoreError::ValidationError(crate::error::ValidationError::InvalidName {
            reason: format!(
                "target user {} not found in membership list",
                target_user_id.as_str()
            ),
        })
    })?;

    // Verify target role level < actor's role level
    if target_role.level() >= actor_role.level() {
        return Err(CoreError::ValidationError(
            crate::error::ValidationError::InvalidName {
                reason: format!(
                    "cannot remove user with role {:?} (level {}) >= actor's role {:?} (level {})",
                    target_role,
                    target_role.level(),
                    actor_role,
                    actor_role.level()
                ),
            },
        ));
    }

    // Remove member from membership list
    let mut updated_list = membership_list.clone();
    updated_list
        .members
        .retain(|m| &m.user_id != target_user_id);
    updated_list.updated_at = OffsetDateTime::now_utc();
    updated_list.updated_by = actor_device_id;

    // Rotate PDK (generate new PDK and wrap to remaining members only)
    let (new_pdk, new_wrapped_pdks) = rotate_pdk(remaining_devices)?;

    // Sign the updated membership list
    updated_list.sign(actor_signing_key)?;

    Ok(RemoveMemberResult {
        membership_list: updated_list,
        new_pdk,
        new_wrapped_pdks,
    })
}

/// Result of a change role operation.
#[derive(Debug)]
pub struct ChangeRoleResult {
    /// Updated membership list.
    pub membership_list: MembershipList,
}

/// Change a member's role in a project.
///
/// This function:
/// 1. Verifies the actor has share permission
/// 2. Verifies the new role level <= actor's role level
/// 3. Verifies the target's current role level < actor's role level
/// 4. Updates the member's role
/// 5. Signs the updated membership list
///
/// # Arguments
///
/// * `membership_list` - The current membership list
/// * `actor_user_id` - The user ID of the actor changing the role
/// * `actor_device_id` - The device ID of the actor
/// * `actor_signing_key` - The actor's Ed25519 signing key
/// * `target_user_id` - The user ID of the member whose role to change
/// * `new_role` - The new role to assign
///
/// # Returns
///
/// A `ChangeRoleResult` containing the updated membership list
///
/// # Errors
///
/// Returns an error if:
/// - The actor doesn't have share permission
/// - The new role level > actor's role level
/// - The target's current role level >= actor's role level
/// - The target member is not found
/// - Signing fails
pub fn change_role(
    membership_list: &MembershipList,
    actor_user_id: &UserId,
    actor_device_id: DeviceId,
    actor_signing_key: &Ed25519SecretKey,
    target_user_id: &UserId,
    new_role: Role,
) -> Result<ChangeRoleResult> {
    // Verify actor has share permission
    check_permission(membership_list, actor_user_id, Permission::Share)?;

    // Get actor's role
    let actor_role = membership_list.get_role(actor_user_id).ok_or_else(|| {
        CoreError::ValidationError(crate::error::ValidationError::InvalidName {
            reason: "actor not found in membership list".to_string(),
        })
    })?;

    // Get target's current role
    let target_current_role = membership_list.get_role(target_user_id).ok_or_else(|| {
        CoreError::ValidationError(crate::error::ValidationError::InvalidName {
            reason: format!(
                "target user {} not found in membership list",
                target_user_id.as_str()
            ),
        })
    })?;

    // Verify new role level <= actor's role level
    if new_role.level() > actor_role.level() {
        return Err(CoreError::ValidationError(
            crate::error::ValidationError::InvalidName {
                reason: format!(
                    "cannot assign role {:?} (level {}) higher than actor's role {:?} (level {})",
                    new_role,
                    new_role.level(),
                    actor_role,
                    actor_role.level()
                ),
            },
        ));
    }

    // Verify target's current role level < actor's role level
    if target_current_role.level() >= actor_role.level() {
        return Err(CoreError::ValidationError(
            crate::error::ValidationError::InvalidName {
                reason: format!(
                    "cannot change role of user with role {:?} (level {}) >= actor's role {:?} (level {})",
                    target_current_role,
                    target_current_role.level(),
                    actor_role,
                    actor_role.level()
                ),
            },
        ));
    }

    // Update member's role
    let mut updated_list = membership_list.clone();
    if let Some(member) = updated_list.find_member_mut(target_user_id) {
        member.role = new_role;
    }
    updated_list.updated_at = OffsetDateTime::now_utc();
    updated_list.updated_by = actor_device_id;

    // Sign the updated membership list
    updated_list.sign(actor_signing_key)?;

    Ok(ChangeRoleResult {
        membership_list: updated_list,
    })
}

/// Result of a transfer ownership operation.
#[derive(Debug)]
pub struct TransferOwnershipResult {
    /// Updated membership list.
    pub membership_list: MembershipList,
}

/// Transfer project ownership to another admin.
///
/// This function:
/// 1. Verifies the actor is the current owner
/// 2. Verifies the target is currently an admin
/// 3. Sets the target's role to owner
/// 4. Sets the actor's role to admin
/// 5. Signs the updated membership list
///
/// # Arguments
///
/// * `membership_list` - The current membership list
/// * `actor_user_id` - The user ID of the current owner
/// * `actor_device_id` - The device ID of the actor
/// * `actor_signing_key` - The actor's Ed25519 signing key
/// * `target_user_id` - The user ID of the admin to promote to owner
///
/// # Returns
///
/// A `TransferOwnershipResult` containing the updated membership list
///
/// # Errors
///
/// Returns an error if:
/// - The actor is not the current owner
/// - The target is not currently an admin
/// - The target member is not found
/// - Signing fails
pub fn transfer_ownership(
    membership_list: &MembershipList,
    actor_user_id: &UserId,
    actor_device_id: DeviceId,
    actor_signing_key: &Ed25519SecretKey,
    target_user_id: &UserId,
) -> Result<TransferOwnershipResult> {
    // Verify actor is current owner
    let actor_role = membership_list.get_role(actor_user_id).ok_or_else(|| {
        CoreError::ValidationError(crate::error::ValidationError::InvalidName {
            reason: "actor not found in membership list".to_string(),
        })
    })?;

    if actor_role != Role::Owner {
        return Err(CoreError::ValidationError(
            crate::error::ValidationError::InvalidName {
                reason: format!(
                    "only the owner can transfer ownership, actor has role {:?}",
                    actor_role
                ),
            },
        ));
    }

    // Verify target is current admin
    let target_role = membership_list.get_role(target_user_id).ok_or_else(|| {
        CoreError::ValidationError(crate::error::ValidationError::InvalidName {
            reason: format!(
                "target user {} not found in membership list",
                target_user_id.as_str()
            ),
        })
    })?;

    if target_role != Role::Admin {
        return Err(CoreError::ValidationError(
            crate::error::ValidationError::InvalidName {
                reason: format!(
                    "can only transfer ownership to an admin, target has role {:?}",
                    target_role
                ),
            },
        ));
    }

    // Update roles
    let mut updated_list = membership_list.clone();

    // Set target to owner
    if let Some(member) = updated_list.find_member_mut(target_user_id) {
        member.role = Role::Owner;
    }

    // Set actor to admin
    if let Some(member) = updated_list.find_member_mut(actor_user_id) {
        member.role = Role::Admin;
    }

    updated_list.updated_at = OffsetDateTime::now_utc();
    updated_list.updated_by = actor_device_id;

    // Sign the updated membership list
    updated_list.sign(actor_signing_key)?;

    Ok(TransferOwnershipResult {
        membership_list: updated_list,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use myc_crypto::sign::generate_ed25519_keypair;

    #[test]
    fn test_membership_list_creation() {
        let project_id = ProjectId::new();
        let device_id = DeviceId::new();
        let user_id = UserId::from("github|12345678");

        let member = ProjectMember::new(user_id.clone(), Role::Owner, device_id);
        let list = MembershipList::new(project_id, vec![member], device_id);

        assert_eq!(list.schema_version, MembershipList::SCHEMA_VERSION);
        assert_eq!(list.project_id, project_id);
        assert_eq!(list.members.len(), 1);
        assert_eq!(list.updated_by, device_id);
        assert!(list.signature.is_none());
    }

    #[test]
    fn test_membership_list_sign_and_verify() {
        let project_id = ProjectId::new();
        let device_id = DeviceId::new();
        let user_id = UserId::from("github|12345678");
        let (secret_key, public_key) = generate_ed25519_keypair().unwrap();

        let member = ProjectMember::new(user_id, Role::Owner, device_id);
        let mut list = MembershipList::new(project_id, vec![member], device_id);

        // Sign the list
        list.sign(&secret_key).unwrap();
        assert!(list.signature.is_some());

        // Verify the signature
        assert!(list.verify(&public_key).is_ok());
    }

    #[test]
    fn test_membership_list_verify_fails_with_wrong_key() {
        let project_id = ProjectId::new();
        let device_id = DeviceId::new();
        let user_id = UserId::from("github|12345678");
        let (secret_key1, _) = generate_ed25519_keypair().unwrap();
        let (_, public_key2) = generate_ed25519_keypair().unwrap();

        let member = ProjectMember::new(user_id, Role::Owner, device_id);
        let mut list = MembershipList::new(project_id, vec![member], device_id);

        // Sign with key 1
        list.sign(&secret_key1).unwrap();

        // Verify with key 2 should fail
        assert!(list.verify(&public_key2).is_err());
    }

    #[test]
    fn test_find_member() {
        let project_id = ProjectId::new();
        let device_id = DeviceId::new();
        let user_id1 = UserId::from("github|12345678");
        let user_id2 = UserId::from("github|87654321");

        let member1 = ProjectMember::new(user_id1.clone(), Role::Owner, device_id);
        let member2 = ProjectMember::new(user_id2.clone(), Role::Admin, device_id);
        let list = MembershipList::new(project_id, vec![member1, member2], device_id);

        assert!(list.find_member(&user_id1).is_some());
        assert!(list.find_member(&user_id2).is_some());

        let nonexistent = UserId::from("github|99999999");
        assert!(list.find_member(&nonexistent).is_none());
    }

    #[test]
    fn test_has_permission() {
        let project_id = ProjectId::new();
        let device_id = DeviceId::new();
        let owner_id = UserId::from("github|owner");
        let admin_id = UserId::from("github|admin");
        let member_id = UserId::from("github|member");
        let reader_id = UserId::from("github|reader");

        let members = vec![
            ProjectMember::new(owner_id.clone(), Role::Owner, device_id),
            ProjectMember::new(admin_id.clone(), Role::Admin, device_id),
            ProjectMember::new(member_id.clone(), Role::Member, device_id),
            ProjectMember::new(reader_id.clone(), Role::Reader, device_id),
        ];
        let list = MembershipList::new(project_id, members, device_id);

        // Owner has all permissions
        assert!(list.has_permission(&owner_id, Permission::Read));
        assert!(list.has_permission(&owner_id, Permission::Write));
        assert!(list.has_permission(&owner_id, Permission::Share));
        assert!(list.has_permission(&owner_id, Permission::Rotate));
        assert!(list.has_permission(&owner_id, Permission::DeleteProject));
        assert!(list.has_permission(&owner_id, Permission::TransferOwnership));

        // Admin has read, write, share, rotate
        assert!(list.has_permission(&admin_id, Permission::Read));
        assert!(list.has_permission(&admin_id, Permission::Write));
        assert!(list.has_permission(&admin_id, Permission::Share));
        assert!(list.has_permission(&admin_id, Permission::Rotate));
        assert!(!list.has_permission(&admin_id, Permission::DeleteProject));
        assert!(!list.has_permission(&admin_id, Permission::TransferOwnership));

        // Member has read, write
        assert!(list.has_permission(&member_id, Permission::Read));
        assert!(list.has_permission(&member_id, Permission::Write));
        assert!(!list.has_permission(&member_id, Permission::Share));
        assert!(!list.has_permission(&member_id, Permission::Rotate));

        // Reader has read only
        assert!(list.has_permission(&reader_id, Permission::Read));
        assert!(!list.has_permission(&reader_id, Permission::Write));
        assert!(!list.has_permission(&reader_id, Permission::Share));
        assert!(!list.has_permission(&reader_id, Permission::Rotate));
    }

    #[test]
    fn test_check_permission_success() {
        let project_id = ProjectId::new();
        let device_id = DeviceId::new();
        let user_id = UserId::from("github|12345678");

        let member = ProjectMember::new(user_id.clone(), Role::Admin, device_id);
        let list = MembershipList::new(project_id, vec![member], device_id);

        // Admin has share permission
        assert!(check_permission(&list, &user_id, Permission::Share).is_ok());
    }

    #[test]
    fn test_check_permission_fails_not_member() {
        let project_id = ProjectId::new();
        let device_id = DeviceId::new();
        let user_id = UserId::from("github|12345678");
        let nonmember_id = UserId::from("github|87654321");

        let member = ProjectMember::new(user_id, Role::Admin, device_id);
        let list = MembershipList::new(project_id, vec![member], device_id);

        // Non-member should fail
        assert!(check_permission(&list, &nonmember_id, Permission::Share).is_err());
    }

    #[test]
    fn test_check_permission_fails_insufficient_permission() {
        let project_id = ProjectId::new();
        let device_id = DeviceId::new();
        let user_id = UserId::from("github|12345678");

        let member = ProjectMember::new(user_id.clone(), Role::Member, device_id);
        let list = MembershipList::new(project_id, vec![member], device_id);

        // Member doesn't have share permission
        assert!(check_permission(&list, &user_id, Permission::Share).is_err());
    }
}
