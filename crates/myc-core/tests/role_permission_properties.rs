//! Property-based tests for role permissions.
//!
//! These tests verify that each role has the correct set of permissions:
//! - Owner has all permissions
//! - Admin has read, write, share, rotate
//! - Member has read, write
//! - Reader has read only

use myc_core::project::{Permission, Role};
use proptest::prelude::*;

// ============================================================================
// Property 32: Owner Has All Permissions
// ============================================================================

/// Feature: mycelium-cli, Property 32: Owner Has All Permissions
///
/// For any operation, a user with Owner role SHALL have all permissions.
///
/// **Validates: Requirements 9.2**
#[test]
fn property_owner_has_all_permissions() {
    proptest!(|(
        _seed in any::<u32>(),
    )| {
        let owner = Role::Owner;

        // Owner should have all permissions
        for permission in Permission::all() {
            prop_assert!(
                owner.has_permission(permission),
                "Owner should have {:?} permission",
                permission
            );
        }

        // Verify the permission count matches
        let owner_permissions = owner.permissions();
        prop_assert_eq!(
            owner_permissions.len(),
            Permission::all().len(),
            "Owner should have all {} permissions",
            Permission::all().len()
        );

        // Verify each permission is present
        prop_assert!(
            owner.has_permission(Permission::Read),
            "Owner should have Read permission"
        );
        prop_assert!(
            owner.has_permission(Permission::Write),
            "Owner should have Write permission"
        );
        prop_assert!(
            owner.has_permission(Permission::Share),
            "Owner should have Share permission"
        );
        prop_assert!(
            owner.has_permission(Permission::Rotate),
            "Owner should have Rotate permission"
        );
        prop_assert!(
            owner.has_permission(Permission::DeleteProject),
            "Owner should have DeleteProject permission"
        );
        prop_assert!(
            owner.has_permission(Permission::TransferOwnership),
            "Owner should have TransferOwnership permission"
        );
    });
}

// ============================================================================
// Property 33: Admin Permission Set
// ============================================================================

/// Feature: mycelium-cli, Property 33: Admin Permission Set
///
/// For any operation, a user with Admin role SHALL have read, write, share, rotate permissions
/// and NOT delete_project or transfer_ownership.
///
/// **Validates: Requirements 9.3**
#[test]
fn property_admin_permission_set() {
    proptest!(|(
        _seed in any::<u32>(),
    )| {
        let admin = Role::Admin;

        // Admin should have these permissions
        prop_assert!(
            admin.has_permission(Permission::Read),
            "Admin should have Read permission"
        );
        prop_assert!(
            admin.has_permission(Permission::Write),
            "Admin should have Write permission"
        );
        prop_assert!(
            admin.has_permission(Permission::Share),
            "Admin should have Share permission"
        );
        prop_assert!(
            admin.has_permission(Permission::Rotate),
            "Admin should have Rotate permission"
        );

        // Admin should NOT have these permissions
        prop_assert!(
            !admin.has_permission(Permission::DeleteProject),
            "Admin should NOT have DeleteProject permission"
        );
        prop_assert!(
            !admin.has_permission(Permission::TransferOwnership),
            "Admin should NOT have TransferOwnership permission"
        );

        // Verify the permission count is exactly 4
        let admin_permissions = admin.permissions();
        prop_assert_eq!(
            admin_permissions.len(),
            4,
            "Admin should have exactly 4 permissions"
        );

        // Verify the exact set of permissions
        prop_assert!(
            admin_permissions.contains(&Permission::Read),
            "Admin permissions should include Read"
        );
        prop_assert!(
            admin_permissions.contains(&Permission::Write),
            "Admin permissions should include Write"
        );
        prop_assert!(
            admin_permissions.contains(&Permission::Share),
            "Admin permissions should include Share"
        );
        prop_assert!(
            admin_permissions.contains(&Permission::Rotate),
            "Admin permissions should include Rotate"
        );
        prop_assert!(
            !admin_permissions.contains(&Permission::DeleteProject),
            "Admin permissions should NOT include DeleteProject"
        );
        prop_assert!(
            !admin_permissions.contains(&Permission::TransferOwnership),
            "Admin permissions should NOT include TransferOwnership"
        );
    });
}

// ============================================================================
// Property 34: Member Permission Set
// ============================================================================

/// Feature: mycelium-cli, Property 34: Member Permission Set
///
/// For any operation, a user with Member role SHALL have read, write permissions
/// and NOT share, rotate, delete_project, or transfer_ownership.
///
/// **Validates: Requirements 9.4**
#[test]
fn property_member_permission_set() {
    proptest!(|(
        _seed in any::<u32>(),
    )| {
        let member = Role::Member;

        // Member should have these permissions
        prop_assert!(
            member.has_permission(Permission::Read),
            "Member should have Read permission"
        );
        prop_assert!(
            member.has_permission(Permission::Write),
            "Member should have Write permission"
        );

        // Member should NOT have these permissions
        prop_assert!(
            !member.has_permission(Permission::Share),
            "Member should NOT have Share permission"
        );
        prop_assert!(
            !member.has_permission(Permission::Rotate),
            "Member should NOT have Rotate permission"
        );
        prop_assert!(
            !member.has_permission(Permission::DeleteProject),
            "Member should NOT have DeleteProject permission"
        );
        prop_assert!(
            !member.has_permission(Permission::TransferOwnership),
            "Member should NOT have TransferOwnership permission"
        );

        // Verify the permission count is exactly 2
        let member_permissions = member.permissions();
        prop_assert_eq!(
            member_permissions.len(),
            2,
            "Member should have exactly 2 permissions"
        );

        // Verify the exact set of permissions
        prop_assert!(
            member_permissions.contains(&Permission::Read),
            "Member permissions should include Read"
        );
        prop_assert!(
            member_permissions.contains(&Permission::Write),
            "Member permissions should include Write"
        );
        prop_assert!(
            !member_permissions.contains(&Permission::Share),
            "Member permissions should NOT include Share"
        );
        prop_assert!(
            !member_permissions.contains(&Permission::Rotate),
            "Member permissions should NOT include Rotate"
        );
        prop_assert!(
            !member_permissions.contains(&Permission::DeleteProject),
            "Member permissions should NOT include DeleteProject"
        );
        prop_assert!(
            !member_permissions.contains(&Permission::TransferOwnership),
            "Member permissions should NOT include TransferOwnership"
        );
    });
}

// ============================================================================
// Property 35: Reader Permission Set
// ============================================================================

/// Feature: mycelium-cli, Property 35: Reader Permission Set
///
/// For any operation, a user with Reader role SHALL have read permission only.
///
/// **Validates: Requirements 9.5**
#[test]
fn property_reader_permission_set() {
    proptest!(|(
        _seed in any::<u32>(),
    )| {
        let reader = Role::Reader;

        // Reader should have only Read permission
        prop_assert!(
            reader.has_permission(Permission::Read),
            "Reader should have Read permission"
        );

        // Reader should NOT have any other permissions
        prop_assert!(
            !reader.has_permission(Permission::Write),
            "Reader should NOT have Write permission"
        );
        prop_assert!(
            !reader.has_permission(Permission::Share),
            "Reader should NOT have Share permission"
        );
        prop_assert!(
            !reader.has_permission(Permission::Rotate),
            "Reader should NOT have Rotate permission"
        );
        prop_assert!(
            !reader.has_permission(Permission::DeleteProject),
            "Reader should NOT have DeleteProject permission"
        );
        prop_assert!(
            !reader.has_permission(Permission::TransferOwnership),
            "Reader should NOT have TransferOwnership permission"
        );

        // Verify the permission count is exactly 1
        let reader_permissions = reader.permissions();
        prop_assert_eq!(
            reader_permissions.len(),
            1,
            "Reader should have exactly 1 permission"
        );

        // Verify the exact set of permissions
        prop_assert!(
            reader_permissions.contains(&Permission::Read),
            "Reader permissions should include Read"
        );
        prop_assert!(
            !reader_permissions.contains(&Permission::Write),
            "Reader permissions should NOT include Write"
        );
        prop_assert!(
            !reader_permissions.contains(&Permission::Share),
            "Reader permissions should NOT include Share"
        );
        prop_assert!(
            !reader_permissions.contains(&Permission::Rotate),
            "Reader permissions should NOT include Rotate"
        );
        prop_assert!(
            !reader_permissions.contains(&Permission::DeleteProject),
            "Reader permissions should NOT include DeleteProject"
        );
        prop_assert!(
            !reader_permissions.contains(&Permission::TransferOwnership),
            "Reader permissions should NOT include TransferOwnership"
        );
    });
}

// ============================================================================
// Additional Property: Role Hierarchy
// ============================================================================

/// Test that role hierarchy is maintained: higher roles have all permissions of lower roles
#[test]
fn property_role_hierarchy_permissions() {
    proptest!(|(
        _seed in any::<u32>(),
    )| {
        let reader = Role::Reader;
        let member = Role::Member;
        let admin = Role::Admin;
        let owner = Role::Owner;

        // Member should have all Reader permissions
        for permission in reader.permissions() {
            prop_assert!(
                member.has_permission(permission),
                "Member should have all Reader permissions, missing {:?}",
                permission
            );
        }

        // Admin should have all Member permissions
        for permission in member.permissions() {
            prop_assert!(
                admin.has_permission(permission),
                "Admin should have all Member permissions, missing {:?}",
                permission
            );
        }

        // Owner should have all Admin permissions
        for permission in admin.permissions() {
            prop_assert!(
                owner.has_permission(permission),
                "Owner should have all Admin permissions, missing {:?}",
                permission
            );
        }

        // Verify permission count increases with role level
        prop_assert!(
            member.permissions().len() >= reader.permissions().len(),
            "Member should have at least as many permissions as Reader"
        );
        prop_assert!(
            admin.permissions().len() >= member.permissions().len(),
            "Admin should have at least as many permissions as Member"
        );
        prop_assert!(
            owner.permissions().len() >= admin.permissions().len(),
            "Owner should have at least as many permissions as Admin"
        );
    });
}

// ============================================================================
// Additional Property: Permission Consistency
// ============================================================================

/// Test that permission checking is consistent with the permissions() method
#[test]
fn property_permission_consistency() {
    proptest!(|(
        role_index in 0..4usize,
    )| {
        let role = match role_index {
            0 => Role::Reader,
            1 => Role::Member,
            2 => Role::Admin,
            _ => Role::Owner,
        };

        let permissions_list = role.permissions();

        // For each permission in the list, has_permission should return true
        for permission in &permissions_list {
            prop_assert!(
                role.has_permission(*permission),
                "{:?} should have {:?} permission (from permissions() list)",
                role,
                permission
            );
        }

        // For each permission not in the list, has_permission should return false
        for permission in Permission::all() {
            if permissions_list.contains(&permission) {
                prop_assert!(
                    role.has_permission(permission),
                    "{:?} should have {:?} permission",
                    role,
                    permission
                );
            } else {
                prop_assert!(
                    !role.has_permission(permission),
                    "{:?} should NOT have {:?} permission",
                    role,
                    permission
                );
            }
        }
    });
}

// ============================================================================
// Additional Property: Role Level Ordering
// ============================================================================

/// Test that role levels are correctly ordered and correspond to permission sets
#[test]
fn property_role_level_ordering() {
    proptest!(|(
        _seed in any::<u32>(),
    )| {
        let reader = Role::Reader;
        let member = Role::Member;
        let admin = Role::Admin;
        let owner = Role::Owner;

        // Verify level values
        prop_assert_eq!(reader.level(), 1, "Reader should have level 1");
        prop_assert_eq!(member.level(), 2, "Member should have level 2");
        prop_assert_eq!(admin.level(), 3, "Admin should have level 3");
        prop_assert_eq!(owner.level(), 4, "Owner should have level 4");

        // Verify ordering
        prop_assert!(reader < member, "Reader should be less than Member");
        prop_assert!(member < admin, "Member should be less than Admin");
        prop_assert!(admin < owner, "Admin should be less than Owner");

        // Verify transitivity
        prop_assert!(reader < admin, "Reader should be less than Admin");
        prop_assert!(reader < owner, "Reader should be less than Owner");
        prop_assert!(member < owner, "Member should be less than Owner");
    });
}

// ============================================================================
// Property 36: Add Member Permission Check
// ============================================================================

/// Feature: mycelium-cli, Property 36: Add Member Permission Check
///
/// For any member addition, the actor SHALL have share permission and target role level
/// SHALL be <= actor's role level.
///
/// **Validates: Requirements 9.6**
#[test]
fn property_add_member_permission_check() {
    use myc_core::ids::{DeviceId, ProjectId, UserId};
    use myc_core::membership_ops::{add_member, MembershipList};
    use myc_core::pdk_ops::{create_pdk_version, generate_pdk, wrap_pdk};
    use myc_core::project::ProjectMember;
    use myc_crypto::kex::generate_x25519_keypair;
    use myc_crypto::sign::generate_ed25519_keypair;

    proptest!(|(
        actor_role_index in 0..4usize,
        target_role_index in 0..4usize,
    )| {
        // Map indices to roles
        let actor_role = match actor_role_index {
            0 => Role::Reader,
            1 => Role::Member,
            2 => Role::Admin,
            _ => Role::Owner,
        };

        let target_role = match target_role_index {
            0 => Role::Reader,
            1 => Role::Member,
            2 => Role::Admin,
            _ => Role::Owner,
        };

        // Setup: Create project with actor
        let project_id = ProjectId::new();
        let actor_user_id = UserId::from("github|actor");
        let actor_device_id = DeviceId::new();
        let (actor_signing_key, _) = generate_ed25519_keypair().unwrap();
        let (actor_encryption_secret, actor_encryption_pubkey) = generate_x25519_keypair().unwrap();

        // Create membership list with actor
        let actor_member = ProjectMember::new(actor_user_id.clone(), actor_role, actor_device_id);
        let membership_list = MembershipList::new(project_id, vec![actor_member], actor_device_id);

        // Create PDK version with actor's device
        let pdk = generate_pdk().unwrap();
        let actor_wrapped = wrap_pdk(&pdk, actor_device_id, &actor_encryption_pubkey).unwrap();
        let pdk_version = create_pdk_version(
            myc_core::ids::VersionNumber::FIRST,
            actor_device_id,
            None,
            vec![actor_wrapped],
        );

        // Try to add a new member
        let new_user_id = UserId::from("github|newmember");
        let new_device_id = DeviceId::new();
        let (_, new_device_pubkey) = generate_x25519_keypair().unwrap();

        let result = add_member(
            &membership_list,
            &pdk_version,
            &actor_user_id,
            actor_device_id,
            &actor_encryption_secret,
            &actor_signing_key,
            new_user_id.clone(),
            target_role,
            &[(new_device_id, new_device_pubkey)],
        );

        // Determine expected outcome based on permissions
        let actor_has_share = actor_role.has_permission(Permission::Share);
        let target_level_ok = target_role.level() <= actor_role.level();
        let should_succeed = actor_has_share && target_level_ok;

        if should_succeed {
            // Operation should succeed
            prop_assert!(
                result.is_ok(),
                "add_member should succeed when actor ({:?}, level {}) has share permission and target role ({:?}, level {}) <= actor level",
                actor_role,
                actor_role.level(),
                target_role,
                target_role.level()
            );

            // Verify the member was added
            let add_result = result.unwrap();
            prop_assert_eq!(
                add_result.membership_list.members.len(),
                2,
                "membership list should have 2 members after successful add"
            );
            prop_assert!(
                add_result.membership_list.find_member(&new_user_id).is_some(),
                "new member should be in membership list"
            );
            prop_assert_eq!(
                add_result.membership_list.get_role(&new_user_id),
                Some(target_role),
                "new member should have the target role"
            );
        } else {
            // Operation should fail
            prop_assert!(
                result.is_err(),
                "add_member should fail when actor ({:?}, level {}) lacks share permission ({}) or target role ({:?}, level {}) > actor level ({})",
                actor_role,
                actor_role.level(),
                actor_has_share,
                target_role,
                target_role.level(),
                target_level_ok
            );
        }
    });
}
