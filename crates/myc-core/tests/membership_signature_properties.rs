//! Property-based tests for membership signature verification.
//!
//! These tests verify that membership list signatures are correctly verified
//! and that tampering is detected.

use myc_core::ids::{DeviceId, ProjectId, UserId};
use myc_core::membership_ops::MembershipList;
use myc_core::project::{ProjectMember, Role};
use myc_crypto::sign::generate_ed25519_keypair;
use proptest::prelude::*;

// ============================================================================
// Property 38: Membership Signature Verification
// ============================================================================

/// Feature: mycelium-cli, Property 38: Membership Signature Verification
///
/// For any members.json file, the signature SHALL verify using the signer's Ed25519 public key.
///
/// **Validates: Requirements 9.8**
#[test]
fn property_membership_signature_verification() {
    proptest!(|(
        num_members in 1..10usize,
        role_indices in prop::collection::vec(0..4usize, 1..10),
    )| {
        // Generate signing keypair
        let (signing_key, public_key) = generate_ed25519_keypair().unwrap();

        // Create project and device IDs
        let project_id = ProjectId::new();
        let device_id = DeviceId::new();

        // Create members with random roles
        let members: Vec<ProjectMember> = role_indices
            .iter()
            .take(num_members)
            .enumerate()
            .map(|(i, &role_index)| {
                let user_id = UserId::from(format!("github|user{}", i));
                let role = match role_index {
                    0 => Role::Reader,
                    1 => Role::Member,
                    2 => Role::Admin,
                    _ => Role::Owner,
                };
                ProjectMember::new(user_id, role, device_id)
            })
            .collect();

        // Create membership list
        let mut membership_list = MembershipList::new(project_id, members, device_id);

        // Sign the membership list
        membership_list.sign(&signing_key).unwrap();

        // Verify the signature with the correct public key
        let verify_result = membership_list.verify(&public_key);
        prop_assert!(
            verify_result.is_ok(),
            "Signature verification should succeed with correct public key"
        );

        // Verify that signature is present
        prop_assert!(
            membership_list.signature.is_some(),
            "Signature should be present after signing"
        );
    });
}

/// Test that signature verification fails with wrong public key
#[test]
fn property_membership_signature_wrong_key_fails() {
    proptest!(|(
        num_members in 1..10usize,
    )| {
        // Generate two different keypairs
        let (signing_key1, _public_key1) = generate_ed25519_keypair().unwrap();
        let (_signing_key2, public_key2) = generate_ed25519_keypair().unwrap();

        // Create project and device IDs
        let project_id = ProjectId::new();
        let device_id = DeviceId::new();

        // Create members
        let members: Vec<ProjectMember> = (0..num_members)
            .map(|i| {
                let user_id = UserId::from(format!("github|user{}", i));
                ProjectMember::new(user_id, Role::Member, device_id)
            })
            .collect();

        // Create and sign membership list with key 1
        let mut membership_list = MembershipList::new(project_id, members, device_id);
        membership_list.sign(&signing_key1).unwrap();

        // Verify with key 2 should fail
        let verify_result = membership_list.verify(&public_key2);
        prop_assert!(
            verify_result.is_err(),
            "Signature verification should fail with wrong public key"
        );
    });
}

/// Test that signature verification fails when membership list is tampered with
#[test]
fn property_membership_signature_tampering_detected() {
    proptest!(|(
        num_members in 2..10usize,
    )| {
        // Generate signing keypair
        let (signing_key, public_key) = generate_ed25519_keypair().unwrap();

        // Create project and device IDs
        let project_id = ProjectId::new();
        let device_id = DeviceId::new();

        // Create members
        let members: Vec<ProjectMember> = (0..num_members)
            .map(|i| {
                let user_id = UserId::from(format!("github|user{}", i));
                ProjectMember::new(user_id, Role::Member, device_id)
            })
            .collect();

        // Create and sign membership list
        let mut membership_list = MembershipList::new(project_id, members, device_id);
        membership_list.sign(&signing_key).unwrap();

        // Verify original signature works
        prop_assert!(
            membership_list.verify(&public_key).is_ok(),
            "Original signature should verify"
        );

        // Tamper with the membership list by adding a new member
        let new_user_id = UserId::from("github|attacker");
        let new_member = ProjectMember::new(new_user_id, Role::Owner, device_id);
        membership_list.members.push(new_member);

        // Verification should now fail
        let verify_result = membership_list.verify(&public_key);
        prop_assert!(
            verify_result.is_err(),
            "Signature verification should fail after tampering with members"
        );
    });
}

/// Test that signature verification fails when project_id is tampered with
#[test]
fn property_membership_signature_project_id_tampering() {
    proptest!(|(
        num_members in 1..10usize,
    )| {
        // Generate signing keypair
        let (signing_key, public_key) = generate_ed25519_keypair().unwrap();

        // Create project and device IDs
        let project_id = ProjectId::new();
        let device_id = DeviceId::new();

        // Create members
        let members: Vec<ProjectMember> = (0..num_members)
            .map(|i| {
                let user_id = UserId::from(format!("github|user{}", i));
                ProjectMember::new(user_id, Role::Member, device_id)
            })
            .collect();

        // Create and sign membership list
        let mut membership_list = MembershipList::new(project_id, members, device_id);
        membership_list.sign(&signing_key).unwrap();

        // Verify original signature works
        prop_assert!(
            membership_list.verify(&public_key).is_ok(),
            "Original signature should verify"
        );

        // Tamper with the project_id
        membership_list.project_id = ProjectId::new();

        // Verification should now fail
        let verify_result = membership_list.verify(&public_key);
        prop_assert!(
            verify_result.is_err(),
            "Signature verification should fail after tampering with project_id"
        );
    });
}

/// Test that signature verification fails when updated_by is tampered with
#[test]
fn property_membership_signature_updated_by_tampering() {
    proptest!(|(
        num_members in 1..10usize,
    )| {
        // Generate signing keypair
        let (signing_key, public_key) = generate_ed25519_keypair().unwrap();

        // Create project and device IDs
        let project_id = ProjectId::new();
        let device_id = DeviceId::new();

        // Create members
        let members: Vec<ProjectMember> = (0..num_members)
            .map(|i| {
                let user_id = UserId::from(format!("github|user{}", i));
                ProjectMember::new(user_id, Role::Member, device_id)
            })
            .collect();

        // Create and sign membership list
        let mut membership_list = MembershipList::new(project_id, members, device_id);
        membership_list.sign(&signing_key).unwrap();

        // Verify original signature works
        prop_assert!(
            membership_list.verify(&public_key).is_ok(),
            "Original signature should verify"
        );

        // Tamper with the updated_by field
        membership_list.updated_by = DeviceId::new();

        // Verification should now fail
        let verify_result = membership_list.verify(&public_key);
        prop_assert!(
            verify_result.is_err(),
            "Signature verification should fail after tampering with updated_by"
        );
    });
}

/// Test that signature verification fails when member roles are tampered with
#[test]
fn property_membership_signature_role_tampering() {
    proptest!(|(
        num_members in 1..10usize,
    )| {
        // Generate signing keypair
        let (signing_key, public_key) = generate_ed25519_keypair().unwrap();

        // Create project and device IDs
        let project_id = ProjectId::new();
        let device_id = DeviceId::new();

        // Create members
        let members: Vec<ProjectMember> = (0..num_members)
            .map(|i| {
                let user_id = UserId::from(format!("github|user{}", i));
                ProjectMember::new(user_id, Role::Member, device_id)
            })
            .collect();

        // Create and sign membership list
        let mut membership_list = MembershipList::new(project_id, members, device_id);
        membership_list.sign(&signing_key).unwrap();

        // Verify original signature works
        prop_assert!(
            membership_list.verify(&public_key).is_ok(),
            "Original signature should verify"
        );

        // Tamper with a member's role (escalate to Owner)
        if let Some(member) = membership_list.members.first_mut() {
            member.role = Role::Owner;
        }

        // Verification should now fail
        let verify_result = membership_list.verify(&public_key);
        prop_assert!(
            verify_result.is_err(),
            "Signature verification should fail after tampering with member role"
        );
    });
}

/// Test that unsigned membership list fails verification
#[test]
fn property_membership_signature_unsigned_fails() {
    proptest!(|(
        num_members in 1..10usize,
    )| {
        // Generate public key for verification
        let (_signing_key, public_key) = generate_ed25519_keypair().unwrap();

        // Create project and device IDs
        let project_id = ProjectId::new();
        let device_id = DeviceId::new();

        // Create members
        let members: Vec<ProjectMember> = (0..num_members)
            .map(|i| {
                let user_id = UserId::from(format!("github|user{}", i));
                ProjectMember::new(user_id, Role::Member, device_id)
            })
            .collect();

        // Create membership list WITHOUT signing
        let membership_list = MembershipList::new(project_id, members, device_id);

        // Verify that signature is not present
        prop_assert!(
            membership_list.signature.is_none(),
            "Unsigned membership list should not have a signature"
        );

        // Verification should fail
        let verify_result = membership_list.verify(&public_key);
        prop_assert!(
            verify_result.is_err(),
            "Verification should fail for unsigned membership list"
        );
    });
}

/// Test that re-signing after modification produces valid signature
#[test]
fn property_membership_signature_resign_after_modification() {
    proptest!(|(
        num_members in 1..10usize,
    )| {
        // Generate signing keypair
        let (signing_key, public_key) = generate_ed25519_keypair().unwrap();

        // Create project and device IDs
        let project_id = ProjectId::new();
        let device_id = DeviceId::new();

        // Create members
        let members: Vec<ProjectMember> = (0..num_members)
            .map(|i| {
                let user_id = UserId::from(format!("github|user{}", i));
                ProjectMember::new(user_id, Role::Member, device_id)
            })
            .collect();

        // Create and sign membership list
        let mut membership_list = MembershipList::new(project_id, members, device_id);
        membership_list.sign(&signing_key).unwrap();

        // Verify original signature works
        prop_assert!(
            membership_list.verify(&public_key).is_ok(),
            "Original signature should verify"
        );

        // Modify the membership list
        let new_user_id = UserId::from("github|newuser");
        let new_member = ProjectMember::new(new_user_id, Role::Reader, device_id);
        membership_list.members.push(new_member);

        // Old signature should now fail
        prop_assert!(
            membership_list.verify(&public_key).is_err(),
            "Old signature should fail after modification"
        );

        // Re-sign the membership list
        membership_list.sign(&signing_key).unwrap();

        // New signature should verify
        let verify_result = membership_list.verify(&public_key);
        prop_assert!(
            verify_result.is_ok(),
            "New signature should verify after re-signing"
        );
    });
}

/// Test signature verification with all role types
#[test]
fn property_membership_signature_all_roles() {
    proptest!(|(
        _seed in any::<u32>(),
    )| {
        // Generate signing keypair
        let (signing_key, public_key) = generate_ed25519_keypair().unwrap();

        // Create project and device IDs
        let project_id = ProjectId::new();
        let device_id = DeviceId::new();

        // Create members with all role types
        let members = vec![
            ProjectMember::new(UserId::from("github|owner"), Role::Owner, device_id),
            ProjectMember::new(UserId::from("github|admin"), Role::Admin, device_id),
            ProjectMember::new(UserId::from("github|member"), Role::Member, device_id),
            ProjectMember::new(UserId::from("github|reader"), Role::Reader, device_id),
        ];

        // Create and sign membership list
        let mut membership_list = MembershipList::new(project_id, members, device_id);
        membership_list.sign(&signing_key).unwrap();

        // Verify the signature
        let verify_result = membership_list.verify(&public_key);
        prop_assert!(
            verify_result.is_ok(),
            "Signature should verify for membership list with all role types"
        );
    });
}

/// Test that signature is deterministic (signing twice produces same signature)
#[test]
fn property_membership_signature_deterministic() {
    proptest!(|(
        num_members in 1..10usize,
    )| {
        // Generate signing keypair
        let (signing_key, _public_key) = generate_ed25519_keypair().unwrap();

        // Create project and device IDs
        let project_id = ProjectId::new();
        let device_id = DeviceId::new();

        // Create members
        let members: Vec<ProjectMember> = (0..num_members)
            .map(|i| {
                let user_id = UserId::from(format!("github|user{}", i));
                ProjectMember::new(user_id, Role::Member, device_id)
            })
            .collect();

        // Create membership list
        let mut membership_list1 = MembershipList::new(project_id, members.clone(), device_id);
        let mut membership_list2 = MembershipList::new(project_id, members, device_id);

        // Ensure timestamps are the same for deterministic comparison
        membership_list2.updated_at = membership_list1.updated_at;

        // Sign both
        membership_list1.sign(&signing_key).unwrap();
        membership_list2.sign(&signing_key).unwrap();

        // Signatures should be identical
        prop_assert_eq!(
            membership_list1.signature,
            membership_list2.signature,
            "Signing identical membership lists should produce identical signatures"
        );
    });
}
