//! Integration tests for membership operations.

use myc_core::ids::{DeviceId, ProjectId, UserId};
use myc_core::membership_ops::{
    add_member, change_role, check_permission, remove_member, transfer_ownership, MembershipList,
};
use myc_core::pdk_ops::{create_pdk_version, generate_pdk, wrap_pdk};
use myc_core::project::{Permission, ProjectMember, Role};
use myc_crypto::kex::generate_x25519_keypair;
use myc_crypto::sign::generate_ed25519_keypair;

#[test]
fn test_add_member_integration() {
    // Setup: Create initial project with owner
    let project_id = ProjectId::new();
    let owner_user_id = UserId::from("github|owner");
    let owner_device_id = DeviceId::new();
    let (owner_signing_key, _) = generate_ed25519_keypair().unwrap();
    let (owner_encryption_secret, owner_encryption_pubkey) = generate_x25519_keypair().unwrap();

    // Create initial membership list with owner
    let owner_member = ProjectMember::new(owner_user_id.clone(), Role::Owner, owner_device_id);
    let mut membership_list = MembershipList::new(project_id, vec![owner_member], owner_device_id);
    membership_list.sign(&owner_signing_key).unwrap();

    // Create initial PDK version with owner's device
    let pdk = generate_pdk().unwrap();
    let owner_wrapped = wrap_pdk(&pdk, owner_device_id, &owner_encryption_pubkey).unwrap();
    let pdk_version = create_pdk_version(
        myc_core::ids::VersionNumber::FIRST,
        owner_device_id,
        Some("Initial PDK".to_string()),
        vec![owner_wrapped],
    );

    // Add a new member
    let new_user_id = UserId::from("github|newmember");
    let new_device_id = DeviceId::new();
    let (_, new_device_pubkey) = generate_x25519_keypair().unwrap();

    let result = add_member(
        &membership_list,
        &pdk_version,
        &owner_user_id,
        owner_device_id,
        &owner_encryption_secret,
        &owner_signing_key,
        new_user_id.clone(),
        Role::Member,
        &[(new_device_id, new_device_pubkey)],
    )
    .unwrap();

    // Verify membership list updated
    assert_eq!(result.membership_list.members.len(), 2);
    assert!(result.membership_list.find_member(&new_user_id).is_some());
    assert_eq!(
        result.membership_list.get_role(&new_user_id),
        Some(Role::Member)
    );

    // Verify new wrapped PDKs created
    assert_eq!(result.new_wrapped_pdks.len(), 1);
    assert_eq!(result.new_wrapped_pdks[0].device_id, new_device_id);

    // Verify signature is present
    assert!(result.membership_list.signature.is_some());
}

#[test]
fn test_add_member_fails_without_permission() {
    // Setup: Create project with a member (not admin)
    let project_id = ProjectId::new();
    let member_user_id = UserId::from("github|member");
    let member_device_id = DeviceId::new();
    let (member_signing_key, _) = generate_ed25519_keypair().unwrap();
    let (member_encryption_secret, _) = generate_x25519_keypair().unwrap();

    let member = ProjectMember::new(member_user_id.clone(), Role::Member, member_device_id);
    let membership_list = MembershipList::new(project_id, vec![member], member_device_id);

    let _pdk = generate_pdk().unwrap();
    let pdk_version = create_pdk_version(
        myc_core::ids::VersionNumber::FIRST,
        member_device_id,
        None,
        vec![],
    );

    // Try to add a new member (should fail - member doesn't have share permission)
    let new_user_id = UserId::from("github|newmember");
    let new_device_id = DeviceId::new();
    let (_, new_device_pubkey) = generate_x25519_keypair().unwrap();

    let result = add_member(
        &membership_list,
        &pdk_version,
        &member_user_id,
        member_device_id,
        &member_encryption_secret,
        &member_signing_key,
        new_user_id,
        Role::Reader,
        &[(new_device_id, new_device_pubkey)],
    );

    assert!(result.is_err());
}

#[test]
fn test_add_member_fails_role_level_too_high() {
    // Setup: Create project with admin
    let project_id = ProjectId::new();
    let admin_user_id = UserId::from("github|admin");
    let admin_device_id = DeviceId::new();
    let (admin_signing_key, _) = generate_ed25519_keypair().unwrap();
    let (admin_encryption_secret, admin_encryption_pubkey) = generate_x25519_keypair().unwrap();

    let admin_member = ProjectMember::new(admin_user_id.clone(), Role::Admin, admin_device_id);
    let membership_list = MembershipList::new(project_id, vec![admin_member], admin_device_id);

    let pdk = generate_pdk().unwrap();
    let admin_wrapped = wrap_pdk(&pdk, admin_device_id, &admin_encryption_pubkey).unwrap();
    let pdk_version = create_pdk_version(
        myc_core::ids::VersionNumber::FIRST,
        admin_device_id,
        None,
        vec![admin_wrapped],
    );

    // Try to add a new owner (should fail - admin can't assign owner role)
    let new_user_id = UserId::from("github|newowner");
    let new_device_id = DeviceId::new();
    let (_, new_device_pubkey) = generate_x25519_keypair().unwrap();

    let result = add_member(
        &membership_list,
        &pdk_version,
        &admin_user_id,
        admin_device_id,
        &admin_encryption_secret,
        &admin_signing_key,
        new_user_id,
        Role::Owner,
        &[(new_device_id, new_device_pubkey)],
    );

    assert!(result.is_err());
}

#[test]
fn test_remove_member_integration() {
    // Setup: Create project with owner and member
    let project_id = ProjectId::new();
    let owner_user_id = UserId::from("github|owner");
    let owner_device_id = DeviceId::new();
    let (owner_signing_key, _) = generate_ed25519_keypair().unwrap();
    let (_, owner_encryption_pubkey) = generate_x25519_keypair().unwrap();

    let member_user_id = UserId::from("github|member");
    let member_device_id = DeviceId::new();
    let (_, _member_encryption_pubkey) = generate_x25519_keypair().unwrap();

    let owner_member = ProjectMember::new(owner_user_id.clone(), Role::Owner, owner_device_id);
    let member = ProjectMember::new(member_user_id.clone(), Role::Member, member_device_id);
    let membership_list =
        MembershipList::new(project_id, vec![owner_member, member], owner_device_id);

    // Remove the member
    let remaining_devices = vec![(owner_device_id, owner_encryption_pubkey)];

    let result = remove_member(
        &membership_list,
        &owner_user_id,
        owner_device_id,
        &owner_signing_key,
        &member_user_id,
        &remaining_devices,
    )
    .unwrap();

    // Verify membership list updated
    assert_eq!(result.membership_list.members.len(), 1);
    assert!(result
        .membership_list
        .find_member(&member_user_id)
        .is_none());
    assert!(result.membership_list.find_member(&owner_user_id).is_some());

    // Verify new PDK created
    assert_eq!(result.new_wrapped_pdks.len(), 1);
    assert_eq!(result.new_wrapped_pdks[0].device_id, owner_device_id);

    // Verify signature is present
    assert!(result.membership_list.signature.is_some());
}

#[test]
fn test_remove_member_fails_insufficient_role() {
    // Setup: Create project with two members
    let project_id = ProjectId::new();
    let member1_user_id = UserId::from("github|member1");
    let member1_device_id = DeviceId::new();
    let (member1_signing_key, _) = generate_ed25519_keypair().unwrap();

    let member2_user_id = UserId::from("github|member2");

    let member1 = ProjectMember::new(member1_user_id.clone(), Role::Member, member1_device_id);
    let member2 = ProjectMember::new(member2_user_id.clone(), Role::Member, member1_device_id);
    let membership_list =
        MembershipList::new(project_id, vec![member1, member2], member1_device_id);

    // Try to remove member2 (should fail - member1 doesn't have share permission)
    let result = remove_member(
        &membership_list,
        &member1_user_id,
        member1_device_id,
        &member1_signing_key,
        &member2_user_id,
        &[],
    );

    assert!(result.is_err());
}

#[test]
fn test_change_role_integration() {
    // Setup: Create project with owner and member
    let project_id = ProjectId::new();
    let owner_user_id = UserId::from("github|owner");
    let owner_device_id = DeviceId::new();
    let (owner_signing_key, _) = generate_ed25519_keypair().unwrap();

    let member_user_id = UserId::from("github|member");

    let owner_member = ProjectMember::new(owner_user_id.clone(), Role::Owner, owner_device_id);
    let member = ProjectMember::new(member_user_id.clone(), Role::Member, owner_device_id);
    let membership_list =
        MembershipList::new(project_id, vec![owner_member, member], owner_device_id);

    // Change member to admin
    let result = change_role(
        &membership_list,
        &owner_user_id,
        owner_device_id,
        &owner_signing_key,
        &member_user_id,
        Role::Admin,
    )
    .unwrap();

    // Verify role changed
    assert_eq!(
        result.membership_list.get_role(&member_user_id),
        Some(Role::Admin)
    );

    // Verify signature is present
    assert!(result.membership_list.signature.is_some());
}

#[test]
fn test_change_role_fails_role_too_high() {
    // Setup: Create project with admin and member
    let project_id = ProjectId::new();
    let admin_user_id = UserId::from("github|admin");
    let admin_device_id = DeviceId::new();
    let (admin_signing_key, _) = generate_ed25519_keypair().unwrap();

    let member_user_id = UserId::from("github|member");

    let admin_member = ProjectMember::new(admin_user_id.clone(), Role::Admin, admin_device_id);
    let member = ProjectMember::new(member_user_id.clone(), Role::Member, admin_device_id);
    let membership_list =
        MembershipList::new(project_id, vec![admin_member, member], admin_device_id);

    // Try to change member to owner (should fail - admin can't assign owner role)
    let result = change_role(
        &membership_list,
        &admin_user_id,
        admin_device_id,
        &admin_signing_key,
        &member_user_id,
        Role::Owner,
    );

    assert!(result.is_err());
}

#[test]
fn test_transfer_ownership_integration() {
    // Setup: Create project with owner and admin
    let project_id = ProjectId::new();
    let owner_user_id = UserId::from("github|owner");
    let owner_device_id = DeviceId::new();
    let (owner_signing_key, _) = generate_ed25519_keypair().unwrap();

    let admin_user_id = UserId::from("github|admin");

    let owner_member = ProjectMember::new(owner_user_id.clone(), Role::Owner, owner_device_id);
    let admin_member = ProjectMember::new(admin_user_id.clone(), Role::Admin, owner_device_id);
    let membership_list = MembershipList::new(
        project_id,
        vec![owner_member, admin_member],
        owner_device_id,
    );

    // Transfer ownership to admin
    let result = transfer_ownership(
        &membership_list,
        &owner_user_id,
        owner_device_id,
        &owner_signing_key,
        &admin_user_id,
    )
    .unwrap();

    // Verify roles swapped
    assert_eq!(
        result.membership_list.get_role(&owner_user_id),
        Some(Role::Admin)
    );
    assert_eq!(
        result.membership_list.get_role(&admin_user_id),
        Some(Role::Owner)
    );

    // Verify signature is present
    assert!(result.membership_list.signature.is_some());
}

#[test]
fn test_transfer_ownership_fails_not_owner() {
    // Setup: Create project with admin and member
    let project_id = ProjectId::new();
    let admin_user_id = UserId::from("github|admin");
    let admin_device_id = DeviceId::new();
    let (admin_signing_key, _) = generate_ed25519_keypair().unwrap();

    let member_user_id = UserId::from("github|member");

    let admin_member = ProjectMember::new(admin_user_id.clone(), Role::Admin, admin_device_id);
    let member = ProjectMember::new(member_user_id.clone(), Role::Member, admin_device_id);
    let membership_list =
        MembershipList::new(project_id, vec![admin_member, member], admin_device_id);

    // Try to transfer ownership (should fail - admin is not owner)
    let result = transfer_ownership(
        &membership_list,
        &admin_user_id,
        admin_device_id,
        &admin_signing_key,
        &member_user_id,
    );

    assert!(result.is_err());
}

#[test]
fn test_transfer_ownership_fails_target_not_admin() {
    // Setup: Create project with owner and member
    let project_id = ProjectId::new();
    let owner_user_id = UserId::from("github|owner");
    let owner_device_id = DeviceId::new();
    let (owner_signing_key, _) = generate_ed25519_keypair().unwrap();

    let member_user_id = UserId::from("github|member");

    let owner_member = ProjectMember::new(owner_user_id.clone(), Role::Owner, owner_device_id);
    let member = ProjectMember::new(member_user_id.clone(), Role::Member, owner_device_id);
    let membership_list =
        MembershipList::new(project_id, vec![owner_member, member], owner_device_id);

    // Try to transfer ownership to member (should fail - target must be admin)
    let result = transfer_ownership(
        &membership_list,
        &owner_user_id,
        owner_device_id,
        &owner_signing_key,
        &member_user_id,
    );

    assert!(result.is_err());
}

#[test]
fn test_check_permission_integration() {
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

    // Owner can do everything
    assert!(check_permission(&list, &owner_id, Permission::Read).is_ok());
    assert!(check_permission(&list, &owner_id, Permission::Write).is_ok());
    assert!(check_permission(&list, &owner_id, Permission::Share).is_ok());
    assert!(check_permission(&list, &owner_id, Permission::Rotate).is_ok());
    assert!(check_permission(&list, &owner_id, Permission::DeleteProject).is_ok());
    assert!(check_permission(&list, &owner_id, Permission::TransferOwnership).is_ok());

    // Admin can read, write, share, rotate
    assert!(check_permission(&list, &admin_id, Permission::Read).is_ok());
    assert!(check_permission(&list, &admin_id, Permission::Write).is_ok());
    assert!(check_permission(&list, &admin_id, Permission::Share).is_ok());
    assert!(check_permission(&list, &admin_id, Permission::Rotate).is_ok());
    assert!(check_permission(&list, &admin_id, Permission::DeleteProject).is_err());
    assert!(check_permission(&list, &admin_id, Permission::TransferOwnership).is_err());

    // Member can read, write
    assert!(check_permission(&list, &member_id, Permission::Read).is_ok());
    assert!(check_permission(&list, &member_id, Permission::Write).is_ok());
    assert!(check_permission(&list, &member_id, Permission::Share).is_err());
    assert!(check_permission(&list, &member_id, Permission::Rotate).is_err());

    // Reader can only read
    assert!(check_permission(&list, &reader_id, Permission::Read).is_ok());
    assert!(check_permission(&list, &reader_id, Permission::Write).is_err());
    assert!(check_permission(&list, &reader_id, Permission::Share).is_err());
    assert!(check_permission(&list, &reader_id, Permission::Rotate).is_err());
}
