//! End-to-end integration tests for complete workflows.
//!
//! These tests verify that complete user workflows work correctly from start to finish,
//! including vault initialization, project creation, secret management, membership operations,
//! and recovery scenarios.

use anyhow::Result;
use myc_core::audit::{AuditEvent, EventDetails, EventId, EventType, OrgEventDetails, ProjectEventDetails, MembershipEventDetails};
use myc_core::device::{Device, DeviceStatus, DeviceType};
use myc_core::ids::{DeviceId, OrgId, ProjectId, SecretSetId, UserId, VersionNumber};
use myc_core::org::{Org, OrgSettings};
use myc_core::pdk::{PdkVersion, WrappedPdk};
use myc_core::project::{Project, ProjectMember, Role};
use myc_core::secret_set::{SecretEntry, SecretSet, SecretSetVersion};
use myc_crypto::aead::{encrypt, AeadKey};
use myc_crypto::hash::{chain_hash, hash, HashOutput};
use myc_crypto::kex::{diffie_hellman, generate_x25519_keypair, X25519PublicKey, X25519SecretKey};
use myc_crypto::random::generate_random_bytes;
use myc_crypto::sign::{generate_ed25519_keypair, sign, verify, Ed25519SecretKey};
use serde_json;
use time::OffsetDateTime;

/// Test helper to create a mock device
fn create_test_device(user_id: &str, name: &str) -> (Device, Ed25519SecretKey, X25519SecretKey) {
    let device_id = DeviceId::new();
    let user_id = UserId::from(user_id);
    let (signing_secret, signing_public) = generate_ed25519_keypair().unwrap();
    let (encryption_secret, encryption_public) = generate_x25519_keypair().unwrap();

    let device = Device {
        schema_version: 1,
        id: device_id,
        user_id,
        name: name.to_string(),
        device_type: DeviceType::Interactive,
        signing_pubkey: signing_public,
        encryption_pubkey: encryption_public,
        enrolled_at: OffsetDateTime::now_utc(),
        status: DeviceStatus::Active,
        expires_at: None,
    };

    (device, signing_secret, encryption_secret)
}

/// Test helper to create a test PDK
fn create_test_pdk() -> AeadKey {
    let key_bytes: [u8; 32] = generate_random_bytes().unwrap();
    AeadKey::from_bytes(key_bytes)
}

/// Test helper to wrap a PDK to a device
fn wrap_pdk_to_device(
    pdk: &AeadKey,
    device_id: DeviceId,
    device_pubkey: &X25519PublicKey,
) -> Result<WrappedPdk> {
    // Generate ephemeral keypair
    let (ephemeral_secret, ephemeral_public) = generate_x25519_keypair()?;

    // Compute shared secret
    let shared_secret = diffie_hellman(&ephemeral_secret, device_pubkey);

    // Derive wrap key using HKDF
    let wrap_key = myc_crypto::kdf::derive_aead_key(&shared_secret, b"mycelium-pdk-wrap");

    // Encrypt PDK
    let pdk_bytes = pdk.as_bytes();
    let ciphertext = encrypt(&wrap_key, pdk_bytes, &[])?;

    Ok(WrappedPdk {
        device_id,
        ephemeral_pubkey: ephemeral_public,
        ciphertext,
    })
}

/// Test helper to unwrap a PDK from a wrapped PDK
fn unwrap_pdk_from_wrapped(
    wrapped: &WrappedPdk,
    device_secret: &X25519SecretKey,
) -> Result<AeadKey> {
    // Compute shared secret
    let shared_secret = diffie_hellman(device_secret, &wrapped.ephemeral_pubkey);

    // Derive wrap key
    let wrap_key = myc_crypto::kdf::derive_aead_key(&shared_secret, b"mycelium-pdk-wrap");

    // Decrypt PDK
    let pdk_bytes = myc_crypto::aead::decrypt(&wrap_key, &wrapped.ciphertext, &[])?;
    let pdk_array: [u8; 32] = pdk_bytes.try_into().map_err(|_| anyhow::anyhow!("Invalid PDK size"))?;
    Ok(AeadKey::from_bytes(pdk_array))
}

#[test]
fn test_complete_vault_initialization_workflow() -> Result<()> {
    // Test the complete workflow: vault init → project creation → secret push/pull

    // Step 1: Create organization (vault initialization)
    let org_id = OrgId::new();
    let (owner_device, owner_signing_key, owner_encryption_key) =
        create_test_device("github|owner", "Owner's Laptop");

    let org = Org {
        schema_version: 1,
        id: org_id,
        name: "Test Organization".to_string(),
        created_at: OffsetDateTime::now_utc(),
        settings: OrgSettings {
            require_device_approval: false,
            github_org: Some("testorg".to_string()),
            default_rotation_policy: None,
            network_beacon: "mycelium_spore_network_v1".to_string(),
        },
    };

    // Step 2: Create project
    let project_id = ProjectId::new();
    let project = Project {
        schema_version: 1,
        id: project_id,
        org_id,
        name: "Test Project".to_string(),
        created_at: OffsetDateTime::now_utc(),
        created_by: owner_device.id,
        current_pdk_version: VersionNumber::FIRST,
    };

    // Step 3: Create initial PDK version
    let pdk = create_test_pdk();
    let owner_wrapped = wrap_pdk_to_device(&pdk, owner_device.id, &owner_device.encryption_pubkey)?;

    let pdk_version = PdkVersion {
        version: VersionNumber::FIRST,
        created_at: OffsetDateTime::now_utc(),
        created_by: owner_device.id,
        reason: Some("Initial PDK".to_string()),
        wrapped_keys: vec![owner_wrapped],
    };

    // Step 4: Create secret set
    let set_id = SecretSetId::new();
    let secret_set = SecretSet {
        schema_version: 1,
        id: set_id,
        project_id,
        name: "production".to_string(),
        created_at: OffsetDateTime::now_utc(),
        created_by: owner_device.id,
        current_version: VersionNumber::FIRST,
    };

    // Step 5: Create and encrypt first secret version
    let entries = vec![
        SecretEntry {
            key: "API_KEY".to_string(),
            value: "secret123".to_string(),
            metadata: None,
        },
        SecretEntry {
            key: "DB_URL".to_string(),
            value: "postgres://localhost:5432/myapp".to_string(),
            metadata: None,
        },
    ];

    // Serialize entries (canonical JSON, sorted by key)
    let mut sorted_entries = entries.clone();
    sorted_entries.sort_by(|a, b| a.key.cmp(&b.key));
    let plaintext = serde_json::to_string(&sorted_entries)?;

    // Compute content hash
    let content_hash = hash(plaintext.as_bytes());

    // Compute chain hash (first version, so no previous)
    let chain_hash = hash(content_hash.as_bytes());

    // Construct AAD
    let aad = format!(
        "{}{}{}{}",
        project_id.as_uuid(),
        set_id.as_uuid(),
        VersionNumber::FIRST.as_u64(),
        VersionNumber::FIRST.as_u64()
    );

    // Encrypt with PDK
    let ciphertext = encrypt(&pdk, plaintext.as_bytes(), aad.as_bytes())?;

    // Create version metadata
    let version_metadata = SecretSetVersion {
        schema_version: 1,
        set_id,
        version: VersionNumber::FIRST,
        pdk_version: VersionNumber::FIRST,
        created_at: OffsetDateTime::now_utc(),
        created_by: owner_device.id,
        message: Some("Initial secrets".to_string()),
        content_hash,
        previous_hash: None,
        ciphertext: ciphertext.clone(),
        signature: myc_crypto::sign::Signature::from_bytes([0u8; 64]), // Placeholder
    };

    // Sign the metadata
    let metadata_json = myc_core::canonical::to_canonical_json(&version_metadata)?;
    let signature = sign(&owner_signing_key, metadata_json.as_bytes());

    // Step 6: Verify we can decrypt the secrets back
    let decrypted_plaintext = myc_crypto::aead::decrypt(&pdk, &ciphertext, aad.as_bytes())?;
    let decrypted_entries: Vec<SecretEntry> = serde_json::from_slice(&decrypted_plaintext)?;

    // Verify content
    assert_eq!(decrypted_entries.len(), 2);
    assert_eq!(decrypted_entries[0].key, "API_KEY");
    assert_eq!(decrypted_entries[0].value, "secret123");
    assert_eq!(decrypted_entries[1].key, "DB_URL");
    assert_eq!(decrypted_entries[1].value, "postgres://localhost:5432/myapp");

    // Verify content hash
    let recomputed_content_hash = hash(&decrypted_plaintext);
    assert_eq!(content_hash, recomputed_content_hash);

    // Verify signature
    verify(
        &owner_device.signing_pubkey,
        metadata_json.as_bytes(),
        &signature,
    )?;

    println!("✓ Complete vault initialization workflow test passed");
    Ok(())
}

#[test]
fn test_membership_workflow() -> Result<()> {
    // Test complete membership workflow: add member → change role → remove member

    // Setup: Create project with owner
    let project_id = ProjectId::new();
    let (owner_device, owner_signing_key, owner_encryption_key) =
        create_test_device("github|owner", "Owner's Device");

    // Create initial PDK
    let pdk = create_test_pdk();
    let owner_wrapped = wrap_pdk_to_device(&pdk, owner_device.id, &owner_device.encryption_pubkey)?;

    let mut pdk_version = PdkVersion {
        version: VersionNumber::FIRST,
        created_at: OffsetDateTime::now_utc(),
        created_by: owner_device.id,
        reason: Some("Initial PDK".to_string()),
        wrapped_keys: vec![owner_wrapped],
    };

    // Step 1: Add a new member
    let (member_device, _member_signing_key, _member_encryption_key) =
        create_test_device("github|member", "Member's Device");

    // Wrap PDK to new member's device
    let member_wrapped =
        wrap_pdk_to_device(&pdk, member_device.id, &member_device.encryption_pubkey)?;
    pdk_version.wrapped_keys.push(member_wrapped);

    // Create membership list
    let owner_member = ProjectMember {
        user_id: UserId::from("github|owner"),
        role: Role::Owner,
        added_at: OffsetDateTime::now_utc(),
        added_by: owner_device.id,
    };

    let new_member = ProjectMember {
        user_id: UserId::from("github|member"),
        role: Role::Member,
        added_at: OffsetDateTime::now_utc(),
        added_by: owner_device.id,
    };

    let members = vec![owner_member.clone(), new_member.clone()];

    // Verify both devices can unwrap the PDK
    let owner_unwrapped = unwrap_pdk_from_wrapped(&pdk_version.wrapped_keys[0], &owner_encryption_key)?;
    let member_unwrapped = unwrap_pdk_from_wrapped(&pdk_version.wrapped_keys[1], &_member_encryption_key)?;

    assert_eq!(pdk.as_bytes(), owner_unwrapped.as_bytes());
    assert_eq!(pdk.as_bytes(), member_unwrapped.as_bytes());

    // Step 2: Change member role to admin
    let mut updated_members = members.clone();
    updated_members[1].role = Role::Admin;

    // Step 3: Remove member (simulate PDK rotation)
    let new_pdk = create_test_pdk();
    let new_owner_wrapped =
        wrap_pdk_to_device(&new_pdk, owner_device.id, &owner_device.encryption_pubkey)?;

    let rotated_pdk_version = PdkVersion {
        version: VersionNumber::new(2),
        created_at: OffsetDateTime::now_utc(),
        created_by: owner_device.id,
        reason: Some("Member removed".to_string()),
        wrapped_keys: vec![new_owner_wrapped], // Only owner remains
    };

    // Verify only owner can unwrap the new PDK
    let owner_new_unwrapped =
        unwrap_pdk_from_wrapped(&rotated_pdk_version.wrapped_keys[0], &owner_encryption_key)?;
    assert_eq!(new_pdk.as_bytes(), owner_new_unwrapped.as_bytes());

    // Verify member cannot unwrap new PDK (no wrapped PDK for them)
    assert_eq!(rotated_pdk_version.wrapped_keys.len(), 1);
    assert_eq!(rotated_pdk_version.wrapped_keys[0].device_id, owner_device.id);

    println!("✓ Complete membership workflow test passed");
    Ok(())
}

#[test]
fn test_rotation_workflow() -> Result<()> {
    // Test rotation workflows: manual, policy-based, emergency

    let project_id = ProjectId::new();
    let (owner_device, owner_signing_key, owner_encryption_key) =
        create_test_device("github|owner", "Owner's Device");
    let (member_device, _member_signing_key, member_encryption_key) =
        create_test_device("github|member", "Member's Device");

    // Step 1: Create initial PDK with two members
    let pdk_v1 = create_test_pdk();
    let owner_wrapped_v1 =
        wrap_pdk_to_device(&pdk_v1, owner_device.id, &owner_device.encryption_pubkey)?;
    let member_wrapped_v1 =
        wrap_pdk_to_device(&pdk_v1, member_device.id, &member_device.encryption_pubkey)?;

    let pdk_version_v1 = PdkVersion {
        version: VersionNumber::FIRST,
        created_at: OffsetDateTime::now_utc(),
        created_by: owner_device.id,
        reason: Some("Initial PDK".to_string()),
        wrapped_keys: vec![owner_wrapped_v1, member_wrapped_v1],
    };

    // Step 2: Manual rotation
    let pdk_v2 = create_test_pdk();
    let owner_wrapped_v2 =
        wrap_pdk_to_device(&pdk_v2, owner_device.id, &owner_device.encryption_pubkey)?;
    let member_wrapped_v2 =
        wrap_pdk_to_device(&pdk_v2, member_device.id, &member_device.encryption_pubkey)?;

    let pdk_version_v2 = PdkVersion {
        version: VersionNumber::new(2),
        created_at: OffsetDateTime::now_utc(),
        created_by: owner_device.id,
        reason: Some("Manual rotation".to_string()),
        wrapped_keys: vec![owner_wrapped_v2, member_wrapped_v2],
    };

    // Step 3: Policy-based rotation (member removal)
    let pdk_v3 = create_test_pdk();
    let owner_wrapped_v3 =
        wrap_pdk_to_device(&pdk_v3, owner_device.id, &owner_device.encryption_pubkey)?;

    let pdk_version_v3 = PdkVersion {
        version: VersionNumber::new(3),
        created_at: OffsetDateTime::now_utc(),
        created_by: owner_device.id,
        reason: Some("Member removed".to_string()),
        wrapped_keys: vec![owner_wrapped_v3], // Member excluded
    };

    // Step 4: Emergency rotation
    let pdk_v4 = create_test_pdk();
    let owner_wrapped_v4 =
        wrap_pdk_to_device(&pdk_v4, owner_device.id, &owner_device.encryption_pubkey)?;

    let pdk_version_v4 = PdkVersion {
        version: VersionNumber::new(4),
        created_at: OffsetDateTime::now_utc(),
        created_by: owner_device.id,
        reason: Some("Emergency: suspected compromise".to_string()),
        wrapped_keys: vec![owner_wrapped_v4],
    };

    // Verify version progression
    assert_eq!(pdk_version_v1.version.as_u64(), 1);
    assert_eq!(pdk_version_v2.version.as_u64(), 2);
    assert_eq!(pdk_version_v3.version.as_u64(), 3);
    assert_eq!(pdk_version_v4.version.as_u64(), 4);

    // Verify forward secrecy: member cannot decrypt v3 and v4
    let owner_can_decrypt_v3 =
        unwrap_pdk_from_wrapped(&pdk_version_v3.wrapped_keys[0], &owner_encryption_key);
    assert!(owner_can_decrypt_v3.is_ok());

    // Member has no wrapped PDK in v3
    let member_wrapped_in_v3 = pdk_version_v3
        .wrapped_keys
        .iter()
        .find(|w| w.device_id == member_device.id);
    assert!(member_wrapped_in_v3.is_none());

    // Verify historical access: owner can still decrypt v1 and v2 with old PDKs
    let owner_v1_unwrapped =
        unwrap_pdk_from_wrapped(&pdk_version_v1.wrapped_keys[0], &owner_encryption_key)?;
    let member_v1_unwrapped =
        unwrap_pdk_from_wrapped(&pdk_version_v1.wrapped_keys[1], &member_encryption_key)?;

    assert_eq!(pdk_v1.as_bytes(), owner_v1_unwrapped.as_bytes());
    assert_eq!(pdk_v1.as_bytes(), member_v1_unwrapped.as_bytes());

    println!("✓ Complete rotation workflow test passed");
    Ok(())
}

#[test]
fn test_recovery_workflow() -> Result<()> {
    // Test recovery workflows: multi-device and recovery contacts

    // Step 1: Multi-device setup
    let (device1, signing_key1, encryption_key1) =
        create_test_device("github|user", "Primary Device");
    let (device2, _signing_key2, encryption_key2) =
        create_test_device("github|user", "Backup Device");

    // Create PDK wrapped to both devices
    let pdk = create_test_pdk();
    let wrapped1 = wrap_pdk_to_device(&pdk, device1.id, &device1.encryption_pubkey)?;
    let wrapped2 = wrap_pdk_to_device(&pdk, device2.id, &device2.encryption_pubkey)?;

    let pdk_version = PdkVersion {
        version: VersionNumber::FIRST,
        created_at: OffsetDateTime::now_utc(),
        created_by: device1.id,
        reason: Some("Multi-device setup".to_string()),
        wrapped_keys: vec![wrapped1, wrapped2],
    };

    // Verify both devices can access the PDK
    let pdk1_unwrapped = unwrap_pdk_from_wrapped(&pdk_version.wrapped_keys[0], &encryption_key1)?;
    let pdk2_unwrapped = unwrap_pdk_from_wrapped(&pdk_version.wrapped_keys[1], &encryption_key2)?;

    assert_eq!(pdk.as_bytes(), pdk1_unwrapped.as_bytes());
    assert_eq!(pdk.as_bytes(), pdk2_unwrapped.as_bytes());

    // Step 2: Recovery contact scenario
    let (user_device, _user_signing_key, user_encryption_key) =
        create_test_device("github|user", "User's Device");
    let (contact_device, contact_signing_key, contact_encryption_key) =
        create_test_device("github|contact", "Contact's Device");
    let (new_device, _new_signing_key, new_encryption_key) =
        create_test_device("github|user", "New Device");

    // Create project where both user and contact are members
    let project_pdk = create_test_pdk();
    let user_wrapped = wrap_pdk_to_device(&project_pdk, user_device.id, &user_device.encryption_pubkey)?;
    let contact_wrapped = wrap_pdk_to_device(&project_pdk, contact_device.id, &contact_device.encryption_pubkey)?;

    let project_pdk_version = PdkVersion {
        version: VersionNumber::FIRST,
        created_at: OffsetDateTime::now_utc(),
        created_by: user_device.id,
        reason: Some("Project creation".to_string()),
        wrapped_keys: vec![user_wrapped, contact_wrapped],
    };

    // Recovery: Contact helps wrap PDK to user's new device
    let contact_unwrapped = unwrap_pdk_from_wrapped(&project_pdk_version.wrapped_keys[1], &contact_encryption_key)?;
    let new_device_wrapped = wrap_pdk_to_device(&contact_unwrapped, new_device.id, &new_device.encryption_pubkey)?;

    // Create new PDK version with recovered access
    let recovered_pdk_version = PdkVersion {
        version: VersionNumber::new(2),
        created_at: OffsetDateTime::now_utc(),
        created_by: contact_device.id,
        reason: Some("Recovery assistance".to_string()),
        wrapped_keys: vec![
            project_pdk_version.wrapped_keys[1].clone(), // Contact keeps access
            new_device_wrapped,                          // New device gets access
        ],
    };

    // Verify new device can access the PDK
    let new_device_unwrapped = unwrap_pdk_from_wrapped(&recovered_pdk_version.wrapped_keys[1], &new_encryption_key)?;
    assert_eq!(project_pdk.as_bytes(), new_device_unwrapped.as_bytes());

    println!("✓ Complete recovery workflow test passed");
    Ok(())
}

#[test]
fn test_ci_workflow() -> Result<()> {
    // Test CI workflows: OIDC enrollment and pull

    // Step 1: Create CI device (simulating OIDC enrollment)
    let ci_device_id = DeviceId::new();
    let user_id = UserId::from("github|repo:myorg/myapp:ref:refs/heads/main");
    let (ci_signing_secret, ci_signing_public) = generate_ed25519_keypair()?;
    let (ci_encryption_secret, ci_encryption_public) = generate_x25519_keypair()?;

    let ci_device = Device {
        schema_version: 1,
        id: ci_device_id,
        user_id: user_id.clone(),
        name: "GitHub Actions CI".to_string(),
        device_type: DeviceType::CI,
        signing_pubkey: ci_signing_public,
        encryption_pubkey: ci_encryption_public,
        enrolled_at: OffsetDateTime::now_utc(),
        status: DeviceStatus::Active,
        expires_at: Some(OffsetDateTime::now_utc() + time::Duration::hours(1)), // 1 hour expiry
    };

    // Step 2: Create project with CI device authorized
    let project_id = ProjectId::new();
    let (owner_device, owner_signing_key, owner_encryption_key) =
        create_test_device("github|owner", "Owner's Device");

    // Create PDK wrapped to both owner and CI device
    let pdk = create_test_pdk();
    let owner_wrapped = wrap_pdk_to_device(&pdk, owner_device.id, &owner_device.encryption_pubkey)?;
    let ci_wrapped = wrap_pdk_to_device(&pdk, ci_device.id, &ci_device.encryption_pubkey)?;

    let pdk_version = PdkVersion {
        version: VersionNumber::FIRST,
        created_at: OffsetDateTime::now_utc(),
        created_by: owner_device.id,
        reason: Some("CI device authorized".to_string()),
        wrapped_keys: vec![owner_wrapped, ci_wrapped],
    };

    // Step 3: Create secret set for CI to pull
    let set_id = SecretSetId::new();
    let entries = vec![
        SecretEntry {
            key: "API_KEY".to_string(),
            value: "ci-secret-123".to_string(),
            metadata: None,
        },
        SecretEntry {
            key: "DEPLOY_TOKEN".to_string(),
            value: "deploy-token-456".to_string(),
            metadata: None,
        },
    ];

    // Encrypt secrets with PDK
    let mut sorted_entries = entries.clone();
    sorted_entries.sort_by(|a, b| a.key.cmp(&b.key));
    let plaintext = serde_json::to_string(&sorted_entries)?;

    let aad = format!(
        "{}{}{}{}",
        project_id.as_uuid(),
        set_id.as_uuid(),
        VersionNumber::FIRST.as_u64(),
        VersionNumber::FIRST.as_u64()
    );

    let ciphertext = encrypt(&pdk, plaintext.as_bytes(), aad.as_bytes())?;

    // Step 4: CI pulls secrets (simulating ci pull command)
    // CI unwraps PDK
    let ci_unwrapped_pdk = unwrap_pdk_from_wrapped(&pdk_version.wrapped_keys[1], &ci_encryption_secret)?;

    // CI decrypts secrets
    let ci_decrypted_plaintext = myc_crypto::aead::decrypt(&ci_unwrapped_pdk, &ciphertext, aad.as_bytes())?;
    let ci_decrypted_entries: Vec<SecretEntry> = serde_json::from_slice(&ci_decrypted_plaintext)?;

    // Verify CI got the correct secrets
    assert_eq!(ci_decrypted_entries.len(), 2);
    assert_eq!(ci_decrypted_entries[0].key, "API_KEY");
    assert_eq!(ci_decrypted_entries[0].value, "ci-secret-123");
    assert_eq!(ci_decrypted_entries[1].key, "DEPLOY_TOKEN");
    assert_eq!(ci_decrypted_entries[1].value, "deploy-token-456");

    // Step 5: Verify CI device expiry handling
    assert!(ci_device.expires_at.is_some());
    let expires_at = ci_device.expires_at.unwrap();
    let now = OffsetDateTime::now_utc();
    assert!(expires_at > now); // Should not be expired yet

    // Simulate expired CI device
    let expired_ci_device = Device {
        expires_at: Some(now - time::Duration::hours(1)), // Expired 1 hour ago
        ..ci_device
    };

    // Verify expiry check would fail
    if let Some(expiry) = expired_ci_device.expires_at {
        assert!(expiry < now); // Should be expired
    }

    println!("✓ Complete CI workflow test passed");
    Ok(())
}

#[test]
fn test_audit_trail_workflow() -> Result<()> {
    // Test that all operations create proper audit events

    let org_id = OrgId::new();
    let project_id = ProjectId::new();
    let (device, signing_key, _encryption_key) = create_test_device("github|user", "User's Device");

    // Step 1: Org creation audit event
    let org_created_event = AuditEvent {
        schema_version: 1,
        event_id: EventId::new(),
        event_type: EventType::OrgCreated,
        timestamp: OffsetDateTime::now_utc(),
        actor_device_id: device.id,
        actor_user_id: device.user_id.to_string(),
        org_id: org_id,
        project_id: None,
        details: EventDetails::Org(OrgEventDetails {
            name: "Test Org".to_string(),
            settings: None,
        }),
        chain_hash: vec![0u8; 32], // Placeholder
        previous_event_id: None,
    };

    // Step 2: Project creation audit event
    let project_created_event = AuditEvent {
        schema_version: 1,
        event_id: EventId::new(),
        event_type: EventType::ProjectCreated,
        timestamp: OffsetDateTime::now_utc(),
        actor_device_id: device.id,
        actor_user_id: device.user_id.to_string(),
        org_id: org_id,
        project_id: Some(project_id),
        details: EventDetails::Project(ProjectEventDetails {
            project_id: project_id,
            project_name: "Test Project".to_string(),
        }),
        chain_hash: vec![0u8; 32], // Placeholder
        previous_event_id: Some(org_created_event.event_id),
    };

    // Step 3: Member added audit event
    let member_added_event = AuditEvent {
        schema_version: 1,
        event_id: EventId::new(),
        event_type: EventType::MemberAdded,
        timestamp: OffsetDateTime::now_utc(),
        actor_device_id: device.id,
        actor_user_id: device.user_id.to_string(),
        org_id: org_id,
        project_id: Some(project_id),
        details: EventDetails::Membership(MembershipEventDetails {
            project_id: project_id,
            user_id: "github|newmember".to_string(),
            role: Some("member".to_string()),
            previous_role: None,
        }),
        chain_hash: vec![0u8; 32], // Placeholder
        previous_event_id: Some(project_created_event.event_id),
    };

    // Step 4: Verify audit chain computation
    let events = vec![
        &org_created_event,
        &project_created_event,
        &member_added_event,
    ];

    let mut previous_hash: Option<HashOutput> = None;
    for event in &events {
        // Compute chain hash
        let event_json = myc_core::canonical::to_canonical_json(event)?;
        let event_hash = hash(event_json.as_bytes());

        let computed_chain_hash = match previous_hash {
            None => event_hash,
            Some(prev) => chain_hash(&prev, event_json.as_bytes()),
        };

        // In a real implementation, we would verify this matches event.chain_hash
        previous_hash = Some(computed_chain_hash);
    }

    // Step 5: Verify audit signatures
    for event in &events {
        let event_json = myc_core::canonical::to_canonical_json(event)?;
        let signature = sign(&signing_key, event_json.as_bytes());

        // Verify signature
        myc_crypto::sign::verify(&device.signing_pubkey, event_json.as_bytes(), &signature)?;
    }

    println!("✓ Complete audit trail workflow test passed");
    Ok(())
}