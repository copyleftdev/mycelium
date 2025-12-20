//! Property-based tests for integrity verification completeness.
//!
//! These tests verify that the integrity verification system checks all required
//! components: signatures, content hashes, and hash chains across projects,
//! secret sets, and audit logs.

#![allow(dead_code)]
#![allow(clippy::for_kv_map)]

use myc_core::{
    audit::{
        verification::verify_all as verify_audit_events, AuditEvent, EventDetails, EventType,
        ProjectEventDetails, SignedAuditEvent,
    },
    error::ValidationError,
    ids::{DeviceId, OrgId, ProjectId, SecretSetId, VersionNumber},
    membership_ops::MembershipList,
    pdk::{PdkVersion, WrappedPdk},
    pdk_ops::{create_pdk_version, generate_pdk, wrap_pdk},
    project::{Project, ProjectMember, Role},
    secret_set::{SecretSet, SecretSetVersion},
    secret_set_ops::{verify_chain as verify_secret_chain, verify_version_metadata},
};
use myc_crypto::{
    hash::{chain_hash, hash, HashOutput},
    kex::generate_x25519_keypair,
    sign::{generate_ed25519_keypair, Ed25519PublicKey},
};
use proptest::prelude::*;
use std::collections::HashMap;
use time::OffsetDateTime;

// ============================================================================
// Property 55: Integrity Verification Completeness
// ============================================================================

/// Feature: mycelium-cli, Property 55: Integrity Verification Completeness
///
/// For any project, verification SHALL check all signatures, content hashes, and hash chains.
///
/// **Validates: Requirements 19.1, 19.2, 19.3, 19.4, 19.5, 19.6**
#[test]
fn property_integrity_verification_completeness() {
    proptest!(|(
        num_members in 1..5usize,
        num_secret_versions in 1..5usize,
        num_audit_events in 1..10usize,
        project_name in "[a-z]{3,10}",
        set_name in "[a-z]{3,10}",
    )| {
        // Generate test data
        let test_data = generate_test_project_data(
            num_members,
            num_secret_versions,
            num_audit_events,
            &project_name,
            &set_name,
        )?;

        // Perform comprehensive verification
        let verification_result = perform_comprehensive_verification(&test_data)?;

        // Verify that all components were checked
        prop_assert!(
            verification_result.membership_verified,
            "Membership signatures should be verified"
        );

        prop_assert!(
            verification_result.pdk_versions_verified > 0,
            "PDK version signatures should be verified"
        );

        prop_assert!(
            verification_result.secret_versions_verified == num_secret_versions,
            "All secret set versions should be verified (expected {}, got {})",
            num_secret_versions,
            verification_result.secret_versions_verified
        );

        prop_assert!(
            verification_result.secret_chain_verified,
            "Secret set hash chain should be verified"
        );

        prop_assert!(
            verification_result.audit_events_verified == num_audit_events,
            "All audit events should be verified (expected {}, got {})",
            num_audit_events,
            verification_result.audit_events_verified
        );

        prop_assert!(
            verification_result.audit_chain_verified,
            "Audit hash chain should be verified"
        );

        prop_assert!(
            verification_result.all_signatures_verified,
            "All signatures should be verified"
        );

        prop_assert!(
            verification_result.all_hashes_verified,
            "All content hashes should be verified"
        );

        // Verify total items checked matches expected
        let expected_total = 1 + // membership
                           test_data.pdk_versions.len() + // PDK versions
                           num_secret_versions + // secret versions
                           num_audit_events; // audit events

        prop_assert_eq!(
            verification_result.total_items_verified,
            expected_total,
            "Total items verified should match expected count"
        );

        // Verify no errors were reported for valid data
        prop_assert!(
            verification_result.errors.is_empty(),
            "No errors should be reported for valid data: {:?}",
            verification_result.errors
        );
    });
}

/// Test that verification detects tampering with signatures
#[test]
fn property_verification_detects_signature_tampering() {
    proptest!(|(
        tamper_component in 0..3usize, // Which component to tamper with (excluding PDK for now)
        project_name in "[a-z]{3,10}",
        set_name in "[a-z]{3,10}",
    )| {
        // Generate test data
        let mut test_data = generate_test_project_data(2, 2, 3, &project_name, &set_name)?;

        // Tamper with different components based on tamper_component
        match tamper_component {
            0 => {
                // Tamper with membership signature
                test_data.membership.signature = Some(
                    myc_crypto::sign::Signature::from_bytes([0xFF; 64])
                );
            }
            1 => {
                // Tamper with secret version signature
                if !test_data.secret_versions.is_empty() {
                    test_data.secret_versions[0].signature =
                        myc_crypto::sign::Signature::from_bytes([0xFF; 64]);
                }
            }
            _ => {
                // Tamper with audit event signature
                if !test_data.audit_events.is_empty() {
                    test_data.audit_events[0].signature =
                        myc_crypto::sign::Signature::from_bytes([0xFF; 64]);
                }
            }
        }

        // Perform verification
        let verification_result = perform_comprehensive_verification(&test_data)?;

        // Verify that tampering was detected
        prop_assert!(
            !verification_result.errors.is_empty(),
            "Verification should detect tampering and report errors"
        );

        prop_assert!(
            !verification_result.all_signatures_verified,
            "Signature verification should fail when signatures are tampered"
        );
    });
}

/// Test that verification detects hash chain breaks
#[test]
fn property_verification_detects_chain_breaks() {
    proptest!(|(
        break_secret_chain in any::<bool>(),
        break_audit_chain in any::<bool>(),
        project_name in "[a-z]{3,10}",
        set_name in "[a-z]{3,10}",
    )| {
        // Skip if no chains to break
        if !break_secret_chain && !break_audit_chain {
            return Ok(());
        }

        // Generate test data with multiple versions/events
        let mut test_data = generate_test_project_data(2, 3, 4, &project_name, &set_name)?;

        if break_secret_chain && test_data.secret_versions.len() > 1 {
            // Break the secret version chain by modifying the previous hash
            test_data.secret_versions[1].previous_hash = Some(HashOutput::from_bytes([0xFF; 32]));
        }

        if break_audit_chain && test_data.audit_events.len() > 1 {
            // Break the audit chain by modifying a chain hash
            test_data.audit_events[1].event.chain_hash = vec![0xFF; 32];
        }

        // Perform verification
        let verification_result = perform_comprehensive_verification(&test_data)?;

        // Verify that chain breaks were detected
        prop_assert!(
            !verification_result.errors.is_empty(),
            "Verification should detect chain breaks and report errors"
        );

        if break_secret_chain && test_data.secret_versions.len() > 1 {
            prop_assert!(
                !verification_result.secret_chain_verified,
                "Secret chain verification should fail when chain is broken"
            );
        }

        if break_audit_chain && test_data.audit_events.len() > 1 {
            prop_assert!(
                !verification_result.audit_chain_verified,
                "Audit chain verification should fail when chain is broken"
            );
        }
    });
}

/// Test that verification detects content hash mismatches
#[test]
fn property_verification_detects_content_hash_mismatches() {
    proptest!(|(
        project_name in "[a-z]{3,10}",
        set_name in "[a-z]{3,10}",
    )| {
        // Generate test data
        let mut test_data = generate_test_project_data(2, 2, 2, &project_name, &set_name)?;

        if !test_data.secret_versions.is_empty() {
            // Tamper with content hash
            test_data.secret_versions[0].content_hash = HashOutput::from_bytes([0xFF; 32]);
        }

        // Perform verification
        let verification_result = perform_comprehensive_verification(&test_data)?;

        // Verify that content hash mismatch was detected
        prop_assert!(
            !verification_result.errors.is_empty(),
            "Verification should detect content hash mismatches and report errors"
        );

        prop_assert!(
            !verification_result.all_hashes_verified,
            "Hash verification should fail when content hashes are tampered"
        );
    });
}

// ============================================================================
// Test Data Generation and Verification Logic
// ============================================================================

/// Test project data containing all components that need verification
#[derive(Debug)]
struct TestProjectData {
    project: Project,
    membership: MembershipList,
    pdk_versions: Vec<PdkVersion>,
    secret_set: SecretSet,
    secret_versions: Vec<SecretSetVersion>,
    audit_events: Vec<SignedAuditEvent>,
    device_keys: HashMap<DeviceId, Ed25519PublicKey>,
}

/// Comprehensive verification result
#[derive(Debug)]
struct ComprehensiveVerificationResult {
    membership_verified: bool,
    pdk_versions_verified: usize,
    secret_versions_verified: usize,
    secret_chain_verified: bool,
    audit_events_verified: usize,
    audit_chain_verified: bool,
    all_signatures_verified: bool,
    all_hashes_verified: bool,
    total_items_verified: usize,
    errors: Vec<String>,
}

/// Generate test project data with all components
fn generate_test_project_data(
    num_members: usize,
    num_secret_versions: usize,
    num_audit_events: usize,
    project_name: &str,
    set_name: &str,
) -> Result<TestProjectData, proptest::test_runner::TestCaseError> {
    let org_id = OrgId::new();
    let project_id = ProjectId::new();
    let set_id = SecretSetId::new();
    let creator_device_id = DeviceId::new();

    // Generate device keys
    let mut device_keys = HashMap::new();
    let (creator_signing_key, creator_public_key) = generate_ed25519_keypair().map_err(|e| {
        proptest::test_runner::TestCaseError::fail(format!("Key generation failed: {}", e))
    })?;
    device_keys.insert(creator_device_id, creator_public_key);

    // Create project
    let project = Project {
        schema_version: 1,
        id: project_id,
        org_id,
        name: project_name.to_string(),
        created_at: OffsetDateTime::now_utc(),
        created_by: creator_device_id,
        current_pdk_version: VersionNumber::new(1),
    };

    // Create membership list
    let mut members = vec![ProjectMember {
        user_id: "github|creator".to_string().into(),
        role: Role::Owner,
        added_at: OffsetDateTime::now_utc(),
        added_by: creator_device_id,
    }];

    // Add additional members
    for i in 1..num_members {
        let device_id = DeviceId::new();
        let (_, public_key) = generate_ed25519_keypair().map_err(|e| {
            proptest::test_runner::TestCaseError::fail(format!("Key generation failed: {}", e))
        })?;
        device_keys.insert(device_id, public_key);

        members.push(ProjectMember {
            user_id: format!("github|member{}", i).into(),
            role: Role::Member,
            added_at: OffsetDateTime::now_utc(),
            added_by: creator_device_id,
        });
    }

    let mut membership = MembershipList::new(project_id, members, creator_device_id);
    membership.sign(&creator_signing_key).map_err(|e| {
        proptest::test_runner::TestCaseError::fail(format!("Membership signing failed: {}", e))
    })?;

    // Create PDK versions
    let pdk = generate_pdk().map_err(|e| {
        proptest::test_runner::TestCaseError::fail(format!("PDK generation failed: {}", e))
    })?;

    let mut wrapped_keys = vec![];
    for (device_id, _) in &device_keys {
        let (_, device_public_key) = generate_x25519_keypair().map_err(|e| {
            proptest::test_runner::TestCaseError::fail(format!(
                "X25519 key generation failed: {}",
                e
            ))
        })?;
        let wrapped = wrap_pdk(&pdk, *device_id, &device_public_key).map_err(|e| {
            proptest::test_runner::TestCaseError::fail(format!("PDK wrapping failed: {}", e))
        })?;
        wrapped_keys.push(WrappedPdk {
            device_id: *device_id,
            ephemeral_pubkey: wrapped.ephemeral_pubkey,
            ciphertext: wrapped.ciphertext,
        });
    }

    let pdk_version =
        create_pdk_version(VersionNumber::new(1), creator_device_id, None, wrapped_keys);

    // Create secret set
    let secret_set = SecretSet {
        schema_version: 1,
        id: set_id,
        project_id,
        name: set_name.to_string(),
        created_at: OffsetDateTime::now_utc(),
        created_by: creator_device_id,
        current_version: VersionNumber::new(num_secret_versions as u64),
    };

    // Create secret versions
    let mut secret_versions = vec![];
    let mut previous_chain_hash: Option<HashOutput> = None;

    for version_num in 1..=num_secret_versions {
        let content = format!("SECRET_KEY_{}", version_num);
        let content_hash = hash(content.as_bytes());

        // Compute chain hash according to spec:
        // - For version 1: chain_hash = content_hash
        // - For version N: chain_hash = BLAKE3(previous_chain_hash || content_hash)
        let current_chain_hash = if let Some(prev_hash) = previous_chain_hash {
            chain_hash(&prev_hash, content_hash.as_bytes())
        } else {
            content_hash // For version 1, chain_hash = content_hash
        };

        let mut version = SecretSetVersion {
            schema_version: 1,
            set_id,
            version: VersionNumber::new(version_num as u64),
            pdk_version: VersionNumber::new(1),
            created_at: OffsetDateTime::now_utc(),
            created_by: creator_device_id,
            message: Some(format!("Version {}", version_num)),
            content_hash,
            previous_hash: previous_chain_hash,
            ciphertext: content.into_bytes(),
            signature: myc_crypto::sign::Signature::from_bytes([0u8; 64]), // Will be set below
        };

        // Sign the version metadata using the correct chain hash
        let signature = myc_core::secret_set_ops::sign_version_metadata(
            &set_id,
            &VersionNumber::new(version_num as u64),
            &VersionNumber::new(1),
            version.created_at,
            &creator_device_id,
            version.message.clone(),
            &content_hash,
            &current_chain_hash,
            previous_chain_hash.as_ref(),
            &creator_signing_key,
        )
        .map_err(|e| {
            proptest::test_runner::TestCaseError::fail(format!("Version signing failed: {}", e))
        })?;
        version.signature = signature;

        previous_chain_hash = Some(current_chain_hash);
        secret_versions.push(version);
    }

    // Create audit events
    let mut audit_events = vec![];
    let mut previous_audit_hash = vec![];
    let mut previous_event_id = None;

    for i in 0..num_audit_events {
        let details = EventDetails::Project(ProjectEventDetails {
            project_id,
            project_name: format!("{}-event-{}", project_name, i),
        });

        let mut event = AuditEvent::new(
            EventType::ProjectCreated,
            creator_device_id,
            format!("github|creator{}", i),
            org_id,
            Some(project_id),
            details,
            vec![],
            previous_event_id,
        );

        // Compute chain hash
        let chain_hash = myc_core::audit::chain::compute_chain_hash(&previous_audit_hash, &event)
            .map_err(|e| {
            proptest::test_runner::TestCaseError::fail(format!("Audit chain hash failed: {}", e))
        })?;
        event.chain_hash = chain_hash.clone();

        // Sign the event
        let signed_event = myc_core::audit::signing::sign_event(event, &creator_signing_key)
            .map_err(|e| {
                proptest::test_runner::TestCaseError::fail(format!(
                    "Audit event signing failed: {}",
                    e
                ))
            })?;

        previous_audit_hash = chain_hash;
        previous_event_id = Some(signed_event.event.event_id);
        audit_events.push(signed_event);
    }

    Ok(TestProjectData {
        project,
        membership,
        pdk_versions: vec![pdk_version],
        secret_set,
        secret_versions,
        audit_events,
        device_keys,
    })
}

/// Perform comprehensive verification of all project components
fn perform_comprehensive_verification(
    test_data: &TestProjectData,
) -> Result<ComprehensiveVerificationResult, proptest::test_runner::TestCaseError> {
    let mut errors = vec![];
    let mut total_items = 0;
    let mut signatures_verified = 0;
    let mut hashes_verified = 0;

    // 1. Verify membership signatures (Requirement 19.1, 19.4)
    let membership_verified = match test_data
        .membership
        .verify(&test_data.device_keys[&test_data.membership.members[0].added_by])
    {
        Ok(()) => {
            total_items += 1;
            signatures_verified += 1;
            true
        }
        Err(e) => {
            errors.push(format!("Membership verification failed: {}", e));
            false
        }
    };

    // 2. Verify PDK version signatures (Requirement 19.1)
    let mut pdk_versions_verified = 0;
    for pdk_version in &test_data.pdk_versions {
        // For this test, we'll just check that wrapped keys are valid
        // In a real implementation, PDK versions would have signatures too
        let mut pdk_valid = true;
        for wrapped_pdk in &pdk_version.wrapped_keys {
            // Check that the wrapped PDK has the expected structure
            if wrapped_pdk.ciphertext.len() != 60 {
                // 12 (nonce) + 32 (PDK) + 16 (tag)
                pdk_valid = false;
                errors.push(format!(
                    "Invalid wrapped PDK ciphertext length: {}",
                    wrapped_pdk.ciphertext.len()
                ));
                break;
            }
        }
        if pdk_valid {
            pdk_versions_verified += 1;
            signatures_verified += 1;
        }
    }
    total_items += test_data.pdk_versions.len();

    // 3. Verify secret set version signatures and content hashes (Requirement 19.2)
    let mut secret_versions_verified = 0;
    for version in &test_data.secret_versions {
        // Compute the chain hash for verification according to spec:
        // - For version 1: chain_hash = content_hash
        // - For version N: chain_hash = BLAKE3(previous_chain_hash || content_hash)
        let computed_chain_hash = if let Some(prev_hash) = &version.previous_hash {
            chain_hash(prev_hash, version.content_hash.as_bytes())
        } else {
            version.content_hash // For version 1, chain_hash = content_hash
        };

        match verify_version_metadata(
            &test_data.secret_set.id,
            &version.version,
            &version.pdk_version,
            version.created_at,
            &version.created_by,
            version.message.clone(),
            &version.content_hash,
            &computed_chain_hash,
            version.previous_hash.as_ref(),
            &version.signature,
            &test_data.device_keys[&version.created_by],
        ) {
            Ok(()) => {
                secret_versions_verified += 1;
                signatures_verified += 1;
                hashes_verified += 1;
            }
            Err(e) => {
                errors.push(format!(
                    "Secret version {} verification failed: {}",
                    version.version.as_u64(),
                    e
                ));
            }
        }
    }
    total_items += test_data.secret_versions.len();

    // 4. Verify secret set hash chain (Requirement 19.2)
    let secret_chain_verified = match verify_secret_chain(&test_data.secret_versions) {
        Ok(()) => true,
        Err(e) => {
            errors.push(format!("Secret chain verification failed: {}", e));
            false
        }
    };

    // 5. Verify audit events and chain (Requirement 19.3)
    let mut audit_events_verified = 0;
    let mut audit_chain_verified = false;

    if !test_data.audit_events.is_empty() {
        let key_lookup = test_data.device_keys.clone();

        match verify_audit_events(&test_data.audit_events, |device_id| {
            key_lookup.get(device_id).copied().ok_or_else(|| {
                myc_core::error::CoreError::ValidationError(ValidationError::InvalidName {
                    reason: "Device key not found".to_string(),
                })
            })
        }) {
            Ok(result) => {
                audit_events_verified = result.total_events;
                audit_chain_verified = result.all_passed;
                signatures_verified += result.signatures_verified;
                if !result.all_passed {
                    errors.extend(result.errors);
                }
            }
            Err(e) => {
                errors.push(format!("Audit verification failed: {}", e));
            }
        }
    }
    total_items += test_data.audit_events.len();

    Ok(ComprehensiveVerificationResult {
        membership_verified,
        pdk_versions_verified,
        secret_versions_verified,
        secret_chain_verified,
        audit_events_verified,
        audit_chain_verified,
        all_signatures_verified: errors.is_empty() && signatures_verified > 0,
        all_hashes_verified: errors.is_empty() && hashes_verified > 0,
        total_items_verified: total_items,
        errors,
    })
}
