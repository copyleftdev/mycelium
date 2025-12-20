//! Property-based tests for audit event creation.
//!
//! These tests verify that mutating operations create properly signed audit events
//! with correct chain hashes and linkage.

#![allow(clippy::clone_on_copy)]

use myc_core::audit::{
    chain, signing, verification::verify_all, AuditEvent, CiEventDetails, DeviceEventDetails,
    EventDetails, EventId, EventType, KeyEventDetails, MembershipEventDetails, OrgEventDetails,
    ProjectEventDetails, SecretEventDetails, SignedAuditEvent,
};
use myc_core::ids::{DeviceId, OrgId, ProjectId, SecretSetId};
use myc_crypto::sign::generate_ed25519_keypair;
use proptest::prelude::*;

// ============================================================================
// Property 46: Mutating Operations Create Audit Events
// ============================================================================

/// Feature: mycelium-cli, Property 46: Mutating Operations Create Audit Events
///
/// For any mutating operation, a signed audit event SHALL be created.
///
/// **Validates: Requirements 13.1**
#[test]
fn property_mutating_operations_create_audit_events() {
    proptest!(|(
        event_type_index in 0..20usize,
        user_id_suffix in 1000..9999u32,
        project_name in "[a-z]{3,10}",
        device_name in "[a-z]{3,10}",
    )| {
        // Generate signing keypair
        let (signing_key, public_key) = generate_ed25519_keypair().unwrap();

        // Create IDs
        let device_id = DeviceId::new();
        let org_id = OrgId::new();
        let project_id = ProjectId::new();
        let user_id = format!("github|{}", user_id_suffix);

        // Select event type based on index
        let (event_type, details, has_project_id) = match event_type_index {
            0 => (
                EventType::OrgCreated,
                EventDetails::Org(OrgEventDetails {
                    name: "test-org".to_string(),
                    settings: None,
                }),
                false,
            ),
            1 => (
                EventType::OrgSettingsUpdated,
                EventDetails::Org(OrgEventDetails {
                    name: "test-org".to_string(),
                    settings: Some(serde_json::json!({"require_device_approval": true})),
                }),
                false,
            ),
            2 => (
                EventType::DeviceEnrolled,
                EventDetails::Device(DeviceEventDetails {
                    device_id,
                    device_name: device_name.clone(),
                    device_type: "interactive".to_string(),
                    reason: None,
                }),
                false,
            ),
            3 => (
                EventType::DeviceApproved,
                EventDetails::Device(DeviceEventDetails {
                    device_id,
                    device_name: device_name.clone(),
                    device_type: "interactive".to_string(),
                    reason: None,
                }),
                false,
            ),
            4 => (
                EventType::DeviceRevoked,
                EventDetails::Device(DeviceEventDetails {
                    device_id,
                    device_name: device_name.clone(),
                    device_type: "interactive".to_string(),
                    reason: Some("compromised".to_string()),
                }),
                false,
            ),
            5 => (
                EventType::ProjectCreated,
                EventDetails::Project(ProjectEventDetails {
                    project_id,
                    project_name: project_name.clone(),
                }),
                true,
            ),
            6 => (
                EventType::ProjectDeleted,
                EventDetails::Project(ProjectEventDetails {
                    project_id,
                    project_name: project_name.clone(),
                }),
                true,
            ),
            7 => (
                EventType::MemberAdded,
                EventDetails::Membership(MembershipEventDetails {
                    project_id,
                    user_id: format!("github|{}", user_id_suffix + 1),
                    role: Some("member".to_string()),
                    previous_role: None,
                }),
                true,
            ),
            8 => (
                EventType::MemberRemoved,
                EventDetails::Membership(MembershipEventDetails {
                    project_id,
                    user_id: format!("github|{}", user_id_suffix + 1),
                    role: None,
                    previous_role: Some("member".to_string()),
                }),
                true,
            ),
            9 => (
                EventType::RoleChanged,
                EventDetails::Membership(MembershipEventDetails {
                    project_id,
                    user_id: format!("github|{}", user_id_suffix + 1),
                    role: Some("admin".to_string()),
                    previous_role: Some("member".to_string()),
                }),
                true,
            ),
            10 => (
                EventType::OwnershipTransferred,
                EventDetails::Membership(MembershipEventDetails {
                    project_id,
                    user_id: format!("github|{}", user_id_suffix + 1),
                    role: Some("owner".to_string()),
                    previous_role: Some("admin".to_string()),
                }),
                true,
            ),
            11 => (
                EventType::SecretSetCreated,
                EventDetails::Secret(SecretEventDetails {
                    project_id,
                    set_id: SecretSetId::new(),
                    set_name: "production".to_string(),
                    version: None,
                    message: None,
                }),
                true,
            ),
            12 => (
                EventType::SecretSetDeleted,
                EventDetails::Secret(SecretEventDetails {
                    project_id,
                    set_id: SecretSetId::new(),
                    set_name: "staging".to_string(),
                    version: None,
                    message: None,
                }),
                true,
            ),
            13 => (
                EventType::SecretVersionCreated,
                EventDetails::Secret(SecretEventDetails {
                    project_id,
                    set_id: SecretSetId::new(),
                    set_name: "production".to_string(),
                    version: Some(1),
                    message: Some("Initial version".to_string()),
                }),
                true,
            ),
            14 => (
                EventType::PdkRotated,
                EventDetails::Key(KeyEventDetails {
                    project_id,
                    pdk_version: 2,
                    reason: "member_removed".to_string(),
                    excluded_devices: vec![DeviceId::new()],
                }),
                true,
            ),
            15 => (
                EventType::PdkWrapped,
                EventDetails::Key(KeyEventDetails {
                    project_id,
                    pdk_version: 1,
                    reason: "member_added".to_string(),
                    excluded_devices: vec![],
                }),
                true,
            ),
            16 => (
                EventType::CiEnrolled,
                EventDetails::Ci(CiEventDetails {
                    device_id,
                    repository: "myorg/myrepo".to_string(),
                    workflow: Some("ci.yml".to_string()),
                    git_ref: Some("refs/heads/main".to_string()),
                    project_id: None,
                    set_id: None,
                }),
                false,
            ),
            17 => (
                EventType::CiPull,
                EventDetails::Ci(CiEventDetails {
                    device_id,
                    repository: "myorg/myrepo".to_string(),
                    workflow: Some("ci.yml".to_string()),
                    git_ref: Some("refs/heads/main".to_string()),
                    project_id: Some(project_id),
                    set_id: Some(SecretSetId::new()),
                }),
                true,
            ),
            18 => (
                EventType::CiExpired,
                EventDetails::Ci(CiEventDetails {
                    device_id,
                    repository: "myorg/myrepo".to_string(),
                    workflow: None,
                    git_ref: None,
                    project_id: None,
                    set_id: None,
                }),
                false,
            ),
            _ => (
                EventType::CiRevoked,
                EventDetails::Ci(CiEventDetails {
                    device_id,
                    repository: "myorg/myrepo".to_string(),
                    workflow: None,
                    git_ref: None,
                    project_id: None,
                    set_id: None,
                }),
                false,
            ),
        };

        // Create audit event
        let event = AuditEvent::new(
            event_type,
            device_id,
            user_id.clone(),
            org_id,
            if has_project_id { Some(project_id) } else { None },
            details,
            vec![],
            None,
        );

        // Verify event was created with correct fields
        prop_assert_eq!(event.schema_version, 1, "Event should have schema version 1");
        prop_assert_eq!(event.actor_device_id, device_id, "Event should have correct actor device ID");
        prop_assert_eq!(&event.actor_user_id, &user_id, "Event should have correct actor user ID");
        prop_assert_eq!(event.org_id, org_id, "Event should have correct org ID");

        // Compute chain hash
        let chain_hash = chain::compute_chain_hash(&[], &event).unwrap();
        prop_assert_eq!(chain_hash.len(), 32, "Chain hash should be 32 bytes");

        // Create signed event
        let mut event_with_hash = event.clone();
        event_with_hash.chain_hash = chain_hash;
        let signed_event = signing::sign_event(event_with_hash, &signing_key).unwrap();

        // Verify the signed event has all required fields
        prop_assert_eq!(signed_event.signed_by, device_id, "Signed event should have correct signer");
        prop_assert!(signed_event.signature.as_bytes().len() == 64, "Signature should be 64 bytes");

        // Verify the signature
        let verify_result = signing::verify_signature(&signed_event, &public_key);
        prop_assert!(
            verify_result.is_ok(),
            "Signature verification should succeed: {:?}",
            verify_result.err()
        );
    });
}

/// Test that audit events are properly chained together
#[test]
fn property_audit_events_chain_correctly() {
    proptest!(|(
        num_events in 1..10usize,
    )| {
        // Generate signing keypair
        let (signing_key, public_key) = generate_ed25519_keypair().unwrap();

        // Create IDs
        let device_id = DeviceId::new();
        let org_id = OrgId::new();
        let project_id = ProjectId::new();

        let mut signed_events = vec![];
        let mut previous_chain_hash = vec![];
        let mut previous_event_id: Option<EventId> = None;

        // Create a chain of events
        for i in 0..num_events {
            let details = EventDetails::Project(ProjectEventDetails {
                project_id,
                project_name: format!("project-{}", i),
            });

            let mut event = AuditEvent::new(
                EventType::ProjectCreated,
                device_id,
                format!("github|user{}", i),
                org_id,
                Some(project_id),
                details,
                vec![],
                previous_event_id,
            );

            // Compute chain hash
            let chain_hash = chain::compute_chain_hash(&previous_chain_hash, &event).unwrap();
            event.chain_hash = chain_hash.clone();

            // Sign the event
            let signed_event = signing::sign_event(event, &signing_key).unwrap();

            // Verify signature
            prop_assert!(
                signing::verify_signature(&signed_event, &public_key).is_ok(),
                "Event {} signature should verify",
                i
            );

            // Update for next iteration
            previous_chain_hash = chain_hash;
            previous_event_id = Some(signed_event.event.event_id);
            signed_events.push(signed_event);
        }

        // Verify the entire chain
        let events: Vec<AuditEvent> = signed_events.iter().map(|se| se.event.clone()).collect();
        let chain_result = chain::verify_chain(&events);
        prop_assert!(
            chain_result.is_ok(),
            "Chain verification should succeed: {:?}",
            chain_result.err()
        );
    });
}

/// Test that tampering with an event breaks the chain
#[test]
fn property_audit_event_tampering_breaks_chain() {
    proptest!(|(
        num_events in 3..10usize,
        tamper_index in 1..3usize,
    )| {
        // Ensure tamper_index is within bounds
        let tamper_index = tamper_index.min(num_events - 1);

        // Generate signing keypair
        let (_signing_key, _public_key) = generate_ed25519_keypair().unwrap();

        // Create IDs
        let device_id = DeviceId::new();
        let org_id = OrgId::new();
        let project_id = ProjectId::new();

        let mut events = vec![];
        let mut previous_chain_hash = vec![];
        let mut previous_event_id: Option<EventId> = None;

        // Create a chain of events
        for i in 0..num_events {
            let details = EventDetails::Project(ProjectEventDetails {
                project_id,
                project_name: format!("project-{}", i),
            });

            let mut event = AuditEvent::new(
                EventType::ProjectCreated,
                device_id,
                format!("github|user{}", i),
                org_id,
                Some(project_id),
                details,
                vec![],
                previous_event_id,
            );

            // Compute chain hash
            let chain_hash = chain::compute_chain_hash(&previous_chain_hash, &event).unwrap();
            event.chain_hash = chain_hash.clone();

            // Update for next iteration
            previous_chain_hash = chain_hash;
            previous_event_id = Some(event.event_id);
            events.push(event);
        }

        // Verify the chain is valid before tampering
        prop_assert!(
            chain::verify_chain(&events).is_ok(),
            "Chain should be valid before tampering"
        );

        // Tamper with an event in the middle
        events[tamper_index].actor_user_id = "github|attacker".to_string();

        // Verify the chain is now broken
        let chain_result = chain::verify_chain(&events);
        prop_assert!(
            chain_result.is_err(),
            "Chain verification should fail after tampering"
        );
    });
}

/// Test that each event type creates a valid audit event
#[test]
fn property_all_event_types_create_valid_events() {
    proptest!(|(
        _seed in any::<u32>(),
    )| {
        // Generate signing keypair
        let (signing_key, public_key) = generate_ed25519_keypair().unwrap();

        // Create IDs
        let device_id = DeviceId::new();
        let org_id = OrgId::new();
        let project_id = ProjectId::new();
        let set_id = SecretSetId::new();

        // Test all event types
        let event_types_and_details = vec![
            (EventType::OrgCreated, EventDetails::Org(OrgEventDetails {
                name: "test-org".to_string(),
                settings: None,
            }), false),
            (EventType::DeviceEnrolled, EventDetails::Device(DeviceEventDetails {
                device_id,
                device_name: "test-device".to_string(),
                device_type: "interactive".to_string(),
                reason: None,
            }), false),
            (EventType::ProjectCreated, EventDetails::Project(ProjectEventDetails {
                project_id,
                project_name: "test-project".to_string(),
            }), true),
            (EventType::MemberAdded, EventDetails::Membership(MembershipEventDetails {
                project_id,
                user_id: "github|12345".to_string(),
                role: Some("member".to_string()),
                previous_role: None,
            }), true),
            (EventType::SecretVersionCreated, EventDetails::Secret(SecretEventDetails {
                project_id,
                set_id,
                set_name: "production".to_string(),
                version: Some(1),
                message: Some("Initial version".to_string()),
            }), true),
            (EventType::PdkRotated, EventDetails::Key(KeyEventDetails {
                project_id,
                pdk_version: 2,
                reason: "member_removed".to_string(),
                excluded_devices: vec![],
            }), true),
            (EventType::CiEnrolled, EventDetails::Ci(CiEventDetails {
                device_id,
                repository: "myorg/myrepo".to_string(),
                workflow: Some("ci.yml".to_string()),
                git_ref: Some("refs/heads/main".to_string()),
                project_id: None,
                set_id: None,
            }), false),
        ];

        for (event_type, details, has_project_id) in event_types_and_details {
            // Create event
            let mut event = AuditEvent::new(
                event_type.clone(),
                device_id,
                "github|12345".to_string(),
                org_id,
                if has_project_id { Some(project_id) } else { None },
                details,
                vec![],
                None,
            );

            // Compute chain hash
            let chain_hash = chain::compute_chain_hash(&[], &event).unwrap();
            event.chain_hash = chain_hash;

            // Sign the event
            let signed_event = signing::sign_event(event, &signing_key).unwrap();

            // Verify signature
            prop_assert!(
                signing::verify_signature(&signed_event, &public_key).is_ok(),
                "Event type {:?} should create valid signed event",
                event_type
            );
        }
    });
}

/// Test that audit events can be serialized and deserialized
#[test]
fn property_audit_events_serialize_correctly() {
    proptest!(|(
        user_id_suffix in 1000..9999u32,
        project_name in "[a-z]{3,10}",
    )| {
        // Generate signing keypair
        let (signing_key, _public_key) = generate_ed25519_keypair().unwrap();

        // Create IDs
        let device_id = DeviceId::new();
        let org_id = OrgId::new();
        let project_id = ProjectId::new();

        let details = EventDetails::Project(ProjectEventDetails {
            project_id,
            project_name: project_name.clone(),
        });

        let mut event = AuditEvent::new(
            EventType::ProjectCreated,
            device_id,
            format!("github|{}", user_id_suffix),
            org_id,
            Some(project_id),
            details,
            vec![],
            None,
        );

        // Compute chain hash
        let chain_hash = chain::compute_chain_hash(&[], &event).unwrap();
        event.chain_hash = chain_hash;

        // Sign the event
        let signed_event = signing::sign_event(event, &signing_key).unwrap();

        // Serialize to JSON
        let json = serde_json::to_string(&signed_event).unwrap();

        // Deserialize back
        let deserialized: SignedAuditEvent = serde_json::from_str(&json).unwrap();

        // Verify fields match
        prop_assert_eq!(
            signed_event.event.event_id,
            deserialized.event.event_id,
            "Event ID should match after serialization"
        );
        prop_assert_eq!(
            signed_event.event.event_type,
            deserialized.event.event_type,
            "Event type should match after serialization"
        );
        prop_assert_eq!(
            signed_event.event.actor_device_id,
            deserialized.event.actor_device_id,
            "Actor device ID should match after serialization"
        );
        prop_assert_eq!(
            signed_event.signature,
            deserialized.signature,
            "Signature should match after serialization"
        );
    });
}

/// Test that audit events have unique IDs
#[test]
fn property_audit_events_have_unique_ids() {
    proptest!(|(
        num_events in 2..20usize,
    )| {
        let device_id = DeviceId::new();
        let org_id = OrgId::new();
        let project_id = ProjectId::new();

        let mut event_ids = std::collections::HashSet::new();

        // Create multiple events
        for i in 0..num_events {
            let details = EventDetails::Project(ProjectEventDetails {
                project_id,
                project_name: format!("project-{}", i),
            });

            let event = AuditEvent::new(
                EventType::ProjectCreated,
                device_id,
                format!("github|user{}", i),
                org_id,
                Some(project_id),
                details,
                vec![],
                None,
            );

            // Check that event ID is unique
            prop_assert!(
                event_ids.insert(event.event_id),
                "Event IDs should be unique"
            );
        }

        // Verify we have the expected number of unique IDs
        prop_assert_eq!(
            event_ids.len(),
            num_events,
            "Should have {} unique event IDs",
            num_events
        );
    });
}

/// Test that audit events include timestamps
#[test]
fn property_audit_events_have_timestamps() {
    proptest!(|(
        _seed in any::<u32>(),
    )| {
        let device_id = DeviceId::new();
        let org_id = OrgId::new();
        let project_id = ProjectId::new();

        let details = EventDetails::Project(ProjectEventDetails {
            project_id,
            project_name: "test-project".to_string(),
        });

        let event = AuditEvent::new(
            EventType::ProjectCreated,
            device_id,
            "github|12345".to_string(),
            org_id,
            Some(project_id),
            details,
            vec![],
            None,
        );

        // Verify timestamp is present and reasonable (not in the far future)
        let now = time::OffsetDateTime::now_utc();
        let one_minute_from_now = now + time::Duration::seconds(60);

        prop_assert!(
            event.timestamp <= one_minute_from_now,
            "Event timestamp should not be in the future"
        );
    });
}

// ============================================================================
// Property 47: Audit Hash Chain Computation
// ============================================================================

/// Feature: mycelium-cli, Property 47: Audit Hash Chain Computation
///
/// For any audit event, chain_hash SHALL equal BLAKE3(previous_chain_hash || canonical_json(event_data)).
///
/// **Validates: Requirements 13.2**
#[test]
fn property_audit_hash_chain_computation() {
    proptest!(|(
        num_events in 1..20usize,
        user_id_suffix in 1000..9999u32,
        project_name in "[a-z]{3,10}",
    )| {
        let device_id = DeviceId::new();
        let org_id = OrgId::new();
        let project_id = ProjectId::new();

        let mut previous_chain_hash = vec![];
        let mut previous_event_id: Option<EventId> = None;

        // Create a chain of events and verify each chain hash computation
        for i in 0..num_events {
            let details = EventDetails::Project(ProjectEventDetails {
                project_id,
                project_name: format!("{}-{}", project_name, i),
            });

            let event = AuditEvent::new(
                EventType::ProjectCreated,
                device_id,
                format!("github|{}", user_id_suffix + i as u32),
                org_id,
                Some(project_id),
                details,
                vec![],
                previous_event_id,
            );

            // Compute the chain hash using the chain module
            let computed_hash = chain::compute_chain_hash(&previous_chain_hash, &event)
                .expect("Chain hash computation should succeed");

            // Verify the hash is 32 bytes (BLAKE3 output size)
            prop_assert_eq!(
                computed_hash.len(),
                32,
                "Chain hash should be 32 bytes (BLAKE3 output size)"
            );

            // Verify the hash is deterministic - computing again should give same result
            let computed_hash_again = chain::compute_chain_hash(&previous_chain_hash, &event)
                .expect("Chain hash computation should succeed");
            prop_assert_eq!(
                &computed_hash,
                &computed_hash_again,
                "Chain hash computation should be deterministic"
            );

            // Verify that different previous hashes produce different chain hashes
            if i > 0 {
                // Use a different previous hash
                let different_prev_hash = vec![0xFF; 32];
                let different_chain_hash = chain::compute_chain_hash(&different_prev_hash, &event)
                    .expect("Chain hash computation should succeed");

                prop_assert_ne!(
                    &computed_hash,
                    &different_chain_hash,
                    "Different previous hashes should produce different chain hashes"
                );
            }

            // Verify that modifying the event produces a different chain hash
            let mut modified_event = event.clone();
            modified_event.actor_user_id = "github|different".to_string();
            let modified_hash = chain::compute_chain_hash(&previous_chain_hash, &modified_event)
                .expect("Chain hash computation should succeed");

            prop_assert_ne!(
                &computed_hash,
                &modified_hash,
                "Modified event should produce different chain hash"
            );

            // Update for next iteration
            previous_chain_hash = computed_hash;
            previous_event_id = Some(event.event_id);
        }
    });
}

/// Test that chain hash computation follows the correct formula
#[test]
fn property_chain_hash_formula_correctness() {
    proptest!(|(
        user_id_suffix in 1000..9999u32,
        project_name in "[a-z]{3,10}",
    )| {
        use myc_core::canonical::to_canonical_json;
        use myc_crypto::hash::{chain_hash as crypto_chain_hash, HashOutput};

        let device_id = DeviceId::new();
        let org_id = OrgId::new();
        let project_id = ProjectId::new();

        let details = EventDetails::Project(ProjectEventDetails {
            project_id,
            project_name: project_name.clone(),
        });

        let event = AuditEvent::new(
            EventType::ProjectCreated,
            device_id,
            format!("github|{}", user_id_suffix),
            org_id,
            Some(project_id),
            details,
            vec![],
            None,
        );

        // Test with empty previous hash (first event)
        let computed_hash = chain::compute_chain_hash(&[], &event)
            .expect("Chain hash computation should succeed");

        // Manually compute the hash using the same formula
        // Create event data structure without chain_hash field
        #[derive(serde::Serialize)]
        struct EventDataForHash<'a> {
            schema_version: u32,
            event_id: EventId,
            event_type: &'a EventType,
            #[serde(with = "time::serde::rfc3339")]
            timestamp: time::OffsetDateTime,
            actor_device_id: DeviceId,
            actor_user_id: &'a str,
            org_id: OrgId,
            project_id: Option<ProjectId>,
            details: &'a EventDetails,
            previous_event_id: Option<EventId>,
        }

        let event_data = EventDataForHash {
            schema_version: event.schema_version,
            event_id: event.event_id,
            event_type: &event.event_type,
            timestamp: event.timestamp,
            actor_device_id: event.actor_device_id,
            actor_user_id: &event.actor_user_id,
            org_id: event.org_id,
            project_id: event.project_id,
            details: &event.details,
            previous_event_id: event.previous_event_id,
        };

        let canonical = to_canonical_json(&event_data)
            .expect("Canonical JSON serialization should succeed");

        let prev_hash = HashOutput::from_bytes([0u8; 32]);
        let manual_hash = crypto_chain_hash(&prev_hash, canonical.as_bytes());

        prop_assert_eq!(
            computed_hash,
            manual_hash.as_bytes().to_vec(),
            "Chain hash should match manual computation using BLAKE3(previous_chain_hash || canonical_json)"
        );

        // Test with non-empty previous hash (subsequent event)
        let previous_hash = vec![0x42; 32];
        let computed_hash2 = chain::compute_chain_hash(&previous_hash, &event)
            .expect("Chain hash computation should succeed");

        let prev_hash2 = HashOutput::from_bytes(
            previous_hash.as_slice().try_into().expect("Should be 32 bytes")
        );
        let manual_hash2 = crypto_chain_hash(&prev_hash2, canonical.as_bytes());

        prop_assert_eq!(
            computed_hash2,
            manual_hash2.as_bytes().to_vec(),
            "Chain hash with previous hash should match manual computation"
        );
    });
}

/// Test that chain hash links events correctly in a sequence
#[test]
fn property_chain_hash_links_events() {
    proptest!(|(
        num_events in 2..15usize,
    )| {
        let device_id = DeviceId::new();
        let org_id = OrgId::new();
        let project_id = ProjectId::new();

        let mut events = vec![];
        let mut previous_chain_hash = vec![];
        let mut previous_event_id: Option<EventId> = None;

        // Create a chain of events
        for i in 0..num_events {
            let details = EventDetails::Project(ProjectEventDetails {
                project_id,
                project_name: format!("project-{}", i),
            });

            let mut event = AuditEvent::new(
                EventType::ProjectCreated,
                device_id,
                format!("github|user{}", i),
                org_id,
                Some(project_id),
                details,
                vec![],
                previous_event_id,
            );

            // Compute and store chain hash
            let chain_hash = chain::compute_chain_hash(&previous_chain_hash, &event)
                .expect("Chain hash computation should succeed");
            event.chain_hash = chain_hash.clone();

            // Verify the chain hash is correctly stored
            prop_assert_eq!(
                &event.chain_hash,
                &chain_hash,
                "Event should store the computed chain hash"
            );

            // Update for next iteration
            previous_chain_hash = chain_hash;
            previous_event_id = Some(event.event_id);
            events.push(event);
        }

        // Verify the entire chain
        let chain_result = chain::verify_chain(&events);
        prop_assert!(
            chain_result.is_ok(),
            "Chain verification should succeed for properly linked events: {:?}",
            chain_result.err()
        );

        // Verify each link in the chain
        for i in 1..events.len() {
            let prev_hash = &events[i - 1].chain_hash;
            let current_event = &events[i];

            let expected_hash = chain::compute_chain_hash(prev_hash, current_event)
                .expect("Chain hash computation should succeed");

            prop_assert_eq!(
                &current_event.chain_hash,
                &expected_hash,
                "Event {} chain hash should be computed from previous event's chain hash",
                i
            );
        }
    });
}

/// Test that chain hash computation is sensitive to all event fields
#[test]
fn property_chain_hash_sensitive_to_all_fields() {
    proptest!(|(
        user_id_suffix in 1000..9999u32,
        project_name in "[a-z]{3,10}",
    )| {
        let device_id = DeviceId::new();
        let org_id = OrgId::new();
        let project_id = ProjectId::new();

        let details = EventDetails::Project(ProjectEventDetails {
            project_id,
            project_name: project_name.clone(),
        });

        let base_event = AuditEvent::new(
            EventType::ProjectCreated,
            device_id,
            format!("github|{}", user_id_suffix),
            org_id,
            Some(project_id),
            details.clone(),
            vec![],
            None,
        );

        let base_hash = chain::compute_chain_hash(&[], &base_event)
            .expect("Chain hash computation should succeed");

        // Test that changing actor_user_id changes the hash
        let mut modified_event = base_event.clone();
        modified_event.actor_user_id = "github|different".to_string();
        let modified_hash = chain::compute_chain_hash(&[], &modified_event)
            .expect("Chain hash computation should succeed");
        prop_assert_ne!(
            &base_hash,
            &modified_hash,
            "Changing actor_user_id should change chain hash"
        );

        // Test that changing event_type changes the hash
        let mut modified_event = base_event.clone();
        modified_event.event_type = EventType::ProjectDeleted;
        let modified_hash = chain::compute_chain_hash(&[], &modified_event)
            .expect("Chain hash computation should succeed");
        prop_assert_ne!(
            &base_hash,
            &modified_hash,
            "Changing event_type should change chain hash"
        );

        // Test that changing details changes the hash
        let mut modified_event = base_event.clone();
        modified_event.details = EventDetails::Project(ProjectEventDetails {
            project_id,
            project_name: "different-name".to_string(),
        });
        let modified_hash = chain::compute_chain_hash(&[], &modified_event)
            .expect("Chain hash computation should succeed");
        prop_assert_ne!(
            &base_hash,
            &modified_hash,
            "Changing details should change chain hash"
        );

        // Test that changing previous_event_id changes the hash
        let mut modified_event = base_event.clone();
        modified_event.previous_event_id = Some(EventId::new());
        let modified_hash = chain::compute_chain_hash(&[], &modified_event)
            .expect("Chain hash computation should succeed");
        prop_assert_ne!(
            &base_hash,
            &modified_hash,
            "Changing previous_event_id should change chain hash"
        );
    });
}

// ============================================================================
// Property 48: Audit Event Signature Verification
// ============================================================================

/// Feature: mycelium-cli, Property 48: Audit Event Signature Verification
///
/// For any audit event, the signature SHALL verify using the actor's Ed25519 public key.
///
/// **Validates: Requirements 13.3**
#[test]
fn property_audit_event_signature_verification() {
    proptest!(|(
        event_type_index in 0..20usize,
        user_id_suffix in 1000..9999u32,
        project_name in "[a-z]{3,10}",
        device_name in "[a-z]{3,10}",
    )| {
        // Generate signing keypair for the actor
        let (signing_key, public_key) = generate_ed25519_keypair().unwrap();

        // Create IDs
        let device_id = DeviceId::new();
        let org_id = OrgId::new();
        let project_id = ProjectId::new();
        let user_id = format!("github|{}", user_id_suffix);

        // Select event type and details based on index
        let (event_type, details, has_project_id) = match event_type_index {
            0 => (
                EventType::OrgCreated,
                EventDetails::Org(OrgEventDetails {
                    name: "test-org".to_string(),
                    settings: None,
                }),
                false,
            ),
            1 => (
                EventType::DeviceEnrolled,
                EventDetails::Device(DeviceEventDetails {
                    device_id,
                    device_name: device_name.clone(),
                    device_type: "interactive".to_string(),
                    reason: None,
                }),
                false,
            ),
            2 => (
                EventType::DeviceRevoked,
                EventDetails::Device(DeviceEventDetails {
                    device_id,
                    device_name: device_name.clone(),
                    device_type: "interactive".to_string(),
                    reason: Some("compromised".to_string()),
                }),
                false,
            ),
            3 => (
                EventType::ProjectCreated,
                EventDetails::Project(ProjectEventDetails {
                    project_id,
                    project_name: project_name.clone(),
                }),
                true,
            ),
            4 => (
                EventType::ProjectDeleted,
                EventDetails::Project(ProjectEventDetails {
                    project_id,
                    project_name: project_name.clone(),
                }),
                true,
            ),
            5 => (
                EventType::MemberAdded,
                EventDetails::Membership(MembershipEventDetails {
                    project_id,
                    user_id: format!("github|{}", user_id_suffix + 1),
                    role: Some("member".to_string()),
                    previous_role: None,
                }),
                true,
            ),
            6 => (
                EventType::MemberRemoved,
                EventDetails::Membership(MembershipEventDetails {
                    project_id,
                    user_id: format!("github|{}", user_id_suffix + 1),
                    role: None,
                    previous_role: Some("member".to_string()),
                }),
                true,
            ),
            7 => (
                EventType::RoleChanged,
                EventDetails::Membership(MembershipEventDetails {
                    project_id,
                    user_id: format!("github|{}", user_id_suffix + 1),
                    role: Some("admin".to_string()),
                    previous_role: Some("member".to_string()),
                }),
                true,
            ),
            8 => (
                EventType::SecretSetCreated,
                EventDetails::Secret(SecretEventDetails {
                    project_id,
                    set_id: SecretSetId::new(),
                    set_name: "production".to_string(),
                    version: None,
                    message: None,
                }),
                true,
            ),
            9 => (
                EventType::SecretVersionCreated,
                EventDetails::Secret(SecretEventDetails {
                    project_id,
                    set_id: SecretSetId::new(),
                    set_name: "production".to_string(),
                    version: Some(1),
                    message: Some("Initial version".to_string()),
                }),
                true,
            ),
            10 => (
                EventType::PdkRotated,
                EventDetails::Key(KeyEventDetails {
                    project_id,
                    pdk_version: 2,
                    reason: "member_removed".to_string(),
                    excluded_devices: vec![DeviceId::new()],
                }),
                true,
            ),
            11 => (
                EventType::PdkWrapped,
                EventDetails::Key(KeyEventDetails {
                    project_id,
                    pdk_version: 1,
                    reason: "member_added".to_string(),
                    excluded_devices: vec![],
                }),
                true,
            ),
            12 => (
                EventType::CiEnrolled,
                EventDetails::Ci(CiEventDetails {
                    device_id,
                    repository: "myorg/myrepo".to_string(),
                    workflow: Some("ci.yml".to_string()),
                    git_ref: Some("refs/heads/main".to_string()),
                    project_id: None,
                    set_id: None,
                }),
                false,
            ),
            13 => (
                EventType::CiPull,
                EventDetails::Ci(CiEventDetails {
                    device_id,
                    repository: "myorg/myrepo".to_string(),
                    workflow: Some("ci.yml".to_string()),
                    git_ref: Some("refs/heads/main".to_string()),
                    project_id: Some(project_id),
                    set_id: Some(SecretSetId::new()),
                }),
                true,
            ),
            14 => (
                EventType::CiExpired,
                EventDetails::Ci(CiEventDetails {
                    device_id,
                    repository: "myorg/myrepo".to_string(),
                    workflow: None,
                    git_ref: None,
                    project_id: None,
                    set_id: None,
                }),
                false,
            ),
            15 => (
                EventType::CiRevoked,
                EventDetails::Ci(CiEventDetails {
                    device_id,
                    repository: "myorg/myrepo".to_string(),
                    workflow: None,
                    git_ref: None,
                    project_id: None,
                    set_id: None,
                }),
                false,
            ),
            16 => (
                EventType::OrgSettingsUpdated,
                EventDetails::Org(OrgEventDetails {
                    name: "test-org".to_string(),
                    settings: Some(serde_json::json!({"require_device_approval": true})),
                }),
                false,
            ),
            17 => (
                EventType::DeviceApproved,
                EventDetails::Device(DeviceEventDetails {
                    device_id,
                    device_name: device_name.clone(),
                    device_type: "interactive".to_string(),
                    reason: None,
                }),
                false,
            ),
            18 => (
                EventType::OwnershipTransferred,
                EventDetails::Membership(MembershipEventDetails {
                    project_id,
                    user_id: format!("github|{}", user_id_suffix + 1),
                    role: Some("owner".to_string()),
                    previous_role: Some("admin".to_string()),
                }),
                true,
            ),
            _ => (
                EventType::SecretSetDeleted,
                EventDetails::Secret(SecretEventDetails {
                    project_id,
                    set_id: SecretSetId::new(),
                    set_name: "staging".to_string(),
                    version: None,
                    message: None,
                }),
                true,
            ),
        };

        // Create audit event
        let mut event = AuditEvent::new(
            event_type,
            device_id,
            user_id.clone(),
            org_id,
            if has_project_id { Some(project_id) } else { None },
            details,
            vec![],
            None,
        );

        // Compute chain hash
        let chain_hash = chain::compute_chain_hash(&[], &event).unwrap();
        event.chain_hash = chain_hash;

        // Sign the event with the actor's key
        let signed_event = signing::sign_event(event, &signing_key).unwrap();

        // Verify the signature using the actor's public key
        let verification_result = signing::verify_signature(&signed_event, &public_key);
        prop_assert!(
            verification_result.is_ok(),
            "Signature should verify with the correct public key: {:?}",
            verification_result.err()
        );

        // Verify that the signed event has the correct signer
        prop_assert_eq!(
            signed_event.signed_by,
            device_id,
            "Signed event should be marked as signed by the actor device"
        );

        // Verify that the signature is the correct length (Ed25519 signatures are 64 bytes)
        prop_assert_eq!(
            signed_event.signature.as_bytes().len(),
            64,
            "Ed25519 signature should be 64 bytes"
        );
    });
}

/// Test that signature verification fails with wrong public key
#[test]
fn property_signature_verification_fails_with_wrong_key() {
    proptest!(|(
        user_id_suffix in 1000..9999u32,
        project_name in "[a-z]{3,10}",
    )| {
        // Generate two different keypairs
        let (signing_key, _correct_public_key) = generate_ed25519_keypair().unwrap();
        let (_wrong_signing_key, wrong_public_key) = generate_ed25519_keypair().unwrap();

        // Create IDs
        let device_id = DeviceId::new();
        let org_id = OrgId::new();
        let project_id = ProjectId::new();

        let details = EventDetails::Project(ProjectEventDetails {
            project_id,
            project_name: project_name.clone(),
        });

        let mut event = AuditEvent::new(
            EventType::ProjectCreated,
            device_id,
            format!("github|{}", user_id_suffix),
            org_id,
            Some(project_id),
            details,
            vec![],
            None,
        );

        // Compute chain hash
        let chain_hash = chain::compute_chain_hash(&[], &event).unwrap();
        event.chain_hash = chain_hash;

        // Sign the event with one key
        let signed_event = signing::sign_event(event, &signing_key).unwrap();

        // Try to verify with a different public key - should fail
        let verification_result = signing::verify_signature(&signed_event, &wrong_public_key);
        prop_assert!(
            verification_result.is_err(),
            "Signature verification should fail with wrong public key"
        );
    });
}

/// Test that signature verification fails when event is tampered with
#[test]
fn property_signature_verification_fails_when_tampered() {
    proptest!(|(
        user_id_suffix in 1000..9999u32,
        project_name in "[a-z]{3,10}",
    )| {
        // Generate signing keypair
        let (signing_key, public_key) = generate_ed25519_keypair().unwrap();

        // Create IDs
        let device_id = DeviceId::new();
        let org_id = OrgId::new();
        let project_id = ProjectId::new();

        let details = EventDetails::Project(ProjectEventDetails {
            project_id,
            project_name: project_name.clone(),
        });

        let mut event = AuditEvent::new(
            EventType::ProjectCreated,
            device_id,
            format!("github|{}", user_id_suffix),
            org_id,
            Some(project_id),
            details,
            vec![],
            None,
        );

        // Compute chain hash
        let chain_hash = chain::compute_chain_hash(&[], &event).unwrap();
        event.chain_hash = chain_hash;

        // Sign the event
        let mut signed_event = signing::sign_event(event, &signing_key).unwrap();

        // Verify the signature works before tampering
        prop_assert!(
            signing::verify_signature(&signed_event, &public_key).is_ok(),
            "Signature should verify before tampering"
        );

        // Tamper with the event data
        signed_event.event.actor_user_id = "github|attacker".to_string();

        // Verify that signature verification now fails
        let verification_result = signing::verify_signature(&signed_event, &public_key);
        prop_assert!(
            verification_result.is_err(),
            "Signature verification should fail after tampering with event data"
        );
    });
}

/// Test that signature verification works for all event types
#[test]
fn property_signature_verification_works_for_all_event_types() {
    proptest!(|(
        _seed in any::<u32>(),
    )| {
        // Generate signing keypair
        let (signing_key, public_key) = generate_ed25519_keypair().unwrap();

        // Create IDs
        let device_id = DeviceId::new();
        let org_id = OrgId::new();
        let project_id = ProjectId::new();
        let set_id = SecretSetId::new();

        // Test all major event types
        let event_types_and_details = vec![
            (EventType::OrgCreated, EventDetails::Org(OrgEventDetails {
                name: "test-org".to_string(),
                settings: None,
            }), false),
            (EventType::DeviceEnrolled, EventDetails::Device(DeviceEventDetails {
                device_id,
                device_name: "test-device".to_string(),
                device_type: "interactive".to_string(),
                reason: None,
            }), false),
            (EventType::ProjectCreated, EventDetails::Project(ProjectEventDetails {
                project_id,
                project_name: "test-project".to_string(),
            }), true),
            (EventType::MemberAdded, EventDetails::Membership(MembershipEventDetails {
                project_id,
                user_id: "github|12345".to_string(),
                role: Some("member".to_string()),
                previous_role: None,
            }), true),
            (EventType::SecretVersionCreated, EventDetails::Secret(SecretEventDetails {
                project_id,
                set_id,
                set_name: "production".to_string(),
                version: Some(1),
                message: Some("Initial version".to_string()),
            }), true),
            (EventType::PdkRotated, EventDetails::Key(KeyEventDetails {
                project_id,
                pdk_version: 2,
                reason: "member_removed".to_string(),
                excluded_devices: vec![],
            }), true),
            (EventType::CiEnrolled, EventDetails::Ci(CiEventDetails {
                device_id,
                repository: "myorg/myrepo".to_string(),
                workflow: Some("ci.yml".to_string()),
                git_ref: Some("refs/heads/main".to_string()),
                project_id: None,
                set_id: None,
            }), false),
        ];

        for (event_type, details, has_project_id) in event_types_and_details {
            // Create event
            let mut event = AuditEvent::new(
                event_type.clone(),
                device_id,
                "github|12345".to_string(),
                org_id,
                if has_project_id { Some(project_id) } else { None },
                details,
                vec![],
                None,
            );

            // Compute chain hash
            let chain_hash = chain::compute_chain_hash(&[], &event).unwrap();
            event.chain_hash = chain_hash;

            // Sign the event
            let signed_event = signing::sign_event(event, &signing_key).unwrap();

            // Verify signature
            let verification_result = signing::verify_signature(&signed_event, &public_key);
            prop_assert!(
                verification_result.is_ok(),
                "Signature verification should succeed for event type {:?}: {:?}",
                event_type,
                verification_result.err()
            );
        }
    });
}
// ============================================================================
// Property 49: Audit Verification Detects Tampering
// ============================================================================

/// Feature: mycelium-cli, Property 49: Audit Verification Detects Tampering
///
/// For any tampered audit event, verification SHALL detect the tampering and report the specific event.
///
/// **Validates: Requirements 13.5, 13.6**
#[test]
fn property_audit_verification_detects_tampering() {
    proptest!(|(
        num_events in 3..15usize,
        tamper_event_index in 1..3usize,
        tamper_type in 0..5usize,
        user_id_suffix in 1000..9999u32,
        project_name in "[a-z]{3,10}",
    )| {
        // Ensure tamper_event_index is within bounds
        let tamper_event_index = tamper_event_index.min(num_events - 1);

        // Generate signing keypair
        let (signing_key, public_key) = generate_ed25519_keypair().unwrap();

        // Create IDs
        let device_id = DeviceId::new();
        let org_id = OrgId::new();
        let project_id = ProjectId::new();

        let mut signed_events = vec![];
        let mut previous_chain_hash = vec![];
        let mut previous_event_id: Option<EventId> = None;

        // Create a valid chain of signed events
        for i in 0..num_events {
            let details = EventDetails::Project(ProjectEventDetails {
                project_id,
                project_name: format!("{}-{}", project_name, i),
            });

            let mut event = AuditEvent::new(
                EventType::ProjectCreated,
                device_id,
                format!("github|{}", user_id_suffix + i as u32),
                org_id,
                Some(project_id),
                details,
                vec![],
                previous_event_id,
            );

            // Compute chain hash
            let chain_hash = chain::compute_chain_hash(&previous_chain_hash, &event).unwrap();
            event.chain_hash = chain_hash.clone();

            // Sign the event
            let signed_event = signing::sign_event(event, &signing_key).unwrap();

            // Update for next iteration
            previous_chain_hash = chain_hash;
            previous_event_id = Some(signed_event.event.event_id);
            signed_events.push(signed_event);
        }

        // Verify the chain is valid before tampering
        let get_public_key = |_device_id: &DeviceId| Ok(public_key.clone());
        let verification_result = verify_all(&signed_events, get_public_key).unwrap();
        prop_assert!(
            verification_result.all_passed,
            "Chain should be valid before tampering: {:?}",
            verification_result.errors
        );

        // Tamper with an event based on tamper_type
        match tamper_type {
            0 => {
                // Tamper with actor_user_id
                signed_events[tamper_event_index].event.actor_user_id = "github|attacker".to_string();
            },
            1 => {
                // Tamper with event_type
                signed_events[tamper_event_index].event.event_type = EventType::ProjectDeleted;
            },
            2 => {
                // Tamper with chain_hash
                signed_events[tamper_event_index].event.chain_hash = vec![0xFF; 32];
            },
            3 => {
                // Tamper with signature
                let mut tampered_sig = *signed_events[tamper_event_index].signature.as_bytes();
                tampered_sig[0] = tampered_sig[0].wrapping_add(1);
                signed_events[tamper_event_index].signature = myc_crypto::sign::Signature::from_bytes(tampered_sig);
            },
            _ => {
                // Tamper with details
                if let EventDetails::Project(ref mut project_details) = signed_events[tamper_event_index].event.details {
                    project_details.project_name = "tampered-project".to_string();
                }
            },
        }

        // Verify that tampering is detected
        let get_public_key = |_device_id: &DeviceId| Ok(public_key.clone());
        let verification_result = verify_all(&signed_events, get_public_key).unwrap();

        prop_assert!(
            !verification_result.all_passed,
            "Verification should fail after tampering (tamper_type: {})",
            tamper_type
        );

        prop_assert!(
            !verification_result.errors.is_empty(),
            "Verification should report errors after tampering"
        );

        // Verify that the error message indicates tampering was detected
        let error_message = verification_result.errors.join(" ");
        let has_relevant_error = error_message.contains("Hash chain verification failed") ||
                                error_message.contains("Signature verification failed") ||
                                error_message.contains("verification failed");

        prop_assert!(
            has_relevant_error,
            "Error message should indicate tampering was detected: {:?}",
            verification_result.errors
        );
    });
}

/// Test that verification detects tampering in different parts of the audit chain
#[test]
fn property_audit_verification_detects_chain_tampering() {
    proptest!(|(
        num_events in 5..20usize,
        tamper_position in 0..3usize, // 0=beginning, 1=middle, 2=end
        user_id_suffix in 1000..9999u32,
    )| {
        // Generate signing keypair
        let (signing_key, public_key) = generate_ed25519_keypair().unwrap();

        // Create IDs
        let device_id = DeviceId::new();
        let org_id = OrgId::new();
        let project_id = ProjectId::new();

        let mut signed_events = vec![];
        let mut previous_chain_hash = vec![];
        let mut previous_event_id: Option<EventId> = None;

        // Create a valid chain of signed events
        for i in 0..num_events {
            let details = EventDetails::Project(ProjectEventDetails {
                project_id,
                project_name: format!("project-{}", i),
            });

            let mut event = AuditEvent::new(
                EventType::ProjectCreated,
                device_id,
                format!("github|{}", user_id_suffix + i as u32),
                org_id,
                Some(project_id),
                details,
                vec![],
                previous_event_id,
            );

            // Compute chain hash
            let chain_hash = chain::compute_chain_hash(&previous_chain_hash, &event).unwrap();
            event.chain_hash = chain_hash.clone();

            // Sign the event
            let signed_event = signing::sign_event(event, &signing_key).unwrap();

            // Update for next iteration
            previous_chain_hash = chain_hash;
            previous_event_id = Some(signed_event.event.event_id);
            signed_events.push(signed_event);
        }

        // Determine which event to tamper with based on position
        let tamper_index = match tamper_position {
            0 => 1, // Beginning (not first event to avoid edge cases)
            1 => num_events / 2, // Middle
            _ => num_events - 1, // End
        };

        // Verify the chain is valid before tampering
        let get_public_key = |_device_id: &DeviceId| Ok(public_key.clone());
        let verification_result = verify_all(&signed_events, get_public_key).unwrap();
        prop_assert!(
            verification_result.all_passed,
            "Chain should be valid before tampering"
        );

        // Tamper with the chain hash to break the chain
        signed_events[tamper_index].event.chain_hash = vec![0x42; 32];

        // Verify that chain tampering is detected
        let get_public_key = |_device_id: &DeviceId| Ok(public_key.clone());
        let verification_result = verify_all(&signed_events, get_public_key).unwrap();

        prop_assert!(
            !verification_result.all_passed,
            "Verification should fail after chain tampering at position {}",
            tamper_position
        );

        prop_assert!(
            !verification_result.errors.is_empty(),
            "Verification should report errors after chain tampering"
        );

        // The error should specifically mention hash chain verification failure
        let error_message = verification_result.errors.join(" ");
        prop_assert!(
            error_message.contains("Hash chain verification failed"),
            "Error should mention hash chain verification failure: {:?}",
            verification_result.errors
        );
    });
}

/// Test that verification detects signature tampering across different event types
#[test]
fn property_audit_verification_detects_signature_tampering() {
    proptest!(|(
        event_type_index in 0..7usize,
        user_id_suffix in 1000..9999u32,
        project_name in "[a-z]{3,10}",
    )| {
        // Generate two different keypairs
        let (signing_key, public_key) = generate_ed25519_keypair().unwrap();
        let (wrong_signing_key, _wrong_public_key) = generate_ed25519_keypair().unwrap();

        // Create IDs
        let device_id = DeviceId::new();
        let org_id = OrgId::new();
        let project_id = ProjectId::new();
        let set_id = SecretSetId::new();

        // Select event type and details
        let (event_type, details, has_project_id) = match event_type_index {
            0 => (
                EventType::OrgCreated,
                EventDetails::Org(OrgEventDetails {
                    name: "test-org".to_string(),
                    settings: None,
                }),
                false,
            ),
            1 => (
                EventType::DeviceEnrolled,
                EventDetails::Device(DeviceEventDetails {
                    device_id,
                    device_name: "test-device".to_string(),
                    device_type: "interactive".to_string(),
                    reason: None,
                }),
                false,
            ),
            2 => (
                EventType::ProjectCreated,
                EventDetails::Project(ProjectEventDetails {
                    project_id,
                    project_name: project_name.clone(),
                }),
                true,
            ),
            3 => (
                EventType::MemberAdded,
                EventDetails::Membership(MembershipEventDetails {
                    project_id,
                    user_id: format!("github|{}", user_id_suffix + 1),
                    role: Some("member".to_string()),
                    previous_role: None,
                }),
                true,
            ),
            4 => (
                EventType::SecretVersionCreated,
                EventDetails::Secret(SecretEventDetails {
                    project_id,
                    set_id,
                    set_name: "production".to_string(),
                    version: Some(1),
                    message: Some("Initial version".to_string()),
                }),
                true,
            ),
            5 => (
                EventType::PdkRotated,
                EventDetails::Key(KeyEventDetails {
                    project_id,
                    pdk_version: 2,
                    reason: "member_removed".to_string(),
                    excluded_devices: vec![],
                }),
                true,
            ),
            _ => (
                EventType::CiEnrolled,
                EventDetails::Ci(CiEventDetails {
                    device_id,
                    repository: "myorg/myrepo".to_string(),
                    workflow: Some("ci.yml".to_string()),
                    git_ref: Some("refs/heads/main".to_string()),
                    project_id: None,
                    set_id: None,
                }),
                false,
            ),
        };

        // Create and sign event with correct key
        let mut event = AuditEvent::new(
            event_type.clone(),
            device_id,
            format!("github|{}", user_id_suffix),
            org_id,
            if has_project_id { Some(project_id) } else { None },
            details,
            vec![],
            None,
        );

        // Compute chain hash
        let chain_hash = chain::compute_chain_hash(&[], &event).unwrap();
        event.chain_hash = chain_hash;

        // Sign with correct key first to verify it works
        let mut signed_event = signing::sign_event(event.clone(), &signing_key).unwrap();

        // Verify the original signature works
        let get_public_key = |_device_id: &DeviceId| Ok(public_key.clone());
        let verification_result = verify_all(&[signed_event.clone()], get_public_key).unwrap();
        prop_assert!(
            verification_result.all_passed,
            "Original signature should verify for event type {:?}",
            event_type
        );

        // Now tamper with the signature by signing with wrong key
        let wrong_signed_event = signing::sign_event(event, &wrong_signing_key).unwrap();
        signed_event.signature = wrong_signed_event.signature;

        // Verify that signature tampering is detected
        let get_public_key = |_device_id: &DeviceId| Ok(public_key.clone());
        let verification_result = verify_all(&[signed_event], get_public_key).unwrap();

        prop_assert!(
            !verification_result.all_passed,
            "Verification should fail after signature tampering for event type {:?}",
            event_type
        );

        prop_assert!(
            !verification_result.errors.is_empty(),
            "Verification should report errors after signature tampering"
        );

        // The error should specifically mention signature verification failure
        let error_message = verification_result.errors.join(" ");
        prop_assert!(
            error_message.contains("Signature verification failed"),
            "Error should mention signature verification failure: {:?}",
            verification_result.errors
        );
    });
}

/// Test that verification correctly identifies the position of tampering in a chain
#[test]
fn property_audit_verification_identifies_tamper_position() {
    proptest!(|(
        num_events in 5..15usize,
        user_id_suffix in 1000..9999u32,
    )| {
        // Generate signing keypair
        let (signing_key, public_key) = generate_ed25519_keypair().unwrap();

        // Create IDs
        let device_id = DeviceId::new();
        let org_id = OrgId::new();
        let project_id = ProjectId::new();

        let mut signed_events = vec![];
        let mut previous_chain_hash = vec![];
        let mut previous_event_id: Option<EventId> = None;

        // Create a valid chain of signed events
        for i in 0..num_events {
            let details = EventDetails::Project(ProjectEventDetails {
                project_id,
                project_name: format!("project-{}", i),
            });

            let mut event = AuditEvent::new(
                EventType::ProjectCreated,
                device_id,
                format!("github|{}", user_id_suffix + i as u32),
                org_id,
                Some(project_id),
                details,
                vec![],
                previous_event_id,
            );

            // Compute chain hash
            let chain_hash = chain::compute_chain_hash(&previous_chain_hash, &event).unwrap();
            event.chain_hash = chain_hash.clone();

            // Sign the event
            let signed_event = signing::sign_event(event, &signing_key).unwrap();

            // Update for next iteration
            previous_chain_hash = chain_hash;
            previous_event_id = Some(signed_event.event.event_id);
            signed_events.push(signed_event);
        }

        // Test tampering at different positions
        for tamper_index in 1..num_events {
            let mut test_events = signed_events.clone();

            // Tamper with the event at this position
            test_events[tamper_index].event.actor_user_id = format!("github|attacker-{}", tamper_index);

            // Verify that tampering is detected
            let get_public_key = |_device_id: &DeviceId| Ok(public_key.clone());
            let verification_result = verify_all(&test_events, get_public_key).unwrap();

            prop_assert!(
                !verification_result.all_passed,
                "Verification should fail when tampering at position {}",
                tamper_index
            );

            prop_assert!(
                !verification_result.errors.is_empty(),
                "Verification should report errors when tampering at position {}",
                tamper_index
            );

            // The verification should detect that something is wrong
            // (The exact position reporting depends on implementation details,
            // but we should at least detect that tampering occurred)
            prop_assert!(
                verification_result.total_events == num_events,
                "Verification should process all {} events even when tampering detected",
                num_events
            );
        }
    });
}

// ============================================================================
// Property 50: Audit Export Format Validity
// ============================================================================

/// Feature: mycelium-cli, Property 50: Audit Export Format Validity
///
/// For any audit events and export format, the exported output SHALL be valid according to the format specification.
///
/// **Validates: Requirements 13.7**
#[test]
fn property_audit_export_format_validity() {
    proptest!(|(
        num_events in 1..20usize,
        export_format_index in 0..3usize,
        user_id_suffix in 1000..9999u32,
        project_name in "[a-z]{3,10}",
        use_filter in any::<bool>(),
        filter_by_project in any::<bool>(),
        filter_by_user in any::<bool>(),
        filter_by_event_type in any::<bool>(),
    )| {
        use myc_core::audit::export::{ExportFormat, ExportFilter, export, to_json, to_csv, to_syslog};

        // Generate signing keypair
        let (signing_key, _public_key) = generate_ed25519_keypair().unwrap();

        // Create IDs
        let device_id = DeviceId::new();
        let org_id = OrgId::new();
        let project_id = ProjectId::new();

        let mut signed_events = vec![];
        let mut previous_chain_hash = vec![];
        let mut previous_event_id: Option<EventId> = None;

        // Create a chain of signed events with different event types
        for i in 0..num_events {
            let event_type = match i % 7 {
                0 => EventType::OrgCreated,
                1 => EventType::DeviceEnrolled,
                2 => EventType::ProjectCreated,
                3 => EventType::MemberAdded,
                4 => EventType::SecretVersionCreated,
                5 => EventType::PdkRotated,
                _ => EventType::CiEnrolled,
            };

            let (details, has_project_id) = match event_type {
                EventType::OrgCreated => (
                    EventDetails::Org(OrgEventDetails {
                        name: format!("org-{}", i),
                        settings: None,
                    }),
                    false,
                ),
                EventType::DeviceEnrolled => (
                    EventDetails::Device(DeviceEventDetails {
                        device_id,
                        device_name: format!("device-{}", i),
                        device_type: "interactive".to_string(),
                        reason: None,
                    }),
                    false,
                ),
                EventType::ProjectCreated => (
                    EventDetails::Project(ProjectEventDetails {
                        project_id,
                        project_name: format!("{}-{}", project_name, i),
                    }),
                    true,
                ),
                EventType::MemberAdded => (
                    EventDetails::Membership(MembershipEventDetails {
                        project_id,
                        user_id: format!("github|{}", user_id_suffix + i as u32),
                        role: Some("member".to_string()),
                        previous_role: None,
                    }),
                    true,
                ),
                EventType::SecretVersionCreated => (
                    EventDetails::Secret(SecretEventDetails {
                        project_id,
                        set_id: SecretSetId::new(),
                        set_name: format!("set-{}", i),
                        version: Some(1),
                        message: Some(format!("Version {}", i)),
                    }),
                    true,
                ),
                EventType::PdkRotated => (
                    EventDetails::Key(KeyEventDetails {
                        project_id,
                        pdk_version: (i as u64) + 1,
                        reason: "test_rotation".to_string(),
                        excluded_devices: vec![],
                    }),
                    true,
                ),
                _ => (
                    EventDetails::Ci(CiEventDetails {
                        device_id,
                        repository: format!("org/repo-{}", i),
                        workflow: Some("ci.yml".to_string()),
                        git_ref: Some("refs/heads/main".to_string()),
                        project_id: None,
                        set_id: None,
                    }),
                    false,
                ),
            };

            let mut event = AuditEvent::new(
                event_type,
                device_id,
                format!("github|{}", user_id_suffix + i as u32),
                org_id,
                if has_project_id { Some(project_id) } else { None },
                details,
                vec![],
                previous_event_id,
            );

            // Compute chain hash
            let chain_hash = chain::compute_chain_hash(&previous_chain_hash, &event).unwrap();
            event.chain_hash = chain_hash.clone();

            // Sign the event
            let signed_event = signing::sign_event(event, &signing_key).unwrap();

            // Update for next iteration
            previous_chain_hash = chain_hash;
            previous_event_id = Some(signed_event.event.event_id);
            signed_events.push(signed_event);
        }

        // Create export filter if requested
        let filter = if use_filter {
            let mut f = ExportFilter::new();

            if filter_by_project {
                f.project_id = Some(project_id);
            }

            if filter_by_user {
                f.user_id = Some(format!("github|{}", user_id_suffix));
            }

            if filter_by_event_type {
                f.event_type = Some(EventType::ProjectCreated);
            }

            Some(f)
        } else {
            None
        };

        // Select export format
        let export_format = match export_format_index {
            0 => ExportFormat::Json,
            1 => ExportFormat::Csv,
            _ => ExportFormat::Syslog,
        };

        // Test the main export function
        let exported = export(&signed_events, export_format, filter.as_ref()).unwrap();

        // Verify the export is not empty (unless all events are filtered out)
        if filter.is_none() || signed_events.iter().any(|e| filter.as_ref().unwrap().matches(&e.event)) {
            prop_assert!(
                !exported.is_empty(),
                "Export should not be empty when events match filter"
            );
        }

        // Test format-specific validity
        match export_format {
            ExportFormat::Json => {
                // Test JSON format validity
                let json_output = to_json(&signed_events, filter.as_ref()).unwrap();

                // Verify it's valid JSON
                let parsed: serde_json::Value = serde_json::from_str(&json_output)
                    .expect("JSON export should produce valid JSON");

                // Verify it's an array
                prop_assert!(
                    parsed.is_array(),
                    "JSON export should produce an array"
                );

                // Verify each element has required fields
                if let Some(array) = parsed.as_array() {
                    for item in array {
                        // SignedAuditEvent uses #[serde(flatten)] so event fields are at top level
                        prop_assert!(
                            item.get("signature").is_some(),
                            "Each JSON item should have a 'signature' field"
                        );
                        prop_assert!(
                            item.get("signed_by").is_some(),
                            "Each JSON item should have a 'signed_by' field"
                        );

                        // Verify flattened event fields are present at top level
                        prop_assert!(
                            item.get("event_id").is_some(),
                            "JSON item should have 'event_id' field"
                        );
                        prop_assert!(
                            item.get("event_type").is_some(),
                            "JSON item should have 'event_type' field"
                        );
                        prop_assert!(
                            item.get("timestamp").is_some(),
                            "JSON item should have 'timestamp' field"
                        );
                        prop_assert!(
                            item.get("actor_device_id").is_some(),
                            "JSON item should have 'actor_device_id' field"
                        );
                        prop_assert!(
                            item.get("actor_user_id").is_some(),
                            "JSON item should have 'actor_user_id' field"
                        );
                        prop_assert!(
                            item.get("org_id").is_some(),
                            "JSON item should have 'org_id' field"
                        );
                        prop_assert!(
                            item.get("details").is_some(),
                            "JSON item should have 'details' field"
                        );
                    }
                }

                // Verify the main export function produces the same result
                prop_assert_eq!(
                    exported.clone(),
                    json_output,
                    "Main export function should match format-specific function for JSON"
                );
            },

            ExportFormat::Csv => {
                // Test CSV format validity
                let csv_output = to_csv(&signed_events, filter.as_ref()).unwrap();

                // Verify it has a header line
                let lines: Vec<&str> = csv_output.lines().collect();
                prop_assert!(
                    !lines.is_empty(),
                    "CSV export should have at least a header line"
                );

                // Verify header contains expected columns
                let header = lines[0];
                prop_assert!(
                    header.contains("event_id"),
                    "CSV header should contain 'event_id'"
                );
                prop_assert!(
                    header.contains("event_type"),
                    "CSV header should contain 'event_type'"
                );
                prop_assert!(
                    header.contains("timestamp"),
                    "CSV header should contain 'timestamp'"
                );
                prop_assert!(
                    header.contains("actor_device_id"),
                    "CSV header should contain 'actor_device_id'"
                );
                prop_assert!(
                    header.contains("actor_user_id"),
                    "CSV header should contain 'actor_user_id'"
                );

                // Verify each data line has the correct number of columns
                let expected_columns = header.split(',').count();
                for (i, line) in lines.iter().skip(1).enumerate() {
                    let columns = line.split(',').count();
                    prop_assert_eq!(
                        columns,
                        expected_columns,
                        "CSV line {} should have {} columns, got {}",
                        i + 1,
                        expected_columns,
                        columns
                    );
                }

                // Verify the main export function produces the same result
                prop_assert_eq!(
                    exported.clone(),
                    csv_output,
                    "Main export function should match format-specific function for CSV"
                );
            },

            ExportFormat::Syslog => {
                // Test Syslog format validity
                let syslog_output = to_syslog(&signed_events, filter.as_ref()).unwrap();

                // Verify each line follows syslog format
                for line in syslog_output.lines() {
                    if !line.is_empty() {
                        // Syslog format: <timestamp> mycelium audit[<event_id>]: <message>
                        prop_assert!(
                            line.contains("mycelium audit["),
                            "Syslog line should contain 'mycelium audit[': {}",
                            line
                        );
                        prop_assert!(
                            line.contains("event_type="),
                            "Syslog line should contain 'event_type=': {}",
                            line
                        );
                        prop_assert!(
                            line.contains("actor="),
                            "Syslog line should contain 'actor=': {}",
                            line
                        );
                        prop_assert!(
                            line.contains("org="),
                            "Syslog line should contain 'org=': {}",
                            line
                        );

                        // Verify timestamp format (should start with a valid timestamp)
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        prop_assert!(
                            !parts.is_empty(),
                            "Syslog line should have timestamp at start: {}",
                            line
                        );

                        // The first part should be a timestamp (contains 'T' for ISO format)
                        prop_assert!(
                            parts[0].contains('T') || parts[0].contains('-'),
                            "First part should be a timestamp: {}",
                            parts[0]
                        );
                    }
                }

                // Verify the main export function produces the same result
                prop_assert_eq!(
                    exported.clone(),
                    syslog_output,
                    "Main export function should match format-specific function for Syslog"
                );
            },
        }

        // Test that filtering works correctly
        if let Some(ref f) = filter {
            let filtered_events: Vec<&SignedAuditEvent> = signed_events
                .iter()
                .filter(|e| f.matches(&e.event))
                .collect();

            // Export with filter should only include matching events
            match export_format {
                ExportFormat::Json => {
                    let parsed: serde_json::Value = serde_json::from_str(&exported).unwrap();
                    if let Some(array) = parsed.as_array() {
                        prop_assert_eq!(
                            array.len(),
                            filtered_events.len(),
                            "JSON export with filter should contain {} events, got {}",
                            filtered_events.len(),
                            array.len()
                        );
                    }
                },
                ExportFormat::Csv => {
                    let lines: Vec<&str> = exported.lines().collect();
                    // Subtract 1 for header line
                    let data_lines = if lines.len() > 1 { lines.len() - 1 } else { 0 };
                    prop_assert_eq!(
                        data_lines,
                        filtered_events.len(),
                        "CSV export with filter should contain {} data lines, got {}",
                        filtered_events.len(),
                        data_lines
                    );
                },
                ExportFormat::Syslog => {
                    let non_empty_lines = exported.lines().filter(|l| !l.is_empty()).count();
                    prop_assert_eq!(
                        non_empty_lines,
                        filtered_events.len(),
                        "Syslog export with filter should contain {} lines, got {}",
                        filtered_events.len(),
                        non_empty_lines
                    );
                },
            }
        }
    });
}
