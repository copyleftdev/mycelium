//! Property-based tests for validation.
//!
//! These tests verify that validation logic correctly rejects invalid inputs:
//! - Invalid names (empty or too long)
//! - Future timestamps

use myc_core::device::{Device, DeviceStatus, DeviceType};
use myc_core::ids::{DeviceId, OrgId, ProjectId, UserId};
use myc_core::org::{Org, OrgSettings};
use myc_core::project::Project;
use myc_core::secret_set::SecretSet;
use myc_crypto::kex::generate_x25519_keypair;
use myc_crypto::sign::generate_ed25519_keypair;
use proptest::prelude::*;
use time::OffsetDateTime;

// ============================================================================
// Property 13: Validation Rejects Invalid Names
// ============================================================================

/// Feature: mycelium-cli, Property 13: Validation Rejects Invalid Names
///
/// For any name that is empty or exceeds 256 characters, validation SHALL reject it.
///
/// **Validates: Requirements 4.5**
#[test]
fn property_validation_rejects_invalid_names() {
    proptest!(|(
        // Generate names that are either empty or too long
        name_type in 0..2usize,
        extra_chars in 1usize..100,
    )| {
        let invalid_name = match name_type {
            0 => String::new(), // Empty name
            _ => "a".repeat(256 + extra_chars), // Name exceeding max length
        };

        // Test Org validation with invalid name
        let mut org = Org::new("Valid Name".to_string(), OrgSettings::default());
        org.name = invalid_name.clone();
        let org_result = org.validate();
        prop_assert!(
            org_result.is_err(),
            "Org validation should reject invalid name: '{}'",
            if invalid_name.is_empty() { "<empty>" } else { "<too long>" }
        );

        // Test Project validation with invalid name
        let org_id = OrgId::new();
        let device_id = DeviceId::new();
        let mut project = Project::new(org_id, "Valid Name".to_string(), device_id);
        project.name = invalid_name.clone();
        let project_result = project.validate();
        prop_assert!(
            project_result.is_err(),
            "Project validation should reject invalid name: '{}'",
            if invalid_name.is_empty() { "<empty>" } else { "<too long>" }
        );

        // Test SecretSet validation with invalid name
        let project_id = ProjectId::new();
        let mut set = SecretSet::new(project_id, "Valid Name".to_string(), device_id);
        set.name = invalid_name.clone();
        let set_result = set.validate();
        prop_assert!(
            set_result.is_err(),
            "SecretSet validation should reject invalid name: '{}'",
            if invalid_name.is_empty() { "<empty>" } else { "<too long>" }
        );

        // Test Device validation with invalid name
        let user_id = UserId::from("github|12345678");
        let (_, signing_pubkey) = generate_ed25519_keypair().unwrap();
        let (_, encryption_pubkey) = generate_x25519_keypair().unwrap();
        let mut device = Device::new(
            user_id,
            "Valid Name".to_string(),
            DeviceType::Interactive,
            signing_pubkey,
            encryption_pubkey,
            DeviceStatus::Active,
            None,
        );
        device.name = invalid_name.clone();
        let device_result = device.validate();
        prop_assert!(
            device_result.is_err(),
            "Device validation should reject invalid name: '{}'",
            if invalid_name.is_empty() { "<empty>" } else { "<too long>" }
        );
    });
}

/// Test that validation accepts valid names (boundary testing)
#[test]
fn property_validation_accepts_valid_names() {
    proptest!(|(
        // Generate valid names: 1 to 256 characters
        name_length in 1usize..=256,
        char_choice in 0..3usize,
    )| {
        // Create names with different character types
        let valid_name = match char_choice {
            0 => "a".repeat(name_length),
            1 => "A".repeat(name_length),
            _ => "0".repeat(name_length),
        };

        // Test Org validation with valid name
        let org = Org::new(valid_name.clone(), OrgSettings::default());
        let org_result = org.validate();
        prop_assert!(
            org_result.is_ok(),
            "Org validation should accept valid name of length {}",
            name_length
        );

        // Test Project validation with valid name
        let org_id = OrgId::new();
        let device_id = DeviceId::new();
        let project = Project::new(org_id, valid_name.clone(), device_id);
        let project_result = project.validate();
        prop_assert!(
            project_result.is_ok(),
            "Project validation should accept valid name of length {}",
            name_length
        );

        // Test SecretSet validation with valid name
        let project_id = ProjectId::new();
        let set = SecretSet::new(project_id, valid_name.clone(), device_id);
        let set_result = set.validate();
        prop_assert!(
            set_result.is_ok(),
            "SecretSet validation should accept valid name of length {}",
            name_length
        );

        // Test Device validation with valid name
        let user_id = UserId::from("github|12345678");
        let (_, signing_pubkey) = generate_ed25519_keypair().unwrap();
        let (_, encryption_pubkey) = generate_x25519_keypair().unwrap();
        let device = Device::new(
            user_id,
            valid_name.clone(),
            DeviceType::Interactive,
            signing_pubkey,
            encryption_pubkey,
            DeviceStatus::Active,
            None,
        );
        let device_result = device.validate();
        prop_assert!(
            device_result.is_ok(),
            "Device validation should accept valid name of length {}",
            name_length
        );
    });
}

// ============================================================================
// Property 14: Validation Rejects Future Timestamps
// ============================================================================

/// Feature: mycelium-cli, Property 14: Validation Rejects Future Timestamps
///
/// For any timestamp in the future, validation SHALL reject it.
///
/// **Validates: Requirements 4.5**
#[test]
fn property_validation_rejects_future_timestamps() {
    proptest!(|(
        // Generate future timestamps: 1 second to 365 days in the future
        seconds_in_future in 1i64..=(365 * 24 * 60 * 60),
    )| {
        let future_timestamp = OffsetDateTime::now_utc() + time::Duration::seconds(seconds_in_future);

        // Test Org validation with future timestamp
        let mut org = Org::new("Test Org".to_string(), OrgSettings::default());
        org.created_at = future_timestamp;
        let org_result = org.validate();
        prop_assert!(
            org_result.is_err(),
            "Org validation should reject future timestamp: {} seconds in future",
            seconds_in_future
        );

        // Test Project validation with future timestamp
        let org_id = OrgId::new();
        let device_id = DeviceId::new();
        let mut project = Project::new(org_id, "Test Project".to_string(), device_id);
        project.created_at = future_timestamp;
        let project_result = project.validate();
        prop_assert!(
            project_result.is_err(),
            "Project validation should reject future timestamp: {} seconds in future",
            seconds_in_future
        );

        // Test SecretSet validation with future timestamp
        let project_id = ProjectId::new();
        let mut set = SecretSet::new(project_id, "Test Set".to_string(), device_id);
        set.created_at = future_timestamp;
        let set_result = set.validate();
        prop_assert!(
            set_result.is_err(),
            "SecretSet validation should reject future timestamp: {} seconds in future",
            seconds_in_future
        );

        // Test Device validation with future timestamp
        let user_id = UserId::from("github|12345678");
        let (_, signing_pubkey) = generate_ed25519_keypair().unwrap();
        let (_, encryption_pubkey) = generate_x25519_keypair().unwrap();
        let mut device = Device::new(
            user_id,
            "Test Device".to_string(),
            DeviceType::Interactive,
            signing_pubkey,
            encryption_pubkey,
            DeviceStatus::Active,
            None,
        );
        device.enrolled_at = future_timestamp;
        let device_result = device.validate();
        prop_assert!(
            device_result.is_err(),
            "Device validation should reject future timestamp: {} seconds in future",
            seconds_in_future
        );
    });
}

/// Test that validation accepts past and present timestamps
#[test]
fn property_validation_accepts_past_timestamps() {
    proptest!(|(
        // Generate past timestamps: 1 second to 365 days in the past
        seconds_in_past in 1i64..=(365 * 24 * 60 * 60),
    )| {
        let past_timestamp = OffsetDateTime::now_utc() - time::Duration::seconds(seconds_in_past);

        // Test Org validation with past timestamp
        let mut org = Org::new("Test Org".to_string(), OrgSettings::default());
        org.created_at = past_timestamp;
        let org_result = org.validate();
        prop_assert!(
            org_result.is_ok(),
            "Org validation should accept past timestamp: {} seconds in past",
            seconds_in_past
        );

        // Test Project validation with past timestamp
        let org_id = OrgId::new();
        let device_id = DeviceId::new();
        let mut project = Project::new(org_id, "Test Project".to_string(), device_id);
        project.created_at = past_timestamp;
        let project_result = project.validate();
        prop_assert!(
            project_result.is_ok(),
            "Project validation should accept past timestamp: {} seconds in past",
            seconds_in_past
        );

        // Test SecretSet validation with past timestamp
        let project_id = ProjectId::new();
        let mut set = SecretSet::new(project_id, "Test Set".to_string(), device_id);
        set.created_at = past_timestamp;
        let set_result = set.validate();
        prop_assert!(
            set_result.is_ok(),
            "SecretSet validation should accept past timestamp: {} seconds in past",
            seconds_in_past
        );

        // Test Device validation with past timestamp
        let user_id = UserId::from("github|12345678");
        let (_, signing_pubkey) = generate_ed25519_keypair().unwrap();
        let (_, encryption_pubkey) = generate_x25519_keypair().unwrap();
        let mut device = Device::new(
            user_id,
            "Test Device".to_string(),
            DeviceType::Interactive,
            signing_pubkey,
            encryption_pubkey,
            DeviceStatus::Active,
            None,
        );
        device.enrolled_at = past_timestamp;
        let device_result = device.validate();
        prop_assert!(
            device_result.is_ok(),
            "Device validation should accept past timestamp: {} seconds in past",
            seconds_in_past
        );
    });
}

/// Test edge case: validation should accept timestamps very close to now
/// (within a small tolerance to account for test execution time)
#[test]
fn property_validation_accepts_current_timestamp() {
    proptest!(|(
        _seed in any::<u32>(),
    )| {
        // Use current timestamp (what the constructors use)
        let org = Org::new("Test Org".to_string(), OrgSettings::default());
        let org_result = org.validate();
        prop_assert!(
            org_result.is_ok(),
            "Org validation should accept current timestamp"
        );

        let org_id = OrgId::new();
        let device_id = DeviceId::new();
        let project = Project::new(org_id, "Test Project".to_string(), device_id);
        let project_result = project.validate();
        prop_assert!(
            project_result.is_ok(),
            "Project validation should accept current timestamp"
        );

        let project_id = ProjectId::new();
        let set = SecretSet::new(project_id, "Test Set".to_string(), device_id);
        let set_result = set.validate();
        prop_assert!(
            set_result.is_ok(),
            "SecretSet validation should accept current timestamp"
        );

        let user_id = UserId::from("github|12345678");
        let (_, signing_pubkey) = generate_ed25519_keypair().unwrap();
        let (_, encryption_pubkey) = generate_x25519_keypair().unwrap();
        let device = Device::new(
            user_id,
            "Test Device".to_string(),
            DeviceType::Interactive,
            signing_pubkey,
            encryption_pubkey,
            DeviceStatus::Active,
            None,
        );
        let device_result = device.validate();
        prop_assert!(
            device_result.is_ok(),
            "Device validation should accept current timestamp"
        );
    });
}

// ============================================================================
// Property 15: Version Number Monotonicity
// ============================================================================

/// Feature: mycelium-cli, Property 15: Version Number Monotonicity
///
/// For any sequence of version creations, version numbers SHALL start at 1 and increment by 1.
///
/// **Validates: Requirements 4.6**
#[test]
fn property_version_number_monotonicity() {
    use myc_core::ids::VersionNumber;

    proptest!(|(
        // Generate a sequence length between 1 and 100
        sequence_length in 1usize..100,
    )| {
        // Start with the first version
        let mut current_version = VersionNumber::FIRST;

        // Verify the first version is 1
        prop_assert_eq!(
            current_version.as_u64(),
            1,
            "First version number should be 1"
        );

        // Generate a sequence of versions by incrementing
        let mut versions = vec![current_version];
        for _ in 1..sequence_length {
            current_version = current_version.increment();
            versions.push(current_version);
        }

        // Verify monotonicity: each version is exactly 1 more than the previous
        for i in 1..versions.len() {
            let prev = versions[i - 1].as_u64();
            let curr = versions[i].as_u64();
            prop_assert_eq!(
                curr,
                prev + 1,
                "Version {} should be exactly 1 more than version {}",
                i,
                i - 1
            );
        }

        // Verify the sequence is strictly increasing
        for i in 1..versions.len() {
            prop_assert!(
                versions[i] > versions[i - 1],
                "Version {} should be greater than version {}",
                i,
                i - 1
            );
        }

        // Verify the final version number equals the sequence length
        prop_assert_eq!(
            versions.last().unwrap().as_u64(),
            sequence_length as u64,
            "Final version number should equal sequence length"
        );

        // Verify no duplicates in the sequence
        use std::collections::HashSet;
        let version_set: HashSet<_> = versions.iter().collect();
        prop_assert_eq!(
            version_set.len(),
            versions.len(),
            "All version numbers in sequence should be unique"
        );
    });
}

/// Test that version numbers maintain ordering properties
#[test]
fn property_version_number_ordering() {
    use myc_core::ids::VersionNumber;

    proptest!(|(
        v1_value in 1u64..1000,
        increment_by in 1u64..100,
    )| {
        let v1 = VersionNumber::new(v1_value);
        let v2 = VersionNumber::new(v1_value + increment_by);

        // Test ordering
        prop_assert!(v1 < v2, "v1 should be less than v2");
        prop_assert!(v2 > v1, "v2 should be greater than v1");
        prop_assert!(v1 <= v2, "v1 should be less than or equal to v2");
        prop_assert!(v2 >= v1, "v2 should be greater than or equal to v1");
        prop_assert_ne!(v1, v2, "v1 should not equal v2");

        // Test that equal versions are equal
        let v1_copy = VersionNumber::new(v1_value);
        prop_assert_eq!(v1, v1_copy, "Equal version numbers should be equal");
        prop_assert!(v1 <= v1_copy, "Equal versions should satisfy <=");
        prop_assert!(v1 >= v1_copy, "Equal versions should satisfy >=");
    });
}

/// Test that increment produces the next sequential version
#[test]
fn property_version_increment_sequential() {
    use myc_core::ids::VersionNumber;

    proptest!(|(
        start_value in 1u64..u64::MAX - 100,
    )| {
        let v = VersionNumber::new(start_value);
        let v_next = v.increment();

        // Verify increment produces exactly the next number
        prop_assert_eq!(
            v_next.as_u64(),
            start_value + 1,
            "Increment should produce exactly the next sequential number"
        );

        // Verify ordering relationship
        prop_assert!(
            v_next > v,
            "Incremented version should be greater than original"
        );

        // Verify multiple increments maintain monotonicity
        let v_next_next = v_next.increment();
        prop_assert_eq!(
            v_next_next.as_u64(),
            start_value + 2,
            "Double increment should produce start + 2"
        );
        prop_assert!(
            v_next_next > v_next,
            "Second increment should be greater than first"
        );
        prop_assert!(
            v_next_next > v,
            "Second increment should be greater than original"
        );
    });
}
