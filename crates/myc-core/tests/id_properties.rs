//! Property-based tests for identifier types.

use myc_core::ids::{DeviceId, OrgId, ProjectId, SecretSetId};
use proptest::prelude::*;
use std::collections::HashSet;

/// Feature: mycelium-cli, Property 9: UUID Uniqueness
///
/// For any two entity creations, generated UUIDs SHALL be different.
///
/// **Validates: Requirements 4.1**
#[test]
fn property_uuid_uniqueness() {
    proptest!(|(
        // Generate a number of IDs to test
        count in 2usize..100
    )| {
        // Test OrgId uniqueness
        let org_ids: Vec<OrgId> = (0..count).map(|_| OrgId::new()).collect();
        let org_set: HashSet<_> = org_ids.iter().collect();
        prop_assert_eq!(
            org_set.len(),
            org_ids.len(),
            "All generated OrgIds should be unique"
        );

        // Test ProjectId uniqueness
        let project_ids: Vec<ProjectId> = (0..count).map(|_| ProjectId::new()).collect();
        let project_set: HashSet<_> = project_ids.iter().collect();
        prop_assert_eq!(
            project_set.len(),
            project_ids.len(),
            "All generated ProjectIds should be unique"
        );

        // Test SecretSetId uniqueness
        let secret_set_ids: Vec<SecretSetId> = (0..count).map(|_| SecretSetId::new()).collect();
        let secret_set_set: HashSet<_> = secret_set_ids.iter().collect();
        prop_assert_eq!(
            secret_set_set.len(),
            secret_set_ids.len(),
            "All generated SecretSetIds should be unique"
        );

        // Test DeviceId uniqueness
        let device_ids: Vec<DeviceId> = (0..count).map(|_| DeviceId::new()).collect();
        let device_set: HashSet<_> = device_ids.iter().collect();
        prop_assert_eq!(
            device_set.len(),
            device_ids.len(),
            "All generated DeviceIds should be unique"
        );
    });
}

/// Test that IDs generated across different types don't collide
/// (though they use different types, the underlying UUIDs should still be unique)
#[test]
fn property_cross_type_uuid_uniqueness() {
    proptest!(|(
        count in 2usize..50
    )| {
        let org_ids: Vec<OrgId> = (0..count).map(|_| OrgId::new()).collect();
        let project_ids: Vec<ProjectId> = (0..count).map(|_| ProjectId::new()).collect();
        let secret_set_ids: Vec<SecretSetId> = (0..count).map(|_| SecretSetId::new()).collect();
        let device_ids: Vec<DeviceId> = (0..count).map(|_| DeviceId::new()).collect();

        // Collect all UUIDs as strings
        let mut all_uuids = HashSet::new();

        for id in &org_ids {
            all_uuids.insert(id.as_uuid().to_string());
        }
        for id in &project_ids {
            all_uuids.insert(id.as_uuid().to_string());
        }
        for id in &secret_set_ids {
            all_uuids.insert(id.as_uuid().to_string());
        }
        for id in &device_ids {
            all_uuids.insert(id.as_uuid().to_string());
        }

        // All UUIDs across all types should be unique
        prop_assert_eq!(
            all_uuids.len(),
            count * 4,
            "All generated UUIDs across all types should be unique"
        );
    });
}
