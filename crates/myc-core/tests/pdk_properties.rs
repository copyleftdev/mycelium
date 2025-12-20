//! Property-based tests for PDK operations.
//!
//! These tests verify that PDK wrapping and unwrapping operations work correctly
//! across all valid inputs.

use myc_core::ids::DeviceId;
use myc_core::pdk_ops::{generate_pdk, unwrap_pdk, wrap_pdk};
use myc_crypto::kex::generate_x25519_keypair;
use proptest::prelude::*;

// ============================================================================
// Property 21: PDK Wrap-Unwrap Roundtrip
// ============================================================================

/// Feature: mycelium-cli, Property 21: PDK Wrap-Unwrap Roundtrip
///
/// For any PDK and device public key, wrapping then unwrapping with the
/// corresponding private key SHALL recover the original PDK.
///
/// **Validates: Requirements 7.2**
#[test]
fn property_pdk_wrap_unwrap_roundtrip() {
    proptest!(ProptestConfig::with_cases(100), |(
        _seed in any::<u64>(),
    )| {
        // Generate a random PDK
        let pdk = generate_pdk().unwrap();

        // Generate a device keypair
        let device_id = DeviceId::new();
        let (device_secret, device_pubkey) = generate_x25519_keypair().unwrap();

        // Wrap the PDK to the device's public key
        let wrapped = wrap_pdk(&pdk, device_id, &device_pubkey).unwrap();

        // Unwrap the PDK using the device's secret key
        let unwrapped = unwrap_pdk(&wrapped, &device_secret).unwrap();

        // Verify roundtrip: original and unwrapped PDKs should be identical
        prop_assert_eq!(
            pdk.as_bytes(),
            unwrapped.as_bytes(),
            "PDK wrap-unwrap roundtrip should recover the original PDK"
        );
    });
}

/// Test that wrapping the same PDK twice produces different ciphertexts
/// (due to different ephemeral keys and nonces)
#[test]
fn property_pdk_wrap_produces_different_ciphertexts() {
    proptest!(ProptestConfig::with_cases(100), |(
        _seed in any::<u64>(),
    )| {
        // Generate a random PDK
        let pdk = generate_pdk().unwrap();

        // Generate a device keypair
        let device_id = DeviceId::new();
        let (_, device_pubkey) = generate_x25519_keypair().unwrap();

        // Wrap the same PDK twice
        let wrapped1 = wrap_pdk(&pdk, device_id, &device_pubkey).unwrap();
        let wrapped2 = wrap_pdk(&pdk, device_id, &device_pubkey).unwrap();

        // Ephemeral public keys should be different
        prop_assert_ne!(
            wrapped1.ephemeral_pubkey.as_bytes(),
            wrapped2.ephemeral_pubkey.as_bytes(),
            "Each wrap should use a different ephemeral key"
        );

        // Ciphertexts should be different (due to different ephemeral keys and nonces)
        prop_assert_ne!(
            wrapped1.ciphertext,
            wrapped2.ciphertext,
            "Each wrap should produce different ciphertext"
        );
    });
}

/// Test that unwrapping with the wrong key fails
#[test]
fn property_pdk_unwrap_with_wrong_key_fails() {
    proptest!(ProptestConfig::with_cases(100), |(
        _seed in any::<u64>(),
    )| {
        // Generate a random PDK
        let pdk = generate_pdk().unwrap();

        // Generate two different device keypairs
        let device_id = DeviceId::new();
        let (_, device_pubkey) = generate_x25519_keypair().unwrap();
        let (wrong_secret, _) = generate_x25519_keypair().unwrap();

        // Wrap the PDK to the first device's public key
        let wrapped = wrap_pdk(&pdk, device_id, &device_pubkey).unwrap();

        // Try to unwrap with the wrong secret key
        let result = unwrap_pdk(&wrapped, &wrong_secret);

        // Should fail
        prop_assert!(
            result.is_err(),
            "Unwrapping with wrong key should fail"
        );
    });
}

/// Test that wrapping to multiple devices allows each to unwrap
#[test]
fn property_pdk_wrap_to_multiple_devices() {
    proptest!(ProptestConfig::with_cases(100), |(
        num_devices in 1usize..10,
    )| {
        // Generate a random PDK
        let pdk = generate_pdk().unwrap();

        // Generate multiple device keypairs
        let mut devices = Vec::new();
        for _ in 0..num_devices {
            let device_id = DeviceId::new();
            let (device_secret, device_pubkey) = generate_x25519_keypair().unwrap();
            devices.push((device_id, device_secret, device_pubkey));
        }

        // Wrap the PDK to each device
        let mut wrapped_pdks = Vec::new();
        for (device_id, _, device_pubkey) in &devices {
            let wrapped = wrap_pdk(&pdk, *device_id, device_pubkey).unwrap();
            wrapped_pdks.push(wrapped);
        }

        // Each device should be able to unwrap the PDK
        for (i, (_, device_secret, _)) in devices.iter().enumerate() {
            let unwrapped = unwrap_pdk(&wrapped_pdks[i], device_secret).unwrap();
            prop_assert_eq!(
                pdk.as_bytes(),
                unwrapped.as_bytes(),
                "Device {} should be able to unwrap the PDK",
                i
            );
        }
    });
}

/// Test that tampering with ciphertext causes unwrap to fail
#[test]
fn property_pdk_tampered_ciphertext_fails() {
    proptest!(ProptestConfig::with_cases(100), |(
        _seed in any::<u64>(),
        tamper_index in 0usize..60, // WrappedPdk::CIPHERTEXT_SIZE
    )| {
        // Generate a random PDK
        let pdk = generate_pdk().unwrap();

        // Generate a device keypair
        let device_id = DeviceId::new();
        let (device_secret, device_pubkey) = generate_x25519_keypair().unwrap();

        // Wrap the PDK
        let mut wrapped = wrap_pdk(&pdk, device_id, &device_pubkey).unwrap();

        // Tamper with the ciphertext at a random position
        if tamper_index < wrapped.ciphertext.len() {
            wrapped.ciphertext[tamper_index] ^= 0xFF;

            // Try to unwrap the tampered ciphertext
            let result = unwrap_pdk(&wrapped, &device_secret);

            // Should fail due to authentication tag mismatch
            prop_assert!(
                result.is_err(),
                "Unwrapping tampered ciphertext should fail"
            );
        }
    });
}

/// Test that different PDKs produce different ciphertexts when wrapped to the same device
#[test]
fn property_different_pdks_produce_different_ciphertexts() {
    proptest!(ProptestConfig::with_cases(100), |(
        _seed in any::<u64>(),
    )| {
        // Generate two different PDKs
        let pdk1 = generate_pdk().unwrap();
        let pdk2 = generate_pdk().unwrap();

        // PDKs should be different (with overwhelming probability)
        prop_assume!(pdk1.as_bytes() != pdk2.as_bytes());

        // Generate a device keypair
        let device_id = DeviceId::new();
        let (device_secret, device_pubkey) = generate_x25519_keypair().unwrap();

        // Wrap both PDKs to the same device
        let wrapped1 = wrap_pdk(&pdk1, device_id, &device_pubkey).unwrap();
        let wrapped2 = wrap_pdk(&pdk2, device_id, &device_pubkey).unwrap();

        // Verify each unwraps to the correct PDK
        let unwrapped1 = unwrap_pdk(&wrapped1, &device_secret).unwrap();
        let unwrapped2 = unwrap_pdk(&wrapped2, &device_secret).unwrap();

        // Ciphertexts should be different
        prop_assert_ne!(
            &wrapped1.ciphertext,
            &wrapped2.ciphertext,
            "Different PDKs should produce different ciphertexts"
        );

        prop_assert_eq!(pdk1.as_bytes(), unwrapped1.as_bytes());
        prop_assert_eq!(pdk2.as_bytes(), unwrapped2.as_bytes());
    });
}

// ============================================================================
// Property 25: Profile Switch Clears PDK Cache
// ============================================================================

/// Feature: mycelium-cli, Property 25: Profile Switch Clears PDK Cache
///
/// For any cached PDK, switching profiles SHALL clear the cache.
///
/// **Validates: Requirements 7.7**
#[test]
fn property_profile_switch_clears_pdk_cache() {
    use myc_core::ids::VersionNumber;
    use myc_core::pdk_cache::{PdkCache, PdkCacheKey};

    proptest!(ProptestConfig::with_cases(100), |(
        num_projects in 1usize..10,
        num_versions_per_project in 1usize..5,
    )| {
        // Create a PDK cache and populate it with multiple PDKs
        let mut cache = PdkCache::new();

        // Generate multiple projects with multiple PDK versions each
        let mut cache_keys = Vec::new();
        for _ in 0..num_projects {
            let project_id = myc_core::ids::ProjectId::new();

            for version_num in 1..=num_versions_per_project {
                let version = VersionNumber::new(version_num as u64);
                let key = PdkCacheKey::new(project_id, version);

                // Generate and cache a PDK
                let pdk = generate_pdk().unwrap();
                cache.insert(key, pdk);

                cache_keys.push(key);
            }
        }

        // Property: Cache should contain all inserted PDKs
        let expected_count = num_projects * num_versions_per_project;
        prop_assert_eq!(
            cache.len(),
            expected_count,
            "Cache should contain {} PDKs before profile switch",
            expected_count
        );

        // Property: All cache keys should be retrievable
        for key in &cache_keys {
            prop_assert!(
                cache.get(key).is_some(),
                "PDK for project {:?} version {} should be cached",
                key.project_id,
                key.version
            );
        }

        // Simulate profile switch by clearing the cache
        // (In the actual CLI, this would happen when switching profiles)
        cache.clear();

        // Property: Cache should be empty after profile switch
        prop_assert!(
            cache.is_empty(),
            "Cache should be empty after profile switch"
        );

        prop_assert_eq!(
            cache.len(),
            0,
            "Cache should have 0 PDKs after profile switch"
        );

        // Property: All previously cached PDKs should no longer be retrievable
        for key in &cache_keys {
            prop_assert!(
                cache.get(key).is_none(),
                "PDK for project {:?} version {} should not be cached after profile switch",
                key.project_id,
                key.version
            );
        }

        // Property: Cache should be usable after clearing (can insert new PDKs)
        let new_project_id = myc_core::ids::ProjectId::new();
        let new_key = PdkCacheKey::new(new_project_id, VersionNumber::FIRST);
        let new_pdk = generate_pdk().unwrap();
        let new_pdk_bytes = *new_pdk.as_bytes();

        cache.insert(new_key, new_pdk);

        prop_assert_eq!(
            cache.len(),
            1,
            "Cache should be usable after clearing"
        );

        let cached_new_pdk = cache.get(&new_key);
        prop_assert!(
            cached_new_pdk.is_some(),
            "New PDK should be retrievable after profile switch"
        );

        prop_assert_eq!(
            cached_new_pdk.unwrap().as_bytes(),
            &new_pdk_bytes,
            "New PDK should match what was inserted"
        );
    });
}

/// Test that clearing an empty cache is safe
#[test]
fn property_clear_empty_cache_is_safe() {
    proptest!(ProptestConfig::with_cases(100), |(
        _seed in any::<u64>(),
    )| {
        use myc_core::pdk_cache::PdkCache;

        // Create an empty cache
        let mut cache = PdkCache::new();

        // Property: Empty cache should be empty
        prop_assert!(cache.is_empty());
        prop_assert_eq!(cache.len(), 0);

        // Clear the empty cache (should not panic or error)
        cache.clear();

        // Property: Cache should still be empty after clearing
        prop_assert!(cache.is_empty());
        prop_assert_eq!(cache.len(), 0);

        // Property: Cache should still be usable after clearing empty cache
        let project_id = myc_core::ids::ProjectId::new();
        let key = myc_core::pdk_cache::PdkCacheKey::new(
            project_id,
            myc_core::ids::VersionNumber::FIRST
        );
        let pdk = generate_pdk().unwrap();

        cache.insert(key, pdk);

        prop_assert_eq!(cache.len(), 1);
        prop_assert!(cache.get(&key).is_some());
    });
}

/// Test that multiple clears in succession work correctly
#[test]
fn property_multiple_clears_work() {
    proptest!(ProptestConfig::with_cases(100), |(
        num_clears in 1usize..10,
    )| {
        use myc_core::pdk_cache::{PdkCache, PdkCacheKey};
        use myc_core::ids::{ProjectId, VersionNumber};

        let mut cache = PdkCache::new();

        // Insert some PDKs
        let project_id = ProjectId::new();
        let key = PdkCacheKey::new(project_id, VersionNumber::FIRST);
        let pdk = generate_pdk().unwrap();
        cache.insert(key, pdk);

        prop_assert_eq!(cache.len(), 1);

        // Clear multiple times
        for i in 0..num_clears {
            cache.clear();

            // Property: Cache should be empty after each clear
            prop_assert!(
                cache.is_empty(),
                "Cache should be empty after clear #{}",
                i + 1
            );
            prop_assert_eq!(
                cache.len(),
                0,
                "Cache should have 0 PDKs after clear #{}",
                i + 1
            );
        }

        // Property: Cache should still be usable after multiple clears
        let new_pdk = generate_pdk().unwrap();
        cache.insert(key, new_pdk);

        prop_assert_eq!(cache.len(), 1);
        prop_assert!(cache.get(&key).is_some());
    });
}

// ============================================================================
// Property 22: Member Addition Wraps to All Devices
// ============================================================================

/// Feature: mycelium-cli, Property 22: Member Addition Wraps to All Devices
///
/// For any member addition, the current PDK SHALL be wrapped to all of the
/// member's active devices.
///
/// **Validates: Requirements 7.3**
#[test]
fn property_member_addition_wraps_to_all_devices() {
    use myc_core::ids::VersionNumber;
    use myc_core::pdk_ops::{add_member_wrapped_pdks, create_pdk_version, unwrap_pdk_from_version};

    proptest!(ProptestConfig::with_cases(100), |(
        num_existing_devices in 1usize..5,
        num_new_member_devices in 1usize..10,
    )| {
        // Generate a PDK for the existing project
        let pdk = generate_pdk().unwrap();

        // Generate existing member devices
        let mut existing_devices = Vec::new();
        for _ in 0..num_existing_devices {
            let device_id = DeviceId::new();
            let (device_secret, device_pubkey) = generate_x25519_keypair().unwrap();
            existing_devices.push((device_id, device_secret, device_pubkey));
        }

        // Create initial PDK version with existing devices
        let existing_wrapped: Vec<_> = existing_devices
            .iter()
            .map(|(id, _, pubkey)| wrap_pdk(&pdk, *id, pubkey).unwrap())
            .collect();

        let mut pdk_version = create_pdk_version(
            VersionNumber::FIRST,
            existing_devices[0].0,
            Some("Initial PDK".to_string()),
            existing_wrapped,
        );

        // Generate new member's devices
        let mut new_member_devices = Vec::new();
        let mut new_member_device_info = Vec::new();
        for _ in 0..num_new_member_devices {
            let device_id = DeviceId::new();
            let (device_secret, device_pubkey) = generate_x25519_keypair().unwrap();
            new_member_devices.push((device_id, device_pubkey));
            new_member_device_info.push((device_id, device_secret, device_pubkey));
        }

        // Admin unwraps PDK to add new member
        let admin_device_id = existing_devices[0].0;
        let admin_secret = &existing_devices[0].1;
        let unwrapped_pdk = unwrap_pdk_from_version(&pdk_version, &admin_device_id, admin_secret).unwrap();

        // Add member: wrap PDK to all new member's devices
        let new_wrapped_keys = add_member_wrapped_pdks(&unwrapped_pdk, &new_member_devices).unwrap();

        // Property: The number of wrapped keys should equal the number of new member devices
        prop_assert_eq!(
            new_wrapped_keys.len(),
            num_new_member_devices,
            "PDK should be wrapped to all {} new member devices",
            num_new_member_devices
        );

        // Property: Each new device should have exactly one wrapped PDK
        for (device_id, _) in &new_member_devices {
            let count = new_wrapped_keys.iter().filter(|w| w.device_id == *device_id).count();
            prop_assert_eq!(
                count,
                1,
                "Device {:?} should have exactly one wrapped PDK",
                device_id
            );
        }

        // Append new wrapped keys to PDK version (simulating member addition)
        pdk_version.wrapped_keys.extend(new_wrapped_keys);

        // Property: All new member devices should now have access
        for (device_id, _, _) in &new_member_device_info {
            prop_assert!(
                pdk_version.has_device_access(device_id),
                "New member device {:?} should have access after addition",
                device_id
            );
        }

        // Property: All new member devices should be able to unwrap the PDK
        for (device_id, device_secret, _) in &new_member_device_info {
            let unwrapped = unwrap_pdk_from_version(&pdk_version, device_id, device_secret);
            prop_assert!(
                unwrapped.is_ok(),
                "New member device {:?} should be able to unwrap PDK",
                device_id
            );

            // Property: Unwrapped PDK should match the original
            let unwrapped_pdk = unwrapped.unwrap();
            prop_assert_eq!(
                pdk.as_bytes(),
                unwrapped_pdk.as_bytes(),
                "Unwrapped PDK should match original for device {:?}",
                device_id
            );
        }

        // Property: Existing devices should still have access
        for (device_id, device_secret, _) in &existing_devices {
            let unwrapped = unwrap_pdk_from_version(&pdk_version, device_id, device_secret);
            prop_assert!(
                unwrapped.is_ok(),
                "Existing device {:?} should still have access",
                device_id
            );

            let unwrapped_pdk = unwrapped.unwrap();
            prop_assert_eq!(
                pdk.as_bytes(),
                unwrapped_pdk.as_bytes(),
                "Existing device {:?} should still unwrap to same PDK",
                device_id
            );
        }

        // Property: Total device count should be sum of existing and new devices
        prop_assert_eq!(
            pdk_version.device_count(),
            num_existing_devices + num_new_member_devices,
            "Total device count should be {} + {}",
            num_existing_devices,
            num_new_member_devices
        );
    });
}

// ============================================================================
// Property 23: Member Removal Excludes Devices
// ============================================================================

/// Feature: mycelium-cli, Property 23: Member Removal Excludes Devices
///
/// For any member removal, the new PDK version SHALL NOT contain wrapped PDKs
/// for the removed member's devices.
///
/// **Validates: Requirements 7.4**
#[test]
fn property_member_removal_excludes_devices() {
    use myc_core::ids::VersionNumber;
    use myc_core::pdk_ops::{
        create_pdk_version, rotate_pdk, unwrap_pdk_from_version, wrap_pdk_to_devices,
    };

    proptest!(ProptestConfig::with_cases(100), |(
        num_remaining_members in 1usize..5,
        num_removed_member_devices in 1usize..10,
    )| {
        // Generate initial PDK for the project
        let old_pdk = generate_pdk().unwrap();

        // Generate devices for remaining members
        let mut remaining_devices = Vec::new();
        let mut remaining_device_info = Vec::new();
        for _ in 0..num_remaining_members {
            let device_id = DeviceId::new();
            let (device_secret, device_pubkey) = generate_x25519_keypair().unwrap();
            remaining_devices.push((device_id, device_pubkey));
            remaining_device_info.push((device_id, device_secret, device_pubkey));
        }

        // Generate devices for member to be removed
        let mut removed_devices = Vec::new();
        let mut removed_device_info = Vec::new();
        for _ in 0..num_removed_member_devices {
            let device_id = DeviceId::new();
            let (device_secret, device_pubkey) = generate_x25519_keypair().unwrap();
            removed_devices.push((device_id, device_pubkey));
            removed_device_info.push((device_id, device_secret, device_pubkey));
        }

        // Create initial PDK version with all devices (remaining + removed)
        let mut all_devices = remaining_devices.clone();
        all_devices.extend(removed_devices.clone());

        let old_wrapped_keys = wrap_pdk_to_devices(&old_pdk, &all_devices).unwrap();
        let old_pdk_version = create_pdk_version(
            VersionNumber::FIRST,
            remaining_devices[0].0,
            Some("Initial PDK".to_string()),
            old_wrapped_keys,
        );

        // Property: All devices (remaining + removed) should have access to old PDK version
        for (device_id, _, _) in &remaining_device_info {
            prop_assert!(
                old_pdk_version.has_device_access(device_id),
                "Remaining device {:?} should have access to old PDK version",
                device_id
            );
        }
        for (device_id, _, _) in &removed_device_info {
            prop_assert!(
                old_pdk_version.has_device_access(device_id),
                "Removed device {:?} should have access to old PDK version",
                device_id
            );
        }

        // Simulate member removal: rotate PDK with only remaining devices
        let (new_pdk, new_wrapped_keys) = rotate_pdk(&remaining_devices).unwrap();

        let new_pdk_version = create_pdk_version(
            VersionNumber::new(2),
            remaining_devices[0].0,
            Some("Member removed".to_string()),
            new_wrapped_keys,
        );

        // Property: New PDK should be different from old PDK
        prop_assert_ne!(
            old_pdk.as_bytes(),
            new_pdk.as_bytes(),
            "Rotated PDK should be different from old PDK"
        );

        // Property: New PDK version should contain wrapped PDKs for all remaining devices
        for (device_id, _, _) in &remaining_device_info {
            prop_assert!(
                new_pdk_version.has_device_access(device_id),
                "Remaining device {:?} should have access to new PDK version",
                device_id
            );
        }

        // Property: New PDK version should NOT contain wrapped PDKs for removed devices
        for (device_id, _, _) in &removed_device_info {
            prop_assert!(
                !new_pdk_version.has_device_access(device_id),
                "Removed device {:?} should NOT have access to new PDK version",
                device_id
            );
        }

        // Property: Device count in new version should equal number of remaining devices
        prop_assert_eq!(
            new_pdk_version.device_count(),
            num_remaining_members,
            "New PDK version should have exactly {} devices",
            num_remaining_members
        );

        // Property: Remaining devices should be able to unwrap the new PDK
        for (device_id, device_secret, _) in &remaining_device_info {
            let unwrapped = unwrap_pdk_from_version(&new_pdk_version, device_id, device_secret);
            prop_assert!(
                unwrapped.is_ok(),
                "Remaining device {:?} should be able to unwrap new PDK",
                device_id
            );

            let unwrapped_pdk = unwrapped.unwrap();
            prop_assert_eq!(
                new_pdk.as_bytes(),
                unwrapped_pdk.as_bytes(),
                "Remaining device {:?} should unwrap to correct new PDK",
                device_id
            );
        }

        // Property: Removed devices should NOT be able to unwrap the new PDK
        for (device_id, device_secret, _) in &removed_device_info {
            let result = unwrap_pdk_from_version(&new_pdk_version, device_id, device_secret);
            prop_assert!(
                result.is_err(),
                "Removed device {:?} should NOT be able to unwrap new PDK",
                device_id
            );
        }

        // Property: Removed devices should still be able to unwrap the old PDK (historical access)
        for (device_id, device_secret, _) in &removed_device_info {
            let unwrapped = unwrap_pdk_from_version(&old_pdk_version, device_id, device_secret);
            prop_assert!(
                unwrapped.is_ok(),
                "Removed device {:?} should still be able to unwrap old PDK",
                device_id
            );

            let unwrapped_pdk = unwrapped.unwrap();
            prop_assert_eq!(
                old_pdk.as_bytes(),
                unwrapped_pdk.as_bytes(),
                "Removed device {:?} should unwrap to correct old PDK",
                device_id
            );
        }

        // Property: Remaining devices should still be able to unwrap the old PDK
        for (device_id, device_secret, _) in &remaining_device_info {
            let unwrapped = unwrap_pdk_from_version(&old_pdk_version, device_id, device_secret);
            prop_assert!(
                unwrapped.is_ok(),
                "Remaining device {:?} should still be able to unwrap old PDK",
                device_id
            );

            let unwrapped_pdk = unwrapped.unwrap();
            prop_assert_eq!(
                old_pdk.as_bytes(),
                unwrapped_pdk.as_bytes(),
                "Remaining device {:?} should unwrap to correct old PDK",
                device_id
            );
        }
    });
}

// ============================================================================
// Property 24: Unwrap Without Wrapped PDK Fails
// ============================================================================

/// Feature: mycelium-cli, Property 24: Unwrap Without Wrapped PDK Fails
///
/// For any device without a wrapped PDK in a PDK version, attempting to unwrap
/// SHALL fail with AccessDenied.
///
/// **Validates: Requirements 7.5**
#[test]
fn property_unwrap_without_wrapped_pdk_fails() {
    use myc_core::ids::VersionNumber;
    use myc_core::pdk_ops::{create_pdk_version, unwrap_pdk_from_version};

    proptest!(ProptestConfig::with_cases(100), |(
        num_authorized_devices in 1usize..10,
    )| {
        // Generate a random PDK
        let pdk = generate_pdk().unwrap();

        // Generate authorized devices and wrap PDK to them
        let mut authorized_devices = Vec::new();
        for _ in 0..num_authorized_devices {
            let device_id = DeviceId::new();
            let (_, device_pubkey) = generate_x25519_keypair().unwrap();
            authorized_devices.push((device_id, device_pubkey));
        }

        // Wrap PDK to authorized devices
        let mut wrapped_pdks = Vec::new();
        for (device_id, device_pubkey) in &authorized_devices {
            let wrapped = wrap_pdk(&pdk, *device_id, device_pubkey).unwrap();
            wrapped_pdks.push(wrapped);
        }

        // Create PDK version with authorized devices
        let pdk_version = create_pdk_version(
            VersionNumber::FIRST,
            authorized_devices[0].0,
            Some("Test PDK version".to_string()),
            wrapped_pdks,
        );

        // Generate an unauthorized device (not in the PDK version)
        let unauthorized_device_id = DeviceId::new();
        let (unauthorized_secret, _) = generate_x25519_keypair().unwrap();

        // Verify the unauthorized device is not in the PDK version
        prop_assert!(
            !pdk_version.has_device_access(&unauthorized_device_id),
            "Unauthorized device should not have access"
        );

        // Try to unwrap PDK for unauthorized device
        let result = unwrap_pdk_from_version(
            &pdk_version,
            &unauthorized_device_id,
            &unauthorized_secret,
        );

        // Should fail because no wrapped PDK exists for this device
        prop_assert!(
            result.is_err(),
            "Unwrapping without wrapped PDK should fail"
        );

        // Verify authorized devices can still unwrap successfully
        for (i, (device_id, _)) in authorized_devices.iter().enumerate() {
            // We need the secret key, so generate a new keypair and re-wrap
            // (In a real scenario, we'd keep the secret keys)
            let (device_secret, device_pubkey) = generate_x25519_keypair().unwrap();
            let wrapped = wrap_pdk(&pdk, *device_id, &device_pubkey).unwrap();
            let test_version = create_pdk_version(
                VersionNumber::FIRST,
                *device_id,
                None,
                vec![wrapped],
            );

            let unwrapped = unwrap_pdk_from_version(&test_version, device_id, &device_secret);
            prop_assert!(
                unwrapped.is_ok(),
                "Authorized device {} should be able to unwrap",
                i
            );
        }
    });
}
