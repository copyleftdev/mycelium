//! Property-based tests for secret set operations.

#![allow(unused_variables)]
#![allow(clippy::len_zero)]
//!
//! These tests verify:
//! - Content hash verification (Property 27)
//! - AAD construction (Property 28)
//! - Size limit enforcement (Property 31)

use myc_core::error::CoreError;
use myc_core::ids::{ProjectId, SecretSetId, VersionNumber};
use myc_core::pdk_ops::generate_pdk;
use myc_core::secret_set::SecretEntry;
use myc_core::secret_set_ops::{
    decrypt_secrets, encrypt_secrets, serialize_secrets, validate_size_limits, MAX_ENTRIES,
    MAX_KEY_LENGTH, MAX_PLAINTEXT_SIZE, MAX_VALUE_LENGTH,
};
use myc_crypto::hash::hash;
use proptest::prelude::*;

// ============================================================================
// Property 27: Content Hash Verification
// ============================================================================

/// Feature: mycelium-cli, Property 27: Content Hash Verification
///
/// For any encrypted version, the content_hash SHALL equal BLAKE3(plaintext).
///
/// **Validates: Requirements 8.2**
#[test]
fn property_content_hash_verification() {
    proptest!(|(
        // Generate random secret entries
        keys in prop::collection::vec("[A-Z_][A-Z0-9_]{0,19}", 1..20),
        values in prop::collection::vec("[a-z0-9]{1,100}", 1..20),
    )| {
        // Ensure we have matching keys and values
        let min_len = keys.len().min(values.len());
        let keys = &keys[..min_len];
        let values = &values[..min_len];

        // Create secret entries
        let entries: Vec<SecretEntry> = keys
            .iter()
            .zip(values.iter())
            .map(|(k, v)| SecretEntry::new(k.clone(), v.clone()))
            .collect();

        // Generate test data
        let project_id = ProjectId::new();
        let set_id = SecretSetId::new();
        let pdk = generate_pdk().unwrap();

        // Encrypt secrets
        let (_, content_hash, _) = encrypt_secrets(
            &entries,
            &project_id,
            &set_id,
            &VersionNumber::FIRST,
            &VersionNumber::FIRST,
            &pdk,
            None,
        ).unwrap();

        // Compute expected content hash from plaintext
        let plaintext = serialize_secrets(&entries).unwrap();
        let expected_content_hash = hash(plaintext.as_bytes());

        // Verify that content_hash equals BLAKE3(plaintext)
        prop_assert_eq!(
            content_hash,
            expected_content_hash,
            "Content hash should equal BLAKE3(plaintext)"
        );

        // Verify that content hash is deterministic for the same plaintext
        let plaintext2 = serialize_secrets(&entries).unwrap();
        let expected_content_hash2 = hash(plaintext2.as_bytes());

        prop_assert_eq!(
            content_hash,
            expected_content_hash2,
            "Content hash should be deterministic for the same plaintext"
        );
    });
}

/// Test content hash verification with empty entries
#[test]
fn property_content_hash_verification_empty() {
    let entries: Vec<SecretEntry> = vec![];

    let project_id = ProjectId::new();
    let set_id = SecretSetId::new();
    let pdk = generate_pdk().unwrap();

    // Encrypt empty entries
    let (_, content_hash, _) = encrypt_secrets(
        &entries,
        &project_id,
        &set_id,
        &VersionNumber::FIRST,
        &VersionNumber::FIRST,
        &pdk,
        None,
    )
    .unwrap();

    // Compute expected content hash
    let plaintext = serialize_secrets(&entries).unwrap();
    let expected_content_hash = hash(plaintext.as_bytes());

    assert_eq!(
        content_hash, expected_content_hash,
        "Content hash should equal BLAKE3(plaintext) even for empty entries"
    );
}

/// Test content hash verification with single entry
#[test]
fn property_content_hash_verification_single() {
    proptest!(|(
        key in "[A-Z_][A-Z0-9_]{0,19}",
        value in "[a-z0-9]{1,100}",
    )| {
        let entries = vec![SecretEntry::new(key.clone(), value.clone())];

        let project_id = ProjectId::new();
        let set_id = SecretSetId::new();
        let pdk = generate_pdk().unwrap();

        // Encrypt
        let (_, content_hash, _) = encrypt_secrets(
            &entries,
            &project_id,
            &set_id,
            &VersionNumber::FIRST,
            &VersionNumber::FIRST,
            &pdk,
            None,
        ).unwrap();

        // Compute expected content hash
        let plaintext = serialize_secrets(&entries).unwrap();
        let expected_content_hash = hash(plaintext.as_bytes());

        prop_assert_eq!(
            content_hash,
            expected_content_hash,
            "Content hash should equal BLAKE3(plaintext) for single entry"
        );
    });
}

/// Test that different plaintexts produce different content hashes
#[test]
fn property_content_hash_uniqueness() {
    proptest!(|(
        key1 in "[A-Z_][A-Z0-9_]{0,19}",
        value1 in "[a-z0-9]{1,100}",
        key2 in "[A-Z_][A-Z0-9_]{0,19}",
        value2 in "[a-z0-9]{1,100}",
    )| {
        // Skip if entries would be identical
        if key1 == key2 && value1 == value2 {
            return Ok(());
        }

        let entries1 = vec![SecretEntry::new(key1.clone(), value1.clone())];
        let entries2 = vec![SecretEntry::new(key2.clone(), value2.clone())];

        let project_id = ProjectId::new();
        let set_id = SecretSetId::new();
        let pdk = generate_pdk().unwrap();

        // Encrypt both
        let (_, content_hash1, _) = encrypt_secrets(
            &entries1,
            &project_id,
            &set_id,
            &VersionNumber::FIRST,
            &VersionNumber::FIRST,
            &pdk,
            None,
        ).unwrap();

        let (_, content_hash2, _) = encrypt_secrets(
            &entries2,
            &project_id,
            &set_id,
            &VersionNumber::FIRST,
            &VersionNumber::FIRST,
            &pdk,
            None,
        ).unwrap();

        // Different plaintexts should produce different content hashes
        prop_assert_ne!(
            content_hash1,
            content_hash2,
            "Different plaintexts should produce different content hashes"
        );
    });
}

// ============================================================================
// Property 28: AAD Construction
// ============================================================================

/// Feature: mycelium-cli, Property 28: AAD Construction
///
/// For any version encryption, AAD SHALL be constructed as:
/// project_id || set_id || version_number || pdk_version
///
/// **Validates: Requirements 8.3**
#[test]
fn property_aad_construction() {
    proptest!(|(
        // Generate random secret entries
        keys in prop::collection::vec("[A-Z_][A-Z0-9_]{0,19}", 1..10),
        values in prop::collection::vec("[a-z0-9]{1,50}", 1..10),
        version_num in 1u64..100,
        pdk_version_num in 1u64..10,
    )| {
        // Ensure we have matching keys and values
        let min_len = keys.len().min(values.len());
        let keys = &keys[..min_len];
        let values = &values[..min_len];

        // Create secret entries
        let entries: Vec<SecretEntry> = keys
            .iter()
            .zip(values.iter())
            .map(|(k, v)| SecretEntry::new(k.clone(), v.clone()))
            .collect();

        // Generate test data with random version numbers
        let project_id = ProjectId::new();
        let set_id = SecretSetId::new();
        let version = VersionNumber::new(version_num);
        let pdk_version = VersionNumber::new(pdk_version_num);
        let pdk = generate_pdk().unwrap();

        // Encrypt secrets
        let (ciphertext1, _, _) = encrypt_secrets(
            &entries,
            &project_id,
            &set_id,
            &version,
            &pdk_version,
            &pdk,
            None,
        ).unwrap();

        // Encrypt again with same parameters - should produce different ciphertext
        // (due to random nonce) but should decrypt correctly with same AAD
        let (ciphertext2, _, _) = encrypt_secrets(
            &entries,
            &project_id,
            &set_id,
            &version,
            &pdk_version,
            &pdk,
            None,
        ).unwrap();

        // Ciphertexts should be different (random nonces)
        prop_assert_ne!(
            &ciphertext1,
            &ciphertext2,
            "Different encryptions should produce different ciphertexts due to random nonces"
        );

        // Now test that changing any component of AAD produces different results
        // that cannot be decrypted with the original AAD

        // Test 1: Different project_id
        let different_project_id = ProjectId::new();
        let (ciphertext_diff_project, _, _) = encrypt_secrets(
            &entries,
            &different_project_id,
            &set_id,
            &version,
            &pdk_version,
            &pdk,
            None,
        ).unwrap();

        // Ciphertext should be different
        prop_assert_ne!(
            &ciphertext1,
            &ciphertext_diff_project,
            "Different project_id should produce different ciphertext"
        );

        // Test 2: Different set_id
        let different_set_id = SecretSetId::new();
        let (ciphertext_diff_set, _, _) = encrypt_secrets(
            &entries,
            &project_id,
            &different_set_id,
            &version,
            &pdk_version,
            &pdk,
            None,
        ).unwrap();

        prop_assert_ne!(
            &ciphertext1,
            &ciphertext_diff_set,
            "Different set_id should produce different ciphertext"
        );

        // Test 3: Different version number
        let different_version = VersionNumber::new(version_num + 1);
        let (ciphertext_diff_version, _, _) = encrypt_secrets(
            &entries,
            &project_id,
            &set_id,
            &different_version,
            &pdk_version,
            &pdk,
            None,
        ).unwrap();

        prop_assert_ne!(
            &ciphertext1,
            &ciphertext_diff_version,
            "Different version number should produce different ciphertext"
        );

        // Test 4: Different pdk_version
        let different_pdk_version = VersionNumber::new(pdk_version_num + 1);
        let (ciphertext_diff_pdk_version, _, _) = encrypt_secrets(
            &entries,
            &project_id,
            &set_id,
            &version,
            &different_pdk_version,
            &pdk,
            None,
        ).unwrap();

        prop_assert_ne!(
            &ciphertext1,
            &ciphertext_diff_pdk_version,
            "Different pdk_version should produce different ciphertext"
        );
    });
}

/// Test that AAD prevents ciphertext from being decrypted with wrong metadata
#[test]
fn property_aad_prevents_metadata_tampering() {
    use myc_core::secret_set_ops::decrypt_secrets;

    proptest!(|(
        key in "[A-Z_][A-Z0-9_]{0,19}",
        value in "[a-z0-9]{1,50}",
    )| {
        let entries = vec![SecretEntry::new(key.clone(), value.clone())];

        let project_id = ProjectId::new();
        let set_id = SecretSetId::new();
        let version = VersionNumber::FIRST;
        let pdk_version = VersionNumber::FIRST;
        let pdk = generate_pdk().unwrap();

        // Encrypt with original metadata
        let (ciphertext, content_hash, chain_hash) = encrypt_secrets(
            &entries,
            &project_id,
            &set_id,
            &version,
            &pdk_version,
            &pdk,
            None,
        ).unwrap();

        // Try to decrypt with different project_id (wrong AAD)
        let wrong_project_id = ProjectId::new();
        let result = decrypt_secrets(
            &ciphertext,
            &wrong_project_id,  // Wrong!
            &set_id,
            &version,
            &pdk_version,
            &pdk,
            &content_hash,
            &chain_hash,
            None,
        );

        prop_assert!(
            result.is_err(),
            "Decryption should fail with wrong project_id in AAD"
        );

        // Try to decrypt with different set_id (wrong AAD)
        let wrong_set_id = SecretSetId::new();
        let result = decrypt_secrets(
            &ciphertext,
            &project_id,
            &wrong_set_id,  // Wrong!
            &version,
            &pdk_version,
            &pdk,
            &content_hash,
            &chain_hash,
            None,
        );

        prop_assert!(
            result.is_err(),
            "Decryption should fail with wrong set_id in AAD"
        );

        // Try to decrypt with different version (wrong AAD)
        let wrong_version = VersionNumber::new(2);
        let result = decrypt_secrets(
            &ciphertext,
            &project_id,
            &set_id,
            &wrong_version,  // Wrong!
            &pdk_version,
            &pdk,
            &content_hash,
            &chain_hash,
            None,
        );

        prop_assert!(
            result.is_err(),
            "Decryption should fail with wrong version in AAD"
        );

        // Try to decrypt with different pdk_version (wrong AAD)
        let wrong_pdk_version = VersionNumber::new(2);
        let result = decrypt_secrets(
            &ciphertext,
            &project_id,
            &set_id,
            &version,
            &wrong_pdk_version,  // Wrong!
            &pdk,
            &content_hash,
            &chain_hash,
            None,
        );

        prop_assert!(
            result.is_err(),
            "Decryption should fail with wrong pdk_version in AAD"
        );

        // Verify that decryption succeeds with correct AAD
        let result = decrypt_secrets(
            &ciphertext,
            &project_id,
            &set_id,
            &version,
            &pdk_version,
            &pdk,
            &content_hash,
            &chain_hash,
            None,
        );

        prop_assert!(
            result.is_ok(),
            "Decryption should succeed with correct AAD"
        );
    });
}

/// Test AAD construction with edge case version numbers
#[test]
fn property_aad_construction_edge_cases() {
    let entries = vec![SecretEntry::new("KEY".to_string(), "value".to_string())];

    let project_id = ProjectId::new();
    let set_id = SecretSetId::new();
    let pdk = generate_pdk().unwrap();

    // Test with version 1
    let (ciphertext1, _, _) = encrypt_secrets(
        &entries,
        &project_id,
        &set_id,
        &VersionNumber::FIRST,
        &VersionNumber::FIRST,
        &pdk,
        None,
    )
    .unwrap();

    // Test with large version numbers
    let large_version = VersionNumber::new(u64::MAX);
    let (ciphertext2, _, _) = encrypt_secrets(
        &entries,
        &project_id,
        &set_id,
        &large_version,
        &VersionNumber::FIRST,
        &pdk,
        None,
    )
    .unwrap();

    // Should produce different ciphertexts
    assert_ne!(
        ciphertext1, ciphertext2,
        "Different version numbers should produce different ciphertexts"
    );

    // Test with large pdk_version
    let large_pdk_version = VersionNumber::new(u64::MAX);
    let (ciphertext3, _, _) = encrypt_secrets(
        &entries,
        &project_id,
        &set_id,
        &VersionNumber::FIRST,
        &large_pdk_version,
        &pdk,
        None,
    )
    .unwrap();

    // Should produce different ciphertexts
    assert_ne!(
        ciphertext1, ciphertext3,
        "Different pdk_version numbers should produce different ciphertexts"
    );
}

/// Test that AAD is properly included in AEAD encryption
#[test]
fn property_aad_integrity() {
    use myc_core::secret_set_ops::decrypt_secrets;

    proptest!(|(
        keys in prop::collection::vec("[A-Z_][A-Z0-9_]{0,19}", 1..5),
        values in prop::collection::vec("[a-z0-9]{1,50}", 1..5),
    )| {
        let min_len = keys.len().min(values.len());
        let keys = &keys[..min_len];
        let values = &values[..min_len];

        let entries: Vec<SecretEntry> = keys
            .iter()
            .zip(values.iter())
            .map(|(k, v)| SecretEntry::new(k.clone(), v.clone()))
            .collect();

        let project_id = ProjectId::new();
        let set_id = SecretSetId::new();
        let version = VersionNumber::FIRST;
        let pdk_version = VersionNumber::FIRST;
        let pdk = generate_pdk().unwrap();

        // Encrypt
        let (ciphertext, content_hash, chain_hash) = encrypt_secrets(
            &entries,
            &project_id,
            &set_id,
            &version,
            &pdk_version,
            &pdk,
            None,
        ).unwrap();

        // Decrypt with correct AAD should succeed
        let result = decrypt_secrets(
            &ciphertext,
            &project_id,
            &set_id,
            &version,
            &pdk_version,
            &pdk,
            &content_hash,
            &chain_hash,
            None,
        );

        prop_assert!(
            result.is_ok(),
            "Decryption with correct AAD should succeed"
        );

        // Verify decrypted content matches original
        let decrypted = result.unwrap();
        let mut expected = entries.clone();
        expected.sort_by(|a, b| a.key.cmp(&b.key));

        prop_assert_eq!(
            decrypted,
            expected,
            "Decrypted content should match original entries"
        );
    });
}

// ============================================================================
// Property 29: Version Signature Verification
// ============================================================================

/// Feature: mycelium-cli, Property 29: Version Signature Verification
///
/// For any version, the signature SHALL verify using the creator's Ed25519 public key.
///
/// **Validates: Requirements 8.4**
#[test]
fn property_version_signature_verification() {
    use myc_core::ids::DeviceId;
    use myc_core::secret_set_ops::{sign_version_metadata, verify_version_metadata};
    use myc_crypto::sign::generate_ed25519_keypair;
    use time::OffsetDateTime;

    proptest!(|(
        // Generate random secret entries
        keys in prop::collection::vec("[A-Z_][A-Z0-9_]{0,19}", 1..10),
        values in prop::collection::vec("[a-z0-9]{1,50}", 1..10),
        version_num in 1u64..100,
        pdk_version_num in 1u64..10,
        message in prop::option::of("[a-z0-9 ]{0,100}"),
    )| {
        // Ensure we have matching keys and values
        let min_len = keys.len().min(values.len());
        let keys = &keys[..min_len];
        let values = &values[..min_len];

        // Create secret entries
        let entries: Vec<SecretEntry> = keys
            .iter()
            .zip(values.iter())
            .map(|(k, v)| SecretEntry::new(k.clone(), v.clone()))
            .collect();

        // Generate test data
        let project_id = ProjectId::new();
        let set_id = SecretSetId::new();
        let device_id = DeviceId::new();
        let version = VersionNumber::new(version_num);
        let pdk_version = VersionNumber::new(pdk_version_num);
        let pdk = generate_pdk().unwrap();

        // Generate device keypair
        let (device_key, device_pubkey) = generate_ed25519_keypair().unwrap();

        // Encrypt secrets to get content_hash and chain_hash
        let (_, content_hash, chain_hash) = encrypt_secrets(
            &entries,
            &project_id,
            &set_id,
            &version,
            &pdk_version,
            &pdk,
            None,
        ).unwrap();

        let created_at = OffsetDateTime::now_utc();

        // Sign the version metadata
        let signature = sign_version_metadata(
            &set_id,
            &version,
            &pdk_version,
            created_at,
            &device_id,
            message.clone(),
            &content_hash,
            &chain_hash,
            None,
            &device_key,
        ).unwrap();

        // Verify the signature with the correct public key
        let result = verify_version_metadata(
            &set_id,
            &version,
            &pdk_version,
            created_at,
            &device_id,
            message.clone(),
            &content_hash,
            &chain_hash,
            None,
            &signature,
            &device_pubkey,
        );

        prop_assert!(
            result.is_ok(),
            "Signature verification should succeed with correct public key"
        );
    });
}

/// Test that signature verification fails with wrong public key
#[test]
fn property_version_signature_verification_wrong_key() {
    use myc_core::ids::DeviceId;
    use myc_core::secret_set_ops::{sign_version_metadata, verify_version_metadata};
    use myc_crypto::sign::generate_ed25519_keypair;
    use time::OffsetDateTime;

    proptest!(|(
        key in "[A-Z_][A-Z0-9_]{0,19}",
        value in "[a-z0-9]{1,50}",
    )| {
        let entries = vec![SecretEntry::new(key.clone(), value.clone())];

        let project_id = ProjectId::new();
        let set_id = SecretSetId::new();
        let device_id = DeviceId::new();
        let version = VersionNumber::FIRST;
        let pdk_version = VersionNumber::FIRST;
        let pdk = generate_pdk().unwrap();

        // Generate two different keypairs
        let (device_key1, _) = generate_ed25519_keypair().unwrap();
        let (_, device_pubkey2) = generate_ed25519_keypair().unwrap();

        // Encrypt secrets
        let (_, content_hash, chain_hash) = encrypt_secrets(
            &entries,
            &project_id,
            &set_id,
            &version,
            &pdk_version,
            &pdk,
            None,
        ).unwrap();

        let created_at = OffsetDateTime::now_utc();

        // Sign with key 1
        let signature = sign_version_metadata(
            &set_id,
            &version,
            &pdk_version,
            created_at,
            &device_id,
            None,
            &content_hash,
            &chain_hash,
            None,
            &device_key1,
        ).unwrap();

        // Try to verify with key 2 (wrong key)
        let result = verify_version_metadata(
            &set_id,
            &version,
            &pdk_version,
            created_at,
            &device_id,
            None,
            &content_hash,
            &chain_hash,
            None,
            &signature,
            &device_pubkey2,  // Wrong key!
        );

        prop_assert!(
            result.is_err(),
            "Signature verification should fail with wrong public key"
        );
    });
}

/// Test that signature verification fails with tampered metadata
#[test]
fn property_version_signature_verification_tampered_metadata() {
    use myc_core::ids::DeviceId;
    use myc_core::secret_set_ops::{sign_version_metadata, verify_version_metadata};
    use myc_crypto::sign::generate_ed25519_keypair;
    use time::OffsetDateTime;

    proptest!(|(
        key in "[A-Z_][A-Z0-9_]{0,19}",
        value in "[a-z0-9]{1,50}",
        tampered_message in "[a-z0-9 ]{1,50}",
    )| {
        let entries = vec![SecretEntry::new(key.clone(), value.clone())];

        let project_id = ProjectId::new();
        let set_id = SecretSetId::new();
        let device_id = DeviceId::new();
        let version = VersionNumber::FIRST;
        let pdk_version = VersionNumber::FIRST;
        let pdk = generate_pdk().unwrap();

        // Generate keypair
        let (device_key, device_pubkey) = generate_ed25519_keypair().unwrap();

        // Encrypt secrets
        let (_, content_hash, chain_hash) = encrypt_secrets(
            &entries,
            &project_id,
            &set_id,
            &version,
            &pdk_version,
            &pdk,
            None,
        ).unwrap();

        let created_at = OffsetDateTime::now_utc();

        // Sign with no message
        let signature = sign_version_metadata(
            &set_id,
            &version,
            &pdk_version,
            created_at,
            &device_id,
            None,
            &content_hash,
            &chain_hash,
            None,
            &device_key,
        ).unwrap();

        // Try to verify with a different message (tampered metadata)
        let result = verify_version_metadata(
            &set_id,
            &version,
            &pdk_version,
            created_at,
            &device_id,
            Some(tampered_message),  // Tampered!
            &content_hash,
            &chain_hash,
            None,
            &signature,
            &device_pubkey,
        );

        prop_assert!(
            result.is_err(),
            "Signature verification should fail with tampered metadata"
        );
    });
}

/// Test that signature verification fails with tampered content hash
#[test]
fn property_version_signature_verification_tampered_content_hash() {
    use myc_core::ids::DeviceId;
    use myc_core::secret_set_ops::{sign_version_metadata, verify_version_metadata};
    use myc_crypto::sign::generate_ed25519_keypair;
    use time::OffsetDateTime;

    proptest!(|(
        key in "[A-Z_][A-Z0-9_]{0,19}",
        value in "[a-z0-9]{1,50}",
    )| {
        let entries = vec![SecretEntry::new(key.clone(), value.clone())];

        let project_id = ProjectId::new();
        let set_id = SecretSetId::new();
        let device_id = DeviceId::new();
        let version = VersionNumber::FIRST;
        let pdk_version = VersionNumber::FIRST;
        let pdk = generate_pdk().unwrap();

        // Generate keypair
        let (device_key, device_pubkey) = generate_ed25519_keypair().unwrap();

        // Encrypt secrets
        let (_, content_hash, chain_hash) = encrypt_secrets(
            &entries,
            &project_id,
            &set_id,
            &version,
            &pdk_version,
            &pdk,
            None,
        ).unwrap();

        let created_at = OffsetDateTime::now_utc();

        // Sign with original content hash
        let signature = sign_version_metadata(
            &set_id,
            &version,
            &pdk_version,
            created_at,
            &device_id,
            None,
            &content_hash,
            &chain_hash,
            None,
            &device_key,
        ).unwrap();

        // Create a different content hash (tampered)
        let tampered_content_hash = myc_crypto::hash::hash(b"tampered content");

        // Try to verify with tampered content hash
        let result = verify_version_metadata(
            &set_id,
            &version,
            &pdk_version,
            created_at,
            &device_id,
            None,
            &tampered_content_hash,  // Tampered!
            &chain_hash,
            None,
            &signature,
            &device_pubkey,
        );

        prop_assert!(
            result.is_err(),
            "Signature verification should fail with tampered content hash"
        );
    });
}

/// Test signature verification with version chains
#[test]
fn property_version_signature_verification_with_chain() {
    use myc_core::ids::DeviceId;
    use myc_core::secret_set_ops::{sign_version_metadata, verify_version_metadata};
    use myc_crypto::sign::generate_ed25519_keypair;
    use time::OffsetDateTime;

    proptest!(|(
        key1 in "[A-Z_][A-Z0-9_]{0,19}",
        value1 in "[a-z0-9]{1,50}",
        key2 in "[A-Z_][A-Z0-9_]{0,19}",
        value2 in "[a-z0-9]{1,50}",
    )| {
        let entries1 = vec![SecretEntry::new(key1.clone(), value1.clone())];
        let entries2 = vec![SecretEntry::new(key2.clone(), value2.clone())];

        let project_id = ProjectId::new();
        let set_id = SecretSetId::new();
        let device_id = DeviceId::new();
        let pdk_version = VersionNumber::FIRST;
        let pdk = generate_pdk().unwrap();

        // Generate keypair
        let (device_key, device_pubkey) = generate_ed25519_keypair().unwrap();

        // Create version 1
        let (_, content_hash1, chain_hash1) = encrypt_secrets(
            &entries1,
            &project_id,
            &set_id,
            &VersionNumber::FIRST,
            &pdk_version,
            &pdk,
            None,
        ).unwrap();

        let created_at1 = OffsetDateTime::now_utc();

        let signature1 = sign_version_metadata(
            &set_id,
            &VersionNumber::FIRST,
            &pdk_version,
            created_at1,
            &device_id,
            Some("Version 1".to_string()),
            &content_hash1,
            &chain_hash1,
            None,
            &device_key,
        ).unwrap();

        // Verify version 1
        let result1 = verify_version_metadata(
            &set_id,
            &VersionNumber::FIRST,
            &pdk_version,
            created_at1,
            &device_id,
            Some("Version 1".to_string()),
            &content_hash1,
            &chain_hash1,
            None,
            &signature1,
            &device_pubkey,
        );

        prop_assert!(
            result1.is_ok(),
            "Version 1 signature verification should succeed"
        );

        // Create version 2 with chain
        let (_, content_hash2, chain_hash2) = encrypt_secrets(
            &entries2,
            &project_id,
            &set_id,
            &VersionNumber::new(2),
            &pdk_version,
            &pdk,
            Some(&chain_hash1),  // Chain to version 1
        ).unwrap();

        let created_at2 = OffsetDateTime::now_utc();

        let signature2 = sign_version_metadata(
            &set_id,
            &VersionNumber::new(2),
            &pdk_version,
            created_at2,
            &device_id,
            Some("Version 2".to_string()),
            &content_hash2,
            &chain_hash2,
            Some(&chain_hash1),  // Include previous chain hash
            &device_key,
        ).unwrap();

        // Verify version 2
        let result2 = verify_version_metadata(
            &set_id,
            &VersionNumber::new(2),
            &pdk_version,
            created_at2,
            &device_id,
            Some("Version 2".to_string()),
            &content_hash2,
            &chain_hash2,
            Some(&chain_hash1),
            &signature2,
            &device_pubkey,
        );

        prop_assert!(
            result2.is_ok(),
            "Version 2 signature verification should succeed"
        );
    });
}

/// Test that signature is deterministic for same metadata
#[test]
fn property_version_signature_determinism() {
    use myc_core::ids::DeviceId;
    use myc_core::secret_set_ops::sign_version_metadata;
    use myc_crypto::sign::generate_ed25519_keypair;
    use time::OffsetDateTime;

    proptest!(|(
        key in "[A-Z_][A-Z0-9_]{0,19}",
        value in "[a-z0-9]{1,50}",
    )| {
        let entries = vec![SecretEntry::new(key.clone(), value.clone())];

        let project_id = ProjectId::new();
        let set_id = SecretSetId::new();
        let device_id = DeviceId::new();
        let version = VersionNumber::FIRST;
        let pdk_version = VersionNumber::FIRST;
        let pdk = generate_pdk().unwrap();

        // Generate keypair
        let (device_key, _) = generate_ed25519_keypair().unwrap();

        // Encrypt secrets
        let (_, content_hash, chain_hash) = encrypt_secrets(
            &entries,
            &project_id,
            &set_id,
            &version,
            &pdk_version,
            &pdk,
            None,
        ).unwrap();

        let created_at = OffsetDateTime::now_utc();

        // Sign twice with same metadata
        let signature1 = sign_version_metadata(
            &set_id,
            &version,
            &pdk_version,
            created_at,
            &device_id,
            None,
            &content_hash,
            &chain_hash,
            None,
            &device_key,
        ).unwrap();

        let signature2 = sign_version_metadata(
            &set_id,
            &version,
            &pdk_version,
            created_at,
            &device_id,
            None,
            &content_hash,
            &chain_hash,
            None,
            &device_key,
        ).unwrap();

        prop_assert_eq!(
            signature1,
            signature2,
            "Signatures should be deterministic for same metadata"
        );
    });
}

// ============================================================================
// Property 30: Tampering Breaks Verification
// ============================================================================

/// Feature: mycelium-cli, Property 30: Tampering Breaks Verification
///
/// For any version, tampering with ciphertext, content_hash, chain_hash, or signature
/// SHALL cause verification to fail.
///
/// **Validates: Requirements 8.5**
#[test]
fn property_tampering_breaks_verification() {
    use myc_core::ids::DeviceId;
    use myc_core::secret_set_ops::{
        decrypt_secrets, sign_version_metadata, verify_version_metadata,
    };
    use myc_crypto::sign::generate_ed25519_keypair;
    use time::OffsetDateTime;

    proptest!(|(
        // Generate random secret entries
        keys in prop::collection::vec("[A-Z_][A-Z0-9_]{0,19}", 1..10),
        values in prop::collection::vec("[a-z0-9]{1,50}", 1..10),
        tamper_byte_index in 0usize..100,
    )| {
        // Ensure we have matching keys and values
        let min_len = keys.len().min(values.len());
        let keys = &keys[..min_len];
        let values = &values[..min_len];

        // Create secret entries
        let entries: Vec<SecretEntry> = keys
            .iter()
            .zip(values.iter())
            .map(|(k, v)| SecretEntry::new(k.clone(), v.clone()))
            .collect();

        // Generate test data
        let project_id = ProjectId::new();
        let set_id = SecretSetId::new();
        let device_id = DeviceId::new();
        let version = VersionNumber::FIRST;
        let pdk_version = VersionNumber::FIRST;
        let pdk = generate_pdk().unwrap();

        // Generate device keypair
        let (device_key, device_pubkey) = generate_ed25519_keypair().unwrap();

        // Encrypt secrets
        let (ciphertext, content_hash, chain_hash) = encrypt_secrets(
            &entries,
            &project_id,
            &set_id,
            &version,
            &pdk_version,
            &pdk,
            None,
        ).unwrap();

        let created_at = OffsetDateTime::now_utc();

        // Sign the version metadata
        let signature = sign_version_metadata(
            &set_id,
            &version,
            &pdk_version,
            created_at,
            &device_id,
            None,
            &content_hash,
            &chain_hash,
            None,
            &device_key,
        ).unwrap();

        // Test 1: Tamper with ciphertext
        if ciphertext.len() > 0 {
            let mut tampered_ciphertext = ciphertext.clone();
            let tamper_index = tamper_byte_index % tampered_ciphertext.len();
            tampered_ciphertext[tamper_index] ^= 0xFF;

            let result = decrypt_secrets(
                &tampered_ciphertext,
                &project_id,
                &set_id,
                &version,
                &pdk_version,
                &pdk,
                &content_hash,
                &chain_hash,
                None,
            );

            prop_assert!(
                result.is_err(),
                "Decryption should fail with tampered ciphertext"
            );
        }

        // Test 2: Tamper with content_hash
        let mut tampered_content_hash_bytes = content_hash.as_bytes().to_vec();
        let tamper_index = tamper_byte_index % tampered_content_hash_bytes.len();
        tampered_content_hash_bytes[tamper_index] ^= 0xFF;
        let tampered_content_hash = myc_crypto::hash::HashOutput::from_bytes(
            tampered_content_hash_bytes.as_slice().try_into().unwrap()
        );

        let result = decrypt_secrets(
            &ciphertext,
            &project_id,
            &set_id,
            &version,
            &pdk_version,
            &pdk,
            &tampered_content_hash,
            &chain_hash,
            None,
        );

        prop_assert!(
            result.is_err(),
            "Decryption should fail with tampered content_hash"
        );

        // Test 3: Tamper with chain_hash
        let mut tampered_chain_hash_bytes = chain_hash.as_bytes().to_vec();
        let tamper_index = tamper_byte_index % tampered_chain_hash_bytes.len();
        tampered_chain_hash_bytes[tamper_index] ^= 0xFF;
        let tampered_chain_hash = myc_crypto::hash::HashOutput::from_bytes(
            tampered_chain_hash_bytes.as_slice().try_into().unwrap()
        );

        let result = decrypt_secrets(
            &ciphertext,
            &project_id,
            &set_id,
            &version,
            &pdk_version,
            &pdk,
            &content_hash,
            &tampered_chain_hash,
            None,
        );

        prop_assert!(
            result.is_err(),
            "Decryption should fail with tampered chain_hash"
        );

        // Test 4: Tamper with signature
        let mut tampered_signature_bytes = signature.as_bytes().to_vec();
        let tamper_index = tamper_byte_index % tampered_signature_bytes.len();
        tampered_signature_bytes[tamper_index] ^= 0xFF;
        let tampered_signature = myc_crypto::sign::Signature::from_bytes(
            tampered_signature_bytes.as_slice().try_into().unwrap()
        );

        let result = verify_version_metadata(
            &set_id,
            &version,
            &pdk_version,
            created_at,
            &device_id,
            None,
            &content_hash,
            &chain_hash,
            None,
            &tampered_signature,
            &device_pubkey,
        );

        prop_assert!(
            result.is_err(),
            "Signature verification should fail with tampered signature"
        );

        // Test 5: Verify that untampered data succeeds
        let result = decrypt_secrets(
            &ciphertext,
            &project_id,
            &set_id,
            &version,
            &pdk_version,
            &pdk,
            &content_hash,
            &chain_hash,
            None,
        );

        prop_assert!(
            result.is_ok(),
            "Decryption should succeed with untampered data"
        );

        let result = verify_version_metadata(
            &set_id,
            &version,
            &pdk_version,
            created_at,
            &device_id,
            None,
            &content_hash,
            &chain_hash,
            None,
            &signature,
            &device_pubkey,
        );

        prop_assert!(
            result.is_ok(),
            "Signature verification should succeed with untampered data"
        );
    });
}

/// Test tampering detection with chained versions
#[test]
fn property_tampering_breaks_verification_with_chain() {
    use myc_core::ids::DeviceId;
    use myc_core::secret_set_ops::{decrypt_secrets, sign_version_metadata};
    use myc_crypto::sign::generate_ed25519_keypair;
    use time::OffsetDateTime;

    proptest!(|(
        key1 in "[A-Z_][A-Z0-9_]{0,19}",
        value1 in "[a-z0-9]{1,50}",
        key2 in "[A-Z_][A-Z0-9_]{0,19}",
        value2 in "[a-z0-9]{1,50}",
    )| {
        let entries1 = vec![SecretEntry::new(key1.clone(), value1.clone())];
        let entries2 = vec![SecretEntry::new(key2.clone(), value2.clone())];

        let project_id = ProjectId::new();
        let set_id = SecretSetId::new();
        let device_id = DeviceId::new();
        let pdk_version = VersionNumber::FIRST;
        let pdk = generate_pdk().unwrap();

        // Generate device keypair
        let (device_key, _) = generate_ed25519_keypair().unwrap();

        // Create version 1
        let (ciphertext1, content_hash1, chain_hash1) = encrypt_secrets(
            &entries1,
            &project_id,
            &set_id,
            &VersionNumber::FIRST,
            &pdk_version,
            &pdk,
            None,
        ).unwrap();

        let created_at1 = OffsetDateTime::now_utc();

        let _signature1 = sign_version_metadata(
            &set_id,
            &VersionNumber::FIRST,
            &pdk_version,
            created_at1,
            &device_id,
            None,
            &content_hash1,
            &chain_hash1,
            None,
            &device_key,
        ).unwrap();

        // Create version 2 with chain
        let (ciphertext2, content_hash2, chain_hash2) = encrypt_secrets(
            &entries2,
            &project_id,
            &set_id,
            &VersionNumber::new(2),
            &pdk_version,
            &pdk,
            Some(&chain_hash1),  // Chain to version 1
        ).unwrap();

        // Test: Tamper with previous_chain_hash
        // Try to decrypt version 2 with wrong previous hash
        let wrong_previous_hash = myc_crypto::hash::hash(b"wrong previous hash");

        let result = decrypt_secrets(
            &ciphertext2,
            &project_id,
            &set_id,
            &VersionNumber::new(2),
            &pdk_version,
            &pdk,
            &content_hash2,
            &chain_hash2,
            Some(&wrong_previous_hash),  // Wrong previous hash!
        );

        prop_assert!(
            result.is_err(),
            "Decryption should fail with tampered previous_chain_hash"
        );

        // Verify that correct previous hash succeeds
        let result = decrypt_secrets(
            &ciphertext2,
            &project_id,
            &set_id,
            &VersionNumber::new(2),
            &pdk_version,
            &pdk,
            &content_hash2,
            &chain_hash2,
            Some(&chain_hash1),  // Correct previous hash
        );

        prop_assert!(
            result.is_ok(),
            "Decryption should succeed with correct previous_chain_hash"
        );
    });
}

/// Test that tampering with any single byte in ciphertext causes failure
#[test]
fn property_tampering_single_byte_ciphertext() {
    proptest!(|(
        key in "[A-Z_][A-Z0-9_]{0,19}",
        value in "[a-z0-9]{1,50}",
        byte_to_flip in 0u8..=255,
    )| {
        let entries = vec![SecretEntry::new(key.clone(), value.clone())];

        let project_id = ProjectId::new();
        let set_id = SecretSetId::new();
        let version = VersionNumber::FIRST;
        let pdk_version = VersionNumber::FIRST;
        let pdk = generate_pdk().unwrap();

        // Encrypt
        let (ciphertext, content_hash, chain_hash) = encrypt_secrets(
            &entries,
            &project_id,
            &set_id,
            &version,
            &pdk_version,
            &pdk,
            None,
        ).unwrap();

        // Tamper with each byte position
        for i in 0..ciphertext.len() {
            let mut tampered = ciphertext.clone();
            tampered[i] ^= byte_to_flip;

            // Skip if we didn't actually change anything
            if tampered == ciphertext {
                continue;
            }

            let result = decrypt_secrets(
                &tampered,
                &project_id,
                &set_id,
                &version,
                &pdk_version,
                &pdk,
                &content_hash,
                &chain_hash,
                None,
            );

            prop_assert!(
                result.is_err(),
                "Decryption should fail when byte {} is tampered", i
            );
        }
    });
}

/// Test tampering detection with metadata fields
#[test]
fn property_tampering_metadata_fields() {
    use myc_core::ids::DeviceId;
    use myc_core::secret_set_ops::{sign_version_metadata, verify_version_metadata};
    use myc_crypto::sign::generate_ed25519_keypair;
    use time::OffsetDateTime;

    proptest!(|(
        key in "[A-Z_][A-Z0-9_]{0,19}",
        value in "[a-z0-9]{1,50}",
        wrong_version_num in 2u64..100,
    )| {
        let entries = vec![SecretEntry::new(key.clone(), value.clone())];

        let project_id = ProjectId::new();
        let set_id = SecretSetId::new();
        let device_id = DeviceId::new();
        let version = VersionNumber::FIRST;
        let pdk_version = VersionNumber::FIRST;
        let pdk = generate_pdk().unwrap();

        // Generate device keypair
        let (device_key, device_pubkey) = generate_ed25519_keypair().unwrap();

        // Encrypt secrets
        let (_, content_hash, chain_hash) = encrypt_secrets(
            &entries,
            &project_id,
            &set_id,
            &version,
            &pdk_version,
            &pdk,
            None,
        ).unwrap();

        let created_at = OffsetDateTime::now_utc();

        // Sign with correct version
        let signature = sign_version_metadata(
            &set_id,
            &version,
            &pdk_version,
            created_at,
            &device_id,
            None,
            &content_hash,
            &chain_hash,
            None,
            &device_key,
        ).unwrap();

        // Try to verify with different version number (metadata tampering)
        let wrong_version = VersionNumber::new(wrong_version_num);
        let result = verify_version_metadata(
            &set_id,
            &wrong_version,  // Tampered!
            &pdk_version,
            created_at,
            &device_id,
            None,
            &content_hash,
            &chain_hash,
            None,
            &signature,
            &device_pubkey,
        );

        prop_assert!(
            result.is_err(),
            "Signature verification should fail with tampered version number"
        );

        // Try to verify with different device_id (metadata tampering)
        let wrong_device_id = DeviceId::new();
        let result = verify_version_metadata(
            &set_id,
            &version,
            &pdk_version,
            created_at,
            &wrong_device_id,  // Tampered!
            None,
            &content_hash,
            &chain_hash,
            None,
            &signature,
            &device_pubkey,
        );

        prop_assert!(
            result.is_err(),
            "Signature verification should fail with tampered device_id"
        );
    });
}

/// Test that tampering is detected even with valid-looking data
#[test]
fn property_tampering_with_valid_looking_data() {
    proptest!(|(
        key1 in "[A-Z_][A-Z0-9_]{0,19}",
        value1 in "[a-z0-9]{1,50}",
        key2 in "[A-Z_][A-Z0-9_]{0,19}",
        value2 in "[a-z0-9]{1,50}",
    )| {
        // Skip if entries would be identical
        if key1 == key2 && value1 == value2 {
            return Ok(());
        }

        let entries1 = vec![SecretEntry::new(key1.clone(), value1.clone())];
        let entries2 = vec![SecretEntry::new(key2.clone(), value2.clone())];

        let project_id = ProjectId::new();
        let set_id = SecretSetId::new();
        let version = VersionNumber::FIRST;
        let pdk_version = VersionNumber::FIRST;
        let pdk = generate_pdk().unwrap();

        // Encrypt both sets
        let (ciphertext1, content_hash1, chain_hash1) = encrypt_secrets(
            &entries1,
            &project_id,
            &set_id,
            &version,
            &pdk_version,
            &pdk,
            None,
        ).unwrap();

        let (_, content_hash2, _) = encrypt_secrets(
            &entries2,
            &project_id,
            &set_id,
            &version,
            &pdk_version,
            &pdk,
            None,
        ).unwrap();

        // Try to decrypt ciphertext1 with content_hash2 (substitution attack)
        let result = decrypt_secrets(
            &ciphertext1,
            &project_id,
            &set_id,
            &version,
            &pdk_version,
            &pdk,
            &content_hash2,  // Wrong hash from different data!
            &chain_hash1,
            None,
        );

        prop_assert!(
            result.is_err(),
            "Decryption should fail when content_hash is substituted with another valid hash"
        );
    });
}

// ============================================================================
// Property 31: Size Limit Enforcement
// ============================================================================

/// Feature: mycelium-cli, Property 31: Size Limit Enforcement
///
/// For any secret set exceeding 10MB plaintext, the system SHALL reject it.
///
/// **Validates: Requirements 8.7**
#[test]
fn property_size_limit_enforcement() {
    proptest!(ProptestConfig::with_cases(10), |(
        // Generate random offsets to test boundaries
        entry_count_offset in 1usize..10,
        key_length_offset in 1usize..10,
        value_length_offset in 1usize..100,
    )| {
        // Test 1: Entry count limit
        // Generate entries that exceed MAX_ENTRIES
        let entries: Vec<SecretEntry> = (0..MAX_ENTRIES + entry_count_offset)
            .map(|i| SecretEntry::new(format!("KEY_{}", i), "value".to_string()))
            .collect();

        let result = validate_size_limits(&entries);

        prop_assert!(
            result.is_err(),
            "Should reject secret sets with more than {} entries", MAX_ENTRIES
        );

        if let Err(CoreError::SizeLimitExceeded { size, max }) = result {
            prop_assert_eq!(size, MAX_ENTRIES + entry_count_offset, "Error should report correct size");
            prop_assert_eq!(max, MAX_ENTRIES, "Error should report correct max");
        } else {
            prop_assert!(false, "Should return SizeLimitExceeded error");
        }

        // Test 2: Key length limit
        // Generate a key that exceeds MAX_KEY_LENGTH
        let long_key = "A".repeat(MAX_KEY_LENGTH + key_length_offset);
        let entries = vec![SecretEntry::new(long_key.clone(), "value".to_string())];

        let result = validate_size_limits(&entries);

        prop_assert!(
            result.is_err(),
            "Should reject keys longer than {} characters", MAX_KEY_LENGTH
        );

        if let Err(CoreError::SizeLimitExceeded { size, max }) = result {
            prop_assert_eq!(size, MAX_KEY_LENGTH + key_length_offset, "Error should report correct key size");
            prop_assert_eq!(max, MAX_KEY_LENGTH, "Error should report correct max key length");
        } else {
            prop_assert!(false, "Should return SizeLimitExceeded error for long key");
        }

        // Test 3: Value length limit
        // Generate a value that exceeds MAX_VALUE_LENGTH
        let long_value = "B".repeat(MAX_VALUE_LENGTH + value_length_offset);
        let entries = vec![SecretEntry::new("KEY".to_string(), long_value.clone())];

        let result = validate_size_limits(&entries);

        prop_assert!(
            result.is_err(),
            "Should reject values longer than {} bytes", MAX_VALUE_LENGTH
        );

        if let Err(CoreError::SizeLimitExceeded { size, max }) = result {
            prop_assert_eq!(size, MAX_VALUE_LENGTH + value_length_offset, "Error should report correct value size");
            prop_assert_eq!(max, MAX_VALUE_LENGTH, "Error should report correct max value length");
        } else {
            prop_assert!(false, "Should return SizeLimitExceeded error for long value");
        }

        // Test 4: Total plaintext size limit
        // Create entries that together exceed MAX_PLAINTEXT_SIZE
        // Each entry is 1MB, so 11 entries will exceed 10MB
        let large_value = "C".repeat(MAX_VALUE_LENGTH); // 1MB each
        let entries: Vec<SecretEntry> = (0..11)
            .map(|i| SecretEntry::new(format!("KEY_{}", i), large_value.clone()))
            .collect();

        let result = validate_size_limits(&entries);

        prop_assert!(
            result.is_err(),
            "Should reject secret sets exceeding {} bytes total plaintext", MAX_PLAINTEXT_SIZE
        );

        if let Err(CoreError::SizeLimitExceeded { size, max }) = result {
            prop_assert!(size > MAX_PLAINTEXT_SIZE, "Error should report size exceeding limit");
            prop_assert_eq!(max, MAX_PLAINTEXT_SIZE, "Error should report correct max plaintext size");
        } else {
            prop_assert!(false, "Should return SizeLimitExceeded error for large plaintext");
        }
    });
}

/// Test size limit enforcement at exact boundaries
#[test]
fn property_size_limit_enforcement_boundaries() {
    // Test 1: Exactly MAX_ENTRIES should succeed
    let entries: Vec<SecretEntry> = (0..MAX_ENTRIES)
        .map(|i| SecretEntry::new(format!("KEY_{}", i), "value".to_string()))
        .collect();

    let result = validate_size_limits(&entries);
    assert!(
        result.is_ok(),
        "Should accept exactly {} entries",
        MAX_ENTRIES
    );

    // Test 2: MAX_ENTRIES + 1 should fail
    let entries: Vec<SecretEntry> = (0..MAX_ENTRIES + 1)
        .map(|i| SecretEntry::new(format!("KEY_{}", i), "value".to_string()))
        .collect();

    let result = validate_size_limits(&entries);
    assert!(result.is_err(), "Should reject {} entries", MAX_ENTRIES + 1);

    // Test 3: Exactly MAX_KEY_LENGTH should succeed
    let key_at_limit = "A".repeat(MAX_KEY_LENGTH);
    let entries = vec![SecretEntry::new(key_at_limit, "value".to_string())];

    let result = validate_size_limits(&entries);
    assert!(
        result.is_ok(),
        "Should accept key with exactly {} characters",
        MAX_KEY_LENGTH
    );

    // Test 4: MAX_KEY_LENGTH + 1 should fail
    let key_over_limit = "A".repeat(MAX_KEY_LENGTH + 1);
    let entries = vec![SecretEntry::new(key_over_limit, "value".to_string())];

    let result = validate_size_limits(&entries);
    assert!(
        result.is_err(),
        "Should reject key with {} characters",
        MAX_KEY_LENGTH + 1
    );

    // Test 5: Exactly MAX_VALUE_LENGTH should succeed
    let value_at_limit = "B".repeat(MAX_VALUE_LENGTH);
    let entries = vec![SecretEntry::new("KEY".to_string(), value_at_limit)];

    let result = validate_size_limits(&entries);
    assert!(
        result.is_ok(),
        "Should accept value with exactly {} bytes",
        MAX_VALUE_LENGTH
    );

    // Test 6: MAX_VALUE_LENGTH + 1 should fail
    let value_over_limit = "B".repeat(MAX_VALUE_LENGTH + 1);
    let entries = vec![SecretEntry::new("KEY".to_string(), value_over_limit)];

    let result = validate_size_limits(&entries);
    assert!(
        result.is_err(),
        "Should reject value with {} bytes",
        MAX_VALUE_LENGTH + 1
    );
}

/// Test that size limits are enforced before encryption
#[test]
fn property_size_limit_enforcement_before_encryption() {
    proptest!(ProptestConfig::with_cases(5), |(
        num_large_entries in 11usize..15,
    )| {
        // Create entries that exceed total plaintext size
        let large_value = "D".repeat(MAX_VALUE_LENGTH); // 1MB each
        let entries: Vec<SecretEntry> = (0..num_large_entries)
            .map(|i| SecretEntry::new(format!("KEY_{}", i), large_value.clone()))
            .collect();

        // Validate size limits - should fail
        let result = validate_size_limits(&entries);

        prop_assert!(
            result.is_err(),
            "Validation should fail when plaintext exceeds size limit"
        );

        if let Err(CoreError::SizeLimitExceeded { size, max }) = result {
            prop_assert!(size > MAX_PLAINTEXT_SIZE, "Error should report size exceeding limit");
            prop_assert_eq!(max, MAX_PLAINTEXT_SIZE, "Error should report correct max");
        } else {
            prop_assert!(false, "Should return SizeLimitExceeded error");
        }

        // Note: encrypt_secrets itself doesn't validate size limits.
        // The validation is done by create_version before calling encrypt_secrets.
        // This is by design to allow encrypt_secrets to be a pure crypto operation.
    });
}

/// Test that valid sizes within limits are accepted
#[test]
fn property_size_limit_enforcement_accepts_valid_sizes() {
    proptest!(|(
        num_entries in 1usize..100,
        key_length in 1usize..50,
        value_length in 1usize..1000,
    )| {
        // Generate entries well within limits
        let entries: Vec<SecretEntry> = (0..num_entries)
            .map(|i| {
                let key = format!("KEY_{}", i);
                let value = "v".repeat(value_length);
                SecretEntry::new(key, value)
            })
            .collect();

        // Only test if within all limits
        let total_size = serialize_secrets(&entries).unwrap().len();
        if entries.len() <= MAX_ENTRIES
            && entries.iter().all(|e| e.key.len() <= MAX_KEY_LENGTH)
            && entries.iter().all(|e| e.value.len() <= MAX_VALUE_LENGTH)
            && total_size <= MAX_PLAINTEXT_SIZE
        {
            let result = validate_size_limits(&entries);

            prop_assert!(
                result.is_ok(),
                "Should accept entries within all size limits"
            );

            // Also verify encryption succeeds
            let project_id = ProjectId::new();
            let set_id = SecretSetId::new();
            let pdk = generate_pdk().unwrap();

            let result = encrypt_secrets(
                &entries,
                &project_id,
                &set_id,
                &VersionNumber::FIRST,
                &VersionNumber::FIRST,
                &pdk,
                None,
            );

            prop_assert!(
                result.is_ok(),
                "Encryption should succeed for entries within size limits"
            );
        }
    });
}

/// Test that size limits are checked for each individual entry
#[test]
fn property_size_limit_enforcement_per_entry() {
    proptest!(|(
        valid_entries_count in 1usize..10,
        invalid_entry_position in 0usize..10,
    )| {
        let invalid_entry_position = invalid_entry_position % (valid_entries_count + 1);

        // Create a mix of valid and one invalid entry
        let mut entries: Vec<SecretEntry> = (0..valid_entries_count)
            .map(|i| SecretEntry::new(format!("KEY_{}", i), "valid_value".to_string()))
            .collect();

        // Insert an invalid entry (key too long) at random position
        let invalid_key = "X".repeat(MAX_KEY_LENGTH + 1);
        entries.insert(
            invalid_entry_position,
            SecretEntry::new(invalid_key, "value".to_string())
        );

        let result = validate_size_limits(&entries);

        prop_assert!(
            result.is_err(),
            "Should reject if any single entry violates size limits"
        );

        if let Err(CoreError::SizeLimitExceeded { size, max }) = result {
            prop_assert_eq!(size, MAX_KEY_LENGTH + 1, "Error should report the invalid key size");
            prop_assert_eq!(max, MAX_KEY_LENGTH, "Error should report correct max key length");
        } else {
            prop_assert!(false, "Should return SizeLimitExceeded error");
        }
    });
}

/// Test size limit enforcement with empty entries
#[test]
fn property_size_limit_enforcement_empty() {
    // Empty entries list should be valid
    let entries: Vec<SecretEntry> = vec![];

    let result = validate_size_limits(&entries);
    assert!(result.is_ok(), "Should accept empty entries list");

    // Empty entries should also encrypt successfully
    let project_id = ProjectId::new();
    let set_id = SecretSetId::new();
    let pdk = generate_pdk().unwrap();

    let result = encrypt_secrets(
        &entries,
        &project_id,
        &set_id,
        &VersionNumber::FIRST,
        &VersionNumber::FIRST,
        &pdk,
        None,
    );

    assert!(
        result.is_ok(),
        "Encryption should succeed for empty entries"
    );
}

/// Test that size limit errors contain useful information
#[test]
fn property_size_limit_enforcement_error_details() {
    // Test entry count error
    let entries: Vec<SecretEntry> = (0..MAX_ENTRIES + 100)
        .map(|i| SecretEntry::new(format!("KEY_{}", i), "value".to_string()))
        .collect();

    let result = validate_size_limits(&entries);

    match result {
        Err(CoreError::SizeLimitExceeded { size, max }) => {
            assert_eq!(size, MAX_ENTRIES + 100, "Should report actual entry count");
            assert_eq!(max, MAX_ENTRIES, "Should report max entry count");
        }
        _ => panic!("Should return SizeLimitExceeded error with correct details"),
    }

    // Test key length error
    let long_key = "K".repeat(MAX_KEY_LENGTH + 50);
    let entries = vec![SecretEntry::new(long_key, "value".to_string())];

    let result = validate_size_limits(&entries);

    match result {
        Err(CoreError::SizeLimitExceeded { size, max }) => {
            assert_eq!(size, MAX_KEY_LENGTH + 50, "Should report actual key length");
            assert_eq!(max, MAX_KEY_LENGTH, "Should report max key length");
        }
        _ => panic!("Should return SizeLimitExceeded error with correct details"),
    }

    // Test value length error
    let long_value = "V".repeat(MAX_VALUE_LENGTH + 100);
    let entries = vec![SecretEntry::new("KEY".to_string(), long_value)];

    let result = validate_size_limits(&entries);

    match result {
        Err(CoreError::SizeLimitExceeded { size, max }) => {
            assert_eq!(
                size,
                MAX_VALUE_LENGTH + 100,
                "Should report actual value length"
            );
            assert_eq!(max, MAX_VALUE_LENGTH, "Should report max value length");
        }
        _ => panic!("Should return SizeLimitExceeded error with correct details"),
    }
}
