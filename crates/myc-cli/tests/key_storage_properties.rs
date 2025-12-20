//! Property-based tests for device key encryption and storage.
//!
//! These tests verify that device keys can be encrypted and decrypted correctly
//! using Argon2id-derived keys from user passphrases.
//!
//! Note: Due to Argon2id's computational cost (64MB memory, 3 iterations, 4 threads),
//! we use a small number of concrete test cases rather than extensive property-based
//! testing to keep test execution time reasonable.

use myc_cli::key_storage::{
    load_encrypted_key, load_encryption_key, load_signing_key, save_encrypted_key,
    save_encryption_keypair, save_signing_keypair,
};
use myc_crypto::kex::generate_x25519_keypair;
use myc_crypto::random::generate_random_bytes;
use myc_crypto::sign::generate_ed25519_keypair;
use tempfile::TempDir;

// ============================================================================
// Property 16: Device Key Encryption Roundtrip
// ============================================================================

/// Feature: mycelium-cli, Property 16: Device Key Encryption Roundtrip
///
/// For any device keys and passphrase, encrypting then decrypting with the same
/// passphrase SHALL recover the original keys.
///
/// **Validates: Requirements 5.2**
#[test]
fn property_device_key_encryption_roundtrip() {
    // Test with multiple passphrases to verify the property holds
    let test_passphrases = vec!["simple123", "LongerPassphrase456", "with-special!@#chars"];

    for passphrase in test_passphrases {
        let temp_dir = TempDir::new().unwrap();

        // Test with raw key material (32 bytes)
        let original_key = generate_random_bytes::<32>().unwrap();
        let key_path = temp_dir.path().join("test.key");

        // Save encrypted key
        save_encrypted_key(&key_path, &original_key, passphrase).unwrap();

        // Load and decrypt key
        let decrypted_key = load_encrypted_key(&key_path, passphrase).unwrap();

        // Verify roundtrip
        assert_eq!(
            &original_key[..],
            &decrypted_key[..],
            "Decrypted key should match original key for passphrase: {}",
            passphrase
        );
    }
}

/// Test signing keypair encryption roundtrip
#[test]
fn property_signing_keypair_encryption_roundtrip() {
    let test_passphrases = vec!["test123", "another456"];

    for passphrase in test_passphrases {
        let temp_dir = TempDir::new().unwrap();
        let secret_path = temp_dir.path().join("signing.key");
        let public_path = temp_dir.path().join("signing.pub");

        // Generate keypair
        let (secret_key, public_key) = generate_ed25519_keypair().unwrap();

        // Save keypair
        save_signing_keypair(
            &secret_path,
            &public_path,
            &secret_key,
            &public_key,
            passphrase,
        )
        .unwrap();

        // Load secret key
        let loaded_key = load_signing_key(&secret_path, passphrase).unwrap();

        // Verify they're the same by comparing the bytes
        assert_eq!(
            secret_key.to_bytes(),
            loaded_key.to_bytes(),
            "Loaded signing key should match original for passphrase: {}",
            passphrase
        );
    }
}

/// Test encryption keypair encryption roundtrip
#[test]
fn property_encryption_keypair_encryption_roundtrip() {
    let test_passphrases = vec!["test123", "another456"];

    for passphrase in test_passphrases {
        let temp_dir = TempDir::new().unwrap();
        let secret_path = temp_dir.path().join("encryption.key");
        let public_path = temp_dir.path().join("encryption.pub");

        // Generate keypair
        let (secret_key, public_key) = generate_x25519_keypair().unwrap();

        // Save keypair
        save_encryption_keypair(
            &secret_path,
            &public_path,
            &secret_key,
            &public_key,
            passphrase,
        )
        .unwrap();

        // Load secret key
        let loaded_key = load_encryption_key(&secret_path, passphrase).unwrap();

        // Verify they're the same by comparing the bytes
        assert_eq!(
            secret_key.to_bytes(),
            loaded_key.to_bytes(),
            "Loaded encryption key should match original for passphrase: {}",
            passphrase
        );
    }
}

/// Test that different passphrases produce different ciphertexts
#[test]
fn property_different_passphrases_produce_different_ciphertexts() {
    let temp_dir = TempDir::new().unwrap();
    let key_path1 = temp_dir.path().join("test1.key");
    let key_path2 = temp_dir.path().join("test2.key");

    // Same key material
    let key_material = generate_random_bytes::<32>().unwrap();

    let passphrase1 = "password1";
    let passphrase2 = "password2";

    // Encrypt with different passphrases
    save_encrypted_key(&key_path1, &key_material, passphrase1).unwrap();
    save_encrypted_key(&key_path2, &key_material, passphrase2).unwrap();

    // Read the encrypted files
    let encrypted1 = std::fs::read_to_string(&key_path1).unwrap();
    let encrypted2 = std::fs::read_to_string(&key_path2).unwrap();

    // The encrypted files should be different (different salts and ciphertexts)
    assert_ne!(
        encrypted1, encrypted2,
        "Different passphrases should produce different encrypted files"
    );

    // But both should decrypt to the same key
    let decrypted1 = load_encrypted_key(&key_path1, passphrase1).unwrap();
    let decrypted2 = load_encrypted_key(&key_path2, passphrase2).unwrap();

    assert_eq!(
        &decrypted1[..],
        &decrypted2[..],
        "Both should decrypt to the same original key"
    );
}

/// Test that encrypting the same key twice produces different ciphertexts (due to random salt)
#[test]
fn property_same_key_different_encryptions() {
    let temp_dir = TempDir::new().unwrap();
    let key_path1 = temp_dir.path().join("test1.key");
    let key_path2 = temp_dir.path().join("test2.key");

    // Same key material and passphrase
    let key_material = generate_random_bytes::<32>().unwrap();
    let passphrase = "samepassword";

    // Encrypt twice with same passphrase
    save_encrypted_key(&key_path1, &key_material, passphrase).unwrap();
    save_encrypted_key(&key_path2, &key_material, passphrase).unwrap();

    // Read the encrypted files
    let encrypted1 = std::fs::read_to_string(&key_path1).unwrap();
    let encrypted2 = std::fs::read_to_string(&key_path2).unwrap();

    // The encrypted files should be different (different random salts)
    assert_ne!(
        encrypted1, encrypted2,
        "Same key encrypted twice should produce different ciphertexts (random salt)"
    );

    // But both should decrypt to the same key
    let decrypted1 = load_encrypted_key(&key_path1, passphrase).unwrap();
    let decrypted2 = load_encrypted_key(&key_path2, passphrase).unwrap();

    assert_eq!(
        &decrypted1[..],
        &decrypted2[..],
        "Both should decrypt to the same original key"
    );
    assert_eq!(
        &key_material[..],
        &decrypted1[..],
        "Decrypted key should match original"
    );
}

/// Test with various key sizes (not just 32 bytes)
#[test]
fn property_various_key_sizes() {
    let test_sizes = vec![16, 32, 64, 128];
    let passphrase = "testpass";

    for key_size in test_sizes {
        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("test.key");

        // Generate random key material of specified size
        let mut key_material = vec![0u8; key_size];
        let _ = myc_crypto::random::fill_random(&mut key_material);

        // Save encrypted key
        save_encrypted_key(&key_path, &key_material, passphrase).unwrap();

        // Load and decrypt key
        let decrypted_key = load_encrypted_key(&key_path, passphrase).unwrap();

        // Verify roundtrip
        assert_eq!(
            key_material.len(),
            decrypted_key.len(),
            "Decrypted key should have same length as original for size {}",
            key_size
        );
        assert_eq!(
            &key_material[..],
            &decrypted_key[..],
            "Decrypted key should match original key for size {}",
            key_size
        );
    }
}

/// Test with empty passphrase (edge case)
#[test]
fn property_empty_passphrase() {
    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("test.key");

    let key_material = generate_random_bytes::<32>().unwrap();
    let passphrase = "";

    // Save encrypted key with empty passphrase
    save_encrypted_key(&key_path, &key_material, passphrase).unwrap();

    // Load and decrypt key with empty passphrase
    let decrypted_key = load_encrypted_key(&key_path, passphrase).unwrap();

    // Verify roundtrip
    assert_eq!(&key_material[..], &decrypted_key[..]);
}

/// Test with very long passphrase (edge case)
#[test]
fn property_very_long_passphrase() {
    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("test.key");

    let key_material = generate_random_bytes::<32>().unwrap();
    // Create a very long passphrase (1000 characters)
    let passphrase = "a".repeat(1000);

    // Save encrypted key with very long passphrase
    save_encrypted_key(&key_path, &key_material, &passphrase).unwrap();

    // Load and decrypt key with same long passphrase
    let decrypted_key = load_encrypted_key(&key_path, &passphrase).unwrap();

    // Verify roundtrip
    assert_eq!(&key_material[..], &decrypted_key[..]);
}

/// Test with special characters in passphrase
#[test]
fn property_special_characters_passphrase() {
    let test_passphrases = vec!["pass!@#$%^&*()", "with spaces in it", "unicode-café-🔐"];

    for passphrase in test_passphrases {
        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("test.key");

        let key_material = generate_random_bytes::<32>().unwrap();

        // Save encrypted key
        save_encrypted_key(&key_path, &key_material, passphrase).unwrap();

        // Load and decrypt key
        let decrypted_key = load_encrypted_key(&key_path, passphrase).unwrap();

        // Verify roundtrip
        assert_eq!(
            &key_material[..],
            &decrypted_key[..],
            "Decrypted key should match original key with special character passphrase: {}",
            passphrase
        );
    }
}
