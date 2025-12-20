//! Property-based tests for profile isolation.
//!
//! These tests verify that profiles are properly isolated from each other,
//! with independent device keys and separate storage.

use myc_cli::key_storage::{
    load_encryption_key, load_signing_key, save_encryption_keypair, save_signing_keypair,
};
use myc_cli::profile::{Profile, ProfileManager};
use myc_core::ids::DeviceId;
use myc_crypto::kex::generate_x25519_keypair;
use myc_crypto::sign::generate_ed25519_keypair;
use tempfile::TempDir;
use time::OffsetDateTime;

/// Helper function to create a test profile with a given name
fn create_test_profile(name: &str) -> Profile {
    Profile {
        name: name.to_string(),
        github_owner: format!("{}-owner", name),
        github_repo: format!("{}-vault", name),
        github_user_id: 12345,
        github_username: format!("{}-user", name),
        device_id: DeviceId::new(),
        created_at: OffsetDateTime::now_utc(),
    }
}

// ============================================================================
// Property 18: Profile Isolation
// ============================================================================

/// Feature: mycelium-cli, Property 18: Profile Isolation
///
/// For any two profiles, they SHALL have independent device keys and cannot
/// access each other's keys.
///
/// **Validates: Requirements 5.6**
#[test]
fn property_profile_isolation() {
    let temp_dir = TempDir::new().unwrap();
    let manager = ProfileManager::new(temp_dir.path().to_path_buf());

    // Create two profiles
    let profile1 = create_test_profile("profile1");
    let profile2 = create_test_profile("profile2");

    manager.create_profile(&profile1).unwrap();
    manager.create_profile(&profile2).unwrap();

    // Generate independent keypairs for each profile
    let (signing_key1, signing_pub1) = generate_ed25519_keypair().unwrap();
    let (encryption_key1, encryption_pub1) = generate_x25519_keypair().unwrap();

    let (signing_key2, signing_pub2) = generate_ed25519_keypair().unwrap();
    let (encryption_key2, encryption_pub2) = generate_x25519_keypair().unwrap();

    let passphrase1 = "passphrase-for-profile1";
    let passphrase2 = "passphrase-for-profile2";

    // Save keys for profile1
    let signing_secret_path1 = manager.signing_key_path(&profile1.name);
    let signing_public_path1 = manager.signing_pubkey_path(&profile1.name);
    save_signing_keypair(
        &signing_secret_path1,
        &signing_public_path1,
        &signing_key1,
        &signing_pub1,
        passphrase1,
    )
    .unwrap();

    let encryption_secret_path1 = manager.encryption_key_path(&profile1.name);
    let encryption_public_path1 = manager.encryption_pubkey_path(&profile1.name);
    save_encryption_keypair(
        &encryption_secret_path1,
        &encryption_public_path1,
        &encryption_key1,
        &encryption_pub1,
        passphrase1,
    )
    .unwrap();

    // Save keys for profile2
    let signing_secret_path2 = manager.signing_key_path(&profile2.name);
    let signing_public_path2 = manager.signing_pubkey_path(&profile2.name);
    save_signing_keypair(
        &signing_secret_path2,
        &signing_public_path2,
        &signing_key2,
        &signing_pub2,
        passphrase2,
    )
    .unwrap();

    let encryption_secret_path2 = manager.encryption_key_path(&profile2.name);
    let encryption_public_path2 = manager.encryption_pubkey_path(&profile2.name);
    save_encryption_keypair(
        &encryption_secret_path2,
        &encryption_public_path2,
        &encryption_key2,
        &encryption_pub2,
        passphrase2,
    )
    .unwrap();

    // Verify profile1 can load its own keys
    let loaded_signing1 = load_signing_key(&signing_secret_path1, passphrase1).unwrap();
    let loaded_encryption1 = load_encryption_key(&encryption_secret_path1, passphrase1).unwrap();

    assert_eq!(
        signing_key1.to_bytes(),
        loaded_signing1.to_bytes(),
        "Profile1 should be able to load its own signing key"
    );
    assert_eq!(
        encryption_key1.to_bytes(),
        loaded_encryption1.to_bytes(),
        "Profile1 should be able to load its own encryption key"
    );

    // Verify profile2 can load its own keys
    let loaded_signing2 = load_signing_key(&signing_secret_path2, passphrase2).unwrap();
    let loaded_encryption2 = load_encryption_key(&encryption_secret_path2, passphrase2).unwrap();

    assert_eq!(
        signing_key2.to_bytes(),
        loaded_signing2.to_bytes(),
        "Profile2 should be able to load its own signing key"
    );
    assert_eq!(
        encryption_key2.to_bytes(),
        loaded_encryption2.to_bytes(),
        "Profile2 should be able to load its own encryption key"
    );

    // Verify the keys are different between profiles
    assert_ne!(
        signing_key1.to_bytes(),
        signing_key2.to_bytes(),
        "Signing keys should be different between profiles"
    );
    assert_ne!(
        encryption_key1.to_bytes(),
        encryption_key2.to_bytes(),
        "Encryption keys should be different between profiles"
    );

    // Verify profile1's passphrase cannot decrypt profile2's keys
    let result = load_signing_key(&signing_secret_path2, passphrase1);
    assert!(
        result.is_err(),
        "Profile1's passphrase should not decrypt profile2's signing key"
    );

    let result = load_encryption_key(&encryption_secret_path2, passphrase1);
    assert!(
        result.is_err(),
        "Profile1's passphrase should not decrypt profile2's encryption key"
    );

    // Verify profile2's passphrase cannot decrypt profile1's keys
    let result = load_signing_key(&signing_secret_path1, passphrase2);
    assert!(
        result.is_err(),
        "Profile2's passphrase should not decrypt profile1's signing key"
    );

    let result = load_encryption_key(&encryption_secret_path1, passphrase2);
    assert!(
        result.is_err(),
        "Profile2's passphrase should not decrypt profile1's encryption key"
    );
}

/// Test that profiles have separate directory structures
#[test]
fn property_profile_separate_directories() {
    let temp_dir = TempDir::new().unwrap();
    let manager = ProfileManager::new(temp_dir.path().to_path_buf());

    // Create multiple profiles
    let profile1 = create_test_profile("profile1");
    let profile2 = create_test_profile("profile2");
    let profile3 = create_test_profile("profile3");

    manager.create_profile(&profile1).unwrap();
    manager.create_profile(&profile2).unwrap();
    manager.create_profile(&profile3).unwrap();

    // Verify each profile has its own directory structure
    let keys_dir1 = manager.keys_dir(&profile1.name);
    let keys_dir2 = manager.keys_dir(&profile2.name);
    let keys_dir3 = manager.keys_dir(&profile3.name);

    assert!(keys_dir1.exists(), "Profile1 keys directory should exist");
    assert!(keys_dir2.exists(), "Profile2 keys directory should exist");
    assert!(keys_dir3.exists(), "Profile3 keys directory should exist");

    // Verify directories are different
    assert_ne!(
        keys_dir1, keys_dir2,
        "Profile1 and Profile2 should have different keys directories"
    );
    assert_ne!(
        keys_dir2, keys_dir3,
        "Profile2 and Profile3 should have different keys directories"
    );
    assert_ne!(
        keys_dir1, keys_dir3,
        "Profile1 and Profile3 should have different keys directories"
    );

    // Verify cache directories are also separate
    let cache_dir1 = manager.cache_dir(&profile1.name);
    let cache_dir2 = manager.cache_dir(&profile2.name);
    let cache_dir3 = manager.cache_dir(&profile3.name);

    assert!(cache_dir1.exists(), "Profile1 cache directory should exist");
    assert!(cache_dir2.exists(), "Profile2 cache directory should exist");
    assert!(cache_dir3.exists(), "Profile3 cache directory should exist");

    assert_ne!(
        cache_dir1, cache_dir2,
        "Profile1 and Profile2 should have different cache directories"
    );
    assert_ne!(
        cache_dir2, cache_dir3,
        "Profile2 and Profile3 should have different cache directories"
    );
    assert_ne!(
        cache_dir1, cache_dir3,
        "Profile1 and Profile3 should have different cache directories"
    );
}

/// Test that deleting one profile doesn't affect another
#[test]
fn property_profile_deletion_isolation() {
    let temp_dir = TempDir::new().unwrap();
    let manager = ProfileManager::new(temp_dir.path().to_path_buf());

    // Create two profiles
    let profile1 = create_test_profile("profile1");
    let profile2 = create_test_profile("profile2");

    manager.create_profile(&profile1).unwrap();
    manager.create_profile(&profile2).unwrap();

    // Save keys for both profiles
    let (signing_key1, signing_pub1) = generate_ed25519_keypair().unwrap();
    let (encryption_key1, encryption_pub1) = generate_x25519_keypair().unwrap();
    let passphrase1 = "passphrase1";

    save_signing_keypair(
        &manager.signing_key_path(&profile1.name),
        &manager.signing_pubkey_path(&profile1.name),
        &signing_key1,
        &signing_pub1,
        passphrase1,
    )
    .unwrap();

    save_encryption_keypair(
        &manager.encryption_key_path(&profile1.name),
        &manager.encryption_pubkey_path(&profile1.name),
        &encryption_key1,
        &encryption_pub1,
        passphrase1,
    )
    .unwrap();

    let (signing_key2, signing_pub2) = generate_ed25519_keypair().unwrap();
    let (encryption_key2, encryption_pub2) = generate_x25519_keypair().unwrap();
    let passphrase2 = "passphrase2";

    save_signing_keypair(
        &manager.signing_key_path(&profile2.name),
        &manager.signing_pubkey_path(&profile2.name),
        &signing_key2,
        &signing_pub2,
        passphrase2,
    )
    .unwrap();

    save_encryption_keypair(
        &manager.encryption_key_path(&profile2.name),
        &manager.encryption_pubkey_path(&profile2.name),
        &encryption_key2,
        &encryption_pub2,
        passphrase2,
    )
    .unwrap();

    // Delete profile1
    manager.delete_profile(&profile1.name).unwrap();

    // Verify profile1 is gone
    assert!(
        manager.get_profile(&profile1.name).is_err(),
        "Profile1 should be deleted"
    );
    assert!(
        !manager.keys_dir(&profile1.name).exists(),
        "Profile1 keys directory should be deleted"
    );

    // Verify profile2 still exists and its keys are intact
    assert!(
        manager.get_profile(&profile2.name).is_ok(),
        "Profile2 should still exist"
    );

    let loaded_signing2 =
        load_signing_key(&manager.signing_key_path(&profile2.name), passphrase2).unwrap();
    let loaded_encryption2 =
        load_encryption_key(&manager.encryption_key_path(&profile2.name), passphrase2).unwrap();

    assert_eq!(
        signing_key2.to_bytes(),
        loaded_signing2.to_bytes(),
        "Profile2's signing key should still be accessible after profile1 deletion"
    );
    assert_eq!(
        encryption_key2.to_bytes(),
        loaded_encryption2.to_bytes(),
        "Profile2's encryption key should still be accessible after profile1 deletion"
    );
}

/// Test that profiles with the same passphrase still have independent keys
#[test]
fn property_profile_isolation_same_passphrase() {
    let temp_dir = TempDir::new().unwrap();
    let manager = ProfileManager::new(temp_dir.path().to_path_buf());

    // Create two profiles
    let profile1 = create_test_profile("profile1");
    let profile2 = create_test_profile("profile2");

    manager.create_profile(&profile1).unwrap();
    manager.create_profile(&profile2).unwrap();

    // Use the SAME passphrase for both profiles
    let shared_passphrase = "shared-passphrase-123";

    // Generate DIFFERENT keypairs for each profile
    let (signing_key1, signing_pub1) = generate_ed25519_keypair().unwrap();
    let (encryption_key1, encryption_pub1) = generate_x25519_keypair().unwrap();

    let (signing_key2, signing_pub2) = generate_ed25519_keypair().unwrap();
    let (encryption_key2, encryption_pub2) = generate_x25519_keypair().unwrap();

    // Save keys for both profiles with the same passphrase
    save_signing_keypair(
        &manager.signing_key_path(&profile1.name),
        &manager.signing_pubkey_path(&profile1.name),
        &signing_key1,
        &signing_pub1,
        shared_passphrase,
    )
    .unwrap();

    save_encryption_keypair(
        &manager.encryption_key_path(&profile1.name),
        &manager.encryption_pubkey_path(&profile1.name),
        &encryption_key1,
        &encryption_pub1,
        shared_passphrase,
    )
    .unwrap();

    save_signing_keypair(
        &manager.signing_key_path(&profile2.name),
        &manager.signing_pubkey_path(&profile2.name),
        &signing_key2,
        &signing_pub2,
        shared_passphrase,
    )
    .unwrap();

    save_encryption_keypair(
        &manager.encryption_key_path(&profile2.name),
        &manager.encryption_pubkey_path(&profile2.name),
        &encryption_key2,
        &encryption_pub2,
        shared_passphrase,
    )
    .unwrap();

    // Load keys from both profiles using the same passphrase
    let loaded_signing1 =
        load_signing_key(&manager.signing_key_path(&profile1.name), shared_passphrase).unwrap();
    let loaded_encryption1 = load_encryption_key(
        &manager.encryption_key_path(&profile1.name),
        shared_passphrase,
    )
    .unwrap();

    let loaded_signing2 =
        load_signing_key(&manager.signing_key_path(&profile2.name), shared_passphrase).unwrap();
    let loaded_encryption2 = load_encryption_key(
        &manager.encryption_key_path(&profile2.name),
        shared_passphrase,
    )
    .unwrap();

    // Verify each profile gets its own keys back
    assert_eq!(
        signing_key1.to_bytes(),
        loaded_signing1.to_bytes(),
        "Profile1 should load its own signing key"
    );
    assert_eq!(
        encryption_key1.to_bytes(),
        loaded_encryption1.to_bytes(),
        "Profile1 should load its own encryption key"
    );

    assert_eq!(
        signing_key2.to_bytes(),
        loaded_signing2.to_bytes(),
        "Profile2 should load its own signing key"
    );
    assert_eq!(
        encryption_key2.to_bytes(),
        loaded_encryption2.to_bytes(),
        "Profile2 should load its own encryption key"
    );

    // Verify the keys are still different between profiles despite same passphrase
    assert_ne!(
        loaded_signing1.to_bytes(),
        loaded_signing2.to_bytes(),
        "Profiles should have different signing keys even with same passphrase"
    );
    assert_ne!(
        loaded_encryption1.to_bytes(),
        loaded_encryption2.to_bytes(),
        "Profiles should have different encryption keys even with same passphrase"
    );
}

/// Test that profile metadata is isolated
#[test]
fn property_profile_metadata_isolation() {
    let temp_dir = TempDir::new().unwrap();
    let manager = ProfileManager::new(temp_dir.path().to_path_buf());

    // Create profiles with different metadata
    let mut profile1 = create_test_profile("profile1");
    profile1.github_owner = "owner1".to_string();
    profile1.github_repo = "vault1".to_string();
    profile1.github_user_id = 111;

    let mut profile2 = create_test_profile("profile2");
    profile2.github_owner = "owner2".to_string();
    profile2.github_repo = "vault2".to_string();
    profile2.github_user_id = 222;

    manager.create_profile(&profile1).unwrap();
    manager.create_profile(&profile2).unwrap();

    // Load profiles and verify metadata is isolated
    let loaded1 = manager.get_profile(&profile1.name).unwrap();
    let loaded2 = manager.get_profile(&profile2.name).unwrap();

    assert_eq!(loaded1.github_owner, "owner1");
    assert_eq!(loaded1.github_repo, "vault1");
    assert_eq!(loaded1.github_user_id, 111);

    assert_eq!(loaded2.github_owner, "owner2");
    assert_eq!(loaded2.github_repo, "vault2");
    assert_eq!(loaded2.github_user_id, 222);

    // Verify device IDs are different
    assert_ne!(
        loaded1.device_id, loaded2.device_id,
        "Profiles should have different device IDs"
    );
}
