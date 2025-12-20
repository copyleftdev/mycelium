//! Device key operations.
//!
//! This module provides high-level operations for managing device keys,
//! combining key storage and profile management.

use anyhow::{Context, Result};
use myc_crypto::{
    kex::{X25519PublicKey, X25519SecretKey},
    sign::{Ed25519PublicKey, Ed25519SecretKey},
};
use std::fs;

use crate::key_storage;
use crate::profile::ProfileManager;

/// Loads the signing secret key for a profile
///
/// # Arguments
///
/// * `manager` - The profile manager
/// * `profile_name` - Name of the profile
/// * `passphrase` - Passphrase to decrypt the key
///
/// # Returns
///
/// The decrypted Ed25519 secret key
///
/// # Errors
///
/// Returns an error if the key file doesn't exist, can't be read, or the passphrase is incorrect
pub fn load_signing_key(
    manager: &ProfileManager,
    profile_name: &str,
    passphrase: &str,
) -> Result<Ed25519SecretKey> {
    let key_path = manager.signing_key_path(profile_name);

    if !key_path.exists() {
        anyhow::bail!(
            "Signing key not found for profile '{}'. Has the device been enrolled?",
            profile_name
        );
    }

    key_storage::load_signing_key(&key_path, passphrase)
        .with_context(|| format!("Failed to load signing key for profile '{}'", profile_name))
}

/// Loads the encryption secret key for a profile
///
/// # Arguments
///
/// * `manager` - The profile manager
/// * `profile_name` - Name of the profile
/// * `passphrase` - Passphrase to decrypt the key
///
/// # Returns
///
/// The decrypted X25519 secret key
///
/// # Errors
///
/// Returns an error if the key file doesn't exist, can't be read, or the passphrase is incorrect
pub fn load_encryption_key(
    manager: &ProfileManager,
    profile_name: &str,
    passphrase: &str,
) -> Result<X25519SecretKey> {
    let key_path = manager.encryption_key_path(profile_name);

    if !key_path.exists() {
        anyhow::bail!(
            "Encryption key not found for profile '{}'. Has the device been enrolled?",
            profile_name
        );
    }

    key_storage::load_encryption_key(&key_path, passphrase).with_context(|| {
        format!(
            "Failed to load encryption key for profile '{}'",
            profile_name
        )
    })
}

/// Loads the signing public key for a profile
///
/// # Arguments
///
/// * `manager` - The profile manager
/// * `profile_name` - Name of the profile
///
/// # Returns
///
/// The Ed25519 public key
pub fn load_signing_pubkey(
    manager: &ProfileManager,
    profile_name: &str,
) -> Result<Ed25519PublicKey> {
    let pubkey_path = manager.signing_pubkey_path(profile_name);

    if !pubkey_path.exists() {
        anyhow::bail!(
            "Signing public key not found for profile '{}'",
            profile_name
        );
    }

    let bytes = fs::read(&pubkey_path).with_context(|| {
        format!(
            "Failed to read signing public key for profile '{}'",
            profile_name
        )
    })?;

    if bytes.len() != 32 {
        anyhow::bail!(
            "Invalid signing public key length: expected 32 bytes, got {}",
            bytes.len()
        );
    }

    let key_array: [u8; 32] = bytes[..32]
        .try_into()
        .context("Failed to convert public key bytes to array")?;

    Ed25519PublicKey::from_bytes(key_array).context("Failed to parse Ed25519 public key")
}

/// Loads the encryption public key for a profile
///
/// # Arguments
///
/// * `manager` - The profile manager
/// * `profile_name` - Name of the profile
///
/// # Returns
///
/// The X25519 public key
pub fn load_encryption_pubkey(
    manager: &ProfileManager,
    profile_name: &str,
) -> Result<X25519PublicKey> {
    let pubkey_path = manager.encryption_pubkey_path(profile_name);

    if !pubkey_path.exists() {
        anyhow::bail!(
            "Encryption public key not found for profile '{}'",
            profile_name
        );
    }

    let bytes = fs::read(&pubkey_path).with_context(|| {
        format!(
            "Failed to read encryption public key for profile '{}'",
            profile_name
        )
    })?;

    if bytes.len() != 32 {
        anyhow::bail!(
            "Invalid encryption public key length: expected 32 bytes, got {}",
            bytes.len()
        );
    }

    let key_array: [u8; 32] = bytes[..32]
        .try_into()
        .context("Failed to convert public key bytes to array")?;

    Ok(X25519PublicKey::from_bytes(key_array))
}

/// Saves a keypair for a profile
///
/// # Arguments
///
/// * `manager` - The profile manager
/// * `profile_name` - Name of the profile
/// * `signing_secret` - The Ed25519 secret key
/// * `signing_public` - The Ed25519 public key
/// * `encryption_secret` - The X25519 secret key
/// * `encryption_public` - The X25519 public key
/// * `passphrase` - Passphrase to encrypt the secret keys
///
/// # Errors
///
/// Returns an error if file operations fail
pub fn save_keypair(
    manager: &ProfileManager,
    profile_name: &str,
    signing_secret: &Ed25519SecretKey,
    signing_public: &Ed25519PublicKey,
    encryption_secret: &X25519SecretKey,
    encryption_public: &X25519PublicKey,
    passphrase: &str,
) -> Result<()> {
    // Save signing keypair
    let signing_secret_path = manager.signing_key_path(profile_name);
    let signing_public_path = manager.signing_pubkey_path(profile_name);

    key_storage::save_signing_keypair(
        &signing_secret_path,
        &signing_public_path,
        signing_secret,
        signing_public,
        passphrase,
    )
    .with_context(|| {
        format!(
            "Failed to save signing keypair for profile '{}'",
            profile_name
        )
    })?;

    // Set file permissions on secret key (Unix only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(&signing_secret_path, perms)
            .context("Failed to set signing key permissions")?;
    }

    // Save encryption keypair
    let encryption_secret_path = manager.encryption_key_path(profile_name);
    let encryption_public_path = manager.encryption_pubkey_path(profile_name);

    key_storage::save_encryption_keypair(
        &encryption_secret_path,
        &encryption_public_path,
        encryption_secret,
        encryption_public,
        passphrase,
    )
    .with_context(|| {
        format!(
            "Failed to save encryption keypair for profile '{}'",
            profile_name
        )
    })?;

    // Set file permissions on secret key (Unix only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(&encryption_secret_path, perms)
            .context("Failed to set encryption key permissions")?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::Profile;
    use myc_core::ids::DeviceId;
    use tempfile::TempDir;
    use time::OffsetDateTime;

    fn create_test_profile_manager() -> (TempDir, ProfileManager, Profile) {
        let temp_dir = TempDir::new().unwrap();
        let manager = ProfileManager::new(temp_dir.path().to_path_buf());

        let profile = Profile {
            name: "test-profile".to_string(),
            github_owner: "testorg".to_string(),
            github_repo: "test-vault".to_string(),
            github_user_id: 12345,
            github_username: "testuser".to_string(),
            device_id: DeviceId::new(),
            created_at: OffsetDateTime::now_utc(),
        };

        manager.create_profile(&profile).unwrap();

        (temp_dir, manager, profile)
    }

    #[test]
    fn test_save_and_load_signing_key() {
        let (_temp_dir, manager, profile) = create_test_profile_manager();

        // Generate keypair
        let (secret_key, public_key) = myc_crypto::sign::generate_ed25519_keypair().unwrap();
        let passphrase = "test-passphrase";

        // Save keypair
        key_storage::save_signing_keypair(
            &manager.signing_key_path(&profile.name),
            &manager.signing_pubkey_path(&profile.name),
            &secret_key,
            &public_key,
            passphrase,
        )
        .unwrap();

        // Load secret key
        let loaded_secret = load_signing_key(&manager, &profile.name, passphrase).unwrap();

        // Verify by signing a message
        let message = b"test message";
        let sig1 = myc_crypto::sign::sign(&secret_key, message);
        let sig2 = myc_crypto::sign::sign(&loaded_secret, message);
        assert_eq!(sig1.as_bytes(), sig2.as_bytes());

        // Load public key
        let loaded_public = load_signing_pubkey(&manager, &profile.name).unwrap();
        assert_eq!(public_key.as_bytes(), loaded_public.as_bytes());
    }

    #[test]
    fn test_save_and_load_encryption_key() {
        let (_temp_dir, manager, profile) = create_test_profile_manager();

        // Generate keypair
        let (secret_key, public_key) = myc_crypto::kex::generate_x25519_keypair().unwrap();
        let passphrase = "test-passphrase";

        // Save keypair
        key_storage::save_encryption_keypair(
            &manager.encryption_key_path(&profile.name),
            &manager.encryption_pubkey_path(&profile.name),
            &secret_key,
            &public_key,
            passphrase,
        )
        .unwrap();

        // Load secret key
        let loaded_secret = load_encryption_key(&manager, &profile.name, passphrase).unwrap();

        // Verify by performing DH
        let (_, test_public) = myc_crypto::kex::generate_x25519_keypair().unwrap();
        let shared1 = myc_crypto::kex::diffie_hellman(&secret_key, &test_public);
        let shared2 = myc_crypto::kex::diffie_hellman(&loaded_secret, &test_public);
        assert_eq!(shared1.as_bytes(), shared2.as_bytes());

        // Load public key
        let loaded_public = load_encryption_pubkey(&manager, &profile.name).unwrap();
        assert_eq!(public_key.as_bytes(), loaded_public.as_bytes());
    }

    #[test]
    fn test_save_keypair() {
        let (_temp_dir, manager, profile) = create_test_profile_manager();

        // Generate keypairs
        let (signing_secret, signing_public) =
            myc_crypto::sign::generate_ed25519_keypair().unwrap();
        let (encryption_secret, encryption_public) =
            myc_crypto::kex::generate_x25519_keypair().unwrap();
        let passphrase = "test-passphrase";

        // Save both keypairs
        save_keypair(
            &manager,
            &profile.name,
            &signing_secret,
            &signing_public,
            &encryption_secret,
            &encryption_public,
            passphrase,
        )
        .unwrap();

        // Verify both can be loaded
        let loaded_signing = load_signing_key(&manager, &profile.name, passphrase).unwrap();
        let loaded_encryption = load_encryption_key(&manager, &profile.name, passphrase).unwrap();

        // Verify signing key
        let message = b"test";
        let sig1 = myc_crypto::sign::sign(&signing_secret, message);
        let sig2 = myc_crypto::sign::sign(&loaded_signing, message);
        assert_eq!(sig1.as_bytes(), sig2.as_bytes());

        // Verify encryption key
        let (_, test_public) = myc_crypto::kex::generate_x25519_keypair().unwrap();
        let shared1 = myc_crypto::kex::diffie_hellman(&encryption_secret, &test_public);
        let shared2 = myc_crypto::kex::diffie_hellman(&loaded_encryption, &test_public);
        assert_eq!(shared1.as_bytes(), shared2.as_bytes());
    }

    #[test]
    fn test_load_nonexistent_key() {
        let (_temp_dir, manager, profile) = create_test_profile_manager();

        // Try to load keys that don't exist
        let result = load_signing_key(&manager, &profile.name, "passphrase");
        assert!(result.is_err());

        let result = load_encryption_key(&manager, &profile.name, "passphrase");
        assert!(result.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn test_key_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let (_temp_dir, manager, profile) = create_test_profile_manager();

        // Generate and save keypairs
        let (signing_secret, signing_public) =
            myc_crypto::sign::generate_ed25519_keypair().unwrap();
        let (encryption_secret, encryption_public) =
            myc_crypto::kex::generate_x25519_keypair().unwrap();

        save_keypair(
            &manager,
            &profile.name,
            &signing_secret,
            &signing_public,
            &encryption_secret,
            &encryption_public,
            "passphrase",
        )
        .unwrap();

        // Check signing key permissions (0600)
        let signing_key_path = manager.signing_key_path(&profile.name);
        let metadata = fs::metadata(&signing_key_path).unwrap();
        let mode = metadata.permissions().mode();
        assert_eq!(mode & 0o777, 0o600);

        // Check encryption key permissions (0600)
        let encryption_key_path = manager.encryption_key_path(&profile.name);
        let metadata = fs::metadata(&encryption_key_path).unwrap();
        let mode = metadata.permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
