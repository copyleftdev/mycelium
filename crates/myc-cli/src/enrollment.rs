//! Device enrollment flow.
//!
//! This module handles the device enrollment process, which includes:
//! - Generating Ed25519 and X25519 keypairs
//! - Prompting for optional passphrase
//! - Encrypting and saving keys to disk
//! - Creating profile and device metadata files

use anyhow::{Context, Result};
use myc_core::ids::DeviceId;
use time::OffsetDateTime;

use crate::device;
use crate::profile::{Profile, ProfileManager};

/// Device enrollment parameters
pub struct EnrollmentParams {
    /// Profile name
    pub profile_name: String,
    /// GitHub repository owner
    pub github_owner: String,
    /// GitHub repository name
    pub github_repo: String,
    /// GitHub user ID
    pub github_user_id: u64,
    /// GitHub username
    pub github_username: String,
    /// Passphrase for encrypting keys (empty string for no passphrase)
    pub passphrase: String,
}

/// Enrolls a new device
///
/// This function performs the complete device enrollment flow:
/// 1. Generates Ed25519 and X25519 keypairs
/// 2. Creates a new profile
/// 3. Encrypts and saves keys to disk
/// 4. Creates device metadata
///
/// # Arguments
///
/// * `manager` - The profile manager
/// * `params` - Enrollment parameters
///
/// # Returns
///
/// The created profile and device ID
///
/// # Errors
///
/// Returns an error if:
/// - Profile already exists
/// - Key generation fails
/// - File operations fail
pub fn enroll_device(
    manager: &ProfileManager,
    params: EnrollmentParams,
) -> Result<(Profile, DeviceId)> {
    // Check if profile already exists
    if manager.get_profile(&params.profile_name).is_ok() {
        anyhow::bail!("Profile '{}' already exists", params.profile_name);
    }

    // Generate device ID
    let device_id = DeviceId::new();

    // Generate Ed25519 signing keypair
    let (signing_secret, signing_public) = myc_crypto::sign::generate_ed25519_keypair()
        .context("Failed to generate Ed25519 keypair")?;

    // Generate X25519 encryption keypair
    let (encryption_secret, encryption_public) =
        myc_crypto::kex::generate_x25519_keypair().context("Failed to generate X25519 keypair")?;

    // Create profile
    let profile = Profile {
        name: params.profile_name.clone(),
        github_owner: params.github_owner,
        github_repo: params.github_repo,
        github_user_id: params.github_user_id,
        github_username: params.github_username,
        device_id,
        created_at: OffsetDateTime::now_utc(),
    };

    // Create profile directory structure
    manager
        .create_profile(&profile)
        .context("Failed to create profile")?;

    // Save keypairs
    device::save_keypair(
        manager,
        &params.profile_name,
        &signing_secret,
        &signing_public,
        &encryption_secret,
        &encryption_public,
        &params.passphrase,
    )
    .context("Failed to save device keys")?;

    Ok((profile, device_id))
}

/// Prompts for a passphrase (interactive mode)
///
/// This function prompts the user to enter a passphrase for encrypting device keys.
/// The passphrase is optional - users can press Enter to skip.
///
/// # Returns
///
/// The passphrase entered by the user (empty string if skipped)
///
/// # Errors
///
/// Returns an error if the prompt fails
#[cfg(feature = "interactive")]
pub fn prompt_for_passphrase() -> Result<String> {
    use dialoguer::{theme::ColorfulTheme, Password};

    println!("\nDevice keys will be encrypted at rest.");
    println!("Enter a passphrase to protect your keys, or press Enter to skip.");
    println!("(You'll need this passphrase every time you use this profile)\n");

    let passphrase = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Passphrase (optional)")
        .allow_empty_password(true)
        .interact()
        .context("Failed to read passphrase")?;

    if !passphrase.is_empty() {
        let confirm = Password::with_theme(&ColorfulTheme::default())
            .with_prompt("Confirm passphrase")
            .allow_empty_password(true)
            .interact()
            .context("Failed to read passphrase confirmation")?;

        if passphrase != confirm {
            anyhow::bail!("Passphrases do not match");
        }
    }

    Ok(passphrase)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_enroll_device() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ProfileManager::new(temp_dir.path().to_path_buf());

        let params = EnrollmentParams {
            profile_name: "test-profile".to_string(),
            github_owner: "testorg".to_string(),
            github_repo: "test-vault".to_string(),
            github_user_id: 12345,
            github_username: "testuser".to_string(),
            passphrase: "test-passphrase".to_string(),
        };

        // Enroll device
        let (profile, device_id) = enroll_device(&manager, params).unwrap();

        // Verify profile was created
        assert_eq!(profile.name, "test-profile");
        assert_eq!(profile.github_owner, "testorg");
        assert_eq!(profile.device_id, device_id);

        // Verify profile can be loaded
        let loaded_profile = manager.get_profile(&profile.name).unwrap();
        assert_eq!(loaded_profile.name, profile.name);
        assert_eq!(loaded_profile.device_id, device_id);

        // Verify keys can be loaded
        let signing_key =
            device::load_signing_key(&manager, &profile.name, "test-passphrase").unwrap();
        let encryption_key =
            device::load_encryption_key(&manager, &profile.name, "test-passphrase").unwrap();

        // Verify keys work
        let message = b"test message";
        let signature = myc_crypto::sign::sign(&signing_key, message);
        let public_key = device::load_signing_pubkey(&manager, &profile.name).unwrap();
        assert!(myc_crypto::sign::verify(&public_key, message, &signature).is_ok());

        // Verify encryption key works
        let (_, test_public) = myc_crypto::kex::generate_x25519_keypair().unwrap();
        let _shared = myc_crypto::kex::diffie_hellman(&encryption_key, &test_public);
    }

    #[test]
    fn test_enroll_device_duplicate_profile() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ProfileManager::new(temp_dir.path().to_path_buf());

        let params = EnrollmentParams {
            profile_name: "test-profile".to_string(),
            github_owner: "testorg".to_string(),
            github_repo: "test-vault".to_string(),
            github_user_id: 12345,
            github_username: "testuser".to_string(),
            passphrase: "test-passphrase".to_string(),
        };

        // First enrollment should succeed
        enroll_device(&manager, params).unwrap();

        // Second enrollment with same profile name should fail
        let params2 = EnrollmentParams {
            profile_name: "test-profile".to_string(),
            github_owner: "testorg2".to_string(),
            github_repo: "test-vault2".to_string(),
            github_user_id: 67890,
            github_username: "testuser2".to_string(),
            passphrase: "test-passphrase2".to_string(),
        };

        let result = enroll_device(&manager, params2);
        assert!(result.is_err());
    }

    #[test]
    fn test_enroll_device_empty_passphrase() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ProfileManager::new(temp_dir.path().to_path_buf());

        let params = EnrollmentParams {
            profile_name: "test-profile".to_string(),
            github_owner: "testorg".to_string(),
            github_repo: "test-vault".to_string(),
            github_user_id: 12345,
            github_username: "testuser".to_string(),
            passphrase: String::new(), // Empty passphrase
        };

        // Enroll device with empty passphrase
        let (profile, _) = enroll_device(&manager, params).unwrap();

        // Verify keys can be loaded with empty passphrase
        let _signing_key = device::load_signing_key(&manager, &profile.name, "").unwrap();
        let _encryption_key = device::load_encryption_key(&manager, &profile.name, "").unwrap();
    }
}
