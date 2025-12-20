//! Environment variable handling for CI and headless mode.
//!
//! This module provides functions to read configuration from environment variables,
//! supporting CI/CD workflows and headless operation.

use std::env;

/// Environment variable names
pub const ENV_KEY_PASSPHRASE: &str = "MYC_KEY_PASSPHRASE";
pub const ENV_NON_INTERACTIVE: &str = "MYC_NON_INTERACTIVE";
pub const ENV_PROFILE: &str = "MYC_PROFILE";

/// Gets the key passphrase from environment variable
///
/// # Returns
///
/// The passphrase if MYC_KEY_PASSPHRASE is set, None otherwise
pub fn get_passphrase_from_env() -> Option<String> {
    env::var(ENV_KEY_PASSPHRASE).ok()
}

/// Checks if non-interactive mode is enabled
///
/// # Returns
///
/// true if MYC_NON_INTERACTIVE is set to "1", "true", or "yes" (case-insensitive)
pub fn is_non_interactive() -> bool {
    env::var(ENV_NON_INTERACTIVE)
        .ok()
        .map(|v| {
            let v = v.to_lowercase();
            v == "1" || v == "true" || v == "yes"
        })
        .unwrap_or(false)
}

/// Gets the profile name from environment variable
///
/// # Returns
///
/// The profile name if MYC_PROFILE is set, None otherwise
pub fn get_profile_from_env() -> Option<String> {
    env::var(ENV_PROFILE).ok()
}

/// Gets the passphrase for a profile
///
/// This function tries to get the passphrase in the following order:
/// 1. From MYC_KEY_PASSPHRASE environment variable
/// 2. Prompt the user (if interactive mode)
/// 3. Use empty passphrase (if non-interactive and no env var)
///
/// # Arguments
///
/// * `profile_name` - Name of the profile (for display purposes)
///
/// # Returns
///
/// The passphrase to use
///
/// # Errors
///
/// Returns an error if:
/// - Interactive mode is required but MYC_NON_INTERACTIVE is set
/// - User cancels the prompt
pub fn get_passphrase(_profile_name: &str) -> anyhow::Result<String> {
    // Try environment variable first
    if let Some(passphrase) = get_passphrase_from_env() {
        return Ok(passphrase);
    }

    // Check if we're in non-interactive mode
    if is_non_interactive() {
        // In non-interactive mode without passphrase env var, use empty passphrase
        return Ok(String::new());
    }

    // Interactive mode - prompt for passphrase
    #[cfg(feature = "interactive")]
    {
        use dialoguer::{theme::ColorfulTheme, Password};

        let passphrase = Password::with_theme(&ColorfulTheme::default())
            .with_prompt(format!("Passphrase for profile '{}'", profile_name))
            .allow_empty_password(true)
            .interact()
            .map_err(|e| anyhow::anyhow!("Failed to read passphrase: {}", e))?;

        Ok(passphrase)
    }

    #[cfg(not(feature = "interactive"))]
    {
        // If interactive feature is not enabled, use empty passphrase
        Ok(String::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_get_passphrase_from_env() {
        // Clear env var first
        env::remove_var(ENV_KEY_PASSPHRASE);
        assert_eq!(get_passphrase_from_env(), None);

        // Set env var
        env::set_var(ENV_KEY_PASSPHRASE, "test-passphrase");
        assert_eq!(
            get_passphrase_from_env(),
            Some("test-passphrase".to_string())
        );

        // Clean up
        env::remove_var(ENV_KEY_PASSPHRASE);
    }

    #[test]
    fn test_is_non_interactive() {
        // Clear env var first
        env::remove_var(ENV_NON_INTERACTIVE);
        assert_eq!(is_non_interactive(), false);

        // Test various true values
        for value in &["1", "true", "TRUE", "True", "yes", "YES", "Yes"] {
            env::set_var(ENV_NON_INTERACTIVE, value);
            assert_eq!(is_non_interactive(), true, "Failed for value: {}", value);
        }

        // Test false values
        for value in &["0", "false", "no", "anything"] {
            env::set_var(ENV_NON_INTERACTIVE, value);
            assert_eq!(is_non_interactive(), false, "Failed for value: {}", value);
        }

        // Clean up
        env::remove_var(ENV_NON_INTERACTIVE);
    }

    #[test]
    fn test_get_profile_from_env() {
        // Clear env var first
        env::remove_var(ENV_PROFILE);
        assert_eq!(get_profile_from_env(), None);

        // Set env var
        env::set_var(ENV_PROFILE, "test-profile");
        assert_eq!(get_profile_from_env(), Some("test-profile".to_string()));

        // Clean up
        env::remove_var(ENV_PROFILE);
    }

    #[test]
    fn test_get_passphrase_from_env_var() {
        // Clear non-interactive mode first
        env::remove_var(ENV_NON_INTERACTIVE);

        // Set passphrase in env
        env::set_var(ENV_KEY_PASSPHRASE, "env-passphrase");

        let passphrase = get_passphrase("test-profile").unwrap();
        assert_eq!(passphrase, "env-passphrase");

        // Clean up
        env::remove_var(ENV_KEY_PASSPHRASE);
    }

    #[test]
    fn test_get_passphrase_non_interactive_no_env() {
        // Clear passphrase env var
        env::remove_var(ENV_KEY_PASSPHRASE);

        // Set non-interactive mode
        env::set_var(ENV_NON_INTERACTIVE, "1");

        // Should return empty passphrase
        let passphrase = get_passphrase("test-profile").unwrap();
        assert_eq!(passphrase, "");

        // Clean up
        env::remove_var(ENV_NON_INTERACTIVE);
    }
}
