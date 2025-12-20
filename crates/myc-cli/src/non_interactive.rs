//! Non-interactive mode support for the Mycelium CLI.
//!
//! This module provides utilities for handling non-interactive mode,
//! including environment variable checks and appropriate error handling.

use anyhow::{Context, Result};
use std::env;
use std::process;

/// Exit code for when user input is required in non-interactive mode.
pub const EXIT_CODE_USER_INPUT_REQUIRED: i32 = 10;

/// Non-interactive mode manager.
pub struct NonInteractiveMode;

impl NonInteractiveMode {
    /// Check if we're running in non-interactive mode.
    pub fn is_enabled() -> bool {
        env::var("MYC_NON_INTERACTIVE").is_ok()
    }

    /// Get the non-interactive mode setting as a boolean.
    /// Returns true if MYC_NON_INTERACTIVE is set to "1", "true", "yes", or "on".
    /// Returns false if MYC_NON_INTERACTIVE is set to "0", "false", "no", or "off".
    /// Returns true if MYC_NON_INTERACTIVE is set to any other value (for safety).
    pub fn is_strictly_enabled() -> bool {
        match env::var("MYC_NON_INTERACTIVE") {
            Ok(value) => match value.to_lowercase().as_str() {
                "0" | "false" | "no" | "off" => false,
                _ => true, // Default to non-interactive for safety
            },
            Err(_) => false,
        }
    }

    /// Fail with appropriate exit code if user input would be required.
    pub fn fail_if_input_required(operation: &str) -> Result<()> {
        if Self::is_enabled() {
            anyhow::bail!(
                "Cannot {} in non-interactive mode (MYC_NON_INTERACTIVE is set). \
                 This operation requires user input.",
                operation
            );
        }
        Ok(())
    }

    /// Fail with appropriate exit code and message for confirmation prompts.
    pub fn fail_if_confirmation_required(operation: &str) -> Result<()> {
        if Self::is_enabled() {
            anyhow::bail!(
                "Cannot {} in non-interactive mode (MYC_NON_INTERACTIVE is set). \
                 Use --force to skip confirmation or run interactively.",
                operation
            );
        }
        Ok(())
    }

    /// Fail with appropriate exit code for password prompts.
    pub fn fail_if_password_required() -> Result<()> {
        if Self::is_enabled() {
            anyhow::bail!(
                "Cannot prompt for password in non-interactive mode (MYC_NON_INTERACTIVE is set). \
                 Set MYC_KEY_PASSPHRASE environment variable or run interactively."
            );
        }
        Ok(())
    }

    /// Get a required environment variable or fail appropriately.
    pub fn require_env_var(var_name: &str, operation: &str) -> Result<String> {
        env::var(var_name).with_context(|| {
            if Self::is_enabled() {
                format!(
                    "Environment variable {} is required for {} in non-interactive mode",
                    var_name, operation
                )
            } else {
                format!("Environment variable {} is not set", var_name)
            }
        })
    }

    /// Get an optional environment variable with a default value.
    pub fn get_env_var_or_default(var_name: &str, default: &str) -> String {
        env::var(var_name).unwrap_or_else(|_| default.to_string())
    }

    /// Get a boolean environment variable with a default value.
    pub fn get_bool_env_var_or_default(var_name: &str, default: bool) -> bool {
        match env::var(var_name) {
            Ok(value) => match value.to_lowercase().as_str() {
                "1" | "true" | "yes" | "on" => true,
                "0" | "false" | "no" | "off" => false,
                _ => default,
            },
            Err(_) => default,
        }
    }

    /// Exit with the appropriate code for non-interactive mode failures.
    pub fn exit_for_user_input_required(message: &str) -> ! {
        eprintln!("Error: {}", message);
        eprintln!(
            "Exiting with code {} (user input required in non-interactive mode)",
            EXIT_CODE_USER_INPUT_REQUIRED
        );
        process::exit(EXIT_CODE_USER_INPUT_REQUIRED);
    }

    /// Check if we can proceed with a destructive action in non-interactive mode.
    /// Returns Ok(true) if --force is provided, Err if confirmation would be required.
    pub fn check_destructive_action(force: bool, action: &str) -> Result<bool> {
        if Self::is_enabled() {
            if force {
                Ok(true)
            } else {
                anyhow::bail!(
                    "Cannot {} in non-interactive mode without --force flag. \
                     This is a destructive action that normally requires confirmation.",
                    action
                )
            }
        } else {
            Ok(false) // Interactive mode, will prompt
        }
    }

    /// Get passphrase from environment or fail appropriately.
    pub fn get_passphrase() -> Result<String> {
        if Self::is_enabled() {
            Self::require_env_var("MYC_KEY_PASSPHRASE", "key decryption")
        } else {
            // In interactive mode, this should not be called directly
            anyhow::bail!("get_passphrase() should not be called in interactive mode")
        }
    }

    /// Get GitHub token from environment or fail appropriately.
    pub fn get_github_token() -> Result<String> {
        Self::require_env_var("GITHUB_TOKEN", "GitHub API access")
    }

    /// Get profile name from environment or use default.
    pub fn get_profile_name(
        cli_profile: Option<&str>,
        default_profile: Option<&str>,
    ) -> Result<String> {
        // Priority: CLI argument > MYC_PROFILE env var > default profile > error
        if let Some(profile) = cli_profile {
            Ok(profile.to_string())
        } else if let Ok(profile) = env::var("MYC_PROFILE") {
            Ok(profile)
        } else if let Some(profile) = default_profile {
            Ok(profile.to_string())
        } else if Self::is_enabled() {
            anyhow::bail!(
                "No profile specified in non-interactive mode. \
                 Use --profile argument or set MYC_PROFILE environment variable."
            )
        } else {
            anyhow::bail!(
                "No default profile set. Use 'myc profile use <name>' to set a default profile."
            )
        }
    }

    /// Validate that all required environment variables are set for CI mode.
    pub fn validate_ci_environment() -> Result<()> {
        if !Self::is_enabled() {
            return Ok(()); // Not in non-interactive mode
        }

        // Check for required CI environment variables
        let required_vars = [
            ("GITHUB_TOKEN", "GitHub API access"),
            ("MYC_KEY_PASSPHRASE", "key decryption"),
        ];

        let mut missing_vars = Vec::new();
        for (var_name, purpose) in &required_vars {
            if env::var(var_name).is_err() {
                missing_vars.push(format!("{} (for {})", var_name, purpose));
            }
        }

        if !missing_vars.is_empty() {
            anyhow::bail!(
                "Missing required environment variables for non-interactive mode:\n  {}",
                missing_vars.join("\n  ")
            );
        }

        Ok(())
    }

    /// Get output format preference for non-interactive mode.
    pub fn get_output_format(cli_json: bool) -> OutputFormat {
        if cli_json {
            OutputFormat::Json
        } else if Self::is_enabled() {
            // In non-interactive mode, prefer JSON for machine consumption
            OutputFormat::Json
        } else {
            OutputFormat::Human
        }
    }

    /// Check if colors should be disabled in non-interactive mode.
    pub fn should_disable_colors(cli_no_color: bool) -> bool {
        cli_no_color
            || env::var("NO_COLOR").is_ok()
            || (Self::is_enabled() && env::var("FORCE_COLOR").is_err())
    }

    /// Get verbosity level for non-interactive mode.
    pub fn get_verbosity_level(cli_verbose: u8) -> u8 {
        if Self::is_enabled() {
            // In non-interactive mode, reduce verbosity unless explicitly requested
            if cli_verbose > 0 {
                cli_verbose
            } else {
                0 // Minimal output in non-interactive mode
            }
        } else {
            cli_verbose
        }
    }
}

/// Output format preference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Human,
    Json,
}

/// Environment variable names used by the CLI.
pub mod env_vars {
    pub const NON_INTERACTIVE: &str = "MYC_NON_INTERACTIVE";
    pub const KEY_PASSPHRASE: &str = "MYC_KEY_PASSPHRASE";
    pub const GITHUB_TOKEN: &str = "GITHUB_TOKEN";
    pub const PROFILE: &str = "MYC_PROFILE";
    pub const NO_COLOR: &str = "NO_COLOR";
    pub const FORCE_COLOR: &str = "FORCE_COLOR";
    pub const TERM: &str = "TERM";
}

/// Helper macro for failing with user input required error.
#[macro_export]
macro_rules! fail_if_non_interactive {
    ($operation:expr) => {
        if $crate::non_interactive::NonInteractiveMode::is_enabled() {
            $crate::non_interactive::NonInteractiveMode::exit_for_user_input_required(&format!(
                "Cannot {} in non-interactive mode",
                $operation
            ));
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_non_interactive_detection() {
        // Save original value
        let original = env::var("MYC_NON_INTERACTIVE").ok();

        // Test when not set
        env::remove_var("MYC_NON_INTERACTIVE");
        assert!(!NonInteractiveMode::is_enabled());

        // Test when set to any value
        env::set_var("MYC_NON_INTERACTIVE", "1");
        assert!(NonInteractiveMode::is_enabled());

        env::set_var("MYC_NON_INTERACTIVE", "true");
        assert!(NonInteractiveMode::is_enabled());

        env::set_var("MYC_NON_INTERACTIVE", "anything");
        assert!(NonInteractiveMode::is_enabled());

        // Restore original value
        if let Some(value) = original {
            env::set_var("MYC_NON_INTERACTIVE", value);
        } else {
            env::remove_var("MYC_NON_INTERACTIVE");
        }
    }

    #[test]
    fn test_strict_non_interactive_detection() {
        // Save original value
        let original = env::var("MYC_NON_INTERACTIVE").ok();

        // Test false values
        for false_value in &["0", "false", "no", "off"] {
            env::set_var("MYC_NON_INTERACTIVE", false_value);
            assert!(!NonInteractiveMode::is_strictly_enabled());
        }

        // Test true values
        for true_value in &["1", "true", "yes", "on", "anything"] {
            env::set_var("MYC_NON_INTERACTIVE", true_value);
            assert!(NonInteractiveMode::is_strictly_enabled());
        }

        // Test when not set
        env::remove_var("MYC_NON_INTERACTIVE");
        assert!(!NonInteractiveMode::is_strictly_enabled());

        // Restore original value
        if let Some(value) = original {
            env::set_var("MYC_NON_INTERACTIVE", value);
        } else {
            env::remove_var("MYC_NON_INTERACTIVE");
        }
    }

    #[test]
    fn test_bool_env_var_parsing() {
        assert!(NonInteractiveMode::get_bool_env_var_or_default(
            "NONEXISTENT_VAR",
            true
        ));
        assert!(!NonInteractiveMode::get_bool_env_var_or_default(
            "NONEXISTENT_VAR",
            false
        ));

        // Test with actual environment variable
        env::set_var("TEST_BOOL_VAR", "true");
        assert!(NonInteractiveMode::get_bool_env_var_or_default(
            "TEST_BOOL_VAR",
            false
        ));

        env::set_var("TEST_BOOL_VAR", "false");
        assert!(!NonInteractiveMode::get_bool_env_var_or_default(
            "TEST_BOOL_VAR",
            true
        ));

        env::remove_var("TEST_BOOL_VAR");
    }

    #[test]
    fn test_output_format_selection() {
        // Save original value
        let original = env::var("MYC_NON_INTERACTIVE").ok();

        // Test interactive mode
        env::remove_var("MYC_NON_INTERACTIVE");
        assert_eq!(
            NonInteractiveMode::get_output_format(false),
            OutputFormat::Human
        );
        assert_eq!(
            NonInteractiveMode::get_output_format(true),
            OutputFormat::Json
        );

        // Test non-interactive mode
        env::set_var("MYC_NON_INTERACTIVE", "1");
        assert_eq!(
            NonInteractiveMode::get_output_format(false),
            OutputFormat::Json
        );
        assert_eq!(
            NonInteractiveMode::get_output_format(true),
            OutputFormat::Json
        );

        // Restore original value
        if let Some(value) = original {
            env::set_var("MYC_NON_INTERACTIVE", value);
        } else {
            env::remove_var("MYC_NON_INTERACTIVE");
        }
    }
}
