//! Error message formatting for the Mycelium CLI.
//!
//! This module provides actionable error messages with clear guidance
//! on what went wrong, why it matters, and how to fix it.

use anyhow::{Error, Result};
use console::{style, Color};
use std::fmt;

/// Formatted error with actionable guidance.
#[derive(Debug)]
pub struct FormattedError {
    /// What went wrong
    pub what: String,
    /// Why it matters / context
    pub why: String,
    /// How to fix it
    pub how_to_fix: String,
    /// Optional example of correct usage
    pub example: Option<String>,
    /// Error category for programmatic handling
    pub category: ErrorCategory,
}

/// Categories of errors for consistent handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCategory {
    Authentication,
    Permission,
    NotFound,
    AlreadyExists,
    InvalidInput,
    Network,
    Crypto,
    Conflict,
    RateLimit,
    Internal,
    UserCancelled,
}

impl ErrorCategory {
    /// Get the exit code for this error category.
    pub fn exit_code(&self) -> i32 {
        match self {
            ErrorCategory::Authentication => 3,
            ErrorCategory::Permission => 4,
            ErrorCategory::NotFound => 8,
            ErrorCategory::AlreadyExists => 7,
            ErrorCategory::InvalidInput => 2,
            ErrorCategory::Network => 6,
            ErrorCategory::Crypto => 5,
            ErrorCategory::Conflict => 7,
            ErrorCategory::RateLimit => 6,
            ErrorCategory::Internal => 1,
            ErrorCategory::UserCancelled => 10,
        }
    }

    /// Get a human-readable name for this error category.
    pub fn name(&self) -> &'static str {
        match self {
            ErrorCategory::Authentication => "Authentication Error",
            ErrorCategory::Permission => "Permission Denied",
            ErrorCategory::NotFound => "Not Found",
            ErrorCategory::AlreadyExists => "Already Exists",
            ErrorCategory::InvalidInput => "Invalid Input",
            ErrorCategory::Network => "Network Error",
            ErrorCategory::Crypto => "Cryptographic Error",
            ErrorCategory::Conflict => "Conflict",
            ErrorCategory::RateLimit => "Rate Limited",
            ErrorCategory::Internal => "Internal Error",
            ErrorCategory::UserCancelled => "User Cancelled",
        }
    }

    /// Get the color to use for this error category.
    pub fn color(&self) -> Color {
        match self {
            ErrorCategory::Authentication => Color::Red,
            ErrorCategory::Permission => Color::Red,
            ErrorCategory::NotFound => Color::Yellow,
            ErrorCategory::AlreadyExists => Color::Yellow,
            ErrorCategory::InvalidInput => Color::Magenta,
            ErrorCategory::Network => Color::Blue,
            ErrorCategory::Crypto => Color::Red,
            ErrorCategory::Conflict => Color::Yellow,
            ErrorCategory::RateLimit => Color::Blue,
            ErrorCategory::Internal => Color::Red,
            ErrorCategory::UserCancelled => Color::Cyan,
        }
    }
}

impl FormattedError {
    /// Create a new formatted error.
    pub fn new(
        what: impl Into<String>,
        why: impl Into<String>,
        how_to_fix: impl Into<String>,
        category: ErrorCategory,
    ) -> Self {
        Self {
            what: what.into(),
            why: why.into(),
            how_to_fix: how_to_fix.into(),
            example: None,
            category,
        }
    }

    /// Add an example to the error.
    pub fn with_example(mut self, example: impl Into<String>) -> Self {
        self.example = Some(example.into());
        self
    }

    /// Format the error for human-readable output.
    pub fn format_human(&self, colors_enabled: bool) -> String {
        let mut output = String::new();

        // Error header
        let header = if colors_enabled {
            format!(
                "{} {}",
                style("✗").fg(self.category.color()).bold(),
                style(self.category.name()).fg(self.category.color()).bold()
            )
        } else {
            format!("✗ {}", self.category.name())
        };
        output.push_str(&header);
        output.push('\n');

        // What went wrong
        let what_label = if colors_enabled {
            style("What:").bold().to_string()
        } else {
            "What:".to_string()
        };
        output.push_str(&format!("{} {}\n", what_label, self.what));

        // Why it matters
        let why_label = if colors_enabled {
            style("Why:").bold().to_string()
        } else {
            "Why:".to_string()
        };
        output.push_str(&format!("{} {}\n", why_label, self.why));

        // How to fix
        let fix_label = if colors_enabled {
            style("Fix:").green().bold().to_string()
        } else {
            "Fix:".to_string()
        };
        output.push_str(&format!("{} {}\n", fix_label, self.how_to_fix));

        // Example if provided
        if let Some(example) = &self.example {
            let example_label = if colors_enabled {
                style("Example:").cyan().to_string()
            } else {
                "Example:".to_string()
            };
            output.push_str(&format!("{} {}\n", example_label, example));
        }

        output
    }

    /// Format the error for JSON output.
    pub fn format_json(&self) -> Result<String> {
        let json = serde_json::json!({
            "success": false,
            "error": {
                "category": format!("{:?}", self.category).to_lowercase(),
                "what": self.what,
                "why": self.why,
                "how_to_fix": self.how_to_fix,
                "example": self.example
            },
            "exit_code": self.category.exit_code()
        });
        Ok(serde_json::to_string_pretty(&json)?)
    }
}

/// Error formatter that creates actionable error messages.
pub struct ErrorFormatter;

impl ErrorFormatter {
    /// Format authentication errors.
    pub fn authentication_failed(details: &str) -> FormattedError {
        FormattedError::new(
            format!("Authentication failed: {}", details),
            "You need to authenticate with GitHub to access your vault",
            "Run 'myc profile add <name>' to authenticate with GitHub OAuth",
            ErrorCategory::Authentication,
        )
        .with_example("myc profile add my-profile")
    }

    /// Format GitHub token errors.
    pub fn github_token_invalid() -> FormattedError {
        FormattedError::new(
            "GitHub token is invalid or expired",
            "The stored GitHub token cannot access the API",
            "Re-authenticate by running 'myc profile add' or set a valid GITHUB_TOKEN environment variable",
            ErrorCategory::Authentication,
        ).with_example("export GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx")
    }

    /// Format permission denied errors.
    pub fn permission_denied(resource: &str, required_permission: &str) -> FormattedError {
        FormattedError::new(
            format!("Permission denied accessing {}", resource),
            format!(
                "You need '{}' permission to perform this operation",
                required_permission
            ),
            "Ask a project owner or admin to grant you the required permissions",
            ErrorCategory::Permission,
        )
    }

    /// Format repository access errors.
    pub fn repository_access_denied(owner: &str, repo: &str) -> FormattedError {
        FormattedError::new(
            format!("Cannot access repository {}/{}", owner, repo),
            "The repository doesn't exist or you don't have access",
            "Verify the repository exists and you have access, or check your GitHub token permissions",
            ErrorCategory::Permission,
        ).with_example(format!("Visit https://github.com/{}/{} to check access", owner, repo))
    }

    /// Format project not found errors.
    pub fn project_not_found(identifier: &str) -> FormattedError {
        FormattedError::new(
            format!("Project '{}' not found", identifier),
            "The project doesn't exist in this vault or you don't have access",
            "Use 'myc project list' to see available projects, or ask for access if the project exists",
            ErrorCategory::NotFound,
        ).with_example("myc project list")
    }

    /// Format secret set not found errors.
    pub fn secret_set_not_found(project: &str, set: &str) -> FormattedError {
        FormattedError::new(
            format!("Secret set '{}' not found in project '{}'", set, project),
            "The secret set doesn't exist or you don't have access",
            format!("Use 'myc set list {}' to see available secret sets, or create it with 'myc set create {} {}'", project, project, set),
            ErrorCategory::NotFound,
        ).with_example(format!("myc set create {} {}", project, set))
    }

    /// Format version not found errors.
    pub fn version_not_found(project: &str, set: &str, version: u64) -> FormattedError {
        FormattedError::new(
            format!(
                "Version {} not found for secret set '{}/{}' ",
                version, project, set
            ),
            "The requested version doesn't exist",
            format!(
                "Use 'myc versions list {} {}' to see available versions",
                project, set
            ),
            ErrorCategory::NotFound,
        )
        .with_example(format!("myc versions list {} {}", project, set))
    }

    /// Format device not found errors.
    pub fn device_not_found(device_id: &str) -> FormattedError {
        FormattedError::new(
            format!("Device '{}' not found", device_id),
            "The device doesn't exist in this vault",
            "Use 'myc device list' to see available devices, or check the device ID",
            ErrorCategory::NotFound,
        )
        .with_example("myc device list")
    }

    /// Format profile not found errors.
    pub fn profile_not_found(profile_name: &str) -> FormattedError {
        FormattedError::new(
            format!("Profile '{}' not found", profile_name),
            "The profile doesn't exist on this system",
            "Use 'myc profile list' to see available profiles, or create it with 'myc profile add'",
            ErrorCategory::NotFound,
        )
        .with_example(format!("myc profile add {}", profile_name))
    }

    /// Format already exists errors.
    pub fn already_exists(resource_type: &str, name: &str) -> FormattedError {
        FormattedError::new(
            format!("{} '{}' already exists", resource_type, name),
            "Cannot create a resource that already exists",
            "Use a different name or update the existing resource",
            ErrorCategory::AlreadyExists,
        )
    }

    /// Format invalid input errors.
    pub fn invalid_input(field: &str, value: &str, constraint: &str) -> FormattedError {
        FormattedError::new(
            format!("Invalid {}: '{}'", field, value),
            format!("The {} must {}", field, constraint),
            format!("Provide a valid {} that {}", field, constraint),
            ErrorCategory::InvalidInput,
        )
    }

    /// Format passphrase errors.
    pub fn invalid_passphrase() -> FormattedError {
        FormattedError::new(
            "Invalid passphrase",
            "The passphrase cannot decrypt your device keys",
            "Check your passphrase or set MYC_KEY_PASSPHRASE environment variable",
            ErrorCategory::Crypto,
        )
        .with_example("export MYC_KEY_PASSPHRASE='your-passphrase'")
    }

    /// Format PDK access errors.
    pub fn pdk_access_denied(project: &str) -> FormattedError {
        FormattedError::new(
            format!("Cannot access encryption keys for project '{}'", project),
            "Your device doesn't have access to the project's encryption keys",
            "Ask a project admin to add you to the project or re-wrap the keys to your device",
            ErrorCategory::Crypto,
        )
    }

    /// Format signature verification errors.
    pub fn signature_verification_failed(file: &str) -> FormattedError {
        FormattedError::new(
            format!("Signature verification failed for {}", file),
            "The file may have been tampered with or corrupted",
            "Run 'myc verify' to check vault integrity, or contact your vault administrator",
            ErrorCategory::Crypto,
        )
        .with_example("myc verify")
    }

    /// Format hash chain errors.
    pub fn hash_chain_broken(project: &str, set: &str) -> FormattedError {
        FormattedError::new(
            format!("Hash chain broken in secret set '{}/{}'", project, set),
            "The version history has been tampered with or corrupted",
            "Run 'myc verify' for detailed analysis, or contact your vault administrator",
            ErrorCategory::Crypto,
        )
        .with_example(format!("myc verify {} {}", project, set))
    }

    /// Format network errors.
    pub fn network_error(operation: &str, details: &str) -> FormattedError {
        FormattedError::new(
            format!("Network error during {}: {}", operation, details),
            "Cannot communicate with GitHub API",
            "Check your internet connection and GitHub API status, then retry",
            ErrorCategory::Network,
        )
        .with_example("Check https://www.githubstatus.com/ for API status")
    }

    /// Format rate limit errors.
    pub fn rate_limited(reset_time: Option<&str>) -> FormattedError {
        let fix_message = if let Some(reset) = reset_time {
            format!(
                "Wait until {} or use a different GitHub token with higher rate limits",
                reset
            )
        } else {
            "Wait a few minutes or use a different GitHub token with higher rate limits".to_string()
        };

        FormattedError::new(
            "GitHub API rate limit exceeded",
            "Too many requests have been made to the GitHub API",
            fix_message,
            ErrorCategory::RateLimit,
        )
        .with_example("Use a GitHub token with higher rate limits or wait for the limit to reset")
    }

    /// Format conflict errors.
    pub fn conflict_error(resource: &str, details: &str) -> FormattedError {
        FormattedError::new(
            format!("Conflict with {}: {}", resource, details),
            "Another operation has modified the resource concurrently",
            "Pull the latest changes and retry your operation",
            ErrorCategory::Conflict,
        )
        .with_example("myc pull <project> <set> && myc push <project> <set>")
    }

    /// Format user cancelled errors.
    pub fn user_cancelled(operation: &str) -> FormattedError {
        FormattedError::new(
            format!("Operation cancelled: {}", operation),
            "You chose to cancel the operation",
            "Run the command again if you want to proceed, or use --force to skip confirmation",
            ErrorCategory::UserCancelled,
        )
    }

    /// Format non-interactive mode errors.
    pub fn non_interactive_input_required(operation: &str) -> FormattedError {
        FormattedError::new(
            format!("Cannot {} in non-interactive mode", operation),
            "This operation requires user input but MYC_NON_INTERACTIVE is set",
            "Run interactively or provide required values via environment variables/flags",
            ErrorCategory::UserCancelled,
        )
        .with_example("unset MYC_NON_INTERACTIVE  # or provide --force flag")
    }

    /// Format internal errors.
    pub fn internal_error(details: &str) -> FormattedError {
        FormattedError::new(
            format!("Internal error: {}", details),
            "An unexpected error occurred in the CLI",
            "This is likely a bug. Please report it with the error details",
            ErrorCategory::Internal,
        )
        .with_example("Report at: https://github.com/mycelium-org/mycelium/issues")
    }

    /// Convert an anyhow::Error to a FormattedError with best-effort categorization.
    pub fn from_anyhow_error(error: &Error) -> FormattedError {
        let error_str = error.to_string().to_lowercase();

        // Try to categorize based on error message content
        let category = if error_str.contains("authentication") || error_str.contains("unauthorized")
        {
            ErrorCategory::Authentication
        } else if error_str.contains("permission") || error_str.contains("forbidden") {
            ErrorCategory::Permission
        } else if error_str.contains("not found") || error_str.contains("does not exist") {
            ErrorCategory::NotFound
        } else if error_str.contains("already exists") || error_str.contains("conflict") {
            ErrorCategory::AlreadyExists
        } else if error_str.contains("invalid") || error_str.contains("malformed") {
            ErrorCategory::InvalidInput
        } else if error_str.contains("network")
            || error_str.contains("connection")
            || error_str.contains("timeout")
        {
            ErrorCategory::Network
        } else if error_str.contains("crypto")
            || error_str.contains("signature")
            || error_str.contains("decrypt")
        {
            ErrorCategory::Crypto
        } else if error_str.contains("rate limit") {
            ErrorCategory::RateLimit
        } else if error_str.contains("cancelled") {
            ErrorCategory::UserCancelled
        } else {
            ErrorCategory::Internal
        };

        FormattedError::new(
            error.to_string(),
            "An error occurred while processing your request",
            "Check the error details above and try again",
            category,
        )
    }
}

impl fmt::Display for FormattedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.format_human(false))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_category_exit_codes() {
        assert_eq!(ErrorCategory::Authentication.exit_code(), 3);
        assert_eq!(ErrorCategory::Permission.exit_code(), 4);
        assert_eq!(ErrorCategory::NotFound.exit_code(), 8);
        assert_eq!(ErrorCategory::InvalidInput.exit_code(), 2);
        assert_eq!(ErrorCategory::Internal.exit_code(), 1);
    }

    #[test]
    fn test_formatted_error_creation() {
        let error = FormattedError::new(
            "Test error",
            "This is a test",
            "Fix by testing",
            ErrorCategory::InvalidInput,
        );

        assert_eq!(error.what, "Test error");
        assert_eq!(error.why, "This is a test");
        assert_eq!(error.how_to_fix, "Fix by testing");
        assert_eq!(error.category, ErrorCategory::InvalidInput);
        assert!(error.example.is_none());
    }

    #[test]
    fn test_formatted_error_with_example() {
        let error = FormattedError::new(
            "Test error",
            "This is a test",
            "Fix by testing",
            ErrorCategory::InvalidInput,
        )
        .with_example("myc test command");

        assert_eq!(error.example, Some("myc test command".to_string()));
    }

    #[test]
    fn test_error_formatter_methods() {
        let auth_error = ErrorFormatter::authentication_failed("token expired");
        assert_eq!(auth_error.category, ErrorCategory::Authentication);
        assert!(auth_error.what.contains("token expired"));

        let not_found_error = ErrorFormatter::project_not_found("test-project");
        assert_eq!(not_found_error.category, ErrorCategory::NotFound);
        assert!(not_found_error.what.contains("test-project"));
    }

    #[test]
    fn test_json_formatting() -> Result<()> {
        let error = FormattedError::new(
            "Test error",
            "This is a test",
            "Fix by testing",
            ErrorCategory::InvalidInput,
        );

        let json = error.format_json()?;
        assert!(json.contains("\"success\": false"));
        assert!(json.contains("\"what\": \"Test error\""));
        assert!(json.contains("\"category\": \"invalidinput\""));
        Ok(())
    }

    #[test]
    fn test_human_formatting() {
        let error = FormattedError::new(
            "Test error",
            "This is a test",
            "Fix by testing",
            ErrorCategory::InvalidInput,
        )
        .with_example("myc test");

        let human = error.format_human(false);
        assert!(human.contains("Test error"));
        assert!(human.contains("This is a test"));
        assert!(human.contains("Fix by testing"));
        assert!(human.contains("myc test"));
    }
}
