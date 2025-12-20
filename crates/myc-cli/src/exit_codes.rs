//! Exit code handling for the Mycelium CLI.
//!
//! This module provides consistent exit codes for different error types
//! and utilities for proper process termination.

use crate::error_formatting::{ErrorCategory, ErrorFormatter, FormattedError};
use anyhow::Error;
use std::process;

/// Standard exit codes used by the Mycelium CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCode {
    /// Success
    Success = 0,
    /// General error
    GeneralError = 1,
    /// Invalid arguments or usage
    InvalidArgs = 2,
    /// Authentication error
    AuthError = 3,
    /// Permission denied
    PermissionDenied = 4,
    /// Cryptographic error
    CryptoError = 5,
    /// Network error
    NetworkError = 6,
    /// Conflict or already exists
    Conflict = 7,
    /// Not found
    NotFound = 8,
    /// Internal error
    InternalError = 9,
    /// User cancelled or input required in non-interactive mode
    UserCancelled = 10,
}

impl ExitCode {
    /// Get the exit code as an i32.
    pub fn as_i32(self) -> i32 {
        self as i32
    }

    /// Get a human-readable description of the exit code.
    pub fn description(self) -> &'static str {
        match self {
            ExitCode::Success => "Success",
            ExitCode::GeneralError => "General error",
            ExitCode::InvalidArgs => "Invalid arguments or usage",
            ExitCode::AuthError => "Authentication error",
            ExitCode::PermissionDenied => "Permission denied",
            ExitCode::CryptoError => "Cryptographic error",
            ExitCode::NetworkError => "Network error",
            ExitCode::Conflict => "Conflict or resource already exists",
            ExitCode::NotFound => "Resource not found",
            ExitCode::InternalError => "Internal error",
            ExitCode::UserCancelled => "User cancelled or input required in non-interactive mode",
        }
    }

    /// Convert from an ErrorCategory to an ExitCode.
    pub fn from_error_category(category: ErrorCategory) -> Self {
        match category {
            ErrorCategory::Authentication => ExitCode::AuthError,
            ErrorCategory::Permission => ExitCode::PermissionDenied,
            ErrorCategory::NotFound => ExitCode::NotFound,
            ErrorCategory::AlreadyExists => ExitCode::Conflict,
            ErrorCategory::InvalidInput => ExitCode::InvalidArgs,
            ErrorCategory::Network => ExitCode::NetworkError,
            ErrorCategory::Crypto => ExitCode::CryptoError,
            ErrorCategory::Conflict => ExitCode::Conflict,
            ErrorCategory::RateLimit => ExitCode::NetworkError,
            ErrorCategory::Internal => ExitCode::InternalError,
            ErrorCategory::UserCancelled => ExitCode::UserCancelled,
        }
    }

    /// Convert from an anyhow::Error to an ExitCode with best-effort categorization.
    pub fn from_anyhow_error(error: &Error) -> Self {
        let formatted_error = ErrorFormatter::from_anyhow_error(error);
        Self::from_error_category(formatted_error.category)
    }
}

/// Exit handler that manages process termination with appropriate codes.
pub struct ExitHandler {
    /// Whether to print exit codes in verbose mode
    verbose: bool,
    /// Whether we're in JSON mode
    json_mode: bool,
}

impl ExitHandler {
    /// Create a new exit handler.
    pub fn new(verbose: bool, json_mode: bool) -> Self {
        Self { verbose, json_mode }
    }

    /// Exit with success code.
    pub fn success(&self) -> ! {
        if self.verbose && !self.json_mode {
            eprintln!("Exiting with code 0 (success)");
        }
        process::exit(ExitCode::Success.as_i32());
    }

    /// Exit with a specific exit code.
    pub fn exit_with_code(&self, code: ExitCode) -> ! {
        if self.verbose && !self.json_mode {
            eprintln!(
                "Exiting with code {} ({})",
                code.as_i32(),
                code.description()
            );
        }
        process::exit(code.as_i32());
    }

    /// Exit with an error, printing the formatted error message.
    pub fn exit_with_error(&self, error: FormattedError) -> ! {
        let exit_code = ExitCode::from_error_category(error.category);

        if self.json_mode {
            if let Ok(json) = error.format_json() {
                eprintln!("{}", json);
            } else {
                eprintln!("{{\"success\": false, \"error\": \"Failed to format error as JSON\"}}");
            }
        } else {
            eprintln!("{}", error.format_human(true));
        }

        if self.verbose && !self.json_mode {
            eprintln!(
                "Exiting with code {} ({})",
                exit_code.as_i32(),
                exit_code.description()
            );
        }

        process::exit(exit_code.as_i32());
    }

    /// Exit with an anyhow error, converting it to a formatted error first.
    pub fn exit_with_anyhow_error(&self, error: &Error) -> ! {
        let formatted_error = ErrorFormatter::from_anyhow_error(error);
        self.exit_with_error(formatted_error);
    }

    /// Handle a Result, exiting on error or returning the value on success.
    pub fn handle_result<T>(&self, result: Result<T, Error>) -> T {
        match result {
            Ok(value) => value,
            Err(error) => self.exit_with_anyhow_error(&error),
        }
    }

    /// Handle a Result with a custom error formatter.
    pub fn handle_result_with_formatter<T, F>(&self, result: Result<T, Error>, formatter: F) -> T
    where
        F: FnOnce(&Error) -> FormattedError,
    {
        match result {
            Ok(value) => value,
            Err(error) => {
                let formatted_error = formatter(&error);
                self.exit_with_error(formatted_error);
            }
        }
    }
}

/// Macro for early exit with a specific exit code.
#[macro_export]
macro_rules! exit_with_code {
    ($code:expr) => {
        std::process::exit($code.as_i32());
    };
}

/// Macro for early exit with an error message.
#[macro_export]
macro_rules! exit_with_error {
    ($error:expr) => {
        eprintln!("{}", $error);
        std::process::exit($crate::exit_codes::ExitCode::GeneralError.as_i32());
    };
}

/// Utility functions for common exit patterns.
pub mod utils {
    use super::*;
    use crate::error_formatting::ErrorFormatter;

    /// Exit with authentication error.
    pub fn exit_auth_error(details: &str) -> ! {
        let error = ErrorFormatter::authentication_failed(details);
        eprintln!("{}", error.format_human(true));
        process::exit(ExitCode::AuthError.as_i32());
    }

    /// Exit with permission denied error.
    pub fn exit_permission_denied(resource: &str, required_permission: &str) -> ! {
        let error = ErrorFormatter::permission_denied(resource, required_permission);
        eprintln!("{}", error.format_human(true));
        process::exit(ExitCode::PermissionDenied.as_i32());
    }

    /// Exit with not found error.
    pub fn exit_not_found(resource_type: &str, identifier: &str) -> ! {
        let error = match resource_type {
            "project" => ErrorFormatter::project_not_found(identifier),
            "profile" => ErrorFormatter::profile_not_found(identifier),
            "device" => ErrorFormatter::device_not_found(identifier),
            _ => {
                ErrorFormatter::internal_error(&format!("Unknown resource type: {}", resource_type))
            }
        };
        eprintln!("{}", error.format_human(true));
        process::exit(ExitCode::NotFound.as_i32());
    }

    /// Exit with invalid input error.
    pub fn exit_invalid_input(field: &str, value: &str, constraint: &str) -> ! {
        let error = ErrorFormatter::invalid_input(field, value, constraint);
        eprintln!("{}", error.format_human(true));
        process::exit(ExitCode::InvalidArgs.as_i32());
    }

    /// Exit with network error.
    pub fn exit_network_error(operation: &str, details: &str) -> ! {
        let error = ErrorFormatter::network_error(operation, details);
        eprintln!("{}", error.format_human(true));
        process::exit(ExitCode::NetworkError.as_i32());
    }

    /// Exit with crypto error.
    pub fn exit_crypto_error(details: &str) -> ! {
        let error = if details.contains("passphrase") {
            ErrorFormatter::invalid_passphrase()
        } else if details.contains("signature") {
            ErrorFormatter::signature_verification_failed("unknown file")
        } else {
            ErrorFormatter::internal_error(&format!("Cryptographic error: {}", details))
        };
        eprintln!("{}", error.format_human(true));
        process::exit(ExitCode::CryptoError.as_i32());
    }

    /// Exit with user cancelled error.
    pub fn exit_user_cancelled(operation: &str) -> ! {
        let error = ErrorFormatter::user_cancelled(operation);
        eprintln!("{}", error.format_human(true));
        process::exit(ExitCode::UserCancelled.as_i32());
    }

    /// Exit with non-interactive mode error.
    pub fn exit_non_interactive_input_required(operation: &str) -> ! {
        let error = ErrorFormatter::non_interactive_input_required(operation);
        eprintln!("{}", error.format_human(true));
        process::exit(ExitCode::UserCancelled.as_i32());
    }
}

/// Signal handler for graceful shutdown.
pub struct SignalHandler {
    exit_handler: ExitHandler,
}

impl SignalHandler {
    /// Create a new signal handler.
    pub fn new(exit_handler: ExitHandler) -> Self {
        Self { exit_handler }
    }

    /// Install signal handlers for graceful shutdown.
    pub fn install(&self) {
        // Note: In a full implementation, this would set up signal handlers
        // for SIGINT, SIGTERM, etc. to ensure graceful cleanup.
        // For now, this is a placeholder.
    }

    /// Handle SIGINT (Ctrl+C).
    pub fn handle_sigint(&self) -> ! {
        if !self.exit_handler.json_mode {
            eprintln!("\nOperation cancelled by user");
        }
        self.exit_handler.exit_with_code(ExitCode::UserCancelled);
    }

    /// Handle SIGTERM.
    pub fn handle_sigterm(&self) -> ! {
        if !self.exit_handler.json_mode {
            eprintln!("Received termination signal");
        }
        self.exit_handler.exit_with_code(ExitCode::UserCancelled);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exit_code_values() {
        assert_eq!(ExitCode::Success.as_i32(), 0);
        assert_eq!(ExitCode::GeneralError.as_i32(), 1);
        assert_eq!(ExitCode::InvalidArgs.as_i32(), 2);
        assert_eq!(ExitCode::AuthError.as_i32(), 3);
        assert_eq!(ExitCode::PermissionDenied.as_i32(), 4);
        assert_eq!(ExitCode::CryptoError.as_i32(), 5);
        assert_eq!(ExitCode::NetworkError.as_i32(), 6);
        assert_eq!(ExitCode::Conflict.as_i32(), 7);
        assert_eq!(ExitCode::NotFound.as_i32(), 8);
        assert_eq!(ExitCode::InternalError.as_i32(), 9);
        assert_eq!(ExitCode::UserCancelled.as_i32(), 10);
    }

    #[test]
    fn test_exit_code_descriptions() {
        assert_eq!(ExitCode::Success.description(), "Success");
        assert_eq!(ExitCode::AuthError.description(), "Authentication error");
        assert_eq!(ExitCode::NotFound.description(), "Resource not found");
    }

    #[test]
    fn test_exit_code_from_error_category() {
        assert_eq!(
            ExitCode::from_error_category(ErrorCategory::Authentication),
            ExitCode::AuthError
        );
        assert_eq!(
            ExitCode::from_error_category(ErrorCategory::NotFound),
            ExitCode::NotFound
        );
        assert_eq!(
            ExitCode::from_error_category(ErrorCategory::Network),
            ExitCode::NetworkError
        );
    }

    #[test]
    fn test_exit_handler_creation() {
        let handler = ExitHandler::new(true, false);
        assert!(handler.verbose);
        assert!(!handler.json_mode);

        let json_handler = ExitHandler::new(false, true);
        assert!(!json_handler.verbose);
        assert!(json_handler.json_mode);
    }
}
