//! GitHub error types.

use thiserror::Error;

/// Errors that can occur during GitHub operations.
#[derive(Debug, Error)]
pub enum GitHubError {
    /// Token expired or revoked (HTTP 401).
    #[error(
        "unauthorized: token expired or revoked - please re-authenticate with 'myc profile add'"
    )]
    Unauthorized,

    /// Rate limited or insufficient permissions (HTTP 403).
    #[error("forbidden: {reason}")]
    Forbidden {
        /// Reason for forbidden access.
        reason: String,
    },

    /// Repository or file not found (HTTP 404).
    #[error("not found: {resource}")]
    NotFound {
        /// Resource that was not found.
        resource: String,
    },

    /// SHA mismatch, concurrent modification detected (HTTP 409).
    #[error("conflict: concurrent modification detected - pull latest changes and retry")]
    Conflict,

    /// GitHub API validation error (HTTP 422).
    #[error("validation error: {0}")]
    ValidationError(String),

    /// Network error or timeout.
    #[error("network error: {0}")]
    NetworkError(String),

    /// Rate limit exceeded.
    #[error("rate limit exceeded: GitHub API rate limit has been reached. The limit will reset in {reset_at}. Please wait before making more requests, or use a different authentication token.")]
    RateLimitExceeded {
        /// Time when rate limit resets (human-readable format).
        reset_at: String,
    },

    /// JSON parsing error.
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    /// HTTP request error.
    #[error("HTTP error: {0}")]
    HttpError(String),

    /// OIDC token validation failed.
    #[error("OIDC validation failed: {0}")]
    OidcValidationFailed(String),

    /// Cache error (failed to read/write cache).
    #[error("Cache error: {0}")]
    CacheError(String),
}

/// Result type for GitHub operations.
pub type Result<T> = std::result::Result<T, GitHubError>;

impl GitHubError {
    /// Checks if this error is retryable.
    ///
    /// Some errors like network errors and rate limits are transient and
    /// can be retried. Others like authentication failures are permanent.
    ///
    /// # Returns
    ///
    /// Returns `true` if the operation can be retried, `false` otherwise.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            GitHubError::NetworkError(_) | GitHubError::RateLimitExceeded { .. }
        )
    }

    /// Checks if this error indicates an authentication problem.
    ///
    /// # Returns
    ///
    /// Returns `true` if the error is due to authentication issues.
    pub fn is_auth_error(&self) -> bool {
        matches!(self, GitHubError::Unauthorized)
    }

    /// Checks if this error indicates a permission problem.
    ///
    /// # Returns
    ///
    /// Returns `true` if the error is due to insufficient permissions.
    pub fn is_permission_error(&self) -> bool {
        matches!(self, GitHubError::Forbidden { .. })
    }
    /// Maps an octocrab error to a GitHubError with actionable messages.
    ///
    /// This method examines the error message to determine the HTTP status code
    /// and provides appropriate error messages with guidance on how to resolve
    /// the issue.
    ///
    /// # Arguments
    ///
    /// * `error` - The octocrab error to map
    /// * `context` - Additional context about what operation failed (e.g., "repository", "file")
    ///
    /// # Returns
    ///
    /// Returns a GitHubError with an actionable error message.
    pub fn from_octocrab(error: octocrab::Error, context: &str) -> Self {
        let error_msg = error.to_string();

        // Check for HTTP status codes in the error message
        if error_msg.contains("401") {
            GitHubError::Unauthorized
        } else if error_msg.contains("403") {
            // Check if this is a rate limit error
            if error_msg.to_lowercase().contains("rate limit") {
                // Try to extract reset time from error message, or use a generic message
                GitHubError::RateLimitExceeded {
                    reset_at: "unknown time (check GitHub API status)".to_string(),
                }
            } else {
                GitHubError::Forbidden {
                    reason: format!(
                        "insufficient permissions to access {}. Verify that your token has the required scopes (repo, read:user, user:email)",
                        context
                    ),
                }
            }
        } else if error_msg.contains("404") {
            GitHubError::NotFound {
                resource: format!(
                    "{}. Verify that the repository exists and you have access to it",
                    context
                ),
            }
        } else if error_msg.contains("409") {
            GitHubError::Conflict
        } else if error_msg.contains("422") {
            GitHubError::ValidationError(format!(
                "GitHub API validation failed for {}. Check that the input is valid",
                context
            ))
        } else {
            // Generic network error
            GitHubError::NetworkError(format!("failed to access {}: {}", context, error_msg))
        }
    }

    /// Creates a rate limit exceeded error with a formatted reset time.
    ///
    /// # Arguments
    ///
    /// * `reset_at_unix` - Unix timestamp when the rate limit resets
    ///
    /// # Returns
    ///
    /// Returns a RateLimitExceeded error with a human-readable reset time.
    pub fn rate_limit_exceeded(reset_at_unix: u64) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let reset_time = if reset_at_unix > now {
            let seconds = reset_at_unix - now;
            if seconds < 60 {
                format!("{} seconds", seconds)
            } else if seconds < 3600 {
                format!("{} minutes", seconds / 60)
            } else {
                format!("{} hours {} minutes", seconds / 3600, (seconds % 3600) / 60)
            }
        } else {
            "now".to_string()
        };

        GitHubError::RateLimitExceeded {
            reset_at: reset_time,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unauthorized_error_message() {
        let error = GitHubError::Unauthorized;
        let message = error.to_string();
        assert!(message.contains("unauthorized"));
        assert!(message.contains("re-authenticate"));
        assert!(message.contains("myc profile add"));
    }

    #[test]
    fn test_forbidden_error_message() {
        let error = GitHubError::Forbidden {
            reason: "insufficient permissions".to_string(),
        };
        let message = error.to_string();
        assert!(message.contains("forbidden"));
        assert!(message.contains("insufficient permissions"));
    }

    #[test]
    fn test_not_found_error_message() {
        let error = GitHubError::NotFound {
            resource: "repository myorg/myrepo".to_string(),
        };
        let message = error.to_string();
        assert!(message.contains("not found"));
        assert!(message.contains("repository myorg/myrepo"));
    }

    #[test]
    fn test_conflict_error_message() {
        let error = GitHubError::Conflict;
        let message = error.to_string();
        assert!(message.contains("conflict"));
        assert!(message.contains("concurrent modification"));
        assert!(message.contains("pull latest changes"));
        assert!(message.contains("retry"));
    }

    #[test]
    fn test_validation_error_message() {
        let error = GitHubError::ValidationError("invalid name".to_string());
        let message = error.to_string();
        assert!(message.contains("validation error"));
        assert!(message.contains("invalid name"));
    }

    #[test]
    fn test_rate_limit_error_message() {
        let error = GitHubError::RateLimitExceeded {
            reset_at: "30 minutes".to_string(),
        };
        let message = error.to_string();
        assert!(message.contains("rate limit exceeded"));
        assert!(message.contains("30 minutes"));
        assert!(message.contains("wait before making more requests"));
    }

    #[test]
    fn test_network_error_message() {
        let error = GitHubError::NetworkError("connection timeout".to_string());
        let message = error.to_string();
        assert!(message.contains("network error"));
        assert!(message.contains("connection timeout"));
    }

    #[test]
    fn test_is_retryable() {
        assert!(GitHubError::NetworkError("timeout".to_string()).is_retryable());
        assert!(GitHubError::RateLimitExceeded {
            reset_at: "now".to_string()
        }
        .is_retryable());

        assert!(!GitHubError::Unauthorized.is_retryable());
        assert!(!GitHubError::Forbidden {
            reason: "no access".to_string()
        }
        .is_retryable());
        assert!(!GitHubError::NotFound {
            resource: "repo".to_string()
        }
        .is_retryable());
        assert!(!GitHubError::Conflict.is_retryable());
        assert!(!GitHubError::ValidationError("bad input".to_string()).is_retryable());
    }

    #[test]
    fn test_is_auth_error() {
        assert!(GitHubError::Unauthorized.is_auth_error());

        assert!(!GitHubError::Forbidden {
            reason: "no access".to_string()
        }
        .is_auth_error());
        assert!(!GitHubError::NetworkError("timeout".to_string()).is_auth_error());
    }

    #[test]
    fn test_is_permission_error() {
        assert!(GitHubError::Forbidden {
            reason: "no access".to_string()
        }
        .is_permission_error());

        assert!(!GitHubError::Unauthorized.is_permission_error());
        assert!(!GitHubError::NetworkError("timeout".to_string()).is_permission_error());
    }

    #[test]
    fn test_rate_limit_exceeded_formatting() {
        // Test with future reset time
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // 30 seconds from now
        let error = GitHubError::rate_limit_exceeded(now + 30);
        let message = error.to_string();
        assert!(message.contains("30 seconds"));

        // 2 minutes from now
        let error = GitHubError::rate_limit_exceeded(now + 120);
        let message = error.to_string();
        assert!(message.contains("2 minutes"));

        // 1 hour from now
        let error = GitHubError::rate_limit_exceeded(now + 3600);
        let message = error.to_string();
        assert!(message.contains("1 hours"));

        // Past time
        let error = GitHubError::rate_limit_exceeded(now - 100);
        let message = error.to_string();
        assert!(message.contains("now"));
    }

    #[test]
    fn test_error_type_messages() {
        // Test that all error types have appropriate messages
        // We can't easily create octocrab errors in tests, so we verify
        // that each error type produces the expected message format

        let err = GitHubError::Unauthorized;
        assert!(err.to_string().contains("unauthorized"));
        assert!(err.to_string().contains("re-authenticate"));

        let err = GitHubError::RateLimitExceeded {
            reset_at: "30 minutes".to_string(),
        };
        assert!(err.to_string().contains("rate limit"));
        assert!(err.to_string().contains("30 minutes"));

        let err = GitHubError::Forbidden {
            reason: "no access".to_string(),
        };
        assert!(err.to_string().contains("forbidden"));
        assert!(err.to_string().contains("no access"));

        let err = GitHubError::NotFound {
            resource: "repository".to_string(),
        };
        assert!(err.to_string().contains("not found"));
        assert!(err.to_string().contains("repository"));

        let err = GitHubError::Conflict;
        assert!(err.to_string().contains("conflict"));
        assert!(err.to_string().contains("concurrent modification"));

        let err = GitHubError::ValidationError("invalid input".to_string());
        assert!(err.to_string().contains("validation"));
        assert!(err.to_string().contains("invalid input"));

        let err = GitHubError::NetworkError("timeout".to_string());
        assert!(err.to_string().contains("network"));
        assert!(err.to_string().contains("timeout"));
    }
}
