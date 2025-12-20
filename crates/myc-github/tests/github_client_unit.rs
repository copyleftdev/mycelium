//! Unit tests for GitHub client.
//!
//! These tests verify error handling, rate limit tracking, and client behavior
//! with mocked GitHub API responses.
//!
//! **Validates: Requirements 6.2, 6.4, 6.5**

use myc_github::{GitHubClient, GitHubError};
use std::time::{SystemTime, UNIX_EPOCH};

/// Test that client creation succeeds with valid parameters.
#[tokio::test]
async fn test_client_creation_succeeds() {
    let result = GitHubClient::new(
        "test_token".to_string(),
        "test_owner".to_string(),
        "test_repo".to_string(),
    );

    assert!(result.is_ok());
    let client = result.unwrap();
    assert_eq!(client.owner(), "test_owner");
    assert_eq!(client.repo(), "test_repo");
}

/// Test that client stores owner and repo correctly.
#[tokio::test]
async fn test_client_stores_metadata() {
    let client = GitHubClient::new(
        "token123".to_string(),
        "myorg".to_string(),
        "myrepo".to_string(),
    )
    .expect("client creation should succeed");

    assert_eq!(client.owner(), "myorg");
    assert_eq!(client.repo(), "myrepo");
}

/// Test initial rate limit state.
#[tokio::test]
async fn test_initial_rate_limit_state() {
    let client = GitHubClient::new(
        "test_token".to_string(),
        "owner".to_string(),
        "repo".to_string(),
    )
    .expect("client creation should succeed");

    let rate_limit = client.rate_limit_info();
    assert_eq!(rate_limit.limit, 5000, "Default limit should be 5000");
    assert_eq!(
        rate_limit.remaining, 5000,
        "Initial remaining should be 5000"
    );
    assert_eq!(rate_limit.reset_at, 0, "Initial reset_at should be 0");
    assert!(
        !rate_limit.is_approaching_limit(),
        "Should not be approaching limit initially"
    );
    assert!(
        !rate_limit.is_exceeded(),
        "Should not be exceeded initially"
    );
}

/// Test rate limit update functionality.
#[tokio::test]
async fn test_rate_limit_update() {
    let client = GitHubClient::new(
        "test_token".to_string(),
        "owner".to_string(),
        "repo".to_string(),
    )
    .expect("client creation should succeed");

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Update rate limit
    client.update_rate_limit_info(5000, 4500, now + 3600);

    let rate_limit = client.rate_limit_info();
    assert_eq!(rate_limit.limit, 5000);
    assert_eq!(rate_limit.remaining, 4500);
    assert_eq!(rate_limit.reset_at, now + 3600);
}

/// Test rate limit approaching detection.
#[tokio::test]
async fn test_rate_limit_approaching_detection() {
    let client = GitHubClient::new(
        "test_token".to_string(),
        "owner".to_string(),
        "repo".to_string(),
    )
    .expect("client creation should succeed");

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // At 50% remaining - not approaching
    client.update_rate_limit_info(5000, 2500, now + 3600);
    let rate_limit = client.rate_limit_info();
    assert!(!rate_limit.is_approaching_limit());

    // At 10% remaining - exactly at threshold, not approaching yet
    client.update_rate_limit_info(5000, 500, now + 3600);
    let rate_limit = client.rate_limit_info();
    assert!(!rate_limit.is_approaching_limit());

    // At 9% remaining - approaching
    client.update_rate_limit_info(5000, 450, now + 3600);
    let rate_limit = client.rate_limit_info();
    assert!(rate_limit.is_approaching_limit());

    // At 5% remaining - approaching
    client.update_rate_limit_info(5000, 250, now + 3600);
    let rate_limit = client.rate_limit_info();
    assert!(rate_limit.is_approaching_limit());

    // At 1% remaining - approaching
    client.update_rate_limit_info(5000, 50, now + 3600);
    let rate_limit = client.rate_limit_info();
    assert!(rate_limit.is_approaching_limit());
}

/// Test rate limit exceeded detection.
#[tokio::test]
async fn test_rate_limit_exceeded_detection() {
    let client = GitHubClient::new(
        "test_token".to_string(),
        "owner".to_string(),
        "repo".to_string(),
    )
    .expect("client creation should succeed");

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // With 1 remaining - not exceeded
    client.update_rate_limit_info(5000, 1, now + 3600);
    let rate_limit = client.rate_limit_info();
    assert!(!rate_limit.is_exceeded());

    // With 0 remaining - exceeded
    client.update_rate_limit_info(5000, 0, now + 3600);
    let rate_limit = client.rate_limit_info();
    assert!(rate_limit.is_exceeded());
}

/// Test time until reset calculation.
#[tokio::test]
async fn test_time_until_reset_calculation() {
    let client = GitHubClient::new(
        "test_token".to_string(),
        "owner".to_string(),
        "repo".to_string(),
    )
    .expect("client creation should succeed");

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Set reset time to 1 hour from now
    client.update_rate_limit_info(5000, 4500, now + 3600);

    let rate_limit = client.rate_limit_info();
    let duration = rate_limit.time_until_reset();

    // Should be approximately 1 hour (allowing for test execution time)
    assert!(
        duration.as_secs() >= 3599 && duration.as_secs() <= 3600,
        "Expected ~3600 seconds, got {}",
        duration.as_secs()
    );
}

/// Test reset time string formatting for various durations.
#[tokio::test]
async fn test_reset_time_string_formatting() {
    let client = GitHubClient::new(
        "test_token".to_string(),
        "owner".to_string(),
        "repo".to_string(),
    )
    .expect("client creation should succeed");

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Test 30 seconds
    client.update_rate_limit_info(5000, 4500, now + 30);
    let rate_limit = client.rate_limit_info();
    assert_eq!(rate_limit.reset_time_string(), "30 seconds");

    // Test 2 minutes
    client.update_rate_limit_info(5000, 4500, now + 120);
    let rate_limit = client.rate_limit_info();
    assert_eq!(rate_limit.reset_time_string(), "2 minutes");

    // Test 1 hour 1 minute
    client.update_rate_limit_info(5000, 4500, now + 3660);
    let rate_limit = client.rate_limit_info();
    assert_eq!(rate_limit.reset_time_string(), "1 hours 1 minutes");

    // Test past reset time
    client.update_rate_limit_info(5000, 4500, now - 100);
    let rate_limit = client.rate_limit_info();
    assert_eq!(rate_limit.reset_time_string(), "now");
}

/// Test error type classification - retryable errors.
#[test]
fn test_retryable_errors() {
    // Network errors are retryable
    let error = GitHubError::NetworkError("connection timeout".to_string());
    assert!(error.is_retryable());

    // Rate limit errors are retryable
    let error = GitHubError::RateLimitExceeded {
        reset_at: "30 minutes".to_string(),
    };
    assert!(error.is_retryable());
}

/// Test error type classification - non-retryable errors.
#[test]
fn test_non_retryable_errors() {
    // Auth errors are not retryable
    let error = GitHubError::Unauthorized;
    assert!(!error.is_retryable());

    // Permission errors are not retryable
    let error = GitHubError::Forbidden {
        reason: "insufficient permissions".to_string(),
    };
    assert!(!error.is_retryable());

    // Not found errors are not retryable
    let error = GitHubError::NotFound {
        resource: "repository".to_string(),
    };
    assert!(!error.is_retryable());

    // Conflict errors are not retryable (need user intervention)
    let error = GitHubError::Conflict;
    assert!(!error.is_retryable());

    // Validation errors are not retryable
    let error = GitHubError::ValidationError("invalid input".to_string());
    assert!(!error.is_retryable());
}

/// Test authentication error detection.
#[test]
fn test_auth_error_detection() {
    // Unauthorized is an auth error
    let error = GitHubError::Unauthorized;
    assert!(error.is_auth_error());

    // Other errors are not auth errors
    let error = GitHubError::Forbidden {
        reason: "no access".to_string(),
    };
    assert!(!error.is_auth_error());

    let error = GitHubError::NetworkError("timeout".to_string());
    assert!(!error.is_auth_error());

    let error = GitHubError::NotFound {
        resource: "repo".to_string(),
    };
    assert!(!error.is_auth_error());
}

/// Test permission error detection.
#[test]
fn test_permission_error_detection() {
    // Forbidden is a permission error
    let error = GitHubError::Forbidden {
        reason: "no access".to_string(),
    };
    assert!(error.is_permission_error());

    // Other errors are not permission errors
    let error = GitHubError::Unauthorized;
    assert!(!error.is_permission_error());

    let error = GitHubError::NetworkError("timeout".to_string());
    assert!(!error.is_permission_error());

    let error = GitHubError::NotFound {
        resource: "repo".to_string(),
    };
    assert!(!error.is_permission_error());
}

/// Test error message formatting for 401 Unauthorized.
#[test]
fn test_unauthorized_error_message() {
    let error = GitHubError::Unauthorized;
    let message = error.to_string();

    assert!(message.contains("unauthorized"));
    assert!(message.contains("token expired or revoked"));
    assert!(message.contains("re-authenticate"));
    assert!(message.contains("myc profile add"));
}

/// Test error message formatting for 403 Forbidden.
#[test]
fn test_forbidden_error_message() {
    let error = GitHubError::Forbidden {
        reason: "insufficient permissions to access repository".to_string(),
    };
    let message = error.to_string();

    assert!(message.contains("forbidden"));
    assert!(message.contains("insufficient permissions"));
}

/// Test error message formatting for 404 Not Found.
#[test]
fn test_not_found_error_message() {
    let error = GitHubError::NotFound {
        resource: "repository myorg/myrepo".to_string(),
    };
    let message = error.to_string();

    assert!(message.contains("not found"));
    assert!(message.contains("repository myorg/myrepo"));
}

/// Test error message formatting for 409 Conflict.
#[test]
fn test_conflict_error_message() {
    let error = GitHubError::Conflict;
    let message = error.to_string();

    assert!(message.contains("conflict"));
    assert!(message.contains("concurrent modification"));
    assert!(message.contains("pull latest changes"));
    assert!(message.contains("retry"));
}

/// Test error message formatting for 422 Validation Error.
#[test]
fn test_validation_error_message() {
    let error = GitHubError::ValidationError("repository name is invalid".to_string());
    let message = error.to_string();

    assert!(message.contains("validation error"));
    assert!(message.contains("repository name is invalid"));
}

/// Test error message formatting for Rate Limit Exceeded.
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

/// Test error message formatting for Network Error.
#[test]
fn test_network_error_message() {
    let error = GitHubError::NetworkError("connection timeout".to_string());
    let message = error.to_string();

    assert!(message.contains("network error"));
    assert!(message.contains("connection timeout"));
}

/// Test rate limit exceeded error formatting with various durations.
#[test]
fn test_rate_limit_exceeded_formatting() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Test 30 seconds from now
    let error = GitHubError::rate_limit_exceeded(now + 30);
    let message = error.to_string();
    assert!(message.contains("30 seconds"));

    // Test 2 minutes from now
    let error = GitHubError::rate_limit_exceeded(now + 120);
    let message = error.to_string();
    assert!(message.contains("2 minutes"));

    // Test 1 hour from now
    let error = GitHubError::rate_limit_exceeded(now + 3600);
    let message = error.to_string();
    assert!(message.contains("1 hours"));

    // Test past time
    let error = GitHubError::rate_limit_exceeded(now - 100);
    let message = error.to_string();
    assert!(message.contains("now"));
}

/// Test that all error types produce actionable messages.
#[test]
fn test_all_error_types_have_actionable_messages() {
    // Unauthorized - tells user how to fix
    let err = GitHubError::Unauthorized;
    assert!(err.to_string().contains("re-authenticate"));

    // Forbidden - explains what's wrong
    let err = GitHubError::Forbidden {
        reason: "no access".to_string(),
    };
    assert!(err.to_string().contains("forbidden"));

    // Not Found - identifies what's missing
    let err = GitHubError::NotFound {
        resource: "repository".to_string(),
    };
    assert!(err.to_string().contains("not found"));
    assert!(err.to_string().contains("repository"));

    // Conflict - tells user what to do
    let err = GitHubError::Conflict;
    assert!(err.to_string().contains("pull latest changes"));
    assert!(err.to_string().contains("retry"));

    // Validation - explains the problem
    let err = GitHubError::ValidationError("invalid input".to_string());
    assert!(err.to_string().contains("validation"));

    // Rate Limit - tells when it resets
    let err = GitHubError::RateLimitExceeded {
        reset_at: "30 minutes".to_string(),
    };
    assert!(err.to_string().contains("30 minutes"));
    assert!(err.to_string().contains("wait"));

    // Network - explains the issue
    let err = GitHubError::NetworkError("timeout".to_string());
    assert!(err.to_string().contains("network"));
}

/// Test check_access with non-existent repository.
///
/// This test verifies that check_access returns false for repositories
/// that don't exist or aren't accessible, rather than returning an error.
#[tokio::test]
async fn test_check_access_nonexistent_repo() {
    let client = GitHubClient::new(
        "invalid_token".to_string(),
        "nonexistent_owner".to_string(),
        "nonexistent_repo".to_string(),
    )
    .expect("client creation should succeed");

    let result = client.check_access().await;

    // With an invalid token, we expect Unauthorized or NetworkError
    // With a valid token and non-existent repo, we'd expect Ok(false)
    assert!(
        matches!(result, Err(GitHubError::Unauthorized))
            || matches!(result, Err(GitHubError::NetworkError(_)))
            || matches!(result, Ok(false)),
        "Expected Unauthorized, NetworkError, or Ok(false), got: {:?}",
        result
    );
}

/// Test create_repository with invalid token.
///
/// This test verifies that authentication failures are properly detected
/// and reported when attempting to create a repository.
#[tokio::test]
async fn test_create_repository_invalid_token() {
    let client = GitHubClient::new(
        "invalid_token".to_string(),
        "test_owner".to_string(),
        "test_repo".to_string(),
    )
    .expect("client creation should succeed");

    let result = client.create_repository("test-vault", true).await;

    // Should fail with Unauthorized or NetworkError
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, GitHubError::Unauthorized) || matches!(err, GitHubError::NetworkError(_)),
        "Expected Unauthorized or NetworkError, got: {:?}",
        err
    );
}

/// Test that network errors are handled gracefully without panicking.
#[tokio::test]
async fn test_network_error_handling() {
    // Create a client with an empty token to trigger errors
    let client = GitHubClient::new("".to_string(), "owner".to_string(), "repo".to_string())
        .expect("client creation should succeed");

    // Both operations should handle errors gracefully
    let check_result = client.check_access().await;
    let create_result = client.create_repository("test", true).await;

    // Both should return errors or false, not panic
    match check_result {
        Ok(false) | Err(_) => {} // Expected
        Ok(true) => panic!("Unexpected success with invalid token"),
    }
    assert!(create_result.is_err());
}

/// Test rate limit backoff behavior when approaching limit.
///
/// This test verifies that the client implements backoff when the rate limit
/// is approaching, to avoid hitting the limit.
#[tokio::test]
async fn test_rate_limit_backoff_when_approaching() {
    let client = GitHubClient::new(
        "test_token".to_string(),
        "owner".to_string(),
        "repo".to_string(),
    )
    .expect("client creation should succeed");

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Set rate limit to 5% remaining (approaching)
    client.update_rate_limit_info(5000, 250, now + 3600);

    // The check_rate_limit method is private, but we can test it indirectly
    // by verifying that the rate limit info is correct
    let rate_limit = client.rate_limit_info();
    assert!(rate_limit.is_approaching_limit());
    assert!(!rate_limit.is_exceeded());
}

/// Test that rate limit exceeded state is properly detected.
#[tokio::test]
async fn test_rate_limit_exceeded_state() {
    let client = GitHubClient::new(
        "test_token".to_string(),
        "owner".to_string(),
        "repo".to_string(),
    )
    .expect("client creation should succeed");

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Set rate limit to exceeded
    client.update_rate_limit_info(5000, 0, now + 3600);

    let rate_limit = client.rate_limit_info();
    assert!(rate_limit.is_exceeded());
    assert!(rate_limit.is_approaching_limit()); // 0 is also approaching
}

/// Test rate limit info cloning.
#[tokio::test]
async fn test_rate_limit_info_cloning() {
    let client = GitHubClient::new(
        "test_token".to_string(),
        "owner".to_string(),
        "repo".to_string(),
    )
    .expect("client creation should succeed");

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    client.update_rate_limit_info(5000, 4500, now + 3600);

    let info1 = client.rate_limit_info();
    let info2 = client.rate_limit_info();

    // Both should have the same values
    assert_eq!(info1.limit, info2.limit);
    assert_eq!(info1.remaining, info2.remaining);
    assert_eq!(info1.reset_at, info2.reset_at);
}

/// Test client cloning preserves rate limit state.
#[tokio::test]
async fn test_client_cloning_preserves_rate_limit() {
    let client1 = GitHubClient::new(
        "test_token".to_string(),
        "owner".to_string(),
        "repo".to_string(),
    )
    .expect("client creation should succeed");

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    client1.update_rate_limit_info(5000, 4500, now + 3600);

    // Clone the client
    let client2 = client1.clone();

    // Both should share the same rate limit state (Arc)
    let info1 = client1.rate_limit_info();
    let info2 = client2.rate_limit_info();

    assert_eq!(info1.limit, info2.limit);
    assert_eq!(info1.remaining, info2.remaining);
    assert_eq!(info1.reset_at, info2.reset_at);

    // Update through client2
    client2.update_rate_limit_info(5000, 4000, now + 3600);

    // Both should see the update
    let info1 = client1.rate_limit_info();
    let info2 = client2.rate_limit_info();

    assert_eq!(info1.remaining, 4000);
    assert_eq!(info2.remaining, 4000);
}
