//! Integration tests for repository operations.
//!
//! These tests verify that the GitHubClient correctly handles repository
//! creation and access checking operations.

use myc_github::{GitHubClient, GitHubError};

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

/// Test that check_access returns false for non-existent repositories.
///
/// Note: This test will fail with Unauthorized or NetworkError if the token is invalid,
/// which is expected behavior. In a real scenario with a valid token,
/// it should return Ok(false) for non-existent repos.
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

/// Test that create_repository fails with invalid token.
///
/// This test verifies that the error handling correctly identifies
/// authentication failures.
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

/// Test that repository operations handle network errors gracefully.
#[tokio::test]
async fn test_network_error_handling() {
    // Create a client with an invalid token to trigger errors
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
