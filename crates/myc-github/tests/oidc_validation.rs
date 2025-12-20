//! Integration tests for OIDC validation.
//!
//! These tests verify that the OIDC validator correctly handles various scenarios.

use myc_github::{OidcClaims, OidcValidator};

#[test]
fn test_oidc_validator_creation() {
    let validator = OidcValidator::new();
    // Validator should be created successfully
    drop(validator);
}

#[test]
fn test_oidc_validator_with_custom_jwks_uri() {
    let custom_uri = "https://example.com/.well-known/jwks".to_string();
    let validator = OidcValidator::with_jwks_uri(custom_uri);
    // Validator should be created with custom URI
    drop(validator);
}

#[test]
fn test_oidc_claims_structure() {
    // Verify that OidcClaims has all required fields
    let claims = OidcClaims {
        repository: "myorg/myrepo".to_string(),
        workflow: ".github/workflows/deploy.yml".to_string(),
        ref_: "refs/heads/main".to_string(),
        actor: "alice".to_string(),
        environment: Some("production".to_string()),
        subject: "repo:myorg/myrepo:ref:refs/heads/main".to_string(),
        issuer: "https://token.actions.githubusercontent.com".to_string(),
        audience: "myorg/myrepo".to_string(),
        expiration: 1234567890,
        issued_at: 1234567800,
    };

    // Verify all required fields are present
    assert_eq!(claims.repository, "myorg/myrepo");
    assert_eq!(claims.workflow, ".github/workflows/deploy.yml");
    assert_eq!(claims.ref_, "refs/heads/main");
    assert_eq!(claims.actor, "alice");
    assert_eq!(claims.environment, Some("production".to_string()));
}

#[test]
fn test_oidc_claims_without_environment() {
    // Verify that environment is optional
    let claims = OidcClaims {
        repository: "myorg/myrepo".to_string(),
        workflow: ".github/workflows/test.yml".to_string(),
        ref_: "refs/heads/feature".to_string(),
        actor: "bob".to_string(),
        environment: None,
        subject: "repo:myorg/myrepo:ref:refs/heads/feature".to_string(),
        issuer: "https://token.actions.githubusercontent.com".to_string(),
        audience: "myorg/myrepo".to_string(),
        expiration: 1234567890,
        issued_at: 1234567800,
    };

    assert!(claims.environment.is_none());
}

#[test]
fn test_oidc_claims_json_roundtrip() {
    let claims = OidcClaims {
        repository: "myorg/myrepo".to_string(),
        workflow: ".github/workflows/deploy.yml".to_string(),
        ref_: "refs/heads/main".to_string(),
        actor: "alice".to_string(),
        environment: Some("production".to_string()),
        subject: "repo:myorg/myrepo:ref:refs/heads/main".to_string(),
        issuer: "https://token.actions.githubusercontent.com".to_string(),
        audience: "myorg/myrepo".to_string(),
        expiration: 1234567890,
        issued_at: 1234567800,
    };

    // Serialize to JSON
    let json = serde_json::to_string(&claims).expect("Failed to serialize");

    // Deserialize back
    let deserialized: OidcClaims = serde_json::from_str(&json).expect("Failed to deserialize");

    // Verify all fields match
    assert_eq!(claims.repository, deserialized.repository);
    assert_eq!(claims.workflow, deserialized.workflow);
    assert_eq!(claims.ref_, deserialized.ref_);
    assert_eq!(claims.actor, deserialized.actor);
    assert_eq!(claims.environment, deserialized.environment);
    assert_eq!(claims.subject, deserialized.subject);
    assert_eq!(claims.issuer, deserialized.issuer);
    assert_eq!(claims.audience, deserialized.audience);
    assert_eq!(claims.expiration, deserialized.expiration);
    assert_eq!(claims.issued_at, deserialized.issued_at);
}

#[tokio::test]
async fn test_validate_token_with_invalid_format() {
    let validator = OidcValidator::new();

    // Test with invalid token format
    let result = validator.validate_token("not.a.valid.jwt").await;
    assert!(result.is_err());

    // Verify error message indicates validation failure
    if let Err(e) = result {
        let error_msg = e.to_string();
        assert!(
            error_msg.contains("OIDC validation failed") || error_msg.contains("failed to decode")
        );
    }
}

#[tokio::test]
async fn test_validate_token_with_empty_string() {
    let validator = OidcValidator::new();

    // Test with empty token
    let result = validator.validate_token("").await;
    assert!(result.is_err());
}

#[test]
fn test_oidc_claims_field_names() {
    // Verify that the JSON field names match the expected OIDC standard
    let claims = OidcClaims {
        repository: "myorg/myrepo".to_string(),
        workflow: ".github/workflows/deploy.yml".to_string(),
        ref_: "refs/heads/main".to_string(),
        actor: "alice".to_string(),
        environment: Some("production".to_string()),
        subject: "repo:myorg/myrepo:ref:refs/heads/main".to_string(),
        issuer: "https://token.actions.githubusercontent.com".to_string(),
        audience: "myorg/myrepo".to_string(),
        expiration: 1234567890,
        issued_at: 1234567800,
    };

    let json = serde_json::to_value(&claims).expect("Failed to serialize");

    // Verify standard JWT claim names
    assert!(json.get("sub").is_some(), "Missing 'sub' field");
    assert!(json.get("iss").is_some(), "Missing 'iss' field");
    assert!(json.get("aud").is_some(), "Missing 'aud' field");
    assert!(json.get("exp").is_some(), "Missing 'exp' field");
    assert!(json.get("iat").is_some(), "Missing 'iat' field");

    // Verify GitHub-specific claim names
    assert!(
        json.get("repository").is_some(),
        "Missing 'repository' field"
    );
    assert!(json.get("workflow").is_some(), "Missing 'workflow' field");
    assert!(json.get("ref").is_some(), "Missing 'ref' field");
    assert!(json.get("actor").is_some(), "Missing 'actor' field");
    assert!(
        json.get("environment").is_some(),
        "Missing 'environment' field"
    );
}
