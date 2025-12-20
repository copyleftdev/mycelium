//! GitHub Actions OIDC token validation.
//!
//! This module provides validation of GitHub Actions OIDC tokens for CI authentication.
//! It validates JWT tokens issued by GitHub Actions and extracts workflow identity claims.

use crate::error::{GitHubError, Result};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

/// GitHub Actions OIDC token validator.
///
/// Validates OIDC tokens from GitHub Actions workflows and extracts identity claims.
pub struct OidcValidator {
    /// JWKS URI for fetching GitHub's public keys.
    jwks_uri: String,
}

/// Claims extracted from a GitHub Actions OIDC token.
///
/// These claims identify the workflow and can be used for authorization decisions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OidcClaims {
    /// Repository in format "owner/repo".
    pub repository: String,

    /// Workflow file path (e.g., ".github/workflows/deploy.yml").
    pub workflow: String,

    /// Git ref (e.g., "refs/heads/main").
    #[serde(rename = "ref")]
    pub ref_: String,

    /// GitHub username of the actor who triggered the workflow.
    pub actor: String,

    /// Environment name if the job is associated with an environment.
    pub environment: Option<String>,

    /// Subject claim (standard JWT claim).
    #[serde(rename = "sub")]
    pub subject: String,

    /// Issuer (should be "<https://token.actions.githubusercontent.com>").
    #[serde(rename = "iss")]
    pub issuer: String,

    /// Audience (typically the repository or a custom value).
    #[serde(rename = "aud")]
    pub audience: String,

    /// Expiration time (Unix timestamp).
    #[serde(rename = "exp")]
    pub expiration: i64,

    /// Issued at time (Unix timestamp).
    #[serde(rename = "iat")]
    pub issued_at: i64,
}

impl OidcValidator {
    /// Creates a new OIDC validator with the default GitHub Actions JWKS URI.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use myc_github::OidcValidator;
    ///
    /// let validator = OidcValidator::new();
    /// ```
    pub fn new() -> Self {
        Self {
            jwks_uri: "https://token.actions.githubusercontent.com/.well-known/jwks".to_string(),
        }
    }

    /// Creates a new OIDC validator with a custom JWKS URI.
    ///
    /// This is primarily useful for testing with mock OIDC providers.
    ///
    /// # Arguments
    ///
    /// * `jwks_uri` - The URI to fetch JSON Web Key Sets from
    ///
    /// # Examples
    ///
    /// ```
    /// use myc_github::OidcValidator;
    ///
    /// let validator = OidcValidator::with_jwks_uri(
    ///     "https://example.com/.well-known/jwks".to_string()
    /// );
    /// ```
    pub fn with_jwks_uri(jwks_uri: String) -> Self {
        Self { jwks_uri }
    }

    /// Validates a GitHub Actions OIDC token and extracts claims.
    ///
    /// This function:
    /// 1. Decodes the JWT header to get the key ID
    /// 2. Fetches the public key from GitHub's JWKS endpoint
    /// 3. Validates the token signature and standard claims
    /// 4. Extracts and returns the workflow identity claims
    ///
    /// # Arguments
    ///
    /// * `token` - The OIDC token string from GitHub Actions
    ///
    /// # Returns
    ///
    /// Returns `Ok(OidcClaims)` if the token is valid, or an error if validation fails.
    ///
    /// # Errors
    ///
    /// Returns `GitHubError::OidcValidationFailed` if:
    /// - The token format is invalid
    /// - The signature verification fails
    /// - Required claims are missing
    /// - The token is expired
    /// - The issuer is not GitHub Actions
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use myc_github::OidcValidator;
    ///
    /// let validator = OidcValidator::new();
    /// let token = std::env::var("ACTIONS_ID_TOKEN")?;
    /// let claims = validator.validate_token(&token).await?;
    ///
    /// println!("Repository: {}", claims.repository);
    /// println!("Workflow: {}", claims.workflow);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn validate_token(&self, token: &str) -> Result<OidcClaims> {
        // Decode the header to get the key ID
        let header = decode_header(token).map_err(|e| {
            GitHubError::OidcValidationFailed(format!("failed to decode JWT header: {}", e))
        })?;

        let kid = header.kid.ok_or_else(|| {
            GitHubError::OidcValidationFailed("JWT header missing 'kid' field".to_string())
        })?;

        // Fetch the JWKS and find the matching key
        let jwks = self.fetch_jwks().await?;
        let jwk = jwks
            .keys
            .iter()
            .find(|k| k.kid.as_ref() == Some(&kid))
            .ok_or_else(|| {
                GitHubError::OidcValidationFailed(format!("no matching key found for kid: {}", kid))
            })?;

        // Convert JWK to DecodingKey
        let decoding_key = self.jwk_to_decoding_key(jwk)?;

        // Set up validation parameters
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&["https://token.actions.githubusercontent.com"]);
        validation.validate_exp = true;

        // Decode and validate the token
        let token_data = decode::<OidcClaims>(token, &decoding_key, &validation).map_err(|e| {
            GitHubError::OidcValidationFailed(format!("token validation failed: {}", e))
        })?;

        // Verify required claims are present
        let claims = token_data.claims;
        if claims.repository.is_empty() {
            return Err(GitHubError::OidcValidationFailed(
                "missing required claim: repository".to_string(),
            ));
        }
        if claims.workflow.is_empty() {
            return Err(GitHubError::OidcValidationFailed(
                "missing required claim: workflow".to_string(),
            ));
        }
        if claims.ref_.is_empty() {
            return Err(GitHubError::OidcValidationFailed(
                "missing required claim: ref".to_string(),
            ));
        }
        if claims.actor.is_empty() {
            return Err(GitHubError::OidcValidationFailed(
                "missing required claim: actor".to_string(),
            ));
        }

        Ok(claims)
    }

    /// Fetches the JSON Web Key Set from GitHub's JWKS endpoint.
    async fn fetch_jwks(&self) -> Result<Jwks> {
        let response = reqwest::get(&self.jwks_uri)
            .await
            .map_err(|e| GitHubError::NetworkError(format!("failed to fetch JWKS: {}", e)))?;

        if !response.status().is_success() {
            return Err(GitHubError::OidcValidationFailed(format!(
                "JWKS endpoint returned status: {}",
                response.status()
            )));
        }

        response
            .json::<Jwks>()
            .await
            .map_err(|e| GitHubError::OidcValidationFailed(format!("failed to parse JWKS: {}", e)))
    }

    /// Converts a JWK to a DecodingKey for token validation.
    fn jwk_to_decoding_key(&self, jwk: &Jwk) -> Result<DecodingKey> {
        // GitHub uses RSA keys
        if jwk.kty != "RSA" {
            return Err(GitHubError::OidcValidationFailed(format!(
                "unsupported key type: {}",
                jwk.kty
            )));
        }

        let n = jwk.n.as_ref().ok_or_else(|| {
            GitHubError::OidcValidationFailed("JWK missing 'n' parameter".to_string())
        })?;

        let e = jwk.e.as_ref().ok_or_else(|| {
            GitHubError::OidcValidationFailed("JWK missing 'e' parameter".to_string())
        })?;

        DecodingKey::from_rsa_components(n, e).map_err(|e| {
            GitHubError::OidcValidationFailed(format!("failed to create decoding key: {}", e))
        })
    }
}

impl Default for OidcValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// JSON Web Key Set response from JWKS endpoint.
#[derive(Debug, Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

/// A single JSON Web Key.
#[derive(Debug, Deserialize)]
struct Jwk {
    /// Key type (e.g., "RSA").
    kty: String,

    /// Key ID.
    kid: Option<String>,

    /// RSA modulus (base64url encoded).
    n: Option<String>,

    /// RSA exponent (base64url encoded).
    e: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oidc_validator_new() {
        let validator = OidcValidator::new();
        assert_eq!(
            validator.jwks_uri,
            "https://token.actions.githubusercontent.com/.well-known/jwks"
        );
    }

    #[test]
    fn test_oidc_validator_with_custom_uri() {
        let custom_uri = "https://example.com/jwks".to_string();
        let validator = OidcValidator::with_jwks_uri(custom_uri.clone());
        assert_eq!(validator.jwks_uri, custom_uri);
    }

    #[test]
    fn test_oidc_claims_serialization() {
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

        let json = serde_json::to_string(&claims).unwrap();
        let deserialized: OidcClaims = serde_json::from_str(&json).unwrap();

        assert_eq!(claims, deserialized);
    }
}
