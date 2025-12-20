//! OAuth device flow for GitHub authentication.
//!
//! This module implements the GitHub OAuth Device Authorization Grant flow,
//! which allows users to authenticate without a web browser redirect.
//! The flow is designed for CLI applications and devices with limited input capabilities.
//!
//! # Flow
//!
//! 1. Call `start()` to request a device code from GitHub
//! 2. Display the user code and verification URI to the user
//! 3. Poll `poll()` at the specified interval until the user authorizes
//! 4. Once authorized, use `get_user_info()` to fetch user details
//!
//! # Example
//!
//! ```no_run
//! use myc_github::auth::OAuthDeviceFlow;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let flow = OAuthDeviceFlow::new("my_client_id".to_string());
//! let response = flow.start().await?;
//!
//! println!("Go to {} and enter code: {}",
//!          response.verification_uri, response.user_code);
//!
//! loop {
//!     tokio::time::sleep(tokio::time::Duration::from_secs(response.interval)).await;
//!     if let Some(token) = flow.poll(&response.device_code).await? {
//!         let user = flow.get_user_info(&token).await?;
//!         println!("Authenticated as: {}", user.login);
//!         break;
//!     }
//! }
//! # Ok(())
//! # }
//! ```

use crate::error::{GitHubError, Result};
use serde::{Deserialize, Serialize};

/// OAuth device flow handler for GitHub authentication.
///
/// Implements the GitHub OAuth Device Authorization Grant flow.
/// This flow is designed for CLI applications where the user authenticates
/// via a web browser on another device.
#[derive(Debug, Clone)]
pub struct OAuthDeviceFlow {
    client_id: String,
    http_client: reqwest::Client,
}

impl OAuthDeviceFlow {
    /// Creates a new OAuth device flow handler.
    ///
    /// # Arguments
    ///
    /// * `client_id` - GitHub OAuth application client ID
    ///
    /// # Example
    ///
    /// ```
    /// use myc_github::auth::OAuthDeviceFlow;
    ///
    /// let flow = OAuthDeviceFlow::new("my_client_id".to_string());
    /// ```
    pub fn new(client_id: String) -> Self {
        Self {
            client_id,
            http_client: reqwest::Client::new(),
        }
    }

    /// Starts the device authorization flow by requesting a device code.
    ///
    /// This initiates the OAuth device flow by requesting a device code from GitHub.
    /// The response contains a user code that the user must enter at the verification URI,
    /// and a device code that is used to poll for the access token.
    ///
    /// # Returns
    ///
    /// A `DeviceCodeResponse` containing:
    /// - `device_code`: Used to poll for the access token
    /// - `user_code`: Code the user enters at the verification URI
    /// - `verification_uri`: URL where the user authorizes the device
    /// - `expires_in`: Seconds until the device code expires
    /// - `interval`: Minimum seconds between poll requests
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails or GitHub returns an error.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use myc_github::auth::OAuthDeviceFlow;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let flow = OAuthDeviceFlow::new("my_client_id".to_string());
    /// let response = flow.start().await?;
    /// println!("Go to {} and enter: {}",
    ///          response.verification_uri, response.user_code);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn start(&self) -> Result<DeviceCodeResponse> {
        let url = "https://github.com/login/device/code";

        let params = [
            ("client_id", self.client_id.as_str()),
            ("scope", "repo read:user user:email"),
        ];

        let response = self
            .http_client
            .post(url)
            .header("Accept", "application/json")
            .form(&params)
            .send()
            .await
            .map_err(|e| GitHubError::NetworkError(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "unknown error".to_string());
            return Err(GitHubError::HttpError(format!(
                "failed to start device flow: {} - {}",
                status, body
            )));
        }

        let device_response: DeviceCodeResponse = response
            .json()
            .await
            .map_err(|e| GitHubError::NetworkError(e.to_string()))?;
        Ok(device_response)
    }

    /// Polls for an access token using the device code.
    ///
    /// This should be called repeatedly at the interval specified in the
    /// `DeviceCodeResponse` until it returns `Some(AccessToken)` or an error.
    ///
    /// # Arguments
    ///
    /// * `device_code` - The device code from `start()`
    ///
    /// # Returns
    ///
    /// - `Ok(Some(AccessToken))` if the user has authorized the device
    /// - `Ok(None)` if authorization is still pending
    /// - `Err(...)` if the device code expired or another error occurred
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The device code has expired
    /// - The user denied authorization
    /// - The HTTP request fails
    /// - GitHub returns an unexpected error
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use myc_github::auth::OAuthDeviceFlow;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let flow = OAuthDeviceFlow::new("my_client_id".to_string());
    /// # let response = flow.start().await?;
    /// loop {
    ///     tokio::time::sleep(tokio::time::Duration::from_secs(response.interval)).await;
    ///     match flow.poll(&response.device_code).await? {
    ///         Some(token) => {
    ///             println!("Got token: {}", token.access_token);
    ///             break;
    ///         }
    ///         None => println!("Still waiting for authorization..."),
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn poll(&self, device_code: &str) -> Result<Option<AccessToken>> {
        let url = "https://github.com/login/oauth/access_token";

        let params = [
            ("client_id", self.client_id.as_str()),
            ("device_code", device_code),
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
        ];

        let response = self
            .http_client
            .post(url)
            .header("Accept", "application/json")
            .form(&params)
            .send()
            .await
            .map_err(|e| GitHubError::NetworkError(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "unknown error".to_string());
            return Err(GitHubError::HttpError(format!(
                "failed to poll for token: {} - {}",
                status, body
            )));
        }

        let poll_response: PollResponse = response
            .json()
            .await
            .map_err(|e| GitHubError::NetworkError(e.to_string()))?;

        match poll_response {
            PollResponse::Success(token) => Ok(Some(token)),
            PollResponse::Pending { error } if error == "authorization_pending" => Ok(None),
            PollResponse::Pending { error } if error == "slow_down" => {
                // Caller should increase polling interval
                Ok(None)
            }
            PollResponse::Error {
                error,
                error_description,
            } => {
                if error == "expired_token" {
                    Err(GitHubError::HttpError(
                        "device code expired - please restart the authentication flow".to_string(),
                    ))
                } else if error == "access_denied" {
                    Err(GitHubError::HttpError(
                        "user denied authorization".to_string(),
                    ))
                } else {
                    Err(GitHubError::HttpError(format!(
                        "authorization failed: {} - {}",
                        error,
                        error_description.unwrap_or_default()
                    )))
                }
            }
            _ => Err(GitHubError::HttpError(
                "unexpected response from GitHub".to_string(),
            )),
        }
    }

    /// Fetches user information using an access token.
    ///
    /// After successfully obtaining an access token, this method retrieves
    /// the authenticated user's GitHub profile information.
    ///
    /// # Arguments
    ///
    /// * `token` - The access token obtained from `poll()`
    ///
    /// # Returns
    ///
    /// A `GitHubUser` containing the user's profile information including:
    /// - `id`: GitHub user ID
    /// - `login`: GitHub username
    /// - `email`: Primary email address (if available)
    /// - `name`: Display name (if set)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The token is invalid or expired
    /// - The HTTP request fails
    /// - GitHub returns an error
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use myc_github::auth::{OAuthDeviceFlow, AccessToken};
    /// # async fn example(token: AccessToken) -> Result<(), Box<dyn std::error::Error>> {
    /// let flow = OAuthDeviceFlow::new("my_client_id".to_string());
    /// let user = flow.get_user_info(&token).await?;
    /// println!("Authenticated as: {} (ID: {})", user.login, user.id);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_user_info(&self, token: &AccessToken) -> Result<GitHubUser> {
        let url = "https://api.github.com/user";

        let response = self
            .http_client
            .get(url)
            .header("Accept", "application/vnd.github+json")
            .header("Authorization", format!("Bearer {}", token.access_token))
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("User-Agent", "mycelium-cli")
            .send()
            .await
            .map_err(|e| GitHubError::NetworkError(e.to_string()))?;

        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(GitHubError::Unauthorized);
        }

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "unknown error".to_string());
            return Err(GitHubError::HttpError(format!(
                "failed to get user info: {} - {}",
                status, body
            )));
        }

        let user: GitHubUser = response
            .json()
            .await
            .map_err(|e| GitHubError::NetworkError(e.to_string()))?;
        Ok(user)
    }
}

/// Response from the device code request.
///
/// Contains the information needed to complete the OAuth device flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCodeResponse {
    /// Device code used to poll for the access token.
    pub device_code: String,

    /// User code to display to the user.
    pub user_code: String,

    /// URL where the user authorizes the device.
    pub verification_uri: String,

    /// Seconds until the device code expires.
    pub expires_in: u64,

    /// Minimum seconds between poll requests.
    pub interval: u64,
}

/// Access token returned after successful authorization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessToken {
    /// The OAuth access token.
    pub access_token: String,

    /// Token type (usually "bearer").
    pub token_type: String,

    /// Scopes granted to the token.
    pub scope: String,
}

/// GitHub user information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubUser {
    /// GitHub user ID.
    pub id: u64,

    /// GitHub username.
    pub login: String,

    /// Primary email address (may be null if not public).
    pub email: Option<String>,

    /// Display name (may be null if not set).
    pub name: Option<String>,
}

/// Internal response type for polling.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum PollResponse {
    Success(AccessToken),
    Pending {
        error: String,
    },
    Error {
        error: String,
        error_description: Option<String>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oauth_device_flow_creation() {
        let flow = OAuthDeviceFlow::new("test_client_id".to_string());
        assert_eq!(flow.client_id, "test_client_id");
    }

    #[test]
    fn test_device_code_response_deserialization() {
        let json = r#"{
            "device_code": "3584d83530557fdd1f46af8289938c8ef79f9dc5",
            "user_code": "WDJB-MJHT",
            "verification_uri": "https://github.com/login/device",
            "expires_in": 900,
            "interval": 5
        }"#;

        let response: DeviceCodeResponse = serde_json::from_str(json).unwrap();
        assert_eq!(
            response.device_code,
            "3584d83530557fdd1f46af8289938c8ef79f9dc5"
        );
        assert_eq!(response.user_code, "WDJB-MJHT");
        assert_eq!(response.verification_uri, "https://github.com/login/device");
        assert_eq!(response.expires_in, 900);
        assert_eq!(response.interval, 5);
    }

    #[test]
    fn test_access_token_deserialization() {
        let json = r#"{
            "access_token": "gho_16C7e42F292c6912E7710c838347Ae178B4a",
            "token_type": "bearer",
            "scope": "repo,read:user"
        }"#;

        let token: AccessToken = serde_json::from_str(json).unwrap();
        assert_eq!(
            token.access_token,
            "gho_16C7e42F292c6912E7710c838347Ae178B4a"
        );
        assert_eq!(token.token_type, "bearer");
        assert_eq!(token.scope, "repo,read:user");
    }

    #[test]
    fn test_github_user_deserialization() {
        let json = r#"{
            "id": 12345678,
            "login": "octocat",
            "email": "octocat@github.com",
            "name": "The Octocat"
        }"#;

        let user: GitHubUser = serde_json::from_str(json).unwrap();
        assert_eq!(user.id, 12345678);
        assert_eq!(user.login, "octocat");
        assert_eq!(user.email, Some("octocat@github.com".to_string()));
        assert_eq!(user.name, Some("The Octocat".to_string()));
    }

    #[test]
    fn test_github_user_deserialization_with_nulls() {
        let json = r#"{
            "id": 12345678,
            "login": "octocat",
            "email": null,
            "name": null
        }"#;

        let user: GitHubUser = serde_json::from_str(json).unwrap();
        assert_eq!(user.id, 12345678);
        assert_eq!(user.login, "octocat");
        assert_eq!(user.email, None);
        assert_eq!(user.name, None);
    }
}
