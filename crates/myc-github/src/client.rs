//! GitHub API client for repository operations.

use crate::error::{GitHubError, Result};
use octocrab::{models::Repository, Octocrab};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Rate limit information from GitHub API.
///
/// GitHub provides rate limit information in response headers:
/// - `X-RateLimit-Limit`: Maximum number of requests per hour
/// - `X-RateLimit-Remaining`: Number of requests remaining
/// - `X-RateLimit-Reset`: Unix timestamp when the rate limit resets
#[derive(Debug, Clone)]
pub struct RateLimitInfo {
    /// Maximum number of requests allowed per hour.
    pub limit: u32,
    /// Number of requests remaining in the current window.
    pub remaining: u32,
    /// Unix timestamp when the rate limit resets.
    pub reset_at: u64,
}

impl RateLimitInfo {
    /// Creates a new rate limit info with default values.
    ///
    /// Default is 5000 requests per hour for authenticated requests.
    fn new() -> Self {
        Self {
            limit: 5000,
            remaining: 5000,
            reset_at: 0,
        }
    }

    /// Checks if we're approaching the rate limit.
    ///
    /// Returns true if remaining requests are less than 10% of the limit.
    pub fn is_approaching_limit(&self) -> bool {
        let threshold = self.limit / 10; // 10% threshold
        self.remaining < threshold
    }

    /// Checks if the rate limit has been exceeded.
    pub fn is_exceeded(&self) -> bool {
        self.remaining == 0
    }

    /// Gets the time until rate limit reset.
    pub fn time_until_reset(&self) -> Duration {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs();

        if self.reset_at > now {
            Duration::from_secs(self.reset_at - now)
        } else {
            Duration::from_secs(0)
        }
    }

    /// Formats the reset time as a human-readable string.
    pub fn reset_time_string(&self) -> String {
        let duration = self.time_until_reset();
        let seconds = duration.as_secs();

        if seconds == 0 {
            "now".to_string()
        } else if seconds < 60 {
            format!("{} seconds", seconds)
        } else if seconds < 3600 {
            format!("{} minutes", seconds / 60)
        } else {
            format!("{} hours {} minutes", seconds / 3600, (seconds % 3600) / 60)
        }
    }
}

/// GitHub API client for Mycelium operations.
///
/// This client handles repository operations including creating repositories,
/// checking access, and managing files. It operates on ciphertext bytes only
/// and does not perform any cryptographic operations.
///
/// The client tracks GitHub API rate limits and provides backoff when approaching
/// the limit to avoid hitting rate limit errors.
#[derive(Clone)]
pub struct GitHubClient {
    octocrab: Octocrab,
    owner: String,
    repo: String,
    rate_limit: Arc<Mutex<RateLimitInfo>>,
}

impl GitHubClient {
    /// Creates a new GitHub client.
    ///
    /// # Arguments
    ///
    /// * `token` - GitHub personal access token or OAuth token
    /// * `owner` - Repository owner (user or organization)
    /// * `repo` - Repository name
    ///
    /// # Errors
    ///
    /// Returns an error if the token is invalid or the client cannot be initialized.
    pub fn new(token: String, owner: String, repo: String) -> Result<Self> {
        let octocrab = Octocrab::builder()
            .personal_token(token)
            .build()
            .map_err(|e| GitHubError::HttpError(e.to_string()))?;

        Ok(Self {
            octocrab,
            owner,
            repo,
            rate_limit: Arc::new(Mutex::new(RateLimitInfo::new())),
        })
    }

    /// Gets the current rate limit information.
    ///
    /// # Returns
    ///
    /// Returns a clone of the current rate limit information.
    pub fn rate_limit_info(&self) -> RateLimitInfo {
        self.rate_limit.lock().unwrap().clone()
    }

    /// Updates rate limit information from response headers.
    ///
    /// This method should be called after each API request to track rate limits.
    /// It extracts rate limit information from the response headers if available.
    ///
    /// Note: Currently not used because octocrab's high-level API doesn't expose
    /// response headers. This will be used when we implement lower-level API calls
    /// for file operations (read_file, write_file, etc.) in future tasks.
    ///
    /// # Arguments
    ///
    /// * `headers` - HTTP response headers from GitHub API
    #[allow(dead_code)]
    fn update_rate_limit(&self, headers: &reqwest::header::HeaderMap) {
        let mut rate_limit = self.rate_limit.lock().unwrap();

        // Extract rate limit headers
        if let Some(limit) = headers.get("x-ratelimit-limit") {
            if let Ok(limit_str) = limit.to_str() {
                if let Ok(limit_val) = limit_str.parse::<u32>() {
                    rate_limit.limit = limit_val;
                }
            }
        }

        if let Some(remaining) = headers.get("x-ratelimit-remaining") {
            if let Ok(remaining_str) = remaining.to_str() {
                if let Ok(remaining_val) = remaining_str.parse::<u32>() {
                    rate_limit.remaining = remaining_val;
                }
            }
        }

        if let Some(reset) = headers.get("x-ratelimit-reset") {
            if let Ok(reset_str) = reset.to_str() {
                if let Ok(reset_val) = reset_str.parse::<u64>() {
                    rate_limit.reset_at = reset_val;
                }
            }
        }
    }

    /// Checks rate limit and backs off if approaching limit.
    ///
    /// This method should be called before making API requests to ensure
    /// we don't hit rate limits. If we're approaching the limit, it will
    /// sleep briefly to allow the rate limit to reset.
    ///
    /// # Errors
    ///
    /// Returns `RateLimitExceeded` if the rate limit has been exceeded.
    async fn check_rate_limit(&self) -> Result<()> {
        let rate_limit = self.rate_limit.lock().unwrap().clone();

        // If rate limit is exceeded, return error with reset time
        if rate_limit.is_exceeded() {
            let reset_time = rate_limit.reset_time_string();
            return Err(GitHubError::RateLimitExceeded {
                reset_at: reset_time,
            });
        }

        // If approaching limit, implement exponential backoff
        if rate_limit.is_approaching_limit() {
            // Calculate backoff duration based on how close we are to the limit
            let percentage_remaining = (rate_limit.remaining as f64) / (rate_limit.limit as f64);

            // Backoff increases as we get closer to the limit
            // At 10% remaining: ~100ms delay
            // At 5% remaining: ~200ms delay
            // At 1% remaining: ~500ms delay
            let backoff_ms = ((1.0 - percentage_remaining * 10.0) * 500.0).max(0.0) as u64;

            if backoff_ms > 0 {
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
            }
        }

        Ok(())
    }

    /// Creates a new private GitHub repository.
    ///
    /// This operation creates a new repository under the authenticated user's account
    /// or the specified organization. The repository is created as private by default.
    ///
    /// # Arguments
    ///
    /// * `name` - Name of the repository to create
    /// * `private` - Whether the repository should be private (true) or public (false)
    ///
    /// # Returns
    ///
    /// Returns the created repository metadata.
    ///
    /// # Errors
    ///
    /// * `Unauthorized` - If the token is invalid or expired
    /// * `Forbidden` - If the user lacks permission to create repositories
    /// * `RateLimitExceeded` - If the rate limit has been exceeded
    /// * `ValidationError` - If the repository name is invalid or already exists
    /// * `NetworkError` - If the request fails due to network issues
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use myc_github::client::GitHubClient;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = GitHubClient::new(
    ///     "token".to_string(),
    ///     "owner".to_string(),
    ///     "repo".to_string()
    /// )?;
    /// let repo = client.create_repository("my-vault", true).await?;
    /// println!("Created repository: {}", repo.name);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn create_repository(&self, name: &str, private: bool) -> Result<Repository> {
        // Check rate limit before making request
        self.check_rate_limit().await?;

        // Build the request body
        let body = serde_json::json!({
            "name": name,
            "private": private,
        });

        // Use the lower-level API to create a repository
        // POST /user/repos for user repositories
        // POST /orgs/{org}/repos for organization repositories
        let route = "/user/repos".to_string();

        let result: std::result::Result<Repository, octocrab::Error> =
            self.octocrab.post(route, Some(&body)).await;

        match result {
            Ok(repo) => Ok(repo),
            Err(e) => {
                // Use the helper method to map octocrab errors
                let mut error = GitHubError::from_octocrab(e, "repository");

                // For rate limit errors, use our tracked rate limit info if available
                if matches!(error, GitHubError::RateLimitExceeded { .. }) {
                    let rate_limit = self.rate_limit.lock().unwrap().clone();
                    if rate_limit.reset_at > 0 {
                        error = GitHubError::rate_limit_exceeded(rate_limit.reset_at);
                    }
                }

                // Provide more specific messages for validation errors
                if let GitHubError::ValidationError(_) = error {
                    error = GitHubError::ValidationError(
                        "repository name is invalid or already exists. Repository names must be unique and contain only alphanumeric characters, hyphens, and underscores".to_string(),
                    );
                }

                Err(error)
            }
        }
    }

    /// Checks if the client has access to the configured repository.
    ///
    /// This operation verifies that the authenticated user can access the repository
    /// by attempting to retrieve its metadata. This is useful for validating
    /// credentials and repository existence before performing other operations.
    ///
    /// # Returns
    ///
    /// Returns `true` if the repository exists and is accessible, `false` otherwise.
    ///
    /// # Errors
    ///
    /// * `Unauthorized` - If the token is invalid or expired
    /// * `RateLimitExceeded` - If the rate limit has been exceeded
    /// * `NetworkError` - If the request fails due to network issues
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use myc_github::client::GitHubClient;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = GitHubClient::new(
    ///     "token".to_string(),
    ///     "owner".to_string(),
    ///     "repo".to_string()
    /// )?;
    /// if client.check_access().await? {
    ///     println!("Repository is accessible");
    /// } else {
    ///     println!("Repository not found or not accessible");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn check_access(&self) -> Result<bool> {
        // Check rate limit before making request
        self.check_rate_limit().await?;

        let result = self.octocrab.repos(&self.owner, &self.repo).get().await;

        match result {
            Ok(_) => Ok(true),
            Err(e) => {
                // Use the helper method to map octocrab errors
                let error = GitHubError::from_octocrab(
                    e,
                    &format!("repository {}/{}", self.owner, self.repo),
                );

                match error {
                    // For check_access, 404 and 403 (non-rate-limit) are not errors
                    GitHubError::NotFound { .. } => Ok(false),
                    GitHubError::Forbidden { ref reason } if !reason.contains("rate limit") => {
                        Ok(false)
                    }

                    // For rate limit errors, use our tracked rate limit info if available
                    GitHubError::RateLimitExceeded { .. } => {
                        let rate_limit = self.rate_limit.lock().unwrap().clone();
                        if rate_limit.reset_at > 0 {
                            Err(GitHubError::rate_limit_exceeded(rate_limit.reset_at))
                        } else {
                            Err(error)
                        }
                    }

                    // All other errors are propagated
                    _ => Err(error),
                }
            }
        }
    }

    /// Manually updates rate limit information.
    ///
    /// This method can be used to update rate limit information when it's
    /// available from API responses or error messages.
    ///
    /// # Arguments
    ///
    /// * `limit` - Maximum number of requests per hour
    /// * `remaining` - Number of requests remaining
    /// * `reset_at` - Unix timestamp when the rate limit resets
    pub fn update_rate_limit_info(&self, limit: u32, remaining: u32, reset_at: u64) {
        let mut rate_limit = self.rate_limit.lock().unwrap();
        rate_limit.limit = limit;
        rate_limit.remaining = remaining;
        rate_limit.reset_at = reset_at;
    }

    /// Gets the repository owner.
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Gets the repository name.
    pub fn repo(&self) -> &str {
        &self.repo
    }

    /// Reads a file from the repository.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the file in the repository
    ///
    /// # Returns
    ///
    /// Returns the file content as bytes.
    ///
    /// # Errors
    ///
    /// * `NotFound` - If the file doesn't exist
    /// * `Unauthorized` - If the token is invalid or expired
    /// * `RateLimitExceeded` - If the rate limit has been exceeded
    /// * `NetworkError` - If the request fails due to network issues
    pub async fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        // Check rate limit before making request
        self.check_rate_limit().await?;

        let result = self
            .octocrab
            .repos(&self.owner, &self.repo)
            .get_content()
            .path(path)
            .send()
            .await;

        match result {
            Ok(content) => {
                // Handle the content response
                match content.items.first() {
                    Some(item) => {
                        if let Some(content_str) = &item.content {
                            // Decode base64 content
                            let decoded = base64::Engine::decode(
                                &base64::engine::general_purpose::STANDARD,
                                content_str.replace('\n', ""),
                            )
                            .map_err(|e| {
                                GitHubError::ValidationError(format!(
                                    "Invalid base64 content: {}",
                                    e
                                ))
                            })?;
                            Ok(decoded)
                        } else {
                            Err(GitHubError::ValidationError(
                                "File content is empty or binary".to_string(),
                            ))
                        }
                    }
                    None => Err(GitHubError::NotFound {
                        resource: format!("file {}. Check that the file path is correct", path),
                    }),
                }
            }
            Err(e) => {
                let error = GitHubError::from_octocrab(e, &format!("file {}", path));
                match error {
                    GitHubError::RateLimitExceeded { .. } => {
                        let rate_limit = self.rate_limit.lock().unwrap().clone();
                        if rate_limit.reset_at > 0 {
                            Err(GitHubError::rate_limit_exceeded(rate_limit.reset_at))
                        } else {
                            Err(error)
                        }
                    }
                    _ => Err(error),
                }
            }
        }
    }

    /// Writes a file to the repository.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the file in the repository
    /// * `content` - File content as bytes
    /// * `message` - Commit message
    /// * `sha` - Optional SHA of existing file for updates
    ///
    /// # Returns
    ///
    /// Returns the SHA of the created/updated file.
    ///
    /// # Errors
    ///
    /// * `Conflict` - If the file has been modified (SHA mismatch)
    /// * `Unauthorized` - If the token is invalid or expired
    /// * `RateLimitExceeded` - If the rate limit has been exceeded
    /// * `NetworkError` - If the request fails due to network issues
    pub async fn write_file(
        &self,
        path: &str,
        content: &[u8],
        message: &str,
        sha: Option<&str>,
    ) -> Result<String> {
        // Check rate limit before making request
        self.check_rate_limit().await?;

        // Encode content as base64
        let encoded_content =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, content);

        // Build request body
        let mut body = serde_json::json!({
            "message": message,
            "content": encoded_content,
        });

        if let Some(sha) = sha {
            body["sha"] = serde_json::Value::String(sha.to_string());
        }

        // Use the lower-level API to create/update file
        let route = format!("/repos/{}/{}/contents/{}", self.owner, self.repo, path);

        let result: std::result::Result<serde_json::Value, octocrab::Error> =
            self.octocrab.put(route, Some(&body)).await;

        match result {
            Ok(response) => {
                // Extract SHA from response
                if let Some(content) = response.get("content") {
                    if let Some(sha) = content.get("sha") {
                        if let Some(sha_str) = sha.as_str() {
                            return Ok(sha_str.to_string());
                        }
                    }
                }
                Err(GitHubError::ValidationError(
                    "Invalid response format".to_string(),
                ))
            }
            Err(e) => {
                let error = GitHubError::from_octocrab(e, &format!("file {}", path));
                match error {
                    GitHubError::RateLimitExceeded { .. } => {
                        let rate_limit = self.rate_limit.lock().unwrap().clone();
                        if rate_limit.reset_at > 0 {
                            Err(GitHubError::rate_limit_exceeded(rate_limit.reset_at))
                        } else {
                            Err(error)
                        }
                    }
                    _ => Err(error),
                }
            }
        }
    }

    /// Lists directory contents.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the directory in the repository
    ///
    /// # Returns
    ///
    /// Returns a list of directory entries.
    ///
    /// # Errors
    ///
    /// * `NotFound` - If the directory doesn't exist
    /// * `Unauthorized` - If the token is invalid or expired
    /// * `RateLimitExceeded` - If the rate limit has been exceeded
    /// * `NetworkError` - If the request fails due to network issues
    pub async fn list_directory(&self, path: &str) -> Result<Vec<DirectoryEntry>> {
        // Check rate limit before making request
        self.check_rate_limit().await?;

        let result = self
            .octocrab
            .repos(&self.owner, &self.repo)
            .get_content()
            .path(path)
            .send()
            .await;

        match result {
            Ok(content) => {
                let mut entries = Vec::new();
                for item in content.items {
                    entries.push(DirectoryEntry {
                        name: item.name,
                        is_dir: item.r#type == "dir",
                        size: item.size as u64,
                        sha: item.sha,
                    });
                }
                Ok(entries)
            }
            Err(e) => {
                let error = GitHubError::from_octocrab(e, &format!("directory {}", path));
                match error {
                    GitHubError::RateLimitExceeded { .. } => {
                        let rate_limit = self.rate_limit.lock().unwrap().clone();
                        if rate_limit.reset_at > 0 {
                            Err(GitHubError::rate_limit_exceeded(rate_limit.reset_at))
                        } else {
                            Err(error)
                        }
                    }
                    _ => Err(error),
                }
            }
        }
    }
}

/// Directory entry information.
#[derive(Debug, Clone)]
pub struct DirectoryEntry {
    /// Name of the file or directory.
    pub name: String,
    /// Whether this entry is a directory.
    pub is_dir: bool,
    /// Size in bytes (0 for directories).
    pub size: u64,
    /// Git SHA of the entry.
    pub sha: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_client_creation() {
        let client = GitHubClient::new(
            "test_token".to_string(),
            "test_owner".to_string(),
            "test_repo".to_string(),
        );
        assert!(client.is_ok());

        let client = client.unwrap();
        assert_eq!(client.owner(), "test_owner");
        assert_eq!(client.repo(), "test_repo");
    }

    #[test]
    fn test_rate_limit_info_defaults() {
        let info = RateLimitInfo::new();
        assert_eq!(info.limit, 5000);
        assert_eq!(info.remaining, 5000);
        assert_eq!(info.reset_at, 0);
        assert!(!info.is_approaching_limit());
        assert!(!info.is_exceeded());
    }

    #[test]
    fn test_rate_limit_approaching() {
        let mut info = RateLimitInfo::new();

        // At 50% remaining, not approaching
        info.remaining = 2500;
        assert!(!info.is_approaching_limit());

        // At 10% remaining, approaching
        info.remaining = 500;
        assert!(!info.is_approaching_limit()); // Exactly at threshold

        // At 9% remaining, approaching
        info.remaining = 450;
        assert!(info.is_approaching_limit());

        // At 1% remaining, approaching
        info.remaining = 50;
        assert!(info.is_approaching_limit());
    }

    #[test]
    fn test_rate_limit_exceeded() {
        let mut info = RateLimitInfo::new();

        info.remaining = 1;
        assert!(!info.is_exceeded());

        info.remaining = 0;
        assert!(info.is_exceeded());
    }

    #[test]
    fn test_time_until_reset() {
        let mut info = RateLimitInfo::new();

        // Set reset time to 1 hour from now
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        info.reset_at = now + 3600;

        let duration = info.time_until_reset();
        // Should be approximately 1 hour (allowing for test execution time)
        assert!(duration.as_secs() >= 3599 && duration.as_secs() <= 3600);
    }

    #[test]
    fn test_reset_time_string() {
        let mut info = RateLimitInfo::new();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Test various durations
        info.reset_at = now + 30;
        assert_eq!(info.reset_time_string(), "30 seconds");

        info.reset_at = now + 120;
        assert_eq!(info.reset_time_string(), "2 minutes");

        info.reset_at = now + 3660;
        assert_eq!(info.reset_time_string(), "1 hours 1 minutes");

        // Past reset time
        info.reset_at = now - 100;
        assert_eq!(info.reset_time_string(), "now");
    }

    #[tokio::test]
    async fn test_rate_limit_tracking() {
        let client = GitHubClient::new(
            "test_token".to_string(),
            "test_owner".to_string(),
            "test_repo".to_string(),
        )
        .unwrap();

        // Initial state
        let info = client.rate_limit_info();
        assert_eq!(info.limit, 5000);
        assert_eq!(info.remaining, 5000);

        // Update rate limit
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        client.update_rate_limit_info(5000, 4500, now + 3600);

        let info = client.rate_limit_info();
        assert_eq!(info.limit, 5000);
        assert_eq!(info.remaining, 4500);
        assert_eq!(info.reset_at, now + 3600);
    }

    #[tokio::test]
    async fn test_check_rate_limit_ok() {
        let client = GitHubClient::new(
            "test_token".to_string(),
            "test_owner".to_string(),
            "test_repo".to_string(),
        )
        .unwrap();

        // With plenty of requests remaining, should succeed
        let result = client.check_rate_limit().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_check_rate_limit_exceeded() {
        let client = GitHubClient::new(
            "test_token".to_string(),
            "test_owner".to_string(),
            "test_repo".to_string(),
        )
        .unwrap();

        // Set rate limit to exceeded
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        client.update_rate_limit_info(5000, 0, now + 3600);

        // Should return error
        let result = client.check_rate_limit().await;
        assert!(result.is_err());

        match result {
            Err(GitHubError::RateLimitExceeded { reset_at }) => {
                assert!(reset_at.contains("hour") || reset_at.contains("minute"));
            }
            _ => panic!("Expected RateLimitExceeded error"),
        }
    }

    #[tokio::test]
    async fn test_check_rate_limit_approaching() {
        let client = GitHubClient::new(
            "test_token".to_string(),
            "test_owner".to_string(),
            "test_repo".to_string(),
        )
        .unwrap();

        // Set rate limit to approaching (5% remaining)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        client.update_rate_limit_info(5000, 250, now + 3600);

        // Should succeed but with backoff
        let start = std::time::Instant::now();
        let result = client.check_rate_limit().await;
        let elapsed = start.elapsed();

        assert!(result.is_ok());
        // Should have some backoff delay (at least a few milliseconds)
        assert!(elapsed.as_millis() > 0);
    }

    #[tokio::test]
    async fn test_update_rate_limit_from_headers() {
        let client = GitHubClient::new(
            "test_token".to_string(),
            "test_owner".to_string(),
            "test_repo".to_string(),
        )
        .unwrap();

        // Create mock headers
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("x-ratelimit-limit", "5000".parse().unwrap());
        headers.insert("x-ratelimit-remaining", "4999".parse().unwrap());
        headers.insert("x-ratelimit-reset", "1234567890".parse().unwrap());

        // Update from headers
        client.update_rate_limit(&headers);

        // Verify update
        let info = client.rate_limit_info();
        assert_eq!(info.limit, 5000);
        assert_eq!(info.remaining, 4999);
        assert_eq!(info.reset_at, 1234567890);
    }
}
