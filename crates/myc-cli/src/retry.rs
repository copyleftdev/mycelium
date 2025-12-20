//! Retry logic with exponential backoff for the Mycelium CLI.
//!
//! This module provides retry mechanisms for network operations and other
//! potentially transient failures, with exponential backoff and clear feedback.

use anyhow::Result;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use tracing::{debug, info, warn};

use indicatif::{ProgressBar, ProgressStyle};

/// Configuration for retry behavior.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts
    pub max_attempts: u32,
    /// Initial delay between retries
    pub initial_delay: Duration,
    /// Maximum delay between retries
    pub max_delay: Duration,
    /// Multiplier for exponential backoff
    pub backoff_multiplier: f64,
    /// Jitter factor to add randomness (0.0 to 1.0)
    pub jitter_factor: f64,
    /// Whether to show progress during retries
    pub show_progress: bool,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay: Duration::from_millis(1000),
            max_delay: Duration::from_secs(30),
            backoff_multiplier: 2.0,
            jitter_factor: 0.1,
            show_progress: true,
        }
    }
}

impl RetryConfig {
    /// Create a new retry config with custom max attempts.
    pub fn with_max_attempts(mut self, max_attempts: u32) -> Self {
        self.max_attempts = max_attempts;
        self
    }

    /// Create a new retry config with custom initial delay.
    pub fn with_initial_delay(mut self, delay: Duration) -> Self {
        self.initial_delay = delay;
        self
    }

    /// Create a new retry config with custom max delay.
    pub fn with_max_delay(mut self, delay: Duration) -> Self {
        self.max_delay = delay;
        self
    }

    /// Create a new retry config with custom backoff multiplier.
    pub fn with_backoff_multiplier(mut self, multiplier: f64) -> Self {
        self.backoff_multiplier = multiplier;
        self
    }

    /// Create a new retry config without progress display.
    pub fn without_progress(mut self) -> Self {
        self.show_progress = false;
        self
    }

    /// Create a config optimized for network operations.
    pub fn for_network() -> Self {
        Self {
            max_attempts: 3,
            initial_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(10),
            backoff_multiplier: 2.0,
            jitter_factor: 0.2,
            show_progress: true,
        }
    }

    /// Create a config optimized for GitHub API operations.
    pub fn for_github_api() -> Self {
        Self {
            max_attempts: 5,
            initial_delay: Duration::from_millis(1000),
            max_delay: Duration::from_secs(60),
            backoff_multiplier: 2.0,
            jitter_factor: 0.1,
            show_progress: true,
        }
    }

    /// Create a config for quick operations (minimal delay).
    pub fn for_quick_operations() -> Self {
        Self {
            max_attempts: 2,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(1),
            backoff_multiplier: 2.0,
            jitter_factor: 0.0,
            show_progress: false,
        }
    }
}

/// Retry strategy that determines whether an error should be retried.
pub trait RetryStrategy {
    /// Determine if an error should be retried.
    fn should_retry(&self, error: &anyhow::Error, attempt: u32) -> bool;

    /// Get a human-readable description of the error for logging.
    fn error_description(&self, error: &anyhow::Error) -> String {
        error.to_string()
    }
}

/// Default retry strategy for network errors.
pub struct NetworkRetryStrategy;

impl RetryStrategy for NetworkRetryStrategy {
    fn should_retry(&self, error: &anyhow::Error, attempt: u32) -> bool {
        if attempt >= 3 {
            return false;
        }

        let error_str = error.to_string().to_lowercase();

        // Retry on network-related errors
        error_str.contains("timeout")
            || error_str.contains("connection")
            || error_str.contains("network")
            || error_str.contains("dns")
            || error_str.contains("temporary failure")
            || error_str.contains("service unavailable")
            || error_str.contains("502")
            || error_str.contains("503")
            || error_str.contains("504")
    }
}

/// Retry strategy for GitHub API operations.
pub struct GitHubRetryStrategy;

impl RetryStrategy for GitHubRetryStrategy {
    fn should_retry(&self, error: &anyhow::Error, attempt: u32) -> bool {
        if attempt >= 5 {
            return false;
        }

        let error_str = error.to_string().to_lowercase();

        // Retry on GitHub API errors that are likely transient
        error_str.contains("rate limit")
            || error_str.contains("502")
            || error_str.contains("503")
            || error_str.contains("504")
            || error_str.contains("timeout")
            || error_str.contains("connection")
            || error_str.contains("temporary failure")
            || error_str.contains("abuse detection")
            || error_str.contains("server error")
    }

    fn error_description(&self, error: &anyhow::Error) -> String {
        let error_str = error.to_string();
        if error_str.to_lowercase().contains("rate limit") {
            "GitHub API rate limit exceeded".to_string()
        } else if error_str.contains("502")
            || error_str.contains("503")
            || error_str.contains("504")
        {
            "GitHub API server error".to_string()
        } else {
            error_str
        }
    }
}

/// Retry executor that handles the retry logic.
pub struct RetryExecutor {
    config: RetryConfig,
    strategy: Box<dyn RetryStrategy>,
}

impl RetryExecutor {
    /// Create a new retry executor with the given config and strategy.
    pub fn new(config: RetryConfig, strategy: Box<dyn RetryStrategy>) -> Self {
        Self { config, strategy }
    }

    /// Create a retry executor for network operations.
    pub fn for_network() -> Self {
        Self::new(RetryConfig::for_network(), Box::new(NetworkRetryStrategy))
    }

    /// Create a retry executor for GitHub API operations.
    pub fn for_github_api() -> Self {
        Self::new(RetryConfig::for_github_api(), Box::new(GitHubRetryStrategy))
    }

    /// Execute an async operation with retry logic.
    pub async fn execute<F, Fut, T>(&self, operation_name: &str, operation: F) -> Result<T>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let mut last_error = None;
        let start_time = Instant::now();

        let progress_bar = if self.config.show_progress {
            let pb = ProgressBar::new_spinner();
            pb.set_style(
                ProgressStyle::with_template("{spinner:.green} {msg}")
                    .unwrap_or_else(|_| ProgressStyle::default_spinner()),
            );
            pb.set_message(format!("Executing {}", operation_name));
            Some(pb)
        } else {
            None
        };

        for attempt in 1..=self.config.max_attempts {
            debug!(
                "Attempt {} of {} for {}",
                attempt, self.config.max_attempts, operation_name
            );

            if let Some(pb) = &progress_bar {
                pb.set_message(format!(
                    "Executing {} (attempt {})",
                    operation_name, attempt
                ));
            }

            match operation().await {
                Ok(result) => {
                    if let Some(pb) = &progress_bar {
                        pb.finish_and_clear();
                    }

                    let duration = start_time.elapsed();
                    if attempt > 1 {
                        info!(
                            "{} succeeded after {} attempts in {:.2}s",
                            operation_name,
                            attempt,
                            duration.as_secs_f64()
                        );
                    } else {
                        debug!(
                            "{} succeeded on first attempt in {:.2}s",
                            operation_name,
                            duration.as_secs_f64()
                        );
                    }

                    return Ok(result);
                }
                Err(error) => {
                    let should_retry = attempt < self.config.max_attempts
                        && self.strategy.should_retry(&error, attempt);

                    if should_retry {
                        let delay = self.calculate_delay(attempt);
                        let error_desc = self.strategy.error_description(&error);

                        warn!(
                            "{} failed (attempt {}): {}. Retrying in {:.1}s...",
                            operation_name,
                            attempt,
                            error_desc,
                            delay.as_secs_f64()
                        );

                        if let Some(pb) = &progress_bar {
                            pb.set_message(format!(
                                "Retrying {} in {:.1}s (attempt {} failed)",
                                operation_name,
                                delay.as_secs_f64(),
                                attempt
                            ));
                        }

                        sleep(delay).await;
                        last_error = Some(error);
                    } else {
                        if let Some(pb) = &progress_bar {
                            pb.finish_and_clear();
                        }

                        if attempt >= self.config.max_attempts {
                            warn!(
                                "{} failed after {} attempts: {}",
                                operation_name,
                                self.config.max_attempts,
                                self.strategy.error_description(&error)
                            );
                        } else {
                            debug!(
                                "{} failed (not retryable): {}",
                                operation_name,
                                self.strategy.error_description(&error)
                            );
                        }

                        return Err(error);
                    }
                }
            }
        }

        if let Some(pb) = &progress_bar {
            pb.finish_and_clear();
        }

        // This should never be reached, but just in case
        Err(last_error.unwrap_or_else(|| {
            anyhow::anyhow!(
                "Operation {} failed after {} attempts",
                operation_name,
                self.config.max_attempts
            )
        }))
    }

    /// Execute a synchronous operation with retry logic.
    pub fn execute_sync<F, T>(&self, operation_name: &str, operation: F) -> Result<T>
    where
        F: Fn() -> Result<T>,
    {
        let mut last_error = None;
        let start_time = Instant::now();

        for attempt in 1..=self.config.max_attempts {
            debug!(
                "Attempt {} of {} for {}",
                attempt, self.config.max_attempts, operation_name
            );

            match operation() {
                Ok(result) => {
                    let duration = start_time.elapsed();
                    if attempt > 1 {
                        info!(
                            "{} succeeded after {} attempts in {:.2}s",
                            operation_name,
                            attempt,
                            duration.as_secs_f64()
                        );
                    } else {
                        debug!(
                            "{} succeeded on first attempt in {:.2}s",
                            operation_name,
                            duration.as_secs_f64()
                        );
                    }
                    return Ok(result);
                }
                Err(error) => {
                    let should_retry = attempt < self.config.max_attempts
                        && self.strategy.should_retry(&error, attempt);

                    if should_retry {
                        let delay = self.calculate_delay(attempt);
                        let error_desc = self.strategy.error_description(&error);

                        warn!(
                            "{} failed (attempt {}): {}. Retrying in {:.1}s...",
                            operation_name,
                            attempt,
                            error_desc,
                            delay.as_secs_f64()
                        );

                        std::thread::sleep(delay);
                        last_error = Some(error);
                    } else {
                        if attempt >= self.config.max_attempts {
                            warn!(
                                "{} failed after {} attempts: {}",
                                operation_name,
                                self.config.max_attempts,
                                self.strategy.error_description(&error)
                            );
                        } else {
                            debug!(
                                "{} failed (not retryable): {}",
                                operation_name,
                                self.strategy.error_description(&error)
                            );
                        }
                        return Err(error);
                    }
                }
            }
        }

        // This should never be reached, but just in case
        Err(last_error.unwrap_or_else(|| {
            anyhow::anyhow!(
                "Operation {} failed after {} attempts",
                operation_name,
                self.config.max_attempts
            )
        }))
    }

    /// Calculate the delay for the given attempt number.
    fn calculate_delay(&self, attempt: u32) -> Duration {
        let base_delay = self.config.initial_delay.as_millis() as f64;
        let exponential_delay =
            base_delay * self.config.backoff_multiplier.powi(attempt as i32 - 1);

        // Apply jitter
        let jitter = if self.config.jitter_factor > 0.0 {
            use rand::Rng;
            let mut rng = rand::thread_rng();
            let jitter_amount = exponential_delay * self.config.jitter_factor;
            rng.gen_range(-jitter_amount..=jitter_amount)
        } else {
            0.0
        };

        let final_delay = (exponential_delay + jitter).max(0.0);
        let capped_delay = final_delay.min(self.config.max_delay.as_millis() as f64);

        Duration::from_millis(capped_delay as u64)
    }
}

/// Convenience functions for common retry patterns.
pub mod helpers {
    use super::*;

    /// Retry a GitHub API operation.
    pub async fn retry_github_api<F, Fut, T>(operation_name: &str, operation: F) -> Result<T>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let executor = RetryExecutor::for_github_api();
        executor.execute(operation_name, operation).await
    }

    /// Retry a network operation.
    pub async fn retry_network<F, Fut, T>(operation_name: &str, operation: F) -> Result<T>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let executor = RetryExecutor::for_network();
        executor.execute(operation_name, operation).await
    }

    /// Retry a quick operation with minimal delay.
    pub async fn retry_quick<F, Fut, T>(operation_name: &str, operation: F) -> Result<T>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let config = RetryConfig::for_quick_operations();
        let executor = RetryExecutor::new(config, Box::new(NetworkRetryStrategy));
        executor.execute(operation_name, operation).await
    }

    /// Retry a synchronous operation.
    pub fn retry_sync<F, T>(operation_name: &str, operation: F) -> Result<T>
    where
        F: Fn() -> Result<T>,
    {
        let executor = RetryExecutor::for_network();
        executor.execute_sync(operation_name, operation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn test_retry_config_defaults() {
        let config = RetryConfig::default();
        assert_eq!(config.max_attempts, 3);
        assert_eq!(config.initial_delay, Duration::from_millis(1000));
        assert_eq!(config.backoff_multiplier, 2.0);
    }

    #[test]
    fn test_retry_config_builders() {
        let config = RetryConfig::default()
            .with_max_attempts(5)
            .with_initial_delay(Duration::from_millis(500))
            .without_progress();

        assert_eq!(config.max_attempts, 5);
        assert_eq!(config.initial_delay, Duration::from_millis(500));
        assert!(!config.show_progress);
    }

    #[test]
    fn test_network_retry_strategy() {
        let strategy = NetworkRetryStrategy;

        // Should retry on network errors
        let network_error = anyhow::anyhow!("Connection timeout");
        assert!(strategy.should_retry(&network_error, 1));

        // Should not retry on non-network errors
        let other_error = anyhow::anyhow!("Invalid input");
        assert!(!strategy.should_retry(&other_error, 1));

        // Should not retry after max attempts
        assert!(!strategy.should_retry(&network_error, 3));
    }

    #[test]
    fn test_github_retry_strategy() {
        let strategy = GitHubRetryStrategy;

        // Should retry on rate limit
        let rate_limit_error = anyhow::anyhow!("Rate limit exceeded");
        assert!(strategy.should_retry(&rate_limit_error, 1));

        // Should retry on server errors
        let server_error = anyhow::anyhow!("502 Bad Gateway");
        assert!(strategy.should_retry(&server_error, 1));

        // Should not retry on client errors
        let client_error = anyhow::anyhow!("404 Not Found");
        assert!(!strategy.should_retry(&client_error, 1));
    }

    #[tokio::test]
    async fn test_retry_executor_success_on_first_attempt() {
        let config = RetryConfig::default().without_progress();
        let executor = RetryExecutor::new(config, Box::new(NetworkRetryStrategy));

        let result = executor
            .execute("test operation", || async { Ok::<i32, anyhow::Error>(42) })
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
    }

    #[tokio::test]
    async fn test_retry_executor_success_after_retry() {
        let config = RetryConfig::default().without_progress();
        let executor = RetryExecutor::new(config, Box::new(NetworkRetryStrategy));

        let attempt_count = Arc::new(Mutex::new(0));
        let attempt_count_clone = attempt_count.clone();

        let result = executor
            .execute("test operation", move || {
                let count = attempt_count_clone.clone();
                async move {
                    let mut attempts = count.lock().unwrap();
                    *attempts += 1;
                    if *attempts < 2 {
                        Err(anyhow::anyhow!("Connection timeout"))
                    } else {
                        Ok(42)
                    }
                }
            })
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
        assert_eq!(*attempt_count.lock().unwrap(), 2);
    }

    #[test]
    fn test_delay_calculation() {
        let config = RetryConfig {
            initial_delay: Duration::from_millis(1000),
            max_delay: Duration::from_secs(10),
            backoff_multiplier: 2.0,
            jitter_factor: 0.0, // No jitter for predictable testing
            ..Default::default()
        };

        let executor = RetryExecutor::new(config, Box::new(NetworkRetryStrategy));

        // First retry should be initial_delay
        let delay1 = executor.calculate_delay(1);
        assert_eq!(delay1, Duration::from_millis(1000));

        // Second retry should be doubled
        let delay2 = executor.calculate_delay(2);
        assert_eq!(delay2, Duration::from_millis(2000));

        // Third retry should be doubled again
        let delay3 = executor.calculate_delay(3);
        assert_eq!(delay3, Duration::from_millis(4000));
    }
}
