//! GitHub API client and authentication for Mycelium.
//!
//! This crate provides GitHub integration including OAuth device flow,
//! OIDC validation for GitHub Actions, and repository operations.
//! It handles only ciphertext bytes and does not depend on cryptographic primitives.
//!
//! # Modules
//!
//! - `auth`: OAuth device flow
//! - `api`: GitHub REST API operations
//! - `oidc`: GitHub Actions OIDC validation
//! - `repo`: Repository operations
//! - `error`: GitHub error types

#![deny(missing_docs)]
#![deny(clippy::all)]

pub mod auth;
pub mod cache;
pub mod client;
pub mod error;
pub mod oidc;

// Module stubs - will be implemented in subsequent tasks
// pub mod api;
// pub mod repo;

// Re-export commonly used types
pub use auth::{AccessToken, DeviceCodeResponse, GitHubUser, OAuthDeviceFlow};
pub use cache::{Cache, CacheStats};
pub use client::{DirectoryEntry, GitHubClient};
pub use error::{GitHubError, Result};
pub use oidc::{OidcClaims, OidcValidator};
