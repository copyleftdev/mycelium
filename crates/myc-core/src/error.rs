//! Core error types.

use thiserror::Error;

/// Errors that can occur in core domain operations.
#[derive(Debug, Error)]
pub enum CoreError {
    /// Entity validation failed.
    #[error("validation error: {0}")]
    ValidationError(#[from] ValidationError),

    /// JSON serialization or deserialization failed.
    #[error("serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    /// Content hash doesn't match computed hash.
    #[error("hash mismatch: expected {expected}, got {actual}")]
    HashMismatch {
        /// Expected hash value.
        expected: String,
        /// Actual computed hash value.
        actual: String,
    },

    /// Hash chain verification failed.
    #[error("hash chain broken at version {version}")]
    ChainBroken {
        /// Version number where chain broke.
        version: u64,
    },

    /// Signature verification failed.
    #[error("signature verification failed")]
    SignatureInvalid,

    /// Requested version doesn't exist.
    #[error("version {0} not found")]
    VersionNotFound(u64),

    /// Plaintext exceeds maximum size.
    #[error("size limit exceeded: {size} bytes exceeds maximum of {max} bytes")]
    SizeLimitExceeded {
        /// Actual size in bytes.
        size: usize,
        /// Maximum allowed size in bytes.
        max: usize,
    },

    /// Cryptographic operation failed.
    #[error("crypto error: {0}")]
    CryptoError(#[from] myc_crypto::error::CryptoError),
}

/// Validation errors for domain entities.
#[derive(Debug, Error)]
pub enum ValidationError {
    /// Name is empty or exceeds maximum length.
    #[error("invalid name: {reason}")]
    InvalidName {
        /// Reason for validation failure.
        reason: String,
    },

    /// Timestamp is in the future.
    #[error("timestamp cannot be in the future: {timestamp}")]
    FutureTimestamp {
        /// The invalid timestamp.
        timestamp: String,
    },

    /// Version number is invalid.
    #[error("invalid version number: {reason}")]
    InvalidVersion {
        /// Reason for validation failure.
        reason: String,
    },

    /// UUID is invalid.
    #[error("invalid UUID: {0}")]
    InvalidUuid(String),

    /// Format parsing failed.
    #[error("invalid {format} format: {reason}")]
    InvalidFormat {
        /// The format that failed to parse.
        format: String,
        /// Reason for validation failure.
        reason: String,
    },
}

/// Result type for core operations.
pub type Result<T> = std::result::Result<T, CoreError>;
