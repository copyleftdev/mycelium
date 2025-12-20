//! Cryptographic error types.

use thiserror::Error;

/// Errors that can occur during cryptographic operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// AEAD decryption failed (authentication tag mismatch or invalid ciphertext).
    #[error("decryption failed: authentication tag mismatch or invalid ciphertext")]
    DecryptionFailed,

    /// Ed25519 signature verification failed.
    #[error("signature verification failed")]
    InvalidSignature,

    /// Key material has incorrect length.
    #[error("invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength {
        /// Expected key length in bytes.
        expected: usize,
        /// Actual key length in bytes.
        actual: usize,
    },

    /// Key size is invalid.
    #[error("invalid key size: expected {expected}, got {actual}")]
    InvalidKeySize {
        /// Expected key size in bytes.
        expected: usize,
        /// Actual key size in bytes.
        actual: usize,
    },

    /// OS random number generator is unavailable (fatal).
    #[error("randomness source unavailable: {0}")]
    RandomnessFailure(String),

    /// Invalid nonce size.
    #[error("invalid nonce size: expected {expected}, got {actual}")]
    InvalidNonceSize {
        /// Expected nonce size in bytes.
        expected: usize,
        /// Actual nonce size in bytes.
        actual: usize,
    },
}

/// Result type for cryptographic operations.
pub type Result<T> = std::result::Result<T, CryptoError>;
