//! Secure random byte generation.
//!
//! This module provides secure random byte generation using the operating
//! system's cryptographically secure random number generator (CSPRNG).

use crate::error::{CryptoError, Result};

/// Fills a buffer with secure random bytes.
///
/// This function uses the operating system's CSPRNG via `getrandom`.
/// It will block if insufficient entropy is available.
///
/// # Arguments
///
/// * `dest` - The buffer to fill with random bytes
///
/// # Returns
///
/// `Ok(())` on success, or `CryptoError::RandomnessFailure` if the OS RNG is unavailable
///
/// # Examples
///
/// ```
/// use myc_crypto::random::fill_random;
///
/// let mut buffer = [0u8; 32];
/// fill_random(&mut buffer).unwrap();
/// // buffer now contains 32 random bytes
/// ```
pub fn fill_random(dest: &mut [u8]) -> Result<()> {
    getrandom::getrandom(dest).map_err(|e| CryptoError::RandomnessFailure(e.to_string()))
}

/// Generates a fixed-size array of random bytes.
///
/// This is a convenience function that wraps `fill_random` for
/// fixed-size arrays.
///
/// # Returns
///
/// An array of N random bytes, or `CryptoError::RandomnessFailure` if the OS RNG is unavailable
///
/// # Examples
///
/// ```
/// use myc_crypto::random::generate_random_bytes;
///
/// let random_key: [u8; 32] = generate_random_bytes().unwrap();
/// ```
pub fn generate_random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0u8; N];
    fill_random(&mut bytes)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fill_random() {
        let mut buffer = [0u8; 32];
        let result = fill_random(&mut buffer);
        assert!(result.is_ok());

        // Buffer should no longer be all zeros (with overwhelming probability)
        assert_ne!(buffer, [0u8; 32]);
    }

    #[test]
    fn test_fill_random_different_calls() {
        let mut buffer1 = [0u8; 32];
        let mut buffer2 = [0u8; 32];

        fill_random(&mut buffer1).unwrap();
        fill_random(&mut buffer2).unwrap();

        // Two calls should produce different random bytes (with overwhelming probability)
        assert_ne!(buffer1, buffer2);
    }

    #[test]
    fn test_fill_random_empty() {
        let mut buffer = [];
        let result = fill_random(&mut buffer);
        assert!(result.is_ok());
    }

    #[test]
    fn test_generate_random_bytes() {
        let bytes: [u8; 32] = generate_random_bytes().unwrap();

        // Should not be all zeros (with overwhelming probability)
        assert_ne!(bytes, [0u8; 32]);
    }

    #[test]
    fn test_generate_random_bytes_different_calls() {
        let bytes1: [u8; 32] = generate_random_bytes().unwrap();
        let bytes2: [u8; 32] = generate_random_bytes().unwrap();

        // Two calls should produce different random bytes (with overwhelming probability)
        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn test_generate_random_bytes_various_sizes() {
        let bytes16: [u8; 16] = generate_random_bytes().unwrap();
        let bytes32: [u8; 32] = generate_random_bytes().unwrap();
        let bytes64: [u8; 64] = generate_random_bytes().unwrap();

        assert_ne!(bytes16, [0u8; 16]);
        assert_ne!(bytes32, [0u8; 32]);
        assert_ne!(bytes64, [0u8; 64]);
    }
}
