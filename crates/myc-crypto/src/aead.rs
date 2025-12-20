//! ChaCha20-Poly1305 authenticated encryption with associated data (AEAD).
//!
//! This module provides authenticated encryption using ChaCha20-Poly1305.
//! All encryption operations use randomly generated nonces that are prepended
//! to the ciphertext.

use crate::error::{CryptoError, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce as ChaCha20Nonce,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Size of a ChaCha20-Poly1305 nonce in bytes.
pub const NONCE_SIZE: usize = 12;

/// Size of a Poly1305 authentication tag in bytes.
pub const TAG_SIZE: usize = 16;

/// Size of an AEAD key in bytes (256 bits).
pub const KEY_SIZE: usize = 32;

/// A 256-bit AEAD key for ChaCha20-Poly1305.
///
/// This type wraps the key material and implements `Zeroize` and
/// `ZeroizeOnDrop` to ensure the key is securely cleared from memory
/// when dropped.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct AeadKey([u8; KEY_SIZE]);

impl AeadKey {
    /// Creates a new AEAD key from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A 32-byte array containing the key material
    ///
    /// # Returns
    ///
    /// A new `AeadKey` instance
    pub fn from_bytes(bytes: [u8; KEY_SIZE]) -> Self {
        Self(bytes)
    }

    /// Creates a new AEAD key from a byte slice.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A byte slice containing exactly 32 bytes of key material
    ///
    /// # Returns
    ///
    /// A new `AeadKey` instance or an error if the slice is not exactly 32 bytes
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != KEY_SIZE {
            return Err(CryptoError::InvalidKeySize {
                expected: KEY_SIZE,
                actual: bytes.len(),
            });
        }
        let mut key_bytes = [0u8; KEY_SIZE];
        key_bytes.copy_from_slice(bytes);
        Ok(Self(key_bytes))
    }

    /// Exposes the key bytes for cryptographic operations.
    ///
    /// # Returns
    ///
    /// A reference to the 32-byte key array
    pub fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.0
    }
}

/// A 12-byte nonce for ChaCha20-Poly1305.
///
/// Nonces must never be reused with the same key. This implementation
/// generates random nonces for each encryption operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Nonce([u8; NONCE_SIZE]);

impl Nonce {
    /// Creates a new nonce from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A 12-byte array containing the nonce
    ///
    /// # Returns
    ///
    /// A new `Nonce` instance
    pub fn from_bytes(bytes: [u8; NONCE_SIZE]) -> Self {
        Self(bytes)
    }

    /// Returns the nonce as a byte slice.
    ///
    /// # Returns
    ///
    /// A reference to the 12-byte nonce array
    pub fn as_bytes(&self) -> &[u8; NONCE_SIZE] {
        &self.0
    }
}

impl From<[u8; NONCE_SIZE]> for Nonce {
    fn from(bytes: [u8; NONCE_SIZE]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl AsRef<[u8]> for Nonce {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Encrypts plaintext using ChaCha20-Poly1305 AEAD.
///
/// This function generates a random nonce, encrypts the plaintext with the
/// provided key and optional associated data, and returns the nonce prepended
/// to the ciphertext and authentication tag.
///
/// # Output Format
///
/// The output has the structure: `nonce (12 bytes) || ciphertext || tag (16 bytes)`
///
/// # Arguments
///
/// * `key` - The AEAD key to use for encryption
/// * `plaintext` - The data to encrypt
/// * `aad` - Optional associated data to authenticate (not encrypted)
///
/// # Returns
///
/// A vector containing the nonce, ciphertext, and authentication tag
///
/// # Errors
///
/// Returns `CryptoError::RandomnessFailure` if random nonce generation fails
pub fn encrypt(key: &AeadKey, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    // Generate random nonce
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    getrandom::getrandom(&mut nonce_bytes)
        .map_err(|e| CryptoError::RandomnessFailure(e.to_string()))?;
    let nonce = ChaCha20Nonce::from_slice(&nonce_bytes);

    // Create cipher instance
    let cipher = ChaCha20Poly1305::new(key.as_bytes().into());

    // Encrypt with AAD
    let payload = Payload {
        msg: plaintext,
        aad,
    };

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    // Prepend nonce to ciphertext
    let mut output = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

/// Decrypts ciphertext using ChaCha20-Poly1305 AEAD.
///
/// This function extracts the nonce from the beginning of the input,
/// then decrypts and authenticates the ciphertext with the provided
/// key and optional associated data.
///
/// # Input Format
///
/// The input must have the structure: `nonce (12 bytes) || ciphertext || tag (16 bytes)`
///
/// # Arguments
///
/// * `key` - The AEAD key to use for decryption
/// * `ciphertext_with_nonce` - The nonce, ciphertext, and tag concatenated
/// * `aad` - Optional associated data to authenticate (must match encryption)
///
/// # Returns
///
/// A vector containing the decrypted plaintext
///
/// # Errors
///
/// Returns `CryptoError::InvalidNonceSize` if the input is too short to contain a nonce.
/// Returns `CryptoError::DecryptionFailed` if authentication fails or decryption fails.
pub fn decrypt(key: &AeadKey, ciphertext_with_nonce: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    // Check minimum size (nonce + tag)
    if ciphertext_with_nonce.len() < NONCE_SIZE + TAG_SIZE {
        return Err(CryptoError::InvalidNonceSize {
            expected: NONCE_SIZE,
            actual: ciphertext_with_nonce.len(),
        });
    }

    // Extract nonce and ciphertext
    let (nonce_bytes, ciphertext) = ciphertext_with_nonce.split_at(NONCE_SIZE);
    let nonce = ChaCha20Nonce::from_slice(nonce_bytes);

    // Create cipher instance
    let cipher = ChaCha20Poly1305::new(key.as_bytes().into());

    // Decrypt with AAD
    let payload = Payload {
        msg: ciphertext,
        aad,
    };

    let plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = AeadKey::from_bytes([42u8; KEY_SIZE]);
        let plaintext = b"Hello, World!";
        let aad = b"additional data";

        let ciphertext = encrypt(&key, plaintext, aad).unwrap();
        let decrypted = decrypt(&key, &ciphertext, aad).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_empty_plaintext() {
        let key = AeadKey::from_bytes([42u8; KEY_SIZE]);
        let plaintext = b"";
        let aad = b"";

        let ciphertext = encrypt(&key, plaintext, aad).unwrap();
        let decrypted = decrypt(&key, &ciphertext, aad).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_decrypt_with_wrong_key() {
        let key1 = AeadKey::from_bytes([1u8; KEY_SIZE]);
        let key2 = AeadKey::from_bytes([2u8; KEY_SIZE]);
        let plaintext = b"secret message";
        let aad = b"";

        let ciphertext = encrypt(&key1, plaintext, aad).unwrap();
        let result = decrypt(&key2, &ciphertext, aad);

        assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    }

    #[test]
    fn test_decrypt_with_wrong_aad() {
        let key = AeadKey::from_bytes([42u8; KEY_SIZE]);
        let plaintext = b"secret message";
        let aad1 = b"correct aad";
        let aad2 = b"wrong aad";

        let ciphertext = encrypt(&key, plaintext, aad1).unwrap();
        let result = decrypt(&key, &ciphertext, aad2);

        assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    }

    #[test]
    fn test_decrypt_tampered_ciphertext() {
        let key = AeadKey::from_bytes([42u8; KEY_SIZE]);
        let plaintext = b"secret message";
        let aad = b"";

        let mut ciphertext = encrypt(&key, plaintext, aad).unwrap();
        // Tamper with the ciphertext (skip nonce)
        if ciphertext.len() > NONCE_SIZE {
            ciphertext[NONCE_SIZE] ^= 0xFF;
        }

        let result = decrypt(&key, &ciphertext, aad);
        assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    }

    #[test]
    fn test_decrypt_too_short() {
        let key = AeadKey::from_bytes([42u8; KEY_SIZE]);
        let short_input = vec![0u8; NONCE_SIZE - 1];

        let result = decrypt(&key, &short_input, b"");
        assert!(matches!(result, Err(CryptoError::InvalidNonceSize { .. })));
    }

    #[test]
    fn test_ciphertext_structure() {
        let key = AeadKey::from_bytes([42u8; KEY_SIZE]);
        let plaintext = b"test";
        let aad = b"";

        let ciphertext = encrypt(&key, plaintext, aad).unwrap();

        // Check structure: nonce (12) + ciphertext (4) + tag (16) = 32 bytes
        assert_eq!(ciphertext.len(), NONCE_SIZE + plaintext.len() + TAG_SIZE);
    }

    #[test]
    fn test_nonce_randomness() {
        let key = AeadKey::from_bytes([42u8; KEY_SIZE]);
        let plaintext = b"test";
        let aad = b"";

        let ciphertext1 = encrypt(&key, plaintext, aad).unwrap();
        let ciphertext2 = encrypt(&key, plaintext, aad).unwrap();

        // Nonces should be different (first 12 bytes)
        assert_ne!(&ciphertext1[..NONCE_SIZE], &ciphertext2[..NONCE_SIZE]);
    }
}
