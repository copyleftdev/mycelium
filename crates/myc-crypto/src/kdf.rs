//! HKDF-SHA256 key derivation.
//!
//! This module provides HKDF (HMAC-based Key Derivation Function) using
//! SHA-256 as the hash function. HKDF is used to derive cryptographic keys
//! from shared secrets and other key material.

use crate::aead::{AeadKey, KEY_SIZE};
use crate::kex::SharedSecret;
use hkdf::Hkdf;
use sha2::Sha256;

/// Derives a key using HKDF-SHA256.
///
/// HKDF expands input key material (IKM) into a longer output key using
/// an optional salt and application-specific info parameter. The info
/// parameter provides domain separation between different uses of the KDF.
///
/// # Arguments
///
/// * `ikm` - Input key material (e.g., a shared secret)
/// * `salt` - Optional salt value (use empty slice if none)
/// * `info` - Application-specific context and domain separation
/// * `len` - Length of output key material in bytes
///
/// # Returns
///
/// A vector containing the derived key material
///
/// # Examples
///
/// ```
/// use myc_crypto::kdf::derive_key;
///
/// let ikm = b"input key material";
/// let salt = b"optional salt";
/// let info = b"application context";
/// let key = derive_key(ikm, salt, info, 32);
/// assert_eq!(key.len(), 32);
/// ```
pub fn derive_key(ikm: &[u8], salt: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut output = vec![0u8; len];
    hkdf.expand(info, &mut output)
        .expect("output length is valid");
    output
}

/// Derives an AEAD key from a shared secret.
///
/// This is a convenience function that wraps `derive_key` to produce
/// an `AeadKey` suitable for ChaCha20-Poly1305 encryption. The context
/// parameter provides domain separation.
///
/// # Arguments
///
/// * `shared_secret` - The shared secret from key agreement
/// * `context` - Application-specific context for domain separation
///
/// # Returns
///
/// An `AeadKey` suitable for AEAD encryption
///
/// # Examples
///
/// ```
/// use myc_crypto::kdf::derive_aead_key;
/// use myc_crypto::kex::{generate_x25519_keypair, diffie_hellman};
///
/// let (secret_a, public_a) = generate_x25519_keypair().unwrap();
/// let (secret_b, public_b) = generate_x25519_keypair().unwrap();
///
/// let shared = diffie_hellman(&secret_a, &public_b);
/// let key = derive_aead_key(&shared, b"mycelium-pdk-wrap");
/// ```
pub fn derive_aead_key(shared_secret: &SharedSecret, context: &[u8]) -> AeadKey {
    let key_bytes = derive_key(shared_secret.as_bytes(), b"", context, KEY_SIZE);
    let mut key_array = [0u8; KEY_SIZE];
    key_array.copy_from_slice(&key_bytes);
    AeadKey::from_bytes(key_array)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key_basic() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"context";

        let key = derive_key(ikm, salt, info, 32);
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_derive_key_determinism() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"context";

        let key1 = derive_key(ikm, salt, info, 32);
        let key2 = derive_key(ikm, salt, info, 32);

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_derive_key_different_info() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info1 = b"context1";
        let info2 = b"context2";

        let key1 = derive_key(ikm, salt, info1, 32);
        let key2 = derive_key(ikm, salt, info2, 32);

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_derive_key_different_salt() {
        let ikm = b"input key material";
        let salt1 = b"salt1";
        let salt2 = b"salt2";
        let info = b"context";

        let key1 = derive_key(ikm, salt1, info, 32);
        let key2 = derive_key(ikm, salt2, info, 32);

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_derive_key_no_salt() {
        let ikm = b"input key material";
        let info = b"context";

        let key = derive_key(ikm, b"", info, 32);
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_derive_key_variable_length() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"context";

        let key16 = derive_key(ikm, salt, info, 16);
        let key32 = derive_key(ikm, salt, info, 32);
        let key64 = derive_key(ikm, salt, info, 64);

        assert_eq!(key16.len(), 16);
        assert_eq!(key32.len(), 32);
        assert_eq!(key64.len(), 64);
    }

    #[test]
    fn test_derive_aead_key() {
        use crate::kex::{diffie_hellman, generate_x25519_keypair};

        let (secret_a, public_a) = generate_x25519_keypair().unwrap();
        let (secret_b, public_b) = generate_x25519_keypair().unwrap();

        let shared_ab = diffie_hellman(&secret_a, &public_b);
        let shared_ba = diffie_hellman(&secret_b, &public_a);

        let key_ab = derive_aead_key(&shared_ab, b"test-context");
        let key_ba = derive_aead_key(&shared_ba, b"test-context");

        // Both parties should derive the same key
        // We can't directly compare AeadKey, so we'll use them to encrypt/decrypt
        use crate::aead::{decrypt, encrypt};
        let plaintext = b"test message";
        let ciphertext = encrypt(&key_ab, plaintext, b"").unwrap();
        let decrypted = decrypt(&key_ba, &ciphertext, b"").unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_derive_aead_key_different_context() {
        use crate::kex::{diffie_hellman, generate_x25519_keypair};

        let (secret_a, public_a) = generate_x25519_keypair().unwrap();
        let (_secret_b, _) = generate_x25519_keypair().unwrap();

        let shared = diffie_hellman(&secret_a, &public_a);

        let key1 = derive_aead_key(&shared, b"context1");
        let key2 = derive_aead_key(&shared, b"context2");

        // Different contexts should produce different keys
        use crate::aead::encrypt;
        let plaintext = b"test";
        let ct1 = encrypt(&key1, plaintext, b"").unwrap();
        let ct2 = encrypt(&key2, plaintext, b"").unwrap();

        // The ciphertexts will be different due to different keys
        // (even though nonces are random, we can verify by trying to decrypt with wrong key)
        use crate::aead::decrypt;
        assert!(decrypt(&key2, &ct1, b"").is_err());
        assert!(decrypt(&key1, &ct2, b"").is_err());
    }
}
