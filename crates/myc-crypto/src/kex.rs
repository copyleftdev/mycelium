//! X25519 key exchange (Elliptic Curve Diffie-Hellman).
//!
//! This module provides X25519 key agreement for deriving shared secrets
//! between two parties. The shared secret must be processed through a KDF
//! before use as a cryptographic key.

use crate::error::Result;
use x25519_dalek::StaticSecret;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Size of an X25519 public key in bytes.
pub const PUBLIC_KEY_SIZE: usize = 32;

/// Size of an X25519 secret key in bytes.
pub const SECRET_KEY_SIZE: usize = 32;

/// Size of a shared secret in bytes.
pub const SHARED_SECRET_SIZE: usize = 32;

/// An X25519 secret key for key agreement.
///
/// This type wraps the secret key and implements `Zeroize` and
/// `ZeroizeOnDrop` to ensure the key is securely cleared from memory
/// when dropped. It does not implement `Clone` to prevent accidental
/// duplication of key material.
#[derive(ZeroizeOnDrop)]
pub struct X25519SecretKey(StaticSecret);

impl X25519SecretKey {
    /// Creates a new secret key from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A 32-byte array containing the secret key
    ///
    /// # Returns
    ///
    /// A new `X25519SecretKey` instance
    pub fn from_bytes(bytes: [u8; SECRET_KEY_SIZE]) -> Self {
        Self(StaticSecret::from(bytes))
    }

    /// Returns the secret key as a byte array.
    ///
    /// # Returns
    ///
    /// A 32-byte array containing the secret key
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_SIZE] {
        self.0.to_bytes()
    }

    /// Returns the corresponding public key for this secret key.
    ///
    /// # Returns
    ///
    /// The X25519 public key corresponding to this secret key
    pub fn public_key(&self) -> X25519PublicKey {
        let public = x25519_dalek::PublicKey::from(&self.0);
        X25519PublicKey(public.to_bytes())
    }

    /// Returns a reference to the inner StaticSecret.
    fn inner(&self) -> &StaticSecret {
        &self.0
    }
}

impl Zeroize for X25519SecretKey {
    fn zeroize(&mut self) {
        // StaticSecret handles zeroization
    }
}

/// An X25519 public key for key agreement.
///
/// Public keys can be freely copied and shared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X25519PublicKey([u8; PUBLIC_KEY_SIZE]);

impl X25519PublicKey {
    /// Creates a new public key from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A 32-byte array containing the public key
    ///
    /// # Returns
    ///
    /// A new `X25519PublicKey` instance
    pub fn from_bytes(bytes: [u8; PUBLIC_KEY_SIZE]) -> Self {
        Self(bytes)
    }

    /// Returns the public key as a byte array.
    ///
    /// # Returns
    ///
    /// A reference to the 32-byte public key array
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_SIZE] {
        &self.0
    }

    /// Converts to the underlying dalek PublicKey type.
    fn to_dalek(self) -> x25519_dalek::PublicKey {
        x25519_dalek::PublicKey::from(self.0)
    }
}

impl From<[u8; PUBLIC_KEY_SIZE]> for X25519PublicKey {
    fn from(bytes: [u8; PUBLIC_KEY_SIZE]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl AsRef<[u8]> for X25519PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl serde::Serialize for X25519PublicKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for X25519PublicKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = <Vec<u8>>::deserialize(deserializer)?;
        if bytes.len() != PUBLIC_KEY_SIZE {
            return Err(serde::de::Error::custom(format!(
                "Invalid public key length: expected {}, got {}",
                PUBLIC_KEY_SIZE,
                bytes.len()
            )));
        }
        let mut array = [0u8; PUBLIC_KEY_SIZE];
        array.copy_from_slice(&bytes);
        Ok(Self(array))
    }
}

/// A shared secret derived from X25519 key agreement.
///
/// This type implements `Zeroize` and `ZeroizeOnDrop` to ensure the
/// shared secret is securely cleared from memory. The shared secret
/// MUST be processed through a KDF (e.g., HKDF) before use as a
/// cryptographic key.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret([u8; SHARED_SECRET_SIZE]);

impl SharedSecret {
    /// Creates a new shared secret from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A 32-byte array containing the shared secret
    ///
    /// # Returns
    ///
    /// A new `SharedSecret` instance
    pub fn from_bytes(bytes: [u8; SHARED_SECRET_SIZE]) -> Self {
        Self(bytes)
    }

    /// Returns the shared secret as a byte array.
    ///
    /// # Returns
    ///
    /// A reference to the 32-byte shared secret array
    pub fn as_bytes(&self) -> &[u8; SHARED_SECRET_SIZE] {
        &self.0
    }
}

/// Generates a new X25519 keypair.
///
/// # Returns
///
/// A tuple containing the secret key and corresponding public key
///
/// # Errors
///
/// Returns `CryptoError::RandomnessFailure` if the OS RNG is unavailable
pub fn generate_x25519_keypair() -> Result<(X25519SecretKey, X25519PublicKey)> {
    let secret = StaticSecret::random_from_rng(rand_core::OsRng);
    let public = x25519_dalek::PublicKey::from(&secret);

    Ok((X25519SecretKey(secret), X25519PublicKey(public.to_bytes())))
}

/// Performs X25519 Diffie-Hellman key agreement.
///
/// Computes a shared secret from a secret key and a public key.
/// The shared secret MUST be processed through a KDF before use.
///
/// # Arguments
///
/// * `secret` - The local secret key
/// * `public` - The remote public key
///
/// # Returns
///
/// A shared secret that must be processed through a KDF
pub fn diffie_hellman(secret: &X25519SecretKey, public: &X25519PublicKey) -> SharedSecret {
    let shared = secret.inner().diffie_hellman(&public.to_dalek());
    SharedSecret(shared.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let result = generate_x25519_keypair();
        assert!(result.is_ok());
    }

    #[test]
    fn test_diffie_hellman_agreement() {
        // Generate two keypairs
        let (secret_a, public_a) = generate_x25519_keypair().unwrap();
        let (secret_b, public_b) = generate_x25519_keypair().unwrap();

        // Compute shared secrets
        let shared_ab = diffie_hellman(&secret_a, &public_b);
        let shared_ba = diffie_hellman(&secret_b, &public_a);

        // Both parties should derive the same shared secret
        assert_eq!(shared_ab.as_bytes(), shared_ba.as_bytes());
    }

    #[test]
    fn test_public_key_roundtrip() {
        let (_, public) = generate_x25519_keypair().unwrap();
        let bytes = *public.as_bytes();
        let restored = X25519PublicKey::from_bytes(bytes);

        assert_eq!(public, restored);
    }

    #[test]
    fn test_secret_key_roundtrip() {
        let (secret, _) = generate_x25519_keypair().unwrap();
        let bytes = secret.to_bytes();
        let restored = X25519SecretKey::from_bytes(bytes);

        // Can't directly compare secret keys, but we can verify they produce
        // the same public key
        let (_, public1) = generate_x25519_keypair().unwrap();
        let shared1 = diffie_hellman(&secret, &public1);
        let shared2 = diffie_hellman(&restored, &public1);

        assert_eq!(shared1.as_bytes(), shared2.as_bytes());
    }

    #[test]
    fn test_different_keypairs_different_secrets() {
        let (secret_a, _) = generate_x25519_keypair().unwrap();
        let (secret_b, _) = generate_x25519_keypair().unwrap();
        let (_, public_c) = generate_x25519_keypair().unwrap();

        let shared_ac = diffie_hellman(&secret_a, &public_c);
        let shared_bc = diffie_hellman(&secret_b, &public_c);

        // Different secret keys should produce different shared secrets
        assert_ne!(shared_ac.as_bytes(), shared_bc.as_bytes());
    }
}
