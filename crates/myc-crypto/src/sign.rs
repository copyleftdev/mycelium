//! Ed25519 digital signatures.
//!
//! This module provides Ed25519 signature generation and verification.
//! Signatures are deterministic and provide strong authentication.

use crate::error::{CryptoError, Result};
use ed25519_dalek::{Signature as DalekSignature, Signer, SigningKey, Verifier, VerifyingKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Size of an Ed25519 public key in bytes.
pub const PUBLIC_KEY_SIZE: usize = 32;

/// Size of an Ed25519 secret key in bytes.
pub const SECRET_KEY_SIZE: usize = 32;

/// Size of an Ed25519 signature in bytes.
pub const SIGNATURE_SIZE: usize = 64;

/// An Ed25519 secret key for signing.
///
/// This type wraps the secret key and implements `Zeroize` and
/// `ZeroizeOnDrop` to ensure the key is securely cleared from memory
/// when dropped. It does not implement `Clone` to prevent accidental
/// duplication of key material.
#[derive(ZeroizeOnDrop)]
pub struct Ed25519SecretKey(SigningKey);

impl Ed25519SecretKey {
    /// Creates a new secret key from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A 32-byte array containing the secret key
    ///
    /// # Returns
    ///
    /// A new `Ed25519SecretKey` instance
    pub fn from_bytes(bytes: [u8; SECRET_KEY_SIZE]) -> Self {
        Self(SigningKey::from_bytes(&bytes))
    }

    /// Returns the secret key as a byte array.
    ///
    /// # Returns
    ///
    /// A 32-byte array containing the secret key
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_SIZE] {
        self.0.to_bytes()
    }

    /// Returns the corresponding public key.
    ///
    /// # Returns
    ///
    /// The Ed25519 public key corresponding to this secret key
    pub fn verifying_key(&self) -> Ed25519PublicKey {
        let verifying_key = self.0.verifying_key();
        Ed25519PublicKey::from_bytes(verifying_key.to_bytes())
            .expect("verifying key should always be valid")
    }

    /// Returns a reference to the inner SigningKey.
    fn inner(&self) -> &SigningKey {
        &self.0
    }
}

impl Zeroize for Ed25519SecretKey {
    fn zeroize(&mut self) {
        // SigningKey handles zeroization
    }
}

/// An Ed25519 public key for signature verification.
///
/// Public keys can be freely copied and shared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ed25519PublicKey([u8; PUBLIC_KEY_SIZE]);

impl Ed25519PublicKey {
    /// Creates a new public key from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A 32-byte array containing the public key
    ///
    /// # Returns
    ///
    /// A new `Ed25519PublicKey` instance
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidKeyLength` if the key is invalid
    pub fn from_bytes(bytes: [u8; PUBLIC_KEY_SIZE]) -> Result<Self> {
        // Validate the public key by attempting to parse it
        VerifyingKey::from_bytes(&bytes).map_err(|_| CryptoError::InvalidKeyLength {
            expected: PUBLIC_KEY_SIZE,
            actual: PUBLIC_KEY_SIZE,
        })?;
        Ok(Self(bytes))
    }

    /// Returns the public key as a byte array.
    ///
    /// # Returns
    ///
    /// A reference to the 32-byte public key array
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_SIZE] {
        &self.0
    }

    /// Converts to the underlying dalek VerifyingKey type.
    fn to_dalek(self) -> VerifyingKey {
        // This should never fail since we validated in from_bytes
        VerifyingKey::from_bytes(&self.0).expect("validated public key")
    }
}

impl From<[u8; PUBLIC_KEY_SIZE]> for Ed25519PublicKey {
    fn from(bytes: [u8; PUBLIC_KEY_SIZE]) -> Self {
        Self::from_bytes(bytes).expect("invalid public key")
    }
}

impl AsRef<[u8]> for Ed25519PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl serde::Serialize for Ed25519PublicKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for Ed25519PublicKey {
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

/// An Ed25519 signature.
///
/// Signatures are 64 bytes and can be freely copied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature([u8; SIGNATURE_SIZE]);

impl Signature {
    /// Creates a new signature from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A 64-byte array containing the signature
    ///
    /// # Returns
    ///
    /// A new `Signature` instance
    pub fn from_bytes(bytes: [u8; SIGNATURE_SIZE]) -> Self {
        Self(bytes)
    }

    /// Returns the signature as a byte array.
    ///
    /// # Returns
    ///
    /// A reference to the 64-byte signature array
    pub fn as_bytes(&self) -> &[u8; SIGNATURE_SIZE] {
        &self.0
    }

    /// Converts to the underlying dalek Signature type.
    fn to_dalek(self) -> DalekSignature {
        DalekSignature::from_bytes(&self.0)
    }
}

impl From<[u8; SIGNATURE_SIZE]> for Signature {
    fn from(bytes: [u8; SIGNATURE_SIZE]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl serde::Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = <Vec<u8>>::deserialize(deserializer)?;
        if bytes.len() != SIGNATURE_SIZE {
            return Err(serde::de::Error::custom(format!(
                "Invalid signature length: expected {}, got {}",
                SIGNATURE_SIZE,
                bytes.len()
            )));
        }
        let mut array = [0u8; SIGNATURE_SIZE];
        array.copy_from_slice(&bytes);
        Ok(Self(array))
    }
}

/// Generates a new Ed25519 keypair.
///
/// # Returns
///
/// A tuple containing the secret key and corresponding public key
///
/// # Errors
///
/// Returns `CryptoError::RandomnessFailure` if the OS RNG is unavailable
pub fn generate_ed25519_keypair() -> Result<(Ed25519SecretKey, Ed25519PublicKey)> {
    let signing_key = SigningKey::generate(&mut rand_core::OsRng);
    let verifying_key = signing_key.verifying_key();

    Ok((
        Ed25519SecretKey(signing_key),
        Ed25519PublicKey::from_bytes(verifying_key.to_bytes())?,
    ))
}

/// Signs a message using Ed25519.
///
/// Ed25519 signatures are deterministic - the same message and key
/// will always produce the same signature.
///
/// # Arguments
///
/// * `key` - The secret key to use for signing
/// * `message` - The message to sign
///
/// # Returns
///
/// A 64-byte signature
pub fn sign(key: &Ed25519SecretKey, message: &[u8]) -> Signature {
    let signature = key.inner().sign(message);
    Signature(signature.to_bytes())
}

/// Verifies an Ed25519 signature.
///
/// # Arguments
///
/// * `key` - The public key to use for verification
/// * `message` - The message that was signed
/// * `signature` - The signature to verify
///
/// # Returns
///
/// `Ok(())` if the signature is valid, `Err(CryptoError::InvalidSignature)` otherwise
pub fn verify(key: &Ed25519PublicKey, message: &[u8], signature: &Signature) -> Result<()> {
    key.to_dalek()
        .verify(message, &signature.to_dalek())
        .map_err(|_| CryptoError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let result = generate_ed25519_keypair();
        assert!(result.is_ok());
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let (secret, public) = generate_ed25519_keypair().unwrap();
        let message = b"Hello, World!";

        let signature = sign(&secret, message);
        let result = verify(&public, message, &signature);

        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_wrong_message() {
        let (secret, public) = generate_ed25519_keypair().unwrap();
        let message1 = b"Hello, World!";
        let message2 = b"Goodbye, World!";

        let signature = sign(&secret, message1);
        let result = verify(&public, message2, &signature);

        assert!(matches!(result, Err(CryptoError::InvalidSignature)));
    }

    #[test]
    fn test_verify_wrong_key() {
        let (secret1, _) = generate_ed25519_keypair().unwrap();
        let (_, public2) = generate_ed25519_keypair().unwrap();
        let message = b"Hello, World!";

        let signature = sign(&secret1, message);
        let result = verify(&public2, message, &signature);

        assert!(matches!(result, Err(CryptoError::InvalidSignature)));
    }

    #[test]
    fn test_verify_tampered_signature() {
        let (secret, public) = generate_ed25519_keypair().unwrap();
        let message = b"Hello, World!";

        let mut signature = sign(&secret, message);
        // Tamper with the signature
        signature.0[0] ^= 0xFF;

        let result = verify(&public, message, &signature);
        assert!(matches!(result, Err(CryptoError::InvalidSignature)));
    }

    #[test]
    fn test_signature_determinism() {
        let (secret, _) = generate_ed25519_keypair().unwrap();
        let message = b"test message";

        let sig1 = sign(&secret, message);
        let sig2 = sign(&secret, message);

        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_public_key_roundtrip() {
        let (_, public) = generate_ed25519_keypair().unwrap();
        let bytes = *public.as_bytes();
        let restored = Ed25519PublicKey::from_bytes(bytes).unwrap();

        assert_eq!(public, restored);
    }

    #[test]
    fn test_secret_key_roundtrip() {
        let (secret, _) = generate_ed25519_keypair().unwrap();
        let bytes = secret.to_bytes();
        let restored = Ed25519SecretKey::from_bytes(bytes);

        // Verify they produce the same signature
        let message = b"test";
        let sig1 = sign(&secret, message);
        let sig2 = sign(&restored, message);

        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_signature_roundtrip() {
        let (secret, public) = generate_ed25519_keypair().unwrap();
        let message = b"test";

        let signature = sign(&secret, message);
        let bytes = *signature.as_bytes();
        let restored = Signature::from_bytes(bytes);

        assert_eq!(signature, restored);
        assert!(verify(&public, message, &restored).is_ok());
    }
}
