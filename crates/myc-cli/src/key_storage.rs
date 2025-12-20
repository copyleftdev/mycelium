//! Device key encryption and storage.
//!
//! This module handles encrypting device keys at rest using Argon2id key derivation
//! from user passphrases. Keys are stored in an encrypted format with a magic header,
//! version, salt, nonce, and ciphertext.

use anyhow::{Context, Result};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2, ParamsBuilder, Version,
};
use base64::Engine;
use myc_crypto::{
    aead::{self, AeadKey},
    kex::{X25519PublicKey, X25519SecretKey},
    sign::Ed25519SecretKey,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use zeroize::Zeroizing;

/// Magic bytes for encrypted key files: "MYC\0"
const MAGIC: &[u8; 4] = b"MYC\0";

/// Current version of the encrypted key file format
const VERSION: u8 = 1;

/// Argon2id parameters for key derivation
const ARGON2_MEM_COST: u32 = 65536; // 64 MiB
const ARGON2_TIME_COST: u32 = 3; // 3 iterations
const ARGON2_PARALLELISM: u32 = 4; // 4 threads

/// Encrypted key file structure
#[derive(Debug, Serialize, Deserialize)]
struct EncryptedKeyFile {
    /// Magic bytes to identify file type
    magic: [u8; 4],
    /// File format version
    version: u8,
    /// Salt for Argon2id (base64 encoded)
    salt: String,
    /// Encrypted key material (nonce + ciphertext + tag, base64 encoded)
    ciphertext: String,
}

/// Derives an AEAD key from a passphrase using Argon2id
fn derive_key_from_passphrase(passphrase: &str, salt: &SaltString) -> Result<AeadKey> {
    let params = ParamsBuilder::new()
        .m_cost(ARGON2_MEM_COST)
        .t_cost(ARGON2_TIME_COST)
        .p_cost(ARGON2_PARALLELISM)
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to build Argon2 parameters: {}", e))?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

    // Hash the passphrase with the salt
    let password_hash = argon2
        .hash_password(passphrase.as_bytes(), salt)
        .map_err(|e| anyhow::anyhow!("Failed to hash passphrase: {}", e))?;

    // Extract the 32-byte hash output
    let hash_bytes = password_hash
        .hash
        .ok_or_else(|| anyhow::anyhow!("Password hash missing hash output"))?;

    // Convert to AeadKey (32 bytes)
    let key_bytes: [u8; 32] = hash_bytes.as_bytes()[..32]
        .try_into()
        .context("Hash output is not 32 bytes")?;

    Ok(AeadKey::from_bytes(key_bytes))
}

/// Saves an encrypted key to disk
///
/// # Arguments
///
/// * `path` - Path to save the encrypted key file
/// * `key_material` - The key bytes to encrypt
/// * `passphrase` - Passphrase to derive encryption key from
///
/// # Security
///
/// - Uses Argon2id for key derivation with high cost parameters
/// - Generates random salt per file
/// - Uses ChaCha20-Poly1305 AEAD for encryption
/// - Key material is zeroized after encryption
pub fn save_encrypted_key(path: &Path, key_material: &[u8], passphrase: &str) -> Result<()> {
    // Generate random salt
    let salt = SaltString::generate(&mut rand_core::OsRng);

    // Derive encryption key from passphrase
    let encryption_key = derive_key_from_passphrase(passphrase, &salt)?;

    // Encrypt the key material (no AAD needed for key files)
    let ciphertext = aead::encrypt(&encryption_key, key_material, &[])
        .context("Failed to encrypt key material")?;

    // Create encrypted key file structure
    let encrypted_file = EncryptedKeyFile {
        magic: *MAGIC,
        version: VERSION,
        salt: salt.to_string(),
        ciphertext: base64::engine::general_purpose::STANDARD.encode(&ciphertext),
    };

    // Serialize to JSON
    let json = serde_json::to_string_pretty(&encrypted_file)
        .context("Failed to serialize encrypted key file")?;

    // Write to disk
    fs::write(path, json).context("Failed to write encrypted key file")?;

    Ok(())
}

/// Loads and decrypts a key from disk
///
/// # Arguments
///
/// * `path` - Path to the encrypted key file
/// * `passphrase` - Passphrase to derive decryption key from
///
/// # Returns
///
/// The decrypted key material as a zeroizing vector
///
/// # Errors
///
/// Returns an error if:
/// - File cannot be read
/// - File format is invalid
/// - Passphrase is incorrect
/// - Decryption fails
pub fn load_encrypted_key(path: &Path, passphrase: &str) -> Result<Zeroizing<Vec<u8>>> {
    // Read file
    let json = fs::read_to_string(path).context("Failed to read encrypted key file")?;

    // Parse JSON
    let encrypted_file: EncryptedKeyFile =
        serde_json::from_str(&json).context("Failed to parse encrypted key file")?;

    // Verify magic bytes
    if encrypted_file.magic != *MAGIC {
        anyhow::bail!("Invalid key file: magic bytes mismatch");
    }

    // Verify version
    if encrypted_file.version != VERSION {
        anyhow::bail!(
            "Unsupported key file version: {} (expected {})",
            encrypted_file.version,
            VERSION
        );
    }

    // Parse salt
    let salt = SaltString::from_b64(&encrypted_file.salt)
        .map_err(|e| anyhow::anyhow!("Failed to parse salt from key file: {}", e))?;

    // Derive decryption key from passphrase
    let decryption_key = derive_key_from_passphrase(passphrase, &salt)?;

    // Decode ciphertext
    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(&encrypted_file.ciphertext)
        .context("Failed to decode ciphertext from key file")?;

    // Decrypt the key material
    let plaintext = aead::decrypt(&decryption_key, &ciphertext, &[])
        .context("Failed to decrypt key material (wrong passphrase?)")?;

    Ok(Zeroizing::new(plaintext))
}

/// Saves an Ed25519 signing keypair to encrypted files
pub fn save_signing_keypair(
    secret_path: &Path,
    public_path: &Path,
    secret_key: &Ed25519SecretKey,
    public_key: &myc_crypto::sign::Ed25519PublicKey,
    passphrase: &str,
) -> Result<()> {
    // Save encrypted secret key
    save_encrypted_key(secret_path, &secret_key.to_bytes(), passphrase)?;

    // Save public key (unencrypted)
    fs::write(public_path, public_key.as_bytes()).context("Failed to write public signing key")?;

    Ok(())
}

/// Loads an Ed25519 signing secret key from an encrypted file
pub fn load_signing_key(path: &Path, passphrase: &str) -> Result<Ed25519SecretKey> {
    let key_bytes = load_encrypted_key(path, passphrase)?;

    if key_bytes.len() != 32 {
        anyhow::bail!(
            "Invalid signing key length: expected 32 bytes, got {}",
            key_bytes.len()
        );
    }

    let key_array: [u8; 32] = key_bytes[..32]
        .try_into()
        .context("Failed to convert key bytes to array")?;

    Ok(Ed25519SecretKey::from_bytes(key_array))
}

/// Saves an X25519 encryption keypair to encrypted files
pub fn save_encryption_keypair(
    secret_path: &Path,
    public_path: &Path,
    secret_key: &X25519SecretKey,
    public_key: &X25519PublicKey,
    passphrase: &str,
) -> Result<()> {
    // Save encrypted secret key
    save_encrypted_key(secret_path, &secret_key.to_bytes(), passphrase)?;

    // Save public key (unencrypted)
    fs::write(public_path, public_key.as_bytes())
        .context("Failed to write public encryption key")?;

    Ok(())
}

/// Loads an X25519 encryption secret key from an encrypted file
pub fn load_encryption_key(path: &Path, passphrase: &str) -> Result<X25519SecretKey> {
    let key_bytes = load_encrypted_key(path, passphrase)?;

    if key_bytes.len() != 32 {
        anyhow::bail!(
            "Invalid encryption key length: expected 32 bytes, got {}",
            key_bytes.len()
        );
    }

    let key_array: [u8; 32] = key_bytes[..32]
        .try_into()
        .context("Failed to convert key bytes to array")?;

    Ok(X25519SecretKey::from_bytes(key_array))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_key_encryption_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("test.key");

        let original_key = myc_crypto::random::generate_random_bytes::<32>().unwrap();
        let passphrase = "test-passphrase-123";

        // Save encrypted key
        save_encrypted_key(&key_path, &original_key, passphrase).unwrap();

        // Load and decrypt key
        let decrypted_key = load_encrypted_key(&key_path, passphrase).unwrap();

        // Verify roundtrip
        assert_eq!(&original_key[..], &decrypted_key[..]);
    }

    #[test]
    fn test_wrong_passphrase_fails() {
        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("test.key");

        let original_key = myc_crypto::random::generate_random_bytes::<32>().unwrap();
        let passphrase = "correct-passphrase";
        let wrong_passphrase = "wrong-passphrase";

        // Save encrypted key
        save_encrypted_key(&key_path, &original_key, passphrase).unwrap();

        // Try to load with wrong passphrase
        let result = load_encrypted_key(&key_path, wrong_passphrase);

        // Should fail
        assert!(result.is_err());
    }

    #[test]
    fn test_signing_keypair_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let secret_path = temp_dir.path().join("signing.key");
        let public_path = temp_dir.path().join("signing.pub");

        let (secret_key, public_key) = myc_crypto::sign::generate_ed25519_keypair().unwrap();
        let passphrase = "test-passphrase";

        // Save keypair
        save_signing_keypair(
            &secret_path,
            &public_path,
            &secret_key,
            &public_key,
            passphrase,
        )
        .unwrap();

        // Load secret key
        let loaded_key = load_signing_key(&secret_path, passphrase).unwrap();

        // Verify they're the same by signing a message and comparing signatures
        let message = b"test message";
        let sig1 = myc_crypto::sign::sign(&secret_key, message);
        let sig2 = myc_crypto::sign::sign(&loaded_key, message);
        assert_eq!(sig1.as_bytes(), sig2.as_bytes());
    }

    #[test]
    fn test_encryption_keypair_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let secret_path = temp_dir.path().join("encryption.key");
        let public_path = temp_dir.path().join("encryption.pub");

        let (secret_key, public_key) = myc_crypto::kex::generate_x25519_keypair().unwrap();
        let passphrase = "test-passphrase";

        // Save keypair
        save_encryption_keypair(
            &secret_path,
            &public_path,
            &secret_key,
            &public_key,
            passphrase,
        )
        .unwrap();

        // Load secret key
        let loaded_key = load_encryption_key(&secret_path, passphrase).unwrap();

        // Verify they're the same by performing DH with a third key
        let (_, test_public) = myc_crypto::kex::generate_x25519_keypair().unwrap();
        let shared1 = myc_crypto::kex::diffie_hellman(&secret_key, &test_public);
        let shared2 = myc_crypto::kex::diffie_hellman(&loaded_key, &test_public);
        assert_eq!(shared1.as_bytes(), shared2.as_bytes());
    }
}
