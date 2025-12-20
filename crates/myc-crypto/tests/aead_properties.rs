//! Property-based tests for AEAD encryption.

use myc_crypto::aead::{decrypt, encrypt, AeadKey, NONCE_SIZE, TAG_SIZE};
use proptest::prelude::*;

/// Feature: mycelium-cli, Property 1: Encryption Roundtrip
///
/// For any plaintext data and AEAD key, encrypting then decrypting
/// SHALL recover the original plaintext.
///
/// Validates: Requirements 3.1, 3.3
#[test]
fn property_encryption_roundtrip() {
    proptest!(|(
        key_bytes in prop::array::uniform32(any::<u8>()),
        plaintext in prop::collection::vec(any::<u8>(), 0..1000),
        aad in prop::collection::vec(any::<u8>(), 0..100)
    )| {
        let key = AeadKey::from_bytes(key_bytes);

        // Encrypt the plaintext
        let ciphertext = encrypt(&key, &plaintext, &aad)
            .expect("encryption should succeed");

        // Decrypt the ciphertext
        let decrypted = decrypt(&key, &ciphertext, &aad)
            .expect("decryption should succeed");

        // Verify roundtrip
        prop_assert_eq!(plaintext, decrypted);
    });
}

/// Feature: mycelium-cli, Property 2: Encryption Produces Correct Structure
///
/// For any plaintext data, encrypted output SHALL have structure:
/// 12-byte nonce || ciphertext || 16-byte tag.
///
/// Validates: Requirements 3.1
#[test]
fn property_encryption_structure() {
    proptest!(|(
        key_bytes in prop::array::uniform32(any::<u8>()),
        plaintext in prop::collection::vec(any::<u8>(), 0..1000),
        aad in prop::collection::vec(any::<u8>(), 0..100)
    )| {
        let key = AeadKey::from_bytes(key_bytes);

        // Encrypt the plaintext
        let ciphertext = encrypt(&key, &plaintext, &aad)
            .expect("encryption should succeed");

        // Verify structure: nonce (12) + plaintext length + tag (16)
        let expected_len = NONCE_SIZE + plaintext.len() + TAG_SIZE;
        prop_assert_eq!(ciphertext.len(), expected_len,
            "ciphertext should be nonce ({}) + plaintext ({}) + tag ({})",
            NONCE_SIZE, plaintext.len(), TAG_SIZE);
    });
}
