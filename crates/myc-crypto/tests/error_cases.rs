//! Unit tests for cryptographic error cases.
//!
//! These tests verify that the crypto primitives properly handle
//! error conditions and return appropriate error types.

use myc_crypto::aead::{decrypt, encrypt, AeadKey, KEY_SIZE, NONCE_SIZE, TAG_SIZE};
use myc_crypto::error::CryptoError;
use myc_crypto::sign::{generate_ed25519_keypair, sign, verify, Ed25519PublicKey, Signature};

/// Test decryption with wrong key
///
/// Validates: Requirements 3.1, 3.3
#[test]
fn test_aead_decryption_wrong_key() {
    let key1 = AeadKey::from_bytes([1u8; KEY_SIZE]);
    let key2 = AeadKey::from_bytes([2u8; KEY_SIZE]);
    let plaintext = b"secret message";
    let aad = b"";

    let ciphertext = encrypt(&key1, plaintext, aad).unwrap();
    let result = decrypt(&key2, &ciphertext, aad);

    assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
}

/// Test decryption with wrong AAD
///
/// Validates: Requirements 3.1
#[test]
fn test_aead_decryption_wrong_aad() {
    let key = AeadKey::from_bytes([42u8; KEY_SIZE]);
    let plaintext = b"secret message";
    let aad1 = b"correct aad";
    let aad2 = b"wrong aad";

    let ciphertext = encrypt(&key, plaintext, aad1).unwrap();
    let result = decrypt(&key, &ciphertext, aad2);

    assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
}

/// Test decryption with tampered ciphertext
///
/// Validates: Requirements 3.1
#[test]
fn test_aead_decryption_tampered_ciphertext() {
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

/// Test decryption with tampered tag
///
/// Validates: Requirements 3.1
#[test]
fn test_aead_decryption_tampered_tag() {
    let key = AeadKey::from_bytes([42u8; KEY_SIZE]);
    let plaintext = b"secret message";
    let aad = b"";

    let mut ciphertext = encrypt(&key, plaintext, aad).unwrap();
    // Tamper with the tag (last 16 bytes)
    let len = ciphertext.len();
    if len > TAG_SIZE {
        ciphertext[len - 1] ^= 0xFF;
    }

    let result = decrypt(&key, &ciphertext, aad);
    assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
}

/// Test decryption with too-short input
///
/// Validates: Requirements 3.1
#[test]
fn test_aead_decryption_too_short() {
    let key = AeadKey::from_bytes([42u8; KEY_SIZE]);
    let short_input = vec![0u8; NONCE_SIZE - 1];

    let result = decrypt(&key, &short_input, b"");
    assert!(matches!(result, Err(CryptoError::InvalidNonceSize { .. })));
}

/// Test signature verification with wrong message
///
/// Validates: Requirements 3.3
#[test]
fn test_signature_verification_wrong_message() {
    let (secret, public) = generate_ed25519_keypair().unwrap();
    let message1 = b"Hello, World!";
    let message2 = b"Goodbye, World!";

    let signature = sign(&secret, message1);
    let result = verify(&public, message2, &signature);

    assert!(matches!(result, Err(CryptoError::InvalidSignature)));
}

/// Test signature verification with wrong key
///
/// Validates: Requirements 3.3
#[test]
fn test_signature_verification_wrong_key() {
    let (secret1, _) = generate_ed25519_keypair().unwrap();
    let (_, public2) = generate_ed25519_keypair().unwrap();
    let message = b"Hello, World!";

    let signature = sign(&secret1, message);
    let result = verify(&public2, message, &signature);

    assert!(matches!(result, Err(CryptoError::InvalidSignature)));
}

/// Test signature verification with tampered signature
///
/// Validates: Requirements 3.3
#[test]
fn test_signature_verification_tampered_signature() {
    let (secret, public) = generate_ed25519_keypair().unwrap();
    let message = b"Hello, World!";

    let signature = sign(&secret, message);
    // Tamper with the signature
    let mut sig_bytes = *signature.as_bytes();
    sig_bytes[0] ^= 0xFF;
    let tampered_signature = Signature::from_bytes(sig_bytes);

    let result = verify(&public, message, &tampered_signature);
    assert!(matches!(result, Err(CryptoError::InvalidSignature)));
}

/// Test invalid public key
///
/// Validates: Requirements 3.3
#[test]
fn test_invalid_public_key() {
    // Note: Ed25519 public key validation is limited - most 32-byte values are technically valid
    // This test verifies the API exists and handles validation attempts
    // In practice, invalid keys will fail during signature verification
    let key_bytes = [0u8; 32];
    let result = Ed25519PublicKey::from_bytes(key_bytes);

    // The key might be accepted (Ed25519 has limited validation)
    // but using it for verification should fail with invalid signatures
    if let Ok(public_key) = result {
        let (secret, _) = generate_ed25519_keypair().unwrap();
        let message = b"test";
        let signature = sign(&secret, message);

        // Verification with the zero key should fail
        let verify_result = verify(&public_key, message, &signature);
        assert!(matches!(verify_result, Err(CryptoError::InvalidSignature)));
    }
}

/// Test multiple error conditions in sequence
///
/// Validates: Requirements 3.1, 3.3
#[test]
fn test_multiple_error_conditions() {
    // Test that errors don't affect subsequent operations
    let key = AeadKey::from_bytes([42u8; KEY_SIZE]);
    let plaintext = b"test";

    // First operation fails
    let result1 = decrypt(&key, &[0u8; 5], b"");
    assert!(result1.is_err());

    // Second operation should still work
    let ciphertext = encrypt(&key, plaintext, b"").unwrap();
    let result2 = decrypt(&key, &ciphertext, b"");
    assert!(result2.is_ok());
    assert_eq!(result2.unwrap(), plaintext);
}

/// Test error display messages
///
/// Validates: Requirements 3.1, 3.2, 3.3
#[test]
fn test_error_display() {
    let err1 = CryptoError::DecryptionFailed;
    let err2 = CryptoError::InvalidSignature;
    let err3 = CryptoError::InvalidKeyLength {
        expected: 32,
        actual: 16,
    };
    let err4 = CryptoError::RandomnessFailure("test error".to_string());

    // Verify error messages are meaningful
    assert!(err1.to_string().contains("decryption"));
    assert!(err2.to_string().contains("signature"));
    assert!(err3.to_string().contains("32"));
    assert!(err3.to_string().contains("16"));
    assert!(err4.to_string().contains("test error"));
}
