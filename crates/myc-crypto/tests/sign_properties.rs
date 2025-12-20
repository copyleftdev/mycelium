//! Property-based tests for Ed25519 signatures.

use myc_crypto::sign::{generate_ed25519_keypair, sign, verify, Ed25519SecretKey};
use proptest::prelude::*;

/// Feature: mycelium-cli, Property 3: Signature Roundtrip
///
/// For any message and Ed25519 keypair, signing then verifying
/// SHALL succeed.
///
/// Validates: Requirements 3.3
#[test]
fn property_signature_roundtrip() {
    proptest!(|(
        message in prop::collection::vec(any::<u8>(), 0..1000)
    )| {
        let (secret, public) = generate_ed25519_keypair()
            .expect("keypair generation should succeed");

        // Sign the message
        let signature = sign(&secret, &message);

        // Verify the signature
        let result = verify(&public, &message, &signature);

        prop_assert!(result.is_ok(), "signature verification should succeed");
    });
}

/// Feature: mycelium-cli, Property 4: Tampering Detection
///
/// For any signed message, modifying the message or signature
/// SHALL cause verification to fail.
///
/// Validates: Requirements 3.3
#[test]
fn property_tampering_detection() {
    proptest!(|(
        message in prop::collection::vec(any::<u8>(), 1..1000),
        tamper_byte_index in 0usize..64,
        tamper_value in any::<u8>().prop_filter("non-zero", |&v| v != 0)
    )| {
        let (secret, public) = generate_ed25519_keypair()
            .expect("keypair generation should succeed");

        // Sign the message
        let signature = sign(&secret, &message);

        // Tamper with the signature
        let mut tampered_sig_bytes = *signature.as_bytes();
        tampered_sig_bytes[tamper_byte_index] ^= tamper_value;
        let tampered_signature = myc_crypto::sign::Signature::from_bytes(tampered_sig_bytes);

        // Verify should fail with tampered signature
        let result = verify(&public, &message, &tampered_signature);
        prop_assert!(result.is_err(), "tampered signature should fail verification");
    });
}

/// Additional property: Message tampering detection
///
/// For any signed message, modifying the message SHALL cause
/// verification to fail.
#[test]
fn property_message_tampering_detection() {
    proptest!(|(
        message in prop::collection::vec(any::<u8>(), 1..1000),
        tamper_index in any::<prop::sample::Index>(),
        tamper_value in any::<u8>().prop_filter("non-zero", |&v| v != 0)
    )| {
        let (secret, public) = generate_ed25519_keypair()
            .expect("keypair generation should succeed");

        // Sign the message
        let signature = sign(&secret, &message);

        // Tamper with the message
        let mut tampered_message = message.clone();
        let idx = tamper_index.index(tampered_message.len());
        tampered_message[idx] ^= tamper_value;

        // Verify should fail with tampered message
        let result = verify(&public, &tampered_message, &signature);
        prop_assert!(result.is_err(), "tampered message should fail verification");
    });
}

/// Additional property: Signature determinism
///
/// For any message and secret key, signing twice SHALL produce
/// the same signature.
#[test]
fn property_signature_determinism() {
    proptest!(|(
        key_bytes in prop::array::uniform32(any::<u8>()),
        message in prop::collection::vec(any::<u8>(), 0..1000)
    )| {
        let secret = Ed25519SecretKey::from_bytes(key_bytes);

        // Sign the message twice
        let sig1 = sign(&secret, &message);
        let sig2 = sign(&secret, &message);

        // Signatures should be identical
        prop_assert_eq!(sig1.as_bytes(), sig2.as_bytes());
    });
}
