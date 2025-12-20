//! Property-based tests for HKDF key derivation.

use myc_crypto::kdf::derive_key;
use proptest::prelude::*;

/// Feature: mycelium-cli, Property 5: KDF Determinism
///
/// For any input key material, salt, and info, HKDF SHALL produce
/// the same output on repeated calls.
///
/// Validates: Requirements 3.2, 3.7
#[test]
fn property_kdf_determinism() {
    proptest!(|(
        ikm in prop::collection::vec(any::<u8>(), 1..100),
        salt in prop::collection::vec(any::<u8>(), 0..64),
        info in prop::collection::vec(any::<u8>(), 0..64),
        output_len in 1usize..128
    )| {
        // Derive key twice with same inputs
        let key1 = derive_key(&ikm, &salt, &info, output_len);
        let key2 = derive_key(&ikm, &salt, &info, output_len);

        // Should produce identical output
        prop_assert_eq!(key1.len(), output_len);
        prop_assert_eq!(key1, key2);
    });
}

/// Feature: mycelium-cli, Property 6: KDF Domain Separation
///
/// For any shared secret, different info parameters SHALL produce
/// different derived keys.
///
/// Validates: Requirements 3.7
#[test]
fn property_kdf_domain_separation() {
    proptest!(|(
        ikm in prop::collection::vec(any::<u8>(), 1..100),
        salt in prop::collection::vec(any::<u8>(), 0..64),
        (info1, info2) in (
            prop::collection::vec(any::<u8>(), 1..64),
            prop::collection::vec(any::<u8>(), 1..64)
        ).prop_filter("different infos", |(i1, i2)| i1 != i2),
        output_len in 1usize..128
    )| {
        // Derive keys with different info parameters
        let key1 = derive_key(&ikm, &salt, &info1, output_len);
        let key2 = derive_key(&ikm, &salt, &info2, output_len);

        // Should produce different outputs
        prop_assert_ne!(key1, key2, "different info should produce different keys");
    });
}

/// Additional property: Salt affects output
///
/// For any input, different salts SHALL produce different keys.
#[test]
fn property_salt_separation() {
    proptest!(|(
        ikm in prop::collection::vec(any::<u8>(), 1..100),
        (salt1, salt2) in (
            prop::collection::vec(any::<u8>(), 1..64),
            prop::collection::vec(any::<u8>(), 1..64)
        ).prop_filter("different salts", |(s1, s2)| s1 != s2),
        info in prop::collection::vec(any::<u8>(), 0..64),
        output_len in 1usize..128
    )| {
        // Derive keys with different salts
        let key1 = derive_key(&ikm, &salt1, &info, output_len);
        let key2 = derive_key(&ikm, &salt2, &info, output_len);

        // Should produce different outputs
        prop_assert_ne!(key1, key2, "different salt should produce different keys");
    });
}

/// Additional property: IKM affects output
///
/// For any parameters, different input key material SHALL produce
/// different keys.
#[test]
fn property_ikm_affects_output() {
    proptest!(|(
        (ikm1, ikm2) in (
            prop::collection::vec(any::<u8>(), 1..100),
            prop::collection::vec(any::<u8>(), 1..100)
        ).prop_filter("different ikms", |(i1, i2)| i1 != i2),
        salt in prop::collection::vec(any::<u8>(), 0..64),
        info in prop::collection::vec(any::<u8>(), 0..64),
        output_len in 1usize..128
    )| {
        // Derive keys with different IKM
        let key1 = derive_key(&ikm1, &salt, &info, output_len);
        let key2 = derive_key(&ikm2, &salt, &info, output_len);

        // Should produce different outputs
        prop_assert_ne!(key1, key2, "different IKM should produce different keys");
    });
}
