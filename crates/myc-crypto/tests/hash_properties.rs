//! Property-based tests for BLAKE3 hashing.

use myc_crypto::hash::{chain_hash, hash};
use proptest::prelude::*;

/// Feature: mycelium-cli, Property 7: Hash Determinism
///
/// For any input data, BLAKE3 SHALL produce the same hash on
/// repeated calls.
///
/// Validates: Requirements 3.4
#[test]
fn property_hash_determinism() {
    proptest!(|(
        data in prop::collection::vec(any::<u8>(), 0..1000)
    )| {
        // Hash the data twice
        let hash1 = hash(&data);
        let hash2 = hash(&data);

        // Should produce identical output
        prop_assert_eq!(hash1, hash2);
    });
}

/// Feature: mycelium-cli, Property 8: Hash Chain Integrity
///
/// For any sequence of versions, the hash chain SHALL link correctly:
/// chain_hash(n) = BLAKE3(chain_hash(n-1) || content_hash(n)).
///
/// Validates: Requirements 3.4, 8.2
#[test]
fn property_hash_chain_integrity() {
    proptest!(|(
        data1 in prop::collection::vec(any::<u8>(), 0..1000),
        data2 in prop::collection::vec(any::<u8>(), 0..1000),
        data3 in prop::collection::vec(any::<u8>(), 0..1000)
    )| {
        // Build a chain of 3 versions
        let h1 = hash(&data1);
        let h2 = chain_hash(&h1, &data2);
        let h3 = chain_hash(&h2, &data3);

        // Recompute the chain
        let h1_recompute = hash(&data1);
        let h2_recompute = chain_hash(&h1_recompute, &data2);
        let h3_recompute = chain_hash(&h2_recompute, &data3);

        // Chain should be deterministic
        prop_assert_eq!(h1, h1_recompute);
        prop_assert_eq!(h2, h2_recompute);
        prop_assert_eq!(h3, h3_recompute);

        // Each hash in chain should be different (unless data is identical)
        if data1 != data2 {
            prop_assert_ne!(h1, h2);
        }
        if data2 != data3 {
            prop_assert_ne!(h2, h3);
        }
    });
}

/// Additional property: Different data produces different hashes
///
/// For any two different inputs, the hashes SHALL be different
/// (collision resistance).
#[test]
fn property_collision_resistance() {
    proptest!(|(
        (data1, data2) in (
            prop::collection::vec(any::<u8>(), 1..1000),
            prop::collection::vec(any::<u8>(), 1..1000)
        ).prop_filter("different data", |(d1, d2)| d1 != d2)
    )| {
        let hash1 = hash(&data1);
        let hash2 = hash(&data2);

        // Different inputs should produce different hashes
        prop_assert_ne!(hash1, hash2);
    });
}

/// Additional property: Chain order matters
///
/// For any sequence, changing the order SHALL produce different
/// chain hashes.
#[test]
fn property_chain_order_matters() {
    proptest!(|(
        (data1, data2) in (
            prop::collection::vec(any::<u8>(), 1..1000),
            prop::collection::vec(any::<u8>(), 1..1000)
        ).prop_filter("different data", |(d1, d2)| d1 != d2)
    )| {
        // Chain in one order
        let h1 = hash(&data1);
        let chain_12 = chain_hash(&h1, &data2);

        // Chain in reverse order
        let h2 = hash(&data2);
        let chain_21 = chain_hash(&h2, &data1);

        // Different order should produce different chain hashes
        prop_assert_ne!(chain_12, chain_21);
    });
}

/// Additional property: Chain tampering detection
///
/// For any chain, modifying any element SHALL break the chain.
#[test]
fn property_chain_tampering_detection() {
    proptest!(|(
        data1 in prop::collection::vec(any::<u8>(), 1..1000),
        data2 in prop::collection::vec(any::<u8>(), 1..1000),
        tamper_index in any::<prop::sample::Index>(),
        tamper_value in any::<u8>().prop_filter("non-zero", |&v| v != 0)
    )| {
        // Build original chain
        let h1 = hash(&data1);
        let h2_original = chain_hash(&h1, &data2);

        // Tamper with data2
        let mut data2_tampered = data2.clone();
        let idx = tamper_index.index(data2_tampered.len());
        data2_tampered[idx] ^= tamper_value;

        // Recompute chain with tampered data
        let h2_tampered = chain_hash(&h1, &data2_tampered);

        // Tampered chain should be different
        prop_assert_ne!(h2_original, h2_tampered);
    });
}
