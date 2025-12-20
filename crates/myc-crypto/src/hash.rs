//! BLAKE3 cryptographic hashing.
//!
//! This module provides BLAKE3 hashing for content hashing and hash chain
//! construction. BLAKE3 is fast, secure, and produces 256-bit (32-byte) hashes.

use blake3::Hasher as Blake3Hasher;

/// Size of a BLAKE3 hash output in bytes.
pub const HASH_OUTPUT_SIZE: usize = 32;

/// A BLAKE3 hash output.
///
/// Hash outputs are 32 bytes and can be freely copied and compared.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HashOutput([u8; HASH_OUTPUT_SIZE]);

impl HashOutput {
    /// Creates a new hash output from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A 32-byte array containing the hash
    ///
    /// # Returns
    ///
    /// A new `HashOutput` instance
    pub fn from_bytes(bytes: [u8; HASH_OUTPUT_SIZE]) -> Self {
        Self(bytes)
    }

    /// Returns the hash as a byte array.
    ///
    /// # Returns
    ///
    /// A reference to the 32-byte hash array
    pub fn as_bytes(&self) -> &[u8; HASH_OUTPUT_SIZE] {
        &self.0
    }
}

impl From<[u8; HASH_OUTPUT_SIZE]> for HashOutput {
    fn from(bytes: [u8; HASH_OUTPUT_SIZE]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl AsRef<[u8]> for HashOutput {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// A BLAKE3 hasher for streaming hashing.
///
/// This allows hashing data incrementally rather than all at once.
pub struct Hasher(Blake3Hasher);

impl Hasher {
    /// Creates a new hasher.
    ///
    /// # Returns
    ///
    /// A new `Hasher` instance
    pub fn new() -> Self {
        Self(Blake3Hasher::new())
    }

    /// Updates the hasher with more data.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to hash
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// Finalizes the hash and returns the output.
    ///
    /// # Returns
    ///
    /// The hash output
    pub fn finalize(&self) -> HashOutput {
        let hash = self.0.finalize();
        HashOutput(hash.into())
    }
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

/// Computes the BLAKE3 hash of data.
///
/// # Arguments
///
/// * `data` - The data to hash
///
/// # Returns
///
/// The hash output
///
/// # Examples
///
/// ```
/// use myc_crypto::hash::hash;
///
/// let data = b"Hello, World!";
/// let hash_output = hash(data);
/// assert_eq!(hash_output.as_bytes().len(), 32);
/// ```
pub fn hash(data: &[u8]) -> HashOutput {
    let hash = blake3::hash(data);
    HashOutput(hash.into())
}

/// Computes a chained hash for version linking.
///
/// This function computes: BLAKE3(previous_hash || current_data)
/// This creates a hash chain where each version's hash depends on
/// the previous version's hash, making tampering detectable.
///
/// # Arguments
///
/// * `previous_hash` - The hash of the previous version
/// * `current_data` - The data for the current version
///
/// # Returns
///
/// The chained hash output
///
/// # Examples
///
/// ```
/// use myc_crypto::hash::{hash, chain_hash};
///
/// let data1 = b"version 1";
/// let hash1 = hash(data1);
///
/// let data2 = b"version 2";
/// let hash2 = chain_hash(&hash1, data2);
///
/// // hash2 depends on both hash1 and data2
/// ```
pub fn chain_hash(previous_hash: &HashOutput, current_data: &[u8]) -> HashOutput {
    let mut hasher = Blake3Hasher::new();
    hasher.update(previous_hash.as_bytes());
    hasher.update(current_data);
    let hash = hasher.finalize();
    HashOutput(hash.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_basic() {
        let data = b"Hello, World!";
        let hash_output = hash(data);
        assert_eq!(hash_output.as_bytes().len(), HASH_OUTPUT_SIZE);
    }

    #[test]
    fn test_hash_determinism() {
        let data = b"test data";
        let hash1 = hash(data);
        let hash2 = hash(data);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_different_data() {
        let data1 = b"data1";
        let data2 = b"data2";
        let hash1 = hash(data1);
        let hash2 = hash(data2);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_empty() {
        let data = b"";
        let hash_output = hash(data);
        assert_eq!(hash_output.as_bytes().len(), HASH_OUTPUT_SIZE);
    }

    #[test]
    fn test_hasher_streaming() {
        let data = b"Hello, World!";

        // Hash all at once
        let hash_direct = hash(data);

        // Hash in chunks
        let mut hasher = Hasher::new();
        hasher.update(b"Hello, ");
        hasher.update(b"World!");
        let hash_streaming = hasher.finalize();

        assert_eq!(hash_direct, hash_streaming);
    }

    #[test]
    fn test_chain_hash_basic() {
        let data1 = b"version 1";
        let hash1 = hash(data1);

        let data2 = b"version 2";
        let hash2 = chain_hash(&hash1, data2);

        assert_eq!(hash2.as_bytes().len(), HASH_OUTPUT_SIZE);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_chain_hash_determinism() {
        let data1 = b"version 1";
        let hash1 = hash(data1);

        let data2 = b"version 2";
        let chain1 = chain_hash(&hash1, data2);
        let chain2 = chain_hash(&hash1, data2);

        assert_eq!(chain1, chain2);
    }

    #[test]
    fn test_chain_hash_order_matters() {
        let hash_a = hash(b"a");
        let hash_b = hash(b"b");

        let data = b"data";
        let chain_ab = chain_hash(&hash_a, data);
        let chain_ba = chain_hash(&hash_b, data);

        assert_ne!(chain_ab, chain_ba);
    }

    #[test]
    fn test_chain_hash_sequence() {
        // Build a chain of 3 versions
        let v1 = b"version 1";
        let h1 = hash(v1);

        let v2 = b"version 2";
        let h2 = chain_hash(&h1, v2);

        let v3 = b"version 3";
        let h3 = chain_hash(&h2, v3);

        // Each hash should be different
        assert_ne!(h1, h2);
        assert_ne!(h2, h3);
        assert_ne!(h1, h3);

        // Recomputing should give same results
        let h2_recompute = chain_hash(&h1, v2);
        let h3_recompute = chain_hash(&h2_recompute, v3);

        assert_eq!(h2, h2_recompute);
        assert_eq!(h3, h3_recompute);
    }

    #[test]
    fn test_hash_output_roundtrip() {
        let data = b"test";
        let hash_output = hash(data);
        let bytes = *hash_output.as_bytes();
        let restored = HashOutput::from_bytes(bytes);

        assert_eq!(hash_output, restored);
    }
}
