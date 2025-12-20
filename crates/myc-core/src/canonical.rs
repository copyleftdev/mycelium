//! Canonical JSON serialization for signing.
//!
//! This module provides deterministic JSON serialization with sorted keys
//! and no whitespace, suitable for cryptographic signing.

use crate::error::{CoreError, Result};
use myc_crypto::sign::{sign, verify, Ed25519PublicKey, Ed25519SecretKey, Signature};
use serde::Serialize;

/// Serialize a value to canonical JSON.
///
/// Canonical JSON has the following properties:
/// - Keys are sorted alphabetically
/// - No whitespace (compact format)
/// - Deterministic output for the same input
///
/// This ensures that signing the same data structure always produces
/// the same signature.
///
/// # Arguments
///
/// * `value` - The value to serialize
///
/// # Returns
///
/// A canonical JSON string
///
/// # Errors
///
/// Returns `CoreError::SerializationError` if serialization fails
///
/// # Examples
///
/// ```
/// use myc_core::canonical::to_canonical_json;
/// use serde::Serialize;
///
/// #[derive(Serialize)]
/// struct Data {
///     name: String,
///     age: u32,
/// }
///
/// let data = Data {
///     name: "Alice".to_string(),
///     age: 30,
/// };
///
/// let json = to_canonical_json(&data).unwrap();
/// assert_eq!(json, r#"{"age":30,"name":"Alice"}"#);
/// ```
pub fn to_canonical_json<T: Serialize>(value: &T) -> Result<String> {
    // Use serde_json with canonical formatting
    let json = serde_json::to_string(value)?;

    // Parse and re-serialize to ensure canonical ordering
    let parsed: serde_json::Value = serde_json::from_str(&json)?;
    let canonical = canonicalize_value(&parsed);

    // Serialize without whitespace
    Ok(serde_json::to_string(&canonical)?)
}

/// Recursively canonicalize a JSON value by sorting object keys.
fn canonicalize_value(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            // Sort keys and recursively canonicalize values
            let mut sorted: Vec<_> = map.iter().collect();
            sorted.sort_by_key(|(k, _)| *k);

            let canonical_map: serde_json::Map<String, serde_json::Value> = sorted
                .into_iter()
                .map(|(k, v)| (k.clone(), canonicalize_value(v)))
                .collect();

            serde_json::Value::Object(canonical_map)
        }
        serde_json::Value::Array(arr) => {
            // Recursively canonicalize array elements
            let canonical_arr: Vec<_> = arr.iter().map(canonicalize_value).collect();
            serde_json::Value::Array(canonical_arr)
        }
        // Primitives are already canonical
        other => other.clone(),
    }
}

/// Sign a payload using canonical JSON serialization.
///
/// This function serializes the payload to canonical JSON and signs it
/// with the provided Ed25519 secret key.
///
/// # Arguments
///
/// * `value` - The value to sign
/// * `key` - The Ed25519 secret key to use for signing
///
/// # Returns
///
/// A 64-byte Ed25519 signature
///
/// # Errors
///
/// Returns `CoreError::SerializationError` if serialization fails
///
/// # Examples
///
/// ```
/// use myc_core::canonical::sign_payload;
/// use myc_crypto::sign::generate_ed25519_keypair;
/// use serde::Serialize;
///
/// #[derive(Serialize)]
/// struct Data {
///     message: String,
/// }
///
/// let (secret_key, _) = generate_ed25519_keypair().unwrap();
/// let data = Data {
///     message: "Hello, World!".to_string(),
/// };
///
/// let signature = sign_payload(&data, &secret_key).unwrap();
/// assert_eq!(signature.as_bytes().len(), 64);
/// ```
pub fn sign_payload<T: Serialize>(value: &T, key: &Ed25519SecretKey) -> Result<Signature> {
    let canonical_json = to_canonical_json(value)?;
    Ok(sign(key, canonical_json.as_bytes()))
}

/// Verify a signature on a payload using canonical JSON serialization.
///
/// This function serializes the payload to canonical JSON and verifies
/// the signature using the provided Ed25519 public key.
///
/// # Arguments
///
/// * `value` - The value to verify
/// * `signature` - The signature to verify
/// * `key` - The Ed25519 public key to use for verification
///
/// # Returns
///
/// `Ok(())` if the signature is valid
///
/// # Errors
///
/// Returns `CoreError::SignatureInvalid` if verification fails
/// Returns `CoreError::SerializationError` if serialization fails
///
/// # Examples
///
/// ```
/// use myc_core::canonical::{sign_payload, verify_payload};
/// use myc_crypto::sign::generate_ed25519_keypair;
/// use serde::Serialize;
///
/// #[derive(Serialize)]
/// struct Data {
///     message: String,
/// }
///
/// let (secret_key, public_key) = generate_ed25519_keypair().unwrap();
/// let data = Data {
///     message: "Hello, World!".to_string(),
/// };
///
/// let signature = sign_payload(&data, &secret_key).unwrap();
/// assert!(verify_payload(&data, &signature, &public_key).is_ok());
/// ```
pub fn verify_payload<T: Serialize>(
    value: &T,
    signature: &Signature,
    key: &Ed25519PublicKey,
) -> Result<()> {
    let canonical_json = to_canonical_json(value)?;
    verify(key, canonical_json.as_bytes(), signature).map_err(|_| CoreError::SignatureInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use myc_crypto::sign::generate_ed25519_keypair;
    use serde::Serialize;

    #[derive(Serialize)]
    struct TestData {
        name: String,
        age: u32,
        active: bool,
    }

    #[test]
    fn test_canonical_json_key_ordering() {
        let data = TestData {
            name: "Alice".to_string(),
            age: 30,
            active: true,
        };

        let json = to_canonical_json(&data).unwrap();

        // Keys should be sorted alphabetically: active, age, name
        assert_eq!(json, r#"{"active":true,"age":30,"name":"Alice"}"#);
    }

    #[test]
    fn test_canonical_json_determinism() {
        let data1 = TestData {
            name: "Bob".to_string(),
            age: 25,
            active: false,
        };

        let data2 = TestData {
            name: "Bob".to_string(),
            age: 25,
            active: false,
        };

        let json1 = to_canonical_json(&data1).unwrap();
        let json2 = to_canonical_json(&data2).unwrap();

        assert_eq!(json1, json2);
    }

    #[test]
    fn test_canonical_json_no_whitespace() {
        let data = TestData {
            name: "Charlie".to_string(),
            age: 35,
            active: true,
        };

        let json = to_canonical_json(&data).unwrap();

        // Should not contain any whitespace
        assert!(!json.contains(' '));
        assert!(!json.contains('\n'));
        assert!(!json.contains('\t'));
    }

    #[test]
    fn test_sign_and_verify_payload() {
        let (secret_key, public_key) = generate_ed25519_keypair().unwrap();

        let data = TestData {
            name: "Dave".to_string(),
            age: 40,
            active: true,
        };

        // Sign the payload
        let signature = sign_payload(&data, &secret_key).unwrap();

        // Verify the signature
        assert!(verify_payload(&data, &signature, &public_key).is_ok());
    }

    #[test]
    fn test_verify_fails_with_wrong_key() {
        let (secret_key1, _) = generate_ed25519_keypair().unwrap();
        let (_, public_key2) = generate_ed25519_keypair().unwrap();

        let data = TestData {
            name: "Eve".to_string(),
            age: 28,
            active: false,
        };

        // Sign with key 1
        let signature = sign_payload(&data, &secret_key1).unwrap();

        // Verify with key 2 should fail
        assert!(verify_payload(&data, &signature, &public_key2).is_err());
    }

    #[test]
    fn test_verify_fails_with_modified_data() {
        let (secret_key, public_key) = generate_ed25519_keypair().unwrap();

        let data1 = TestData {
            name: "Frank".to_string(),
            age: 45,
            active: true,
        };

        let data2 = TestData {
            name: "Frank".to_string(),
            age: 46, // Modified age
            active: true,
        };

        // Sign data1
        let signature = sign_payload(&data1, &secret_key).unwrap();

        // Verify with data2 should fail
        assert!(verify_payload(&data2, &signature, &public_key).is_err());
    }

    #[test]
    fn test_nested_objects_canonical() {
        #[derive(Serialize)]
        struct Nested {
            outer: String,
            inner: Inner,
        }

        #[derive(Serialize)]
        struct Inner {
            z_field: u32,
            a_field: String,
        }

        let data = Nested {
            outer: "test".to_string(),
            inner: Inner {
                z_field: 42,
                a_field: "nested".to_string(),
            },
        };

        let json = to_canonical_json(&data).unwrap();

        // Both outer and inner keys should be sorted
        assert_eq!(
            json,
            r#"{"inner":{"a_field":"nested","z_field":42},"outer":"test"}"#
        );
    }

    #[test]
    fn test_array_elements_preserved() {
        #[derive(Serialize)]
        struct WithArray {
            items: Vec<u32>,
        }

        let data = WithArray {
            items: vec![3, 1, 4, 1, 5, 9],
        };

        let json = to_canonical_json(&data).unwrap();

        // Array order should be preserved
        assert_eq!(json, r#"{"items":[3,1,4,1,5,9]}"#);
    }
}
