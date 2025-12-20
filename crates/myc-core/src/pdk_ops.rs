//! PDK lifecycle operations.
//!
//! This module provides functions for generating, wrapping, unwrapping, and rotating PDKs.

use crate::error::{CoreError, Result};
use crate::ids::{DeviceId, VersionNumber};
use crate::pdk::{PdkVersion, WrappedPdk};
use myc_crypto::aead::{decrypt, encrypt, AeadKey, KEY_SIZE};
use myc_crypto::kdf::derive_aead_key;
use myc_crypto::kex::{diffie_hellman, generate_x25519_keypair, X25519PublicKey, X25519SecretKey};
use myc_crypto::random::generate_random_bytes;

/// Domain separation context for PDK wrapping.
const PDK_WRAP_CONTEXT: &[u8] = b"mycelium-pdk-wrap-v1";

/// Generates a new PDK (Project Data Key).
///
/// This function generates a 32-byte random PDK suitable for use with
/// ChaCha20-Poly1305 AEAD encryption.
///
/// # Returns
///
/// A new `AeadKey` containing the generated PDK
///
/// # Errors
///
/// Returns `CoreError::CryptoError` if random number generation fails
///
/// # Examples
///
/// ```
/// use myc_core::pdk_ops::generate_pdk;
///
/// let pdk = generate_pdk().unwrap();
/// ```
pub fn generate_pdk() -> Result<AeadKey> {
    let pdk_bytes: [u8; KEY_SIZE] = generate_random_bytes()?;
    Ok(AeadKey::from_bytes(pdk_bytes))
}

/// Wraps a PDK to a device's public key using ECIES-style encryption.
///
/// This function:
/// 1. Generates an ephemeral X25519 keypair
/// 2. Computes a shared secret via Diffie-Hellman with the device's public key
/// 3. Derives a wrap key using HKDF with domain separation
/// 4. Encrypts the PDK with the wrap key using AEAD
///
/// # Arguments
///
/// * `pdk` - The PDK to wrap
/// * `device_id` - The ID of the device to wrap the PDK for
/// * `device_pubkey` - The device's X25519 public key
///
/// # Returns
///
/// A `WrappedPdk` containing the device ID, ephemeral public key, and ciphertext
///
/// # Errors
///
/// Returns `CoreError::CryptoError` if key generation or encryption fails
///
/// # Examples
///
/// ```
/// use myc_core::pdk_ops::{generate_pdk, wrap_pdk};
/// use myc_core::ids::DeviceId;
/// use myc_crypto::kex::generate_x25519_keypair;
///
/// let pdk = generate_pdk().unwrap();
/// let device_id = DeviceId::new();
/// let (_, device_pubkey) = generate_x25519_keypair().unwrap();
///
/// let wrapped = wrap_pdk(&pdk, device_id, &device_pubkey).unwrap();
/// ```
pub fn wrap_pdk(
    pdk: &AeadKey,
    device_id: DeviceId,
    device_pubkey: &X25519PublicKey,
) -> Result<WrappedPdk> {
    // Generate ephemeral keypair
    let (ephemeral_secret, ephemeral_pubkey) = generate_x25519_keypair()?;

    // Compute shared secret via Diffie-Hellman
    let shared_secret = diffie_hellman(&ephemeral_secret, device_pubkey);

    // Derive wrap key using HKDF with domain separation
    let wrap_key = derive_aead_key(&shared_secret, PDK_WRAP_CONTEXT);

    // Encrypt PDK with wrap key (no AAD needed for PDK wrapping)
    let pdk_bytes = pdk.as_bytes();
    let ciphertext = encrypt(&wrap_key, pdk_bytes, b"")?;

    Ok(WrappedPdk::new(device_id, ephemeral_pubkey, ciphertext))
}

/// Unwraps a PDK using a device's secret key.
///
/// This function:
/// 1. Computes the shared secret using the device's secret key and the ephemeral public key
/// 2. Derives the wrap key using HKDF with domain separation
/// 3. Decrypts the PDK with the wrap key using AEAD
///
/// # Arguments
///
/// * `wrapped_pdk` - The wrapped PDK to unwrap
/// * `device_secret` - The device's X25519 secret key
///
/// # Returns
///
/// The unwrapped `AeadKey` (PDK)
///
/// # Errors
///
/// Returns `CoreError::CryptoError` if decryption fails (wrong key or tampered ciphertext)
///
/// # Examples
///
/// ```
/// use myc_core::pdk_ops::{generate_pdk, wrap_pdk, unwrap_pdk};
/// use myc_core::ids::DeviceId;
/// use myc_crypto::kex::generate_x25519_keypair;
///
/// let pdk = generate_pdk().unwrap();
/// let device_id = DeviceId::new();
/// let (device_secret, device_pubkey) = generate_x25519_keypair().unwrap();
///
/// let wrapped = wrap_pdk(&pdk, device_id, &device_pubkey).unwrap();
/// let unwrapped = unwrap_pdk(&wrapped, &device_secret).unwrap();
/// ```
pub fn unwrap_pdk(wrapped_pdk: &WrappedPdk, device_secret: &X25519SecretKey) -> Result<AeadKey> {
    // Compute shared secret using device secret key and ephemeral public key
    let shared_secret = diffie_hellman(device_secret, &wrapped_pdk.ephemeral_pubkey);

    // Derive wrap key using HKDF with domain separation
    let wrap_key = derive_aead_key(&shared_secret, PDK_WRAP_CONTEXT);

    // Decrypt PDK
    let pdk_bytes = decrypt(&wrap_key, &wrapped_pdk.ciphertext, b"")?;

    // Convert to AeadKey
    if pdk_bytes.len() != KEY_SIZE {
        return Err(CoreError::CryptoError(
            myc_crypto::error::CryptoError::InvalidKeyLength {
                expected: KEY_SIZE,
                actual: pdk_bytes.len(),
            },
        ));
    }

    let mut key_array = [0u8; KEY_SIZE];
    key_array.copy_from_slice(&pdk_bytes);
    Ok(AeadKey::from_bytes(key_array))
}

/// Creates a new PDK version with wrapped keys for authorized devices.
///
/// This function creates a `PdkVersion` record that contains the PDK wrapped
/// to each authorized device's public key.
///
/// # Arguments
///
/// * `version` - The version number for this PDK
/// * `created_by` - The device ID that created this PDK version
/// * `reason` - Optional reason for PDK creation/rotation
/// * `wrapped_keys` - List of wrapped PDKs for authorized devices
///
/// # Returns
///
/// A new `PdkVersion` instance
///
/// # Examples
///
/// ```
/// use myc_core::pdk_ops::{generate_pdk, wrap_pdk, create_pdk_version};
/// use myc_core::ids::{DeviceId, VersionNumber};
/// use myc_crypto::kex::generate_x25519_keypair;
///
/// let pdk = generate_pdk().unwrap();
/// let device_id = DeviceId::new();
/// let (_, device_pubkey) = generate_x25519_keypair().unwrap();
///
/// let wrapped = wrap_pdk(&pdk, device_id, &device_pubkey).unwrap();
/// let pdk_version = create_pdk_version(
///     VersionNumber::FIRST,
///     device_id,
///     Some("Initial PDK".to_string()),
///     vec![wrapped],
/// );
/// ```
pub fn create_pdk_version(
    version: VersionNumber,
    created_by: DeviceId,
    reason: Option<String>,
    wrapped_keys: Vec<WrappedPdk>,
) -> PdkVersion {
    PdkVersion::new(version, created_by, reason, wrapped_keys)
}

/// Wraps a PDK to multiple devices.
///
/// This is a convenience function that wraps a PDK to multiple devices
/// in one operation, useful for member addition or PDK rotation.
///
/// # Arguments
///
/// * `pdk` - The PDK to wrap
/// * `devices` - A slice of tuples containing (device_id, device_pubkey) pairs
///
/// # Returns
///
/// A vector of `WrappedPdk` instances, one for each device
///
/// # Errors
///
/// Returns `CoreError::CryptoError` if any wrapping operation fails
///
/// # Examples
///
/// ```
/// use myc_core::pdk_ops::{generate_pdk, wrap_pdk_to_devices};
/// use myc_core::ids::DeviceId;
/// use myc_crypto::kex::generate_x25519_keypair;
///
/// let pdk = generate_pdk().unwrap();
///
/// let device1_id = DeviceId::new();
/// let (_, device1_pubkey) = generate_x25519_keypair().unwrap();
///
/// let device2_id = DeviceId::new();
/// let (_, device2_pubkey) = generate_x25519_keypair().unwrap();
///
/// let devices = vec![
///     (device1_id, device1_pubkey),
///     (device2_id, device2_pubkey),
/// ];
///
/// let wrapped_keys = wrap_pdk_to_devices(&pdk, &devices).unwrap();
/// assert_eq!(wrapped_keys.len(), 2);
/// ```
pub fn wrap_pdk_to_devices(
    pdk: &AeadKey,
    devices: &[(DeviceId, X25519PublicKey)],
) -> Result<Vec<WrappedPdk>> {
    devices
        .iter()
        .map(|(device_id, device_pubkey)| wrap_pdk(pdk, *device_id, device_pubkey))
        .collect()
}

/// Finds and unwraps a PDK from a PDK version for a specific device.
///
/// This function searches for a wrapped PDK for the given device in the
/// PDK version and unwraps it using the device's secret key.
///
/// # Arguments
///
/// * `pdk_version` - The PDK version to search
/// * `device_id` - The device ID to find the wrapped PDK for
/// * `device_secret` - The device's X25519 secret key
///
/// # Returns
///
/// The unwrapped `AeadKey` (PDK)
///
/// # Errors
///
/// Returns `CoreError::CryptoError` if:
/// - No wrapped PDK is found for the device
/// - Decryption fails (wrong key or tampered ciphertext)
///
/// # Examples
///
/// ```
/// use myc_core::pdk_ops::{generate_pdk, wrap_pdk, create_pdk_version, unwrap_pdk_from_version};
/// use myc_core::ids::{DeviceId, VersionNumber};
/// use myc_crypto::kex::generate_x25519_keypair;
///
/// let pdk = generate_pdk().unwrap();
/// let device_id = DeviceId::new();
/// let (device_secret, device_pubkey) = generate_x25519_keypair().unwrap();
///
/// let wrapped = wrap_pdk(&pdk, device_id, &device_pubkey).unwrap();
/// let pdk_version = create_pdk_version(
///     VersionNumber::FIRST,
///     device_id,
///     None,
///     vec![wrapped],
/// );
///
/// let unwrapped = unwrap_pdk_from_version(&pdk_version, &device_id, &device_secret).unwrap();
/// ```
pub fn unwrap_pdk_from_version(
    pdk_version: &PdkVersion,
    device_id: &DeviceId,
    device_secret: &X25519SecretKey,
) -> Result<AeadKey> {
    // Find wrapped PDK for this device
    let wrapped_pdk = pdk_version
        .find_wrapped_pdk(device_id)
        .ok_or(CoreError::CryptoError(
            myc_crypto::error::CryptoError::DecryptionFailed,
        ))?;

    // Unwrap the PDK
    unwrap_pdk(wrapped_pdk, device_secret)
}

/// Adds wrapped PDKs for new member devices to an existing PDK version.
///
/// This function is used when adding a new member to a project. It:
/// 1. Takes the current PDK (already unwrapped by the admin)
/// 2. Wraps the PDK to each of the new member's devices
/// 3. Returns the new wrapped PDKs to be appended to the PDK version
///
/// # Arguments
///
/// * `pdk` - The current PDK (unwrapped by admin)
/// * `new_member_devices` - A slice of tuples containing (device_id, device_pubkey) for the new member's devices
///
/// # Returns
///
/// A vector of `WrappedPdk` instances for the new member's devices
///
/// # Errors
///
/// Returns `CoreError::CryptoError` if any wrapping operation fails
///
/// # Examples
///
/// ```
/// use myc_core::pdk_ops::{generate_pdk, add_member_wrapped_pdks};
/// use myc_core::ids::DeviceId;
/// use myc_crypto::kex::generate_x25519_keypair;
///
/// let pdk = generate_pdk().unwrap();
///
/// let new_device1_id = DeviceId::new();
/// let (_, new_device1_pubkey) = generate_x25519_keypair().unwrap();
///
/// let new_device2_id = DeviceId::new();
/// let (_, new_device2_pubkey) = generate_x25519_keypair().unwrap();
///
/// let new_member_devices = vec![
///     (new_device1_id, new_device1_pubkey),
///     (new_device2_id, new_device2_pubkey),
/// ];
///
/// let new_wrapped_keys = add_member_wrapped_pdks(&pdk, &new_member_devices).unwrap();
/// assert_eq!(new_wrapped_keys.len(), 2);
/// ```
pub fn add_member_wrapped_pdks(
    pdk: &AeadKey,
    new_member_devices: &[(DeviceId, X25519PublicKey)],
) -> Result<Vec<WrappedPdk>> {
    wrap_pdk_to_devices(pdk, new_member_devices)
}

/// Rotates a PDK by generating a new one and wrapping it to authorized devices.
///
/// This function is used when rotating a PDK (e.g., after member removal or device revocation).
/// It:
/// 1. Generates a new PDK
/// 2. Wraps the new PDK to all authorized devices (excluding removed members)
/// 3. Returns the new PDK and wrapped keys
///
/// # Arguments
///
/// * `authorized_devices` - A slice of tuples containing (device_id, device_pubkey) for authorized devices
///
/// # Returns
///
/// A tuple containing:
/// - The new PDK (`AeadKey`)
/// - A vector of `WrappedPdk` instances for authorized devices
///
/// # Errors
///
/// Returns `CoreError::CryptoError` if PDK generation or wrapping fails
///
/// # Examples
///
/// ```
/// use myc_core::pdk_ops::rotate_pdk;
/// use myc_core::ids::DeviceId;
/// use myc_crypto::kex::generate_x25519_keypair;
///
/// let device1_id = DeviceId::new();
/// let (_, device1_pubkey) = generate_x25519_keypair().unwrap();
///
/// let device2_id = DeviceId::new();
/// let (_, device2_pubkey) = generate_x25519_keypair().unwrap();
///
/// let authorized_devices = vec![
///     (device1_id, device1_pubkey),
///     (device2_id, device2_pubkey),
/// ];
///
/// let (new_pdk, wrapped_keys) = rotate_pdk(&authorized_devices).unwrap();
/// assert_eq!(wrapped_keys.len(), 2);
/// ```
pub fn rotate_pdk(
    authorized_devices: &[(DeviceId, X25519PublicKey)],
) -> Result<(AeadKey, Vec<WrappedPdk>)> {
    // Generate new PDK
    let new_pdk = generate_pdk()?;

    // Wrap to authorized devices
    let wrapped_keys = wrap_pdk_to_devices(&new_pdk, authorized_devices)?;

    Ok((new_pdk, wrapped_keys))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_pdk() {
        let pdk = generate_pdk().unwrap();
        // PDK should be 32 bytes
        assert_eq!(pdk.as_bytes().len(), KEY_SIZE);
    }

    #[test]
    fn test_generate_pdk_uniqueness() {
        let pdk1 = generate_pdk().unwrap();
        let pdk2 = generate_pdk().unwrap();

        // Two generated PDKs should be different (with overwhelming probability)
        assert_ne!(pdk1.as_bytes(), pdk2.as_bytes());
    }

    #[test]
    fn test_wrap_unwrap_pdk_roundtrip() {
        let pdk = generate_pdk().unwrap();
        let device_id = DeviceId::new();
        let (device_secret, device_pubkey) = generate_x25519_keypair().unwrap();

        // Wrap PDK
        let wrapped = wrap_pdk(&pdk, device_id, &device_pubkey).unwrap();

        // Verify wrapped PDK structure
        assert_eq!(wrapped.device_id, device_id);
        assert_eq!(wrapped.ciphertext.len(), WrappedPdk::CIPHERTEXT_SIZE);

        // Unwrap PDK
        let unwrapped = unwrap_pdk(&wrapped, &device_secret).unwrap();

        // Verify roundtrip: original and unwrapped PDKs should be the same
        assert_eq!(pdk.as_bytes(), unwrapped.as_bytes());
    }

    #[test]
    fn test_unwrap_with_wrong_key() {
        let pdk = generate_pdk().unwrap();
        let device_id = DeviceId::new();
        let (_, device_pubkey) = generate_x25519_keypair().unwrap();
        let (wrong_secret, _) = generate_x25519_keypair().unwrap();

        // Wrap PDK with correct key
        let wrapped = wrap_pdk(&pdk, device_id, &device_pubkey).unwrap();

        // Try to unwrap with wrong key
        let result = unwrap_pdk(&wrapped, &wrong_secret);

        // Should fail
        assert!(result.is_err());
    }

    #[test]
    fn test_wrap_pdk_different_ephemeral_keys() {
        let pdk = generate_pdk().unwrap();
        let device_id = DeviceId::new();
        let (_, device_pubkey) = generate_x25519_keypair().unwrap();

        // Wrap same PDK twice
        let wrapped1 = wrap_pdk(&pdk, device_id, &device_pubkey).unwrap();
        let wrapped2 = wrap_pdk(&pdk, device_id, &device_pubkey).unwrap();

        // Ephemeral public keys should be different
        assert_ne!(
            wrapped1.ephemeral_pubkey.as_bytes(),
            wrapped2.ephemeral_pubkey.as_bytes()
        );

        // Ciphertexts should be different (due to different ephemeral keys and nonces)
        assert_ne!(wrapped1.ciphertext, wrapped2.ciphertext);
    }

    #[test]
    fn test_wrap_pdk_to_multiple_devices() {
        let pdk = generate_pdk().unwrap();

        let device_id1 = DeviceId::new();
        let (device_secret1, device_pubkey1) = generate_x25519_keypair().unwrap();

        let device_id2 = DeviceId::new();
        let (device_secret2, device_pubkey2) = generate_x25519_keypair().unwrap();

        // Wrap PDK to both devices
        let wrapped1 = wrap_pdk(&pdk, device_id1, &device_pubkey1).unwrap();
        let wrapped2 = wrap_pdk(&pdk, device_id2, &device_pubkey2).unwrap();

        // Both devices should be able to unwrap the PDK
        let unwrapped1 = unwrap_pdk(&wrapped1, &device_secret1).unwrap();
        let unwrapped2 = unwrap_pdk(&wrapped2, &device_secret2).unwrap();

        // All should match the original PDK
        assert_eq!(pdk.as_bytes(), unwrapped1.as_bytes());
        assert_eq!(pdk.as_bytes(), unwrapped2.as_bytes());
    }

    #[test]
    fn test_unwrap_tampered_ciphertext() {
        let pdk = generate_pdk().unwrap();
        let device_id = DeviceId::new();
        let (device_secret, device_pubkey) = generate_x25519_keypair().unwrap();

        // Wrap PDK
        let mut wrapped = wrap_pdk(&pdk, device_id, &device_pubkey).unwrap();

        // Tamper with ciphertext
        if !wrapped.ciphertext.is_empty() {
            wrapped.ciphertext[0] ^= 0xFF;
        }

        // Try to unwrap tampered ciphertext
        let result = unwrap_pdk(&wrapped, &device_secret);

        // Should fail due to authentication tag mismatch
        assert!(result.is_err());
    }

    #[test]
    fn test_create_pdk_version() {
        let pdk = generate_pdk().unwrap();
        let device_id = DeviceId::new();
        let (_, device_pubkey) = generate_x25519_keypair().unwrap();

        let wrapped = wrap_pdk(&pdk, device_id, &device_pubkey).unwrap();
        let pdk_version = create_pdk_version(
            VersionNumber::FIRST,
            device_id,
            Some("Initial PDK".to_string()),
            vec![wrapped.clone()],
        );

        assert_eq!(pdk_version.version, VersionNumber::FIRST);
        assert_eq!(pdk_version.created_by, device_id);
        assert_eq!(pdk_version.reason, Some("Initial PDK".to_string()));
        assert_eq!(pdk_version.device_count(), 1);
        assert!(pdk_version.has_device_access(&device_id));
    }

    #[test]
    fn test_wrap_pdk_to_devices() {
        let pdk = generate_pdk().unwrap();

        let device1_id = DeviceId::new();
        let (_, device1_pubkey) = generate_x25519_keypair().unwrap();

        let device2_id = DeviceId::new();
        let (_, device2_pubkey) = generate_x25519_keypair().unwrap();

        let device3_id = DeviceId::new();
        let (_, device3_pubkey) = generate_x25519_keypair().unwrap();

        let devices = vec![
            (device1_id, device1_pubkey),
            (device2_id, device2_pubkey),
            (device3_id, device3_pubkey),
        ];

        let wrapped_keys = wrap_pdk_to_devices(&pdk, &devices).unwrap();

        assert_eq!(wrapped_keys.len(), 3);
        assert_eq!(wrapped_keys[0].device_id, device1_id);
        assert_eq!(wrapped_keys[1].device_id, device2_id);
        assert_eq!(wrapped_keys[2].device_id, device3_id);
    }

    #[test]
    fn test_unwrap_pdk_from_version() {
        let pdk = generate_pdk().unwrap();
        let device_id = DeviceId::new();
        let (device_secret, device_pubkey) = generate_x25519_keypair().unwrap();

        let wrapped = wrap_pdk(&pdk, device_id, &device_pubkey).unwrap();
        let pdk_version = create_pdk_version(VersionNumber::FIRST, device_id, None, vec![wrapped]);

        let unwrapped = unwrap_pdk_from_version(&pdk_version, &device_id, &device_secret).unwrap();

        assert_eq!(pdk.as_bytes(), unwrapped.as_bytes());
    }

    #[test]
    fn test_unwrap_pdk_from_version_device_not_found() {
        let pdk = generate_pdk().unwrap();
        let device_id1 = DeviceId::new();
        let device_id2 = DeviceId::new();
        let (_, device_pubkey1) = generate_x25519_keypair().unwrap();
        let (device_secret2, _) = generate_x25519_keypair().unwrap();

        let wrapped = wrap_pdk(&pdk, device_id1, &device_pubkey1).unwrap();
        let pdk_version = create_pdk_version(VersionNumber::FIRST, device_id1, None, vec![wrapped]);

        // Try to unwrap for device2 which doesn't have access
        let result = unwrap_pdk_from_version(&pdk_version, &device_id2, &device_secret2);

        assert!(result.is_err());
    }

    #[test]
    fn test_wrap_pdk_to_devices_multiple_unwrap() {
        let pdk = generate_pdk().unwrap();

        let device1_id = DeviceId::new();
        let (device1_secret, device1_pubkey) = generate_x25519_keypair().unwrap();

        let device2_id = DeviceId::new();
        let (device2_secret, device2_pubkey) = generate_x25519_keypair().unwrap();

        let devices = vec![(device1_id, device1_pubkey), (device2_id, device2_pubkey)];

        let wrapped_keys = wrap_pdk_to_devices(&pdk, &devices).unwrap();
        let pdk_version = create_pdk_version(
            VersionNumber::FIRST,
            device1_id,
            Some("Multi-device PDK".to_string()),
            wrapped_keys,
        );

        // Both devices should be able to unwrap
        let unwrapped1 =
            unwrap_pdk_from_version(&pdk_version, &device1_id, &device1_secret).unwrap();
        let unwrapped2 =
            unwrap_pdk_from_version(&pdk_version, &device2_id, &device2_secret).unwrap();

        assert_eq!(pdk.as_bytes(), unwrapped1.as_bytes());
        assert_eq!(pdk.as_bytes(), unwrapped2.as_bytes());
    }

    #[test]
    fn test_add_member_wrapped_pdks() {
        // Simulate existing project with one member
        let pdk = generate_pdk().unwrap();
        let admin_device_id = DeviceId::new();
        let (admin_secret, admin_pubkey) = generate_x25519_keypair().unwrap();

        // Create initial PDK version with admin's device
        let admin_wrapped = wrap_pdk(&pdk, admin_device_id, &admin_pubkey).unwrap();
        let mut pdk_version = create_pdk_version(
            VersionNumber::FIRST,
            admin_device_id,
            Some("Initial PDK".to_string()),
            vec![admin_wrapped],
        );

        // Admin unwraps PDK to add new member
        let unwrapped_pdk =
            unwrap_pdk_from_version(&pdk_version, &admin_device_id, &admin_secret).unwrap();

        // New member has two devices
        let new_device1_id = DeviceId::new();
        let (new_device1_secret, new_device1_pubkey) = generate_x25519_keypair().unwrap();

        let new_device2_id = DeviceId::new();
        let (new_device2_secret, new_device2_pubkey) = generate_x25519_keypair().unwrap();

        let new_member_devices = vec![
            (new_device1_id, new_device1_pubkey),
            (new_device2_id, new_device2_pubkey),
        ];

        // Wrap PDK to new member's devices
        let new_wrapped_keys =
            add_member_wrapped_pdks(&unwrapped_pdk, &new_member_devices).unwrap();

        assert_eq!(new_wrapped_keys.len(), 2);

        // Append to PDK version (simulating what would happen in real code)
        pdk_version.wrapped_keys.extend(new_wrapped_keys);

        // Verify all devices can now unwrap
        assert_eq!(pdk_version.device_count(), 3);
        assert!(pdk_version.has_device_access(&admin_device_id));
        assert!(pdk_version.has_device_access(&new_device1_id));
        assert!(pdk_version.has_device_access(&new_device2_id));

        // Verify new devices can unwrap the PDK
        let unwrapped1 =
            unwrap_pdk_from_version(&pdk_version, &new_device1_id, &new_device1_secret).unwrap();
        let unwrapped2 =
            unwrap_pdk_from_version(&pdk_version, &new_device2_id, &new_device2_secret).unwrap();

        assert_eq!(pdk.as_bytes(), unwrapped1.as_bytes());
        assert_eq!(pdk.as_bytes(), unwrapped2.as_bytes());
    }

    #[test]
    fn test_rotate_pdk() {
        // Create authorized devices
        let device1_id = DeviceId::new();
        let (device1_secret, device1_pubkey) = generate_x25519_keypair().unwrap();

        let device2_id = DeviceId::new();
        let (device2_secret, device2_pubkey) = generate_x25519_keypair().unwrap();

        let authorized_devices = vec![(device1_id, device1_pubkey), (device2_id, device2_pubkey)];

        // Rotate PDK
        let (new_pdk, wrapped_keys) = rotate_pdk(&authorized_devices).unwrap();

        assert_eq!(wrapped_keys.len(), 2);
        assert_eq!(wrapped_keys[0].device_id, device1_id);
        assert_eq!(wrapped_keys[1].device_id, device2_id);

        // Create PDK version with rotated PDK
        let pdk_version = create_pdk_version(
            VersionNumber::new(2),
            device1_id,
            Some("Rotation after member removal".to_string()),
            wrapped_keys,
        );

        // Both devices should be able to unwrap the new PDK
        let unwrapped1 =
            unwrap_pdk_from_version(&pdk_version, &device1_id, &device1_secret).unwrap();
        let unwrapped2 =
            unwrap_pdk_from_version(&pdk_version, &device2_id, &device2_secret).unwrap();

        assert_eq!(new_pdk.as_bytes(), unwrapped1.as_bytes());
        assert_eq!(new_pdk.as_bytes(), unwrapped2.as_bytes());
    }

    #[test]
    fn test_rotate_pdk_excludes_removed_device() {
        // Initial setup with 3 devices
        let device1_id = DeviceId::new();
        let (device1_secret, device1_pubkey) = generate_x25519_keypair().unwrap();

        let device2_id = DeviceId::new();
        let (device2_secret, device2_pubkey) = generate_x25519_keypair().unwrap();

        let device3_id = DeviceId::new();
        let (device3_secret, device3_pubkey) = generate_x25519_keypair().unwrap();

        // Create initial PDK version with all 3 devices
        let old_pdk = generate_pdk().unwrap();
        let all_devices = vec![
            (device1_id, device1_pubkey),
            (device2_id, device2_pubkey),
            (device3_id, device3_pubkey),
        ];
        let old_wrapped_keys = wrap_pdk_to_devices(&old_pdk, &all_devices).unwrap();
        let old_pdk_version =
            create_pdk_version(VersionNumber::FIRST, device1_id, None, old_wrapped_keys);

        // All 3 devices can access old PDK
        assert!(old_pdk_version.has_device_access(&device1_id));
        assert!(old_pdk_version.has_device_access(&device2_id));
        assert!(old_pdk_version.has_device_access(&device3_id));

        // Rotate PDK, excluding device3 (simulating member removal)
        let authorized_devices = vec![(device1_id, device1_pubkey), (device2_id, device2_pubkey)];
        let (new_pdk, new_wrapped_keys) = rotate_pdk(&authorized_devices).unwrap();

        let new_pdk_version = create_pdk_version(
            VersionNumber::new(2),
            device1_id,
            Some("Member removed".to_string()),
            new_wrapped_keys,
        );

        // Only devices 1 and 2 should have access to new PDK
        assert!(new_pdk_version.has_device_access(&device1_id));
        assert!(new_pdk_version.has_device_access(&device2_id));
        assert!(!new_pdk_version.has_device_access(&device3_id));

        // Devices 1 and 2 can unwrap new PDK
        let unwrapped1 =
            unwrap_pdk_from_version(&new_pdk_version, &device1_id, &device1_secret).unwrap();
        let unwrapped2 =
            unwrap_pdk_from_version(&new_pdk_version, &device2_id, &device2_secret).unwrap();

        assert_eq!(new_pdk.as_bytes(), unwrapped1.as_bytes());
        assert_eq!(new_pdk.as_bytes(), unwrapped2.as_bytes());

        // Device 3 cannot unwrap new PDK
        let result3 = unwrap_pdk_from_version(&new_pdk_version, &device3_id, &device3_secret);
        assert!(result3.is_err());

        // But device 3 can still unwrap old PDK (historical access)
        let old_unwrapped3 =
            unwrap_pdk_from_version(&old_pdk_version, &device3_id, &device3_secret).unwrap();
        assert_eq!(old_pdk.as_bytes(), old_unwrapped3.as_bytes());
    }

    #[test]
    fn test_rotate_pdk_generates_different_pdk() {
        let device_id = DeviceId::new();
        let (_, device_pubkey) = generate_x25519_keypair().unwrap();

        let devices = vec![(device_id, device_pubkey)];

        // Rotate twice
        let (pdk1, _) = rotate_pdk(&devices).unwrap();
        let (pdk2, _) = rotate_pdk(&devices).unwrap();

        // PDKs should be different
        assert_ne!(pdk1.as_bytes(), pdk2.as_bytes());
    }
}
