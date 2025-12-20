//! Recovery operations for Mycelium.
//!
//! This module implements the business logic for key recovery operations,
//! including multi-device enrollment, recovery contacts, and organization recovery keys.

use crate::{
    canonical::{sign_payload, verify_payload},
    device::Device,
    error::{CoreError, ValidationError},
    ids::{DeviceId, OrgId, ProjectId, UserId},
    pdk::{PdkVersion, WrappedPdk},
    recovery::{
        OrgRecoveryKey, RecoveryAssistance, RecoveryContact, RecoveryRequest, RecoveryShare,
        ShareContribution,
    },
};
use myc_crypto::{
    aead::{decrypt, encrypt, AeadKey},
    kdf::derive_aead_key,
    kex::{diffie_hellman, generate_x25519_keypair, X25519PublicKey, X25519SecretKey},
    sign::{Ed25519PublicKey, Ed25519SecretKey, Signature},
};
use time::OffsetDateTime;

/// Operations for managing recovery contacts
pub struct RecoveryContactOps;

impl RecoveryContactOps {
    /// Create a new recovery contact relationship
    pub fn create_contact(
        user_id: UserId,
        contact_user_id: UserId,
        created_by: DeviceId,
        signing_key: &Ed25519SecretKey,
    ) -> Result<(RecoveryContact, Signature), CoreError> {
        let contact = RecoveryContact::new(user_id, contact_user_id, created_by);
        let signature = sign_payload(&contact, signing_key)?;
        Ok((contact, signature))
    }

    /// Verify a recovery contact relationship signature
    pub fn verify_contact(
        contact: &RecoveryContact,
        signature: &Signature,
        signing_key: &Ed25519PublicKey,
    ) -> Result<(), CoreError> {
        verify_payload(contact, signature, signing_key)
    }

    /// Check if a user can assist with recovery for another user
    pub fn can_assist_recovery(
        contacts: &[RecoveryContact],
        user_id: &UserId,
        contact_user_id: &UserId,
    ) -> bool {
        contacts.iter().any(|contact| {
            contact.user_id == *user_id
                && contact.contact_user_id == *contact_user_id
                && contact.is_valid()
        })
    }

    /// Get all valid recovery contacts for a user
    pub fn get_user_contacts<'a>(
        contacts: &'a [RecoveryContact],
        user_id: &UserId,
    ) -> Vec<&'a RecoveryContact> {
        contacts
            .iter()
            .filter(|contact| contact.user_id == *user_id && contact.is_valid())
            .collect()
    }
}

/// Operations for managing recovery requests
pub struct RecoveryRequestOps;

impl RecoveryRequestOps {
    /// Create a new recovery request
    pub fn create_request(
        user_id: UserId,
        new_device_id: DeviceId,
        new_device_signing_key: Ed25519PublicKey,
        new_device_encryption_key: X25519PublicKey,
        projects: Vec<ProjectId>,
    ) -> RecoveryRequest {
        RecoveryRequest::new(
            user_id,
            new_device_id,
            new_device_signing_key,
            new_device_encryption_key,
            projects,
        )
    }

    /// Provide recovery assistance by wrapping PDKs to the new device
    pub fn provide_assistance(
        request: &RecoveryRequest,
        contact_user_id: UserId,
        contact_device_id: DeviceId,
        _contact_encryption_key: &X25519SecretKey,
        contact_signing_key: &Ed25519SecretKey,
        _pdk_versions: &[PdkVersion],
        projects_with_access: &[ProjectId],
    ) -> Result<RecoveryAssistance, CoreError> {
        // Only assist with projects the contact has access to
        let assisted_projects: Vec<ProjectId> = request
            .projects
            .iter()
            .filter(|project_id| projects_with_access.contains(project_id))
            .cloned()
            .collect();

        if assisted_projects.is_empty() {
            return Err(CoreError::ValidationError(ValidationError::InvalidFormat {
                format: "recovery_request".to_string(),
                reason: "Contact has no access to any requested projects".to_string(),
            }));
        }

        // Create assistance record
        let assistance = RecoveryAssistance {
            contact_user_id,
            contact_device_id,
            assisted_at: OffsetDateTime::now_utc(),
            projects_assisted: assisted_projects,
            signature: Signature::from_bytes([0u8; 64]), // Will be filled below
        };

        // Sign the assistance record
        let signature = sign_payload(&assistance, contact_signing_key)?;

        Ok(RecoveryAssistance {
            signature,
            ..assistance
        })
    }

    /// Wrap PDKs from an existing device to a new device
    ///
    /// This allows an existing device to help enroll a new device by wrapping
    /// PDKs to it, without requiring admin privileges.
    pub fn wrap_pdks_from_device(
        existing_device_key: &X25519SecretKey,
        new_device_encryption_key: &X25519PublicKey,
        pdk_versions: &[PdkVersion],
        projects_to_wrap: &[ProjectId],
    ) -> Result<Vec<(ProjectId, WrappedPdk)>, CoreError> {
        let mut wrapped_pdks = Vec::new();

        for pdk_version in pdk_versions {
            // Find the wrapped PDK for the existing device
            // Note: In a real implementation, we'd need to match the device ID properly
            let existing_wrapped_pdk = pdk_version.wrapped_keys.first().ok_or_else(|| {
                CoreError::ValidationError(ValidationError::InvalidFormat {
                    format: "pdk_version".to_string(),
                    reason: "No wrapped PDK found in version".to_string(),
                })
            })?;

            // Unwrap the PDK using the existing device's key
            let shared_secret =
                diffie_hellman(existing_device_key, &existing_wrapped_pdk.ephemeral_pubkey);
            let wrap_key = derive_aead_key(&shared_secret, b"pdk_wrap");

            // Decrypt the PDK
            let pdk_bytes = decrypt(&wrap_key, &existing_wrapped_pdk.ciphertext, &[])?;
            let pdk = AeadKey::from_slice(&pdk_bytes)?;

            // Generate new ephemeral keypair for the new device
            let (ephemeral_secret, ephemeral_public) = generate_x25519_keypair()?;

            // Compute shared secret with new device
            let new_shared_secret = diffie_hellman(&ephemeral_secret, new_device_encryption_key);
            let new_wrap_key = derive_aead_key(&new_shared_secret, b"pdk_wrap");

            // Encrypt PDK to new device
            let new_ciphertext = encrypt(&new_wrap_key, pdk.as_bytes(), &[])?;

            let new_wrapped_pdk = WrappedPdk {
                device_id: DeviceId::new(), // This would be the new device ID
                ephemeral_pubkey: ephemeral_public,
                ciphertext: new_ciphertext,
            };

            // For this example, we'll use the first project ID
            // In a real implementation, we'd need proper project tracking
            if let Some(project_id) = projects_to_wrap.first() {
                wrapped_pdks.push((*project_id, new_wrapped_pdk));
            }
        }

        Ok(wrapped_pdks)
    }

    /// Wrap PDKs to a new device during recovery
    pub fn wrap_pdks_for_recovery(
        new_device_encryption_key: &X25519PublicKey,
        pdk_versions: &[PdkVersion],
        contact_encryption_key: &X25519SecretKey,
        projects_to_assist: &[ProjectId],
    ) -> Result<Vec<(ProjectId, WrappedPdk)>, CoreError> {
        let mut wrapped_pdks = Vec::new();

        for pdk_version in pdk_versions {
            // Check if this PDK version is for a project we should assist with
            // Note: In a real implementation, we'd need to track which PDK version
            // belongs to which project. For now, we'll assume the caller provides
            // the correct PDK versions.

            // Find the wrapped PDK for the contact's device
            // Note: In a real implementation, we'd need to match the device ID properly
            let contact_wrapped_pdk = pdk_version.wrapped_keys.first().ok_or_else(|| {
                CoreError::ValidationError(ValidationError::InvalidFormat {
                    format: "pdk_version".to_string(),
                    reason: "No wrapped PDK found in version".to_string(),
                })
            })?;

            // Unwrap the PDK using the contact's key
            let shared_secret = diffie_hellman(
                contact_encryption_key,
                &contact_wrapped_pdk.ephemeral_pubkey,
            );
            let wrap_key = derive_aead_key(&shared_secret, b"pdk_wrap");

            // Decrypt the PDK
            let pdk_bytes = decrypt(&wrap_key, &contact_wrapped_pdk.ciphertext, &[])?;
            let pdk = AeadKey::from_slice(&pdk_bytes)?;

            // Generate new ephemeral keypair for the new device
            let (ephemeral_secret, ephemeral_public) = generate_x25519_keypair()?;

            // Compute shared secret with new device
            let new_shared_secret = diffie_hellman(&ephemeral_secret, new_device_encryption_key);
            let new_wrap_key = derive_aead_key(&new_shared_secret, b"pdk_wrap");

            // Encrypt PDK to new device
            let new_ciphertext = encrypt(&new_wrap_key, pdk.as_bytes(), &[])?;

            let new_wrapped_pdk = WrappedPdk {
                device_id: DeviceId::new(), // This would be the new device ID
                ephemeral_pubkey: ephemeral_public,
                ciphertext: new_ciphertext,
            };

            // For this example, we'll use the first project ID
            // In a real implementation, we'd need proper project tracking
            if let Some(project_id) = projects_to_assist.first() {
                wrapped_pdks.push((*project_id, new_wrapped_pdk));
            }
        }

        Ok(wrapped_pdks)
    }
}

/// Operations for organization recovery keys using Shamir's Secret Sharing
pub struct OrgRecoveryKeyOps;

impl OrgRecoveryKeyOps {
    /// Create a new organization recovery key with Shamir's Secret Sharing
    ///
    /// Note: This is a placeholder implementation. A real implementation would use
    /// a proper Shamir's Secret Sharing library like `sharks` or `shamir`.
    pub fn create_org_recovery_key(
        org_id: OrgId,
        threshold: u32,
        admin_devices: &[Device],
        created_by: DeviceId,
    ) -> Result<OrgRecoveryKey, CoreError> {
        if admin_devices.len() < threshold as usize {
            return Err(CoreError::ValidationError(ValidationError::InvalidFormat {
                format: "org_recovery_key".to_string(),
                reason: "Not enough admin devices for threshold".to_string(),
            }));
        }

        // Generate a random 32-byte organization recovery key
        let org_key =
            myc_crypto::random::generate_random_bytes::<32>().map_err(CoreError::CryptoError)?;

        // Split the key using Shamir's Secret Sharing
        // This is a placeholder - real implementation would use a proper SSS library
        let shares = Self::split_secret(&org_key, threshold, admin_devices.len() as u32)?;

        // Encrypt each share to the corresponding admin device
        let mut encrypted_shares = Vec::new();
        for (i, device) in admin_devices.iter().enumerate() {
            if i >= shares.len() {
                break;
            }

            let encrypted_share = Self::encrypt_share_to_device(&shares[i], device)?;
            encrypted_shares.push(RecoveryShare {
                share_number: (i + 1) as u32,
                device_id: device.id,
                encrypted_share,
                created_at: OffsetDateTime::now_utc(),
            });
        }

        Ok(OrgRecoveryKey::new(
            org_id,
            threshold,
            admin_devices.len() as u32,
            created_by,
            encrypted_shares,
        ))
    }

    /// Contribute a recovery share during recovery process
    pub fn contribute_share(
        recovery_key: &OrgRecoveryKey,
        share_number: u32,
        device_id: DeviceId,
        device_encryption_key: &X25519SecretKey,
        device_signing_key: &Ed25519SecretKey,
    ) -> Result<ShareContribution, CoreError> {
        // Find the encrypted share for this device
        let encrypted_share = recovery_key
            .shares
            .iter()
            .find(|share| share.device_id == device_id && share.share_number == share_number)
            .ok_or_else(|| {
                CoreError::ValidationError(ValidationError::InvalidFormat {
                    format: "recovery_share".to_string(),
                    reason: "Share not found for device".to_string(),
                })
            })?;

        // Decrypt the share
        let share_data = Self::decrypt_share_from_device(
            &encrypted_share.encrypted_share,
            device_encryption_key,
        )?;

        // Create contribution record
        let contribution = ShareContribution {
            share_number,
            device_id,
            share_data: share_data.clone(),
            contributed_at: OffsetDateTime::now_utc(),
            signature: Signature::from_bytes([0u8; 64]), // Will be filled below
        };

        // Sign the contribution
        let signature = sign_payload(&contribution, device_signing_key)?;

        Ok(ShareContribution {
            signature,
            ..contribution
        })
    }

    /// Reconstruct the organization recovery key from sufficient shares
    pub fn reconstruct_org_key(
        recovery_key: &OrgRecoveryKey,
        contributions: &[ShareContribution],
    ) -> Result<Vec<u8>, CoreError> {
        if !recovery_key.has_sufficient_shares(contributions) {
            return Err(CoreError::ValidationError(ValidationError::InvalidFormat {
                format: "recovery_shares".to_string(),
                reason: "Insufficient shares for reconstruction".to_string(),
            }));
        }

        // Extract share data from contributions
        let share_data: Vec<&[u8]> = contributions
            .iter()
            .take(recovery_key.threshold as usize)
            .map(|c| c.share_data.as_slice())
            .collect();

        // Reconstruct the secret using Shamir's Secret Sharing
        // This is a placeholder - real implementation would use a proper SSS library
        Self::reconstruct_secret(&share_data, recovery_key.threshold)
    }

    /// Re-wrap PDKs using the reconstructed organization recovery key
    pub fn rewrap_pdks_with_org_key(
        _org_key: &[u8],
        new_device_encryption_key: &X25519PublicKey,
        pdk_versions: &[PdkVersion],
    ) -> Result<Vec<WrappedPdk>, CoreError> {
        // This is a placeholder implementation
        // In a real system, the org recovery key would be used to decrypt
        // a master key that can unwrap all PDKs, then re-wrap them to the new device

        let mut wrapped_pdks = Vec::new();

        for _pdk_version in pdk_versions {
            // Generate ephemeral keypair for wrapping
            let (ephemeral_secret, ephemeral_public) = generate_x25519_keypair()?;

            // Compute shared secret with new device
            let shared_secret = diffie_hellman(&ephemeral_secret, new_device_encryption_key);
            let wrap_key = derive_aead_key(&shared_secret, b"pdk_wrap");

            // For this placeholder, we'll create a dummy PDK
            let dummy_pdk = AeadKey::from_bytes([0u8; 32]);
            let ciphertext = encrypt(&wrap_key, dummy_pdk.as_bytes(), &[])?;

            wrapped_pdks.push(WrappedPdk {
                device_id: DeviceId::new(), // Would be the new device ID
                ephemeral_pubkey: ephemeral_public,
                ciphertext,
            });
        }

        Ok(wrapped_pdks)
    }

    // Placeholder implementations for Shamir's Secret Sharing
    // In a real implementation, these would use a proper SSS library

    fn split_secret(
        secret: &[u8; 32],
        _threshold: u32,
        total_shares: u32,
    ) -> Result<Vec<Vec<u8>>, CoreError> {
        // Placeholder: just duplicate the secret for each share
        // Real implementation would use proper Shamir's Secret Sharing
        let mut shares = Vec::new();
        for i in 0..total_shares {
            let mut share = secret.to_vec();
            share.push(i as u8); // Add share number as a simple differentiator
            shares.push(share);
        }
        Ok(shares)
    }

    fn reconstruct_secret(shares: &[&[u8]], _threshold: u32) -> Result<Vec<u8>, CoreError> {
        // Placeholder: just return the first share without the share number
        if let Some(first_share) = shares.first() {
            if first_share.len() >= 32 {
                return Ok(first_share[..32].to_vec());
            }
        }
        Err(CoreError::ValidationError(ValidationError::InvalidFormat {
            format: "shamir_shares".to_string(),
            reason: "Invalid shares for reconstruction".to_string(),
        }))
    }

    fn encrypt_share_to_device(share: &[u8], device: &Device) -> Result<Vec<u8>, CoreError> {
        // Generate ephemeral keypair
        let (ephemeral_secret, ephemeral_public) =
            generate_x25519_keypair().map_err(CoreError::CryptoError)?;

        // Compute shared secret with device
        let shared_secret = diffie_hellman(&ephemeral_secret, &device.encryption_pubkey);
        let encryption_key = derive_aead_key(&shared_secret, b"share_encrypt");

        // Encrypt the share
        let mut ciphertext = encrypt(&encryption_key, share, &[])?;

        // Prepend the ephemeral public key
        let mut result = ephemeral_public.as_bytes().to_vec();
        result.append(&mut ciphertext);

        Ok(result)
    }

    fn decrypt_share_from_device(
        encrypted_data: &[u8],
        device_encryption_key: &X25519SecretKey,
    ) -> Result<Vec<u8>, CoreError> {
        if encrypted_data.len() < 32 {
            return Err(CoreError::ValidationError(ValidationError::InvalidFormat {
                format: "encrypted_share".to_string(),
                reason: "Invalid encrypted share data".to_string(),
            }));
        }

        // Extract ephemeral public key
        let ephemeral_public_bytes: [u8; 32] = encrypted_data[..32].try_into().map_err(|_| {
            CoreError::ValidationError(ValidationError::InvalidFormat {
                format: "ephemeral_key".to_string(),
                reason: "Invalid ephemeral public key".to_string(),
            })
        })?;
        let ephemeral_public = X25519PublicKey::from_bytes(ephemeral_public_bytes);

        // Extract ciphertext
        let ciphertext = &encrypted_data[32..];

        // Compute shared secret
        let shared_secret = diffie_hellman(device_encryption_key, &ephemeral_public);
        let decryption_key = derive_aead_key(&shared_secret, b"share_encrypt");

        // Decrypt the share
        Ok(decrypt(&decryption_key, ciphertext, &[])?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        device::{Device, DeviceStatus, DeviceType},
        pdk::PdkVersion,
    };
    use myc_crypto::{
        aead::{encrypt, AeadKey},
        kdf::derive_aead_key,
        kex::{diffie_hellman, generate_x25519_keypair},
        sign::generate_ed25519_keypair,
    };

    #[test]
    fn test_create_recovery_contact() {
        let user_id = UserId::new("user1".to_string());
        let contact_id = UserId::new("contact1".to_string());
        let device_id = DeviceId::new();
        let (signing_key, _) = generate_ed25519_keypair().unwrap();

        let result = RecoveryContactOps::create_contact(
            user_id.clone(),
            contact_id.clone(),
            device_id,
            &signing_key,
        );

        assert!(result.is_ok());
        let (contact, _signature) = result.unwrap();
        assert_eq!(contact.user_id, user_id);
        assert_eq!(contact.contact_user_id, contact_id);
        assert_eq!(contact.created_by, device_id);
    }

    #[test]
    fn test_can_assist_recovery() {
        let user_id = UserId::new("user1".to_string());
        let contact_id = UserId::new("contact1".to_string());
        let device_id = DeviceId::new();

        let contact = RecoveryContact::new(user_id.clone(), contact_id.clone(), device_id);
        let contacts = vec![contact];

        assert!(RecoveryContactOps::can_assist_recovery(
            &contacts,
            &user_id,
            &contact_id
        ));

        let other_user = UserId::new("other".to_string());
        assert!(!RecoveryContactOps::can_assist_recovery(
            &contacts,
            &other_user,
            &contact_id
        ));
    }

    #[test]
    fn test_create_recovery_request() {
        let user_id = UserId::new("user1".to_string());
        let device_id = DeviceId::new();
        let (_signing_key, signing_pubkey) = generate_ed25519_keypair().unwrap();
        let (_encryption_key, encryption_pubkey) = generate_x25519_keypair().unwrap();
        let projects = vec![ProjectId::new()];

        let request = RecoveryRequestOps::create_request(
            user_id.clone(),
            device_id,
            signing_pubkey,
            encryption_pubkey,
            projects.clone(),
        );

        assert_eq!(request.user_id, user_id);
        assert_eq!(request.new_device_id, device_id);
        assert_eq!(request.projects, projects);
        assert!(request.is_active());
    }

    #[test]
    fn test_wrap_pdks_from_device() {
        let (existing_key, existing_pubkey) = generate_x25519_keypair().unwrap();
        let (_new_key, new_pubkey) = generate_x25519_keypair().unwrap();

        // Create a mock PDK version with a wrapped PDK
        let (ephemeral_secret, ephemeral_public) = generate_x25519_keypair().unwrap();
        let shared_secret = diffie_hellman(&ephemeral_secret, &existing_pubkey);
        let wrap_key = derive_aead_key(&shared_secret, b"pdk_wrap");

        let dummy_pdk = AeadKey::from_bytes([42u8; 32]);
        let ciphertext = encrypt(&wrap_key, dummy_pdk.as_bytes(), &[]).unwrap();

        let wrapped_pdk = WrappedPdk {
            device_id: DeviceId::new(),
            ephemeral_pubkey: ephemeral_public,
            ciphertext,
        };

        let pdk_version = PdkVersion {
            version: crate::ids::VersionNumber::new(1),
            created_at: OffsetDateTime::now_utc(),
            created_by: DeviceId::new(),
            reason: None,
            wrapped_keys: vec![wrapped_pdk],
        };

        let projects = vec![ProjectId::new()];

        let result = RecoveryRequestOps::wrap_pdks_from_device(
            &existing_key,
            &new_pubkey,
            &[pdk_version],
            &projects,
        );

        assert!(result.is_ok());
        let wrapped_pdks = result.unwrap();
        assert_eq!(wrapped_pdks.len(), 1);
        assert_eq!(wrapped_pdks[0].0, projects[0]);
    }

    #[test]
    fn test_create_org_recovery_key() {
        let org_id = OrgId::new();
        let device_id = DeviceId::new();

        // Create admin devices
        let mut admin_devices = Vec::new();
        for i in 0..5 {
            let (_signing_key, signing_pubkey) = generate_ed25519_keypair().unwrap();
            let (_encryption_key, encryption_pubkey) = generate_x25519_keypair().unwrap();

            let device = Device {
                schema_version: 1,
                id: DeviceId::new(),
                user_id: UserId::new(format!("admin{}", i)),
                name: format!("Admin Device {}", i),
                device_type: DeviceType::Interactive,
                signing_pubkey,
                encryption_pubkey,
                enrolled_at: OffsetDateTime::now_utc(),
                status: DeviceStatus::Active,
                expires_at: None,
            };
            admin_devices.push(device);
        }

        let result = OrgRecoveryKeyOps::create_org_recovery_key(
            org_id,
            3, // 3 of 5 threshold
            &admin_devices,
            device_id,
        );

        assert!(result.is_ok());
        let recovery_key = result.unwrap();
        assert_eq!(recovery_key.org_id, org_id);
        assert_eq!(recovery_key.threshold, 3);
        assert_eq!(recovery_key.total_shares, 5);
        assert_eq!(recovery_key.shares.len(), 5);
    }
}
