//! Property-based tests for serialization.
//!
//! These tests verify that all domain types serialize correctly with:
//! - Schema version presence
//! - RFC 3339 timestamps
//! - Base64 encoding for binary data
//! - Canonical JSON determinism

use myc_core::canonical::to_canonical_json;
use myc_core::device::{Device, DeviceStatus, DeviceType};
use myc_core::ids::{DeviceId, OrgId, ProjectId, SecretSetId, UserId, VersionNumber};
use myc_core::org::{Org, OrgSettings, RotationPolicy};
use myc_core::pdk::{PdkVersion, WrappedPdk};
use myc_core::project::Project;
use myc_core::secret_set::{SecretEntry, SecretSet, SecretSetVersion};
use myc_crypto::hash::hash;
use myc_crypto::kex::generate_x25519_keypair;
use myc_crypto::sign::{generate_ed25519_keypair, sign};
use proptest::prelude::*;
use serde_json::Value;
use time::OffsetDateTime;

// ============================================================================
// Property 10: Schema Version Presence
// ============================================================================

/// Feature: mycelium-cli, Property 10: Schema Version Presence
///
/// For any serialized entity, the JSON SHALL contain "schema_version": 1.
///
/// **Validates: Requirements 4.2**
#[test]
fn property_schema_version_presence() {
    proptest!(|(
        org_name in "[a-zA-Z0-9 ]{1,256}",
        project_name in "[a-zA-Z0-9 ]{1,256}",
        set_name in "[a-zA-Z0-9 ]{1,256}",
        device_name in "[a-zA-Z0-9 ]{1,256}",
    )| {
        // Test Org
        let org = Org::new(org_name.clone(), OrgSettings::default());
        let org_json = serde_json::to_value(&org).unwrap();
        prop_assert_eq!(
            org_json.get("schema_version").and_then(|v| v.as_u64()),
            Some(1),
            "Org should have schema_version: 1"
        );

        // Test Project
        let org_id = OrgId::new();
        let device_id = DeviceId::new();
        let project = Project::new(org_id, project_name.clone(), device_id);
        let project_json = serde_json::to_value(&project).unwrap();
        prop_assert_eq!(
            project_json.get("schema_version").and_then(|v| v.as_u64()),
            Some(1),
            "Project should have schema_version: 1"
        );

        // Test SecretSet
        let project_id = ProjectId::new();
        let set = SecretSet::new(project_id, set_name.clone(), device_id);
        let set_json = serde_json::to_value(&set).unwrap();
        prop_assert_eq!(
            set_json.get("schema_version").and_then(|v| v.as_u64()),
            Some(1),
            "SecretSet should have schema_version: 1"
        );

        // Test Device
        let user_id = UserId::from("github|12345678");
        let (_, signing_pubkey) = generate_ed25519_keypair().unwrap();
        let (_, encryption_pubkey) = generate_x25519_keypair().unwrap();
        let device = Device::new(
            user_id,
            device_name.clone(),
            DeviceType::Interactive,
            signing_pubkey,
            encryption_pubkey,
            DeviceStatus::Active,
            None,
        );
        let device_json = serde_json::to_value(&device).unwrap();
        prop_assert_eq!(
            device_json.get("schema_version").and_then(|v| v.as_u64()),
            Some(1),
            "Device should have schema_version: 1"
        );

        // Test SecretSetVersion
        let set_id = SecretSetId::new();
        let content_hash = hash(b"test content");
        let (secret_key, _) = generate_ed25519_keypair().unwrap();
        let signature = sign(&secret_key, b"test message");
        let version = SecretSetVersion {
            schema_version: SecretSetVersion::SCHEMA_VERSION,
            set_id,
            version: VersionNumber::FIRST,
            pdk_version: VersionNumber::FIRST,
            created_at: OffsetDateTime::now_utc(),
            created_by: device_id,
            message: Some("Test".to_string()),
            content_hash,
            previous_hash: None,
            ciphertext: vec![1, 2, 3],
            signature,
        };
        let version_json = serde_json::to_value(&version).unwrap();
        prop_assert_eq!(
            version_json.get("schema_version").and_then(|v| v.as_u64()),
            Some(1),
            "SecretSetVersion should have schema_version: 1"
        );
    });
}

// ============================================================================
// Property 11: Serialization Format Compliance
// ============================================================================

/// Feature: mycelium-cli, Property 11: Serialization Format Compliance
///
/// For any entity with timestamps and binary data, serialized JSON SHALL use
/// RFC 3339 for timestamps and base64 for binary.
///
/// **Validates: Requirements 4.3**
#[test]
fn property_serialization_format_compliance() {
    proptest!(|(
        org_name in "[a-zA-Z0-9 ]{1,256}",
    )| {
        // Test timestamp format (RFC 3339)
        let org = Org::new(org_name.clone(), OrgSettings::default());
        let org_json = serde_json::to_value(&org).unwrap();

        let created_at_str = org_json
            .get("created_at")
            .and_then(|v| v.as_str())
            .expect("created_at should be a string");

        // Verify it's a valid RFC 3339 timestamp
        let parsed = OffsetDateTime::parse(
            created_at_str,
            &time::format_description::well_known::Rfc3339
        );
        prop_assert!(
            parsed.is_ok(),
            "Timestamp should be valid RFC 3339 format: {}",
            created_at_str
        );

        // Test binary data format (base64)
        let device_id = DeviceId::new();
        let (_, signing_pubkey) = generate_ed25519_keypair().unwrap();
        let (_, encryption_pubkey) = generate_x25519_keypair().unwrap();
        let user_id = UserId::from("github|12345678");
        let device = Device::new(
            user_id,
            "Test Device".to_string(),
            DeviceType::Interactive,
            signing_pubkey,
            encryption_pubkey,
            DeviceStatus::Active,
            None,
        );
        let device_json = serde_json::to_value(&device).unwrap();

        // Verify signing_pubkey is base64
        let signing_pubkey_str = device_json
            .get("signing_pubkey")
            .and_then(|v| v.as_str())
            .expect("signing_pubkey should be a string");

        let signing_decoded = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            signing_pubkey_str
        );
        prop_assert!(
            signing_decoded.is_ok(),
            "signing_pubkey should be valid base64"
        );
        prop_assert_eq!(
            signing_decoded.unwrap().len(),
            32,
            "signing_pubkey should decode to 32 bytes"
        );

        // Verify encryption_pubkey is base64
        let encryption_pubkey_str = device_json
            .get("encryption_pubkey")
            .and_then(|v| v.as_str())
            .expect("encryption_pubkey should be a string");

        let encryption_decoded = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            encryption_pubkey_str
        );
        prop_assert!(
            encryption_decoded.is_ok(),
            "encryption_pubkey should be valid base64"
        );
        prop_assert_eq!(
            encryption_decoded.unwrap().len(),
            32,
            "encryption_pubkey should decode to 32 bytes"
        );

        // Test ciphertext is base64 in SecretSetVersion
        let set_id = SecretSetId::new();
        let content_hash = hash(b"test content");
        let (secret_key, _) = generate_ed25519_keypair().unwrap();
        let signature = sign(&secret_key, b"test message");
        let ciphertext = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let version = SecretSetVersion {
            schema_version: SecretSetVersion::SCHEMA_VERSION,
            set_id,
            version: VersionNumber::FIRST,
            pdk_version: VersionNumber::FIRST,
            created_at: OffsetDateTime::now_utc(),
            created_by: device_id,
            message: Some("Test".to_string()),
            content_hash,
            previous_hash: None,
            ciphertext: ciphertext.clone(),
            signature,
        };
        let version_json = serde_json::to_value(&version).unwrap();

        let ciphertext_str = version_json
            .get("ciphertext")
            .and_then(|v| v.as_str())
            .expect("ciphertext should be a string");

        let ciphertext_decoded = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            ciphertext_str
        );
        prop_assert!(
            ciphertext_decoded.is_ok(),
            "ciphertext should be valid base64"
        );
        prop_assert_eq!(
            ciphertext_decoded.unwrap(),
            ciphertext,
            "ciphertext should decode to original bytes"
        );
    });
}

// ============================================================================
// Property 12: Canonical JSON Determinism
// ============================================================================

/// Feature: mycelium-cli, Property 12: Canonical JSON Determinism
///
/// For any data structure, canonical JSON serialization SHALL be deterministic
/// with sorted keys and no whitespace.
///
/// **Validates: Requirements 4.4, 8.1**
#[test]
fn property_canonical_json_determinism() {
    proptest!(|(
        name1 in "[a-zA-Z0-9 ]{1,256}",
        name2 in "[a-zA-Z0-9 ]{1,256}",
    )| {
        // Create a single structure and serialize it twice
        let org_id = OrgId::new();
        let device_id = DeviceId::new();

        let project = Project::new(org_id, name1.clone(), device_id);

        // Serialize the same structure twice
        let json1 = to_canonical_json(&project).unwrap();
        let json2 = to_canonical_json(&project).unwrap();

        // Should produce identical output
        prop_assert_eq!(
            &json1,
            &json2,
            "Same structure should produce identical canonical JSON when serialized multiple times"
        );

        // Verify no whitespace in JSON structure (outside of string values)
        // Check for whitespace after colons and commas, which would indicate formatting
        prop_assert!(
            !json1.contains(": ") && !json1.contains(", ") && !json1.contains('\n') && !json1.contains('\t'),
            "Canonical JSON should contain no structural whitespace (spaces after colons/commas, newlines, tabs)"
        );

        // Verify keys are sorted by parsing and checking order
        let parsed: Value = serde_json::from_str(&json1).unwrap();
        if let Value::Object(map) = parsed {
            let keys: Vec<&String> = map.keys().collect();
            let mut sorted_keys = keys.clone();
            sorted_keys.sort();
            prop_assert_eq!(
                keys,
                sorted_keys,
                "Keys should be sorted alphabetically in canonical JSON"
            );
        }

        // Test that different data produces different canonical JSON
        if name1 != name2 {
            let project2 = Project::new(org_id, name2.clone(), device_id);
            let json3 = to_canonical_json(&project2).unwrap();

            prop_assert_ne!(
                json1,
                json3,
                "Different structures should produce different canonical JSON"
            );
        }
    });
}

/// Test canonical JSON with nested structures
#[test]
fn property_canonical_json_nested_determinism() {
    proptest!(|(
        org_name in "[a-zA-Z0-9 ]{1,256}",
        require_approval in any::<bool>(),
        rotate_on_remove in any::<bool>(),
        rotate_on_revoke in any::<bool>(),
        max_age_days in proptest::option::of(1u32..365),
    )| {
        // Create org with nested settings
        let settings = OrgSettings {
            require_device_approval: require_approval,
            github_org: Some("test-org".to_string()),
            default_rotation_policy: Some(RotationPolicy {
                rotate_on_member_remove: rotate_on_remove,
                rotate_on_device_revoke: rotate_on_revoke,
                max_age_days,
            }),
            network_beacon: "mycelium_spore_network_v1".to_string(),
        };

        let org = Org::new(org_name.clone(), settings);

        // Serialize the same structure twice
        let json1 = to_canonical_json(&org).unwrap();
        let json2 = to_canonical_json(&org).unwrap();

        // Should produce identical output for the same nested structure
        prop_assert_eq!(
            &json1,
            &json2,
            "Same nested structure should produce identical canonical JSON when serialized multiple times"
        );

        // Verify nested keys are also sorted
        let parsed: Value = serde_json::from_str(&json1).unwrap();
        if let Value::Object(map) = parsed {
            if let Some(Value::Object(settings_map)) = map.get("settings") {
                let settings_keys: Vec<&String> = settings_map.keys().collect();
                let mut sorted_settings_keys = settings_keys.clone();
                sorted_settings_keys.sort();
                prop_assert_eq!(
                    settings_keys,
                    sorted_settings_keys,
                    "Nested keys should also be sorted alphabetically"
                );
            }
        }
    });
}

/// Test canonical JSON with arrays (order should be preserved)
#[test]
fn property_canonical_json_array_order_preserved() {
    proptest!(|(
        keys in prop::collection::vec("[A-Z_]{1,20}", 1..10),
        values in prop::collection::vec("[a-z0-9]{1,50}", 1..10),
    )| {
        // Create secret entries (arrays should preserve order)
        let entries: Vec<SecretEntry> = keys
            .iter()
            .zip(values.iter())
            .map(|(k, v)| SecretEntry::new(k.clone(), v.clone()))
            .collect();

        let json1 = to_canonical_json(&entries).unwrap();
        let json2 = to_canonical_json(&entries).unwrap();

        // Should produce identical output
        prop_assert_eq!(
            &json1,
            &json2,
            "Array serialization should be deterministic"
        );

        // Verify array order is preserved
        let parsed: Value = serde_json::from_str(&json1).unwrap();
        if let Value::Array(arr) = parsed {
            for (i, entry) in arr.iter().enumerate() {
                if let Value::Object(map) = entry {
                    let key = map.get("key").and_then(|v| v.as_str()).unwrap();
                    prop_assert_eq!(
                        key,
                        keys[i].as_str(),
                        "Array order should be preserved in canonical JSON"
                    );
                }
            }
        }
    });
}

/// Test serialization roundtrip for all major types
#[test]
fn property_serialization_roundtrip() {
    proptest!(|(
        org_name in "[a-zA-Z0-9 ]{1,256}",
        project_name in "[a-zA-Z0-9 ]{1,256}",
        set_name in "[a-zA-Z0-9 ]{1,256}",
    )| {
        // Test Org roundtrip
        let org = Org::new(org_name.clone(), OrgSettings::default());
        let org_json = serde_json::to_string(&org).unwrap();
        let org_deserialized: Org = serde_json::from_str(&org_json).unwrap();
        prop_assert_eq!(org, org_deserialized, "Org should roundtrip through JSON");

        // Test Project roundtrip
        let org_id = OrgId::new();
        let device_id = DeviceId::new();
        let project = Project::new(org_id, project_name.clone(), device_id);
        let project_json = serde_json::to_string(&project).unwrap();
        let project_deserialized: Project = serde_json::from_str(&project_json).unwrap();
        prop_assert_eq!(project, project_deserialized, "Project should roundtrip through JSON");

        // Test SecretSet roundtrip
        let project_id = ProjectId::new();
        let set = SecretSet::new(project_id, set_name.clone(), device_id);
        let set_json = serde_json::to_string(&set).unwrap();
        let set_deserialized: SecretSet = serde_json::from_str(&set_json).unwrap();
        prop_assert_eq!(set, set_deserialized, "SecretSet should roundtrip through JSON");

        // Test PdkVersion roundtrip
        let (_, ephemeral_pubkey) = generate_x25519_keypair().unwrap();
        let wrapped = WrappedPdk::new(device_id, ephemeral_pubkey, vec![1, 2, 3, 4, 5]);
        let pdk_version = PdkVersion::new(
            VersionNumber::FIRST,
            device_id,
            Some("Test".to_string()),
            vec![wrapped],
        );
        let pdk_json = serde_json::to_string(&pdk_version).unwrap();
        let pdk_deserialized: PdkVersion = serde_json::from_str(&pdk_json).unwrap();
        prop_assert_eq!(pdk_version, pdk_deserialized, "PdkVersion should roundtrip through JSON");
    });
}

// ============================================================================
// Property 26: Secret Serialization Key Sorting
// ============================================================================

/// Feature: mycelium-cli, Property 26: Secret Serialization Key Sorting
///
/// For any secret entries, serialization SHALL sort entries by key alphabetically.
///
/// **Validates: Requirements 8.1**
#[test]
fn property_secret_serialization_key_sorting() {
    use myc_core::secret_set_ops::serialize_secrets;

    proptest!(|(
        // Generate a vector of key-value pairs
        keys in prop::collection::vec("[A-Z_][A-Z0-9_]{0,19}", 2..20),
        values in prop::collection::vec("[a-z0-9]{1,50}", 2..20),
    )| {
        // Ensure we have matching keys and values
        let min_len = keys.len().min(values.len());
        let keys = &keys[..min_len];
        let values = &values[..min_len];

        // Create secret entries in random order
        let entries: Vec<SecretEntry> = keys
            .iter()
            .zip(values.iter())
            .map(|(k, v)| SecretEntry::new(k.clone(), v.clone()))
            .collect();

        // Serialize the entries
        let json = serialize_secrets(&entries).unwrap();

        // Parse the JSON to extract the keys in order
        let parsed: Vec<SecretEntry> = serde_json::from_str(&json).unwrap();

        // Extract keys from parsed entries
        let parsed_keys: Vec<&str> = parsed.iter().map(|e| e.key.as_str()).collect();

        // Create expected sorted keys
        let mut expected_keys: Vec<&str> = keys.iter().map(|k| k.as_str()).collect();
        expected_keys.sort();

        // Verify that parsed keys are in sorted order
        prop_assert_eq!(
            &parsed_keys,
            &expected_keys,
            "Secret entries should be sorted by key alphabetically in serialized JSON"
        );

        // Verify that the parsed keys are actually sorted
        for i in 0..parsed_keys.len() - 1 {
            prop_assert!(
                parsed_keys[i] <= parsed_keys[i + 1],
                "Keys should be in alphabetical order: '{}' should come before or equal to '{}'",
                parsed_keys[i],
                parsed_keys[i + 1]
            );
        }

        // Verify determinism: serializing the same entries multiple times produces the same output
        let json2 = serialize_secrets(&entries).unwrap();
        prop_assert_eq!(
            json,
            json2,
            "Serializing the same entries should produce identical output"
        );
    });
}

/// Test that key sorting works correctly with duplicate keys (should preserve all entries)
#[test]
fn property_secret_serialization_handles_duplicates() {
    use myc_core::secret_set_ops::serialize_secrets;

    proptest!(|(
        key in "[A-Z_][A-Z0-9_]{0,19}",
        value1 in "[a-z0-9]{1,50}",
        value2 in "[a-z0-9]{1,50}",
    )| {
        // Create entries with duplicate keys
        let entries = vec![
            SecretEntry::new(key.clone(), value1.clone()),
            SecretEntry::new(key.clone(), value2.clone()),
        ];

        // Serialize should succeed
        let json = serialize_secrets(&entries).unwrap();

        // Parse back
        let parsed: Vec<SecretEntry> = serde_json::from_str(&json).unwrap();

        // Should have both entries
        prop_assert_eq!(
            parsed.len(),
            2,
            "Both entries should be preserved even with duplicate keys"
        );

        // Both should have the same key
        prop_assert_eq!(&parsed[0].key, &key);
        prop_assert_eq!(&parsed[1].key, &key);
    });
}

/// Test that empty entries serialize correctly
#[test]
fn property_secret_serialization_empty() {
    use myc_core::secret_set_ops::serialize_secrets;

    let entries: Vec<SecretEntry> = vec![];
    let json = serialize_secrets(&entries).unwrap();

    assert_eq!(json, "[]", "Empty entries should serialize to empty array");
}

/// Test that single entry serializes correctly
#[test]
fn property_secret_serialization_single() {
    use myc_core::secret_set_ops::serialize_secrets;

    proptest!(|(
        key in "[A-Z_][A-Z0-9_]{0,19}",
        value in "[a-z0-9]{1,50}",
    )| {
        let entries = vec![SecretEntry::new(key.clone(), value.clone())];
        let json = serialize_secrets(&entries).unwrap();

        // Parse back
        let parsed: Vec<SecretEntry> = serde_json::from_str(&json).unwrap();

        prop_assert_eq!(parsed.len(), 1);
        prop_assert_eq!(&parsed[0].key, &key);
        prop_assert_eq!(&parsed[0].value, &value);
    });
}
