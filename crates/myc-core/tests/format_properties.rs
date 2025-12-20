//! Property-based tests for secret format parsing and formatting.

use myc_core::formats::{detect_format_from_path, format_dotenv, parse_dotenv, SecretFormat};
use myc_core::secret_set::SecretEntry;
use proptest::prelude::*;

/// Feature: mycelium-cli, Property 51: Dotenv Parse Roundtrip
///
/// For any valid dotenv file, parsing then formatting SHALL produce equivalent key-value pairs.
///
/// Validates: Requirements 16.1
#[test]
fn property_dotenv_parse_roundtrip() {
    proptest!(|(
        entries in prop::collection::vec(
            (
                // Generate valid dotenv keys (alphanumeric + underscore, starting with letter/underscore)
                prop::string::string_regex(r"[A-Za-z_][A-Za-z0-9_]{0,63}").unwrap(),
                // Generate values that can contain various characters but avoid problematic ones
                prop::string::string_regex(r"[A-Za-z0-9 \-_.,!@#$%^&*()+=\[\]{}|;:/?<>~`]{0,200}").unwrap()
            ),
            1..20
        ).prop_filter("unique keys", |entries| {
            let mut keys = std::collections::HashSet::new();
            entries.iter().all(|(key, _)| keys.insert(key.clone()))
        })
    )| {
        // Convert tuples to SecretEntry objects
        let secret_entries: Vec<SecretEntry> = entries
            .into_iter()
            .map(|(key, value)| SecretEntry::new(key, value))
            .collect();

        // Format the entries as dotenv
        let formatted = format_dotenv(&secret_entries);

        // Parse the formatted dotenv back
        let parsed_entries = parse_dotenv(&formatted)
            .expect("formatted dotenv should parse successfully");

        // Verify we have the same number of entries
        prop_assert_eq!(
            secret_entries.len(),
            parsed_entries.len(),
            "number of entries should be preserved"
        );

        // Create maps for comparison (since order might differ)
        let original_map: std::collections::HashMap<String, String> = secret_entries
            .iter()
            .map(|entry| (entry.key.clone(), entry.value.clone()))
            .collect();

        let parsed_map: std::collections::HashMap<String, String> = parsed_entries
            .iter()
            .map(|entry| (entry.key.clone(), entry.value.clone()))
            .collect();

        // Verify all original entries are preserved
        for (key, value) in &original_map {
            prop_assert!(
                parsed_map.contains_key(key),
                "key '{}' should be preserved", key
            );
            prop_assert_eq!(
                parsed_map.get(key).unwrap(),
                value,
                "value for key '{}' should be preserved", key
            );
        }

        // Verify no extra entries were added
        prop_assert_eq!(
            original_map.len(),
            parsed_map.len(),
            "no extra entries should be added"
        );
    });
}

/// Feature: mycelium-cli, Property 54: Format Auto-Detection
///
/// For any file with extension .env, .json, .sh, or .yaml, the system SHALL correctly detect the format.
///
/// Validates: Requirements 16.7
#[test]
fn property_format_auto_detection() {
    proptest!(|(
        // Generate file paths with supported extensions
        base_name in prop::string::string_regex(r"[a-zA-Z0-9_\-]{1,50}").unwrap(),
        directory_path in prop::option::of(
            prop::string::string_regex(r"[a-zA-Z0-9_\-/]{0,100}").unwrap()
        ),
        extension in prop::sample::select(vec!["env", "json", "sh", "bash", "yaml", "yml"])
    )| {
        // Construct the file path
        let file_path = match directory_path {
            Some(dir) if !dir.is_empty() => format!("{}/{}.{}", dir, base_name, extension),
            _ => format!("{}.{}", base_name, extension),
        };

        // Detect the format
        let detected_format = detect_format_from_path(&file_path);

        // Verify the correct format is detected based on extension
        let expected_format = match extension {
            "env" => Some(SecretFormat::Dotenv),
            "json" => Some(SecretFormat::Json),
            "sh" | "bash" => Some(SecretFormat::Shell),
            "yaml" | "yml" => Some(SecretFormat::Yaml),
            _ => None, // This shouldn't happen with our generator
        };

        prop_assert_eq!(
            detected_format,
            expected_format,
            "format detection should correctly identify format for extension '{}'", extension
        );
    });
}

/// Additional property test for case insensitivity and unsupported extensions
#[test]
fn property_format_detection_edge_cases() {
    proptest!(|(
        base_name in prop::string::string_regex(r"[a-zA-Z0-9_\-]{1,50}").unwrap(),
        extension_case in prop::sample::select(vec![
            ("ENV", Some(SecretFormat::Dotenv)),
            ("Json", Some(SecretFormat::Json)),
            ("SH", Some(SecretFormat::Shell)),
            ("YAML", Some(SecretFormat::Yaml)),
            ("YML", Some(SecretFormat::Yaml)),
            ("txt", None),
            ("log", None),
            ("config", None),
            ("", None),
        ])
    )| {
        let (extension, expected_format) = extension_case;

        // Test with the extension as-is
        let file_path = if extension.is_empty() {
            base_name.clone()
        } else {
            format!("{}.{}", base_name, extension)
        };

        let detected_format = detect_format_from_path(&file_path);

        prop_assert_eq!(
            detected_format,
            expected_format,
            "format detection should handle extension '{}' correctly (case insensitive)", extension
        );
    });
}
