//! Integration tests for push command with diff functionality.

use anyhow::Result;
use myc_core::secret_set::SecretEntry;
use std::collections::HashMap;

/// Test helper to create secret entries
fn create_entry(key: &str, value: &str) -> SecretEntry {
    SecretEntry {
        key: key.to_string(),
        value: value.to_string(),
        metadata: None,
    }
}

/// Test the diff computation logic (extracted from main.rs for testing)
fn compute_diff(
    current_entries: &[SecretEntry],
    new_entries: &[SecretEntry],
) -> (Vec<String>, Vec<String>, Vec<String>, Vec<String>) {
    use std::collections::HashSet;

    // Convert to HashMaps for comparison
    let current_map: HashMap<String, String> = current_entries
        .iter()
        .map(|e| (e.key.clone(), e.value.clone()))
        .collect();
    let new_map: HashMap<String, String> = new_entries
        .iter()
        .map(|e| (e.key.clone(), e.value.clone()))
        .collect();

    // Compute diff
    let all_keys: HashSet<String> = current_map.keys().chain(new_map.keys()).cloned().collect();
    let mut added_keys = Vec::new();
    let mut removed_keys = Vec::new();
    let mut changed_keys = Vec::new();
    let mut unchanged_keys = Vec::new();

    for key in all_keys {
        match (current_map.get(&key), new_map.get(&key)) {
            (None, Some(_)) => added_keys.push(key),
            (Some(_), None) => removed_keys.push(key),
            (Some(val1), Some(val2)) => {
                if val1 == val2 {
                    unchanged_keys.push(key);
                } else {
                    changed_keys.push(key);
                }
            }
            (None, None) => unreachable!(), // Key came from one of the maps
        }
    }

    // Sort keys for consistent output
    added_keys.sort();
    removed_keys.sort();
    changed_keys.sort();
    unchanged_keys.sort();

    (added_keys, removed_keys, changed_keys, unchanged_keys)
}

#[test]
fn test_push_diff_integration_scenarios() -> Result<()> {
    // Test scenario 1: First version (empty current)
    let current = vec![];
    let new = vec![
        create_entry("API_KEY", "secret123"),
        create_entry("DB_URL", "postgres://localhost"),
    ];

    let (added, removed, changed, unchanged) = compute_diff(&current, &new);
    assert_eq!(added.len(), 2);
    assert_eq!(removed.len(), 0);
    assert_eq!(changed.len(), 0);
    assert_eq!(unchanged.len(), 0);

    // Test scenario 2: Update with mixed changes
    let current = vec![
        create_entry("API_KEY", "secret123"),
        create_entry("DB_URL", "postgres://localhost"),
        create_entry("OLD_CONFIG", "old_value"),
    ];
    let new = vec![
        create_entry("API_KEY", "newsecret456"),        // changed
        create_entry("DB_URL", "postgres://localhost"), // unchanged
        create_entry("NEW_CONFIG", "new_value"),        // added
                                                        // OLD_CONFIG removed
    ];

    let (added, removed, changed, unchanged) = compute_diff(&current, &new);
    assert_eq!(added, vec!["NEW_CONFIG"]);
    assert_eq!(removed, vec!["OLD_CONFIG"]);
    assert_eq!(changed, vec!["API_KEY"]);
    assert_eq!(unchanged, vec!["DB_URL"]);

    // Test scenario 3: No changes
    let current = vec![
        create_entry("API_KEY", "secret123"),
        create_entry("DB_URL", "postgres://localhost"),
    ];
    let new = current.clone();

    let (added, removed, changed, unchanged) = compute_diff(&current, &new);
    assert_eq!(added.len(), 0);
    assert_eq!(removed.len(), 0);
    assert_eq!(changed.len(), 0);
    assert_eq!(unchanged.len(), 2);

    Ok(())
}

#[test]
fn test_diff_summary_calculation() -> Result<()> {
    let current = vec![
        create_entry("KEEP", "value1"),
        create_entry("CHANGE", "old_value"),
        create_entry("REMOVE", "remove_me"),
    ];
    let new = vec![
        create_entry("KEEP", "value1"),
        create_entry("CHANGE", "new_value"),
        create_entry("ADD", "add_me"),
    ];

    let (added, removed, changed, unchanged) = compute_diff(&current, &new);

    let total_changes = added.len() + removed.len() + changed.len();
    assert_eq!(total_changes, 3); // 1 added + 1 removed + 1 changed
    assert_eq!(unchanged.len(), 1); // 1 unchanged

    // Verify specific changes
    assert_eq!(added, vec!["ADD"]);
    assert_eq!(removed, vec!["REMOVE"]);
    assert_eq!(changed, vec!["CHANGE"]);
    assert_eq!(unchanged, vec!["KEEP"]);

    Ok(())
}

#[test]
fn test_diff_edge_cases() -> Result<()> {
    // Test with empty values
    let current = vec![
        create_entry("EMPTY_KEY", ""),
        create_entry("NORMAL_KEY", "value"),
    ];
    let new = vec![
        create_entry("EMPTY_KEY", "now_has_value"),
        create_entry("NORMAL_KEY", ""),
    ];

    let (added, removed, changed, unchanged) = compute_diff(&current, &new);
    assert_eq!(added.len(), 0);
    assert_eq!(removed.len(), 0);
    assert_eq!(changed.len(), 2); // Both keys changed
    assert_eq!(unchanged.len(), 0);

    // Test with special characters in keys and values
    let current = vec![
        create_entry("KEY_WITH_UNDERSCORE", "value1"),
        create_entry("KEY-WITH-DASH", "value2"),
    ];
    let new = vec![
        create_entry("KEY_WITH_UNDERSCORE", "value1"),
        create_entry("KEY-WITH-DASH", "new_value2"),
        create_entry("NEW_KEY_123", "value3"),
    ];

    let (added, removed, changed, unchanged) = compute_diff(&current, &new);
    assert_eq!(added, vec!["NEW_KEY_123"]);
    assert_eq!(removed.len(), 0);
    assert_eq!(changed, vec!["KEY-WITH-DASH"]);
    assert_eq!(unchanged, vec!["KEY_WITH_UNDERSCORE"]);

    Ok(())
}
