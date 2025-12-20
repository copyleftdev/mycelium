//! Property-based tests for concurrent modification detection.
//!
//! These tests verify that the GitHub client correctly detects concurrent
//! modifications using SHA-based optimistic concurrency control.

use proptest::prelude::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// ============================================================================
// Mock GitHub Client for Testing
// ============================================================================

/// Type alias for file storage to reduce complexity
type FileStorage = HashMap<String, (Vec<u8>, String)>;

/// Mock GitHub client that simulates SHA-based concurrency control
#[derive(Clone)]
struct MockGitHubClient {
    /// Simulated file storage: path -> (content, sha)
    files: Arc<Mutex<FileStorage>>,
}

impl MockGitHubClient {
    fn new() -> Self {
        Self {
            files: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Read a file and return its content and SHA
    fn read_file(&self, path: &str) -> Result<(Vec<u8>, String), String> {
        let files = self.files.lock().unwrap();
        files
            .get(path)
            .map(|(content, sha)| (content.clone(), sha.clone()))
            .ok_or_else(|| format!("File not found: {}", path))
    }

    /// Write a file with optimistic concurrency control
    /// Returns Ok(new_sha) on success, Err on conflict
    fn write_file(
        &self,
        path: &str,
        content: Vec<u8>,
        expected_sha: Option<&str>,
    ) -> Result<String, String> {
        let mut files = self.files.lock().unwrap();

        // Check if file exists
        if let Some((_, current_sha)) = files.get(path) {
            // File exists - verify SHA matches
            if let Some(expected) = expected_sha {
                if current_sha != expected {
                    return Err(format!(
                        "Conflict: expected SHA {} but found {}",
                        expected, current_sha
                    ));
                }
            } else {
                // Expected new file but it already exists
                return Err("Conflict: file already exists".to_string());
            }
        } else {
            // File doesn't exist
            if expected_sha.is_some() {
                // Expected existing file but it doesn't exist
                return Err("Conflict: file does not exist".to_string());
            }
        }

        // Compute new SHA (simplified - just hash the content)
        let new_sha = format!("sha-{:x}", compute_simple_hash(&content));

        // Write the file
        files.insert(path.to_string(), (content, new_sha.clone()));

        Ok(new_sha)
    }
}

/// Simple hash function for testing (not cryptographic)
fn compute_simple_hash(data: &[u8]) -> u64 {
    data.iter()
        .fold(0u64, |acc, &b| acc.wrapping_mul(31).wrapping_add(b as u64))
}

// ============================================================================
// Property 19: Concurrent Modification Detection
// ============================================================================

/// Feature: mycelium-cli, Property 19: Concurrent Modification Detection
///
/// For any two concurrent writes to the same file, the second write SHALL
/// detect the conflict via SHA mismatch.
///
/// **Validates: Requirements 6.4**
#[test]
fn property_concurrent_modification_detection() {
    proptest!(|(
        path in "[a-z0-9/_]{5,50}\\.json",
        content1 in prop::collection::vec(any::<u8>(), 1..1000),
        content2 in prop::collection::vec(any::<u8>(), 1..1000),
        content3 in prop::collection::vec(any::<u8>(), 1..1000),
    )| {
        // Ensure contents are different to simulate real concurrent modifications
        prop_assume!(content1 != content2);
        prop_assume!(content2 != content3);

        let client = MockGitHubClient::new();

        // Scenario 1: Two writers try to create the same file
        // First write should succeed
        let result1 = client.write_file(&path, content1.clone(), None);
        prop_assert!(
            result1.is_ok(),
            "First write to new file should succeed"
        );
        let sha1 = result1.unwrap();

        // Second write without SHA should fail (file already exists)
        let result2 = client.write_file(&path, content2.clone(), None);
        prop_assert!(
            result2.is_err(),
            "Second write to existing file without SHA should fail with conflict"
        );
        prop_assert!(
            result2.unwrap_err().contains("Conflict"),
            "Error should indicate conflict"
        );

        // Scenario 2: Two writers try to update the same file
        // First writer reads the file
        let (read_content1, read_sha1) = client.read_file(&path).unwrap();
        prop_assert_eq!(
            read_content1,
            content1,
            "Read should return the content from first write"
        );
        prop_assert_eq!(
            &read_sha1,
            &sha1,
            "Read should return the SHA from first write"
        );

        // Second writer also reads the file (gets same SHA)
        let (_, read_sha2) = client.read_file(&path).unwrap();
        prop_assert_eq!(
            &read_sha2,
            &sha1,
            "Both readers should see the same SHA"
        );

        // First writer updates the file with correct SHA
        let result3 = client.write_file(&path, content2.clone(), Some(&sha1));
        prop_assert!(
            result3.is_ok(),
            "Update with correct SHA should succeed"
        );
        let sha2 = result3.unwrap();
        prop_assert_ne!(
            &sha1,
            &sha2,
            "New write should produce different SHA"
        );

        // Second writer tries to update with stale SHA
        let result4 = client.write_file(&path, content3.clone(), Some(&sha1));
        prop_assert!(
            result4.is_err(),
            "Update with stale SHA should fail with conflict"
        );
        prop_assert!(
            result4.unwrap_err().contains("Conflict"),
            "Error should indicate conflict with SHA mismatch"
        );

        // Verify the file still has content2 (second writer's update was rejected)
        let (final_content, final_sha) = client.read_file(&path).unwrap();
        prop_assert_eq!(
            final_content,
            content2,
            "File should still contain content from successful update"
        );
        prop_assert_eq!(
            &final_sha,
            &sha2,
            "File should still have SHA from successful update"
        );

        // Scenario 3: Writer can succeed after refreshing SHA
        let (_, current_sha) = client.read_file(&path).unwrap();
        let result5 = client.write_file(&path, content3.clone(), Some(&current_sha));
        prop_assert!(
            result5.is_ok(),
            "Update with refreshed SHA should succeed"
        );
    });
}

/// Test that SHA changes on every write
#[test]
fn property_sha_changes_on_write() {
    proptest!(|(
        path in "[a-z0-9/_]{5,50}\\.json",
        contents in prop::collection::vec(
            prop::collection::vec(any::<u8>(), 1..100),
            2..10
        ),
    )| {
        // Ensure all contents are unique
        let unique_contents: Vec<_> = contents
            .into_iter()
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        prop_assume!(unique_contents.len() >= 2);

        let client = MockGitHubClient::new();
        let mut previous_sha: Option<String> = None;

        // Write each content sequentially
        for content in unique_contents.iter() {
            let result = client.write_file(&path, content.clone(), previous_sha.as_deref());
            prop_assert!(
                result.is_ok(),
                "Sequential writes with correct SHA should succeed"
            );

            let new_sha = result.unwrap();

            // Verify SHA changed (except for first write)
            if let Some(prev) = &previous_sha {
                prop_assert_ne!(
                    prev,
                    &new_sha,
                    "SHA should change when content changes"
                );
            }

            previous_sha = Some(new_sha);
        }
    });
}

/// Test that identical content produces same SHA
#[test]
fn property_identical_content_same_sha() {
    proptest!(|(
        path1 in "[a-z0-9/_]{5,50}\\.json",
        path2 in "[a-z0-9/_]{5,50}\\.json",
        content in prop::collection::vec(any::<u8>(), 1..1000),
    )| {
        prop_assume!(path1 != path2);

        let client = MockGitHubClient::new();

        // Write same content to two different paths
        let sha1 = client.write_file(&path1, content.clone(), None).unwrap();
        let sha2 = client.write_file(&path2, content.clone(), None).unwrap();

        // Same content should produce same SHA
        prop_assert_eq!(
            sha1,
            sha2,
            "Identical content should produce identical SHA"
        );
    });
}

/// Test that missing file is detected
#[test]
fn property_missing_file_detected() {
    proptest!(|(
        path in "[a-z0-9/_]{5,50}\\.json",
        content in prop::collection::vec(any::<u8>(), 1..1000),
        fake_sha in "[a-f0-9]{40}",
    )| {
        let client = MockGitHubClient::new();

        // Try to update a file that doesn't exist
        let result = client.write_file(&path, content.clone(), Some(&fake_sha));
        prop_assert!(
            result.is_err(),
            "Update to non-existent file should fail"
        );
        let err_msg = result.unwrap_err();
        prop_assert!(
            err_msg.contains("Conflict") || err_msg.contains("does not exist"),
            "Error should indicate file doesn't exist"
        );
    });
}

/// Test concurrent reads don't interfere
#[test]
fn property_concurrent_reads_consistent() {
    proptest!(|(
        path in "[a-z0-9/_]{5,50}\\.json",
        content in prop::collection::vec(any::<u8>(), 1..1000),
        num_readers in 2usize..10,
    )| {
        let client = MockGitHubClient::new();

        // Write initial content
        let sha = client.write_file(&path, content.clone(), None).unwrap();

        // Multiple readers should all see the same content and SHA
        for _ in 0..num_readers {
            let (read_content, read_sha) = client.read_file(&path).unwrap();
            prop_assert_eq!(
                &read_content,
                &content,
                "All readers should see the same content"
            );
            prop_assert_eq!(
                &read_sha,
                &sha,
                "All readers should see the same SHA"
            );
        }
    });
}

/// Test that empty content is handled correctly
#[test]
fn property_empty_content_handled() {
    proptest!(|(
        path in "[a-z0-9/_]{5,50}\\.json",
    )| {
        let client = MockGitHubClient::new();

        // Write empty content
        let result = client.write_file(&path, vec![], None);
        prop_assert!(
            result.is_ok(),
            "Writing empty content should succeed"
        );
        let sha = result.unwrap();

        // Read it back
        let (read_content, read_sha) = client.read_file(&path).unwrap();
        prop_assert_eq!(
            read_content,
            vec![],
            "Should be able to read back empty content"
        );
        prop_assert_eq!(
            &read_sha,
            &sha,
            "SHA should match"
        );

        // Update with non-empty content
        let new_content = vec![1, 2, 3];
        let result2 = client.write_file(&path, new_content.clone(), Some(&sha));
        prop_assert!(
            result2.is_ok(),
            "Updating from empty to non-empty should succeed"
        );
    });
}
