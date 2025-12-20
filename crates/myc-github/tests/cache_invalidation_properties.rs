//! Property-based tests for cache invalidation.
//!
//! These tests verify that the cache correctly invalidates entries on write
//! operations to ensure consistency between cached data and actual state.

use myc_github::cache::Cache;
use proptest::prelude::*;
use tempfile::TempDir;

// ============================================================================
// Property 20: Cache Invalidation on Write
// ============================================================================

/// Feature: mycelium-cli, Property 20: Cache Invalidation on Write
///
/// For any cached data, performing a write operation SHALL invalidate the
/// cache for affected paths.
///
/// **Validates: Requirements 6.6**
#[test]
fn property_cache_invalidation_on_write() {
    proptest!(|(
        path in "[a-z0-9/_]{5,50}\\.json",
        initial_data in prop::collection::vec(any::<u8>(), 1..1000),
        updated_data in prop::collection::vec(any::<u8>(), 1..1000),
    )| {
        // Ensure data is different to simulate a real write
        prop_assume!(initial_data != updated_data);

        let temp_dir = TempDir::new().unwrap();
        let cache = Cache::new(temp_dir.path().to_path_buf());

        // Step 1: Cache initial data
        cache.set(&path, initial_data.clone()).unwrap();

        // Verify data is cached
        let cached = cache.get(&path).unwrap();
        prop_assert_eq!(
            cached,
            Some(initial_data.clone()),
            "Initial data should be cached"
        );

        // Step 2: Simulate a write operation by invalidating the cache
        cache.invalidate(&path).unwrap();

        // Step 3: Verify cache is invalidated
        let after_invalidate = cache.get(&path).unwrap();
        prop_assert_eq!(
            after_invalidate,
            None,
            "Cache should be invalidated after write operation"
        );

        // Step 4: Cache new data (simulating the result of the write)
        cache.set(&path, updated_data.clone()).unwrap();

        // Verify new data is cached
        let new_cached = cache.get(&path).unwrap();
        prop_assert_eq!(
            new_cached,
            Some(updated_data.clone()),
            "New data should be cached after write"
        );
    });
}

/// Test that invalidating a non-existent key doesn't cause errors
#[test]
fn property_invalidate_nonexistent_key() {
    proptest!(|(
        path in "[a-z0-9/_]{5,50}\\.json",
    )| {
        let temp_dir = TempDir::new().unwrap();
        let cache = Cache::new(temp_dir.path().to_path_buf());

        // Invalidating a non-existent key should succeed
        let result = cache.invalidate(&path);
        prop_assert!(
            result.is_ok(),
            "Invalidating non-existent key should not error"
        );

        // Cache should still be empty
        let cached = cache.get(&path).unwrap();
        prop_assert_eq!(
            cached,
            None,
            "Cache should remain empty"
        );
    });
}

/// Test that prefix invalidation affects all matching paths
#[test]
fn property_prefix_invalidation() {
    proptest!(|(
        prefix in "[a-z0-9/_]{3,20}",
        suffixes in prop::collection::vec("[a-z0-9]{3,10}\\.json", 2..10),
        other_paths in prop::collection::vec("[a-z0-9/_]{5,50}\\.json", 1..5),
        data in prop::collection::vec(any::<u8>(), 1..100),
    )| {
        let temp_dir = TempDir::new().unwrap();
        let cache = Cache::new(temp_dir.path().to_path_buf());

        // Create paths with the prefix
        let prefixed_paths: Vec<String> = suffixes
            .iter()
            .map(|suffix| format!("{}/{}", prefix, suffix))
            .collect();

        // Ensure other paths don't start with the prefix
        let filtered_other_paths: Vec<String> = other_paths
            .into_iter()
            .filter(|p| !p.starts_with(&prefix))
            .collect();

        prop_assume!(!filtered_other_paths.is_empty());

        // Cache data for all paths
        for path in &prefixed_paths {
            cache.set(path, data.clone()).unwrap();
        }
        for path in &filtered_other_paths {
            cache.set(path, data.clone()).unwrap();
        }

        // Verify all are cached
        for path in &prefixed_paths {
            prop_assert!(
                cache.get(path).unwrap().is_some(),
                "Prefixed path should be cached"
            );
        }
        for path in &filtered_other_paths {
            prop_assert!(
                cache.get(path).unwrap().is_some(),
                "Other path should be cached"
            );
        }

        // Invalidate by prefix
        cache.invalidate_prefix(&prefix).unwrap();

        // Verify prefixed paths are invalidated
        for path in &prefixed_paths {
            prop_assert_eq!(
                cache.get(path).unwrap(),
                None,
                "Prefixed path should be invalidated"
            );
        }

        // Verify other paths are NOT invalidated
        for path in &filtered_other_paths {
            prop_assert!(
                cache.get(path).unwrap().is_some(),
                "Other path should still be cached"
            );
        }
    });
}

/// Test that multiple invalidations are idempotent
#[test]
fn property_multiple_invalidations_idempotent() {
    proptest!(|(
        path in "[a-z0-9/_]{5,50}\\.json",
        data in prop::collection::vec(any::<u8>(), 1..1000),
        num_invalidations in 1usize..10,
    )| {
        let temp_dir = TempDir::new().unwrap();
        let cache = Cache::new(temp_dir.path().to_path_buf());

        // Cache data
        cache.set(&path, data.clone()).unwrap();
        prop_assert!(cache.get(&path).unwrap().is_some());

        // Invalidate multiple times
        for _ in 0..num_invalidations {
            let result = cache.invalidate(&path);
            prop_assert!(
                result.is_ok(),
                "Each invalidation should succeed"
            );
        }

        // Verify cache is still invalidated
        prop_assert_eq!(
            cache.get(&path).unwrap(),
            None,
            "Cache should remain invalidated after multiple invalidations"
        );
    });
}

/// Test that clear invalidates all cached entries
#[test]
fn property_clear_invalidates_all() {
    proptest!(|(
        paths in prop::collection::vec("[a-z0-9/_]{5,50}\\.json", 1..20),
        data in prop::collection::vec(any::<u8>(), 1..100),
    )| {
        let temp_dir = TempDir::new().unwrap();
        let cache = Cache::new(temp_dir.path().to_path_buf());

        // Deduplicate paths
        let unique_paths: Vec<String> = paths
            .into_iter()
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        prop_assume!(!unique_paths.is_empty());

        // Cache data for all paths
        for path in &unique_paths {
            cache.set(path, data.clone()).unwrap();
        }

        // Verify all are cached
        for path in &unique_paths {
            prop_assert!(
                cache.get(path).unwrap().is_some(),
                "Path should be cached before clear"
            );
        }

        // Clear all cache
        cache.clear().unwrap();

        // Verify all are invalidated
        for path in &unique_paths {
            prop_assert_eq!(
                cache.get(path).unwrap(),
                None,
                "Path should be invalidated after clear"
            );
        }
    });
}

/// Test that cache operations on disabled cache don't error
#[test]
fn property_disabled_cache_operations() {
    proptest!(|(
        path in "[a-z0-9/_]{5,50}\\.json",
        data in prop::collection::vec(any::<u8>(), 1..1000),
    )| {
        let cache = Cache::disabled();

        // All operations should succeed but do nothing
        prop_assert!(cache.set(&path, data.clone()).is_ok());
        prop_assert_eq!(cache.get(&path).unwrap(), None);
        prop_assert!(cache.invalidate(&path).is_ok());
        prop_assert!(cache.clear().is_ok());
    });
}

/// Test that invalidation happens before re-caching
#[test]
fn property_invalidate_then_recache() {
    proptest!(|(
        path in "[a-z0-9/_]{5,50}\\.json",
        data_sequence in prop::collection::vec(
            prop::collection::vec(any::<u8>(), 1..100),
            2..10
        ),
    )| {
        let temp_dir = TempDir::new().unwrap();
        let cache = Cache::new(temp_dir.path().to_path_buf());

        // Ensure all data items are unique
        let unique_data: Vec<_> = data_sequence
            .into_iter()
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        prop_assume!(unique_data.len() >= 2);

        // Simulate multiple write operations
        for data in &unique_data {
            // Cache the data
            cache.set(&path, data.clone()).unwrap();

            // Verify it's cached
            let cached = cache.get(&path).unwrap();
            prop_assert_eq!(
                cached,
                Some(data.clone()),
                "Data should be cached"
            );

            // Simulate write operation (invalidate)
            cache.invalidate(&path).unwrap();

            // Verify it's invalidated
            let after_invalidate = cache.get(&path).unwrap();
            prop_assert_eq!(
                after_invalidate,
                None,
                "Cache should be invalidated after each write"
            );
        }
    });
}

/// Test that partial path matches don't get invalidated
#[test]
fn property_exact_path_invalidation() {
    proptest!(|(
        base_path in "[a-z0-9/_]{5,30}",
        suffix1 in "[a-z0-9]{3,10}\\.json",
        suffix2 in "[a-z0-9]{3,10}\\.json",
        data in prop::collection::vec(any::<u8>(), 1..100),
    )| {
        prop_assume!(suffix1 != suffix2);

        let temp_dir = TempDir::new().unwrap();
        let cache = Cache::new(temp_dir.path().to_path_buf());

        let path1 = format!("{}/{}", base_path, suffix1);
        let path2 = format!("{}/{}", base_path, suffix2);

        // Cache both paths
        cache.set(&path1, data.clone()).unwrap();
        cache.set(&path2, data.clone()).unwrap();

        // Invalidate only path1
        cache.invalidate(&path1).unwrap();

        // Verify path1 is invalidated
        prop_assert_eq!(
            cache.get(&path1).unwrap(),
            None,
            "Invalidated path should not be cached"
        );

        // Verify path2 is still cached
        prop_assert!(
            cache.get(&path2).unwrap().is_some(),
            "Other path should still be cached"
        );
    });
}

/// Test that cache stats reflect invalidations
#[test]
fn property_stats_reflect_invalidations() {
    proptest!(|(
        paths in prop::collection::vec("[a-z0-9/_]{5,50}\\.json", 2..20),
        data in prop::collection::vec(any::<u8>(), 1..100),
        num_to_invalidate in 1usize..10,
    )| {
        let temp_dir = TempDir::new().unwrap();
        let cache = Cache::new(temp_dir.path().to_path_buf());

        // Deduplicate paths
        let unique_paths: Vec<String> = paths
            .into_iter()
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        prop_assume!(unique_paths.len() >= 2);
        let num_to_invalidate = num_to_invalidate.min(unique_paths.len() - 1);

        // Cache all paths
        for path in &unique_paths {
            cache.set(path, data.clone()).unwrap();
        }

        // Get initial stats
        let initial_stats = cache.stats().unwrap();
        prop_assert_eq!(
            initial_stats.entry_count,
            unique_paths.len(),
            "Initial entry count should match number of cached paths"
        );

        // Invalidate some paths
        for path in unique_paths.iter().take(num_to_invalidate) {
            cache.invalidate(path).unwrap();
        }

        // Get stats after invalidation
        let after_stats = cache.stats().unwrap();
        prop_assert_eq!(
            after_stats.entry_count,
            unique_paths.len() - num_to_invalidate,
            "Entry count should decrease after invalidations"
        );
    });
}

/// Test that concurrent invalidations don't cause issues
#[test]
fn property_concurrent_invalidations() {
    proptest!(|(
        path in "[a-z0-9/_]{5,50}\\.json",
        data in prop::collection::vec(any::<u8>(), 1..1000),
        num_operations in 2usize..10,
    )| {
        let temp_dir = TempDir::new().unwrap();
        let cache = Cache::new(temp_dir.path().to_path_buf());

        // Cache initial data
        cache.set(&path, data.clone()).unwrap();

        // Perform multiple invalidations (simulating concurrent operations)
        for _ in 0..num_operations {
            let result = cache.invalidate(&path);
            prop_assert!(
                result.is_ok(),
                "Invalidation should always succeed"
            );
        }

        // Final state should be invalidated
        prop_assert_eq!(
            cache.get(&path).unwrap(),
            None,
            "Cache should be invalidated"
        );
    });
}
