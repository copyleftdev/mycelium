//! Local caching for GitHub API responses.
//!
//! This module provides a simple file-based cache for GitHub API responses
//! to reduce API calls and improve performance. The cache stores responses
//! in the profile's cache directory with TTL-based expiration.

use crate::error::{GitHubError, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

/// Time-to-live for cached entries (5 minutes)
const CACHE_TTL: Duration = Duration::from_secs(5 * 60);

/// A cached entry with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheEntry {
    /// The cached data
    data: Vec<u8>,
    /// When the entry was cached
    cached_at: SystemTime,
}

impl CacheEntry {
    /// Creates a new cache entry with the current timestamp
    fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            cached_at: SystemTime::now(),
        }
    }

    /// Checks if the cache entry has expired
    fn is_expired(&self) -> bool {
        match self.cached_at.elapsed() {
            Ok(elapsed) => elapsed > CACHE_TTL,
            Err(_) => true, // If we can't determine elapsed time, consider it expired
        }
    }
}

/// Cache manager for GitHub API responses
///
/// The cache stores responses in the profile's cache directory with a simple
/// file-based structure. Each cached item is stored as a JSON file containing
/// the data and metadata (timestamp).
///
/// Cache entries expire after 5 minutes (TTL) and are automatically invalidated
/// on write operations to ensure consistency.
#[derive(Debug, Clone)]
pub struct Cache {
    cache_dir: PathBuf,
    enabled: bool,
}

impl Cache {
    /// Creates a new cache instance
    ///
    /// # Arguments
    ///
    /// * `cache_dir` - Directory where cache files will be stored
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use myc_github::cache::Cache;
    /// # use std::path::PathBuf;
    /// let cache = Cache::new(PathBuf::from("/path/to/cache"));
    /// ```
    pub fn new(cache_dir: PathBuf) -> Self {
        Self {
            cache_dir,
            enabled: true,
        }
    }

    /// Creates a disabled cache that never stores or retrieves data
    ///
    /// This is useful for testing or when caching should be bypassed.
    pub fn disabled() -> Self {
        Self {
            cache_dir: PathBuf::new(),
            enabled: false,
        }
    }

    /// Checks if the cache is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Ensures the cache directory exists
    fn ensure_cache_dir(&self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        if !self.cache_dir.exists() {
            fs::create_dir_all(&self.cache_dir).map_err(|e| {
                GitHubError::CacheError(format!("Failed to create cache directory: {}", e))
            })?;
        }

        Ok(())
    }

    /// Converts a cache key to a safe filename
    ///
    /// Replaces path separators and special characters with underscores
    fn key_to_filename(key: &str) -> String {
        key.replace(['/', '\\', ':', '*', '?', '"', '<', '>', '|'], "_")
    }

    /// Gets the path for a cache file
    fn cache_file_path(&self, key: &str) -> PathBuf {
        let filename = format!("{}.json", Self::key_to_filename(key));
        self.cache_dir.join(filename)
    }

    /// Retrieves data from the cache
    ///
    /// Returns `None` if the key doesn't exist or the entry has expired.
    ///
    /// # Arguments
    ///
    /// * `key` - The cache key (typically a file path or API endpoint)
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use myc_github::cache::Cache;
    /// # use std::path::PathBuf;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let cache = Cache::new(PathBuf::from("/path/to/cache"));
    /// if let Some(data) = cache.get("path/to/file")? {
    ///     println!("Cache hit!");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        if !self.enabled {
            return Ok(None);
        }

        let path = self.cache_file_path(key);

        if !path.exists() {
            return Ok(None);
        }

        // Read the cache entry
        let json = fs::read_to_string(&path)
            .map_err(|e| GitHubError::CacheError(format!("Failed to read cache file: {}", e)))?;

        let entry: CacheEntry = serde_json::from_str(&json)
            .map_err(|e| GitHubError::CacheError(format!("Failed to parse cache entry: {}", e)))?;

        // Check if expired
        if entry.is_expired() {
            // Remove expired entry
            let _ = fs::remove_file(&path);
            return Ok(None);
        }

        Ok(Some(entry.data))
    }

    /// Stores data in the cache
    ///
    /// # Arguments
    ///
    /// * `key` - The cache key (typically a file path or API endpoint)
    /// * `data` - The data to cache
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use myc_github::cache::Cache;
    /// # use std::path::PathBuf;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let cache = Cache::new(PathBuf::from("/path/to/cache"));
    /// cache.set("path/to/file", b"data".to_vec())?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn set(&self, key: &str, data: Vec<u8>) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        self.ensure_cache_dir()?;

        let entry = CacheEntry::new(data);
        let json = serde_json::to_string(&entry).map_err(|e| {
            GitHubError::CacheError(format!("Failed to serialize cache entry: {}", e))
        })?;

        let path = self.cache_file_path(key);
        fs::write(&path, json)
            .map_err(|e| GitHubError::CacheError(format!("Failed to write cache file: {}", e)))?;

        Ok(())
    }

    /// Invalidates a specific cache entry
    ///
    /// Removes the cached data for the given key. This should be called
    /// after write operations to ensure cache consistency.
    ///
    /// # Arguments
    ///
    /// * `key` - The cache key to invalidate
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use myc_github::cache::Cache;
    /// # use std::path::PathBuf;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let cache = Cache::new(PathBuf::from("/path/to/cache"));
    /// cache.invalidate("path/to/file")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn invalidate(&self, key: &str) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        let path = self.cache_file_path(key);

        if path.exists() {
            fs::remove_file(&path).map_err(|e| {
                GitHubError::CacheError(format!("Failed to remove cache file: {}", e))
            })?;
        }

        Ok(())
    }

    /// Invalidates all cache entries matching a prefix
    ///
    /// This is useful for invalidating related entries, such as all files
    /// in a directory when a write operation occurs.
    ///
    /// # Arguments
    ///
    /// * `prefix` - The key prefix to match
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use myc_github::cache::Cache;
    /// # use std::path::PathBuf;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let cache = Cache::new(PathBuf::from("/path/to/cache"));
    /// // Invalidate all cached files in a directory
    /// cache.invalidate_prefix(".mycelium/projects/")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn invalidate_prefix(&self, prefix: &str) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        if !self.cache_dir.exists() {
            return Ok(());
        }

        let prefix_filename = Self::key_to_filename(prefix);

        // Read all cache files
        let entries = fs::read_dir(&self.cache_dir).map_err(|e| {
            GitHubError::CacheError(format!("Failed to read cache directory: {}", e))
        })?;

        for entry in entries {
            let entry = entry.map_err(|e| {
                GitHubError::CacheError(format!("Failed to read directory entry: {}", e))
            })?;

            let filename = entry.file_name();
            let filename_str = filename.to_string_lossy();

            // Check if filename starts with the prefix
            if filename_str.starts_with(&prefix_filename) {
                let _ = fs::remove_file(entry.path());
            }
        }

        Ok(())
    }

    /// Clears all cache entries
    ///
    /// Removes all cached data. This is useful for cache management commands
    /// or when switching profiles.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use myc_github::cache::Cache;
    /// # use std::path::PathBuf;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let cache = Cache::new(PathBuf::from("/path/to/cache"));
    /// cache.clear()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn clear(&self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        if !self.cache_dir.exists() {
            return Ok(());
        }

        // Remove all files in the cache directory
        let entries = fs::read_dir(&self.cache_dir).map_err(|e| {
            GitHubError::CacheError(format!("Failed to read cache directory: {}", e))
        })?;

        for entry in entries {
            let entry = entry.map_err(|e| {
                GitHubError::CacheError(format!("Failed to read directory entry: {}", e))
            })?;

            if entry.path().is_file() {
                let _ = fs::remove_file(entry.path());
            }
        }

        Ok(())
    }

    /// Gets cache statistics
    ///
    /// Returns information about the cache including number of entries
    /// and total size.
    pub fn stats(&self) -> Result<CacheStats> {
        if !self.enabled {
            return Ok(CacheStats {
                entry_count: 0,
                total_size_bytes: 0,
                expired_count: 0,
            });
        }

        if !self.cache_dir.exists() {
            return Ok(CacheStats {
                entry_count: 0,
                total_size_bytes: 0,
                expired_count: 0,
            });
        }

        let mut entry_count = 0;
        let mut total_size_bytes = 0;
        let mut expired_count = 0;

        let entries = fs::read_dir(&self.cache_dir).map_err(|e| {
            GitHubError::CacheError(format!("Failed to read cache directory: {}", e))
        })?;

        for entry in entries {
            let entry = entry.map_err(|e| {
                GitHubError::CacheError(format!("Failed to read directory entry: {}", e))
            })?;

            let path = entry.path();
            if path.is_file() {
                entry_count += 1;

                if let Ok(metadata) = fs::metadata(&path) {
                    total_size_bytes += metadata.len();
                }

                // Check if expired
                if let Ok(json) = fs::read_to_string(&path) {
                    if let Ok(cache_entry) = serde_json::from_str::<CacheEntry>(&json) {
                        if cache_entry.is_expired() {
                            expired_count += 1;
                        }
                    }
                }
            }
        }

        Ok(CacheStats {
            entry_count,
            total_size_bytes,
            expired_count,
        })
    }

    /// Removes expired cache entries
    ///
    /// Scans the cache directory and removes all expired entries.
    /// This can be called periodically to clean up stale cache data.
    pub fn cleanup_expired(&self) -> Result<usize> {
        if !self.enabled {
            return Ok(0);
        }

        if !self.cache_dir.exists() {
            return Ok(0);
        }

        let mut removed_count = 0;

        let entries = fs::read_dir(&self.cache_dir).map_err(|e| {
            GitHubError::CacheError(format!("Failed to read cache directory: {}", e))
        })?;

        for entry in entries {
            let entry = entry.map_err(|e| {
                GitHubError::CacheError(format!("Failed to read directory entry: {}", e))
            })?;

            let path = entry.path();
            if path.is_file() {
                // Try to read and check if expired
                if let Ok(json) = fs::read_to_string(&path) {
                    if let Ok(cache_entry) = serde_json::from_str::<CacheEntry>(&json) {
                        if cache_entry.is_expired() && fs::remove_file(&path).is_ok() {
                            removed_count += 1;
                        }
                    }
                }
            }
        }

        Ok(removed_count)
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Number of cache entries
    pub entry_count: usize,
    /// Total size of cached data in bytes
    pub total_size_bytes: u64,
    /// Number of expired entries
    pub expired_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_cache_set_and_get() {
        let temp_dir = TempDir::new().unwrap();
        let cache = Cache::new(temp_dir.path().to_path_buf());

        let key = "test/file.txt";
        let data = b"test data".to_vec();

        // Set data
        cache.set(key, data.clone()).unwrap();

        // Get data
        let retrieved = cache.get(key).unwrap();
        assert_eq!(retrieved, Some(data));
    }

    #[test]
    fn test_cache_miss() {
        let temp_dir = TempDir::new().unwrap();
        let cache = Cache::new(temp_dir.path().to_path_buf());

        let retrieved = cache.get("nonexistent").unwrap();
        assert_eq!(retrieved, None);
    }

    #[test]
    fn test_cache_invalidate() {
        let temp_dir = TempDir::new().unwrap();
        let cache = Cache::new(temp_dir.path().to_path_buf());

        let key = "test/file.txt";
        let data = b"test data".to_vec();

        // Set and verify
        cache.set(key, data.clone()).unwrap();
        assert!(cache.get(key).unwrap().is_some());

        // Invalidate
        cache.invalidate(key).unwrap();

        // Should be gone
        assert_eq!(cache.get(key).unwrap(), None);
    }

    #[test]
    fn test_cache_invalidate_prefix() {
        let temp_dir = TempDir::new().unwrap();
        let cache = Cache::new(temp_dir.path().to_path_buf());

        // Set multiple entries
        cache
            .set("projects/1/file1.txt", b"data1".to_vec())
            .unwrap();
        cache
            .set("projects/1/file2.txt", b"data2".to_vec())
            .unwrap();
        cache
            .set("projects/2/file1.txt", b"data3".to_vec())
            .unwrap();
        cache.set("other/file.txt", b"data4".to_vec()).unwrap();

        // Invalidate prefix
        cache.invalidate_prefix("projects/1/").unwrap();

        // Check results
        assert_eq!(cache.get("projects/1/file1.txt").unwrap(), None);
        assert_eq!(cache.get("projects/1/file2.txt").unwrap(), None);
        assert!(cache.get("projects/2/file1.txt").unwrap().is_some());
        assert!(cache.get("other/file.txt").unwrap().is_some());
    }

    #[test]
    fn test_cache_clear() {
        let temp_dir = TempDir::new().unwrap();
        let cache = Cache::new(temp_dir.path().to_path_buf());

        // Set multiple entries
        cache.set("file1.txt", b"data1".to_vec()).unwrap();
        cache.set("file2.txt", b"data2".to_vec()).unwrap();
        cache.set("file3.txt", b"data3".to_vec()).unwrap();

        // Clear all
        cache.clear().unwrap();

        // All should be gone
        assert_eq!(cache.get("file1.txt").unwrap(), None);
        assert_eq!(cache.get("file2.txt").unwrap(), None);
        assert_eq!(cache.get("file3.txt").unwrap(), None);
    }

    #[test]
    fn test_cache_expiration() {
        let temp_dir = TempDir::new().unwrap();
        let cache = Cache::new(temp_dir.path().to_path_buf());

        let key = "test/file.txt";
        let data = b"test data".to_vec();

        // Create an expired entry manually
        let entry = CacheEntry {
            data: data.clone(),
            cached_at: SystemTime::now() - Duration::from_secs(10 * 60), // 10 minutes ago
        };

        let json = serde_json::to_string(&entry).unwrap();
        let path = cache.cache_file_path(key);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, json).unwrap();

        // Should return None for expired entry
        assert_eq!(cache.get(key).unwrap(), None);

        // File should be removed
        assert!(!path.exists());
    }

    #[test]
    fn test_cache_disabled() {
        let cache = Cache::disabled();

        assert!(!cache.is_enabled());

        // Operations should succeed but do nothing
        cache.set("key", b"data".to_vec()).unwrap();
        assert_eq!(cache.get("key").unwrap(), None);

        cache.invalidate("key").unwrap();
        cache.clear().unwrap();
    }

    #[test]
    fn test_cache_stats() {
        let temp_dir = TempDir::new().unwrap();
        let cache = Cache::new(temp_dir.path().to_path_buf());

        // Initially empty
        let stats = cache.stats().unwrap();
        assert_eq!(stats.entry_count, 0);
        assert_eq!(stats.total_size_bytes, 0);

        // Add some entries
        cache.set("file1.txt", b"data1".to_vec()).unwrap();
        cache.set("file2.txt", b"data2".to_vec()).unwrap();

        let stats = cache.stats().unwrap();
        assert_eq!(stats.entry_count, 2);
        assert!(stats.total_size_bytes > 0);
    }

    #[test]
    fn test_cache_cleanup_expired() {
        let temp_dir = TempDir::new().unwrap();
        let cache = Cache::new(temp_dir.path().to_path_buf());

        // Add a fresh entry
        cache.set("fresh.txt", b"fresh data".to_vec()).unwrap();

        // Add an expired entry manually
        let expired_entry = CacheEntry {
            data: b"expired data".to_vec(),
            cached_at: SystemTime::now() - Duration::from_secs(10 * 60),
        };
        let json = serde_json::to_string(&expired_entry).unwrap();
        let path = cache.cache_file_path("expired.txt");
        fs::write(&path, json).unwrap();

        // Cleanup
        let removed = cache.cleanup_expired().unwrap();
        assert_eq!(removed, 1);

        // Fresh entry should still exist
        assert!(cache.get("fresh.txt").unwrap().is_some());

        // Expired entry should be gone
        assert_eq!(cache.get("expired.txt").unwrap(), None);
    }

    #[test]
    fn test_key_to_filename() {
        assert_eq!(Cache::key_to_filename("simple"), "simple");
        assert_eq!(Cache::key_to_filename("path/to/file"), "path_to_file");
        assert_eq!(
            Cache::key_to_filename("C:\\Windows\\file"),
            "C__Windows_file"
        );
        assert_eq!(
            Cache::key_to_filename("file:with:colons"),
            "file_with_colons"
        );
        assert_eq!(
            Cache::key_to_filename("file*with?special<chars>"),
            "file_with_special_chars_"
        );
    }

    #[test]
    fn test_cache_multiple_operations() {
        let temp_dir = TempDir::new().unwrap();
        let cache = Cache::new(temp_dir.path().to_path_buf());

        // Set multiple entries
        for i in 0..10 {
            let key = format!("file{}.txt", i);
            let data = format!("data{}", i).into_bytes();
            cache.set(&key, data).unwrap();
        }

        // Verify all exist
        for i in 0..10 {
            let key = format!("file{}.txt", i);
            assert!(cache.get(&key).unwrap().is_some());
        }

        // Invalidate some
        for i in 0..5 {
            let key = format!("file{}.txt", i);
            cache.invalidate(&key).unwrap();
        }

        // Verify correct ones remain
        for i in 0..5 {
            let key = format!("file{}.txt", i);
            assert_eq!(cache.get(&key).unwrap(), None);
        }
        for i in 5..10 {
            let key = format!("file{}.txt", i);
            assert!(cache.get(&key).unwrap().is_some());
        }
    }

    #[test]
    fn test_cache_entry_expiration_check() {
        // Fresh entry
        let fresh = CacheEntry::new(b"data".to_vec());
        assert!(!fresh.is_expired());

        // Expired entry
        let expired = CacheEntry {
            data: b"data".to_vec(),
            cached_at: SystemTime::now() - Duration::from_secs(10 * 60),
        };
        assert!(expired.is_expired());
    }

    #[test]
    fn test_cache_stats_with_expired() {
        let temp_dir = TempDir::new().unwrap();
        let cache = Cache::new(temp_dir.path().to_path_buf());

        // Add fresh entry
        cache.set("fresh.txt", b"fresh".to_vec()).unwrap();

        // Add expired entry manually
        let expired_entry = CacheEntry {
            data: b"expired".to_vec(),
            cached_at: SystemTime::now() - Duration::from_secs(10 * 60),
        };
        let json = serde_json::to_string(&expired_entry).unwrap();
        let path = cache.cache_file_path("expired.txt");
        fs::write(&path, json).unwrap();

        let stats = cache.stats().unwrap();
        assert_eq!(stats.entry_count, 2);
        assert_eq!(stats.expired_count, 1);
    }
}
