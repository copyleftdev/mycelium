//! In-memory PDK cache.
//!
//! This module provides a simple in-memory cache for unwrapped PDKs.
//! PDKs are cached only in memory and never written to disk. The cache
//! is cleared on profile switch to ensure proper isolation.

use crate::ids::{ProjectId, VersionNumber};
use myc_crypto::aead::AeadKey;
use std::collections::HashMap;

/// A cache key identifying a specific PDK version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PdkCacheKey {
    /// The project ID.
    pub project_id: ProjectId,
    /// The PDK version number.
    pub version: VersionNumber,
}

impl PdkCacheKey {
    /// Creates a new cache key.
    ///
    /// # Arguments
    ///
    /// * `project_id` - The project ID
    /// * `version` - The PDK version number
    ///
    /// # Returns
    ///
    /// A new `PdkCacheKey` instance
    pub fn new(project_id: ProjectId, version: VersionNumber) -> Self {
        Self {
            project_id,
            version,
        }
    }
}

/// An in-memory cache for unwrapped PDKs.
///
/// This cache stores PDKs only in memory and never persists them to disk.
/// All PDKs are automatically zeroized when the cache is dropped.
///
/// # Security
///
/// - PDKs are stored only in memory
/// - PDKs are zeroized on drop (via `AeadKey`'s `ZeroizeOnDrop`)
/// - Cache must be cleared on profile switch
pub struct PdkCache {
    cache: HashMap<PdkCacheKey, AeadKey>,
}

impl PdkCache {
    /// Creates a new empty PDK cache.
    ///
    /// # Returns
    ///
    /// A new `PdkCache` instance
    ///
    /// # Examples
    ///
    /// ```
    /// use myc_core::pdk_cache::PdkCache;
    ///
    /// let cache = PdkCache::new();
    /// ```
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }

    /// Retrieves a PDK from the cache.
    ///
    /// # Arguments
    ///
    /// * `key` - The cache key identifying the PDK
    ///
    /// # Returns
    ///
    /// `Some(&AeadKey)` if the PDK is cached, `None` otherwise
    ///
    /// # Examples
    ///
    /// ```
    /// use myc_core::pdk_cache::{PdkCache, PdkCacheKey};
    /// use myc_core::ids::{ProjectId, VersionNumber};
    /// use myc_core::pdk_ops::generate_pdk;
    ///
    /// let mut cache = PdkCache::new();
    /// let project_id = ProjectId::new();
    /// let key = PdkCacheKey::new(project_id, VersionNumber::FIRST);
    ///
    /// let pdk = generate_pdk().unwrap();
    /// cache.insert(key, pdk);
    ///
    /// assert!(cache.get(&key).is_some());
    /// ```
    pub fn get(&self, key: &PdkCacheKey) -> Option<&AeadKey> {
        self.cache.get(key)
    }

    /// Inserts a PDK into the cache.
    ///
    /// If a PDK with the same key already exists, it is replaced and
    /// the old PDK is zeroized.
    ///
    /// # Arguments
    ///
    /// * `key` - The cache key identifying the PDK
    /// * `pdk` - The PDK to cache
    ///
    /// # Examples
    ///
    /// ```
    /// use myc_core::pdk_cache::{PdkCache, PdkCacheKey};
    /// use myc_core::ids::{ProjectId, VersionNumber};
    /// use myc_core::pdk_ops::generate_pdk;
    ///
    /// let mut cache = PdkCache::new();
    /// let project_id = ProjectId::new();
    /// let key = PdkCacheKey::new(project_id, VersionNumber::FIRST);
    ///
    /// let pdk = generate_pdk().unwrap();
    /// cache.insert(key, pdk);
    /// ```
    pub fn insert(&mut self, key: PdkCacheKey, pdk: AeadKey) {
        self.cache.insert(key, pdk);
    }

    /// Removes a PDK from the cache.
    ///
    /// The removed PDK is zeroized.
    ///
    /// # Arguments
    ///
    /// * `key` - The cache key identifying the PDK to remove
    ///
    /// # Returns
    ///
    /// `Some(AeadKey)` if the PDK was cached, `None` otherwise
    ///
    /// # Examples
    ///
    /// ```
    /// use myc_core::pdk_cache::{PdkCache, PdkCacheKey};
    /// use myc_core::ids::{ProjectId, VersionNumber};
    /// use myc_core::pdk_ops::generate_pdk;
    ///
    /// let mut cache = PdkCache::new();
    /// let project_id = ProjectId::new();
    /// let key = PdkCacheKey::new(project_id, VersionNumber::FIRST);
    ///
    /// let pdk = generate_pdk().unwrap();
    /// cache.insert(key, pdk);
    ///
    /// assert!(cache.remove(&key).is_some());
    /// assert!(cache.get(&key).is_none());
    /// ```
    pub fn remove(&mut self, key: &PdkCacheKey) -> Option<AeadKey> {
        self.cache.remove(key)
    }

    /// Clears all PDKs from the cache.
    ///
    /// All cached PDKs are zeroized. This should be called when switching
    /// profiles to ensure proper isolation.
    ///
    /// # Examples
    ///
    /// ```
    /// use myc_core::pdk_cache::{PdkCache, PdkCacheKey};
    /// use myc_core::ids::{ProjectId, VersionNumber};
    /// use myc_core::pdk_ops::generate_pdk;
    ///
    /// let mut cache = PdkCache::new();
    /// let project_id = ProjectId::new();
    /// let key = PdkCacheKey::new(project_id, VersionNumber::FIRST);
    ///
    /// let pdk = generate_pdk().unwrap();
    /// cache.insert(key, pdk);
    ///
    /// cache.clear();
    /// assert!(cache.get(&key).is_none());
    /// ```
    pub fn clear(&mut self) {
        self.cache.clear();
    }

    /// Returns the number of cached PDKs.
    ///
    /// # Returns
    ///
    /// The number of PDKs in the cache
    ///
    /// # Examples
    ///
    /// ```
    /// use myc_core::pdk_cache::{PdkCache, PdkCacheKey};
    /// use myc_core::ids::{ProjectId, VersionNumber};
    /// use myc_core::pdk_ops::generate_pdk;
    ///
    /// let mut cache = PdkCache::new();
    /// assert_eq!(cache.len(), 0);
    ///
    /// let project_id = ProjectId::new();
    /// let key = PdkCacheKey::new(project_id, VersionNumber::FIRST);
    /// let pdk = generate_pdk().unwrap();
    /// cache.insert(key, pdk);
    ///
    /// assert_eq!(cache.len(), 1);
    /// ```
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Returns `true` if the cache is empty.
    ///
    /// # Returns
    ///
    /// `true` if the cache contains no PDKs, `false` otherwise
    ///
    /// # Examples
    ///
    /// ```
    /// use myc_core::pdk_cache::PdkCache;
    ///
    /// let cache = PdkCache::new();
    /// assert!(cache.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }
}

impl Default for PdkCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdk_ops::generate_pdk;

    #[test]
    fn test_pdk_cache_new() {
        let cache = PdkCache::new();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_pdk_cache_insert_and_get() {
        let mut cache = PdkCache::new();
        let project_id = ProjectId::new();
        let key = PdkCacheKey::new(project_id, VersionNumber::FIRST);

        let pdk = generate_pdk().unwrap();
        let pdk_bytes = *pdk.as_bytes();

        cache.insert(key, pdk);

        assert_eq!(cache.len(), 1);
        assert!(!cache.is_empty());

        let cached_pdk = cache.get(&key).unwrap();
        assert_eq!(cached_pdk.as_bytes(), &pdk_bytes);
    }

    #[test]
    fn test_pdk_cache_get_nonexistent() {
        let cache = PdkCache::new();
        let project_id = ProjectId::new();
        let key = PdkCacheKey::new(project_id, VersionNumber::FIRST);

        assert!(cache.get(&key).is_none());
    }

    #[test]
    fn test_pdk_cache_insert_replace() {
        let mut cache = PdkCache::new();
        let project_id = ProjectId::new();
        let key = PdkCacheKey::new(project_id, VersionNumber::FIRST);

        let pdk1 = generate_pdk().unwrap();
        cache.insert(key, pdk1);

        let pdk2 = generate_pdk().unwrap();
        let pdk2_bytes = *pdk2.as_bytes();
        cache.insert(key, pdk2);

        // Should have replaced the old PDK
        assert_eq!(cache.len(), 1);
        let cached_pdk = cache.get(&key).unwrap();
        assert_eq!(cached_pdk.as_bytes(), &pdk2_bytes);
    }

    #[test]
    fn test_pdk_cache_remove() {
        let mut cache = PdkCache::new();
        let project_id = ProjectId::new();
        let key = PdkCacheKey::new(project_id, VersionNumber::FIRST);

        let pdk = generate_pdk().unwrap();
        cache.insert(key, pdk);

        assert!(cache.remove(&key).is_some());
        assert!(cache.get(&key).is_none());
        assert!(cache.is_empty());
    }

    #[test]
    fn test_pdk_cache_remove_nonexistent() {
        let mut cache = PdkCache::new();
        let project_id = ProjectId::new();
        let key = PdkCacheKey::new(project_id, VersionNumber::FIRST);

        assert!(cache.remove(&key).is_none());
    }

    #[test]
    fn test_pdk_cache_clear() {
        let mut cache = PdkCache::new();

        let project1_id = ProjectId::new();
        let key1 = PdkCacheKey::new(project1_id, VersionNumber::FIRST);
        cache.insert(key1, generate_pdk().unwrap());

        let project2_id = ProjectId::new();
        let key2 = PdkCacheKey::new(project2_id, VersionNumber::FIRST);
        cache.insert(key2, generate_pdk().unwrap());

        assert_eq!(cache.len(), 2);

        cache.clear();

        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
        assert!(cache.get(&key1).is_none());
        assert!(cache.get(&key2).is_none());
    }

    #[test]
    fn test_pdk_cache_multiple_projects() {
        let mut cache = PdkCache::new();

        let project1_id = ProjectId::new();
        let project2_id = ProjectId::new();

        let key1 = PdkCacheKey::new(project1_id, VersionNumber::FIRST);
        let key2 = PdkCacheKey::new(project2_id, VersionNumber::FIRST);

        let pdk1 = generate_pdk().unwrap();
        let pdk1_bytes = *pdk1.as_bytes();
        cache.insert(key1, pdk1);

        let pdk2 = generate_pdk().unwrap();
        let pdk2_bytes = *pdk2.as_bytes();
        cache.insert(key2, pdk2);

        assert_eq!(cache.len(), 2);

        let cached_pdk1 = cache.get(&key1).unwrap();
        let cached_pdk2 = cache.get(&key2).unwrap();

        assert_eq!(cached_pdk1.as_bytes(), &pdk1_bytes);
        assert_eq!(cached_pdk2.as_bytes(), &pdk2_bytes);
    }

    #[test]
    fn test_pdk_cache_multiple_versions() {
        let mut cache = PdkCache::new();
        let project_id = ProjectId::new();

        let key_v1 = PdkCacheKey::new(project_id, VersionNumber::FIRST);
        let key_v2 = PdkCacheKey::new(project_id, VersionNumber::new(2));

        let pdk_v1 = generate_pdk().unwrap();
        let pdk_v1_bytes = *pdk_v1.as_bytes();
        cache.insert(key_v1, pdk_v1);

        let pdk_v2 = generate_pdk().unwrap();
        let pdk_v2_bytes = *pdk_v2.as_bytes();
        cache.insert(key_v2, pdk_v2);

        assert_eq!(cache.len(), 2);

        let cached_pdk_v1 = cache.get(&key_v1).unwrap();
        let cached_pdk_v2 = cache.get(&key_v2).unwrap();

        assert_eq!(cached_pdk_v1.as_bytes(), &pdk_v1_bytes);
        assert_eq!(cached_pdk_v2.as_bytes(), &pdk_v2_bytes);
    }

    #[test]
    fn test_pdk_cache_key_equality() {
        let project_id = ProjectId::new();
        let key1 = PdkCacheKey::new(project_id, VersionNumber::FIRST);
        let key2 = PdkCacheKey::new(project_id, VersionNumber::FIRST);

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_pdk_cache_key_inequality() {
        let project_id1 = ProjectId::new();
        let project_id2 = ProjectId::new();

        let key1 = PdkCacheKey::new(project_id1, VersionNumber::FIRST);
        let key2 = PdkCacheKey::new(project_id2, VersionNumber::FIRST);
        let key3 = PdkCacheKey::new(project_id1, VersionNumber::new(2));

        assert_ne!(key1, key2);
        assert_ne!(key1, key3);
    }
}
