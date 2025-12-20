//! Profile management for Mycelium.
//!
//! This module handles profile creation, storage, and management. Each profile
//! represents a connection to a vault with independent device keys.

use anyhow::{Context, Result};
use myc_core::ids::DeviceId;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use time::OffsetDateTime;

/// Profile metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    /// Profile name (unique identifier)
    pub name: String,
    /// GitHub repository owner
    pub github_owner: String,
    /// GitHub repository name
    pub github_repo: String,
    /// GitHub user ID
    pub github_user_id: u64,
    /// GitHub username
    pub github_username: String,
    /// Device ID for this profile
    pub device_id: DeviceId,
    /// When the profile was created
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// Global configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalConfig {
    /// Default profile name
    pub default_profile: Option<String>,
    /// Whether to output JSON by default
    pub json_output: bool,
    /// Color output setting: "auto", "always", "never"
    pub color: String,
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            default_profile: None,
            json_output: false,
            color: "auto".to_string(),
        }
    }
}

/// Profile manager handles profile operations
pub struct ProfileManager {
    config_dir: PathBuf,
}

impl ProfileManager {
    /// Creates a new profile manager
    ///
    /// # Arguments
    ///
    /// * `config_dir` - Base configuration directory (e.g., ~/.config/mycelium)
    pub fn new(config_dir: PathBuf) -> Self {
        Self { config_dir }
    }

    /// Returns the default configuration directory
    ///
    /// Uses platform-appropriate config directory:
    /// - Linux: ~/.config/mycelium
    /// - macOS: ~/Library/Application Support/mycelium
    /// - Windows: %APPDATA%\mycelium
    pub fn default_config_dir() -> Result<PathBuf> {
        let base_dir = dirs::config_dir()
            .ok_or_else(|| anyhow::anyhow!("Could not determine config directory"))?;
        Ok(base_dir.join("mycelium"))
    }

    /// Returns the profiles directory
    fn profiles_dir(&self) -> PathBuf {
        self.config_dir.join("profiles")
    }

    /// Returns the directory for a specific profile
    fn profile_dir(&self, name: &str) -> PathBuf {
        self.profiles_dir().join(name)
    }

    /// Returns the path to a profile's metadata file
    fn profile_metadata_path(&self, name: &str) -> PathBuf {
        self.profile_dir(name).join("profile.json")
    }

    /// Returns the path to the global config file
    fn global_config_path(&self) -> PathBuf {
        self.config_dir.join("config.json")
    }

    /// Returns the keys directory for a profile
    pub fn keys_dir(&self, name: &str) -> PathBuf {
        self.profile_dir(name).join("keys")
    }

    /// Returns the cache directory for a profile
    pub fn cache_dir(&self, name: &str) -> PathBuf {
        self.profile_dir(name).join("cache")
    }

    /// Lists all available profiles
    pub fn list_profiles(&self) -> Result<Vec<String>> {
        let profiles_dir = self.profiles_dir();

        if !profiles_dir.exists() {
            return Ok(Vec::new());
        }

        let mut profiles = Vec::new();
        for entry in fs::read_dir(&profiles_dir).context("Failed to read profiles directory")? {
            let entry = entry.context("Failed to read directory entry")?;
            let path = entry.path();

            if path.is_dir() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    // Check if profile.json exists
                    if self.profile_metadata_path(name).exists() {
                        profiles.push(name.to_string());
                    }
                }
            }
        }

        profiles.sort();
        Ok(profiles)
    }

    /// Gets a profile by name
    pub fn get_profile(&self, name: &str) -> Result<Profile> {
        let path = self.profile_metadata_path(name);

        if !path.exists() {
            anyhow::bail!("Profile '{}' not found", name);
        }

        let json = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read profile '{}'", name))?;

        let profile: Profile = serde_json::from_str(&json)
            .with_context(|| format!("Failed to parse profile '{}'", name))?;

        Ok(profile)
    }

    /// Creates a new profile
    ///
    /// # Arguments
    ///
    /// * `profile` - The profile metadata to save
    ///
    /// # Errors
    ///
    /// Returns an error if the profile already exists or if file operations fail
    pub fn create_profile(&self, profile: &Profile) -> Result<()> {
        let profile_dir = self.profile_dir(&profile.name);

        if profile_dir.exists() {
            anyhow::bail!("Profile '{}' already exists", profile.name);
        }

        // Create profile directory structure
        fs::create_dir_all(&profile_dir).with_context(|| {
            format!("Failed to create profile directory for '{}'", profile.name)
        })?;

        // Set directory permissions (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o700);
            fs::set_permissions(&profile_dir, perms)
                .context("Failed to set profile directory permissions")?;
        }

        // Create keys directory
        let keys_dir = self.keys_dir(&profile.name);
        fs::create_dir_all(&keys_dir).context("Failed to create keys directory")?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o700);
            fs::set_permissions(&keys_dir, perms)
                .context("Failed to set keys directory permissions")?;
        }

        // Create cache directory
        let cache_dir = self.cache_dir(&profile.name);
        fs::create_dir_all(&cache_dir).context("Failed to create cache directory")?;

        // Save profile metadata
        let json = serde_json::to_string_pretty(profile).context("Failed to serialize profile")?;

        let metadata_path = self.profile_metadata_path(&profile.name);
        fs::write(&metadata_path, json).context("Failed to write profile metadata")?;

        Ok(())
    }

    /// Deletes a profile
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the profile to delete
    ///
    /// # Errors
    ///
    /// Returns an error if the profile doesn't exist or if deletion fails
    pub fn delete_profile(&self, name: &str) -> Result<()> {
        let profile_dir = self.profile_dir(name);

        if !profile_dir.exists() {
            anyhow::bail!("Profile '{}' not found", name);
        }

        // Remove the entire profile directory
        fs::remove_dir_all(&profile_dir)
            .with_context(|| format!("Failed to delete profile '{}'", name))?;

        // If this was the default profile, clear it
        let mut config = self.load_global_config()?;
        if config.default_profile.as_deref() == Some(name) {
            config.default_profile = None;
            self.save_global_config(&config)?;
        }

        Ok(())
    }

    /// Gets the default profile name
    pub fn get_default_profile(&self) -> Result<Option<String>> {
        let config = self.load_global_config()?;
        Ok(config.default_profile)
    }

    /// Sets the default profile
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the profile to set as default
    ///
    /// # Errors
    ///
    /// Returns an error if the profile doesn't exist
    pub fn set_default_profile(&self, name: &str) -> Result<()> {
        // Verify profile exists
        if !self.profile_metadata_path(name).exists() {
            anyhow::bail!("Profile '{}' not found", name);
        }

        let mut config = self.load_global_config()?;
        config.default_profile = Some(name.to_string());
        self.save_global_config(&config)?;

        Ok(())
    }

    /// Loads the global configuration
    pub fn load_global_config(&self) -> Result<GlobalConfig> {
        let path = self.global_config_path();

        if !path.exists() {
            return Ok(GlobalConfig::default());
        }

        let json = fs::read_to_string(&path).context("Failed to read global config")?;

        let config: GlobalConfig =
            serde_json::from_str(&json).context("Failed to parse global config")?;

        Ok(config)
    }

    /// Saves the global configuration
    pub fn save_global_config(&self, config: &GlobalConfig) -> Result<()> {
        // Ensure config directory exists
        fs::create_dir_all(&self.config_dir).context("Failed to create config directory")?;

        let json =
            serde_json::to_string_pretty(config).context("Failed to serialize global config")?;

        let path = self.global_config_path();
        fs::write(&path, json).context("Failed to write global config")?;

        Ok(())
    }

    /// Returns the path to the signing secret key file
    pub fn signing_key_path(&self, profile_name: &str) -> PathBuf {
        self.keys_dir(profile_name).join("signing.key")
    }

    /// Returns the path to the signing public key file
    pub fn signing_pubkey_path(&self, profile_name: &str) -> PathBuf {
        self.keys_dir(profile_name).join("signing.pub")
    }

    /// Returns the path to the encryption secret key file
    pub fn encryption_key_path(&self, profile_name: &str) -> PathBuf {
        self.keys_dir(profile_name).join("encryption.key")
    }

    /// Returns the path to the encryption public key file
    pub fn encryption_pubkey_path(&self, profile_name: &str) -> PathBuf {
        self.keys_dir(profile_name).join("encryption.pub")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_profile() -> Profile {
        Profile {
            name: "test-profile".to_string(),
            github_owner: "testorg".to_string(),
            github_repo: "test-vault".to_string(),
            github_user_id: 12345,
            github_username: "testuser".to_string(),
            device_id: DeviceId::new(),
            created_at: OffsetDateTime::now_utc(),
        }
    }

    #[test]
    fn test_create_and_get_profile() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ProfileManager::new(temp_dir.path().to_path_buf());

        let profile = create_test_profile();
        manager.create_profile(&profile).unwrap();

        let loaded = manager.get_profile(&profile.name).unwrap();
        assert_eq!(loaded.name, profile.name);
        assert_eq!(loaded.github_owner, profile.github_owner);
        assert_eq!(loaded.github_repo, profile.github_repo);
    }

    #[test]
    fn test_list_profiles() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ProfileManager::new(temp_dir.path().to_path_buf());

        // Initially empty
        let profiles = manager.list_profiles().unwrap();
        assert_eq!(profiles.len(), 0);

        // Create profiles
        let mut profile1 = create_test_profile();
        profile1.name = "profile1".to_string();
        manager.create_profile(&profile1).unwrap();

        let mut profile2 = create_test_profile();
        profile2.name = "profile2".to_string();
        manager.create_profile(&profile2).unwrap();

        // List should return both
        let profiles = manager.list_profiles().unwrap();
        assert_eq!(profiles.len(), 2);
        assert!(profiles.contains(&"profile1".to_string()));
        assert!(profiles.contains(&"profile2".to_string()));
    }

    #[test]
    fn test_delete_profile() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ProfileManager::new(temp_dir.path().to_path_buf());

        let profile = create_test_profile();
        manager.create_profile(&profile).unwrap();

        // Verify it exists
        assert!(manager.get_profile(&profile.name).is_ok());

        // Delete it
        manager.delete_profile(&profile.name).unwrap();

        // Verify it's gone
        assert!(manager.get_profile(&profile.name).is_err());
    }

    #[test]
    fn test_default_profile() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ProfileManager::new(temp_dir.path().to_path_buf());

        // Initially no default
        let default = manager.get_default_profile().unwrap();
        assert!(default.is_none());

        // Create and set default
        let profile = create_test_profile();
        manager.create_profile(&profile).unwrap();
        manager.set_default_profile(&profile.name).unwrap();

        // Verify default is set
        let default = manager.get_default_profile().unwrap();
        assert_eq!(default, Some(profile.name.clone()));

        // Delete profile should clear default
        manager.delete_profile(&profile.name).unwrap();
        let default = manager.get_default_profile().unwrap();
        assert!(default.is_none());
    }

    #[test]
    fn test_global_config() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ProfileManager::new(temp_dir.path().to_path_buf());

        // Load default config
        let config = manager.load_global_config().unwrap();
        assert_eq!(config.json_output, false);
        assert_eq!(config.color, "auto");

        // Modify and save
        let mut config = config;
        config.json_output = true;
        config.color = "always".to_string();
        manager.save_global_config(&config).unwrap();

        // Load and verify
        let loaded = manager.load_global_config().unwrap();
        assert_eq!(loaded.json_output, true);
        assert_eq!(loaded.color, "always");
    }

    #[test]
    fn test_profile_directory_structure() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ProfileManager::new(temp_dir.path().to_path_buf());

        let profile = create_test_profile();
        manager.create_profile(&profile).unwrap();

        // Verify directory structure
        assert!(manager.profile_dir(&profile.name).exists());
        assert!(manager.keys_dir(&profile.name).exists());
        assert!(manager.cache_dir(&profile.name).exists());
        assert!(manager.profile_metadata_path(&profile.name).exists());
    }

    #[cfg(unix)]
    #[test]
    fn test_directory_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = TempDir::new().unwrap();
        let manager = ProfileManager::new(temp_dir.path().to_path_buf());

        let profile = create_test_profile();
        manager.create_profile(&profile).unwrap();

        // Check profile directory permissions (0700)
        let profile_dir = manager.profile_dir(&profile.name);
        let metadata = fs::metadata(&profile_dir).unwrap();
        let mode = metadata.permissions().mode();
        assert_eq!(mode & 0o777, 0o700);

        // Check keys directory permissions (0700)
        let keys_dir = manager.keys_dir(&profile.name);
        let metadata = fs::metadata(&keys_dir).unwrap();
        let mode = metadata.permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
    }

    #[test]
    fn test_duplicate_profile_creation_fails() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ProfileManager::new(temp_dir.path().to_path_buf());

        let profile = create_test_profile();

        // First creation should succeed
        manager.create_profile(&profile).unwrap();

        // Second creation with same name should fail
        let result = manager.create_profile(&profile);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already exists"));
    }

    #[test]
    fn test_delete_nonexistent_profile_fails() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ProfileManager::new(temp_dir.path().to_path_buf());

        // Try to delete a profile that doesn't exist
        let result = manager.delete_profile("nonexistent");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn test_get_nonexistent_profile_fails() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ProfileManager::new(temp_dir.path().to_path_buf());

        // Try to get a profile that doesn't exist
        let result = manager.get_profile("nonexistent");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn test_set_nonexistent_default_profile_fails() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ProfileManager::new(temp_dir.path().to_path_buf());

        // Try to set a non-existent profile as default
        let result = manager.set_default_profile("nonexistent");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn test_list_profiles_empty_directory() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ProfileManager::new(temp_dir.path().to_path_buf());

        // List profiles when directory doesn't exist yet
        let profiles = manager.list_profiles().unwrap();
        assert_eq!(profiles.len(), 0);
    }

    #[test]
    fn test_list_profiles_sorted() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ProfileManager::new(temp_dir.path().to_path_buf());

        // Create profiles in non-alphabetical order
        let mut profile_c = create_test_profile();
        profile_c.name = "charlie".to_string();
        manager.create_profile(&profile_c).unwrap();

        let mut profile_a = create_test_profile();
        profile_a.name = "alice".to_string();
        manager.create_profile(&profile_a).unwrap();

        let mut profile_b = create_test_profile();
        profile_b.name = "bob".to_string();
        manager.create_profile(&profile_b).unwrap();

        // List should return sorted
        let profiles = manager.list_profiles().unwrap();
        assert_eq!(profiles, vec!["alice", "bob", "charlie"]);
    }

    #[test]
    fn test_default_profile_persistence() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ProfileManager::new(temp_dir.path().to_path_buf());

        // Create profile and set as default
        let profile = create_test_profile();
        manager.create_profile(&profile).unwrap();
        manager.set_default_profile(&profile.name).unwrap();

        // Create a new manager instance (simulating restart)
        let manager2 = ProfileManager::new(temp_dir.path().to_path_buf());

        // Default should persist
        let default = manager2.get_default_profile().unwrap();
        assert_eq!(default, Some(profile.name));
    }

    #[test]
    fn test_switch_default_profile() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ProfileManager::new(temp_dir.path().to_path_buf());

        // Create two profiles
        let mut profile1 = create_test_profile();
        profile1.name = "profile1".to_string();
        manager.create_profile(&profile1).unwrap();

        let mut profile2 = create_test_profile();
        profile2.name = "profile2".to_string();
        manager.create_profile(&profile2).unwrap();

        // Set profile1 as default
        manager.set_default_profile(&profile1.name).unwrap();
        let default = manager.get_default_profile().unwrap();
        assert_eq!(default, Some(profile1.name.clone()));

        // Switch to profile2
        manager.set_default_profile(&profile2.name).unwrap();
        let default = manager.get_default_profile().unwrap();
        assert_eq!(default, Some(profile2.name));
    }

    #[test]
    fn test_profile_metadata_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ProfileManager::new(temp_dir.path().to_path_buf());

        let profile = create_test_profile();
        manager.create_profile(&profile).unwrap();

        let loaded = manager.get_profile(&profile.name).unwrap();

        // Verify all fields are preserved
        assert_eq!(loaded.name, profile.name);
        assert_eq!(loaded.github_owner, profile.github_owner);
        assert_eq!(loaded.github_repo, profile.github_repo);
        assert_eq!(loaded.github_user_id, profile.github_user_id);
        assert_eq!(loaded.github_username, profile.github_username);
        assert_eq!(loaded.device_id, profile.device_id);
        // Note: timestamps may have slight differences due to serialization
    }

    #[test]
    fn test_global_config_default_values() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ProfileManager::new(temp_dir.path().to_path_buf());

        // Load config when file doesn't exist
        let config = manager.load_global_config().unwrap();

        // Verify default values
        assert_eq!(config.default_profile, None);
        assert_eq!(config.json_output, false);
        assert_eq!(config.color, "auto");
    }

    #[test]
    fn test_key_file_paths() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ProfileManager::new(temp_dir.path().to_path_buf());

        let profile_name = "test-profile";

        // Verify key file paths are correct
        let signing_key = manager.signing_key_path(profile_name);
        let signing_pub = manager.signing_pubkey_path(profile_name);
        let encryption_key = manager.encryption_key_path(profile_name);
        let encryption_pub = manager.encryption_pubkey_path(profile_name);

        assert!(signing_key.to_string_lossy().contains("signing.key"));
        assert!(signing_pub.to_string_lossy().contains("signing.pub"));
        assert!(encryption_key.to_string_lossy().contains("encryption.key"));
        assert!(encryption_pub.to_string_lossy().contains("encryption.pub"));

        // All should be in the keys directory
        let keys_dir = manager.keys_dir(profile_name);
        assert_eq!(signing_key.parent().unwrap(), keys_dir);
        assert_eq!(signing_pub.parent().unwrap(), keys_dir);
        assert_eq!(encryption_key.parent().unwrap(), keys_dir);
        assert_eq!(encryption_pub.parent().unwrap(), keys_dir);
    }

    #[test]
    fn test_multiple_profile_operations() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ProfileManager::new(temp_dir.path().to_path_buf());

        // Create multiple profiles
        for i in 1..=5 {
            let mut profile = create_test_profile();
            profile.name = format!("profile{}", i);
            manager.create_profile(&profile).unwrap();
        }

        // Verify all exist
        let profiles = manager.list_profiles().unwrap();
        assert_eq!(profiles.len(), 5);

        // Delete some
        manager.delete_profile("profile2").unwrap();
        manager.delete_profile("profile4").unwrap();

        // Verify correct ones remain
        let profiles = manager.list_profiles().unwrap();
        assert_eq!(profiles.len(), 3);
        assert!(profiles.contains(&"profile1".to_string()));
        assert!(profiles.contains(&"profile3".to_string()));
        assert!(profiles.contains(&"profile5".to_string()));
        assert!(!profiles.contains(&"profile2".to_string()));
        assert!(!profiles.contains(&"profile4".to_string()));
    }

    #[test]
    fn test_delete_default_profile_clears_default() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ProfileManager::new(temp_dir.path().to_path_buf());

        // Create two profiles
        let mut profile1 = create_test_profile();
        profile1.name = "profile1".to_string();
        manager.create_profile(&profile1).unwrap();

        let mut profile2 = create_test_profile();
        profile2.name = "profile2".to_string();
        manager.create_profile(&profile2).unwrap();

        // Set profile1 as default
        manager.set_default_profile(&profile1.name).unwrap();
        assert_eq!(
            manager.get_default_profile().unwrap(),
            Some(profile1.name.clone())
        );

        // Delete the default profile
        manager.delete_profile(&profile1.name).unwrap();

        // Default should be cleared
        assert_eq!(manager.get_default_profile().unwrap(), None);

        // profile2 should still exist
        assert!(manager.get_profile(&profile2.name).is_ok());
    }

    #[test]
    fn test_delete_non_default_profile_preserves_default() {
        let temp_dir = TempDir::new().unwrap();
        let manager = ProfileManager::new(temp_dir.path().to_path_buf());

        // Create two profiles
        let mut profile1 = create_test_profile();
        profile1.name = "profile1".to_string();
        manager.create_profile(&profile1).unwrap();

        let mut profile2 = create_test_profile();
        profile2.name = "profile2".to_string();
        manager.create_profile(&profile2).unwrap();

        // Set profile1 as default
        manager.set_default_profile(&profile1.name).unwrap();

        // Delete profile2 (not the default)
        manager.delete_profile(&profile2.name).unwrap();

        // Default should still be profile1
        assert_eq!(manager.get_default_profile().unwrap(), Some(profile1.name));
    }
}
