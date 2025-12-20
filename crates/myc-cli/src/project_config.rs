//! Project configuration support for .myc.yaml files.
//!
//! This module provides functionality to discover and parse .myc.yaml configuration
//! files in project directories. These files allow users to set defaults for
//! vault, project, set, and export format settings.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::Path;

/// Project configuration from .myc.yaml file
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProjectConfig {
    /// Vault repository (owner/repo format)
    pub vault: Option<String>,
    /// Default project name or ID
    pub project: Option<String>,
    /// Default secret set name or ID
    pub set: Option<String>,
    /// Default export format (dotenv, json, shell, yaml)
    pub export_format: Option<String>,
    /// Default output file path
    pub output_file: Option<String>,
}

impl ProjectConfig {
    /// Discovers and loads project configuration by walking up the directory tree.
    ///
    /// Starts from the current working directory and walks up until it finds
    /// a .myc.yaml file or reaches the filesystem root.
    ///
    /// # Returns
    ///
    /// Returns the loaded configuration if found, or a default empty configuration
    /// if no .myc.yaml file is found.
    pub fn discover() -> Result<Self> {
        let current_dir = env::current_dir().context("Failed to get current working directory")?;

        Self::discover_from_path(&current_dir)
    }

    /// Discovers and loads project configuration starting from a specific path.
    ///
    /// # Arguments
    ///
    /// * `start_path` - The directory to start searching from
    ///
    /// # Returns
    ///
    /// Returns the loaded configuration if found, or a default empty configuration
    /// if no .myc.yaml file is found.
    pub fn discover_from_path(start_path: &Path) -> Result<Self> {
        let mut current_path = start_path.to_path_buf();

        loop {
            let config_path = current_path.join(".myc.yaml");

            if config_path.exists() {
                tracing::debug!("Found .myc.yaml at: {}", config_path.display());
                return Self::load_from_file(&config_path);
            }

            // Try to go up one directory
            if let Some(parent) = current_path.parent() {
                current_path = parent.to_path_buf();
            } else {
                // Reached filesystem root, no config found
                tracing::debug!("No .myc.yaml found, using default configuration");
                return Ok(Self::default());
            }
        }
    }

    /// Loads project configuration from a specific file.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the .myc.yaml file
    ///
    /// # Returns
    ///
    /// Returns the loaded configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or parsed.
    pub fn load_from_file(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        let config: ProjectConfig = serde_yaml::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))?;

        tracing::info!("Loaded project config from: {}", path.display());
        Ok(config)
    }

    /// Saves project configuration to a file.
    ///
    /// # Arguments
    ///
    /// * `path` - Path where to save the .myc.yaml file
    ///
    /// # Returns
    ///
    /// Returns Ok(()) on success.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be written or serialized.
    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        let content = serde_yaml::to_string(self).context("Failed to serialize config to YAML")?;

        fs::write(path, content)
            .with_context(|| format!("Failed to write config file: {}", path.display()))?;

        tracing::info!("Saved project config to: {}", path.display());
        Ok(())
    }

    /// Validates the configuration values.
    ///
    /// # Returns
    ///
    /// Returns Ok(()) if the configuration is valid.
    ///
    /// # Errors
    ///
    /// Returns an error if any configuration values are invalid.
    pub fn validate(&self) -> Result<()> {
        // Validate vault format (should be owner/repo)
        if let Some(vault) = &self.vault {
            if !vault.contains('/') || vault.split('/').count() != 2 {
                anyhow::bail!("Invalid vault format '{}'. Expected 'owner/repo'", vault);
            }

            let parts: Vec<&str> = vault.split('/').collect();
            if parts[0].is_empty() || parts[1].is_empty() {
                anyhow::bail!(
                    "Invalid vault format '{}'. Owner and repo cannot be empty",
                    vault
                );
            }
        }

        // Validate export format
        if let Some(format) = &self.export_format {
            match format.as_str() {
                "dotenv" | "json" | "shell" | "yaml" => {
                    // Valid formats
                }
                _ => {
                    anyhow::bail!(
                        "Invalid export format '{}'. Supported formats: dotenv, json, shell, yaml",
                        format
                    );
                }
            }
        }

        // Validate project name (basic validation)
        if let Some(project) = &self.project {
            if project.is_empty() {
                anyhow::bail!("Project name cannot be empty");
            }
        }

        // Validate set name (basic validation)
        if let Some(set) = &self.set {
            if set.is_empty() {
                anyhow::bail!("Set name cannot be empty");
            }
        }

        Ok(())
    }

    /// Merges this configuration with command-line overrides.
    ///
    /// Command-line values take precedence over config file values.
    ///
    /// # Arguments
    ///
    /// * `vault_override` - Vault override from command line
    /// * `project_override` - Project override from command line
    /// * `set_override` - Set override from command line
    /// * `format_override` - Format override from command line
    /// * `output_override` - Output file override from command line
    ///
    /// # Returns
    ///
    /// Returns a new configuration with overrides applied.
    pub fn with_overrides(
        &self,
        vault_override: Option<&str>,
        project_override: Option<&str>,
        set_override: Option<&str>,
        format_override: Option<&str>,
        output_override: Option<&str>,
    ) -> Self {
        Self {
            vault: vault_override
                .map(|s| s.to_string())
                .or_else(|| self.vault.clone()),
            project: project_override
                .map(|s| s.to_string())
                .or_else(|| self.project.clone()),
            set: set_override
                .map(|s| s.to_string())
                .or_else(|| self.set.clone()),
            export_format: format_override
                .map(|s| s.to_string())
                .or_else(|| self.export_format.clone()),
            output_file: output_override
                .map(|s| s.to_string())
                .or_else(|| self.output_file.clone()),
        }
    }

    /// Gets the vault owner and repo from the vault configuration.
    ///
    /// # Returns
    ///
    /// Returns (owner, repo) tuple if vault is configured and valid.
    ///
    /// # Errors
    ///
    /// Returns an error if vault is not configured or has invalid format.
    pub fn get_vault_parts(&self) -> Result<(String, String)> {
        let vault = self
            .vault
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No vault configured"))?;

        let parts: Vec<&str> = vault.split('/').collect();
        if parts.len() != 2 {
            anyhow::bail!("Invalid vault format '{}'. Expected 'owner/repo'", vault);
        }

        Ok((parts[0].to_string(), parts[1].to_string()))
    }

    /// Checks if the configuration is empty (no values set).
    pub fn is_empty(&self) -> bool {
        self.vault.is_none()
            && self.project.is_none()
            && self.set.is_none()
            && self.export_format.is_none()
            && self.output_file.is_none()
    }

    /// Creates a sample configuration for documentation purposes.
    pub fn sample() -> Self {
        Self {
            vault: Some("myorg/secrets-vault".to_string()),
            project: Some("api".to_string()),
            set: Some("production".to_string()),
            export_format: Some("dotenv".to_string()),
            output_file: Some(".env".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_default_config() {
        let config = ProjectConfig::default();
        assert!(config.is_empty());
        assert!(config.vault.is_none());
        assert!(config.project.is_none());
        assert!(config.set.is_none());
        assert!(config.export_format.is_none());
        assert!(config.output_file.is_none());
    }

    #[test]
    fn test_sample_config() {
        let config = ProjectConfig::sample();
        assert!(!config.is_empty());
        assert_eq!(config.vault, Some("myorg/secrets-vault".to_string()));
        assert_eq!(config.project, Some("api".to_string()));
        assert_eq!(config.set, Some("production".to_string()));
        assert_eq!(config.export_format, Some("dotenv".to_string()));
        assert_eq!(config.output_file, Some(".env".to_string()));
    }

    #[test]
    fn test_yaml_serialization() {
        let config = ProjectConfig::sample();

        // Serialize to YAML
        let yaml = serde_yaml::to_string(&config).unwrap();

        // Should contain expected fields
        assert!(yaml.contains("vault: myorg/secrets-vault"));
        assert!(yaml.contains("project: api"));
        assert!(yaml.contains("set: production"));
        assert!(yaml.contains("export_format: dotenv"));
        assert!(yaml.contains("output_file: .env"));

        // Deserialize back
        let deserialized: ProjectConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(deserialized.vault, config.vault);
        assert_eq!(deserialized.project, config.project);
        assert_eq!(deserialized.set, config.set);
        assert_eq!(deserialized.export_format, config.export_format);
        assert_eq!(deserialized.output_file, config.output_file);
    }

    #[test]
    fn test_partial_config() {
        let yaml = r#"
vault: myorg/secrets-vault
project: api
"#;

        let config: ProjectConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.vault, Some("myorg/secrets-vault".to_string()));
        assert_eq!(config.project, Some("api".to_string()));
        assert!(config.set.is_none());
        assert!(config.export_format.is_none());
        assert!(config.output_file.is_none());
    }

    #[test]
    fn test_empty_config() {
        let yaml = "";
        let config: ProjectConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.is_empty());
    }

    #[test]
    fn test_validate_valid_config() {
        let config = ProjectConfig::sample();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_invalid_vault_format() {
        let mut config = ProjectConfig::sample();
        config.vault = Some("invalid-vault".to_string());

        let result = config.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid vault format"));
    }

    #[test]
    fn test_validate_empty_vault_parts() {
        let mut config = ProjectConfig::sample();
        config.vault = Some("/".to_string());

        let result = config.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Owner and repo cannot be empty"));
    }

    #[test]
    fn test_validate_invalid_export_format() {
        let mut config = ProjectConfig::sample();
        config.export_format = Some("invalid".to_string());

        let result = config.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid export format"));
    }

    #[test]
    fn test_validate_empty_project() {
        let mut config = ProjectConfig::sample();
        config.project = Some("".to_string());

        let result = config.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Project name cannot be empty"));
    }

    #[test]
    fn test_validate_empty_set() {
        let mut config = ProjectConfig::sample();
        config.set = Some("".to_string());

        let result = config.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Set name cannot be empty"));
    }

    #[test]
    fn test_get_vault_parts() {
        let config = ProjectConfig::sample();
        let (owner, repo) = config.get_vault_parts().unwrap();
        assert_eq!(owner, "myorg");
        assert_eq!(repo, "secrets-vault");
    }

    #[test]
    fn test_get_vault_parts_no_vault() {
        let config = ProjectConfig::default();
        let result = config.get_vault_parts();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("No vault configured"));
    }

    #[test]
    fn test_with_overrides() {
        let config = ProjectConfig::sample();

        let overridden = config.with_overrides(
            Some("neworg/newvault"),
            Some("newproject"),
            None, // Keep original set
            Some("json"),
            None, // Keep original output_file
        );

        assert_eq!(overridden.vault, Some("neworg/newvault".to_string()));
        assert_eq!(overridden.project, Some("newproject".to_string()));
        assert_eq!(overridden.set, Some("production".to_string())); // Original
        assert_eq!(overridden.export_format, Some("json".to_string()));
        assert_eq!(overridden.output_file, Some(".env".to_string())); // Original
    }

    #[test]
    fn test_with_overrides_empty_config() {
        let config = ProjectConfig::default();

        let overridden = config.with_overrides(
            Some("myorg/vault"),
            Some("myproject"),
            Some("myset"),
            Some("yaml"),
            Some("output.yaml"),
        );

        assert_eq!(overridden.vault, Some("myorg/vault".to_string()));
        assert_eq!(overridden.project, Some("myproject".to_string()));
        assert_eq!(overridden.set, Some("myset".to_string()));
        assert_eq!(overridden.export_format, Some("yaml".to_string()));
        assert_eq!(overridden.output_file, Some("output.yaml".to_string()));
    }

    #[test]
    fn test_load_from_file() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join(".myc.yaml");

        let yaml_content = r#"
vault: testorg/test-vault
project: test-project
set: test-set
export_format: json
output_file: test.json
"#;

        fs::write(&config_path, yaml_content).unwrap();

        let config = ProjectConfig::load_from_file(&config_path).unwrap();
        assert_eq!(config.vault, Some("testorg/test-vault".to_string()));
        assert_eq!(config.project, Some("test-project".to_string()));
        assert_eq!(config.set, Some("test-set".to_string()));
        assert_eq!(config.export_format, Some("json".to_string()));
        assert_eq!(config.output_file, Some("test.json".to_string()));
    }

    #[test]
    fn test_save_to_file() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join(".myc.yaml");

        let config = ProjectConfig::sample();
        config.save_to_file(&config_path).unwrap();

        // Verify file was created and can be loaded back
        assert!(config_path.exists());
        let loaded = ProjectConfig::load_from_file(&config_path).unwrap();
        assert_eq!(loaded.vault, config.vault);
        assert_eq!(loaded.project, config.project);
        assert_eq!(loaded.set, config.set);
        assert_eq!(loaded.export_format, config.export_format);
        assert_eq!(loaded.output_file, config.output_file);
    }

    #[test]
    fn test_discover_from_path() {
        let temp_dir = TempDir::new().unwrap();
        let root_dir = temp_dir.path();
        let sub_dir = root_dir.join("subdir");
        let deep_dir = sub_dir.join("deep");

        fs::create_dir_all(&deep_dir).unwrap();

        // Create config in root
        let config_path = root_dir.join(".myc.yaml");
        let config = ProjectConfig::sample();
        config.save_to_file(&config_path).unwrap();

        // Discover from deep directory should find the root config
        let discovered = ProjectConfig::discover_from_path(&deep_dir).unwrap();
        assert_eq!(discovered.vault, config.vault);
        assert_eq!(discovered.project, config.project);
    }

    #[test]
    fn test_discover_no_config() {
        let temp_dir = TempDir::new().unwrap();
        let sub_dir = temp_dir.path().join("subdir");
        fs::create_dir_all(&sub_dir).unwrap();

        // No config file exists
        let discovered = ProjectConfig::discover_from_path(&sub_dir).unwrap();
        assert!(discovered.is_empty());
    }

    #[test]
    fn test_discover_nearest_config() {
        let temp_dir = TempDir::new().unwrap();
        let root_dir = temp_dir.path();
        let sub_dir = root_dir.join("subdir");
        let deep_dir = sub_dir.join("deep");

        fs::create_dir_all(&deep_dir).unwrap();

        // Create config in root
        let root_config = ProjectConfig {
            vault: Some("root/vault".to_string()),
            project: Some("root-project".to_string()),
            ..Default::default()
        };
        root_config
            .save_to_file(&root_dir.join(".myc.yaml"))
            .unwrap();

        // Create config in subdir (should be found first)
        let sub_config = ProjectConfig {
            vault: Some("sub/vault".to_string()),
            project: Some("sub-project".to_string()),
            ..Default::default()
        };
        sub_config.save_to_file(&sub_dir.join(".myc.yaml")).unwrap();

        // Discover from deep directory should find the subdir config (nearest)
        let discovered = ProjectConfig::discover_from_path(&deep_dir).unwrap();
        assert_eq!(discovered.vault, Some("sub/vault".to_string()));
        assert_eq!(discovered.project, Some("sub-project".to_string()));
    }

    #[test]
    fn test_load_invalid_yaml() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join(".myc.yaml");

        // Write invalid YAML
        fs::write(&config_path, "invalid: yaml: content: [").unwrap();

        let result = ProjectConfig::load_from_file(&config_path);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Failed to parse config file"));
    }

    #[test]
    fn test_load_nonexistent_file() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("nonexistent.yaml");

        let result = ProjectConfig::load_from_file(&config_path);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Failed to read config file"));
    }

    #[test]
    fn test_is_empty() {
        let empty_config = ProjectConfig::default();
        assert!(empty_config.is_empty());

        let partial_config = ProjectConfig {
            vault: Some("test/vault".to_string()),
            ..Default::default()
        };
        assert!(!partial_config.is_empty());

        let full_config = ProjectConfig::sample();
        assert!(!full_config.is_empty());
    }

    #[test]
    fn test_valid_export_formats() {
        for format in &["dotenv", "json", "shell", "yaml"] {
            let config = ProjectConfig {
                export_format: Some(format.to_string()),
                ..Default::default()
            };
            assert!(
                config.validate().is_ok(),
                "Format '{}' should be valid",
                format
            );
        }
    }

    #[test]
    fn test_vault_format_variations() {
        // Valid formats
        for vault in &["owner/repo", "my-org/my-repo", "user123/repo_name"] {
            let config = ProjectConfig {
                vault: Some(vault.to_string()),
                ..Default::default()
            };
            assert!(
                config.validate().is_ok(),
                "Vault '{}' should be valid",
                vault
            );
        }

        // Invalid formats
        for vault in &["owner", "owner/", "/repo", "owner/repo/extra", ""] {
            let config = ProjectConfig {
                vault: Some(vault.to_string()),
                ..Default::default()
            };
            assert!(
                config.validate().is_err(),
                "Vault '{}' should be invalid",
                vault
            );
        }
    }
}
