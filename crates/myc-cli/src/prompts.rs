//! Interactive prompts for the Mycelium CLI.
//!
//! This module provides user interaction functionality including confirmation
//! prompts, password input, selection lists, and progress indicators.

use anyhow::{Context, Result};
use console::{style, Term};
use dialoguer::{
    theme::{ColorfulTheme, SimpleTheme, Theme},
    Confirm, FuzzySelect, Input, MultiSelect, Password, Select,
};
use indicatif::{ProgressBar, ProgressStyle};
use std::env;
use std::time::Duration;

/// Interactive prompt manager that handles user input and respects non-interactive mode.
pub struct PromptManager {
    /// Whether we're in non-interactive mode
    non_interactive: bool,
    /// Theme to use for prompts
    theme: Box<dyn Theme>,
    /// Terminal for output
    term: Term,
}

impl PromptManager {
    /// Create a new prompt manager.
    pub fn new() -> Self {
        let non_interactive = env::var("MYC_NON_INTERACTIVE").is_ok();
        let colors_enabled =
            env::var("NO_COLOR").is_err() && env::var("TERM").map_or(true, |term| term != "dumb");

        let theme: Box<dyn Theme> = if colors_enabled {
            Box::new(ColorfulTheme::default())
        } else {
            Box::new(SimpleTheme)
        };

        Self {
            non_interactive,
            theme,
            term: Term::stderr(),
        }
    }

    /// Check if we're in non-interactive mode.
    pub fn is_non_interactive(&self) -> bool {
        self.non_interactive
    }

    /// Prompt for confirmation (yes/no).
    pub fn confirm(&self, message: &str) -> Result<bool> {
        self.confirm_with_default(message, false)
    }

    /// Prompt for confirmation with a default value.
    pub fn confirm_with_default(&self, message: &str, default: bool) -> Result<bool> {
        if self.non_interactive {
            anyhow::bail!("Cannot prompt for confirmation in non-interactive mode. Use --force to skip confirmation or set MYC_NON_INTERACTIVE=0.");
        }

        Confirm::with_theme(&*self.theme)
            .with_prompt(message)
            .default(default)
            .interact()
            .context("Failed to get user confirmation")
    }

    /// Prompt for a password (hidden input).
    pub fn password(&self, message: &str) -> Result<String> {
        if self.non_interactive {
            // Try to get from environment variable first
            if let Ok(password) = env::var("MYC_KEY_PASSPHRASE") {
                return Ok(password);
            }
            anyhow::bail!("Cannot prompt for password in non-interactive mode. Set MYC_KEY_PASSPHRASE environment variable.");
        }

        Password::with_theme(&*self.theme)
            .with_prompt(message)
            .interact()
            .context("Failed to get password input")
    }

    /// Prompt for a password with confirmation.
    pub fn password_with_confirmation(&self, message: &str) -> Result<String> {
        if self.non_interactive {
            if let Ok(password) = env::var("MYC_KEY_PASSPHRASE") {
                return Ok(password);
            }
            anyhow::bail!("Cannot prompt for password in non-interactive mode. Set MYC_KEY_PASSPHRASE environment variable.");
        }

        loop {
            let password = Password::with_theme(&*self.theme)
                .with_prompt(message)
                .interact()
                .context("Failed to get password input")?;

            let confirmation = Password::with_theme(&*self.theme)
                .with_prompt("Confirm password")
                .interact()
                .context("Failed to get password confirmation")?;

            if password == confirmation {
                return Ok(password);
            } else {
                eprintln!(
                    "{} Passwords do not match. Please try again.",
                    style("✗").red()
                );
            }
        }
    }

    /// Prompt for text input.
    pub fn input(&self, message: &str) -> Result<String> {
        if self.non_interactive {
            anyhow::bail!("Cannot prompt for input in non-interactive mode.");
        }

        Input::with_theme(&*self.theme)
            .with_prompt(message)
            .interact_text()
            .context("Failed to get text input")
    }

    /// Prompt for text input with a default value.
    pub fn input_with_default(&self, message: &str, default: &str) -> Result<String> {
        if self.non_interactive {
            return Ok(default.to_string());
        }

        Input::with_theme(&*self.theme)
            .with_prompt(message)
            .default(default.to_string())
            .interact_text()
            .context("Failed to get text input")
    }

    /// Prompt for text input with validation.
    pub fn input_with_validation<F>(&self, message: &str, validator: F) -> Result<String>
    where
        F: Fn(&String) -> Result<(), String> + 'static,
    {
        if self.non_interactive {
            anyhow::bail!("Cannot prompt for input in non-interactive mode.");
        }

        Input::with_theme(&*self.theme)
            .with_prompt(message)
            .validate_with(validator)
            .interact_text()
            .context("Failed to get validated input")
    }

    /// Prompt for selection from a list.
    pub fn select(&self, message: &str, items: &[String]) -> Result<usize> {
        if self.non_interactive {
            anyhow::bail!("Cannot prompt for selection in non-interactive mode.");
        }

        if items.is_empty() {
            anyhow::bail!("Cannot select from empty list");
        }

        Select::with_theme(&*self.theme)
            .with_prompt(message)
            .items(items)
            .interact()
            .context("Failed to get selection")
    }

    /// Prompt for selection with a default.
    pub fn select_with_default(
        &self,
        message: &str,
        items: &[String],
        default: usize,
    ) -> Result<usize> {
        if self.non_interactive {
            return Ok(default);
        }

        if items.is_empty() {
            anyhow::bail!("Cannot select from empty list");
        }

        if default >= items.len() {
            anyhow::bail!(
                "Default index {} is out of range for {} items",
                default,
                items.len()
            );
        }

        Select::with_theme(&*self.theme)
            .with_prompt(message)
            .items(items)
            .default(default)
            .interact()
            .context("Failed to get selection")
    }

    /// Prompt for fuzzy selection from a list.
    pub fn fuzzy_select(&self, message: &str, items: &[String]) -> Result<usize> {
        if self.non_interactive {
            anyhow::bail!("Cannot prompt for selection in non-interactive mode.");
        }

        if items.is_empty() {
            anyhow::bail!("Cannot select from empty list");
        }

        FuzzySelect::with_theme(&*self.theme)
            .with_prompt(message)
            .items(items)
            .interact()
            .context("Failed to get fuzzy selection")
    }

    /// Prompt for multiple selections from a list.
    pub fn multi_select(&self, message: &str, items: &[String]) -> Result<Vec<usize>> {
        if self.non_interactive {
            anyhow::bail!("Cannot prompt for multi-selection in non-interactive mode.");
        }

        if items.is_empty() {
            anyhow::bail!("Cannot select from empty list");
        }

        MultiSelect::with_theme(&*self.theme)
            .with_prompt(message)
            .items(items)
            .interact()
            .context("Failed to get multi-selection")
    }

    /// Create a progress bar for determinate progress.
    pub fn progress_bar(&self, message: &str, total: u64) -> ProgressBar {
        let pb = ProgressBar::new(total);
        pb.set_style(
            ProgressStyle::with_template(
                "{spinner:.green} {msg} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} ({eta})"
            )
            .unwrap_or_else(|_| ProgressStyle::default_bar())
            .progress_chars("#>-")
        );
        pb.set_message(message.to_string());
        pb
    }

    /// Create a spinner for indeterminate progress.
    pub fn spinner(&self, message: &str) -> ProgressBar {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::with_template("{spinner:.green} {msg} [{elapsed_precise}]")
                .unwrap_or_else(|_| ProgressStyle::default_spinner()),
        );
        pb.set_message(message.to_string());
        pb.enable_steady_tick(Duration::from_millis(100));
        pb
    }

    /// Display a warning message and ask for confirmation to continue.
    pub fn warn_and_confirm(&self, warning: &str, prompt: &str) -> Result<bool> {
        if !self.non_interactive {
            eprintln!("{} {}", style("⚠").yellow().bold(), style(warning).yellow());
            eprintln!();
        }
        self.confirm(prompt)
    }

    /// Display an error and ask if the user wants to retry.
    pub fn error_and_retry(&self, error: &str, retry_prompt: &str) -> Result<bool> {
        if !self.non_interactive {
            eprintln!("{} {}", style("✗").red().bold(), style(error).red());
            eprintln!();
        }
        self.confirm(retry_prompt)
    }

    /// Prompt for GitHub repository in owner/repo format.
    pub fn github_repo(&self, message: &str) -> Result<(String, String)> {
        let validator = |input: &String| {
            let parts: Vec<&str> = input.split('/').collect();
            if parts.len() != 2 {
                Err("Repository must be in format 'owner/repo'".to_string())
            } else if parts[0].is_empty() || parts[1].is_empty() {
                Err("Owner and repository name cannot be empty".to_string())
            } else {
                Ok(())
            }
        };

        let repo_str = self.input_with_validation(message, validator)?;
        let parts: Vec<&str> = repo_str.split('/').collect();
        Ok((parts[0].to_string(), parts[1].to_string()))
    }

    /// Prompt for a role selection.
    pub fn select_role(&self, message: &str, available_roles: &[&str]) -> Result<String> {
        let roles: Vec<String> = available_roles.iter().map(|s| s.to_string()).collect();
        let index = self.select(message, &roles)?;
        Ok(available_roles[index].to_string())
    }

    /// Prompt for format selection.
    pub fn select_format(&self, message: &str) -> Result<String> {
        let formats = vec![
            "dotenv".to_string(),
            "json".to_string(),
            "shell".to_string(),
            "yaml".to_string(),
        ];
        let index = self.select(message, &formats)?;
        Ok(formats[index].clone())
    }

    /// Show a destructive action warning.
    pub fn destructive_action_warning(
        &self,
        action: &str,
        target: &str,
        consequences: &[&str],
    ) -> Result<bool> {
        if self.non_interactive {
            anyhow::bail!("Cannot confirm destructive action '{}' in non-interactive mode. Use --force to skip confirmation.", action);
        }

        eprintln!(
            "{} {}",
            style("⚠").yellow().bold(),
            style("DESTRUCTIVE ACTION").yellow().bold()
        );
        eprintln!();
        eprintln!("Action: {}", style(action).red().bold());
        eprintln!("Target: {}", style(target).bold());
        eprintln!();
        eprintln!("This will:");
        for consequence in consequences {
            eprintln!("  • {}", consequence);
        }
        eprintln!();
        eprintln!("{}", style("This action cannot be undone.").red().bold());
        eprintln!();

        self.confirm("Are you absolutely sure you want to proceed?")
    }
}

impl Default for PromptManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper functions for common prompt patterns.
pub mod helpers {
    use super::*;

    /// Prompt for a passphrase with strength validation.
    pub fn secure_passphrase(prompt_manager: &PromptManager) -> Result<String> {
        if prompt_manager.is_non_interactive() {
            if let Ok(passphrase) = env::var("MYC_KEY_PASSPHRASE") {
                return Ok(passphrase);
            }
            anyhow::bail!("Cannot prompt for passphrase in non-interactive mode. Set MYC_KEY_PASSPHRASE environment variable.");
        }

        loop {
            let passphrase = prompt_manager.password("Enter passphrase for device keys")?;

            // Basic strength validation
            if passphrase.len() < 8 {
                eprintln!(
                    "{} Passphrase must be at least 8 characters long.",
                    style("✗").red()
                );
                continue;
            }

            let confirmation = prompt_manager.password("Confirm passphrase")?;

            if passphrase == confirmation {
                return Ok(passphrase);
            } else {
                eprintln!(
                    "{} Passphrases do not match. Please try again.",
                    style("✗").red()
                );
            }
        }
    }

    /// Prompt for optional passphrase (can be empty).
    pub fn optional_passphrase(prompt_manager: &PromptManager) -> Result<Option<String>> {
        if prompt_manager.is_non_interactive() {
            return Ok(env::var("MYC_KEY_PASSPHRASE").ok());
        }

        let use_passphrase = prompt_manager
            .confirm_with_default("Protect device keys with a passphrase? (recommended)", true)?;

        if use_passphrase {
            Ok(Some(secure_passphrase(prompt_manager)?))
        } else {
            eprintln!(
                "{} Device keys will be stored unencrypted.",
                style("⚠").yellow()
            );
            let confirm = prompt_manager
                .confirm("Are you sure you want to continue without a passphrase?")?;
            if confirm {
                Ok(None)
            } else {
                Ok(Some(secure_passphrase(prompt_manager)?))
            }
        }
    }

    /// Validate project name input.
    pub fn validate_project_name(name: &String) -> Result<(), String> {
        if name.is_empty() {
            return Err("Project name cannot be empty".to_string());
        }
        if name.len() > 256 {
            return Err("Project name cannot exceed 256 characters".to_string());
        }
        if !name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == ' ')
        {
            return Err(
                "Project name can only contain letters, numbers, spaces, hyphens, and underscores"
                    .to_string(),
            );
        }
        Ok(())
    }

    /// Validate secret set name input.
    pub fn validate_set_name(name: &String) -> Result<(), String> {
        if name.is_empty() {
            return Err("Secret set name cannot be empty".to_string());
        }
        if name.len() > 256 {
            return Err("Secret set name cannot exceed 256 characters".to_string());
        }
        if !name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        {
            return Err(
                "Secret set name can only contain letters, numbers, hyphens, and underscores"
                    .to_string(),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prompt_manager_creation() {
        let manager = PromptManager::new();
        // In test environment, should not be non-interactive unless explicitly set
        assert!(!manager.is_non_interactive() || env::var("MYC_NON_INTERACTIVE").is_ok());
    }

    #[test]
    fn test_validate_project_name() {
        use helpers::validate_project_name;

        assert!(validate_project_name(&"valid-project".to_string()).is_ok());
        assert!(validate_project_name(&"valid_project".to_string()).is_ok());
        assert!(validate_project_name(&"Valid Project 123".to_string()).is_ok());

        assert!(validate_project_name(&"".to_string()).is_err());
        assert!(validate_project_name(&"a".repeat(300)).is_err());
        assert!(validate_project_name(&"invalid@project".to_string()).is_err());
    }

    #[test]
    fn test_validate_set_name() {
        use helpers::validate_set_name;

        assert!(validate_set_name(&"valid-set".to_string()).is_ok());
        assert!(validate_set_name(&"valid_set".to_string()).is_ok());
        assert!(validate_set_name(&"validset123".to_string()).is_ok());

        assert!(validate_set_name(&"".to_string()).is_err());
        assert!(validate_set_name(&"a".repeat(300)).is_err());
        assert!(validate_set_name(&"invalid set".to_string()).is_err()); // spaces not allowed
        assert!(validate_set_name(&"invalid@set".to_string()).is_err());
    }
}
