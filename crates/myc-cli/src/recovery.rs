//! Recovery status and warnings for Mycelium.
//!
//! This module handles recovery status checking and warning display
//! to help users maintain access to their secrets.

use anyhow::Result;
use console::style;
use myc_core::ids::DeviceId;
use myc_github::client::GitHubClient;
use serde::{Deserialize, Serialize};

/// Recovery status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryStatus {
    /// Number of devices enrolled for the current user
    pub devices_enrolled: u32,
    /// Number of recovery contacts configured
    pub recovery_contacts: u32,
    /// Whether organization recovery key is configured
    pub org_recovery_key: bool,
    /// List of device IDs for the current user
    pub user_devices: Vec<DeviceId>,
}

impl Default for RecoveryStatus {
    fn default() -> Self {
        Self {
            devices_enrolled: 1, // Assume current device is enrolled
            recovery_contacts: 0,
            org_recovery_key: false,
            user_devices: Vec::new(),
        }
    }
}

/// Recovery warnings manager
pub struct RecoveryWarnings {
    /// Whether to show warnings (can be disabled for CI)
    pub show_warnings: bool,
}

impl RecoveryWarnings {
    /// Create a new recovery warnings manager
    pub fn new() -> Self {
        Self {
            show_warnings: !crate::non_interactive::NonInteractiveMode::is_enabled(),
        }
    }

    /// Get recovery status for the current user
    ///
    /// This is a placeholder implementation. In a full implementation, this would:
    /// 1. Read all device files from .mycelium/devices/
    /// 2. Filter by current user ID
    /// 3. Count active devices
    /// 4. Check for recovery contacts
    /// 5. Check for org recovery key
    pub async fn get_recovery_status(
        &self,
        _client: &GitHubClient,
        _user_id: &str,
    ) -> Result<RecoveryStatus> {
        // Placeholder implementation
        // In a full implementation, this would query the vault for:
        // - All devices belonging to the current user
        // - Recovery contact relationships
        // - Organization recovery key status

        Ok(RecoveryStatus::default())
    }

    /// Display recovery warning after first device enrollment
    ///
    /// Requirements 14.1: WHEN a user enrolls their first device,
    /// THEN THE system SHALL recommend enrolling a second device for recovery
    pub fn show_first_device_warning(&self, json_output: bool) {
        if !self.show_warnings {
            return;
        }

        if json_output {
            let warning = serde_json::json!({
                "type": "recovery_warning",
                "level": "info",
                "message": "Consider enrolling a second device for recovery",
                "recommendation": "Run 'myc device enroll <name>' on another device to enable recovery"
            });
            eprintln!(
                "{}",
                serde_json::to_string_pretty(&warning).unwrap_or_default()
            );
        } else {
            eprintln!();
            eprintln!("{}", style("💡 Recovery Recommendation").blue().bold());
            eprintln!("  You've enrolled your first device! For account recovery, consider:");
            eprintln!("  • Enrolling a second device: 'myc device enroll <name>'");
            eprintln!("  • Setting up recovery contacts (coming soon)");
            eprintln!("  • Configuring organization recovery (coming soon)");
            eprintln!();
        }
    }

    /// Display warning for users with only one device
    ///
    /// Requirements 14.2: WHEN a user has only one device,
    /// THEN THE system SHALL display warnings on each command execution
    pub fn show_single_device_warning(&self, json_output: bool, command_name: &str) {
        if !self.show_warnings {
            return;
        }

        // Only show warning for certain commands to avoid spam
        let warning_commands = [
            "pull", "push", "project", "set", "share", "rotate", "verify", "audit", "status",
        ];

        if !warning_commands.contains(&command_name) {
            return;
        }

        if json_output {
            let warning = serde_json::json!({
                "type": "recovery_warning",
                "level": "warning",
                "message": "Only one device enrolled - consider adding recovery options",
                "recommendation": "Enroll additional devices or set up recovery contacts"
            });
            eprintln!(
                "{}",
                serde_json::to_string_pretty(&warning).unwrap_or_default()
            );
        } else {
            eprintln!("{}", style("⚠ Recovery Warning").yellow().bold());
            eprintln!("  You have only one device enrolled. If you lose access to this device,");
            eprintln!("  you may permanently lose access to your secrets.");
            eprintln!("  Consider: 'myc device enroll <name>' on another device");
            eprintln!();
        }
    }

    /// Display recovery status in status command
    ///
    /// This provides detailed recovery information for the status command
    pub fn display_recovery_status(
        &self,
        status: &RecoveryStatus,
        json_output: bool,
    ) -> Result<()> {
        if json_output {
            // JSON output is handled by the caller
            return Ok(());
        }

        println!("{}", style("Recovery Status").bold());

        // Device count with status indicator
        let device_status = if status.devices_enrolled == 1 {
            style(format!("{} (⚠ Single device)", status.devices_enrolled)).yellow()
        } else if status.devices_enrolled >= 2 {
            style(format!("{} (✓ Multiple devices)", status.devices_enrolled)).green()
        } else {
            style(format!("{} (✗ No devices)", status.devices_enrolled)).red()
        };
        println!("  Devices Enrolled: {}", device_status);

        // Recovery contacts
        let contacts_status = if status.recovery_contacts > 0 {
            style(format!("{} (✓ Configured)", status.recovery_contacts)).green()
        } else {
            style("0 (Not configured)".to_string()).yellow()
        };
        println!("  Recovery Contacts: {}", contacts_status);

        // Organization recovery key
        let org_recovery_status = if status.org_recovery_key {
            style("✓ Configured").green()
        } else {
            style("Not configured").yellow()
        };
        println!("  Org Recovery Key: {}", org_recovery_status);

        // Recovery recommendations
        if status.devices_enrolled == 1 && status.recovery_contacts == 0 && !status.org_recovery_key
        {
            println!();
            println!(
                "  {} No recovery options configured!",
                style("⚠").yellow().bold()
            );
            println!("  Recommendations:");
            println!("    • Enroll a second device: 'myc device enroll <name>'");
            println!("    • Set up recovery contacts (coming soon)");
            println!("    • Configure org recovery key (coming soon)");
        } else if status.devices_enrolled == 1 {
            println!();
            println!(
                "  {} Consider enrolling additional devices",
                style("💡").blue()
            );
        }

        Ok(())
    }

    /// Check if recovery warnings should be suppressed
    ///
    /// Warnings are suppressed in:
    /// - Non-interactive mode (CI)
    /// - When explicitly disabled
    /// - For certain commands that shouldn't show warnings
    pub fn should_show_warnings(&self, command_name: &str) -> bool {
        if !self.show_warnings {
            return false;
        }

        // Don't show warnings for these commands
        let no_warning_commands = ["help", "completions", "version", "profile", "cache"];

        !no_warning_commands.contains(&command_name)
    }
}

impl Default for RecoveryWarnings {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recovery_status_default() {
        let status = RecoveryStatus::default();
        assert_eq!(status.devices_enrolled, 1);
        assert_eq!(status.recovery_contacts, 0);
        assert!(!status.org_recovery_key);
        assert!(status.user_devices.is_empty());
    }

    #[test]
    fn test_recovery_warnings_new() {
        let warnings = RecoveryWarnings::new();
        // Should be true unless in non-interactive mode
        assert_eq!(
            warnings.show_warnings,
            !crate::non_interactive::NonInteractiveMode::is_enabled()
        );
    }

    #[test]
    fn test_should_show_warnings() {
        let warnings = RecoveryWarnings {
            show_warnings: true,
        };

        // Should show for most commands
        assert!(warnings.should_show_warnings("pull"));
        assert!(warnings.should_show_warnings("push"));
        assert!(warnings.should_show_warnings("status"));

        // Should not show for these commands
        assert!(!warnings.should_show_warnings("help"));
        assert!(!warnings.should_show_warnings("completions"));
        assert!(!warnings.should_show_warnings("profile"));
    }

    #[test]
    fn test_should_show_warnings_disabled() {
        let warnings = RecoveryWarnings {
            show_warnings: false,
        };

        // Should never show when disabled
        assert!(!warnings.should_show_warnings("pull"));
        assert!(!warnings.should_show_warnings("push"));
        assert!(!warnings.should_show_warnings("status"));
    }
}
