//! JSON output formatting for the Mycelium CLI.
//!
//! This module provides structured JSON output for all CLI operations,
//! ensuring consistent format for both success and error responses.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use time::OffsetDateTime;

/// Standard JSON response structure for CLI operations.
#[derive(Debug, Serialize, Deserialize)]
pub struct JsonResponse {
    /// Whether the operation was successful
    pub success: bool,
    /// Human-readable message
    pub message: String,
    /// Optional error code for programmatic handling
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    /// Optional data payload
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    /// Timestamp of the response
    pub timestamp: OffsetDateTime,
}

impl JsonResponse {
    /// Create a successful response.
    pub fn success(message: impl Into<String>) -> Self {
        Self {
            success: true,
            message: message.into(),
            error_code: None,
            data: None,
            timestamp: OffsetDateTime::now_utc(),
        }
    }

    /// Create a successful response with data.
    pub fn success_with_data<T: Serialize>(message: impl Into<String>, data: T) -> Result<Self> {
        Ok(Self {
            success: true,
            message: message.into(),
            error_code: None,
            data: Some(serde_json::to_value(data)?),
            timestamp: OffsetDateTime::now_utc(),
        })
    }

    /// Create an error response.
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            success: false,
            message: message.into(),
            error_code: Some("general_error".to_string()),
            data: None,
            timestamp: OffsetDateTime::now_utc(),
        }
    }

    /// Create an error response with a specific error code.
    pub fn error_with_code(message: impl Into<String>, error_code: impl Into<String>) -> Self {
        Self {
            success: false,
            message: message.into(),
            error_code: Some(error_code.into()),
            data: None,
            timestamp: OffsetDateTime::now_utc(),
        }
    }

    /// Create an error response with data.
    pub fn error_with_data<T: Serialize>(
        message: impl Into<String>,
        error_code: impl Into<String>,
        data: T,
    ) -> Result<Self> {
        Ok(Self {
            success: false,
            message: message.into(),
            error_code: Some(error_code.into()),
            data: Some(serde_json::to_value(data)?),
            timestamp: OffsetDateTime::now_utc(),
        })
    }

    /// Add data to the response.
    pub fn with_data<T: Serialize>(mut self, data: T) -> Result<Self> {
        self.data = Some(serde_json::to_value(data)?);
        Ok(self)
    }

    /// Convert to pretty-printed JSON string.
    pub fn to_json_string(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Print the JSON response to stdout.
    pub fn print(&self) -> Result<()> {
        println!("{}", self.to_json_string()?);
        Ok(())
    }
}

/// JSON formatter for specific CLI operations.
pub struct JsonFormatter;

impl JsonFormatter {
    /// Format profile list output.
    pub fn profile_list(
        profiles: Vec<String>,
        default_profile: Option<String>,
    ) -> Result<JsonResponse> {
        let data = serde_json::json!({
            "profiles": profiles,
            "default": default_profile,
            "count": profiles.len()
        });
        JsonResponse::success_with_data("Profiles listed successfully", data)
    }

    /// Format profile details output.
    pub fn profile_details(
        profile: &crate::profile::Profile,
        is_default: bool,
    ) -> Result<JsonResponse> {
        let data = serde_json::json!({
            "name": profile.name,
            "github_owner": profile.github_owner,
            "github_repo": profile.github_repo,
            "github_user_id": profile.github_user_id,
            "github_username": profile.github_username,
            "device_id": profile.device_id,
            "created_at": profile.created_at,
            "is_default": is_default,
            "vault_url": format!("https://github.com/{}/{}", profile.github_owner, profile.github_repo)
        });
        JsonResponse::success_with_data("Profile details retrieved", data)
    }

    /// Format device list output.
    pub fn device_list<T: Serialize>(devices: Vec<T>) -> Result<JsonResponse> {
        let data = serde_json::json!({
            "devices": devices,
            "count": devices.len()
        });
        JsonResponse::success_with_data("Devices listed successfully", data)
    }

    /// Format project list output.
    pub fn project_list<T: Serialize>(projects: Vec<T>) -> Result<JsonResponse> {
        let data = serde_json::json!({
            "projects": projects,
            "count": projects.len()
        });
        JsonResponse::success_with_data("Projects listed successfully", data)
    }

    /// Format secret set list output.
    pub fn secret_set_list<T: Serialize>(
        secret_sets: Vec<T>,
        project_name: &str,
    ) -> Result<JsonResponse> {
        let data = serde_json::json!({
            "secret_sets": secret_sets,
            "project": project_name,
            "count": secret_sets.len()
        });
        JsonResponse::success_with_data("Secret sets listed successfully", data)
    }

    /// Format pull operation output.
    pub fn pull_secrets(
        project_name: &str,
        set_name: &str,
        version: u64,
        format: &str,
        entry_count: usize,
        output_file: Option<&str>,
    ) -> Result<JsonResponse> {
        let mut data = serde_json::json!({
            "project": project_name,
            "secret_set": set_name,
            "version": version,
            "format": format,
            "entry_count": entry_count
        });

        if let Some(file) = output_file {
            data.as_object_mut()
                .unwrap()
                .insert("output_file".to_string(), Value::String(file.to_string()));
        }

        JsonResponse::success_with_data("Secrets pulled successfully", data)
    }

    /// Format push operation output.
    pub fn push_secrets(
        project_name: &str,
        set_name: &str,
        new_version: u64,
        entry_count: usize,
        format: &str,
    ) -> Result<JsonResponse> {
        let data = serde_json::json!({
            "project": project_name,
            "secret_set": set_name,
            "new_version": new_version,
            "entry_count": entry_count,
            "format": format
        });
        JsonResponse::success_with_data("Secrets pushed successfully", data)
    }

    /// Format version list output.
    pub fn version_list<T: Serialize>(
        versions: Vec<T>,
        project_name: &str,
        set_name: &str,
    ) -> Result<JsonResponse> {
        let data = serde_json::json!({
            "versions": versions,
            "project": project_name,
            "secret_set": set_name,
            "count": versions.len()
        });
        JsonResponse::success_with_data("Versions listed successfully", data)
    }

    /// Format audit log output.
    pub fn audit_list<T: Serialize>(
        events: Vec<T>,
        filters: Option<HashMap<String, String>>,
    ) -> Result<JsonResponse> {
        let mut data = serde_json::json!({
            "events": events,
            "count": events.len()
        });

        if let Some(filters) = filters {
            data.as_object_mut()
                .unwrap()
                .insert("filters".to_string(), serde_json::to_value(filters)?);
        }

        JsonResponse::success_with_data("Audit events listed successfully", data)
    }

    /// Format verification results.
    pub fn verification_results(
        verified_items: usize,
        failed_items: usize,
        details: Option<Value>,
    ) -> Result<JsonResponse> {
        let mut data = serde_json::json!({
            "verified_items": verified_items,
            "failed_items": failed_items,
            "total_items": verified_items + failed_items,
            "success_rate": if verified_items + failed_items > 0 {
                (verified_items as f64) / ((verified_items + failed_items) as f64)
            } else {
                1.0
            }
        });

        if let Some(details) = details {
            data.as_object_mut()
                .unwrap()
                .insert("details".to_string(), details);
        }

        let message = if failed_items == 0 {
            "All items verified successfully"
        } else {
            "Verification completed with failures"
        };

        JsonResponse::success_with_data(message, data)
    }

    /// Format diff results.
    pub fn diff_results(
        added: Vec<String>,
        removed: Vec<String>,
        changed: Vec<String>,
        project_name: &str,
        set_name: &str,
        v1: u64,
        v2: u64,
    ) -> Result<JsonResponse> {
        let data = serde_json::json!({
            "project": project_name,
            "secret_set": set_name,
            "version_1": v1,
            "version_2": v2,
            "changes": {
                "added": added,
                "removed": removed,
                "changed": changed
            },
            "summary": {
                "added_count": added.len(),
                "removed_count": removed.len(),
                "changed_count": changed.len(),
                "total_changes": added.len() + removed.len() + changed.len()
            }
        });
        JsonResponse::success_with_data("Diff completed successfully", data)
    }

    /// Format membership list output.
    pub fn membership_list<T: Serialize>(
        members: Vec<T>,
        project_name: &str,
    ) -> Result<JsonResponse> {
        let data = serde_json::json!({
            "members": members,
            "project": project_name,
            "count": members.len()
        });
        JsonResponse::success_with_data("Members listed successfully", data)
    }

    /// Format cache status output.
    pub fn cache_status(
        cache_size: u64,
        cache_entries: usize,
        last_cleared: Option<OffsetDateTime>,
    ) -> Result<JsonResponse> {
        let data = serde_json::json!({
            "cache_size_bytes": cache_size,
            "cache_entries": cache_entries,
            "last_cleared": last_cleared,
            "cache_size_human": crate::output::format_size(cache_size)
        });
        JsonResponse::success_with_data("Cache status retrieved", data)
    }
}

/// Common error codes used throughout the CLI.
pub mod error_codes {
    pub const AUTHENTICATION_FAILED: &str = "authentication_failed";
    pub const PERMISSION_DENIED: &str = "permission_denied";
    pub const NOT_FOUND: &str = "not_found";
    pub const ALREADY_EXISTS: &str = "already_exists";
    pub const INVALID_INPUT: &str = "invalid_input";
    pub const NETWORK_ERROR: &str = "network_error";
    pub const CRYPTO_ERROR: &str = "crypto_error";
    pub const CONFLICT: &str = "conflict";
    pub const RATE_LIMITED: &str = "rate_limited";
    pub const INTERNAL_ERROR: &str = "internal_error";
    pub const USER_CANCELLED: &str = "user_cancelled";
    pub const PROJECT_NOT_FOUND: &str = "project_not_found";
    pub const SET_NOT_FOUND: &str = "set_not_found";
    pub const VERSION_NOT_FOUND: &str = "version_not_found";
    pub const DEVICE_NOT_FOUND: &str = "device_not_found";
    pub const PROFILE_NOT_FOUND: &str = "profile_not_found";
    pub const INVALID_PASSPHRASE: &str = "invalid_passphrase";
    pub const PDK_ACCESS_DENIED: &str = "pdk_access_denied";
    pub const SIGNATURE_VERIFICATION_FAILED: &str = "signature_verification_failed";
    pub const HASH_CHAIN_BROKEN: &str = "hash_chain_broken";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_response_success() {
        let response = JsonResponse::success("Operation completed");
        assert!(response.success);
        assert_eq!(response.message, "Operation completed");
        assert!(response.error_code.is_none());
    }

    #[test]
    fn test_json_response_error() {
        let response = JsonResponse::error("Something went wrong");
        assert!(!response.success);
        assert_eq!(response.message, "Something went wrong");
        assert_eq!(response.error_code, Some("general_error".to_string()));
    }

    #[test]
    fn test_json_response_with_data() -> Result<()> {
        let data = serde_json::json!({"key": "value"});
        let response = JsonResponse::success_with_data("Success with data", data)?;
        assert!(response.success);
        assert!(response.data.is_some());
        Ok(())
    }

    #[test]
    fn test_json_response_serialization() -> Result<()> {
        let response = JsonResponse::success("Test message");
        let json_str = response.to_json_string()?;
        assert!(json_str.contains("\"success\": true"));
        assert!(json_str.contains("\"message\": \"Test message\""));
        Ok(())
    }
}
