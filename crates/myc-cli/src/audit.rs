//! Audit command implementations.
//!
//! This module provides CLI commands for managing audit logs:
//! - List audit events with filtering
//! - Show specific audit event details
//! - Export audit logs in various formats
//! - Add manual audit notes

use anyhow::{Context, Result};
use console::style;
use myc_core::audit::{
    export::{ExportFilter, ExportFormat},
    notes, storage, AuditEvent, EventId, EventType, SignedAuditEvent,
};
use myc_core::ids::{OrgId, ProjectId};
use myc_github::client::GitHubClient;
use serde_json;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::profile::{Profile, ProfileManager};

/// List audit events with optional filtering.
pub async fn list_audit_events(
    project: Option<&str>,
    user: Option<&str>,
    event_type: Option<&str>,
    since: Option<&str>,
    until: Option<&str>,
    limit: Option<u64>,
    profile: &Profile,
    json_output: bool,
) -> Result<()> {
    // Create GitHub client
    let token =
        std::env::var("GITHUB_TOKEN").context("GITHUB_TOKEN environment variable not set")?;

    let client = GitHubClient::new(
        token,
        profile.github_owner.clone(),
        profile.github_repo.clone(),
    )?;

    // Check repository access
    if !client.check_access().await? {
        anyhow::bail!(
            "Cannot access repository {}/{}. Check your permissions.",
            profile.github_owner,
            profile.github_repo
        );
    }

    // Load audit events from GitHub
    let audit_events = load_audit_events(&client).await?;

    // Create filter
    let mut filter = ExportFilter::new();

    if let Some(project_str) = project {
        // Try to parse as UUID first, then as project name
        if let Ok(uuid) = Uuid::parse_str(project_str) {
            filter.project_id = Some(ProjectId::from_uuid(uuid));
        } else {
            // For now, we'll need to look up project by name
            // In a full implementation, this would load project metadata
            return Err(anyhow::anyhow!(
                "Project lookup by name not yet implemented. Use project UUID."
            ));
        }
    }

    if let Some(user_id) = user {
        filter.user_id = Some(user_id.to_string());
    }

    if let Some(event_type_str) = event_type {
        let parsed_event_type = parse_event_type(event_type_str)?;
        filter.event_type = Some(parsed_event_type);
    }

    if let Some(since_str) = since {
        let since_date = parse_date(since_str)?;
        filter.start_date = Some(since_date);
    }

    if let Some(until_str) = until {
        let until_date = parse_date(until_str)?;
        filter.end_date = Some(until_date);
    }

    // Filter events
    let filtered_events: Vec<&SignedAuditEvent> = audit_events
        .iter()
        .filter(|event| filter.matches(&event.event))
        .collect();

    // Apply limit
    let limited_events: Vec<&SignedAuditEvent> = if let Some(limit_count) = limit {
        filtered_events
            .into_iter()
            .take(limit_count as usize)
            .collect()
    } else {
        filtered_events
    };

    // Output results
    if json_output {
        let output = serde_json::json!({
            "events": limited_events,
            "total_count": limited_events.len(),
            "filter": {
                "project": project,
                "user": user,
                "event_type": event_type,
                "since": since,
                "until": until,
                "limit": limit
            }
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        if limited_events.is_empty() {
            println!("No audit events found matching the criteria.");
        } else {
            println!("Audit Events ({} found):", limited_events.len());
            println!();

            for event in limited_events {
                print_audit_event_summary(&event.event);
            }
        }
    }

    Ok(())
}

/// Show details of a specific audit event.
pub async fn show_audit_event(event_id: &str, profile: &Profile, json_output: bool) -> Result<()> {
    // Parse event ID
    let uuid = Uuid::parse_str(event_id).context("Invalid event ID format. Expected UUID.")?;
    let event_uuid = EventId::from_uuid(uuid);

    // Create GitHub client
    let token =
        std::env::var("GITHUB_TOKEN").context("GITHUB_TOKEN environment variable not set")?;

    let client = GitHubClient::new(
        token,
        profile.github_owner.clone(),
        profile.github_repo.clone(),
    )?;

    // Check repository access
    if !client.check_access().await? {
        anyhow::bail!(
            "Cannot access repository {}/{}. Check your permissions.",
            profile.github_owner,
            profile.github_repo
        );
    }

    // Load audit events and find the specific one
    let audit_events = load_audit_events(&client).await?;

    let found_event = audit_events
        .iter()
        .find(|event| event.event.event_id == event_uuid)
        .ok_or_else(|| anyhow::anyhow!("Audit event '{}' not found", event_id))?;

    // Output event details
    if json_output {
        println!("{}", serde_json::to_string_pretty(found_event)?);
    } else {
        print_audit_event_details(&found_event.event);

        // Show signature verification status
        println!();
        println!("Signature:");
        println!("  Signed by: {}", found_event.signed_by);
        let signature_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            found_event.signature.as_bytes(),
        );
        println!("  Signature: {}...", &signature_b64[..16]);

        // TODO: Verify signature if we have the public key
        println!(
            "  Status: {} (verification not implemented)",
            style("Unknown").yellow()
        );
    }

    Ok(())
}

/// Export audit logs in the specified format.
pub async fn export_audit_logs(
    format: &str,
    output: Option<&str>,
    project: Option<&str>,
    since: Option<&str>,
    until: Option<&str>,
    profile: &Profile,
) -> Result<()> {
    // Parse export format
    let export_format = match format.to_lowercase().as_str() {
        "json" => ExportFormat::Json,
        "csv" => ExportFormat::Csv,
        "syslog" => ExportFormat::Syslog,
        _ => {
            anyhow::bail!(
                "Unsupported export format '{}'. Supported formats: json, csv, syslog",
                format
            );
        }
    };

    // Create GitHub client
    let token =
        std::env::var("GITHUB_TOKEN").context("GITHUB_TOKEN environment variable not set")?;

    let client = GitHubClient::new(
        token,
        profile.github_owner.clone(),
        profile.github_repo.clone(),
    )?;

    // Check repository access
    if !client.check_access().await? {
        anyhow::bail!(
            "Cannot access repository {}/{}. Check your permissions.",
            profile.github_owner,
            profile.github_repo
        );
    }

    // Load audit events
    let audit_events = load_audit_events(&client).await?;

    // Create filter
    let mut filter = ExportFilter::new();

    if let Some(project_str) = project {
        // Try to parse as UUID first
        if let Ok(uuid) = Uuid::parse_str(project_str) {
            filter.project_id = Some(ProjectId::from_uuid(uuid));
        } else {
            return Err(anyhow::anyhow!(
                "Project lookup by name not yet implemented. Use project UUID."
            ));
        }
    }

    if let Some(since_str) = since {
        let since_date = parse_date(since_str)?;
        filter.start_date = Some(since_date);
    }

    if let Some(until_str) = until {
        let until_date = parse_date(until_str)?;
        filter.end_date = Some(until_date);
    }

    // Export events
    let exported_data =
        myc_core::audit::export::export(&audit_events, export_format, Some(&filter))?;

    // Write output
    if let Some(output_file) = output {
        std::fs::write(output_file, exported_data)
            .with_context(|| format!("Failed to write to file '{}'", output_file))?;

        println!(
            "{} Exported audit logs to '{}'",
            style("✓").green(),
            output_file
        );
    } else {
        print!("{}", exported_data);
    }

    Ok(())
}

/// Add a manual audit note.
pub async fn add_audit_note(
    message: &str,
    project: Option<&str>,
    profile: &Profile,
    json_output: bool,
) -> Result<()> {
    // Create GitHub client
    let token =
        std::env::var("GITHUB_TOKEN").context("GITHUB_TOKEN environment variable not set")?;

    let client = GitHubClient::new(
        token,
        profile.github_owner.clone(),
        profile.github_repo.clone(),
    )?;

    // Check repository access
    if !client.check_access().await? {
        anyhow::bail!(
            "Cannot access repository {}/{}. Check your permissions.",
            profile.github_owner,
            profile.github_repo
        );
    }

    // Parse project ID if provided
    let project_id = if let Some(project_str) = project {
        if let Ok(uuid) = Uuid::parse_str(project_str) {
            Some(ProjectId::from_uuid(uuid))
        } else {
            return Err(anyhow::anyhow!(
                "Project lookup by name not yet implemented. Use project UUID."
            ));
        }
    } else {
        None
    };

    // Load device keys
    let profile_manager = ProfileManager::new(ProfileManager::default_config_dir()?);
    let passphrase = std::env::var("MYC_KEY_PASSPHRASE").unwrap_or_else(|_| {
        // In a full implementation, this would prompt for passphrase
        // For now, we'll use an empty passphrase
        String::new()
    });

    let signing_key_path = profile_manager.signing_key_path(&profile.name);
    let signing_key = crate::key_storage::load_signing_key(&signing_key_path, &passphrase)
        .context("Failed to load signing key. Ensure device is properly enrolled.")?;

    // Load current audit state
    let audit_events = load_audit_events(&client).await?;
    let (previous_chain_hash, previous_event_id) = if let Some(last_event) = audit_events.last() {
        (
            last_event.event.chain_hash.clone(),
            Some(last_event.event.event_id),
        )
    } else {
        (vec![], None)
    };

    // Create audit note
    let signed_note = notes::create_note(
        message.to_string(),
        profile.device_id,
        format!("github|{}", profile.github_user_id),
        OrgId::new(), // TODO: Load actual org ID from vault
        project_id,
        &previous_chain_hash,
        previous_event_id,
        &signing_key,
    )?;

    // Store the audit note
    let event_path = storage::signed_event_path(&signed_note);
    let event_json = serde_json::to_string_pretty(&signed_note)?;

    client
        .write_file(
            &event_path,
            event_json.as_bytes(),
            &format!("Add audit note: {}", message),
            None,
        )
        .await?;

    // Update audit index
    // TODO: Implement audit index update

    if json_output {
        let output = serde_json::json!({
            "success": true,
            "event_id": signed_note.event.event_id,
            "message": "Audit note added successfully",
            "note": message,
            "project_id": project_id
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("{} Added audit note", style("✓").green());
        println!("  Event ID: {}", signed_note.event.event_id);
        println!("  Message: {}", message);
        if let Some(proj_id) = project_id {
            println!("  Project: {}", proj_id);
        }
        println!(
            "  Timestamp: {}",
            signed_note
                .event
                .timestamp
                .format(&time::format_description::well_known::Rfc3339)?
        );
    }

    Ok(())
}

// Helper functions

/// Load all audit events from the GitHub repository.
async fn load_audit_events(client: &GitHubClient) -> Result<Vec<SignedAuditEvent>> {
    let mut events = Vec::new();

    // List audit directories (organized by month)
    let audit_dirs = match client.list_directory(".mycelium/audit").await {
        Ok(dirs) => dirs,
        Err(_) => {
            // No audit directory exists yet
            return Ok(events);
        }
    };

    // Process each month directory
    for dir_entry in audit_dirs {
        if dir_entry.is_dir && dir_entry.name.matches(char::is_numeric).count() >= 4 {
            // This looks like a YYYY-MM directory
            let month_path = format!(".mycelium/audit/{}", dir_entry.name);

            let event_files = match client.list_directory(&month_path).await {
                Ok(files) => files,
                Err(_) => continue, // Skip if we can't read this directory
            };

            // Load each event file
            for file_entry in event_files {
                if file_entry.name.ends_with(".json") {
                    let event_path = format!("{}/{}", month_path, file_entry.name);

                    match client.read_file(&event_path).await {
                        Ok(content) => match serde_json::from_slice::<SignedAuditEvent>(&content) {
                            Ok(event) => events.push(event),
                            Err(e) => {
                                eprintln!(
                                    "Warning: Failed to parse audit event {}: {}",
                                    event_path, e
                                );
                            }
                        },
                        Err(e) => {
                            eprintln!("Warning: Failed to read audit event {}: {}", event_path, e);
                        }
                    }
                }
            }
        }
    }

    // Sort events by timestamp
    events.sort_by(|a, b| a.event.timestamp.cmp(&b.event.timestamp));

    Ok(events)
}

/// Parse an event type string into an EventType enum.
fn parse_event_type(event_type_str: &str) -> Result<EventType> {
    match event_type_str.to_lowercase().as_str() {
        "org_created" => Ok(EventType::OrgCreated),
        "org_settings_updated" => Ok(EventType::OrgSettingsUpdated),
        "device_enrolled" => Ok(EventType::DeviceEnrolled),
        "device_approved" => Ok(EventType::DeviceApproved),
        "device_revoked" => Ok(EventType::DeviceRevoked),
        "project_created" => Ok(EventType::ProjectCreated),
        "project_deleted" => Ok(EventType::ProjectDeleted),
        "member_added" => Ok(EventType::MemberAdded),
        "member_removed" => Ok(EventType::MemberRemoved),
        "role_changed" => Ok(EventType::RoleChanged),
        "ownership_transferred" => Ok(EventType::OwnershipTransferred),
        "secret_set_created" => Ok(EventType::SecretSetCreated),
        "secret_set_deleted" => Ok(EventType::SecretSetDeleted),
        "secret_version_created" => Ok(EventType::SecretVersionCreated),
        "pdk_rotated" => Ok(EventType::PdkRotated),
        "pdk_wrapped" => Ok(EventType::PdkWrapped),
        "audit_note" => Ok(EventType::AuditNote),
        "recovery_initiated" => Ok(EventType::RecoveryInitiated),
        "recovery_completed" => Ok(EventType::RecoveryCompleted),
        "ci_enrolled" => Ok(EventType::CiEnrolled),
        "ci_pull" => Ok(EventType::CiPull),
        "ci_expired" => Ok(EventType::CiExpired),
        "ci_revoked" => Ok(EventType::CiRevoked),
        _ => Err(anyhow::anyhow!("Unknown event type: {}", event_type_str)),
    }
}

/// Parse a date string (YYYY-MM-DD) into an OffsetDateTime.
fn parse_date(date_str: &str) -> Result<OffsetDateTime> {
    let date = time::Date::parse(
        date_str,
        &time::format_description::parse("[year]-[month]-[day]")?,
    )?;

    Ok(date.midnight().assume_utc())
}

/// Print a summary of an audit event.
fn print_audit_event_summary(event: &AuditEvent) {
    let timestamp = event
        .timestamp
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "Invalid timestamp".to_string());

    println!(
        "  {} {} {} {}",
        style(&timestamp).dim(),
        style(format!("{:?}", event.event_type)).cyan(),
        style(&event.actor_user_id).yellow(),
        style(&event.event_id.to_string()[..8]).dim()
    );

    // Show brief details based on event type
    match &event.details {
        myc_core::audit::EventDetails::Project(details) => {
            println!("    Project: {}", details.project_name);
        }
        myc_core::audit::EventDetails::Secret(details) => {
            println!(
                "    Secret Set: {} ({})",
                details.set_name, details.project_id
            );
        }
        myc_core::audit::EventDetails::Membership(details) => {
            println!("    User: {} -> {:?}", details.user_id, details.role);
        }
        myc_core::audit::EventDetails::Admin(details) => {
            println!("    Note: {}", details.note);
        }
        _ => {}
    }

    println!();
}

/// Print detailed information about an audit event.
fn print_audit_event_details(event: &AuditEvent) {
    println!("Audit Event Details:");
    println!("  Event ID: {}", event.event_id);
    println!("  Type: {:?}", event.event_type);
    println!(
        "  Timestamp: {}",
        event
            .timestamp
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "Invalid timestamp".to_string())
    );
    println!(
        "  Actor: {} ({})",
        event.actor_user_id, event.actor_device_id
    );
    println!("  Organization: {}", event.org_id);

    if let Some(project_id) = event.project_id {
        println!("  Project: {}", project_id);
    }

    println!();
    println!("Event Details:");
    match &event.details {
        myc_core::audit::EventDetails::Org(details) => {
            println!("  Organization: {}", details.name);
            if let Some(settings) = &details.settings {
                println!("  Settings: {}", settings);
            }
        }
        myc_core::audit::EventDetails::Device(details) => {
            println!("  Device: {} ({})", details.device_name, details.device_id);
            println!("  Type: {}", details.device_type);
            if let Some(reason) = &details.reason {
                println!("  Reason: {}", reason);
            }
        }
        myc_core::audit::EventDetails::Project(details) => {
            println!(
                "  Project: {} ({})",
                details.project_name, details.project_id
            );
        }
        myc_core::audit::EventDetails::Membership(details) => {
            println!("  Project: {}", details.project_id);
            println!("  User: {}", details.user_id);
            if let Some(role) = &details.role {
                println!("  Role: {}", role);
            }
            if let Some(prev_role) = &details.previous_role {
                println!("  Previous Role: {}", prev_role);
            }
        }
        myc_core::audit::EventDetails::Secret(details) => {
            println!("  Project: {}", details.project_id);
            println!("  Secret Set: {} ({})", details.set_name, details.set_id);
            if let Some(version) = details.version {
                println!("  Version: {}", version);
            }
            if let Some(message) = &details.message {
                println!("  Message: {}", message);
            }
        }
        myc_core::audit::EventDetails::Key(details) => {
            println!("  Project: {}", details.project_id);
            println!("  PDK Version: {}", details.pdk_version);
            println!("  Reason: {}", details.reason);
            if !details.excluded_devices.is_empty() {
                println!("  Excluded Devices: {:?}", details.excluded_devices);
            }
        }
        myc_core::audit::EventDetails::Admin(details) => {
            println!("  Note: {}", details.note);
            if let Some(project_id) = details.project_id {
                println!("  Project: {}", project_id);
            }
        }
        myc_core::audit::EventDetails::Ci(details) => {
            println!("  Device: {}", details.device_id);
            println!("  Repository: {}", details.repository);
            if let Some(workflow) = &details.workflow {
                println!("  Workflow: {}", workflow);
            }
            if let Some(git_ref) = &details.git_ref {
                println!("  Git Ref: {}", git_ref);
            }
            if let Some(project_id) = details.project_id {
                println!("  Project: {}", project_id);
            }
            if let Some(set_id) = details.set_id {
                println!("  Secret Set: {}", set_id);
            }
        }
    }

    println!();
    println!("Chain Information:");
    println!(
        "  Chain Hash: {}",
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &event.chain_hash
        )
    );

    if let Some(prev_id) = event.previous_event_id {
        println!("  Previous Event: {}", prev_id);
    } else {
        println!("  Previous Event: {} (first event)", style("None").dim());
    }
}
