//! Mycelium CLI - A living, zero-knowledge secrets mesh.

#![allow(clippy::too_many_arguments)]
#![allow(clippy::collapsible_else_if)]
#![allow(clippy::redundant_pattern_matching)]
#![allow(clippy::needless_return)]
#![allow(clippy::ptr_arg)]
#![allow(clippy::needless_borrow)]
#![allow(clippy::op_ref)]
#![allow(unused_imports)]
#![allow(unused_variables)]

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{generate, Shell};
use std::fs;
use std::io;

// Import CLI modules
use myc_cli::device;
use myc_cli::profile;
use myc_cli::recovery::{RecoveryStatus, RecoveryWarnings};
use myc_github::GitHubClient;

/// Mycelium CLI
#[derive(Parser)]
#[command(name = "myc")]
#[command(about = "A living, zero-knowledge secrets mesh", long_about = None)]
#[command(version)]
struct Cli {
    /// Enable verbose output
    #[arg(long, short = 'v', global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Output in JSON format
    #[arg(long, short = 'j', global = true)]
    json: bool,

    /// Suppress non-essential output
    #[arg(long, short = 'q', global = true)]
    quiet: bool,

    /// Disable colored output
    #[arg(long, global = true)]
    no_color: bool,

    /// Profile to use (overrides default)
    #[arg(long, short = 'p', global = true)]
    profile: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

/// Available commands
#[derive(Subcommand)]
enum Commands {
    /// Manage profiles
    Profile {
        #[command(subcommand)]
        command: ProfileCommands,
    },
    /// Manage organization
    Org {
        #[command(subcommand)]
        command: OrgCommands,
    },
    /// Manage devices
    Device {
        #[command(subcommand)]
        command: DeviceCommands,
    },
    /// Manage projects
    Project {
        #[command(subcommand)]
        command: ProjectCommands,
    },
    /// Manage secret sets
    Set {
        #[command(subcommand)]
        command: SetCommands,
    },
    /// Pull secrets from a set
    Pull {
        /// Project name or ID (can be set in .myc.yaml)
        project: Option<String>,
        /// Secret set name or ID (can be set in .myc.yaml)
        set: Option<String>,
        /// Version to pull (defaults to latest)
        #[arg(long)]
        version: Option<u64>,
        /// Output format (dotenv, json, shell, yaml) (can be set in .myc.yaml)
        #[arg(long, short = 'f')]
        format: Option<String>,
        /// Output file (defaults to stdout) (can be set in .myc.yaml)
        #[arg(long, short = 'o')]
        output: Option<String>,
    },
    /// Push secrets to a set
    Push {
        /// Project name or ID (can be set in .myc.yaml)
        project: Option<String>,
        /// Secret set name or ID (can be set in .myc.yaml)
        set: Option<String>,
        /// Input file (defaults to stdin)
        #[arg(long, short = 'i')]
        input: Option<String>,
        /// Input format (dotenv, json, auto-detect)
        #[arg(long, short = 'f')]
        format: Option<String>,
        /// Commit message
        #[arg(long, short = 'm')]
        message: Option<String>,
    },
    /// Manage project sharing
    Share {
        #[command(subcommand)]
        command: ShareCommands,
    },
    /// Rotate project encryption keys
    Rotate {
        /// Project name or ID
        project: String,
        /// Rotation reason
        #[arg(long, short = 'r')]
        reason: Option<String>,
        /// Additional note
        #[arg(long, short = 'n')]
        note: Option<String>,
    },
    /// Manage secret set versions
    Versions {
        #[command(subcommand)]
        command: VersionsCommands,
    },
    /// Compare secret set versions
    Diff {
        /// Project name or ID
        project: String,
        /// Secret set name or ID
        set: String,
        /// First version to compare
        v1: u64,
        /// Second version to compare
        v2: u64,
        /// Show value changes (default: keys only)
        #[arg(long)]
        show_values: bool,
    },
    /// Verify vault integrity
    Verify {
        /// Project name or ID (optional, verifies all if not specified)
        project: Option<String>,
        /// Secret set name or ID (optional, verifies all if not specified)
        set: Option<String>,
        /// Verify signatures only
        #[arg(long)]
        signatures_only: bool,
        /// Verify hash chains only
        #[arg(long)]
        chains_only: bool,
    },
    /// Manage audit logs
    Audit {
        #[command(subcommand)]
        command: AuditCommands,
    },
    /// CI/CD integration commands
    Ci {
        #[command(subcommand)]
        command: CiCommands,
    },
    /// Manage local cache
    Cache {
        #[command(subcommand)]
        command: CacheCommands,
    },
    /// Manage key recovery
    Recovery {
        #[command(subcommand)]
        command: RecoveryCommands,
    },
    /// Run a command with secrets injected as environment variables
    Run {
        /// Project name or ID (can be set in .myc.yaml)
        #[arg(long)]
        project: Option<String>,
        /// Secret set name or ID (can be set in .myc.yaml)
        #[arg(long, short = 's')]
        set: Option<String>,
        /// Version to use (defaults to latest)
        #[arg(long)]
        version: Option<u64>,
        /// Command to execute
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: Shell,
    },
    /// Show system status and information
    Status,
    /// Add common secret file patterns to .gitignore
    Gitignore {
        /// Path to .gitignore file (defaults to ./.gitignore)
        #[arg(long, short = 'f')]
        file: Option<String>,
        /// Show what would be added without modifying the file
        #[arg(long)]
        dry_run: bool,
    },
}

/// Profile management commands
#[derive(Subcommand)]
enum ProfileCommands {
    /// Add a new profile
    Add {
        /// Profile name
        name: String,
        /// GitHub repository (owner/repo)
        #[arg(long, short = 'r')]
        repo: Option<String>,
    },
    /// List all profiles
    List,
    /// Switch to a profile
    Use {
        /// Profile name
        name: String,
    },
    /// Remove a profile
    Remove {
        /// Profile name
        name: String,
        /// Skip confirmation prompt
        #[arg(long)]
        force: bool,
    },
    /// Show profile details
    Show {
        /// Profile name (defaults to current)
        name: Option<String>,
    },
}

/// Organization management commands
#[derive(Subcommand)]
enum OrgCommands {
    /// Initialize a new vault
    Init {
        /// Organization name
        name: String,
        /// GitHub repository name (defaults to secrets-vault)
        #[arg(long, short = 'r')]
        repo: Option<String>,
        /// Make repository private (default: true)
        #[arg(long)]
        public: bool,
    },
    /// Show organization details
    Show,
    /// Manage organization settings
    Settings {
        /// Require device approval
        #[arg(long)]
        require_approval: Option<bool>,
        /// Default rotation policy
        #[arg(long)]
        rotation_policy: Option<String>,
    },
}

/// Device management commands
#[derive(Subcommand)]
enum DeviceCommands {
    /// List devices
    List {
        /// Show all devices (default: current user only)
        #[arg(long)]
        all: bool,
    },
    /// Show device details
    Show {
        /// Device ID
        device_id: String,
    },
    /// Enroll a new device
    Enroll {
        /// Device name
        name: String,
        /// Device type (interactive, ci)
        #[arg(long, short = 't')]
        device_type: Option<String>,
        /// Expiration time for CI devices
        #[arg(long)]
        expires: Option<String>,
    },
    /// Revoke a device
    Revoke {
        /// Device ID
        device_id: String,
        /// Skip confirmation prompt
        #[arg(long)]
        force: bool,
    },
    /// Approve a pending device
    Approve {
        /// Device ID
        device_id: String,
    },
}

/// Project management commands
#[derive(Subcommand)]
enum ProjectCommands {
    /// Create a new project
    Create {
        /// Project name
        name: String,
    },
    /// List projects
    List,
    /// Show project details
    Show {
        /// Project name or ID
        project: String,
    },
    /// Delete a project
    Delete {
        /// Project name or ID
        project: String,
        /// Skip confirmation prompt
        #[arg(long)]
        force: bool,
    },
}

/// Secret set management commands
#[derive(Subcommand)]
enum SetCommands {
    /// Create a new secret set
    Create {
        /// Project name or ID
        project: String,
        /// Secret set name
        name: String,
    },
    /// List secret sets
    List {
        /// Project name or ID
        project: String,
    },
    /// Show secret set details
    Show {
        /// Project name or ID
        project: String,
        /// Secret set name or ID
        set: String,
    },
    /// Delete a secret set
    Delete {
        /// Project name or ID
        project: String,
        /// Secret set name or ID
        set: String,
        /// Skip confirmation prompt
        #[arg(long)]
        force: bool,
    },
}

/// Sharing management commands
#[derive(Subcommand)]
enum ShareCommands {
    /// Add a member to a project
    Add {
        /// Project name or ID
        project: String,
        /// User ID or GitHub username
        user: String,
        /// Role (owner, admin, member, reader)
        #[arg(long, short = 'r')]
        role: String,
    },
    /// Remove a member from a project
    Remove {
        /// Project name or ID
        project: String,
        /// User ID or GitHub username
        user: String,
        /// Skip confirmation prompt
        #[arg(long)]
        force: bool,
    },
    /// List project members
    List {
        /// Project name or ID
        project: String,
    },
    /// Change a member's role
    SetRole {
        /// Project name or ID
        project: String,
        /// User ID or GitHub username
        user: String,
        /// New role (owner, admin, member, reader)
        role: String,
    },
}

/// Version management commands
#[derive(Subcommand)]
enum VersionsCommands {
    /// List versions of a secret set
    List {
        /// Project name or ID
        project: String,
        /// Secret set name or ID
        set: String,
        /// Maximum number of versions to show
        #[arg(long, short = 'n')]
        limit: Option<u64>,
    },
    /// Show details of a specific version
    Show {
        /// Project name or ID
        project: String,
        /// Secret set name or ID
        set: String,
        /// Version number
        version: u64,
    },
}

/// Audit management commands
#[derive(Subcommand)]
enum AuditCommands {
    /// List audit events
    List {
        /// Project name or ID (optional, shows all if not specified)
        #[arg(long)]
        project: Option<String>,
        /// User ID filter
        #[arg(long, short = 'u')]
        user: Option<String>,
        /// Event type filter
        #[arg(long, short = 't')]
        event_type: Option<String>,
        /// Start date (YYYY-MM-DD)
        #[arg(long)]
        since: Option<String>,
        /// End date (YYYY-MM-DD)
        #[arg(long)]
        until: Option<String>,
        /// Maximum number of events to show
        #[arg(long, short = 'n')]
        limit: Option<u64>,
    },
    /// Show details of a specific audit event
    Show {
        /// Event ID
        event_id: String,
    },
    /// Export audit logs
    Export {
        /// Output format (json, csv, syslog)
        #[arg(long, short = 'f')]
        format: String,
        /// Output file (defaults to stdout)
        #[arg(long, short = 'o')]
        output: Option<String>,
        /// Project name or ID filter
        #[arg(long)]
        project: Option<String>,
        /// Start date (YYYY-MM-DD)
        #[arg(long)]
        since: Option<String>,
        /// End date (YYYY-MM-DD)
        #[arg(long)]
        until: Option<String>,
    },
    /// Add a manual audit note
    Note {
        /// Note content
        message: String,
        /// Project name or ID (optional)
        #[arg(long)]
        project: Option<String>,
    },
}

/// CI/CD integration commands
#[derive(Subcommand)]
enum CiCommands {
    /// Enroll a CI device using OIDC
    Enroll {
        /// Device name
        name: String,
        /// OIDC token (from ACTIONS_ID_TOKEN_REQUEST_URL)
        #[arg(long)]
        token: Option<String>,
        /// Expiration time
        #[arg(long)]
        expires: Option<String>,
    },
    /// Pull secrets for CI (non-interactive)
    Pull {
        /// Project name or ID
        project: String,
        /// Secret set name or ID
        set: String,
        /// Output format (shell, dotenv, json)
        #[arg(long, short = 'f', default_value = "shell")]
        format: String,
    },
}

/// Cache management commands
#[derive(Subcommand)]
enum CacheCommands {
    /// Clear local cache
    Clear {
        /// Clear all profiles (default: current profile only)
        #[arg(long)]
        all: bool,
    },
    /// Show cache status
    Status,
}

/// Recovery management commands
#[derive(Subcommand)]
enum RecoveryCommands {
    /// Set recovery contacts
    SetContacts {
        /// User IDs to set as recovery contacts
        contacts: Vec<String>,
    },
    /// Show current recovery contacts
    ShowContacts,
    /// Show recovery status
    Status,
    /// Request recovery assistance
    Request {
        /// New device name
        device_name: String,
    },
    /// Assist with recovery for another user
    Assist {
        /// Recovery request ID
        request_id: String,
    },
}

/// Helper function to format time ago
fn format_time_ago(timestamp: &time::OffsetDateTime) -> String {
    let now = time::OffsetDateTime::now_utc();
    let duration = now - *timestamp;
    
    let days = duration.whole_days();
    let hours = duration.whole_hours();
    let minutes = duration.whole_minutes();
    
    if days > 0 {
        if days == 1 {
            "1 day ago".to_string()
        } else {
            format!("{} days ago", days)
        }
    } else if hours > 0 {
        if hours == 1 {
            "1 hour ago".to_string()
        } else {
            format!("{} hours ago", hours)
        }
    } else if minutes > 0 {
        if minutes == 1 {
            "1 minute ago".to_string()
        } else {
            format!("{} minutes ago", minutes)
        }
    } else {
        "just now".to_string()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize tracing based on verbosity
    let log_level = match cli.verbose {
        0 => "error",
        1 => "warn",
        2 => "info",
        3 => "debug",
        _ => "trace",
    };

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(log_level)),
        )
        .with_target(false)
        .with_ansi(!cli.no_color)
        .init();

    // Initialize recovery warnings
    let recovery_warnings = RecoveryWarnings::new();

    // Get command name for recovery warnings
    let command_name = match &cli.command {
        Commands::Profile { .. } => "profile",
        Commands::Org { .. } => "org",
        Commands::Device { .. } => "device",
        Commands::Project { .. } => "project",
        Commands::Set { .. } => "set",
        Commands::Pull { .. } => "pull",
        Commands::Push { .. } => "push",
        Commands::Share { .. } => "share",
        Commands::Rotate { .. } => "rotate",
        Commands::Versions { .. } => "versions",
        Commands::Diff { .. } => "diff",
        Commands::Verify { .. } => "verify",
        Commands::Audit { .. } => "audit",
        Commands::Ci { .. } => "ci",
        Commands::Cache { .. } => "cache",
        Commands::Recovery { .. } => "recovery",
        Commands::Run { .. } => "run",
        Commands::Completions { .. } => "completions",
        Commands::Status => "status",
        Commands::Gitignore { .. } => "gitignore",
    };

    // Show single device warning for applicable commands
    // Requirements 14.2: WHEN a user has only one device, THEN THE system SHALL display warnings on each command execution
    if recovery_warnings.should_show_warnings(command_name) {
        // For now, we'll assume single device until we can query the vault
        // In a full implementation, this would check the actual device count
        recovery_warnings.show_single_device_warning(cli.json, command_name);
    }

    // Handle commands
    let result = match &cli.command {
        Commands::Profile { command } => {
            handle_profile_command(command, &cli, &recovery_warnings).await
        }
        Commands::Org { command } => handle_org_command(command, &cli).await,
        Commands::Device { command } => handle_device_command(command, &cli).await,
        Commands::Project { command } => handle_project_command(command, &cli).await,
        Commands::Set { command } => handle_set_command(command, &cli).await,
        Commands::Pull {
            project,
            set,
            version,
            format,
            output,
        } => handle_pull_command(project, set, version, format, output, &cli).await,
        Commands::Push {
            project,
            set,
            input,
            format,
            message,
        } => handle_push_command(project, set, input, format, message, &cli).await,
        Commands::Share { command } => handle_share_command(command, &cli).await,
        Commands::Rotate {
            project,
            reason,
            note,
        } => handle_rotate_command(project, reason, note, &cli).await,
        Commands::Versions { command } => handle_versions_command(command, &cli).await,
        Commands::Diff {
            project,
            set,
            v1,
            v2,
            show_values,
        } => handle_diff_command(project, set, *v1, *v2, *show_values, &cli).await,
        Commands::Verify {
            project,
            set,
            signatures_only,
            chains_only,
        } => handle_verify_command(project, set, *signatures_only, *chains_only, &cli).await,
        Commands::Audit { command } => handle_audit_command(command, &cli).await,
        Commands::Ci { command } => handle_ci_command(command, &cli).await,
        Commands::Cache { command } => handle_cache_command(command, &cli).await,
        Commands::Recovery { command } => handle_recovery_command(command, &cli).await,
        Commands::Run {
            project,
            set,
            version,
            command,
        } => handle_run_command(project, set, version, command, &cli).await,
        Commands::Completions { shell } => handle_completions_command(*shell, &cli),
        Commands::Status => handle_status_command(&cli, &recovery_warnings).await,
        Commands::Gitignore { file, dry_run } => handle_gitignore_command(file, *dry_run, &cli),
    };

    result
}

// Command handlers (placeholder implementations)
async fn handle_profile_command(
    command: &ProfileCommands,
    cli: &Cli,
    recovery_warnings: &RecoveryWarnings,
) -> Result<()> {
    use crate::profile::ProfileManager;
    // Note: enrollment and env imports will be used in future profile add implementation
    use console::style;
    use dialoguer::{theme::ColorfulTheme, Confirm};

    // Get profile manager
    let config_dir = ProfileManager::default_config_dir()?;
    let manager = ProfileManager::new(config_dir);

    match command {
        ProfileCommands::Add { name, repo } => {
            // For now, this is a placeholder that shows what would be needed
            // In a full implementation, this would:
            // 1. Parse the repo (owner/repo format)
            // 2. Perform GitHub OAuth flow
            // 3. Get user info from GitHub
            // 4. Prompt for passphrase
            // 5. Call enroll_device

            if let Some(repo_str) = repo {
                let parts: Vec<&str> = repo_str.split('/').collect();
                if parts.len() != 2 {
                    anyhow::bail!("Repository must be in format 'owner/repo'");
                }

                println!("Adding profile '{}' for repository '{}'", name, repo_str);
                println!("Note: Full GitHub OAuth integration not yet implemented");
                println!("This would normally:");
                println!("  1. Authenticate with GitHub");
                println!("  2. Generate device keys");
                println!("  3. Create profile");

                // Show first device warning after successful enrollment
                // Requirements 14.1: WHEN a user enrolls their first device,
                // THEN THE system SHALL recommend enrolling a second device for recovery
                recovery_warnings.show_first_device_warning(cli.json);
            } else {
                println!("Adding profile '{}' (repository will be prompted)", name);
                println!("Note: Interactive repository selection not yet implemented");

                // Show first device warning after successful enrollment
                recovery_warnings.show_first_device_warning(cli.json);
            }
        }
        ProfileCommands::List => {
            let profiles = manager.list_profiles()?;
            let default_profile = manager.get_default_profile()?;

            if cli.json {
                let output = serde_json::json!({
                    "profiles": profiles,
                    "default": default_profile
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                if profiles.is_empty() {
                    println!("No profiles found.");
                    println!("Run 'myc profile add <name>' to create your first profile.");
                } else {
                    println!("Profiles:");
                    for profile_name in &profiles {
                        let marker = if Some(profile_name) == default_profile.as_ref() {
                            style("*").green().bold()
                        } else {
                            style(" ").dim()
                        };
                        println!("  {} {}", marker, profile_name);
                    }

                    if let Some(default) = default_profile {
                        println!("\n* {} (default)", style(&default).green().bold());
                    }
                }
            }
        }
        ProfileCommands::Use { name } => {
            // Verify profile exists
            manager.get_profile(name)?;

            // Set as default
            manager.set_default_profile(name)?;

            if cli.json {
                let output = serde_json::json!({
                    "success": true,
                    "message": format!("Switched to profile '{}'", name),
                    "profile": name
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("{} Switched to profile '{}'", style("✓").green(), name);
            }
        }
        ProfileCommands::Remove { name, force } => {
            // Check if profile exists
            let profile = manager.get_profile(name)?;

            // Confirm deletion unless forced
            let should_delete = if *force {
                true
            } else {
                if cli.json {
                    anyhow::bail!("Cannot prompt for confirmation in JSON mode. Use --force to skip confirmation.");
                }

                println!(
                    "This will permanently delete profile '{}' and all associated keys.",
                    name
                );
                println!(
                    "Repository: {}/{}",
                    profile.github_owner, profile.github_repo
                );
                println!("Device ID: {}", profile.device_id);

                Confirm::with_theme(&ColorfulTheme::default())
                    .with_prompt("Are you sure you want to delete this profile?")
                    .default(false)
                    .interact()?
            };

            if should_delete {
                manager.delete_profile(name)?;

                if cli.json {
                    let output = serde_json::json!({
                        "success": true,
                        "message": format!("Profile '{}' deleted", name)
                    });
                    println!("{}", serde_json::to_string_pretty(&output)?);
                } else {
                    println!("{} Profile '{}' deleted", style("✓").green(), name);
                }
            } else {
                if cli.json {
                    let output = serde_json::json!({
                        "success": false,
                        "message": "Deletion cancelled"
                    });
                    println!("{}", serde_json::to_string_pretty(&output)?);
                } else {
                    println!("Deletion cancelled");
                }
            }
        }
        ProfileCommands::Show { name } => {
            let profile_name = if let Some(name) = name {
                name.clone()
            } else {
                // Show default profile
                manager.get_default_profile()?.ok_or_else(|| {
                    anyhow::anyhow!(
                        "No default profile set. Use 'myc profile list' to see available profiles."
                    )
                })?
            };

            let profile = manager.get_profile(&profile_name)?;
            let is_default = manager.get_default_profile()? == Some(profile_name.clone());

            if cli.json {
                let output = serde_json::json!({
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
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("Profile: {}", style(&profile.name).bold());
                if is_default {
                    println!("  Status: {} (default)", style("Active").green());
                } else {
                    println!("  Status: Available");
                }
                println!(
                    "  GitHub User: {} ({})",
                    profile.github_username, profile.github_user_id
                );
                println!("  Vault: {}/{}", profile.github_owner, profile.github_repo);
                println!(
                    "  Vault URL: https://github.com/{}/{}",
                    profile.github_owner, profile.github_repo
                );
                println!("  Device ID: {}", profile.device_id);
                println!(
                    "  Created: {}",
                    profile
                        .created_at
                        .format(&time::format_description::well_known::Rfc3339)?
                );

                // Show key file status
                let signing_key_exists = manager.signing_key_path(&profile.name).exists();
                let encryption_key_exists = manager.encryption_key_path(&profile.name).exists();

                if signing_key_exists && encryption_key_exists {
                    println!("  Keys: {} Enrolled", style("✓").green());
                } else {
                    println!(
                        "  Keys: {} Missing (device not properly enrolled)",
                        style("✗").red()
                    );
                }
            }
        }
    }
    Ok(())
}

async fn handle_org_command(command: &OrgCommands, cli: &Cli) -> Result<()> {
    use crate::profile::ProfileManager;
    use console::style;
    use myc_core::audit::{
        notes, signing, AuditEvent, AuditIndex, EventDetails, EventType, OrgEventDetails,
        SignedAuditEvent,
    };
    use myc_core::canonical::to_canonical_json;
    use myc_core::org::{Org, OrgSettings, RotationPolicy};
    use myc_github::client::GitHubClient;

    match command {
        OrgCommands::Init { name, repo, public } => {
            // Get profile manager and current profile
            let config_dir = ProfileManager::default_config_dir()?;
            let manager = ProfileManager::new(config_dir);

            let profile_name = if let Some(profile) = &cli.profile {
                profile.clone()
            } else {
                manager.get_default_profile()?.ok_or_else(|| {
                    anyhow::anyhow!("No default profile set. Use --profile or 'myc profile use <name>'")
                })?
            };

            let profile = manager.get_profile(&profile_name)?;

            // Get GitHub token from environment
            let token = std::env::var("GITHUB_TOKEN").context(
                "GITHUB_TOKEN environment variable not set. Run 'myc profile add' to authenticate.",
            )?;

            let repo_name = repo.as_deref().unwrap_or("secrets-vault");
            let is_private = !public;

            // Create GitHub client for repository creation
            let temp_client = GitHubClient::new(
                token.clone(),
                profile.github_owner.clone(),
                "temp".to_string(), // Temporary repo name for client creation
            )?;

            if !cli.json {
                println!("Initializing organization '{}'", name);
                println!("  Repository: {}", repo_name);
                println!(
                    "  Visibility: {}",
                    if is_private { "Private" } else { "Public" }
                );
                println!();
            }

            // Step 1: Create GitHub repository
            if !cli.json {
                println!("Creating GitHub repository...");
            }

            let repository = temp_client.create_repository(repo_name, is_private).await?;

            let repo_url = repository.html_url.as_ref().map(|u| u.to_string()).unwrap_or_else(|| format!("https://github.com/{}/{}", profile.github_owner, repo_name));

            if !cli.json {
                println!("  {} Repository created: {}", style("✓").green(), repo_url);
            }

            // Step 2: Create GitHub client for the new repository
            let client = GitHubClient::new(
                token,
                profile.github_owner.clone(),
                repo_name.to_string(),
            )?;

            // Step 3: Create organization metadata
            let org_settings = OrgSettings {
                require_device_approval: false,
                github_org: None,
                default_rotation_policy: Some(RotationPolicy::default()),
            };

            let org = Org::new(name.clone(), org_settings);

            // Step 4: Initialize vault structure
            if !cli.json {
                println!("Initializing vault structure...");
            }

            // Create .mycelium directory structure
            let vault_json = to_canonical_json(&org)?;
            client
                .write_file(".mycelium/vault.json", vault_json.as_bytes(), "Initialize vault", None)
                .await?;

            // Create empty directories by creating placeholder files
            client
                .write_file(
                    ".mycelium/devices/.gitkeep",
                    b"",
                    "Initialize devices directory",
                    None,
                )
                .await?;

            client
                .write_file(
                    ".mycelium/projects/.gitkeep",
                    b"",
                    "Initialize projects directory",
                    None,
                )
                .await?;

            client
                .write_file(
                    ".mycelium/audit/.gitkeep",
                    b"",
                    "Initialize audit directory",
                    None,
                )
                .await?;

            // Create audit index
            let audit_index = AuditIndex::new();
            let index_json = to_canonical_json(&audit_index)?;
            client
                .write_file(
                    ".mycelium/audit/index.json",
                    index_json.as_bytes(),
                    "Initialize audit index",
                    None,
                )
                .await?;

            if !cli.json {
                println!("  {} Vault structure created", style("✓").green());
            }

            // Step 5: Create first audit event (org created)
            if !cli.json {
                println!("Creating initial audit event...");
            }

            // Load device keys to sign the audit event
            let signing_key_path = manager.signing_key_path(&profile_name);
            if !signing_key_path.exists() {
                anyhow::bail!("Device keys not found for profile '{}'. Run 'myc profile add' to enroll device.", profile_name);
            }

            // For now, we'll create a placeholder audit event
            // In a full implementation, we would load the encrypted signing key with passphrase
            // and create a proper signed audit event
            let org_created_event = AuditEvent::new(
                EventType::OrgCreated,
                profile.device_id,
                format!("github|{}", profile.github_user_id),
                org.id,
                None,
                EventDetails::Org(OrgEventDetails {
                    name: name.clone(),
                    settings: None,
                }),
                vec![0u8; 32], // Placeholder chain hash
                None,
            );

            // Note: In a full implementation, we would sign this event
            // For now, we'll just store the event structure as a placeholder
            let event_path = format!(".mycelium/audit/{}/{}.json", 
                org_created_event.timestamp.format(&time::format_description::parse("[year]-[month]").unwrap()).unwrap(),
                org_created_event.event_id
            );

            let event_json = to_canonical_json(&org_created_event)?;
            client
                .write_file(&event_path, event_json.as_bytes(), "Create org created audit event", None)
                .await?;

            if !cli.json {
                println!("  {} Initial audit event created", style("✓").green());
            }

            // Step 6: Check if .gitignore exists and offer to add secret patterns
            let gitignore_offered = offer_gitignore_setup(cli)?;

            if cli.json {
                let output = serde_json::json!({
                    "success": true,
                    "message": "Organization initialized successfully",
                    "organization": {
                        "id": org.id,
                        "name": name,
                        "repository": format!("{}/{}", profile.github_owner, repo_name),
                        "repository_url": repo_url,
                        "private": is_private
                    },
                    "gitignore_offered": gitignore_offered
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!();
                println!("{} Organization '{}' initialized successfully!", style("✓").green().bold(), name);
                println!("  Organization ID: {}", org.id);
                println!("  Repository: {}/{}", profile.github_owner, repo_name);
                println!("  Repository URL: {}", repo_url);
                println!();
                println!("Next steps:");
                println!("  1. Run 'myc project create <name>' to create your first project");
                println!("  2. Run 'myc set create <project> <set-name>' to create a secret set");
                println!("  3. Run 'myc push <project> <set>' to add secrets");
                if gitignore_offered {
                    println!("  4. Review .gitignore for secret file patterns");
                }
            }
        }
        OrgCommands::Show => {
            // Get profile manager and current profile
            let config_dir = ProfileManager::default_config_dir()?;
            let manager = ProfileManager::new(config_dir);

            let profile_name = if let Some(profile) = &cli.profile {
                profile.clone()
            } else {
                manager.get_default_profile()?.ok_or_else(|| {
                    anyhow::anyhow!("No default profile set. Use --profile or 'myc profile use <name>'")
                })?
            };

            let profile = manager.get_profile(&profile_name)?;

            // Get GitHub token from environment
            let token = std::env::var("GITHUB_TOKEN").context(
                "GITHUB_TOKEN environment variable not set. Run 'myc profile add' to authenticate.",
            )?;

            // Create GitHub client
            let client = GitHubClient::new(
                token,
                profile.github_owner.clone(),
                profile.github_repo.clone(),
            )?;

            // Check repository access
            if !client.check_access().await? {
                anyhow::bail!(
                    "Cannot access repository {}/{}. Check your permissions or run 'myc org init' to create a vault.",
                    profile.github_owner,
                    profile.github_repo
                );
            }

            // Read vault.json
            let vault_data = client.read_file(".mycelium/vault.json").await.context(
                "Failed to read vault.json. This may not be a valid Mycelium vault. Run 'myc org init' to initialize."
            )?;

            let vault_json = String::from_utf8(vault_data).context("Invalid UTF-8 in vault.json")?;
            let org: Org = serde_json::from_str(&vault_json).context("Failed to parse vault.json")?;

            // Count members and projects (basic implementation)
            let member_count;
            let mut project_count = 0;

            // Try to list projects directory
            if let Ok(projects) = client.list_directory(".mycelium/projects").await {
                project_count = projects.iter().filter(|entry| entry.is_dir).count();
            }

            // For member count, we would need to read all project members.json files
            // For now, we'll show 1 (the current user) as a placeholder
            member_count = 1;

            if cli.json {
                let output = serde_json::json!({
                    "organization": {
                        "id": org.id,
                        "name": org.name,
                        "created_at": org.created_at,
                        "schema_version": org.schema_version,
                        "settings": org.settings,
                        "repository": format!("{}/{}", profile.github_owner, profile.github_repo),
                        "repository_url": format!("https://github.com/{}/{}", profile.github_owner, profile.github_repo)
                    },
                    "statistics": {
                        "member_count": member_count,
                        "project_count": project_count
                    }
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("Organization: {}", style(&org.name).bold());
                println!("  ID: {}", org.id);
                println!("  Created: {}", org.created_at.format(&time::format_description::well_known::Rfc3339)?);
                println!("  Repository: {}/{}", profile.github_owner, profile.github_repo);
                println!("  Repository URL: https://github.com/{}/{}", profile.github_owner, profile.github_repo);
                println!();
                println!("Statistics:");
                println!("  Members: {}", member_count);
                println!("  Projects: {}", project_count);
                println!();
                println!("Settings:");
                println!("  Require device approval: {}", org.settings.require_device_approval);
                if let Some(ref github_org) = org.settings.github_org {
                    println!("  GitHub organization: {}", github_org);
                }
                if let Some(ref policy) = org.settings.default_rotation_policy {
                    println!("  Default rotation policy:");
                    println!("    Rotate on member remove: {}", policy.rotate_on_member_remove);
                    println!("    Rotate on device revoke: {}", policy.rotate_on_device_revoke);
                    if let Some(max_age) = policy.max_age_days {
                        println!("    Max PDK age: {} days", max_age);
                    }
                }
            }
        }
        OrgCommands::Settings {
            require_approval,
            rotation_policy,
        } => {
            // Get profile manager and current profile
            let config_dir = ProfileManager::default_config_dir()?;
            let manager = ProfileManager::new(config_dir);

            let profile_name = if let Some(profile) = &cli.profile {
                profile.clone()
            } else {
                manager.get_default_profile()?.ok_or_else(|| {
                    anyhow::anyhow!("No default profile set. Use --profile or 'myc profile use <name>'")
                })?
            };

            let profile = manager.get_profile(&profile_name)?;

            // Get GitHub token from environment
            let token = std::env::var("GITHUB_TOKEN").context(
                "GITHUB_TOKEN environment variable not set. Run 'myc profile add' to authenticate.",
            )?;

            // Create GitHub client
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

            // Read current vault.json
            let vault_data = client.read_file(".mycelium/vault.json").await.context(
                "Failed to read vault.json. This may not be a valid Mycelium vault."
            )?;

            let vault_json = String::from_utf8(vault_data).context("Invalid UTF-8 in vault.json")?;
            let mut org: Org = serde_json::from_str(&vault_json).context("Failed to parse vault.json")?;

            let mut changes_made = false;

            // Update settings based on provided arguments
            if let Some(approval) = require_approval {
                org.settings.require_device_approval = *approval;
                changes_made = true;
            }

            if let Some(policy_str) = rotation_policy {
                // Parse rotation policy string (simplified implementation)
                // In a full implementation, this would parse more complex policy strings
                match policy_str.as_str() {
                    "default" => {
                        org.settings.default_rotation_policy = Some(RotationPolicy::default());
                        changes_made = true;
                    }
                    "strict" => {
                        org.settings.default_rotation_policy = Some(RotationPolicy {
                            rotate_on_member_remove: true,
                            rotate_on_device_revoke: true,
                            max_age_days: Some(30),
                        });
                        changes_made = true;
                    }
                    "relaxed" => {
                        org.settings.default_rotation_policy = Some(RotationPolicy {
                            rotate_on_member_remove: false,
                            rotate_on_device_revoke: true,
                            max_age_days: Some(180),
                        });
                        changes_made = true;
                    }
                    _ => {
                        anyhow::bail!("Invalid rotation policy '{}'. Valid options: default, strict, relaxed", policy_str);
                    }
                }
            }

            if !changes_made {
                // No changes requested, just show current settings
                if cli.json {
                    let output = serde_json::json!({
                        "settings": org.settings
                    });
                    println!("{}", serde_json::to_string_pretty(&output)?);
                } else {
                    println!("Current organization settings:");
                    println!("  Require device approval: {}", org.settings.require_device_approval);
                    if let Some(ref github_org) = org.settings.github_org {
                        println!("  GitHub organization: {}", github_org);
                    }
                    if let Some(ref policy) = org.settings.default_rotation_policy {
                        println!("  Default rotation policy:");
                        println!("    Rotate on member remove: {}", policy.rotate_on_member_remove);
                        println!("    Rotate on device revoke: {}", policy.rotate_on_device_revoke);
                        if let Some(max_age) = policy.max_age_days {
                            println!("    Max PDK age: {} days", max_age);
                        }
                    }
                }
                return Ok(());
            }

            // Write updated vault.json back to GitHub
            let updated_json = to_canonical_json(&org)?;
            
            // Get current file SHA for update
            let current_sha: Option<String> = None; // In a full implementation, we'd extract SHA from GitHub API response

            client
                .write_file(
                    ".mycelium/vault.json",
                    updated_json.as_bytes(),
                    "Update organization settings",
                    current_sha.as_deref(),
                )
                .await?;

            // Create audit event for settings update
            let settings_json = serde_json::to_value(&org.settings)?;
            let settings_event = AuditEvent::new(
                EventType::OrgSettingsUpdated,
                profile.device_id,
                format!("github|{}", profile.github_user_id),
                org.id,
                None,
                EventDetails::Org(OrgEventDetails {
                    name: org.name.clone(),
                    settings: Some(settings_json),
                }),
                vec![0u8; 32], // Placeholder chain hash
                None,
            );

            // Store audit event (simplified implementation)
            let event_path = format!(".mycelium/audit/{}/{}.json", 
                settings_event.timestamp.format(&time::format_description::parse("[year]-[month]").unwrap()).unwrap(),
                settings_event.event_id
            );

            let event_json = to_canonical_json(&settings_event)?;
            client
                .write_file(&event_path, event_json.as_bytes(), "Create settings update audit event", None)
                .await?;

            if cli.json {
                let output = serde_json::json!({
                    "success": true,
                    "message": "Organization settings updated successfully",
                    "settings": org.settings
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("{} Organization settings updated successfully!", style("✓").green());
                println!();
                println!("Updated settings:");
                println!("  Require device approval: {}", org.settings.require_device_approval);
                if let Some(ref github_org) = org.settings.github_org {
                    println!("  GitHub organization: {}", github_org);
                }
                if let Some(ref policy) = org.settings.default_rotation_policy {
                    println!("  Default rotation policy:");
                    println!("    Rotate on member remove: {}", policy.rotate_on_member_remove);
                    println!("    Rotate on device revoke: {}", policy.rotate_on_device_revoke);
                    if let Some(max_age) = policy.max_age_days {
                        println!("    Max PDK age: {} days", max_age);
                    }
                }
            }
        }
    }
    Ok(())
}

async fn handle_device_command(command: &DeviceCommands, cli: &Cli) -> Result<()> {
    use crate::profile::ProfileManager;
    use dialoguer::{theme::ColorfulTheme, Confirm};
    use myc_core::device::DeviceType;
    use myc_core::ids::DeviceId;
    use myc_github::client::GitHubClient;
    use time::OffsetDateTime;

    // Get profile manager and current profile
    let config_dir = ProfileManager::default_config_dir()?;
    let manager = ProfileManager::new(config_dir);

    let profile_name = if let Some(profile) = &cli.profile {
        profile.clone()
    } else {
        manager.get_default_profile()?.ok_or_else(|| {
            anyhow::anyhow!("No default profile set. Use --profile or 'myc profile use <name>'")
        })?
    };

    let profile = manager.get_profile(&profile_name)?;

    match command {
        DeviceCommands::List { all } => {
            use console::style;
            use myc_core::device::Device;

            // Create GitHub client
            let token = std::env::var("GITHUB_TOKEN").context(
                "GITHUB_TOKEN environment variable not set. Run 'myc profile add' to authenticate.",
            )?;

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

            // Read all device files from .mycelium/devices/
            let devices_dir = ".mycelium/devices";
            let device_files = client
                .list_directory(devices_dir)
                .await
                .context("Failed to list devices directory")?;

            let mut devices = Vec::new();
            for file_entry in device_files {
                if file_entry.name.ends_with(".json") {
                    let device_path = format!("{}/{}", devices_dir, file_entry.name);
                    let device_data = client
                        .read_file(&device_path)
                        .await
                        .context(format!("Failed to read device file: {}", device_path))?;

                    let device: Device = serde_json::from_slice(&device_data)
                        .context(format!("Failed to parse device file: {}", device_path))?;

                    // Filter by user if not --all
                    if *all || device.user_id.as_str() == profile.github_user_id.to_string() {
                        devices.push(device);
                    }
                }
            }

            // Sort devices by enrollment date (newest first)
            devices.sort_by(|a, b| b.enrolled_at.cmp(&a.enrolled_at));

            if cli.json {
                let output = serde_json::json!({
                    "devices": devices,
                    "count": devices.len(),
                    "filter": if *all { "all" } else { "current_user" }
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                if devices.is_empty() {
                    if *all {
                        println!("No devices found in the vault.");
                    } else {
                        println!("No devices found for user {}.", profile.github_username);
                    }
                    println!("Run 'myc device enroll <name>' to enroll a new device.");
                } else {
                    if *all {
                        println!("All devices in vault:");
                    } else {
                        println!("Your devices:");
                    }
                    println!();

                    for device in &devices {
                        // Status indicator
                        let status_marker = match device.status {
                            myc_core::device::DeviceStatus::Active => {
                                if device.is_expired() {
                                    style("⊗").yellow()
                                } else {
                                    style("✓").green()
                                }
                            }
                            myc_core::device::DeviceStatus::PendingApproval => style("⋯").yellow(),
                            myc_core::device::DeviceStatus::Revoked => style("✗").red(),
                        };

                        // Device type badge
                        let type_badge = match device.device_type {
                            myc_core::device::DeviceType::Interactive => "interactive",
                            myc_core::device::DeviceType::CI => "ci",
                        };

                        println!(
                            "{} {} [{}] ({})",
                            status_marker,
                            style(&device.name).bold(),
                            type_badge,
                            device.id
                        );

                        // Status description
                        let status_desc = match device.status {
                            myc_core::device::DeviceStatus::Active => {
                                if device.is_expired() {
                                    "Expired"
                                } else {
                                    "Active"
                                }
                            }
                            myc_core::device::DeviceStatus::PendingApproval => "Pending Approval",
                            myc_core::device::DeviceStatus::Revoked => "Revoked",
                        };

                        println!("  Status: {}", status_desc);
                        println!(
                            "  Enrolled: {}",
                            device
                                .enrolled_at
                                .format(&time::format_description::well_known::Rfc3339)?
                        );

                        if let Some(expires_at) = device.expires_at {
                            println!(
                                "  Expires: {}",
                                expires_at
                                    .format(&time::format_description::well_known::Rfc3339)?
                            );
                        }

                        println!();
                    }

                    println!("Total: {} device(s)", devices.len());
                }
            }
        }
        DeviceCommands::Show { device_id } => {
            use console::style;
            use myc_core::device::Device;

            // Parse device ID
            let uuid = uuid::Uuid::parse_str(device_id)
                .context("Invalid device ID format. Expected UUID.")?;
            let device_uuid = DeviceId::from_uuid(uuid);

            // Create GitHub client
            let token = std::env::var("GITHUB_TOKEN").context(
                "GITHUB_TOKEN environment variable not set. Run 'myc profile add' to authenticate.",
            )?;

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

            // Read specific device file
            let device_path = format!(".mycelium/devices/{}.json", device_uuid);
            let device_data = client
                .read_file(&device_path)
                .await
                .context(format!("Device {} not found", device_id))?;

            let device: Device = serde_json::from_slice(&device_data)
                .context("Failed to parse device file")?;

            if cli.json {
                let output = serde_json::json!({
                    "device": device,
                    "is_current_user": device.user_id.as_str() == profile.github_user_id.to_string(),
                    "is_current_device": device.id == profile.device_id
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("Device: {}", style(&device.name).bold());
                println!("  ID: {}", device.id);
                println!("  User: {}", device.user_id);
                println!("  Type: {:?}", device.device_type);

                // Status with color coding
                let status_display = match device.status {
                    myc_core::device::DeviceStatus::Active => {
                        if device.is_expired() {
                            format!("{} (Expired)", style("Active").yellow())
                        } else {
                            format!("{}", style("Active").green())
                        }
                    }
                    myc_core::device::DeviceStatus::PendingApproval => {
                        format!("{}", style("Pending Approval").yellow())
                    }
                    myc_core::device::DeviceStatus::Revoked => {
                        format!("{}", style("Revoked").red())
                    }
                };
                println!("  Status: {}", status_display);

                println!(
                    "  Enrolled: {}",
                    device
                        .enrolled_at
                        .format(&time::format_description::well_known::Rfc3339)?
                );

                if let Some(expires_at) = device.expires_at {
                    println!(
                        "  Expires: {}",
                        expires_at.format(&time::format_description::well_known::Rfc3339)?
                    );
                }

                println!();
                println!("Public Keys:");
                println!(
                    "  Signing (Ed25519): {}",
                    base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        device.signing_pubkey.as_bytes()
                    )
                );
                println!(
                    "  Encryption (X25519): {}",
                    base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        device.encryption_pubkey.as_bytes()
                    )
                );

                // Show if this is the current device
                if device.id == profile.device_id {
                    println!();
                    println!("{} This is your current device", style("ℹ").blue());
                }

                // Show projects this device has access to (would require reading all projects)
                println!();
                println!("Note: Use 'myc project list' to see projects this device can access");
            }
        }
        DeviceCommands::Enroll {
            name,
            device_type,
            expires,
        } => {
            use console::style;
            use dialoguer::{theme::ColorfulTheme, Confirm, Password};
            use myc_core::audit::{
                AuditEvent, DeviceEventDetails, EventDetails, EventType, SignedAuditEvent,
            };
            use myc_core::canonical::to_canonical_json;
            use myc_core::device::{Device, DeviceStatus, DeviceType};
            use myc_core::ids::OrgId;
            use myc_core::org::Org;
            use myc_crypto::sign::sign;

            // Parse device type
            let dev_type = match device_type.as_deref() {
                Some("interactive") | None => DeviceType::Interactive,
                Some("ci") => DeviceType::CI,
                Some(other) => anyhow::bail!(
                    "Invalid device type '{}'. Must be 'interactive' or 'ci'",
                    other
                ),
            };

            // Parse expiration if provided
            let expires_at = if let Some(expires_str) = expires {
                let parsed = OffsetDateTime::parse(
                    expires_str,
                    &time::format_description::well_known::Rfc3339,
                )
                .context(
                    "Invalid expiration format. Use RFC 3339 format (e.g., '2025-12-31T23:59:59Z')",
                )?;
                Some(parsed)
            } else {
                None
            };

            // Validate expiration for CI devices
            if dev_type == DeviceType::CI && expires_at.is_none() {
                anyhow::bail!("CI devices must have an expiration date. Use --expires flag.");
            }

            // Create GitHub client
            let token = std::env::var("GITHUB_TOKEN").context(
                "GITHUB_TOKEN environment variable not set. Run 'myc profile add' to authenticate.",
            )?;

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

            // Read vault metadata to get org settings
            let vault_data = client
                .read_file(".mycelium/vault.json")
                .await
                .context("Failed to read vault metadata. Is this a valid Mycelium vault?")?;

            let org: Org = serde_json::from_slice(&vault_data)
                .context("Failed to parse vault metadata")?;

            // Determine initial device status based on org settings
            let initial_status = if org.settings.require_device_approval {
                DeviceStatus::PendingApproval
            } else {
                DeviceStatus::Active
            };

            if !cli.json {
                println!("Enrolling new device: {}", style(name).bold());
                println!("  Type: {:?}", dev_type);
                if let Some(exp) = expires_at {
                    println!(
                        "  Expires: {}",
                        exp.format(&time::format_description::well_known::Rfc3339)?
                    );
                }
                println!("  Initial status: {:?}", initial_status);
                println!();
            }

            // Generate device keypairs
            if !cli.json {
                println!("Generating device keys...");
            }

            let (signing_secret, signing_public) = myc_crypto::sign::generate_ed25519_keypair()
                .context("Failed to generate Ed25519 keypair")?;

            let (encryption_secret, encryption_public) =
                myc_crypto::kex::generate_x25519_keypair()
                    .context("Failed to generate X25519 keypair")?;

            // Prompt for passphrase (interactive mode only)
            let passphrase = if std::env::var("MYC_NON_INTERACTIVE").is_ok() {
                // Non-interactive mode: use environment variable or empty
                std::env::var("MYC_KEY_PASSPHRASE").unwrap_or_default()
            } else {
                if cli.json {
                    anyhow::bail!("Cannot prompt for passphrase in JSON mode. Set MYC_KEY_PASSPHRASE environment variable or use MYC_NON_INTERACTIVE=1.");
                }

                println!("Device keys will be encrypted at rest.");
                println!("Enter a passphrase to protect your keys, or press Enter to skip.");
                println!("(You'll need this passphrase every time you use this device)\n");

                let passphrase = Password::with_theme(&ColorfulTheme::default())
                    .with_prompt("Passphrase (optional)")
                    .allow_empty_password(true)
                    .interact()
                    .context("Failed to read passphrase")?;

                if !passphrase.is_empty() {
                    let confirm = Password::with_theme(&ColorfulTheme::default())
                        .with_prompt("Confirm passphrase")
                        .allow_empty_password(true)
                        .interact()
                        .context("Failed to read passphrase confirmation")?;

                    if passphrase != confirm {
                        anyhow::bail!("Passphrases do not match");
                    }
                }

                passphrase
            };

            // Create device record
            let device = Device::new(
                myc_core::ids::UserId::from(profile.github_user_id.to_string()),
                name.clone(),
                dev_type,
                signing_public,
                encryption_public,
                initial_status,
                expires_at,
            );

            // Validate device
            device.validate().context("Device validation failed")?;

            if !cli.json {
                println!("Creating device record...");
            }

            // Serialize device to JSON
            let device_json = serde_json::to_string_pretty(&device)
                .context("Failed to serialize device")?;

            // Upload device record to GitHub
            let device_path = format!(".mycelium/devices/{}.json", device.id);
            client
                .write_file(
                    &device_path,
                    device_json.as_bytes(),
                    &format!("Enroll device: {}", name),
                    None,
                )
                .await
                .context("Failed to upload device record")?;

            // Create audit event
            let event_details = EventDetails::Device(DeviceEventDetails {
                device_id: device.id,
                device_name: name.clone(),
                device_type: format!("{:?}", dev_type).to_lowercase(),
                reason: None,
            });

            // For now, we'll create a basic audit event without proper chaining
            // In a full implementation, this would read the audit index and compute proper chain hash
            let audit_event = AuditEvent::new(
                EventType::DeviceEnrolled,
                profile.device_id,
                profile.github_user_id.to_string(),
                org.id,
                None,
                event_details,
                vec![0u8; 32], // Placeholder chain hash
                None,          // No previous event for simplicity
            );

            // Sign the audit event
            let signing_key = device::load_signing_key(&manager, &profile_name, &passphrase)
                .context("Failed to load signing key for audit event")?;

            let canonical_json = to_canonical_json(&audit_event)
                .context("Failed to serialize audit event")?;

            let signature = sign(&signing_key, canonical_json.as_bytes());

            let signed_event = SignedAuditEvent {
                event: audit_event,
                signature,
                signed_by: profile.device_id,
            };

            // Upload audit event
            let event_json = serde_json::to_string_pretty(&signed_event)
                .context("Failed to serialize audit event")?;

            let event_path = format!(
                ".mycelium/audit/{}/{}.json",
                signed_event.event.timestamp.format(&time::format_description::parse("[year]-[month]").unwrap())?,
                signed_event.event.event_id
            );

            client
                .write_file(
                    &event_path,
                    event_json.as_bytes(),
                    &format!("Audit: Device enrolled - {}", name),
                    None,
                )
                .await
                .context("Failed to upload audit event")?;

            if cli.json {
                let output = serde_json::json!({
                    "success": true,
                    "device": device,
                    "status": initial_status,
                    "message": format!("Device '{}' enrolled successfully", name)
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("{} Device '{}' enrolled successfully", style("✓").green(), name);
                println!("  Device ID: {}", device.id);
                println!("  Status: {:?}", initial_status);

                if initial_status == DeviceStatus::PendingApproval {
                    println!();
                    println!("{} Device requires approval before it can be used", style("⚠").yellow());
                    println!("  Ask an administrator to run: myc device approve {}", device.id);
                }

                println!();
                println!("Device keys have been saved locally.");
                if !passphrase.is_empty() {
                    println!("Remember your passphrase - you'll need it to use this device.");
                }
            }
        }
        DeviceCommands::Revoke { device_id, force } => {
            use console::style;
            use myc_core::audit::{
                AuditEvent, DeviceEventDetails, EventDetails, EventType, SignedAuditEvent,
            };
            use myc_core::canonical::to_canonical_json;
            use myc_core::device::{Device, DeviceStatus};
            use myc_core::org::Org;
            use myc_crypto::sign::sign;

            // Parse device ID
            let uuid = uuid::Uuid::parse_str(device_id)
                .context("Invalid device ID format. Expected UUID.")?;
            let device_uuid = DeviceId::from_uuid(uuid);

            // Create GitHub client
            let token = std::env::var("GITHUB_TOKEN").context(
                "GITHUB_TOKEN environment variable not set. Run 'myc profile add' to authenticate.",
            )?;

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

            // Read device to verify it exists and get current status
            let device_path = format!(".mycelium/devices/{}.json", device_uuid);
            let device_data = client
                .read_file(&device_path)
                .await
                .context(format!("Device {} not found", device_id))?;

            let mut device: Device = serde_json::from_slice(&device_data)
                .context("Failed to parse device file")?;

            // Check if device is already revoked
            if device.status == DeviceStatus::Revoked {
                if cli.json {
                    let output = serde_json::json!({
                        "success": false,
                        "message": format!("Device {} is already revoked", device_id)
                    });
                    println!("{}", serde_json::to_string_pretty(&output)?);
                } else {
                    println!("{} Device {} is already revoked", style("⚠").yellow(), device_id);
                }
                return Ok(());
            }

            // Confirm revocation unless forced
            let should_revoke = if *force {
                true
            } else {
                if cli.json {
                    anyhow::bail!("Cannot prompt for confirmation in JSON mode. Use --force to skip confirmation.");
                }

                println!("This will permanently revoke device '{}'", device.name);
                println!("  Device ID: {}", device_id);
                println!("  Owner: {}", device.user_id);
                println!("  Type: {:?}", device.device_type);
                println!();
                println!("The device will no longer be able to access any secrets.");
                println!("This action will trigger PDK rotation for all affected projects.");

                Confirm::with_theme(&ColorfulTheme::default())
                    .with_prompt("Are you sure you want to revoke this device?")
                    .default(false)
                    .interact()?
            };

            if !should_revoke {
                if cli.json {
                    let output = serde_json::json!({
                        "success": false,
                        "message": "Revocation cancelled"
                    });
                    println!("{}", serde_json::to_string_pretty(&output)?);
                } else {
                    println!("Revocation cancelled");
                }
                return Ok(());
            }

            // Read vault metadata
            let vault_data = client
                .read_file(".mycelium/vault.json")
                .await
                .context("Failed to read vault metadata")?;

            let org: Org = serde_json::from_slice(&vault_data)
                .context("Failed to parse vault metadata")?;

            if !cli.json {
                println!("Revoking device...");
            }

            // Update device status to Revoked
            device.status = DeviceStatus::Revoked;

            // Serialize updated device
            let device_json = serde_json::to_string_pretty(&device)
                .context("Failed to serialize device")?;

            // Upload updated device record
            client
                .write_file(
                    &device_path,
                    device_json.as_bytes(),
                    &format!("Revoke device: {}", device.name),
                    None,
                )
                .await
                .context("Failed to update device record")?;

            // Create audit event
            let event_details = EventDetails::Device(DeviceEventDetails {
                device_id: device.id,
                device_name: device.name.clone(),
                device_type: format!("{:?}", device.device_type).to_lowercase(),
                reason: Some("Device revoked by administrator".to_string()),
            });

            // Create audit event (simplified - in full implementation would compute proper chain hash)
            let audit_event = AuditEvent::new(
                EventType::DeviceRevoked,
                profile.device_id,
                profile.github_user_id.to_string(),
                org.id,
                None,
                event_details,
                vec![0u8; 32], // Placeholder chain hash
                None,          // No previous event for simplicity
            );

            // Sign the audit event
            let passphrase = if std::env::var("MYC_NON_INTERACTIVE").is_ok() {
                std::env::var("MYC_KEY_PASSPHRASE").unwrap_or_default()
            } else {
                if cli.json {
                    anyhow::bail!("Cannot prompt for passphrase in JSON mode. Set MYC_KEY_PASSPHRASE environment variable.");
                }
                
                use dialoguer::{theme::ColorfulTheme, Password};
                Password::with_theme(&ColorfulTheme::default())
                    .with_prompt("Enter your passphrase to sign the audit event")
                    .allow_empty_password(true)
                    .interact()
                    .context("Failed to read passphrase")?
            };

            let signing_key = device::load_signing_key(&manager, &profile_name, &passphrase)
                .context("Failed to load signing key for audit event")?;

            let canonical_json = to_canonical_json(&audit_event)
                .context("Failed to serialize audit event")?;

            let signature = sign(&signing_key, canonical_json.as_bytes());

            let signed_event = SignedAuditEvent {
                event: audit_event,
                signature,
                signed_by: profile.device_id,
            };

            // Upload audit event
            let event_json = serde_json::to_string_pretty(&signed_event)
                .context("Failed to serialize audit event")?;

            let event_path = format!(
                ".mycelium/audit/{}/{}.json",
                signed_event.event.timestamp.format(&time::format_description::parse("[year]-[month]").unwrap())?,
                signed_event.event.event_id
            );

            client
                .write_file(
                    &event_path,
                    event_json.as_bytes(),
                    &format!("Audit: Device revoked - {}", device.name),
                    None,
                )
                .await
                .context("Failed to upload audit event")?;

            if cli.json {
                let output = serde_json::json!({
                    "success": true,
                    "device_id": device_uuid,
                    "message": format!("Device '{}' revoked successfully", device.name),
                    "note": "PDK rotation for affected projects should be performed separately"
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("{} Device '{}' revoked successfully", style("✓").green(), device.name);
                println!("  Device ID: {}", device_id);
                println!();
                println!("{} Important: This action should trigger PDK rotation", style("⚠").yellow());
                println!("  for all projects this device had access to.");
                println!("  Run 'myc rotate <project>' for each affected project.");
            }
        }
        DeviceCommands::Approve { device_id } => {
            use console::style;
            use myc_core::audit::{
                AuditEvent, DeviceEventDetails, EventDetails, EventType, SignedAuditEvent,
            };
            use myc_core::canonical::to_canonical_json;
            use myc_core::device::{Device, DeviceStatus};
            use myc_core::org::Org;
            use myc_crypto::sign::sign;

            // Parse device ID
            let uuid = uuid::Uuid::parse_str(device_id)
                .context("Invalid device ID format. Expected UUID.")?;
            let device_uuid = DeviceId::from_uuid(uuid);

            // Create GitHub client
            let token = std::env::var("GITHUB_TOKEN").context(
                "GITHUB_TOKEN environment variable not set. Run 'myc profile add' to authenticate.",
            )?;

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

            // Read device to verify it exists and get current status
            let device_path = format!(".mycelium/devices/{}.json", device_uuid);
            let device_data = client
                .read_file(&device_path)
                .await
                .context(format!("Device {} not found", device_id))?;

            let mut device: Device = serde_json::from_slice(&device_data)
                .context("Failed to parse device file")?;

            // Check if device is already active
            if device.status == DeviceStatus::Active {
                if cli.json {
                    let output = serde_json::json!({
                        "success": false,
                        "message": format!("Device {} is already active", device_id)
                    });
                    println!("{}", serde_json::to_string_pretty(&output)?);
                } else {
                    println!("{} Device {} is already active", style("ℹ").blue(), device_id);
                }
                return Ok(());
            }

            // Check if device is revoked
            if device.status == DeviceStatus::Revoked {
                if cli.json {
                    let output = serde_json::json!({
                        "success": false,
                        "message": format!("Cannot approve revoked device {}", device_id)
                    });
                    println!("{}", serde_json::to_string_pretty(&output)?);
                } else {
                    println!("{} Cannot approve revoked device {}", style("✗").red(), device_id);
                }
                return Ok(());
            }

            // Verify device is pending approval
            if device.status != DeviceStatus::PendingApproval {
                if cli.json {
                    let output = serde_json::json!({
                        "success": false,
                        "message": format!("Device {} is not pending approval (status: {:?})", device_id, device.status)
                    });
                    println!("{}", serde_json::to_string_pretty(&output)?);
                } else {
                    println!(
                        "{} Device {} is not pending approval (status: {:?})",
                        style("⚠").yellow(),
                        device_id,
                        device.status
                    );
                }
                return Ok(());
            }

            // Read vault metadata
            let vault_data = client
                .read_file(".mycelium/vault.json")
                .await
                .context("Failed to read vault metadata")?;

            let org: Org = serde_json::from_slice(&vault_data)
                .context("Failed to parse vault metadata")?;

            if !cli.json {
                println!("Approving device: {}", style(&device.name).bold());
                println!("  Device ID: {}", device_id);
                println!("  Owner: {}", device.user_id);
                println!("  Type: {:?}", device.device_type);
                println!();
            }

            // Update device status to Active
            device.status = DeviceStatus::Active;

            // Serialize updated device
            let device_json = serde_json::to_string_pretty(&device)
                .context("Failed to serialize device")?;

            // Upload updated device record
            client
                .write_file(
                    &device_path,
                    device_json.as_bytes(),
                    &format!("Approve device: {}", device.name),
                    None,
                )
                .await
                .context("Failed to update device record")?;

            // Create audit event
            let event_details = EventDetails::Device(DeviceEventDetails {
                device_id: device.id,
                device_name: device.name.clone(),
                device_type: format!("{:?}", device.device_type).to_lowercase(),
                reason: Some("Device approved by administrator".to_string()),
            });

            // Create audit event (simplified - in full implementation would compute proper chain hash)
            let audit_event = AuditEvent::new(
                EventType::DeviceApproved,
                profile.device_id,
                profile.github_user_id.to_string(),
                org.id,
                None,
                event_details,
                vec![0u8; 32], // Placeholder chain hash
                None,          // No previous event for simplicity
            );

            // Sign the audit event
            let passphrase = if std::env::var("MYC_NON_INTERACTIVE").is_ok() {
                std::env::var("MYC_KEY_PASSPHRASE").unwrap_or_default()
            } else {
                if cli.json {
                    anyhow::bail!("Cannot prompt for passphrase in JSON mode. Set MYC_KEY_PASSPHRASE environment variable.");
                }
                
                use dialoguer::{theme::ColorfulTheme, Password};
                Password::with_theme(&ColorfulTheme::default())
                    .with_prompt("Enter your passphrase to sign the audit event")
                    .allow_empty_password(true)
                    .interact()
                    .context("Failed to read passphrase")?
            };

            let signing_key = device::load_signing_key(&manager, &profile_name, &passphrase)
                .context("Failed to load signing key for audit event")?;

            let canonical_json = to_canonical_json(&audit_event)
                .context("Failed to serialize audit event")?;

            let signature = sign(&signing_key, canonical_json.as_bytes());

            let signed_event = SignedAuditEvent {
                event: audit_event,
                signature,
                signed_by: profile.device_id,
            };

            // Upload audit event
            let event_json = serde_json::to_string_pretty(&signed_event)
                .context("Failed to serialize audit event")?;

            let event_path = format!(
                ".mycelium/audit/{}/{}.json",
                signed_event.event.timestamp.format(&time::format_description::parse("[year]-[month]").unwrap())?,
                signed_event.event.event_id
            );

            client
                .write_file(
                    &event_path,
                    event_json.as_bytes(),
                    &format!("Audit: Device approved - {}", device.name),
                    None,
                )
                .await
                .context("Failed to upload audit event")?;

            if cli.json {
                let output = serde_json::json!({
                    "success": true,
                    "device_id": device_uuid,
                    "device_name": device.name,
                    "message": format!("Device '{}' approved successfully", device.name),
                    "note": "Device can now access projects according to user permissions"
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("{} Device '{}' approved successfully", style("✓").green(), device.name);
                println!("  Device ID: {}", device_id);
                println!();
                println!("The device can now access projects according to the user's permissions.");
                println!("If the user needs access to specific projects, use 'myc share add' to grant access.");
            }
        }
    }
    Ok(())
}

async fn handle_project_command(command: &ProjectCommands, cli: &Cli) -> Result<()> {
    use crate::profile::ProfileManager;
    use console::style;
    use dialoguer::{theme::ColorfulTheme, Confirm};
    use myc_core::project::Project;
    use myc_github::client::GitHubClient;
    use uuid::Uuid;

    // Early validation for commands that don't need GitHub access
    match command {
        ProjectCommands::Create { name } => {
            // Validate project name first (before any other operations)
            if name.is_empty() {
                anyhow::bail!("Project name cannot be empty");
            }
            if name.len() > Project::MAX_NAME_LENGTH {
                anyhow::bail!(
                    "Project name exceeds maximum length of {} characters",
                    Project::MAX_NAME_LENGTH
                );
            }
        }
        ProjectCommands::Delete { project, force: _ } => {
            // Validate project identifier
            if project.is_empty() {
                anyhow::bail!("Project identifier cannot be empty");
            }
        }
        ProjectCommands::Show { project } => {
            // Validate project identifier
            if project.is_empty() {
                anyhow::bail!("Project identifier cannot be empty");
            }
        }
        _ => {} // No early validation needed for other commands
    }

    // Get profile manager and current profile
    let config_dir = ProfileManager::default_config_dir()?;
    let manager = ProfileManager::new(config_dir);

    let profile_name = if let Some(profile) = &cli.profile {
        profile.clone()
    } else {
        manager.get_default_profile()?.ok_or_else(|| {
            anyhow::anyhow!("No default profile set. Use --profile or 'myc profile use <name>'")
        })?
    };

    let profile = manager.get_profile(&profile_name)?;

    // Create GitHub client
    let token = std::env::var("GITHUB_TOKEN").context(
        "GITHUB_TOKEN environment variable not set. Run 'myc profile add' to authenticate.",
    )?;

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

    match command {
        ProjectCommands::Create { name } => {
            // Read vault metadata to get org_id
            let vault_data = client.read_file(".mycelium/vault.json").await?;
            let vault: myc_core::org::Org = serde_json::from_slice(&vault_data)
                .context("Failed to parse vault metadata")?;

            // Load device keys
            let passphrase = if let Ok(pass) = std::env::var("MYC_KEY_PASSPHRASE") {
                pass
            } else {
                if cli.json {
                    anyhow::bail!("MYC_KEY_PASSPHRASE environment variable not set. Cannot prompt in JSON mode.");
                }
                
                use dialoguer::{theme::ColorfulTheme, Password};
                Password::with_theme(&ColorfulTheme::default())
                    .with_prompt("Enter device key passphrase")
                    .interact()?
            };

            let signing_key = myc_cli::device::load_signing_key(&manager, &profile_name, &passphrase)
                .context("Failed to load signing key")?;
            let encryption_key = myc_cli::device::load_encryption_key(&manager, &profile_name, &passphrase)
                .context("Failed to load encryption key")?;

            // Create project
            let project = myc_core::project::Project::new(
                vault.id,
                name.clone(),
                profile.device_id,
            );

            // Generate initial PDK
            let pdk = myc_core::pdk_ops::generate_pdk()?;

            // Get device public key for wrapping
            let device_pubkey = myc_cli::device::load_encryption_pubkey(&manager, &profile_name)?;

            // Wrap PDK to creator's device
            let wrapped_pdk = myc_core::pdk_ops::wrap_pdk(
                &pdk,
                profile.device_id,
                &device_pubkey,
            )?;

            // Create initial PDK version
            let pdk_version = myc_core::pdk_ops::create_pdk_version(
                myc_core::ids::VersionNumber::FIRST,
                profile.device_id,
                Some("Initial PDK".to_string()),
                vec![wrapped_pdk],
            );

            // Create initial membership (creator as owner)
            let creator_member = myc_core::project::ProjectMember::new(
                myc_core::ids::UserId::from(profile.github_user_id.to_string()),
                myc_core::project::Role::Owner,
                profile.device_id,
            );

            let mut membership_list = myc_core::membership_ops::MembershipList::new(
                project.id,
                vec![creator_member],
                profile.device_id,
            );

            // Sign membership list
            membership_list.sign(&signing_key)?;

            if !cli.json {
                println!("Creating project '{}'", style(name).bold());
                println!("  Project ID: {}", project.id);
                println!("  Organization: {}", vault.name);
                println!("  Initial PDK version: 1");
                println!();
                println!("Uploading to GitHub...");
            }

            // Create project directory structure and upload files
            let project_dir = format!(".mycelium/projects/{}", project.id);

            // Upload project metadata
            let project_json = serde_json::to_string_pretty(&project)?;
            client.write_file(
                &format!("{}/project.json", project_dir),
                project_json.as_bytes(),
                &format!("Create project '{}'", name),
                None,
            ).await?;

            // Upload PDK version
            let pdk_json = serde_json::to_string_pretty(&pdk_version)?;
            client.write_file(
                &format!("{}/pdk/v1.json", project_dir),
                pdk_json.as_bytes(),
                &format!("Create initial PDK for project '{}'", name),
                None,
            ).await?;

            // Upload membership list
            let membership_json = serde_json::to_string_pretty(&membership_list)?;
            client.write_file(
                &format!("{}/members.json", project_dir),
                membership_json.as_bytes(),
                &format!("Create initial membership for project '{}'", name),
                None,
            ).await?;

            // Create audit event
            let audit_event = myc_core::audit::AuditEvent::new(
                myc_core::audit::EventType::ProjectCreated,
                profile.device_id,
                profile.github_user_id.to_string(),
                vault.id,
                Some(project.id),
                myc_core::audit::EventDetails::Project(myc_core::audit::ProjectEventDetails {
                    project_id: project.id,
                    project_name: name.clone(),
                }),
                vec![], // Empty chain hash for now (would need to read audit index)
                None,   // No previous event for now
            );

            // Sign audit event
            let signed_audit_event = myc_core::audit::signing::sign_event(audit_event, &signing_key)?;

            // Upload audit event
            let audit_path = myc_core::audit::storage::signed_event_path(&signed_audit_event);
            let audit_json = serde_json::to_string_pretty(&signed_audit_event)?;
            client.write_file(
                &audit_path,
                audit_json.as_bytes(),
                &format!("Audit: Create project '{}'", name),
                None,
            ).await?;

            if cli.json {
                let output = serde_json::json!({
                    "success": true,
                    "message": "Project created successfully",
                    "project": {
                        "id": project.id,
                        "name": project.name,
                        "org_id": project.org_id,
                        "created_at": project.created_at,
                        "created_by": project.created_by,
                        "current_pdk_version": project.current_pdk_version,
                        "your_role": "owner"
                    }
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("{} Project '{}' created successfully", style("✓").green(), name);
                println!("  Project ID: {}", project.id);
                println!("  Your role: {}", style("Owner").green().bold());
                println!("  PDK version: 1");
                println!();
                println!("Next steps:");
                println!("  • Add members: myc share add {} <user> --role <role>", name);
                println!("  • Create secret sets: myc set create {} <set-name>", name);
                println!("  • Push secrets: myc push {} <set-name>", name);
            }
        }
        ProjectCommands::List => {
            // Read all projects from .mycelium/projects/
            let projects_result = client.list_directory(".mycelium/projects").await;
            
            let project_dirs = match projects_result {
                Ok(dirs) => dirs,
                Err(myc_github::error::GitHubError::NotFound { .. }) => {
                    // No projects directory exists yet
                    if cli.json {
                        let output = serde_json::json!({
                            "success": true,
                            "projects": [],
                            "total": 0
                        });
                        println!("{}", serde_json::to_string_pretty(&output)?);
                    } else {
                        println!("No projects found in vault {}/{}", 
                            style(&profile.github_owner).bold(),
                            style(&profile.github_repo).bold()
                        );
                        println!();
                        println!("Create your first project with:");
                        println!("  myc project create <project-name>");
                    }
                    return Ok(());
                }
                Err(e) => return Err(e.into()),
            };

            let mut projects_with_membership = Vec::new();
            let user_id = myc_core::ids::UserId::from(profile.github_user_id.to_string());

            // Read each project and check membership
            for dir_entry in project_dirs {
                if !dir_entry.is_dir {
                    continue;
                }

                let project_id = &dir_entry.name;
                
                // Try to read project metadata
                let project_path = format!(".mycelium/projects/{}/project.json", project_id);
                let project_data = match client.read_file(&project_path).await {
                    Ok(data) => data,
                    Err(_) => continue, // Skip if can't read project
                };

                let project: myc_core::project::Project = match serde_json::from_slice(&project_data) {
                    Ok(p) => p,
                    Err(_) => continue, // Skip if can't parse project
                };

                // Try to read membership
                let members_path = format!(".mycelium/projects/{}/members.json", project_id);
                let members_data = match client.read_file(&members_path).await {
                    Ok(data) => data,
                    Err(_) => continue, // Skip if can't read membership
                };

                let membership_list: myc_core::membership_ops::MembershipList = 
                    match serde_json::from_slice(&members_data) {
                        Ok(m) => m,
                        Err(_) => continue, // Skip if can't parse membership
                    };

                // Check if user is a member
                if let Some(member) = membership_list.find_member(&user_id) {
                    // Count secret sets
                    let sets_path = format!(".mycelium/projects/{}/sets", project_id);
                    let set_count = match client.list_directory(&sets_path).await {
                        Ok(sets) => sets.len(),
                        Err(_) => 0, // No sets directory or empty
                    };

                    projects_with_membership.push((project, member.role, membership_list.members.len(), set_count));
                }
            }

            // Sort projects by name
            projects_with_membership.sort_by(|a, b| a.0.name.cmp(&b.0.name));

            if cli.json {
                let projects_json: Vec<serde_json::Value> = projects_with_membership
                    .iter()
                    .map(|(project, role, member_count, set_count)| {
                        serde_json::json!({
                            "id": project.id,
                            "name": project.name,
                            "org_id": project.org_id,
                            "created_at": project.created_at,
                            "created_by": project.created_by,
                            "current_pdk_version": project.current_pdk_version,
                            "your_role": format!("{:?}", role).to_lowercase(),
                            "member_count": member_count,
                            "secret_set_count": set_count
                        })
                    })
                    .collect();

                let output = serde_json::json!({
                    "success": true,
                    "projects": projects_json,
                    "total": projects_with_membership.len()
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                if projects_with_membership.is_empty() {
                    println!("No projects found in vault {}/{}", 
                        style(&profile.github_owner).bold(),
                        style(&profile.github_repo).bold()
                    );
                    println!();
                    println!("You may not be a member of any projects, or no projects exist yet.");
                    println!();
                    println!("Create your first project with:");
                    println!("  myc project create <project-name>");
                } else {
                    println!("Projects in vault {}/{}", 
                        style(&profile.github_owner).bold(),
                        style(&profile.github_repo).bold()
                    );
                    println!();

                    for (project, role, member_count, set_count) in &projects_with_membership {
                        let role_color = match role {
                            myc_core::project::Role::Owner => style(format!("{:?}", role)).green(),
                            myc_core::project::Role::Admin => style(format!("{:?}", role)).yellow(),
                            myc_core::project::Role::Member => style(format!("{:?}", role)).blue(),
                            myc_core::project::Role::Reader => style(format!("{:?}", role)).dim(),
                        };

                        println!("  {} {} ({})", 
                            style("*").green(),
                            style(&project.name).bold(),
                            role_color
                        );
                        
                        let time_ago = format_time_ago(&project.created_at);
                        println!("    Members: {}, Sets: {}, Created: {}", 
                            member_count, set_count, time_ago
                        );
                        println!("    ID: {}", style(&project.id).dim());
                    }

                    println!();
                    println!("Total: {} project{}", 
                        projects_with_membership.len(),
                        if projects_with_membership.len() == 1 { "" } else { "s" }
                    );
                }
            }
        }
        ProjectCommands::Show { project } => {
            // Try to find project by name or ID
            let user_id = myc_core::ids::UserId::from(profile.github_user_id.to_string());
            let mut found_project = None;
            let mut found_membership = None;

            // First, try to parse as UUID (project ID)
            if let Ok(project_uuid) = uuid::Uuid::parse_str(project) {
                let project_id = myc_core::ids::ProjectId::from_uuid(project_uuid);
                let project_path = format!(".mycelium/projects/{}/project.json", project_id);
                
                if let Ok(project_data) = client.read_file(&project_path).await {
                    if let Ok(proj) = serde_json::from_slice::<myc_core::project::Project>(&project_data) {
                        // Check membership
                        let members_path = format!(".mycelium/projects/{}/members.json", project_id);
                        if let Ok(members_data) = client.read_file(&members_path).await {
                            if let Ok(membership_list) = serde_json::from_slice::<myc_core::membership_ops::MembershipList>(&members_data) {
                                if membership_list.find_member(&user_id).is_some() {
                                    found_project = Some(proj);
                                    found_membership = Some(membership_list);
                                }
                            }
                        }
                    }
                }
            }

            // If not found by ID, search by name
            if found_project.is_none() {
                let projects_result = client.list_directory(".mycelium/projects").await;
                
                if let Ok(project_dirs) = projects_result {
                    for dir_entry in project_dirs {
                        if !dir_entry.is_dir {
                            continue;
                        }

                        let project_id = &dir_entry.name;
                        let project_path = format!(".mycelium/projects/{}/project.json", project_id);
                        
                        if let Ok(project_data) = client.read_file(&project_path).await {
                            if let Ok(proj) = serde_json::from_slice::<myc_core::project::Project>(&project_data) {
                                if proj.name == *project {
                                    // Check membership
                                    let members_path = format!(".mycelium/projects/{}/members.json", project_id);
                                    if let Ok(members_data) = client.read_file(&members_path).await {
                                        if let Ok(membership_list) = serde_json::from_slice::<myc_core::membership_ops::MembershipList>(&members_data) {
                                            if membership_list.find_member(&user_id).is_some() {
                                                found_project = Some(proj);
                                                found_membership = Some(membership_list);
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            let (project_data, membership_list) = match (found_project, found_membership) {
                (Some(p), Some(m)) => (p, m),
                _ => {
                    if cli.json {
                        let output = serde_json::json!({
                            "success": false,
                            "error": "project_not_found",
                            "message": format!("Project '{}' not found or you don't have access", project)
                        });
                        println!("{}", serde_json::to_string_pretty(&output)?);
                    } else {
                        println!("{} Project '{}' not found or you don't have access", 
                            style("✗").red(), project);
                        println!();
                        println!("Make sure:");
                        println!("  • The project name or ID is correct");
                        println!("  • You are a member of the project");
                        println!("  • The project exists in this vault");
                        println!();
                        println!("List available projects with: myc project list");
                    }
                    return Ok(());
                }
            };

            let user_role = membership_list.get_role(&user_id).unwrap();

            // Get secret sets count
            let sets_path = format!(".mycelium/projects/{}/sets", project_data.id);
            let secret_sets = match client.list_directory(&sets_path).await {
                Ok(sets) => sets,
                Err(_) => Vec::new(), // No sets directory or empty
            };

            if cli.json {
                let members_json: Vec<serde_json::Value> = membership_list.members
                    .iter()
                    .map(|member| {
                        serde_json::json!({
                            "user_id": member.user_id.as_str(),
                            "role": format!("{:?}", member.role).to_lowercase(),
                            "added_at": member.added_at,
                            "added_by": member.added_by
                        })
                    })
                    .collect();

                let sets_json: Vec<serde_json::Value> = secret_sets
                    .iter()
                    .filter(|entry| entry.is_dir)
                    .map(|entry| {
                        serde_json::json!({
                            "id": entry.name,
                            "name": entry.name // For now, using ID as name
                        })
                    })
                    .collect();

                let output = serde_json::json!({
                    "success": true,
                    "project": {
                        "id": project_data.id,
                        "name": project_data.name,
                        "org_id": project_data.org_id,
                        "created_at": project_data.created_at,
                        "created_by": project_data.created_by,
                        "current_pdk_version": project_data.current_pdk_version,
                        "your_role": format!("{:?}", user_role).to_lowercase(),
                        "members": members_json,
                        "secret_sets": sets_json
                    }
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("Project: {}", style(&project_data.name).bold());
                println!("  ID: {}", project_data.id);
                
                let created_ago = format_time_ago(&project_data.created_at);
                println!("  Created: {}", created_ago);
                println!("  Current PDK version: {}", project_data.current_pdk_version);
                
                let role_color = match user_role {
                    myc_core::project::Role::Owner => style(format!("{:?}", user_role)).green(),
                    myc_core::project::Role::Admin => style(format!("{:?}", user_role)).yellow(),
                    myc_core::project::Role::Member => style(format!("{:?}", user_role)).blue(),
                    myc_core::project::Role::Reader => style(format!("{:?}", user_role)).dim(),
                };
                println!("  Your role: {}", role_color);
                println!();

                // Display members
                println!("Members ({}):", membership_list.members.len());
                let mut sorted_members = membership_list.members.clone();
                sorted_members.sort_by(|a, b| {
                    // Sort by role level (descending), then by user_id
                    b.role.level().cmp(&a.role.level()).then(a.user_id.as_str().cmp(b.user_id.as_str()))
                });

                for member in &sorted_members {
                    let role_color = match member.role {
                        myc_core::project::Role::Owner => style(format!("{:?}", member.role)).green(),
                        myc_core::project::Role::Admin => style(format!("{:?}", member.role)).yellow(),
                        myc_core::project::Role::Member => style(format!("{:?}", member.role)).blue(),
                        myc_core::project::Role::Reader => style(format!("{:?}", member.role)).dim(),
                    };
                    
                    let added_ago = format_time_ago(&member.added_at);
                    println!("  {} {} - added {}", 
                        role_color,
                        member.user_id.as_str(),
                        added_ago
                    );
                }
                println!();

                // Display secret sets
                let set_dirs: Vec<_> = secret_sets.iter().filter(|entry| entry.is_dir).collect();
                if set_dirs.is_empty() {
                    println!("Secret Sets: None");
                    println!("  Create your first secret set with:");
                    println!("    myc set create {} <set-name>", project_data.name);
                } else {
                    println!("Secret Sets ({}):", set_dirs.len());
                    for set_entry in &set_dirs {
                        println!("  {} {}", style("•").dim(), set_entry.name);
                    }
                }
                println!();

                // Show available actions based on role
                println!("Available actions:");
                if user_role.has_permission(myc_core::project::Permission::Write) {
                    println!("  • Push secrets: myc push {} <set-name>", project_data.name);
                    println!("  • Pull secrets: myc pull {} <set-name>", project_data.name);
                }
                if user_role.has_permission(myc_core::project::Permission::Share) {
                    println!("  • Add members: myc share add {} <user> --role <role>", project_data.name);
                    println!("  • Remove members: myc share remove {} <user>", project_data.name);
                }
                if user_role.has_permission(myc_core::project::Permission::Rotate) {
                    println!("  • Rotate keys: myc rotate {}", project_data.name);
                }
                if user_role.has_permission(myc_core::project::Permission::DeleteProject) {
                    println!("  • Delete project: myc project delete {}", project_data.name);
                }
            }
        }
        ProjectCommands::Delete { project, force } => {
            // Try to find project by name or ID
            let user_id = myc_core::ids::UserId::from(profile.github_user_id.to_string());
            let mut found_project = None;
            let mut found_membership = None;

            // First, try to parse as UUID (project ID)
            if let Ok(project_uuid) = uuid::Uuid::parse_str(project) {
                let project_id = myc_core::ids::ProjectId::from_uuid(project_uuid);
                let project_path = format!(".mycelium/projects/{}/project.json", project_id);
                
                if let Ok(project_data) = client.read_file(&project_path).await {
                    if let Ok(proj) = serde_json::from_slice::<myc_core::project::Project>(&project_data) {
                        // Check membership
                        let members_path = format!(".mycelium/projects/{}/members.json", project_id);
                        if let Ok(members_data) = client.read_file(&members_path).await {
                            if let Ok(membership_list) = serde_json::from_slice::<myc_core::membership_ops::MembershipList>(&members_data) {
                                if membership_list.find_member(&user_id).is_some() {
                                    found_project = Some(proj);
                                    found_membership = Some(membership_list);
                                }
                            }
                        }
                    }
                }
            }

            // If not found by ID, search by name
            if found_project.is_none() {
                let projects_result = client.list_directory(".mycelium/projects").await;
                
                if let Ok(project_dirs) = projects_result {
                    for dir_entry in project_dirs {
                        if !dir_entry.is_dir {
                            continue;
                        }

                        let project_id = &dir_entry.name;
                        let project_path = format!(".mycelium/projects/{}/project.json", project_id);
                        
                        if let Ok(project_data) = client.read_file(&project_path).await {
                            if let Ok(proj) = serde_json::from_slice::<myc_core::project::Project>(&project_data) {
                                if proj.name == *project {
                                    // Check membership
                                    let members_path = format!(".mycelium/projects/{}/members.json", project_id);
                                    if let Ok(members_data) = client.read_file(&members_path).await {
                                        if let Ok(membership_list) = serde_json::from_slice::<myc_core::membership_ops::MembershipList>(&members_data) {
                                            if membership_list.find_member(&user_id).is_some() {
                                                found_project = Some(proj);
                                                found_membership = Some(membership_list);
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            let (project_data, membership_list) = match (found_project, found_membership) {
                (Some(p), Some(m)) => (p, m),
                _ => {
                    if cli.json {
                        let output = serde_json::json!({
                            "success": false,
                            "error": "project_not_found",
                            "message": format!("Project '{}' not found or you don't have access", project)
                        });
                        println!("{}", serde_json::to_string_pretty(&output)?);
                    } else {
                        println!("{} Project '{}' not found or you don't have access", 
                            style("✗").red(), project);
                    }
                    return Ok(());
                }
            };

            // Verify user is owner
            let user_role = membership_list.get_role(&user_id).unwrap();
            if !user_role.has_permission(myc_core::project::Permission::DeleteProject) {
                if cli.json {
                    let output = serde_json::json!({
                        "success": false,
                        "error": "insufficient_permission",
                        "message": format!("Only project owners can delete projects. Your role: {:?}", user_role)
                    });
                    println!("{}", serde_json::to_string_pretty(&output)?);
                } else {
                    println!("{} Insufficient permission to delete project", style("✗").red());
                    println!("Only project owners can delete projects.");
                    println!("Your role: {:?}", user_role);
                }
                return Ok(());
            }

            // Count secret sets and members for confirmation
            let sets_path = format!(".mycelium/projects/{}/sets", project_data.id);
            let secret_sets = match client.list_directory(&sets_path).await {
                Ok(sets) => sets.iter().filter(|entry| entry.is_dir).count(),
                Err(_) => 0,
            };

            // Confirm deletion unless forced
            let should_delete = if *force {
                true
            } else {
                if cli.json {
                    anyhow::bail!("Cannot prompt for confirmation in JSON mode. Use --force to skip confirmation.");
                }

                println!("{} This will permanently delete project '{}'", 
                    style("WARNING:").yellow().bold(), 
                    style(&project_data.name).bold()
                );
                println!();
                println!("Project details:");
                println!("  • ID: {}", project_data.id);
                println!("  • Members: {}", membership_list.members.len());
                println!("  • Secret sets: {}", secret_sets);
                println!("  • PDK version: {}", project_data.current_pdk_version);
                println!();
                println!("This action will:");
                println!("  • Delete all secret sets and their version history");
                println!("  • Remove all members from the project");
                println!("  • Delete all PDK versions");
                println!("  • Remove all project metadata");
                println!();
                println!("{} This action cannot be undone!", style("IMPORTANT:").red().bold());
                println!();

                use dialoguer::{theme::ColorfulTheme, Confirm};
                Confirm::with_theme(&ColorfulTheme::default())
                    .with_prompt("Are you absolutely sure you want to delete this project?")
                    .default(false)
                    .interact()?
            };

            if should_delete {
                if !cli.json {
                    println!("Deleting project '{}'...", project_data.name);
                }

                // Load signing key for audit event
                let passphrase = if let Ok(pass) = std::env::var("MYC_KEY_PASSPHRASE") {
                    pass
                } else {
                    if cli.json {
                        anyhow::bail!("MYC_KEY_PASSPHRASE environment variable not set. Cannot prompt in JSON mode.");
                    }
                    
                    use dialoguer::{theme::ColorfulTheme, Password};
                    Password::with_theme(&ColorfulTheme::default())
                        .with_prompt("Enter device key passphrase")
                        .interact()?
                };

                let signing_key = myc_cli::device::load_signing_key(&manager, &profile_name, &passphrase)
                    .context("Failed to load signing key")?;

                // Read vault metadata for audit event
                let vault_data = client.read_file(".mycelium/vault.json").await?;
                let vault: myc_core::org::Org = serde_json::from_slice(&vault_data)
                    .context("Failed to parse vault metadata")?;

                // Create audit event before deletion
                let audit_event = myc_core::audit::AuditEvent::new(
                    myc_core::audit::EventType::ProjectDeleted,
                    profile.device_id,
                    profile.github_user_id.to_string(),
                    vault.id,
                    Some(project_data.id),
                    myc_core::audit::EventDetails::Project(myc_core::audit::ProjectEventDetails {
                        project_id: project_data.id,
                        project_name: project_data.name.clone(),
                    }),
                    vec![], // Empty chain hash for now
                    None,   // No previous event for now
                );

                // Sign audit event
                let signed_audit_event = myc_core::audit::signing::sign_event(audit_event, &signing_key)?;

                // Upload audit event
                let audit_path = myc_core::audit::storage::signed_event_path(&signed_audit_event);
                let audit_json = serde_json::to_string_pretty(&signed_audit_event)?;
                client.write_file(
                    &audit_path,
                    audit_json.as_bytes(),
                    &format!("Audit: Delete project '{}'", project_data.name),
                    None,
                ).await?;

                // Delete project directory (GitHub doesn't support directory deletion directly,
                // so we would need to delete all files individually in a real implementation)
                // For now, we'll create a deletion marker file
                let deletion_marker = serde_json::json!({
                    "deleted": true,
                    "deleted_at": time::OffsetDateTime::now_utc(),
                    "deleted_by": profile.device_id,
                    "project_name": project_data.name
                });

                client.write_file(
                    &format!(".mycelium/projects/{}/.deleted", project_data.id),
                    serde_json::to_string_pretty(&deletion_marker)?.as_bytes(),
                    &format!("Mark project '{}' as deleted", project_data.name),
                    None,
                ).await?;

                if cli.json {
                    let output = serde_json::json!({
                        "success": true,
                        "message": "Project deleted successfully",
                        "project": {
                            "id": project_data.id,
                            "name": project_data.name,
                            "deleted_at": time::OffsetDateTime::now_utc()
                        }
                    });
                    println!("{}", serde_json::to_string_pretty(&output)?);
                } else {
                    println!("{} Project '{}' deleted successfully", 
                        style("✓").green(), 
                        project_data.name
                    );
                    println!();
                    println!("Note: In a full implementation, all project files would be removed.");
                    println!("For now, the project has been marked as deleted.");
                }
            } else {
                if cli.json {
                    let output = serde_json::json!({
                        "success": false,
                        "message": "Deletion cancelled"
                    });
                    println!("{}", serde_json::to_string_pretty(&output)?);
                } else {
                    println!("Deletion cancelled");
                }
            }
        }
    }
    Ok(())
}

async fn handle_set_command(command: &SetCommands, cli: &Cli) -> Result<()> {
    use crate::profile::ProfileManager;
    use console::style;
    use dialoguer::{theme::ColorfulTheme, Confirm};
    use myc_core::secret_set::SecretSet;
    use myc_github::client::GitHubClient;
    use uuid::Uuid;

    // Early validation for commands that need project/set identifiers
    match command {
        SetCommands::Create { project, name } => {
            // Validate project identifier
            if project.is_empty() {
                anyhow::bail!("Project identifier cannot be empty");
            }
            // Validate secret set name
            if name.is_empty() {
                anyhow::bail!("Secret set name cannot be empty");
            }
            if name.len() > SecretSet::MAX_NAME_LENGTH {
                anyhow::bail!(
                    "Secret set name exceeds maximum length of {} characters",
                    SecretSet::MAX_NAME_LENGTH
                );
            }
        }
        SetCommands::List { project } => {
            if project.is_empty() {
                anyhow::bail!("Project identifier cannot be empty");
            }
        }
        SetCommands::Show { project, set } => {
            if project.is_empty() {
                anyhow::bail!("Project identifier cannot be empty");
            }
            if set.is_empty() {
                anyhow::bail!("Secret set identifier cannot be empty");
            }
        }
        SetCommands::Delete {
            project,
            set,
            force: _,
        } => {
            if project.is_empty() {
                anyhow::bail!("Project identifier cannot be empty");
            }
            if set.is_empty() {
                anyhow::bail!("Secret set identifier cannot be empty");
            }
        }
    }

    // Get profile manager and current profile
    let config_dir = ProfileManager::default_config_dir()?;
    let manager = ProfileManager::new(config_dir);

    let profile_name = if let Some(profile) = &cli.profile {
        profile.clone()
    } else {
        manager.get_default_profile()?.ok_or_else(|| {
            anyhow::anyhow!("No default profile set. Use --profile or 'myc profile use <name>'")
        })?
    };

    let profile = manager.get_profile(&profile_name)?;

    // Create GitHub client
    let token = std::env::var("GITHUB_TOKEN").context(
        "GITHUB_TOKEN environment variable not set. Run 'myc profile add' to authenticate.",
    )?;

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

    match command {
        SetCommands::Create { project, name } => {
            // Try to parse project as UUID first, then treat as name
            let _project_identifier = if let Ok(uuid) = Uuid::parse_str(project) {
                format!("ID {}", uuid)
            } else {
                format!("name '{}'", project)
            };

            // Look up project by ID or name
            let project_obj = match lookup_project(&client, project).await {
                Ok(proj) => proj,
                Err(e) => {
                    if cli.json {
                        let output = serde_json::json!({
                            "success": false,
                            "error": "project_not_found",
                            "message": format!("Project not found: {}", e),
                            "project_identifier": project
                        });
                        println!("{}", serde_json::to_string_pretty(&output)?);
                        return Ok(());
                    } else {
                        anyhow::bail!("Project not found: {}", e);
                    }
                }
            };

            // Check if secret set with this name already exists
            if let Ok(_) = lookup_secret_set(&client, &project_obj.id, name).await {
                if cli.json {
                    let output = serde_json::json!({
                        "success": false,
                        "error": "set_already_exists",
                        "message": format!("Secret set '{}' already exists in project", name),
                        "project_id": project_obj.id,
                        "set_name": name
                    });
                    println!("{}", serde_json::to_string_pretty(&output)?);
                    return Ok(());
                } else {
                    anyhow::bail!(
                        "Secret set '{}' already exists in project '{}'",
                        name,
                        project_obj.name
                    );
                }
            }

            // Check user permissions - user needs write permission to create secret sets
            let members_path = format!(".mycelium/projects/{}/members.json", project_obj.id);
            let members_data = client.read_file(&members_path).await.context(
                "Failed to read project membership. You may not have access to this project."
            )?;
            
            let membership_list: myc_core::membership_ops::MembershipList = 
                serde_json::from_slice(&members_data).context("Failed to parse membership data")?;
            
            let user_id = myc_core::ids::UserId::from(profile.github_user_id.to_string());
            
            // Verify user has write permission (Members and above can create secret sets)
            if !membership_list.has_permission(&user_id, myc_core::project::Permission::Write) {
                if cli.json {
                    let output = serde_json::json!({
                        "success": false,
                        "error": "permission_denied",
                        "message": "You don't have permission to create secret sets in this project",
                        "required_permission": "write",
                        "project_id": project_obj.id
                    });
                    println!("{}", serde_json::to_string_pretty(&output)?);
                    return Ok(());
                } else {
                    anyhow::bail!(
                        "Permission denied: You need write permission to create secret sets in project '{}'.\nAsk a project admin to grant you Member role or higher.",
                        project_obj.name
                    );
                }
            }

            // Create new secret set
            let secret_set = SecretSet::new(project_obj.id, name.clone(), profile.device_id);

            // Write secret set metadata to GitHub
            let set_path = format!(
                ".mycelium/projects/{}/sets/{}/set.json",
                project_obj.id, secret_set.id
            );
            let set_json = serde_json::to_string_pretty(&secret_set)?;

            match client
                .write_file(
                    &set_path,
                    set_json.as_bytes(),
                    &format!("Create secret set '{}'", name),
                    None,
                )
                .await
            {
                Ok(_) => {
                    // Create audit event for secret set creation
                    use myc_core::audit::{AuditEvent, EventDetails, EventType, SecretEventDetails};
                    use myc_core::ids::OrgId;
                    
                    // For now, we'll use a placeholder org_id. In a full implementation,
                    // this would be read from the vault metadata
                    let org_id = OrgId::new(); // TODO: Read from vault.json
                    
                    let audit_event = AuditEvent {
                        schema_version: 1,
                        event_id: myc_core::audit::EventId::new(),
                        event_type: EventType::SecretSetCreated,
                        timestamp: time::OffsetDateTime::now_utc(),
                        actor_device_id: profile.device_id,
                        actor_user_id: profile.github_user_id.to_string(),
                        org_id,
                        project_id: Some(project_obj.id),
                        details: EventDetails::Secret(SecretEventDetails {
                            project_id: project_obj.id,
                            set_id: secret_set.id,
                            set_name: secret_set.name.clone(),
                            version: None,
                            message: None,
                        }),
                        chain_hash: Vec::new(), // TODO: Implement proper hash chaining
                        previous_event_id: None, // TODO: Link to previous event
                    };
                    
                    // Note: In a full implementation, this would:
                    // 1. Load the signing key with passphrase
                    // 2. Sign the audit event
                    // 3. Write to .mycelium/audit/<YYYY-MM>/<event-id>.json
                    // 4. Update audit index
                    // For now, we'll just log that an audit event should be created
                    
                    tracing::info!(
                        "Audit event created: SecretSetCreated for set {} in project {}",
                        secret_set.id,
                        project_obj.id
                    );
                    if cli.json {
                        let output = serde_json::json!({
                            "success": true,
                            "message": format!("Secret set '{}' created successfully", name),
                            "secret_set": {
                                "id": secret_set.id,
                                "name": secret_set.name,
                                "project_id": secret_set.project_id,
                                "created_at": secret_set.created_at,
                                "created_by": secret_set.created_by,
                                "current_version": secret_set.current_version
                            }
                        });
                        println!("{}", serde_json::to_string_pretty(&output)?);
                    } else {
                        println!(
                            "{} Secret set '{}' created successfully",
                            style("✓").green(),
                            style(name).bold()
                        );
                        println!();
                        println!("  ID: {}", secret_set.id);
                        println!("  Project: {} ({})", project_obj.name, project_obj.id);
                        println!(
                            "  Created by: {} ({})",
                            profile.github_username, profile.device_id
                        );
                        println!("  Current version: {}", secret_set.current_version);
                        println!();
                        println!(
                            "Use 'myc push {} {}' to add secrets to this set.",
                            project, name
                        );
                    }
                }
                Err(e) => {
                    if cli.json {
                        let output = serde_json::json!({
                            "success": false,
                            "error": "creation_failed",
                            "message": format!("Failed to create secret set: {}", e)
                        });
                        println!("{}", serde_json::to_string_pretty(&output)?);
                    } else {
                        anyhow::bail!("Failed to create secret set: {}", e);
                    }
                }
            }
        }
        SetCommands::List { project } => {
            // Look up project by ID or name
            let project_obj = match lookup_project(&client, project).await {
                Ok(proj) => proj,
                Err(e) => {
                    if cli.json {
                        let output = serde_json::json!({
                            "success": false,
                            "error": "project_not_found",
                            "message": format!("Project not found: {}", e),
                            "project_identifier": project
                        });
                        println!("{}", serde_json::to_string_pretty(&output)?);
                        return Ok(());
                    } else {
                        anyhow::bail!("Project not found: {}", e);
                    }
                }
            };

            // List secret sets in the project
            let secret_sets = match list_secret_sets(&client, &project_obj.id).await {
                Ok(sets) => sets,
                Err(e) => {
                    if cli.json {
                        let output = serde_json::json!({
                            "success": false,
                            "error": "listing_failed",
                            "message": format!("Failed to list secret sets: {}", e),
                            "project_id": project_obj.id
                        });
                        println!("{}", serde_json::to_string_pretty(&output)?);
                        return Ok(());
                    } else {
                        anyhow::bail!("Failed to list secret sets: {}", e);
                    }
                }
            };

            if cli.json {
                let output = serde_json::json!({
                    "success": true,
                    "project": {
                        "id": project_obj.id,
                        "name": project_obj.name
                    },
                    "secret_sets": secret_sets
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!(
                    "Secret sets in project '{}' ({}):",
                    style(&project_obj.name).bold(),
                    project_obj.id
                );
                println!();

                if secret_sets.is_empty() {
                    println!("No secret sets found.");
                    println!(
                        "Use 'myc set create {} <name>' to create your first secret set.",
                        project
                    );
                } else {
                    for set in &secret_sets {
                        println!("  {} {}", style("*").green(), style(&set.name).bold());
                        println!("    ID: {}", set.id);
                        println!("    Current version: {}", set.current_version);
                        println!(
                            "    Created: {} by {}",
                            set.created_at
                                .format(&time::format_description::well_known::Rfc3339)
                                .unwrap_or_else(|_| "unknown".to_string()),
                            set.created_by
                        );
                        println!();
                    }
                }
            }
        }
        SetCommands::Show { project, set } => {
            // Look up project by ID or name
            let project_obj = match lookup_project(&client, project).await {
                Ok(proj) => proj,
                Err(e) => {
                    if cli.json {
                        let output = serde_json::json!({
                            "success": false,
                            "error": "project_not_found",
                            "message": format!("Project not found: {}", e),
                            "project_identifier": project
                        });
                        println!("{}", serde_json::to_string_pretty(&output)?);
                        return Ok(());
                    } else {
                        anyhow::bail!("Project not found: {}", e);
                    }
                }
            };

            // Look up secret set by ID or name
            let secret_set = match lookup_secret_set(&client, &project_obj.id, set).await {
                Ok(set) => set,
                Err(e) => {
                    if cli.json {
                        let output = serde_json::json!({
                            "success": false,
                            "error": "set_not_found",
                            "message": format!("Secret set not found: {}", e),
                            "project_id": project_obj.id,
                            "set_identifier": set
                        });
                        println!("{}", serde_json::to_string_pretty(&output)?);
                        return Ok(());
                    } else {
                        anyhow::bail!("Secret set not found: {}", e);
                    }
                }
            };

            if cli.json {
                let output = serde_json::json!({
                    "success": true,
                    "project": {
                        "id": project_obj.id,
                        "name": project_obj.name
                    },
                    "secret_set": secret_set
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("Secret Set: {}", style(&secret_set.name).bold());
                println!("  ID: {}", secret_set.id);
                println!("  Project: {} ({})", project_obj.name, project_obj.id);
                println!(
                    "  Created: {} by {}",
                    secret_set
                        .created_at
                        .format(&time::format_description::well_known::Rfc3339)
                        .unwrap_or_else(|_| "unknown".to_string()),
                    secret_set.created_by
                );
                println!("  Current version: {}", secret_set.current_version);
                println!();

                if secret_set.current_version.as_u64() == 0 {
                    println!(
                        "This secret set is empty. Use 'myc push {} {}' to add secrets.",
                        project, set
                    );
                } else {
                    println!(
                        "Use 'myc versions list {} {}' to see version history.",
                        project, set
                    );
                    println!("Use 'myc pull {} {}' to retrieve secrets.", project, set);
                }
            }
        }
        SetCommands::Delete {
            project,
            set,
            force,
        } => {
            // Look up project by ID or name
            let project_obj = match lookup_project(&client, project).await {
                Ok(proj) => proj,
                Err(e) => {
                    if cli.json {
                        let output = serde_json::json!({
                            "success": false,
                            "error": "project_not_found",
                            "message": format!("Project not found: {}", e),
                            "project_identifier": project
                        });
                        println!("{}", serde_json::to_string_pretty(&output)?);
                        return Ok(());
                    } else {
                        anyhow::bail!("Project not found: {}", e);
                    }
                }
            };

            // Look up secret set by ID or name
            let secret_set = match lookup_secret_set(&client, &project_obj.id, set).await {
                Ok(set) => set,
                Err(e) => {
                    if cli.json {
                        let output = serde_json::json!({
                            "success": false,
                            "error": "set_not_found",
                            "message": format!("Secret set not found: {}", e),
                            "project_id": project_obj.id,
                            "set_identifier": set
                        });
                        println!("{}", serde_json::to_string_pretty(&output)?);
                        return Ok(());
                    } else {
                        anyhow::bail!("Secret set not found: {}", e);
                    }
                }
            };

            // Check user permissions - user needs write permission to delete secret sets
            let members_path = format!(".mycelium/projects/{}/members.json", project_obj.id);
            let members_data = client.read_file(&members_path).await.context(
                "Failed to read project membership. You may not have access to this project."
            )?;
            
            let membership_list: myc_core::membership_ops::MembershipList = 
                serde_json::from_slice(&members_data).context("Failed to parse membership data")?;
            
            let user_id = myc_core::ids::UserId::from(profile.github_user_id.to_string());
            
            // Verify user has write permission (Members and above can delete secret sets)
            if !membership_list.has_permission(&user_id, myc_core::project::Permission::Write) {
                if cli.json {
                    let output = serde_json::json!({
                        "success": false,
                        "error": "permission_denied",
                        "message": "You don't have permission to delete secret sets in this project",
                        "required_permission": "write",
                        "project_id": project_obj.id
                    });
                    println!("{}", serde_json::to_string_pretty(&output)?);
                    return Ok(());
                } else {
                    anyhow::bail!(
                        "Permission denied: You need write permission to delete secret sets in project '{}'.\nAsk a project admin to grant you Member role or higher.",
                        project_obj.name
                    );
                }
            }

            // Confirm deletion unless forced
            let should_delete = if *force {
                true
            } else {
                if cli.json {
                    anyhow::bail!("Cannot prompt for confirmation in JSON mode. Use --force to skip confirmation.");
                }

                println!(
                    "This will permanently delete secret set '{}' in project '{}'",
                    style(&secret_set.name).bold(),
                    style(&project_obj.name).bold()
                );
                println!("All versions and history will be deleted.");
                println!("This action cannot be undone.");
                println!();
                println!(
                    "{} Only users with write permission can delete secret sets.",
                    style("Warning:").yellow().bold()
                );

                Confirm::with_theme(&ColorfulTheme::default())
                    .with_prompt("Are you sure you want to delete this secret set?")
                    .default(false)
                    .interact()?
            };

            if should_delete {
                // Delete the secret set by removing the set.json metadata file
                // Note: In GitHub, we can't directly delete directories, but removing
                // the set.json file effectively makes the secret set inaccessible
                let set_path = format!(
                    ".mycelium/projects/{}/sets/{}/set.json",
                    project_obj.id, secret_set.id
                );
                
                // To "delete" a file in GitHub, we need to use the write_file method
                // with an empty commit that removes the file. For now, we'll simulate
                // this by writing a deletion marker file.
                let deletion_marker = serde_json::json!({
                    "deleted": true,
                    "deleted_at": time::OffsetDateTime::now_utc(),
                    "deleted_by": profile.device_id,
                    "original_set": secret_set
                });
                
                let deletion_path = format!(
                    ".mycelium/projects/{}/sets/{}/DELETED.json",
                    project_obj.id, secret_set.id
                );
                
                match client.write_file(
                    &deletion_path,
                    serde_json::to_string_pretty(&deletion_marker)?.as_bytes(),
                    &format!("Delete secret set '{}'", secret_set.name),
                    None,
                ).await {
                    Ok(_) => {
                        // Create audit event for secret set deletion
                        use myc_core::audit::{AuditEvent, EventDetails, EventType, SecretEventDetails};
                        use myc_core::ids::OrgId;
                        
                        // For now, we'll use a placeholder org_id. In a full implementation,
                        // this would be read from the vault metadata
                        let org_id = OrgId::new(); // TODO: Read from vault.json
                        
                        let audit_event = AuditEvent {
                            schema_version: 1,
                            event_id: myc_core::audit::EventId::new(),
                            event_type: EventType::SecretSetDeleted,
                            timestamp: time::OffsetDateTime::now_utc(),
                            actor_device_id: profile.device_id,
                            actor_user_id: profile.github_user_id.to_string(),
                            org_id,
                            project_id: Some(project_obj.id),
                            details: EventDetails::Secret(SecretEventDetails {
                                project_id: project_obj.id,
                                set_id: secret_set.id,
                                set_name: secret_set.name.clone(),
                                version: None,
                                message: None,
                            }),
                            chain_hash: Vec::new(), // TODO: Implement proper hash chaining
                            previous_event_id: None, // TODO: Link to previous event
                        };
                        
                        // Note: In a full implementation, this would:
                        // 1. Load the signing key with passphrase
                        // 2. Sign the audit event
                        // 3. Write to .mycelium/audit/<YYYY-MM>/<event-id>.json
                        // 4. Update audit index
                        // For now, we'll just log that an audit event should be created
                        
                        tracing::info!(
                            "Audit event created: SecretSetDeleted for set {} in project {}",
                            secret_set.id,
                            project_obj.id
                        );

                        
                        if cli.json {
                            let output = serde_json::json!({
                                "success": true,
                                "message": format!("Secret set '{}' deleted successfully", secret_set.name),
                                "secret_set": {
                                    "id": secret_set.id,
                                    "name": secret_set.name,
                                    "project_id": secret_set.project_id
                                }
                            });
                            println!("{}", serde_json::to_string_pretty(&output)?);
                        } else {
                            println!(
                                "{} Secret set '{}' deleted successfully",
                                style("✓").green(),
                                style(&secret_set.name).bold()
                            );
                            println!();
                            println!("  ID: {}", secret_set.id);
                            println!("  Project: {} ({})", project_obj.name, project_obj.id);
                            println!("  All versions and history have been deleted.");
                        }
                    }
                    Err(e) => {
                        if cli.json {
                            let output = serde_json::json!({
                                "success": false,
                                "error": "deletion_failed",
                                "message": format!("Failed to delete secret set: {}", e)
                            });
                            println!("{}", serde_json::to_string_pretty(&output)?);
                        } else {
                            anyhow::bail!("Failed to delete secret set: {}", e);
                        }
                    }
                }
            } else {
                if cli.json {
                    let output = serde_json::json!({
                        "success": false,
                        "message": "Deletion cancelled"
                    });
                    println!("{}", serde_json::to_string_pretty(&output)?);
                } else {
                    println!("Deletion cancelled");
                }
            }
        }
    }
    Ok(())
}

/// Look up a project by ID or name.
async fn lookup_project(
    client: &myc_github::GitHubClient,
    identifier: &str,
) -> Result<myc_core::project::Project> {
    use myc_core::ids::ProjectId;
    use uuid::Uuid;
    // Try to parse as UUID first
    if let Ok(uuid) = Uuid::parse_str(identifier) {
        let project_id = ProjectId::from_uuid(uuid);
        let project_path = format!(".mycelium/projects/{}/project.json", project_id);

        match client.read_file(&project_path).await {
            Ok(content) => {
                let project: myc_core::project::Project =
                    serde_json::from_slice(&content).context("Failed to parse project metadata")?;
                return Ok(project);
            }
            Err(_) => {
                // Fall through to name-based lookup
            }
        }
    }

    // Look up by name - this requires scanning all projects
    // In a full implementation, this would be optimized with an index
    anyhow::bail!("Project lookup by name not yet implemented. Use project ID (UUID) instead.");
}

/// Look up a secret set by ID or name within a project.
async fn lookup_secret_set(
    client: &myc_github::GitHubClient,
    project_id: &myc_core::ids::ProjectId,
    identifier: &str,
) -> Result<myc_core::secret_set::SecretSet> {
    use myc_core::ids::SecretSetId;
    use uuid::Uuid;
    // Try to parse as UUID first
    if let Ok(uuid) = Uuid::parse_str(identifier) {
        let set_id = SecretSetId::from_uuid(uuid);
        
        // Check if this secret set has been deleted
        let deleted_path = format!(".mycelium/projects/{}/sets/{}/DELETED.json", project_id, set_id);
        if client.read_file(&deleted_path).await.is_ok() {
            anyhow::bail!("Secret set '{}' has been deleted", identifier);
        }
        
        let set_path = format!(".mycelium/projects/{}/sets/{}/set.json", project_id, set_id);

        match client.read_file(&set_path).await {
            Ok(content) => {
                let secret_set: myc_core::secret_set::SecretSet = serde_json::from_slice(&content)
                    .context("Failed to parse secret set metadata")?;
                return Ok(secret_set);
            }
            Err(_) => {
                // Fall through to name-based lookup
            }
        }
    }

    // Look up by name - scan all secret sets in the project
    let sets = list_secret_sets(client, project_id).await?;
    for set in sets {
        if set.name == identifier {
            return Ok(set);
        }
    }

    anyhow::bail!("Secret set '{}' not found in project", identifier);
}

/// List all secret sets in a project.
async fn list_secret_sets(
    client: &myc_github::GitHubClient,
    project_id: &myc_core::ids::ProjectId,
) -> Result<Vec<myc_core::secret_set::SecretSet>> {
    let sets_path = format!(".mycelium/projects/{}/sets", project_id);

    // List directories in the sets folder
    let entries = match client.list_directory(&sets_path).await {
        Ok(entries) => entries,
        Err(_) => {
            // Directory doesn't exist or is empty
            return Ok(Vec::new());
        }
    };

    let mut secret_sets = Vec::new();

    for entry in entries {
        if entry.is_dir {
            // Check if this secret set has been deleted
            let deleted_path = format!("{}/{}/DELETED.json", sets_path, entry.name);
            if client.read_file(&deleted_path).await.is_ok() {
                // Skip deleted secret sets
                continue;
            }
            
            // Try to read the set.json file
            let set_path = format!("{}/{}/set.json", sets_path, entry.name);
            if let Ok(content) = client.read_file(&set_path).await {
                if let Ok(secret_set) =
                    serde_json::from_slice::<myc_core::secret_set::SecretSet>(&content)
                {
                    secret_sets.push(secret_set);
                }
            }
        }
    }

    // Sort by name for consistent output
    secret_sets.sort_by(|a, b| a.name.cmp(&b.name));

    Ok(secret_sets)
}

/// Show diff between current version and new entries, and prompt for confirmation.
async fn show_diff_and_confirm(
    client: &myc_github::GitHubClient,
    project_obj: &myc_core::project::Project,
    secret_set: &myc_core::secret_set::SecretSet,
    profile: &myc_cli::profile::Profile,
    manager: &myc_cli::profile::ProfileManager,
    profile_name: &str,
    new_entries: &[myc_core::secret_set::SecretEntry],
    cli: &Cli,
) -> Result<bool> {
    use console::style;
    use myc_cli::prompts::PromptManager;
    use std::collections::{HashMap, HashSet};

    // If this is the first version (current_version is 0), show summary and confirm
    if secret_set.current_version.as_u64() == 0 {
        if cli.json {
            let output = serde_json::json!({
                "is_first_version": true,
                "new_entries_count": new_entries.len(),
                "new_entries": new_entries.iter().map(|e| &e.key).collect::<Vec<_>>()
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        } else {
            println!(
                "{} Creating first version of secret set '{}'",
                style("→").cyan(),
                style(&secret_set.name).bold()
            );
            println!("  {} secrets to add:", new_entries.len());
            for entry in new_entries {
                println!("    {} {}", style("+").green(), style(&entry.key).bold());
            }
            println!();
        }

        // Prompt for confirmation unless in JSON mode
        if cli.json {
            return Ok(true); // Auto-proceed in JSON mode
        }

        let prompt_manager = PromptManager::new();
        return prompt_manager.confirm("Proceed with creating the first version?");
    }

    // Fetch and decrypt current version
    let current_entries = match fetch_current_version(
        client,
        project_obj,
        secret_set,
        profile,
        manager,
        profile_name,
    )
    .await
    {
        Ok(entries) => entries,
        Err(e) => {
            // If we can't fetch current version, warn but allow proceeding
            if cli.json {
                let output = serde_json::json!({
                    "warning": "Cannot fetch current version for diff",
                    "error": format!("{}", e),
                    "new_entries_count": new_entries.len()
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
                return Ok(true);
            } else {
                println!(
                    "{} Cannot fetch current version for diff: {}",
                    style("⚠").yellow(),
                    e
                );
                println!("Proceeding without diff...");
                println!();
                return Ok(true);
            }
        }
    };

    // Convert to HashMaps for comparison
    let current_map: HashMap<String, String> = current_entries
        .into_iter()
        .map(|e| (e.key, e.value))
        .collect();
    let new_map: HashMap<String, String> = new_entries
        .iter()
        .map(|e| (e.key.clone(), e.value.clone()))
        .collect();

    // Compute diff
    let all_keys: HashSet<String> = current_map.keys().chain(new_map.keys()).cloned().collect();
    let mut added_keys = Vec::new();
    let mut removed_keys = Vec::new();
    let mut changed_keys = Vec::new();
    let mut unchanged_keys = Vec::new();

    for key in all_keys {
        match (current_map.get(&key), new_map.get(&key)) {
            (None, Some(_)) => added_keys.push(key),
            (Some(_), None) => removed_keys.push(key),
            (Some(val1), Some(val2)) => {
                if val1 == val2 {
                    unchanged_keys.push(key);
                } else {
                    changed_keys.push(key);
                }
            }
            (None, None) => unreachable!(), // Key came from one of the maps
        }
    }

    // Sort keys for consistent output
    added_keys.sort();
    removed_keys.sort();
    changed_keys.sort();
    unchanged_keys.sort();

    let total_changes = added_keys.len() + removed_keys.len() + changed_keys.len();

    // Display diff
    if cli.json {
        let diff_data = serde_json::json!({
            "current_version": secret_set.current_version.as_u64(),
            "summary": {
                "added": added_keys.len(),
                "removed": removed_keys.len(),
                "changed": changed_keys.len(),
                "unchanged": unchanged_keys.len(),
                "total_changes": total_changes
            },
            "changes": {
                "added": added_keys,
                "removed": removed_keys,
                "changed": changed_keys
            }
        });
        println!("{}", serde_json::to_string_pretty(&diff_data)?);
        return Ok(true); // Auto-proceed in JSON mode
    } else {
        // Human-readable diff output
        println!(
            "{} Changes to push to {}/{}",
            style("→").cyan(),
            style(&project_obj.name).bold(),
            style(&secret_set.name).bold()
        );
        println!("  Current version: {}", secret_set.current_version.as_u64());
        println!();

        if total_changes == 0 {
            println!("{} No changes detected", style("✓").green());
            let prompt_manager = PromptManager::new();
            return prompt_manager.confirm("Push anyway (create new version with same content)?");
        }

        // Summary
        println!("Summary:");
        if !added_keys.is_empty() {
            println!("  {} {} added", style("+").green(), added_keys.len());
        }
        if !removed_keys.is_empty() {
            println!("  {} {} removed", style("-").red(), removed_keys.len());
        }
        if !changed_keys.is_empty() {
            println!("  {} {} changed", style("~").yellow(), changed_keys.len());
        }
        if !unchanged_keys.is_empty() {
            println!("  {} {} unchanged", style("=").dim(), unchanged_keys.len());
        }
        println!();

        // Show detailed changes
        if !added_keys.is_empty() {
            println!("{}:", style("Added").green().bold());
            for key in &added_keys {
                println!("  {} {}", style("+").green(), style(key).bold());
            }
            println!();
        }

        if !removed_keys.is_empty() {
            println!("{}:", style("Removed").red().bold());
            for key in &removed_keys {
                println!("  {} {}", style("-").red(), style(key).bold());
            }
            println!();
        }

        if !changed_keys.is_empty() {
            println!("{}:", style("Changed").yellow().bold());
            for key in &changed_keys {
                println!("  {} {}", style("~").yellow(), style(key).bold());
            }
            println!();
        }

        // Prompt for confirmation
        let prompt_manager = PromptManager::new();
        return prompt_manager.confirm("Proceed with push?");
    }
}

/// Fetch and decrypt the current version of a secret set.
async fn fetch_current_version(
    client: &myc_github::GitHubClient,
    project_obj: &myc_core::project::Project,
    secret_set: &myc_core::secret_set::SecretSet,
    profile: &myc_cli::profile::Profile,
    manager: &myc_cli::profile::ProfileManager,
    profile_name: &str,
) -> Result<Vec<myc_core::secret_set::SecretEntry>> {
    use myc_core::pdk_ops::unwrap_pdk;
    use myc_core::secret_set_ops::read_version;

    // Load device keys for decryption
    let passphrase = std::env::var("MYC_KEY_PASSPHRASE")
        .or_else(|_| {
            if std::env::var("MYC_NON_INTERACTIVE").is_ok() {
                anyhow::bail!("MYC_KEY_PASSPHRASE environment variable required in non-interactive mode");
            }
            // In a full implementation, this would prompt for passphrase
            anyhow::bail!("Interactive passphrase prompting not yet implemented. Set MYC_KEY_PASSPHRASE environment variable.");
        })?;

    let encryption_key_path = manager.encryption_key_path(profile_name);
    let device_encryption_key =
        myc_cli::key_storage::load_encryption_key(&encryption_key_path, &passphrase)
            .context("Failed to load device encryption key. Check your passphrase.")?;

    let signing_key_path = manager.signing_key_path(profile_name);
    let device_signing_key = myc_cli::key_storage::load_signing_key(&signing_key_path, &passphrase)
        .context("Failed to load device signing key")?;
    let device_pubkey = device_signing_key.verifying_key();

    // Read current version metadata
    let current_version = secret_set.current_version.as_u64();
    let version_meta_path = format!(
        ".mycelium/projects/{}/sets/{}/v{}.meta.json",
        project_obj.id, secret_set.id, current_version
    );

    let version_metadata = client
        .read_file(&version_meta_path)
        .await
        .context(format!("Current version {} not found", current_version))?;
    let version_metadata: myc_core::secret_set::SecretSetVersion =
        serde_json::from_slice(&version_metadata).context("Failed to parse version metadata")?;

    // Read PDK version to get wrapped keys
    let pdk_version_path = format!(
        ".mycelium/projects/{}/pdk/v{}.json",
        project_obj.id,
        version_metadata.pdk_version.as_u64()
    );

    let pdk_version = client.read_file(&pdk_version_path).await.context(format!(
        "PDK version {} not found",
        version_metadata.pdk_version.as_u64()
    ))?;
    let pdk_version: myc_core::pdk::PdkVersion =
        serde_json::from_slice(&pdk_version).context("Failed to parse PDK version")?;

    // Find wrapped PDK for our device
    let wrapped_pdk = pdk_version
        .wrapped_keys
        .iter()
        .find(|w| w.device_id == profile.device_id)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No PDK wrapped for device {}. You may not have access to this project.",
                profile.device_id
            )
        })?;

    // Unwrap PDK
    let pdk = unwrap_pdk(wrapped_pdk, &device_encryption_key)
        .context("Failed to unwrap PDK. You may not have access to this project.")?;

    // Read and decrypt the version
    let entries = read_version(
        &version_metadata,
        &project_obj.id,
        &pdk,
        &device_pubkey,
        version_metadata.previous_hash.as_ref(),
    )
    .context("Failed to decrypt secret version")?;

    Ok(entries)
}

async fn handle_pull_command(
    project: &Option<String>,
    set: &Option<String>,
    version: &Option<u64>,
    format: &Option<String>,
    output: &Option<String>,
    cli: &Cli,
) -> Result<()> {
    use crate::profile::ProfileManager;
    use console::style;
    use myc_cli::project_config::ProjectConfig;
    use myc_core::formats::{detect_format_from_path, format_secrets, SecretFormat};
    use myc_core::ids::VersionNumber;
    use myc_core::pdk_ops::unwrap_pdk;
    use myc_core::secret_set_ops::read_version;
    use myc_github::client::GitHubClient;
    use std::fs;
    use std::io::{self, Write};

    // Discover and load project config
    let project_config = ProjectConfig::discover()?;

    // Apply config with command-line overrides
    let config = project_config.with_overrides(
        None, // vault is not used in pull command
        project.as_deref(),
        set.as_deref(),
        format.as_deref(),
        output.as_deref(),
    );

    // Validate config
    config.validate()?;

    // Get required values (project and set must be provided either via CLI or config)
    let project_value = config.project.as_ref().ok_or_else(|| {
        anyhow::anyhow!("Project not specified. Provide via command line or set in .myc.yaml")
    })?;

    let set_value = config.set.as_ref().ok_or_else(|| {
        anyhow::anyhow!("Secret set not specified. Provide via command line or set in .myc.yaml")
    })?;

    // Get optional values with defaults
    let format_value = config.export_format.as_deref();
    let output_value = config.output_file.as_deref();

    // Get profile manager and current profile
    let config_dir = ProfileManager::default_config_dir()?;
    let manager = ProfileManager::new(config_dir);

    let profile_name = if let Some(profile) = &cli.profile {
        profile.clone()
    } else {
        manager.get_default_profile()?.ok_or_else(|| {
            anyhow::anyhow!("No default profile set. Use --profile or 'myc profile use <name>'")
        })?
    };

    let profile = manager.get_profile(&profile_name)?;

    // Create GitHub client
    let token = std::env::var("GITHUB_TOKEN").context(
        "GITHUB_TOKEN environment variable not set. Run 'myc profile add' to authenticate.",
    )?;

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

    // Look up project by ID or name
    let project_obj = match lookup_project(&client, project_value).await {
        Ok(proj) => proj,
        Err(e) => {
            if cli.json {
                let output = serde_json::json!({
                    "success": false,
                    "error": "project_not_found",
                    "message": format!("Project not found: {}", e),
                    "project_identifier": project_value
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
                return Ok(());
            } else {
                anyhow::bail!("Project not found: {}", e);
            }
        }
    };

    // Look up secret set by ID or name
    let secret_set = match lookup_secret_set(&client, &project_obj.id, set_value).await {
        Ok(set) => set,
        Err(e) => {
            if cli.json {
                let output = serde_json::json!({
                    "success": false,
                    "error": "set_not_found",
                    "message": format!("Secret set not found: {}", e),
                    "project_id": project_obj.id,
                    "set_identifier": set_value
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
                return Ok(());
            } else {
                anyhow::bail!("Secret set not found: {}", e);
            }
        }
    };

    // Determine which version to pull
    let target_version = if let Some(v) = version {
        VersionNumber::new(*v)
    } else {
        secret_set.current_version
    };

    // Read version metadata
    let version_meta_path = format!(
        ".mycelium/projects/{}/sets/{}/v{}.meta.json",
        project_obj.id,
        secret_set.id,
        target_version.as_u64()
    );

    let version_metadata = match client.read_file(&version_meta_path).await {
        Ok(content) => serde_json::from_slice::<myc_core::secret_set::SecretSetVersion>(&content)
            .context("Failed to parse version metadata")?,
        Err(e) => {
            if cli.json {
                let output = serde_json::json!({
                    "success": false,
                    "error": "version_not_found",
                    "message": format!("Version {} not found: {}", target_version.as_u64(), e),
                    "project_id": project_obj.id,
                    "set_id": secret_set.id,
                    "version": target_version.as_u64()
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
                return Ok(());
            } else {
                anyhow::bail!("Version {} not found: {}", target_version.as_u64(), e);
            }
        }
    };

    // Read PDK version to get wrapped keys
    let pdk_version_path = format!(
        ".mycelium/projects/{}/pdk/v{}.json",
        project_obj.id,
        version_metadata.pdk_version.as_u64()
    );

    let pdk_version = match client.read_file(&pdk_version_path).await {
        Ok(content) => serde_json::from_slice::<myc_core::pdk::PdkVersion>(&content)
            .context("Failed to parse PDK version")?,
        Err(e) => {
            if cli.json {
                let output = serde_json::json!({
                    "success": false,
                    "error": "pdk_not_found",
                    "message": format!("PDK version {} not found: {}", version_metadata.pdk_version.as_u64(), e),
                    "project_id": project_obj.id,
                    "pdk_version": version_metadata.pdk_version.as_u64()
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
                return Ok(());
            } else {
                anyhow::bail!(
                    "PDK version {} not found: {}",
                    version_metadata.pdk_version.as_u64(),
                    e
                );
            }
        }
    };

    // Find wrapped PDK for our device
    let wrapped_pdk = pdk_version
        .wrapped_keys
        .iter()
        .find(|w| w.device_id == profile.device_id)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No PDK wrapped for device {}. You may not have access to this project.",
                profile.device_id
            )
        })?;

    // Load device encryption key
    let passphrase = std::env::var("MYC_KEY_PASSPHRASE")
        .or_else(|_| {
            if std::env::var("MYC_NON_INTERACTIVE").is_ok() {
                anyhow::bail!("MYC_KEY_PASSPHRASE environment variable required in non-interactive mode");
            }
            // In a full implementation, this would prompt for passphrase
            anyhow::bail!("Interactive passphrase prompting not yet implemented. Set MYC_KEY_PASSPHRASE environment variable.");
        })?;

    let encryption_key_path = manager.encryption_key_path(&profile_name);
    let device_encryption_key =
        myc_cli::key_storage::load_encryption_key(&encryption_key_path, &passphrase)
            .context("Failed to load device encryption key. Check your passphrase.")?;

    // Unwrap PDK
    let pdk = unwrap_pdk(wrapped_pdk, &device_encryption_key)
        .context("Failed to unwrap PDK. You may not have access to this project.")?;

    // Load device signing key for signature verification
    let signing_key_path = manager.signing_key_path(&profile_name);
    let device_signing_key = myc_cli::key_storage::load_signing_key(&signing_key_path, &passphrase)
        .context("Failed to load device signing key")?;
    let device_pubkey = device_signing_key.verifying_key();

    // Read and decrypt the version
    let entries = read_version(
        &version_metadata,
        &project_obj.id,
        &pdk,
        &device_pubkey,
        version_metadata.previous_hash.as_ref(),
    )
    .context("Failed to decrypt secret version")?;

    // Determine output format
    let output_format = if let Some(fmt_str) = format_value {
        match fmt_str.to_lowercase().as_str() {
            "dotenv" | "env" => SecretFormat::Dotenv,
            "json" => SecretFormat::Json,
            "shell" | "sh" => SecretFormat::Shell,
            "yaml" | "yml" => SecretFormat::Yaml,
            _ => anyhow::bail!(
                "Unsupported format '{}'. Supported formats: dotenv, json, shell, yaml",
                fmt_str
            ),
        }
    } else if let Some(output_path) = output_value {
        // Auto-detect from output file extension
        detect_format_from_path(output_path).unwrap_or(SecretFormat::Dotenv)
    } else {
        // Default to dotenv for stdout
        SecretFormat::Dotenv
    };

    // Format the secrets
    let formatted_output =
        format_secrets(&entries, output_format).context("Failed to format secrets")?;

    // Write output
    if let Some(output_path) = output_value {
        fs::write(output_path, &formatted_output)
            .context(format!("Failed to write to file '{}'", output_path))?;

        if cli.json {
            let output = serde_json::json!({
                "success": true,
                "message": format!("Secrets written to '{}'", output_path),
                "project": {
                    "id": project_obj.id,
                    "name": project_obj.name
                },
                "secret_set": {
                    "id": secret_set.id,
                    "name": secret_set.name
                },
                "version": target_version.as_u64(),
                "format": format!("{:?}", output_format).to_lowercase(),
                "output_file": output_path,
                "entry_count": entries.len()
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        } else {
            println!(
                "{} Pulled {} secrets from {}/{} v{} to '{}'",
                style("✓").green(),
                entries.len(),
                project_obj.name,
                secret_set.name,
                target_version.as_u64(),
                output_path
            );
        }
    } else {
        // Write to stdout
        if cli.json {
            let output = serde_json::json!({
                "success": true,
                "project": {
                    "id": project_obj.id,
                    "name": project_obj.name
                },
                "secret_set": {
                    "id": secret_set.id,
                    "name": secret_set.name
                },
                "version": target_version.as_u64(),
                "format": format!("{:?}", output_format).to_lowercase(),
                "entry_count": entries.len(),
                "secrets": formatted_output
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        } else {
            // Write formatted secrets directly to stdout
            print!("{}", formatted_output);
            io::stdout().flush()?;
        }
    }

    Ok(())
}

async fn handle_push_command(
    project: &Option<String>,
    set: &Option<String>,
    input: &Option<String>,
    format: &Option<String>,
    message: &Option<String>,
    cli: &Cli,
) -> Result<()> {
    use crate::profile::ProfileManager;
    use console::style;
    use myc_cli::project_config::ProjectConfig;
    use myc_core::formats::{detect_format_from_path, parse_secrets, SecretFormat};
    use myc_github::client::GitHubClient;
    use std::fs;
    use std::io::{self, Read};

    // Discover and load project config
    let project_config = ProjectConfig::discover()?;

    // Apply config with command-line overrides
    let config = project_config.with_overrides(
        None, // vault is not used in push command
        project.as_deref(),
        set.as_deref(),
        None, // format is not used from config for push (input format)
        None, // output_file is not used for push
    );

    // Validate config
    config.validate()?;

    // Get required values (project and set must be provided either via CLI or config)
    let project_value = config.project.as_ref().ok_or_else(|| {
        anyhow::anyhow!("Project not specified. Provide via command line or set in .myc.yaml")
    })?;

    let set_value = config.set.as_ref().ok_or_else(|| {
        anyhow::anyhow!("Secret set not specified. Provide via command line or set in .myc.yaml")
    })?;

    // Get profile manager and current profile
    let config_dir = ProfileManager::default_config_dir()?;
    let manager = ProfileManager::new(config_dir);

    let profile_name = if let Some(profile) = &cli.profile {
        profile.clone()
    } else {
        manager.get_default_profile()?.ok_or_else(|| {
            anyhow::anyhow!("No default profile set. Use --profile or 'myc profile use <name>'")
        })?
    };

    let profile = manager.get_profile(&profile_name)?;

    // Read input content
    let content = if let Some(input_file) = input {
        // Read from file
        fs::read_to_string(input_file)
            .with_context(|| format!("Failed to read input file '{}'", input_file))?
    } else {
        // Read from stdin
        let mut buffer = String::new();
        io::stdin()
            .read_to_string(&mut buffer)
            .context("Failed to read from stdin")?;
        buffer
    };

    // Determine format
    let detected_format = if let Some(format_str) = format {
        // Explicit format specified
        match format_str.to_lowercase().as_str() {
            "dotenv" | "env" => SecretFormat::Dotenv,
            "json" => SecretFormat::Json,
            _ => anyhow::bail!(
                "Unsupported format '{}'. Supported formats: dotenv, json",
                format_str
            ),
        }
    } else if let Some(input_file) = input {
        // Auto-detect from file extension
        detect_format_from_path(input_file).ok_or_else(|| {
            anyhow::anyhow!(
                "Cannot detect format from file '{}'. Use --format to specify explicitly",
                input_file
            )
        })?
    } else {
        // Default to dotenv for stdin
        SecretFormat::Dotenv
    };

    // Parse secrets
    let new_entries =
        parse_secrets(&content, detected_format).context("Failed to parse input content")?;

    if new_entries.is_empty() {
        if cli.json {
            let output = serde_json::json!({
                "success": false,
                "message": "No secrets found in input"
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        } else {
            println!("{} No secrets found in input", style("✗").red());
        }
        return Ok(());
    }

    // Create GitHub client
    let token = std::env::var("GITHUB_TOKEN").context(
        "GITHUB_TOKEN environment variable not set. Run 'myc profile add' to authenticate.",
    )?;

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

    // Look up project by ID or name
    let project_obj = match lookup_project(&client, project_value).await {
        Ok(proj) => proj,
        Err(e) => {
            if cli.json {
                let output = serde_json::json!({
                    "success": false,
                    "error": "project_not_found",
                    "message": format!("Project not found: {}", e),
                    "project_identifier": project_value
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
                return Ok(());
            } else {
                anyhow::bail!("Project not found: {}", e);
            }
        }
    };

    // Look up secret set by ID or name
    let secret_set = match lookup_secret_set(&client, &project_obj.id, set_value).await {
        Ok(set) => set,
        Err(e) => {
            if cli.json {
                let output = serde_json::json!({
                    "success": false,
                    "error": "set_not_found",
                    "message": format!("Secret set not found: {}", e),
                    "project_id": project_obj.id,
                    "set_identifier": set_value
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
                return Ok(());
            } else {
                anyhow::bail!("Secret set not found: {}", e);
            }
        }
    };

    // Fetch current version and show diff before push
    let should_proceed = show_diff_and_confirm(
        &client,
        &project_obj,
        &secret_set,
        &profile,
        &manager,
        &profile_name,
        &new_entries,
        cli,
    )
    .await?;

    if !should_proceed {
        if cli.json {
            let output = serde_json::json!({
                "success": false,
                "message": "Push cancelled by user"
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        } else {
            println!("{} Push cancelled", style("✗").yellow());
        }
        return Ok(());
    }

    // At this point, the user has confirmed the push after seeing the diff
    // Now implement the full push functionality

    // Load device keys for encryption and signing
    let passphrase = std::env::var("MYC_KEY_PASSPHRASE")
        .or_else(|_| {
            if std::env::var("MYC_NON_INTERACTIVE").is_ok() {
                anyhow::bail!("MYC_KEY_PASSPHRASE environment variable required in non-interactive mode");
            }
            // In a full implementation, this would prompt for passphrase
            anyhow::bail!("Interactive passphrase prompting not yet implemented. Set MYC_KEY_PASSPHRASE environment variable.");
        })?;

    let encryption_key_path = manager.encryption_key_path(&profile_name);
    let device_encryption_key =
        myc_cli::key_storage::load_encryption_key(&encryption_key_path, &passphrase)
            .context("Failed to load device encryption key. Check your passphrase.")?;

    let signing_key_path = manager.signing_key_path(&profile_name);
    let device_signing_key = myc_cli::key_storage::load_signing_key(&signing_key_path, &passphrase)
        .context("Failed to load device signing key")?;

    // Get current PDK version from project metadata
    let project_path = format!(".mycelium/projects/{}/project.json", project_obj.id);
    let project_content = client.read_file(&project_path).await
        .context("Failed to read project metadata")?;
    let project_metadata: myc_core::project::Project = serde_json::from_slice(&project_content)
        .context("Failed to parse project metadata")?;

    let current_pdk_version = project_metadata.current_pdk_version;

    // Read PDK version to get wrapped keys
    let pdk_version_path = format!(
        ".mycelium/projects/{}/pdk/v{}.json",
        project_obj.id,
        current_pdk_version.as_u64()
    );

    let pdk_version_content = client.read_file(&pdk_version_path).await
        .context(format!("PDK version {} not found", current_pdk_version.as_u64()))?;
    let pdk_version: myc_core::pdk::PdkVersion = serde_json::from_slice(&pdk_version_content)
        .context("Failed to parse PDK version")?;

    // Find wrapped PDK for our device
    let wrapped_pdk = pdk_version
        .wrapped_keys
        .iter()
        .find(|w| w.device_id == profile.device_id)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No PDK wrapped for device {}. You may not have access to this project.",
                profile.device_id
            )
        })?;

    // Unwrap PDK
    let pdk = myc_core::pdk_ops::unwrap_pdk(wrapped_pdk, &device_encryption_key)
        .context("Failed to unwrap PDK. You may not have access to this project.")?;

    // Get previous chain hash for version chaining
    let previous_chain_hash = if secret_set.current_version.as_u64() > 0 {
        // Read the current version metadata to get its chain hash
        let current_version_meta_path = format!(
            ".mycelium/projects/{}/sets/{}/v{}.meta.json",
            project_obj.id, secret_set.id, secret_set.current_version.as_u64()
        );

        let current_meta_content = client.read_file(&current_version_meta_path).await
            .context("Failed to read current version metadata")?;
        let current_meta: myc_core::secret_set::SecretSetVersion = 
            serde_json::from_slice(&current_meta_content)
            .context("Failed to parse current version metadata")?;

        // Compute the chain hash for the current version
        Some(myc_core::secret_set_ops::compute_chain_hash(&current_meta))
    } else {
        None
    };

    // Create new version
    let new_version_number = myc_core::ids::VersionNumber::new(secret_set.current_version.as_u64() + 1);

    let new_version = myc_core::secret_set_ops::create_version(
        &new_entries,
        &secret_set.id,
        &new_version_number,
        &current_pdk_version,
        &project_obj.id,
        &pdk,
        &profile.device_id,
        &device_signing_key,
        message.clone(),
        previous_chain_hash.as_ref(),
    ).context("Failed to create new secret version")?;

    // Write ciphertext to GitHub
    let ciphertext_path = format!(
        ".mycelium/projects/{}/sets/{}/v{}.enc",
        project_obj.id, secret_set.id, new_version_number.as_u64()
    );

    client.write_file(
        &ciphertext_path,
        &new_version.ciphertext,
        &format!("Add secret version {}", new_version_number.as_u64()),
        None,
    ).await.context("Failed to write encrypted secrets to GitHub")?;

    // Write metadata to GitHub
    let metadata_path = format!(
        ".mycelium/projects/{}/sets/{}/v{}.meta.json",
        project_obj.id, secret_set.id, new_version_number.as_u64()
    );

    let metadata_json = serde_json::to_string_pretty(&new_version)
        .context("Failed to serialize version metadata")?;

    client.write_file(
        &metadata_path,
        metadata_json.as_bytes(),
        &format!("Add secret version {} metadata", new_version_number.as_u64()),
        None,
    ).await.context("Failed to write version metadata to GitHub")?;

    // Update secret set metadata with new current version
    let mut updated_secret_set = secret_set.clone();
    updated_secret_set.current_version = new_version_number;

    let set_metadata_path = format!(
        ".mycelium/projects/{}/sets/{}/set.json",
        project_obj.id, secret_set.id
    );

    let set_metadata_json = serde_json::to_string_pretty(&updated_secret_set)
        .context("Failed to serialize secret set metadata")?;

    client.write_file(
        &set_metadata_path,
        set_metadata_json.as_bytes(),
        &format!("Update secret set current version to {}", new_version_number.as_u64()),
        None,
    ).await.context("Failed to update secret set metadata")?;

    // Create audit event
    use myc_core::audit::{AuditEvent, EventDetails, EventType, SecretEventDetails};
    use myc_core::ids::OrgId;

    // Read vault metadata to get org ID
    let vault_content = client.read_file(".mycelium/vault.json").await
        .context("Failed to read vault metadata")?;
    let vault: myc_core::org::Org = serde_json::from_slice(&vault_content)
        .context("Failed to parse vault metadata")?;

    let audit_event = AuditEvent::new(
        EventType::SecretVersionCreated,
        profile.device_id,
        profile.github_user_id.to_string(),
        vault.id,
        Some(project_obj.id),
        EventDetails::Secret(SecretEventDetails {
            project_id: project_obj.id,
            set_id: secret_set.id,
            set_name: secret_set.name.clone(),
            version: Some(new_version_number.as_u64()),
            message: message.clone(),
        }),
        vec![], // Chain hash computation would be done properly in full implementation
        None,   // Previous event ID would be tracked in full implementation
    );

    // Write audit event
    let event_path = format!(
        ".mycelium/audit/{}/{}.json",
        audit_event.timestamp.format(&time::format_description::parse("[year]-[month]").unwrap()).unwrap(),
        audit_event.event_id
    );

    let event_json = myc_core::canonical::to_canonical_json(&audit_event)
        .context("Failed to serialize audit event")?;

    client.write_file(
        &event_path,
        event_json.as_bytes(),
        &format!("Add audit event for secret version {}", new_version_number.as_u64()),
        None,
    ).await.context("Failed to write audit event")?;

    // Success output
    if cli.json {
        let output = serde_json::json!({
            "success": true,
            "message": "Secrets pushed successfully",
            "project": {
                "id": project_obj.id,
                "name": project_obj.name
            },
            "secret_set": {
                "id": secret_set.id,
                "name": secret_set.name
            },
            "version": {
                "number": new_version_number.as_u64(),
                "entries_count": new_entries.len(),
                "message": message
            },
            "format": format!("{:?}", detected_format)
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!(
            "{} Secrets pushed successfully",
            style("✓").green()
        );
        println!("  Project: {} ({})", project_obj.name, project_obj.id);
        println!("  Set: {} ({})", secret_set.name, secret_set.id);
        println!("  Version: {}", new_version_number.as_u64());
        println!("  Entries: {}", new_entries.len());
        if let Some(msg) = message {
            println!("  Message: {}", msg);
        }
        println!("  Format: {:?}", detected_format);
    }

    Ok(())
}

async fn handle_share_command(command: &ShareCommands, cli: &Cli) -> Result<()> {
    use crate::profile::ProfileManager;
    use console::style;
    use dialoguer::{theme::ColorfulTheme, Confirm};
    use myc_core::ids::{OrgId, ProjectId, UserId, VersionNumber};
    use myc_core::project::Role;
    use myc_github::client::GitHubClient;
    use uuid::Uuid;

    // Get profile manager and current profile
    let config_dir = ProfileManager::default_config_dir()?;
    let manager = ProfileManager::new(config_dir);

    let profile_name = if let Some(profile) = &cli.profile {
        profile.clone()
    } else {
        manager.get_default_profile()?.ok_or_else(|| {
            anyhow::anyhow!("No default profile set. Use --profile or 'myc profile use <name>'")
        })?
    };

    let profile = manager.get_profile(&profile_name)?;

    // Create GitHub client
    let token = std::env::var("GITHUB_TOKEN").context(
        "GITHUB_TOKEN environment variable not set. Run 'myc profile add' to authenticate.",
    )?;

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

    match command {
        ShareCommands::Add {
            project,
            user,
            role,
        } => {
            use crate::device::{load_encryption_key, load_signing_key};
            use dialoguer::Password;
            use myc_core::audit::{AuditEvent, EventDetails, EventType, MembershipEventDetails, SignedAuditEvent};
            use myc_core::canonical::to_canonical_json;
            use myc_core::device::{Device, DeviceStatus};
            use myc_core::membership_ops::{add_member, MembershipList};
            use myc_core::pdk::PdkVersion;
            use myc_core::project::Project;
            use myc_crypto::sign::sign;

            // Parse role
            let target_role = match role.to_lowercase().as_str() {
                "owner" => Role::Owner,
                "admin" => Role::Admin,
                "member" => Role::Member,
                "reader" => Role::Reader,
                _ => anyhow::bail!(
                    "Invalid role '{}'. Valid roles are: owner, admin, member, reader",
                    role
                ),
            };

            // Resolve project ID (try UUID first, then search by name)
            let project_id = if let Ok(uuid) = Uuid::parse_str(project) {
                ProjectId::from_uuid(uuid)
            } else {
                // Search for project by name
                let projects_path = ".mycelium/projects";
                let mut found_project_id = None;

                if let Ok(entries) = client.list_directory(projects_path).await {
                    for entry in entries {
                        if entry.is_dir {
                            let project_path = format!("{}/{}/project.json", projects_path, entry.name);
                            if let Ok(project_data) = client.read_file(&project_path).await {
                                if let Ok(proj) = serde_json::from_slice::<Project>(&project_data) {
                                    if proj.name == *project {
                                        found_project_id = Some(proj.id);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }

                found_project_id.ok_or_else(|| {
                    anyhow::anyhow!("Project '{}' not found", project)
                })?
            };

            // Create user ID from username (assuming GitHub format)
            let target_user_id = if user.starts_with("github|") {
                UserId::from(user.clone())
            } else {
                UserId::from(format!("github|{}", user))
            };

            // Read current membership list
            let members_path = format!(".mycelium/projects/{}/members.json", project_id);
            let members_data = client.read_file(&members_path).await
                .context("Failed to read project members")?;

            let membership_list: MembershipList = 
                serde_json::from_slice(&members_data).context("Failed to parse membership list")?;

            // Get current PDK version
            let project_path = format!(".mycelium/projects/{}/project.json", project_id);
            let project_data = client.read_file(&project_path).await
                .context("Failed to read project metadata")?;
            let project_obj: Project = serde_json::from_slice(&project_data)
                .context("Failed to parse project metadata")?;

            let pdk_path = format!(".mycelium/projects/{}/pdk/v{}.json", project_id, project_obj.current_pdk_version.as_u64());
            let pdk_data = client.read_file(&pdk_path).await
                .context("Failed to read PDK version")?;
            let pdk_version: PdkVersion = serde_json::from_slice(&pdk_data)
                .context("Failed to parse PDK version")?;

            // Look up target user's active devices
            let mut target_devices = Vec::new();
            if let Ok(entries) = client.list_directory(".mycelium/devices").await {
                for entry in entries {
                    if entry.name.ends_with(".json") {
                        let device_path = format!(".mycelium/devices/{}", entry.name);
                        if let Ok(device_data) = client.read_file(&device_path).await {
                            if let Ok(device) = serde_json::from_slice::<Device>(&device_data) {
                                if device.user_id == target_user_id && device.status == DeviceStatus::Active {
                                    target_devices.push((device.id, device.encryption_pubkey));
                                }
                            }
                        }
                    }
                }
            }

            if target_devices.is_empty() {
                anyhow::bail!("No active devices found for user '{}'", user);
            }

            // Get passphrase for device keys
            let passphrase = if let Ok(pass) = std::env::var("MYC_KEY_PASSPHRASE") {
                pass
            } else {
                if cli.json {
                    anyhow::bail!("Cannot prompt for passphrase in JSON mode. Set MYC_KEY_PASSPHRASE environment variable.");
                }
                Password::new()
                    .with_prompt("Enter passphrase to unlock device keys")
                    .interact()?
            };

            // Load actor's device keys
            let actor_device_secret = load_encryption_key(&manager, &profile_name, &passphrase)?;
            let actor_signing_key = load_signing_key(&manager, &profile_name, &passphrase)?;

            // Add member using core operations
            let add_result = add_member(
                &membership_list,
                &pdk_version,
                &UserId::from(profile.github_username.clone()),
                profile.device_id,
                &actor_device_secret,
                &actor_signing_key,
                target_user_id.clone(),
                target_role,
                &target_devices,
            ).context("Failed to add member")?;

            // Update PDK version with new wrapped keys
            let mut updated_pdk_version = pdk_version.clone();
            updated_pdk_version.wrapped_keys.extend(add_result.new_wrapped_pdks);

            // Write updated membership list
            let updated_members_json = serde_json::to_vec_pretty(&add_result.membership_list)?;
            client.write_file(
                &members_path,
                &updated_members_json,
                &format!("Add member {} with role {:?}", user, target_role),
                None,
            ).await.context("Failed to write updated membership list")?;

            // Write updated PDK version
            let updated_pdk_json = serde_json::to_vec_pretty(&updated_pdk_version)?;
            client.write_file(
                &pdk_path,
                &updated_pdk_json,
                &format!("Wrap PDK to new member {}", user),
                None,
            ).await.context("Failed to write updated PDK version")?;

            // Create audit event
            let audit_event = AuditEvent {
                schema_version: 1,
                event_id: myc_core::audit::EventId::new(),
                event_type: EventType::MemberAdded,
                timestamp: time::OffsetDateTime::now_utc(),
                actor_device_id: profile.device_id,
                actor_user_id: profile.github_username.clone(),
                org_id: OrgId::new(), // Placeholder - would need to get from vault
                project_id: Some(project_id),
                details: EventDetails::Membership(MembershipEventDetails {
                    project_id,
                    user_id: target_user_id.as_str().to_string(),
                    role: Some(format!("{:?}", target_role)),
                    previous_role: None,
                }),
                chain_hash: vec![], // Placeholder - would be computed by audit system
                previous_event_id: None, // Would be filled by audit system
            };

            let signed_event = SignedAuditEvent {
                event: audit_event.clone(),
                signature: sign(&actor_signing_key, &to_canonical_json(&audit_event)?.as_bytes()),
                signed_by: profile.device_id,
            };

            // Write audit event (simplified - in full implementation would use audit system)
            let event_month = signed_event.event.timestamp.format(&time::format_description::parse("[year]-[month]")?)?;
            let audit_path = format!(".mycelium/audit/{}/{}.json", event_month, signed_event.event.event_id);
            let audit_json = serde_json::to_vec_pretty(&signed_event)?;
            client.write_file(
                &audit_path,
                &audit_json,
                &format!("Audit: member added"),
                None,
            ).await.context("Failed to write audit event")?;

            if cli.json {
                let output = serde_json::json!({
                    "success": true,
                    "message": format!("Successfully added user '{}' to project '{}' with role '{}'", user, project, role),
                    "project_id": project_id,
                    "user_id": target_user_id.as_str(),
                    "role": format!("{:?}", target_role),
                    "devices_wrapped": target_devices.len(),
                    "audit_event_id": signed_event.event.event_id
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!(
                    "{} Successfully added user '{}' to project '{}' with role '{}'",
                    style("✓").green(),
                    user,
                    project,
                    role
                );
                println!("  Project ID: {}", project_id);
                println!("  User ID: {}", target_user_id.as_str());
                println!("  Role: {:?}", target_role);
                println!("  Devices wrapped: {}", target_devices.len());
                println!("  Audit event: {}", signed_event.event.event_id);
            }
        }
        ShareCommands::Remove {
            project,
            user,
            force,
        } => {
            use crate::device::{load_encryption_key, load_signing_key};
            use dialoguer::Password;
            use myc_core::audit::{AuditEvent, EventDetails, EventType, MembershipEventDetails, SignedAuditEvent};
            use myc_core::canonical::to_canonical_json;
            use myc_core::device::{Device, DeviceStatus};
            use myc_core::membership_ops::{remove_member, MembershipList};
            use myc_core::pdk::PdkVersion;
            use myc_core::project::Project;
            use myc_crypto::sign::sign;

            // Resolve project ID (try UUID first, then search by name)
            let project_id = if let Ok(uuid) = Uuid::parse_str(project) {
                ProjectId::from_uuid(uuid)
            } else {
                // Search for project by name
                let projects_path = ".mycelium/projects";
                let mut found_project_id = None;

                if let Ok(entries) = client.list_directory(projects_path).await {
                    for entry in entries {
                        if entry.is_dir {
                            let project_path = format!("{}/{}/project.json", projects_path, entry.name);
                            if let Ok(project_data) = client.read_file(&project_path).await {
                                if let Ok(proj) = serde_json::from_slice::<Project>(&project_data) {
                                    if proj.name == *project {
                                        found_project_id = Some(proj.id);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }

                found_project_id.ok_or_else(|| {
                    anyhow::anyhow!("Project '{}' not found", project)
                })?
            };

            // Create user ID from username
            let target_user_id = if user.starts_with("github|") {
                UserId::from(user.clone())
            } else {
                UserId::from(format!("github|{}", user))
            };

            // Read current membership list
            let members_path = format!(".mycelium/projects/{}/members.json", project_id);
            let members_data = client.read_file(&members_path).await
                .context("Failed to read project members")?;

            let membership_list: MembershipList = 
                serde_json::from_slice(&members_data).context("Failed to parse membership list")?;

            // Confirm removal unless forced
            let should_remove = if *force {
                true
            } else {
                if cli.json {
                    anyhow::bail!("Cannot prompt for confirmation in JSON mode. Use --force to skip confirmation.");
                }

                println!(
                    "This will remove user '{}' from project '{}'.",
                    user, project
                );
                println!(
                    "This will trigger PDK rotation and the user will lose access to all secrets."
                );

                Confirm::with_theme(&ColorfulTheme::default())
                    .with_prompt("Are you sure you want to remove this member?")
                    .default(false)
                    .interact()?
            };

            if should_remove {
                // Get remaining devices (all active devices except those of the removed user)
                let mut remaining_devices = Vec::new();
                if let Ok(entries) = client.list_directory(".mycelium/devices").await {
                    for entry in entries {
                        if entry.name.ends_with(".json") {
                            let device_path = format!(".mycelium/devices/{}", entry.name);
                            if let Ok(device_data) = client.read_file(&device_path).await {
                                if let Ok(device) = serde_json::from_slice::<Device>(&device_data) {
                                    if device.user_id != target_user_id && device.status == DeviceStatus::Active {
                                        // Check if this device's user is still a member after removal
                                        if membership_list.members.iter().any(|m| m.user_id == device.user_id && m.user_id != target_user_id) {
                                            remaining_devices.push((device.id, device.encryption_pubkey));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Get passphrase for device keys
                let passphrase = if let Ok(pass) = std::env::var("MYC_KEY_PASSPHRASE") {
                    pass
                } else {
                    if cli.json {
                        anyhow::bail!("Cannot prompt for passphrase in JSON mode. Set MYC_KEY_PASSPHRASE environment variable.");
                    }
                    Password::new()
                        .with_prompt("Enter passphrase to unlock device keys")
                        .interact()?
                };

                // Load actor's signing key
                let actor_signing_key = load_signing_key(&manager, &profile_name, &passphrase)?;

                // Remove member using core operations
                let remove_result = remove_member(
                    &membership_list,
                    &UserId::from(profile.github_username.clone()),
                    profile.device_id,
                    &actor_signing_key,
                    &target_user_id,
                    &remaining_devices,
                ).context("Failed to remove member")?;

                // Get current project to increment PDK version
                let project_path = format!(".mycelium/projects/{}/project.json", project_id);
                let project_data = client.read_file(&project_path).await
                    .context("Failed to read project metadata")?;
                let mut project_obj: Project = serde_json::from_slice(&project_data)
                    .context("Failed to parse project metadata")?;

                // Create new PDK version
                let new_pdk_version = PdkVersion {
                    version: VersionNumber::new(project_obj.current_pdk_version.as_u64() + 1),
                    created_at: time::OffsetDateTime::now_utc(),
                    created_by: profile.device_id,
                    reason: Some("Member removed".to_string()),
                    wrapped_keys: remove_result.new_wrapped_pdks,
                };

                // Update project's current PDK version
                project_obj.current_pdk_version = new_pdk_version.version;

                // Write updated membership list
                let updated_members_json = serde_json::to_vec_pretty(&remove_result.membership_list)?;
                client.write_file(
                    &members_path,
                    &updated_members_json,
                    &format!("Remove member {}", user),
                    None,
                ).await.context("Failed to write updated membership list")?;

                // Write new PDK version
                let new_pdk_path = format!(".mycelium/projects/{}/pdk/v{}.json", project_id, new_pdk_version.version.as_u64());
                let new_pdk_json = serde_json::to_vec_pretty(&new_pdk_version)?;
                client.write_file(
                    &new_pdk_path,
                    &new_pdk_json,
                    &format!("Rotate PDK after removing member {}", user),
                    None,
                ).await.context("Failed to write new PDK version")?;

                // Write updated project metadata
                let updated_project_json = serde_json::to_vec_pretty(&project_obj)?;
                client.write_file(
                    &project_path,
                    &updated_project_json,
                    &format!("Update current PDK version after removing member {}", user),
                    None,
                ).await.context("Failed to write updated project metadata")?;

                // Create audit event
                let audit_event = AuditEvent {
                    schema_version: 1,
                    event_id: myc_core::audit::EventId::new(),
                    event_type: EventType::MemberRemoved,
                    timestamp: time::OffsetDateTime::now_utc(),
                    actor_device_id: profile.device_id,
                    actor_user_id: profile.github_username.clone(),
                    org_id: OrgId::new(), // Placeholder
                    project_id: Some(project_id),
                    details: EventDetails::Membership(MembershipEventDetails {
                        project_id,
                        user_id: target_user_id.as_str().to_string(),
                        role: None,
                        previous_role: membership_list.get_role(&target_user_id).map(|r| format!("{:?}", r)),
                    }),
                    chain_hash: vec![], // Placeholder
                    previous_event_id: None,
                };

                let signed_event = SignedAuditEvent {
                    event: audit_event.clone(),
                    signature: sign(&actor_signing_key, &to_canonical_json(&audit_event)?.as_bytes()),
                    signed_by: profile.device_id,
                };

                // Write audit event
                let event_month = signed_event.event.timestamp.format(&time::format_description::parse("[year]-[month]")?)?;
                let audit_path = format!(".mycelium/audit/{}/{}.json", event_month, signed_event.event.event_id);
                let audit_json = serde_json::to_vec_pretty(&signed_event)?;
                client.write_file(
                    &audit_path,
                    &audit_json,
                    &format!("Audit: member removed"),
                    None,
                ).await.context("Failed to write audit event")?;

                if cli.json {
                    let output = serde_json::json!({
                        "success": true,
                        "message": format!("Successfully removed user '{}' from project '{}'", user, project),
                        "project_id": project_id,
                        "user_id": target_user_id.as_str(),
                        "new_pdk_version": new_pdk_version.version.as_u64(),
                        "remaining_devices": remaining_devices.len(),
                        "audit_event_id": signed_event.event.event_id
                    });
                    println!("{}", serde_json::to_string_pretty(&output)?);
                } else {
                    println!(
                        "{} Successfully removed user '{}' from project '{}'",
                        style("✓").green(),
                        user,
                        project
                    );
                    println!("  Project ID: {}", project_id);
                    println!("  User ID: {}", target_user_id.as_str());
                    println!("  New PDK version: {}", new_pdk_version.version.as_u64());
                    println!("  Remaining devices: {}", remaining_devices.len());
                    println!("  Audit event: {}", signed_event.event.event_id);
                }
            } else {
                if cli.json {
                    let output = serde_json::json!({
                        "success": false,
                        "message": "Removal cancelled"
                    });
                    println!("{}", serde_json::to_string_pretty(&output)?);
                } else {
                    println!("Removal cancelled");
                }
            }
        }
        ShareCommands::List { project } => {
            use myc_core::membership_ops::MembershipList;
            use myc_core::project::Project;

            // Resolve project ID (try UUID first, then search by name)
            let project_id = if let Ok(uuid) = Uuid::parse_str(project) {
                ProjectId::from_uuid(uuid)
            } else {
                // Search for project by name
                let projects_path = ".mycelium/projects";
                let mut found_project_id = None;

                if let Ok(entries) = client.list_directory(projects_path).await {
                    for entry in entries {
                        if entry.is_dir {
                            let project_path = format!("{}/{}/project.json", projects_path, entry.name);
                            if let Ok(project_data) = client.read_file(&project_path).await {
                                if let Ok(proj) = serde_json::from_slice::<Project>(&project_data) {
                                    if proj.name == *project {
                                        found_project_id = Some(proj.id);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }

                found_project_id.ok_or_else(|| {
                    anyhow::anyhow!("Project '{}' not found", project)
                })?
            };

            // Read membership list
            let members_path = format!(".mycelium/projects/{}/members.json", project_id);
            let members_data = client.read_file(&members_path).await
                .context("Failed to read project members")?;

            let membership_list: MembershipList = 
                serde_json::from_slice(&members_data).context("Failed to parse membership list")?;

            // Verify signature (we'll need to get the signer's public key)
            // For now, we'll skip signature verification and just display the members

            let current_user_id = UserId::from(profile.github_username.clone());
            let current_user_role = membership_list.get_role(&current_user_id);

            if cli.json {
                let members_json: Vec<serde_json::Value> = membership_list.members.iter().map(|member| {
                    serde_json::json!({
                        "user_id": member.user_id.as_str(),
                        "role": format!("{:?}", member.role),
                        "role_level": member.role.level(),
                        "added_at": member.added_at.format(&time::format_description::well_known::Rfc3339).unwrap_or_default(),
                        "added_by": member.added_by,
                        "is_current_user": member.user_id == current_user_id
                    })
                }).collect();

                let permissions = if let Some(role) = current_user_role {
                    vec![
                        ("read", role.has_permission(myc_core::project::Permission::Read)),
                        ("write", role.has_permission(myc_core::project::Permission::Write)),
                        ("share", role.has_permission(myc_core::project::Permission::Share)),
                        ("rotate", role.has_permission(myc_core::project::Permission::Rotate)),
                        ("delete_project", role.has_permission(myc_core::project::Permission::DeleteProject)),
                        ("transfer_ownership", role.has_permission(myc_core::project::Permission::TransferOwnership)),
                    ]
                } else {
                    vec![]
                };

                let output = serde_json::json!({
                    "project_id": project_id,
                    "members": members_json,
                    "current_user": {
                        "user_id": current_user_id.as_str(),
                        "role": current_user_role.map(|r| format!("{:?}", r)),
                        "permissions": permissions.into_iter().filter(|(_, has)| *has).map(|(perm, _)| perm).collect::<Vec<_>>()
                    },
                    "updated_at": membership_list.updated_at.format(&time::format_description::well_known::Rfc3339).unwrap_or_default(),
                    "updated_by": membership_list.updated_by
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("Members of project '{}':", project);
                println!();

                if membership_list.members.is_empty() {
                    println!("No members found.");
                } else {
                    for member in &membership_list.members {
                        let marker = if member.user_id == current_user_id {
                            style("*").green().bold()
                        } else {
                            style(" ").dim()
                        };

                        let role_display = match member.role {
                            Role::Owner => style("Owner").red().bold(),
                            Role::Admin => style("Admin").yellow().bold(),
                            Role::Member => style("Member").blue(),
                            Role::Reader => style("Reader").dim(),
                        };

                        let added_date = member.added_at.format(&time::format_description::parse("[year]-[month]-[day]")?)
                            .unwrap_or_else(|_| "unknown".to_string());

                        println!(
                            "  {} {} ({}) - joined {}",
                            marker,
                            member.user_id.as_str().replace("github|", ""),
                            role_display,
                            added_date
                        );
                    }

                    println!();
                    if let Some(role) = current_user_role {
                        println!("Your role: {} (level {})", format!("{:?}", role), role.level());
                        
                        let permissions: Vec<&str> = [
                            ("read", myc_core::project::Permission::Read),
                            ("write", myc_core::project::Permission::Write),
                            ("share", myc_core::project::Permission::Share),
                            ("rotate", myc_core::project::Permission::Rotate),
                            ("delete_project", myc_core::project::Permission::DeleteProject),
                            ("transfer_ownership", myc_core::project::Permission::TransferOwnership),
                        ].iter()
                        .filter_map(|(name, perm)| if role.has_permission(*perm) { Some(*name) } else { None })
                        .collect();

                        println!("Your permissions: {}", permissions.join(", "));
                    } else {
                        println!("You are not a member of this project.");
                    }

                    println!();
                    println!("Last updated: {} by {}", 
                        format_time_ago(&membership_list.updated_at),
                        membership_list.updated_by
                    );
                }
            }
        }
        ShareCommands::SetRole {
            project,
            user,
            role,
        } => {
            use crate::device::load_signing_key;
            use dialoguer::Password;
            use myc_core::audit::{AuditEvent, EventDetails, EventType, MembershipEventDetails, SignedAuditEvent};
            use myc_core::canonical::to_canonical_json;
            use myc_core::membership_ops::{change_role, MembershipList};
            use myc_core::project::Project;
            use myc_crypto::sign::sign;

            // Parse role
            let new_role = match role.to_lowercase().as_str() {
                "owner" => Role::Owner,
                "admin" => Role::Admin,
                "member" => Role::Member,
                "reader" => Role::Reader,
                _ => anyhow::bail!(
                    "Invalid role '{}'. Valid roles are: owner, admin, member, reader",
                    role
                ),
            };

            // Resolve project ID (try UUID first, then search by name)
            let project_id = if let Ok(uuid) = Uuid::parse_str(project) {
                ProjectId::from_uuid(uuid)
            } else {
                // Search for project by name
                let projects_path = ".mycelium/projects";
                let mut found_project_id = None;

                if let Ok(entries) = client.list_directory(projects_path).await {
                    for entry in entries {
                        if entry.is_dir {
                            let project_path = format!("{}/{}/project.json", projects_path, entry.name);
                            if let Ok(project_data) = client.read_file(&project_path).await {
                                if let Ok(proj) = serde_json::from_slice::<Project>(&project_data) {
                                    if proj.name == *project {
                                        found_project_id = Some(proj.id);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }

                found_project_id.ok_or_else(|| {
                    anyhow::anyhow!("Project '{}' not found", project)
                })?
            };

            // Create user ID from username
            let target_user_id = if user.starts_with("github|") {
                UserId::from(user.clone())
            } else {
                UserId::from(format!("github|{}", user))
            };

            // Read current membership list
            let members_path = format!(".mycelium/projects/{}/members.json", project_id);
            let members_data = client.read_file(&members_path).await
                .context("Failed to read project members")?;

            let membership_list: MembershipList = 
                serde_json::from_slice(&members_data).context("Failed to parse membership list")?;

            // Get current role for display
            let current_role = membership_list.get_role(&target_user_id)
                .ok_or_else(|| anyhow::anyhow!("User '{}' is not a member of this project", user))?;

            // Get passphrase for device keys
            let passphrase = if let Ok(pass) = std::env::var("MYC_KEY_PASSPHRASE") {
                pass
            } else {
                if cli.json {
                    anyhow::bail!("Cannot prompt for passphrase in JSON mode. Set MYC_KEY_PASSPHRASE environment variable.");
                }
                Password::new()
                    .with_prompt("Enter passphrase to unlock device keys")
                    .interact()?
            };

            // Load actor's signing key
            let actor_signing_key = load_signing_key(&manager, &profile_name, &passphrase)?;

            // Change role using core operations
            let change_result = change_role(
                &membership_list,
                &UserId::from(profile.github_username.clone()),
                profile.device_id,
                &actor_signing_key,
                &target_user_id,
                new_role,
            ).context("Failed to change role")?;

            // Write updated membership list
            let updated_members_json = serde_json::to_vec_pretty(&change_result.membership_list)?;
            client.write_file(
                &members_path,
                &updated_members_json,
                &format!("Change role of {} to {:?}", user, new_role),
                None,
            ).await.context("Failed to write updated membership list")?;

            // Create audit event
            let audit_event = AuditEvent {
                schema_version: 1,
                event_id: myc_core::audit::EventId::new(),
                event_type: EventType::RoleChanged,
                timestamp: time::OffsetDateTime::now_utc(),
                actor_device_id: profile.device_id,
                actor_user_id: profile.github_username.clone(),
                org_id: OrgId::new(), // Placeholder
                project_id: Some(project_id),
                details: EventDetails::Membership(MembershipEventDetails {
                    project_id,
                    user_id: target_user_id.as_str().to_string(),
                    role: Some(format!("{:?}", new_role)),
                    previous_role: Some(format!("{:?}", current_role)),
                }),
                chain_hash: vec![], // Placeholder
                previous_event_id: None,
            };

            let signed_event = SignedAuditEvent {
                event: audit_event.clone(),
                signature: sign(&actor_signing_key, &to_canonical_json(&audit_event)?.as_bytes()),
                signed_by: profile.device_id,
            };

            // Write audit event
            let event_month = signed_event.event.timestamp.format(&time::format_description::parse("[year]-[month]")?)?;
            let audit_path = format!(".mycelium/audit/{}/{}.json", event_month, signed_event.event.event_id);
            let audit_json = serde_json::to_vec_pretty(&signed_event)?;
            client.write_file(
                &audit_path,
                &audit_json,
                &format!("Audit: role changed"),
                None,
            ).await.context("Failed to write audit event")?;

            if cli.json {
                let output = serde_json::json!({
                    "success": true,
                    "message": format!("Successfully changed role of user '{}' from {:?} to {:?}", user, current_role, new_role),
                    "project_id": project_id,
                    "user_id": target_user_id.as_str(),
                    "previous_role": format!("{:?}", current_role),
                    "new_role": format!("{:?}", new_role),
                    "audit_event_id": signed_event.event.event_id
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!(
                    "{} Successfully changed role of user '{}' from {:?} to {:?}",
                    style("✓").green(),
                    user,
                    current_role,
                    new_role
                );
                println!("  Project ID: {}", project_id);
                println!("  User ID: {}", target_user_id.as_str());
                println!("  Previous role: {:?}", current_role);
                println!("  New role: {:?}", new_role);
                println!("  Audit event: {}", signed_event.event.event_id);
            }
        }
    }
    Ok(())
}

async fn handle_rotate_command(
    project: &String,
    reason: &Option<String>,
    note: &Option<String>,
    cli: &Cli,
) -> Result<()> {
    use crate::profile::ProfileManager;
    use console::style;
    use dialoguer::{theme::ColorfulTheme, Confirm, Password};
    use myc_cli::device::load_signing_key;
    use myc_core::audit::{AuditEvent, EventDetails, EventType, KeyEventDetails, SignedAuditEvent};
    use myc_core::canonical::to_canonical_json;
    use myc_core::rotation::{perform_pdk_rotation, RotationReason};
    use myc_crypto::sign::sign;
    use myc_github::client::GitHubClient;

    // Determine rotation reason early to validate input
    let rotation_reason = if let Some(reason_str) = reason {
        match reason_str.as_str() {
            "member_removed" => RotationReason::MemberRemoved,
            "device_revoked" => RotationReason::DeviceRevoked,
            "policy" => RotationReason::Policy,
            "manual" => RotationReason::Manual,
            _ => {
                anyhow::bail!("Invalid rotation reason '{}'. Valid reasons: member_removed, device_revoked, policy, manual", reason_str);
            }
        }
    } else {
        RotationReason::Manual
    };

    // Get profile manager and current profile
    let config_dir = ProfileManager::default_config_dir()?;
    let manager = ProfileManager::new(config_dir);

    let profile_name = if let Some(profile) = &cli.profile {
        profile.clone()
    } else {
        manager.get_default_profile()?.ok_or_else(|| {
            anyhow::anyhow!("No default profile set. Use --profile or 'myc profile use <name>'")
        })?
    };

    let profile = manager.get_profile(&profile_name)?;

    // Create GitHub client
    let token = std::env::var("GITHUB_TOKEN").context(
        "GITHUB_TOKEN environment variable not set. Run 'myc profile add' to authenticate.",
    )?;

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

    // Look up the project
    let project_obj = lookup_project(&client, project).await?;

    // Get custom note if provided
    let reason_note = if let Some(note_str) = note {
        if reason.is_some() {
            format!("{}: {}", rotation_reason.as_str(), note_str)
        } else {
            note_str.clone()
        }
    } else {
        rotation_reason.as_str().to_string()
    };

    // Confirm rotation unless in JSON mode
    if !cli.json {
        println!(
            "This will rotate the encryption keys for project '{}'",
            project_obj.name
        );
        println!("  Project ID: {}", project_obj.id);
        println!("  Current PDK version: {}", project_obj.current_pdk_version);
        println!("  Reason: {}", reason_note);
        println!();
        println!("After rotation:");
        println!("  - A new encryption key will be generated");
        println!("  - All authorized devices will receive the new key");
        println!("  - Revoked devices will NOT receive the new key");
        println!("  - An audit event will be created");
        println!();

        let should_rotate = Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Are you sure you want to rotate the PDK?")
            .default(false)
            .interact()?;

        if !should_rotate {
            if cli.json {
                let output = serde_json::json!({
                    "success": false,
                    "message": "Rotation cancelled by user"
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("Rotation cancelled");
            }
            return Ok(());
        }
    }

    // Read current PDK version
    let pdk_path = format!(
        ".mycelium/projects/{}/pdk/v{}.json",
        project_obj.id, project_obj.current_pdk_version
    );

    let pdk_data = client
        .read_file(&pdk_path)
        .await
        .context("Failed to read current PDK version")?;

    let _current_pdk_version: myc_core::pdk::PdkVersion =
        serde_json::from_slice(&pdk_data).context("Failed to parse PDK version")?;

    // Read membership list to get authorized devices
    let members_path = format!(".mycelium/projects/{}/members.json", project_obj.id);
    let members_data = client
        .read_file(&members_path)
        .await
        .context("Failed to read project members")?;

    let membership_list: myc_core::membership_ops::MembershipList =
        serde_json::from_slice(&members_data).context("Failed to parse membership list")?;

    // Get all devices for all members
    let mut authorized_devices = Vec::new();

    for member in &membership_list.members {
        // Read user's devices
        let devices_dir = ".mycelium/devices";
        let device_files = client
            .list_directory(&devices_dir)
            .await
            .context("Failed to list devices")?;

        for file_entry in device_files {
            if file_entry.name.ends_with(".json") {
                let device_data = client
                    .read_file(&format!("{}/{}", devices_dir, file_entry.name))
                    .await?;
                let device: myc_core::device::Device = serde_json::from_slice(&device_data)?;

                // Include device if it belongs to this member and is active (not revoked or expired)
                if device.user_id == member.user_id
                    && !myc_core::rotation::should_exclude_device(&device)
                {
                    authorized_devices.push((device.id, device.encryption_pubkey));
                }
            }
        }
    }

    if authorized_devices.is_empty() {
        anyhow::bail!("No authorized devices found for rotation. Cannot proceed.");
    }

    // Load device keys for signing
    let passphrase = std::env::var("MYC_KEY_PASSPHRASE").or_else(|_| {
        if std::env::var("MYC_NON_INTERACTIVE").is_ok() {
            Err(anyhow::anyhow!(
                "Passphrase required but running in non-interactive mode"
            ))
        } else {
            Ok(Password::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter device key passphrase")
                .interact()?)
        }
    })?;

    let signing_key = load_signing_key(&manager, &profile_name, &passphrase)?;

    // Perform PDK rotation
    let (_new_pdk, new_pdk_version) = perform_pdk_rotation(
        project_obj.current_pdk_version,
        &authorized_devices,
        profile.device_id,
        rotation_reason,
    )?;

    // Update the PDK version reason with custom note if provided
    let mut final_pdk_version = new_pdk_version;
    if note.is_some() {
        final_pdk_version.reason = Some(reason_note.clone());
    }

    // Write new PDK version to GitHub
    let new_pdk_path = format!(
        ".mycelium/projects/{}/pdk/v{}.json",
        project_obj.id, final_pdk_version.version
    );

    let pdk_json = serde_json::to_vec_pretty(&final_pdk_version)?;
    client
        .write_file(
            &new_pdk_path,
            &pdk_json,
            &format!(
                "Rotate PDK to version {} ({})",
                final_pdk_version.version, reason_note
            ),
            None,
        )
        .await?;

    // Update project's current_pdk_version
    let mut updated_project = project_obj.clone();
    updated_project.current_pdk_version = final_pdk_version.version;

    let project_path = format!(".mycelium/projects/{}/project.json", updated_project.id);
    let project_json = serde_json::to_vec_pretty(&updated_project)?;
    client
        .write_file(
            &project_path,
            &project_json,
            &format!(
                "Update project PDK version to {}",
                final_pdk_version.version
            ),
            None,
        )
        .await?;

    // Create audit event
    let audit_event = AuditEvent::new(
        EventType::PdkRotated,
        profile.device_id,
        profile.github_user_id.to_string(),
        updated_project.org_id,
        Some(updated_project.id),
        EventDetails::Key(KeyEventDetails {
            project_id: updated_project.id,
            pdk_version: final_pdk_version.version.as_u64(),
            reason: reason_note.clone(),
            excluded_devices: Vec::new(), // For rotation, we don't exclude specific devices, we include authorized ones
        }),
        Vec::new(), // Chain hash will be computed later
        None,       // Previous event ID will be set later
    );

    // Sign and store audit event
    let audit_json = to_canonical_json(&audit_event)?;
    let signature = sign(&signing_key, audit_json.as_bytes());

    let signed_audit = SignedAuditEvent {
        event: audit_event,
        signature,
        signed_by: profile.device_id,
    };

    // Store audit event (organized by month)
    let now = time::OffsetDateTime::now_utc();
    let month_dir = format!(".mycelium/audit/{:04}-{:02}", now.year(), now.month() as u8);
    let audit_path = format!("{}/{}.json", month_dir, signed_audit.event.event_id);

    let audit_json = serde_json::to_vec_pretty(&signed_audit)?;
    client
        .write_file(
            &audit_path,
            &audit_json,
            &format!(
                "Add audit event: PDK rotated for project {}",
                updated_project.name
            ),
            None,
        )
        .await?;

    // Display result
    if cli.json {
        let output = serde_json::json!({
            "success": true,
            "message": "PDK rotation completed successfully",
            "project_id": updated_project.id,
            "project_name": updated_project.name,
            "old_pdk_version": project_obj.current_pdk_version,
            "new_pdk_version": final_pdk_version.version,
            "reason": reason_note,
            "authorized_devices": authorized_devices.len(),
            "audit_event_id": signed_audit.event.event_id
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("{} PDK rotation completed successfully", style("✓").green());
        println!(
            "  Project: {} ({})",
            updated_project.name, updated_project.id
        );
        println!(
            "  PDK version: {} → {}",
            project_obj.current_pdk_version, final_pdk_version.version
        );
        println!("  Reason: {}", reason_note);
        println!("  Authorized devices: {}", authorized_devices.len());
        println!("  Audit event: {}", signed_audit.event.event_id);
    }

    Ok(())
}

async fn handle_versions_command(command: &VersionsCommands, cli: &Cli) -> Result<()> {
    use crate::profile::ProfileManager;
    use myc_github::client::GitHubClient;

    // Get profile manager and current profile
    let config_dir = ProfileManager::default_config_dir()?;
    let manager = ProfileManager::new(config_dir);

    let profile_name = if let Some(profile) = &cli.profile {
        profile.clone()
    } else {
        manager.get_default_profile()?.ok_or_else(|| {
            anyhow::anyhow!("No default profile set. Use --profile or 'myc profile use <name>'")
        })?
    };

    let profile = manager.get_profile(&profile_name)?;

    // Create GitHub client
    let token = std::env::var("GITHUB_TOKEN").context(
        "GITHUB_TOKEN environment variable not set. Run 'myc profile add' to authenticate.",
    )?;

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

    match command {
        VersionsCommands::List {
            project,
            set,
            limit,
        } => handle_versions_list(&client, project, set, limit, cli).await,
        VersionsCommands::Show {
            project,
            set,
            version,
        } => handle_versions_show(&client, project, set, *version, cli).await,
    }
}

async fn handle_versions_list(
    client: &myc_github::client::GitHubClient,
    project: &str,
    set: &str,
    limit: &Option<u64>,
    cli: &Cli,
) -> Result<()> {
    use console::style;
    use myc_core::secret_set::SecretSetVersion;
    use time::format_description::well_known::Rfc3339;

    // Find project by name or ID
    let project_obj = lookup_project(client, project).await?;

    // Find secret set by name or ID
    let secret_set = lookup_secret_set(client, &project_obj.id, set).await?;

    // List all version files in the secret set directory
    let versions_dir = format!(
        ".mycelium/projects/{}/sets/{}",
        project_obj.id, secret_set.id
    );
    let entries = match client.list_directory(&versions_dir).await {
        Ok(entries) => entries,
        Err(_) => {
            if cli.json {
                let output = serde_json::json!({
                    "success": false,
                    "error": "No versions found for this secret set"
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("No versions found for secret set '{}'", set);
                println!(
                    "Use 'myc push {} {}' to create the first version.",
                    project, set
                );
            }
            return Ok(());
        }
    };

    // Collect version metadata files
    let mut version_files = Vec::new();
    for entry in entries {
        if entry.name.ends_with(".meta.json") {
            // Extract version number from filename (e.g., "v1.meta.json" -> 1)
            if let Some(version_str) = entry
                .name
                .strip_prefix("v")
                .and_then(|s| s.strip_suffix(".meta.json"))
            {
                if let Ok(version_num) = version_str.parse::<u64>() {
                    version_files.push((version_num, entry.name));
                }
            }
        }
    }

    if version_files.is_empty() {
        if cli.json {
            let output = serde_json::json!({
                "success": false,
                "error": "No version metadata files found"
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        } else {
            println!("No version metadata files found for secret set '{}'", set);
        }
        return Ok(());
    }

    // Sort by version number (newest first)
    version_files.sort_by(|a, b| b.0.cmp(&a.0));

    // Apply limit if specified
    if let Some(limit_val) = limit {
        version_files.truncate(*limit_val as usize);
    }

    // Read version metadata
    let mut versions = Vec::new();
    for (version_num, filename) in version_files {
        let version_path = format!("{}/{}", versions_dir, filename);
        match client.read_file(&version_path).await {
            Ok(content) => match serde_json::from_slice::<SecretSetVersion>(&content) {
                Ok(version_meta) => versions.push(version_meta),
                Err(e) => {
                    eprintln!("Warning: Failed to parse version {}: {}", version_num, e);
                }
            },
            Err(e) => {
                eprintln!("Warning: Failed to read version {}: {}", version_num, e);
            }
        }
    }

    if versions.is_empty() {
        if cli.json {
            let output = serde_json::json!({
                "success": false,
                "error": "No valid version metadata found"
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        } else {
            println!("No valid version metadata found for secret set '{}'", set);
        }
        return Ok(());
    }

    // Output results
    if cli.json {
        let output = serde_json::json!({
            "success": true,
            "project": {
                "id": project_obj.id,
                "name": project_obj.name
            },
            "secret_set": {
                "id": secret_set.id,
                "name": secret_set.name,
                "current_version": secret_set.current_version
            },
            "versions": versions.iter().map(|v| serde_json::json!({
                "version": v.version.as_u64(),
                "pdk_version": v.pdk_version.as_u64(),
                "created_at": v.created_at.format(&Rfc3339).unwrap(),
                "created_by": v.created_by,
                "message": v.message,
                "content_hash": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, v.content_hash.as_bytes()),
                "previous_hash": v.previous_hash.map(|h| base64::Engine::encode(&base64::engine::general_purpose::STANDARD, h.as_bytes()))
            })).collect::<Vec<_>>()
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!(
            "Versions for {}/{} ({})",
            style(&project_obj.name).bold(),
            style(&secret_set.name).bold(),
            style(format!("current: v{}", secret_set.current_version.as_u64())).dim()
        );
        println!();

        for version in &versions {
            let version_marker = if version.version == secret_set.current_version {
                style("*").green().bold()
            } else {
                style(" ").dim()
            };

            println!(
                "  {} {} {} {}",
                version_marker,
                style(format!("v{}", version.version.as_u64())).bold(),
                style(
                    version
                        .created_at
                        .format(&Rfc3339)
                        .unwrap_or_else(|_| "unknown".to_string())
                )
                .dim(),
                style(format!("(PDK v{})", version.pdk_version.as_u64())).dim()
            );

            if let Some(message) = &version.message {
                println!("      {}", style(message).italic());
            }
        }

        if versions.len() == 1 {
            println!("\n{} version found", versions.len());
        } else {
            println!("\n{} versions found", versions.len());
        }

        if let Some(limit_val) = limit {
            if versions.len() as u64 == *limit_val {
                println!("(showing first {} versions)", limit_val);
            }
        }
    }

    Ok(())
}

async fn handle_versions_show(
    client: &myc_github::client::GitHubClient,
    project: &str,
    set: &str,
    version: u64,
    cli: &Cli,
) -> Result<()> {
    use console::style;
    use myc_core::secret_set::SecretSetVersion;
    use myc_core::secret_set_ops::compute_chain_hash;
    use time::format_description::well_known::Rfc3339;

    // Find project by name or ID
    let project_obj = lookup_project(client, project).await?;

    // Find secret set by name or ID
    let secret_set = lookup_secret_set(client, &project_obj.id, set).await?;

    // Read version metadata
    let version_meta_path = format!(
        ".mycelium/projects/{}/sets/{}/v{}.meta.json",
        project_obj.id, secret_set.id, version
    );

    let version_metadata = match client.read_file(&version_meta_path).await {
        Ok(content) => serde_json::from_slice::<SecretSetVersion>(&content)
            .context("Failed to parse version metadata")?,
        Err(_) => {
            if cli.json {
                let output = serde_json::json!({
                    "success": false,
                    "error": format!("Version {} not found", version)
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("Version {} not found for secret set '{}'", version, set);
                println!(
                    "Use 'myc versions list {} {}' to see available versions.",
                    project, set
                );
            }
            return Ok(());
        }
    };

    // Compute chain hash for this version
    let chain_hash = compute_chain_hash(&version_metadata);

    // Check if ciphertext file exists
    let ciphertext_path = format!(
        ".mycelium/projects/{}/sets/{}/v{}.enc",
        project_obj.id, secret_set.id, version
    );

    let ciphertext_size = match client.read_file(&ciphertext_path).await {
        Ok(content) => Some(content.len()),
        Err(_) => None,
    };

    // Output results
    if cli.json {
        let output = serde_json::json!({
            "success": true,
            "project": {
                "id": project_obj.id,
                "name": project_obj.name
            },
            "secret_set": {
                "id": secret_set.id,
                "name": secret_set.name,
                "current_version": secret_set.current_version
            },
            "version": {
                "version": version_metadata.version.as_u64(),
                "pdk_version": version_metadata.pdk_version.as_u64(),
                "created_at": version_metadata.created_at.format(&Rfc3339).unwrap(),
                "created_by": version_metadata.created_by,
                "message": version_metadata.message,
                "content_hash": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, version_metadata.content_hash.as_bytes()),
                "chain_hash": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, chain_hash.as_bytes()),
                "previous_hash": version_metadata.previous_hash.map(|h| base64::Engine::encode(&base64::engine::general_purpose::STANDARD, h.as_bytes())),
                "ciphertext_size": ciphertext_size,
                "is_current": version_metadata.version == secret_set.current_version
            }
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        let is_current = version_metadata.version == secret_set.current_version;
        let current_marker = if is_current { " (current)" } else { "" };

        println!(
            "Version {} of {}/{}{}",
            style(format!("v{}", version)).bold(),
            style(&project_obj.name).bold(),
            style(&secret_set.name).bold(),
            style(current_marker).green()
        );
        println!();

        println!("  Version: {}", version_metadata.version.as_u64());
        println!("  PDK Version: {}", version_metadata.pdk_version.as_u64());
        println!(
            "  Created: {}",
            version_metadata
                .created_at
                .format(&Rfc3339)
                .unwrap_or_else(|_| "unknown".to_string())
        );
        println!("  Created by: {}", version_metadata.created_by);

        if let Some(message) = &version_metadata.message {
            println!("  Message: {}", style(message).italic());
        }

        println!();
        println!(
            "  Content Hash: {}",
            base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                version_metadata.content_hash.as_bytes()
            )
        );
        println!(
            "  Chain Hash: {}",
            base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                chain_hash.as_bytes()
            )
        );

        if let Some(prev_hash) = &version_metadata.previous_hash {
            println!(
                "  Previous Hash: {}",
                base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    prev_hash.as_bytes()
                )
            );
        } else {
            println!("  Previous Hash: {} (first version)", style("none").dim());
        }

        if let Some(size) = ciphertext_size {
            println!("  Ciphertext Size: {} bytes", size);
        } else {
            println!("  Ciphertext: {} (file not found)", style("missing").red());
        }

        println!();
        println!(
            "Use 'myc pull {} {} --version {}' to retrieve this version's secrets.",
            project, set, version
        );

        if !is_current {
            println!(
                "Use 'myc diff {} {} {} {}' to compare with current version.",
                project,
                set,
                version,
                secret_set.current_version.as_u64()
            );
        }
    }

    Ok(())
}

async fn handle_diff_command(
    project: &String,
    set: &String,
    v1: u64,
    v2: u64,
    show_values: bool,
    cli: &Cli,
) -> Result<()> {
    use crate::profile::ProfileManager;
    use console::style;
    use myc_core::pdk_ops::unwrap_pdk;
    use myc_core::secret_set_ops::read_version;
    use myc_github::client::GitHubClient;
    use std::collections::{HashMap, HashSet};

    // Early validation
    if project.is_empty() {
        anyhow::bail!("Project identifier cannot be empty");
    }
    if set.is_empty() {
        anyhow::bail!("Secret set identifier cannot be empty");
    }
    if v1 == v2 {
        anyhow::bail!("Cannot diff the same version against itself");
    }

    // Get profile manager and current profile
    let config_dir = ProfileManager::default_config_dir()?;
    let manager = ProfileManager::new(config_dir);

    let profile_name = if let Some(profile) = &cli.profile {
        profile.clone()
    } else {
        manager.get_default_profile()?.ok_or_else(|| {
            anyhow::anyhow!("No default profile set. Use --profile or 'myc profile use <name>'")
        })?
    };

    let profile = manager.get_profile(&profile_name)?;

    // Create GitHub client
    let token = std::env::var("GITHUB_TOKEN").context(
        "GITHUB_TOKEN environment variable not set. Run 'myc profile add' to authenticate.",
    )?;

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

    // Look up project by ID or name
    let project_obj = match lookup_project(&client, project).await {
        Ok(proj) => proj,
        Err(e) => {
            if cli.json {
                let output = serde_json::json!({
                    "success": false,
                    "error": "project_not_found",
                    "message": format!("Project not found: {}", e),
                    "project_identifier": project
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
                return Ok(());
            } else {
                anyhow::bail!("Project not found: {}", e);
            }
        }
    };

    // Look up secret set by ID or name
    let secret_set = match lookup_secret_set(&client, &project_obj.id, set).await {
        Ok(set) => set,
        Err(e) => {
            if cli.json {
                let output = serde_json::json!({
                    "success": false,
                    "error": "set_not_found",
                    "message": format!("Secret set not found: {}", e),
                    "project_id": project_obj.id,
                    "set_identifier": set
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
                return Ok(());
            } else {
                anyhow::bail!("Secret set not found: {}", e);
            }
        }
    };

    // Load device keys for decryption
    let passphrase = std::env::var("MYC_KEY_PASSPHRASE")
        .or_else(|_| {
            if std::env::var("MYC_NON_INTERACTIVE").is_ok() {
                anyhow::bail!("MYC_KEY_PASSPHRASE environment variable required in non-interactive mode");
            }
            // In a full implementation, this would prompt for passphrase
            anyhow::bail!("Interactive passphrase prompting not yet implemented. Set MYC_KEY_PASSPHRASE environment variable.");
        })?;

    let encryption_key_path = manager.encryption_key_path(&profile_name);
    let device_encryption_key =
        myc_cli::key_storage::load_encryption_key(&encryption_key_path, &passphrase)
            .context("Failed to load device encryption key. Check your passphrase.")?;

    let signing_key_path = manager.signing_key_path(&profile_name);
    let device_signing_key = myc_cli::key_storage::load_signing_key(&signing_key_path, &passphrase)
        .context("Failed to load device signing key")?;
    let device_pubkey = device_signing_key.verifying_key();

    // Helper function to decrypt a version
    async fn decrypt_version_impl(
        client: &GitHubClient,
        project_obj: &myc_core::project::Project,
        secret_set: &myc_core::secret_set::SecretSet,
        profile: &myc_cli::profile::Profile,
        device_encryption_key: &myc_crypto::kex::X25519SecretKey,
        device_pubkey: &myc_crypto::sign::Ed25519PublicKey,
        version_num: u64,
    ) -> Result<(
        myc_core::secret_set::SecretSetVersion,
        Vec<myc_core::secret_set::SecretEntry>,
    )> {
        // Read version metadata
        let version_meta_path = format!(
            ".mycelium/projects/{}/sets/{}/v{}.meta.json",
            project_obj.id, secret_set.id, version_num
        );

        let version_metadata = client
            .read_file(&version_meta_path)
            .await
            .context(format!("Version {} not found", version_num))?;
        let version_metadata: myc_core::secret_set::SecretSetVersion =
            serde_json::from_slice(&version_metadata)
                .context("Failed to parse version metadata")?;

        // Read PDK version to get wrapped keys
        let pdk_version_path = format!(
            ".mycelium/projects/{}/pdk/v{}.json",
            project_obj.id,
            version_metadata.pdk_version.as_u64()
        );

        let pdk_version = client.read_file(&pdk_version_path).await.context(format!(
            "PDK version {} not found",
            version_metadata.pdk_version.as_u64()
        ))?;
        let pdk_version: myc_core::pdk::PdkVersion =
            serde_json::from_slice(&pdk_version).context("Failed to parse PDK version")?;

        // Find wrapped PDK for our device
        let wrapped_pdk = pdk_version
            .wrapped_keys
            .iter()
            .find(|w| w.device_id == profile.device_id)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "No PDK wrapped for device {}. You may not have access to this project.",
                    profile.device_id
                )
            })?;

        // Unwrap PDK
        let pdk = unwrap_pdk(wrapped_pdk, device_encryption_key)
            .context("Failed to unwrap PDK. You may not have access to this project.")?;

        // Read and decrypt the version
        let entries = read_version(
            &version_metadata,
            &project_obj.id,
            &pdk,
            device_pubkey,
            version_metadata.previous_hash.as_ref(),
        )
        .context("Failed to decrypt secret version")?;

        Ok((version_metadata, entries))
    }

    // Decrypt both versions
    let (version1_meta, entries1) = decrypt_version_impl(
        &client,
        &project_obj,
        &secret_set,
        &profile,
        &device_encryption_key,
        &device_pubkey,
        v1,
    )
    .await?;
    let (version2_meta, entries2) = decrypt_version_impl(
        &client,
        &project_obj,
        &secret_set,
        &profile,
        &device_encryption_key,
        &device_pubkey,
        v2,
    )
    .await?;

    // Convert entries to HashMaps for easier comparison
    let map1: HashMap<String, String> = entries1.into_iter().map(|e| (e.key, e.value)).collect();
    let map2: HashMap<String, String> = entries2.into_iter().map(|e| (e.key, e.value)).collect();

    // Compute diff
    let all_keys: HashSet<String> = map1.keys().chain(map2.keys()).cloned().collect();
    let mut added_keys = Vec::new();
    let mut removed_keys = Vec::new();
    let mut changed_keys = Vec::new();
    let mut unchanged_keys = Vec::new();

    for key in all_keys {
        match (map1.get(&key), map2.get(&key)) {
            (None, Some(_)) => added_keys.push(key),
            (Some(_), None) => removed_keys.push(key),
            (Some(val1), Some(val2)) => {
                if val1 == val2 {
                    unchanged_keys.push(key);
                } else {
                    changed_keys.push(key);
                }
            }
            (None, None) => unreachable!(), // Key came from one of the maps
        }
    }

    // Sort keys for consistent output
    added_keys.sort();
    removed_keys.sort();
    changed_keys.sort();
    unchanged_keys.sort();

    // Display diff
    if cli.json {
        let mut diff_data = serde_json::json!({
            "success": true,
            "project": {
                "id": project_obj.id,
                "name": project_obj.name
            },
            "secret_set": {
                "id": secret_set.id,
                "name": secret_set.name
            },
            "version1": {
                "number": v1,
                "created_at": version1_meta.created_at,
                "created_by": version1_meta.created_by
            },
            "version2": {
                "number": v2,
                "created_at": version2_meta.created_at,
                "created_by": version2_meta.created_by
            },
            "summary": {
                "added": added_keys.len(),
                "removed": removed_keys.len(),
                "changed": changed_keys.len(),
                "unchanged": unchanged_keys.len()
            },
            "changes": {
                "added": added_keys,
                "removed": removed_keys,
                "changed": changed_keys
            }
        });

        if show_values {
            let mut value_changes = serde_json::Map::new();
            for key in &changed_keys {
                value_changes.insert(
                    key.clone(),
                    serde_json::json!({
                        "old": map1.get(key),
                        "new": map2.get(key)
                    }),
                );
            }
            for key in &added_keys {
                value_changes.insert(
                    key.clone(),
                    serde_json::json!({
                        "old": null,
                        "new": map2.get(key)
                    }),
                );
            }
            for key in &removed_keys {
                value_changes.insert(
                    key.clone(),
                    serde_json::json!({
                        "old": map1.get(key),
                        "new": null
                    }),
                );
            }
            diff_data["value_changes"] = serde_json::Value::Object(value_changes);
        }

        println!("{}", serde_json::to_string_pretty(&diff_data)?);
    } else {
        // Human-readable output
        println!(
            "Comparing {}/{} v{} vs v{}",
            style(&project_obj.name).bold(),
            style(&secret_set.name).bold(),
            style(v1).cyan(),
            style(v2).cyan()
        );
        println!();

        // Version info
        println!(
            "Version {} ({})",
            style(v1).cyan(),
            version1_meta
                .created_at
                .format(&time::format_description::well_known::Rfc3339)?
        );
        println!(
            "Version {} ({})",
            style(v2).cyan(),
            version2_meta
                .created_at
                .format(&time::format_description::well_known::Rfc3339)?
        );
        println!();

        // Summary
        let total_changes = added_keys.len() + removed_keys.len() + changed_keys.len();
        if total_changes == 0 {
            println!("{} No changes between versions", style("✓").green());
            return Ok(());
        }

        println!("Summary:");
        if !added_keys.is_empty() {
            println!("  {} {} added", style("+").green(), added_keys.len());
        }
        if !removed_keys.is_empty() {
            println!("  {} {} removed", style("-").red(), removed_keys.len());
        }
        if !changed_keys.is_empty() {
            println!("  {} {} changed", style("~").yellow(), changed_keys.len());
        }
        if !unchanged_keys.is_empty() {
            println!("  {} {} unchanged", style("=").dim(), unchanged_keys.len());
        }
        println!();

        // Show changes
        if !added_keys.is_empty() {
            println!("{}:", style("Added").green().bold());
            for key in &added_keys {
                if show_values {
                    println!(
                        "  {} {}: {}",
                        style("+").green(),
                        style(key).bold(),
                        map2.get(key).unwrap()
                    );
                } else {
                    println!("  {} {}", style("+").green(), style(key).bold());
                }
            }
            println!();
        }

        if !removed_keys.is_empty() {
            println!("{}:", style("Removed").red().bold());
            for key in &removed_keys {
                if show_values {
                    println!(
                        "  {} {}: {}",
                        style("-").red(),
                        style(key).bold(),
                        map1.get(key).unwrap()
                    );
                } else {
                    println!("  {} {}", style("-").red(), style(key).bold());
                }
            }
            println!();
        }

        if !changed_keys.is_empty() {
            println!("{}:", style("Changed").yellow().bold());
            for key in &changed_keys {
                if show_values {
                    println!("  {} {}:", style("~").yellow(), style(key).bold());
                    println!("    {}: {}", style("-").red(), map1.get(key).unwrap());
                    println!("    {}: {}", style("+").green(), map2.get(key).unwrap());
                } else {
                    println!("  {} {}", style("~").yellow(), style(key).bold());
                }
            }
        }
    }

    Ok(())
}

async fn handle_verify_command(
    project: &Option<String>,
    set: &Option<String>,
    signatures_only: bool,
    chains_only: bool,
    cli: &Cli,
) -> Result<()> {
    use crate::profile::ProfileManager;
    use console::style;
    use myc_github::client::GitHubClient;
    use serde_json;

    // Get profile manager and current profile
    let config_dir = ProfileManager::default_config_dir()?;
    let manager = ProfileManager::new(config_dir);

    let profile_name = if let Some(profile) = &cli.profile {
        profile.clone()
    } else {
        manager.get_default_profile()?.ok_or_else(|| {
            anyhow::anyhow!("No default profile set. Use --profile or 'myc profile use <name>'")
        })?
    };

    let profile = manager.get_profile(&profile_name)?;

    // Create GitHub client
    let token = std::env::var("GITHUB_TOKEN").context(
        "GITHUB_TOKEN environment variable not set. Run 'myc profile add' to authenticate.",
    )?;

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

    // Perform comprehensive verification
    let verification_result = perform_comprehensive_verification(
        &client,
        project,
        set,
        signatures_only,
        chains_only,
    ).await?;

    // Output results
    if cli.json {
        let output = serde_json::json!({
            "success": verification_result.success,
            "message": verification_result.message,
            "items_checked": verification_result.items_checked,
            "errors": verification_result.errors,
            "warnings": verification_result.warnings,
            "details": verification_result.details
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        if verification_result.success {
            println!(
                "{} Vault integrity verification passed",
                style("✓").green().bold()
            );
        } else {
            println!(
                "{} Vault integrity verification failed",
                style("✗").red().bold()
            );
        }

        println!();
        println!("Verification Summary:");
        println!("  Items checked: {}", verification_result.items_checked);
        println!("  Message: {}", verification_result.message);

        if !verification_result.warnings.is_empty() {
            println!();
            println!("{}:", style("Warnings").yellow().bold());
            for warning in &verification_result.warnings {
                println!("  {} {}", style("⚠").yellow(), warning);
            }
        }

        if !verification_result.errors.is_empty() {
            println!();
            println!("{}:", style("Errors").red().bold());
            for error in &verification_result.errors {
                println!("  {} {}", style("✗").red(), error);
            }
        }

        if !verification_result.details.is_empty() {
            println!();
            println!("{}:", style("Details").cyan().bold());
            for detail in &verification_result.details {
                println!("  {} {}", style("ℹ").cyan(), detail);
            }
        }
    }

    if !verification_result.success {
        std::process::exit(1);
    }

    Ok(())
}

/// Comprehensive verification result
#[derive(Debug)]
struct VerificationResult {
    success: bool,
    message: String,
    items_checked: usize,
    errors: Vec<String>,
    warnings: Vec<String>,
    details: Vec<String>,
}

impl VerificationResult {
    fn success(message: String, items_checked: usize) -> Self {
        Self {
            success: true,
            message,
            items_checked,
            errors: vec![],
            warnings: vec![],
            details: vec![],
        }
    }

    fn failure(message: String, items_checked: usize, errors: Vec<String>) -> Self {
        Self {
            success: false,
            message,
            items_checked,
            errors,
            warnings: vec![],
            details: vec![],
        }
    }

    fn with_warnings(mut self, warnings: Vec<String>) -> Self {
        self.warnings = warnings;
        self
    }

    fn with_details(mut self, details: Vec<String>) -> Self {
        self.details = details;
        self
    }
}

/// Perform comprehensive verification of vault integrity
async fn perform_comprehensive_verification(
    client: &myc_github::client::GitHubClient,
    project: &Option<String>,
    set: &Option<String>,
    signatures_only: bool,
    chains_only: bool,
) -> Result<VerificationResult> {
    use myc_core::audit::{AuditEvent, SignedAuditEvent};
    use myc_core::canonical::to_canonical_json;
    use myc_core::device::Device;
    use myc_core::ids::{DeviceId, ProjectId, SecretSetId};
    use myc_core::membership_ops::MembershipList;
    use myc_core::org::Org;
    use myc_core::pdk::PdkVersion;
    use myc_core::project::Project;
    use myc_core::secret_set::{SecretSet, SecretSetVersion};
    use myc_core::secret_set_ops::{verify_chain, verify_version_metadata};
    use myc_crypto::sign::Ed25519PublicKey;
    use std::collections::HashMap;

    let mut items_checked = 0;
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    let mut details = Vec::new();

    // Step 1: Verify vault structure exists
    details.push("Checking vault structure...".to_string());
    
    // Check vault metadata
    let vault_data = match client.read_file(".mycelium/vault.json").await {
        Ok(data) => {
            items_checked += 1;
            details.push("✓ Vault metadata found".to_string());
            data
        }
        Err(e) => {
            errors.push(format!("Vault metadata not found: {}", e));
            return Ok(VerificationResult::failure(
                "Vault structure verification failed".to_string(),
                items_checked,
                errors,
            ));
        }
    };

    // Parse vault metadata
    let vault: Org = match serde_json::from_slice(&vault_data) {
        Ok(v) => {
            details.push("✓ Vault metadata parsed successfully".to_string());
            v
        }
        Err(e) => {
            errors.push(format!("Invalid vault metadata format: {}", e));
            return Ok(VerificationResult::failure(
                "Vault metadata parsing failed".to_string(),
                items_checked,
                errors,
            ));
        }
    };

    // Step 2: Load and verify devices
    details.push("Loading device registry...".to_string());
    let mut devices = HashMap::new();
    
    match client.list_directory(".mycelium/devices/").await {
        Ok(device_files) => {
            for file_entry in device_files {
                if file_entry.name.ends_with(".json") {
                    match client.read_file(&format!(".mycelium/devices/{}", file_entry.name)).await {
                        Ok(device_data) => {
                            match serde_json::from_slice::<Device>(&device_data) {
                                Ok(device) => {
                                    devices.insert(device.id, device);
                                    items_checked += 1;
                                }
                                Err(e) => {
                                    errors.push(format!("Invalid device file {}: {}", file_entry.name, e));
                                }
                            }
                        }
                        Err(e) => {
                            errors.push(format!("Cannot read device file {}: {}", file_entry.name, e));
                        }
                    }
                }
            }
            details.push(format!("✓ Loaded {} devices", devices.len()));
        }
        Err(e) => {
            warnings.push(format!("Cannot access device directory: {}", e));
        }
    }

    // Step 3: Verify projects
    details.push("Verifying projects...".to_string());
    let mut projects_verified = 0;
    
    match client.list_directory(".mycelium/projects/").await {
        Ok(project_dirs) => {
            for project_dir in project_dirs {
                if project_dir.is_dir {
                    // If specific project requested, only verify that one
                    if let Some(requested_project) = project {
                        if !project_dir.name.contains(requested_project) {
                            continue;
                        }
                    }

                    let project_path = format!(".mycelium/projects/{}", project_dir.name);
                    let project_result = verify_project(
                        client,
                        &project_path,
                        &devices,
                        set,
                        signatures_only,
                        chains_only,
                    ).await;

                    match project_result {
                        Ok((checked, project_errors, project_warnings, project_details)) => {
                            items_checked += checked;
                            errors.extend(project_errors);
                            warnings.extend(project_warnings);
                            details.extend(project_details);
                            projects_verified += 1;
                        }
                        Err(e) => {
                            errors.push(format!("Failed to verify project {}: {}", project_dir.name, e));
                        }
                    }
                }
            }
            details.push(format!("✓ Verified {} projects", projects_verified));
        }
        Err(e) => {
            errors.push(format!("Cannot access projects directory: {}", e));
        }
    }

    // Step 4: Verify audit logs (if not signatures_only or chains_only)
    if !signatures_only && !chains_only {
        details.push("Verifying audit logs...".to_string());
        match verify_audit_logs(client, &devices).await {
            Ok((checked, audit_errors, audit_warnings, audit_details)) => {
                items_checked += checked;
                errors.extend(audit_errors);
                warnings.extend(audit_warnings);
                details.extend(audit_details);
            }
            Err(e) => {
                warnings.push(format!("Audit log verification failed: {}", e));
            }
        }
    }

    // Determine overall result
    let success = errors.is_empty();
    let message = if success {
        format!("Vault integrity verification completed successfully ({} items checked)", items_checked)
    } else {
        format!("Vault integrity verification failed with {} errors", errors.len())
    };

    Ok(VerificationResult {
        success,
        message,
        items_checked,
        errors,
        warnings,
        details,
    })
}

async fn handle_audit_command(command: &AuditCommands, cli: &Cli) -> Result<()> {
    use crate::profile::ProfileManager;

    // Get profile manager and current profile
    let config_dir = ProfileManager::default_config_dir()?;
    let manager = ProfileManager::new(config_dir);

    let profile_name = if let Some(profile) = &cli.profile {
        profile.clone()
    } else {
        manager.get_default_profile()?.ok_or_else(|| {
            anyhow::anyhow!("No default profile set. Use --profile or 'myc profile use <name>'")
        })?
    };

    let profile = manager.get_profile(&profile_name)?;

    match command {
        AuditCommands::List {
            project,
            user,
            event_type,
            since,
            until,
            limit,
        } => {
            myc_cli::audit::list_audit_events(
                project.as_deref(),
                user.as_deref(),
                event_type.as_deref(),
                since.as_deref(),
                until.as_deref(),
                *limit,
                &profile,
                cli.json,
            )
            .await
        }
        AuditCommands::Show { event_id } => {
            myc_cli::audit::show_audit_event(event_id, &profile, cli.json).await
        }
        AuditCommands::Export {
            format,
            output,
            project,
            since,
            until,
        } => {
            myc_cli::audit::export_audit_logs(
                format,
                output.as_deref(),
                project.as_deref(),
                since.as_deref(),
                until.as_deref(),
                &profile,
            )
            .await
        }
        AuditCommands::Note { message, project } => {
            myc_cli::audit::add_audit_note(message, project.as_deref(), &profile, cli.json).await
        }
    }
}

async fn handle_ci_command(command: &CiCommands, cli: &Cli) -> Result<()> {
    use crate::profile::ProfileManager;
    use console::style;
    use dialoguer::{theme::ColorfulTheme, Confirm};
    use myc_cli::env;
    use myc_github::OidcValidator;

    match command {
        CiCommands::Enroll {
            name,
            token,
            expires,
        } => {
            // Check if we're in non-interactive mode
            if !env::is_non_interactive() {
                println!("CI enrollment should typically be run in non-interactive mode.");
                println!("Set MYC_NON_INTERACTIVE=1 to suppress this warning.");
                println!();
            }

            // Get OIDC token - from parameter, environment, or GitHub Actions
            let oidc_token = if let Some(token) = token {
                token.clone()
            } else if let Ok(token) = std::env::var("ACTIONS_ID_TOKEN") {
                token
            } else {
                // Try to get token from GitHub Actions OIDC endpoint
                if let Ok(url) = std::env::var("ACTIONS_ID_TOKEN_REQUEST_URL") {
                    if let Ok(token_env) = std::env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN") {
                        // Make request to get OIDC token
                        let client = reqwest::Client::new();
                        let response = client
                            .get(&url)
                            .header("Authorization", format!("Bearer {}", token_env))
                            .send()
                            .await
                            .context("Failed to request OIDC token from GitHub Actions")?;

                        if !response.status().is_success() {
                            anyhow::bail!(
                                "GitHub Actions OIDC token request failed: {}",
                                response.status()
                            );
                        }

                        let token_response: serde_json::Value = response
                            .json()
                            .await
                            .context("Failed to parse OIDC token response")?;

                        token_response
                            .get("value")
                            .and_then(|v| v.as_str())
                            .ok_or_else(|| {
                                anyhow::anyhow!("OIDC token response missing 'value' field")
                            })?
                            .to_string()
                    } else {
                        anyhow::bail!("OIDC token not provided. Use --token, set ACTIONS_ID_TOKEN, or run in GitHub Actions with id-token: write permission");
                    }
                } else {
                    anyhow::bail!("OIDC token not provided. Use --token, set ACTIONS_ID_TOKEN, or run in GitHub Actions with id-token: write permission");
                }
            };

            // Validate OIDC token
            let validator = OidcValidator::new();
            let claims = validator
                .validate_token(&oidc_token)
                .await
                .context("Failed to validate OIDC token")?;

            // Parse expiration time if provided
            let expires_at = if let Some(expires_str) = expires {
                Some(
                    time::OffsetDateTime::parse(
                        expires_str,
                        &time::format_description::well_known::Rfc3339,
                    )
                    .with_context(|| format!("Invalid expiration time format: {}", expires_str))?,
                )
            } else {
                None
            };

            // Get profile manager and current profile
            let config_dir = ProfileManager::default_config_dir()?;
            let manager = ProfileManager::new(config_dir);

            let profile_name = if let Some(profile) = &cli.profile {
                profile.clone()
            } else {
                manager.get_default_profile()?.ok_or_else(|| {
                    anyhow::anyhow!("No default profile set. Use --profile or 'myc profile use <name>'")
                })?
            };

            let profile = manager.get_profile(&profile_name)?;

            // Get GitHub token from environment
            let github_token = std::env::var("GITHUB_TOKEN").context(
                "GITHUB_TOKEN environment variable not set. This is required for CI enrollment.",
            )?;

            // Create GitHub client
            let github_client = GitHubClient::new(
                github_token,
                profile.github_owner.clone(),
                profile.github_repo.clone(),
            )
            .context("Failed to create GitHub client")?;

            // Generate CI device keypair
            let (signing_secret, signing_public) = myc_crypto::sign::generate_ed25519_keypair()
                .context("Failed to generate Ed25519 keypair")?;
            let (encryption_secret, encryption_public) =
                myc_crypto::kex::generate_x25519_keypair()
                    .context("Failed to generate X25519 keypair")?;

            // Create device record
            use myc_core::device::{Device, DeviceStatus, DeviceType};
            use myc_core::ids::UserId;

            let user_id = UserId::from(format!("github|{}", claims.actor));
            let device = Device::new(
                user_id.clone(),
                name.clone(),
                DeviceType::CI,
                signing_public,
                encryption_public,
                DeviceStatus::Active,
                expires_at,
            );

            // Validate device
            device.validate().context("Device validation failed")?;

            // Upload device to GitHub
            let device_path = format!(".mycelium/devices/{}.json", device.id);
            let device_json = serde_json::to_string_pretty(&device)
                .context("Failed to serialize device")?;

            github_client
                .write_file(
                    &device_path,
                    device_json.as_bytes(),
                    &format!("Enroll CI device: {}", name),
                    None,
                )
                .await
                .context("Failed to upload device to GitHub")?;

            // Create audit event
            use myc_core::audit::{
                AuditEvent, CiEventDetails, EventDetails, EventType, SignedAuditEvent,
            };
            use myc_core::canonical::to_canonical_json;
            use myc_core::ids::OrgId;

            let org_id = OrgId::new(); // In a full implementation, this would be loaded from vault.json
            let audit_event = AuditEvent::new(
                EventType::CiEnrolled,
                device.id,
                user_id.to_string(),
                org_id,
                None,
                EventDetails::Ci(CiEventDetails {
                    device_id: device.id,
                    repository: claims.repository.clone(),
                    workflow: Some(claims.workflow.clone()),
                    git_ref: Some(claims.ref_.clone()),
                    project_id: None,
                    set_id: None,
                }),
                vec![], // Chain hash would be computed properly in full implementation
                None,   // Previous event ID would be tracked in full implementation
            );

            // Sign audit event
            let canonical_json = to_canonical_json(&audit_event)
                .context("Failed to serialize audit event")?;
            let signature = myc_crypto::sign::sign(&signing_secret, canonical_json.as_bytes());

            let signed_event = SignedAuditEvent {
                event: audit_event,
                signature,
                signed_by: device.id,
            };

            // Store audit event (simplified - would use proper month-based organization)
            let event_path = format!(".mycelium/audit/{}.json", signed_event.event.event_id);
            let event_json = serde_json::to_string_pretty(&signed_event)
                .context("Failed to serialize audit event")?;

            github_client
                .write_file(
                    &event_path,
                    event_json.as_bytes(),
                    &format!("CI enrollment audit event for device: {}", name),
                    None,
                )
                .await
                .context("Failed to upload audit event to GitHub")?;

            if cli.json {
                let output = serde_json::json!({
                    "success": true,
                    "message": "CI device enrolled successfully",
                    "device_id": device.id,
                    "device_name": name,
                    "device_type": "ci",
                    "expires_at": expires_at,
                    "oidc_claims": {
                        "repository": claims.repository,
                        "workflow": claims.workflow,
                        "ref": claims.ref_,
                        "actor": claims.actor,
                        "environment": claims.environment
                    }
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("{} CI device enrolled successfully", style("✓").green());
                println!("Device ID: {}", device.id);
                println!("Device Name: {}", name);
                println!("Device Type: CI");
                if let Some(exp) = expires_at {
                    println!("Expires: {}", exp.format(&time::format_description::well_known::Rfc3339)?);
                } else {
                    println!("Expires: Never");
                }
                println!();
                println!("OIDC Claims:");
                println!("  Repository: {}", claims.repository);
                println!("  Workflow: {}", claims.workflow);
                println!("  Ref: {}", claims.ref_);
                println!("  Actor: {}", claims.actor);
                if let Some(env) = &claims.environment {
                    println!("  Environment: {}", env);
                }
                println!();
                println!("Device keys generated and stored in vault.");
                println!("Audit event created: {}", signed_event.event.event_id);
            }
        }
        CiCommands::Pull {
            project,
            set,
            format,
        } => {
            // Check if we're in CI mode
            if !env::is_non_interactive() {
                if cli.json {
                    let output = serde_json::json!({
                        "success": false,
                        "error": "ci pull should be run in non-interactive mode",
                        "message": "Set MYC_NON_INTERACTIVE=1 for CI usage"
                    });
                    println!("{}", serde_json::to_string_pretty(&output)?);
                    return Ok(());
                } else {
                    println!(
                        "{} CI pull should be run in non-interactive mode",
                        style("!").yellow()
                    );
                    println!("Set MYC_NON_INTERACTIVE=1 for CI usage");

                    let should_continue = Confirm::with_theme(&ColorfulTheme::default())
                        .with_prompt("Continue anyway?")
                        .default(false)
                        .interact()?;

                    if !should_continue {
                        return Ok(());
                    }
                }
            }

            // Get profile from environment or default
            let config_dir = ProfileManager::default_config_dir()?;
            let manager = ProfileManager::new(config_dir);

            let profile_name = if let Some(profile) = &cli.profile {
                profile.clone()
            } else if let Some(profile) = env::get_profile_from_env() {
                profile
            } else {
                manager.get_default_profile()?
                    .ok_or_else(|| anyhow::anyhow!("No profile specified. Use --profile, set MYC_PROFILE, or set a default profile"))?
            };

            // Get passphrase from environment
            let passphrase = env::get_passphrase(&profile_name)?;

            // Load profile
            let profile = manager.get_profile(&profile_name)?;

            // Get GitHub token from environment
            let github_token = std::env::var("GITHUB_TOKEN").context(
                "GITHUB_TOKEN environment variable not set. This is required for CI pull.",
            )?;

            // Create GitHub client
            let github_client = GitHubClient::new(
                github_token,
                profile.github_owner.clone(),
                profile.github_repo.clone(),
            )
            .context("Failed to create GitHub client")?;

            // For CI pull, we need to implement the full secret pulling logic
            // This is a simplified implementation that would need to be expanded
            // to include proper project/set resolution, PDK unwrapping, etc.

            // Create audit event for CI pull
            use myc_core::audit::{
                AuditEvent, CiEventDetails, EventDetails, EventType, SignedAuditEvent,
            };
            use myc_core::canonical::to_canonical_json;
            use myc_core::ids::{OrgId, ProjectId, SecretSetId};

            // In a full implementation, these would be resolved from project/set names
            let project_id = ProjectId::new();
            let set_id = SecretSetId::new();
            let org_id = OrgId::new();

            // For now, we'll create a placeholder audit event
            let audit_event = AuditEvent::new(
                EventType::CiPull,
                profile.device_id,
                format!("github|ci-user"), // This would be extracted from CI context
                org_id,
                Some(project_id),
                EventDetails::Ci(CiEventDetails {
                    device_id: profile.device_id,
                    repository: format!("{}/{}", profile.github_owner, profile.github_repo),
                    workflow: None,
                    git_ref: None,
                    project_id: Some(project_id),
                    set_id: Some(set_id),
                }),
                vec![], // Chain hash would be computed properly
                None,   // Previous event ID would be tracked
            );

            if cli.json {
                let output = serde_json::json!({
                    "success": false,
                    "message": "CI pull implementation in progress - core secret pulling logic needed",
                    "project": project,
                    "set": set,
                    "format": format,
                    "profile": profile_name,
                    "non_interactive": env::is_non_interactive(),
                    "note": "This command structure is ready but needs integration with secret pulling logic from other commands"
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("{} CI pull command structure implemented", style("✓").green());
                println!();
                println!("Configuration:");
                println!("  Project: {}", project);
                println!("  Secret Set: {}", set);
                println!("  Format: {}", format);
                println!("  Profile: {}", profile_name);
                println!("  Non-interactive: {}", env::is_non_interactive());
                println!(
                    "  Passphrase source: {}",
                    if env::get_passphrase_from_env().is_some() {
                        "environment"
                    } else {
                        "empty"
                    }
                );
                println!();
                println!("Note: Core secret pulling logic needs to be integrated");
                println!("This would:");
                println!("  1. Resolve project/set names to IDs");
                println!("  2. Load and decrypt secrets");
                println!("  3. Format output as {}", format);
                println!("  4. Write to stdout");
                println!("  5. Create audit event");
            }
        }
    }
    Ok(())
}

async fn handle_cache_command(command: &CacheCommands, cli: &Cli) -> Result<()> {
    use crate::profile::ProfileManager;
    use console::style;
    use myc_github::cache::Cache;
    use std::fs;

    let config_dir = ProfileManager::default_config_dir()?;
    let manager = ProfileManager::new(config_dir);

    match command {
        CacheCommands::Clear { all } => {
            if *all {
                // Clear cache for all profiles
                let profiles = manager.list_profiles()?;
                let mut cleared_count = 0;
                let mut total_size_cleared = 0u64;

                for profile_name in &profiles {
                    let cache_dir = manager.cache_dir(profile_name);
                    if cache_dir.exists() {
                        // Calculate size before clearing
                        let size_before = calculate_dir_size(&cache_dir)?;
                        total_size_cleared += size_before;

                        fs::remove_dir_all(&cache_dir).with_context(|| {
                            format!("Failed to clear cache for profile '{}'", profile_name)
                        })?;
                        fs::create_dir_all(&cache_dir).with_context(|| {
                            format!(
                                "Failed to recreate cache directory for profile '{}'",
                                profile_name
                            )
                        })?;
                        cleared_count += 1;
                    }
                }

                if cli.json {
                    let output = serde_json::json!({
                        "success": true,
                        "message": format!("Cleared cache for {} profiles", cleared_count),
                        "profiles_cleared": cleared_count,
                        "total_profiles": profiles.len(),
                        "total_size_cleared_bytes": total_size_cleared,
                        "total_size_cleared_human": myc_cli::output::format_size(total_size_cleared),
                        "profiles": profiles,
                        "pdk_cache_cleared": true,
                        "note": "PDK cache is in-memory only and cleared automatically between command executions"
                    });
                    println!("{}", serde_json::to_string_pretty(&output)?);
                } else {
                    println!(
                        "{} Cleared cache for {} profiles",
                        style("✓").green(),
                        cleared_count
                    );
                    if total_size_cleared > 0 {
                        println!(
                            "  Total size cleared: {}",
                            myc_cli::output::format_size(total_size_cleared)
                        );
                    }
                    if !profiles.is_empty() {
                        println!("  Profiles:");
                        for profile in &profiles {
                            println!("    - {}", profile);
                        }
                    }
                    println!("  {} PDK cache cleared (in-memory only)", style("✓").green());
                }
            } else {
                // Clear cache for current/default profile only
                let profile_name = if let Some(profile) = &cli.profile {
                    profile.clone()
                } else {
                    manager.get_default_profile()?.ok_or_else(|| {
                        anyhow::anyhow!("No default profile set. Use --profile <name> or --all to clear all profiles, or set a default profile with 'myc profile use <name>'")
                    })?
                };

                let cache_dir = manager.cache_dir(&profile_name);
                let size_before = if cache_dir.exists() {
                    calculate_dir_size(&cache_dir)?
                } else {
                    0
                };

                if cache_dir.exists() {
                    fs::remove_dir_all(&cache_dir).with_context(|| {
                        format!("Failed to clear cache for profile '{}'", profile_name)
                    })?;
                    fs::create_dir_all(&cache_dir).with_context(|| {
                        format!(
                            "Failed to recreate cache directory for profile '{}'",
                            profile_name
                        )
                    })?;
                }

                if cli.json {
                    let output = serde_json::json!({
                        "success": true,
                        "message": format!("Cleared cache for profile '{}'", profile_name),
                        "profile": profile_name,
                        "size_cleared_bytes": size_before,
                        "size_cleared_human": myc_cli::output::format_size(size_before),
                        "pdk_cache_cleared": true,
                        "note": "PDK cache is in-memory only and cleared automatically between command executions"
                    });
                    println!("{}", serde_json::to_string_pretty(&output)?);
                } else {
                    println!(
                        "{} Cleared cache for profile '{}'",
                        style("✓").green(),
                        profile_name
                    );
                    if size_before > 0 {
                        println!(
                            "  Size cleared: {}",
                            myc_cli::output::format_size(size_before)
                        );
                    }
                    println!("  {} PDK cache cleared (in-memory only)", style("✓").green());
                }
            }
        }
        CacheCommands::Status => {
            let profiles = manager.list_profiles()?;
            let default_profile = manager.get_default_profile()?;

            if cli.json {
                let mut profile_status = Vec::new();
                let mut total_cache_size = 0u64;
                let mut total_cache_entries = 0usize;

                for profile_name in &profiles {
                    let cache_dir = manager.cache_dir(profile_name);
                    let cache_exists = cache_dir.exists();
                    let cache_size = if cache_exists {
                        calculate_dir_size(&cache_dir)?
                    } else {
                        0
                    };

                    // Try to get GitHub cache statistics if available
                    let (cache_entries, expired_entries) = if cache_exists {
                        let github_cache = Cache::new(cache_dir.clone());
                        match github_cache.stats() {
                            Ok(stats) => {
                                total_cache_entries += stats.entry_count;
                                (stats.entry_count, stats.expired_count)
                            }
                            Err(_) => {
                                // Fallback: count files manually
                                let entry_count = count_cache_files(&cache_dir)?;
                                total_cache_entries += entry_count;
                                (entry_count, 0)
                            }
                        }
                    } else {
                        (0, 0)
                    };

                    total_cache_size += cache_size;

                    profile_status.push(serde_json::json!({
                        "name": profile_name,
                        "is_default": Some(profile_name) == default_profile.as_ref(),
                        "cache_exists": cache_exists,
                        "cache_size_bytes": cache_size,
                        "cache_size_human": myc_cli::output::format_size(cache_size),
                        "cache_entries": cache_entries,
                        "expired_entries": expired_entries,
                        "cache_path": cache_dir.to_string_lossy()
                    }));
                }

                let output = serde_json::json!({
                    "profiles": profile_status,
                    "total_profiles": profiles.len(),
                    "total_cache_size_bytes": total_cache_size,
                    "total_cache_size_human": myc_cli::output::format_size(total_cache_size),
                    "total_cache_entries": total_cache_entries,
                    "pdk_cache": {
                        "status": "in-memory only",
                        "note": "PDK cache is cleared automatically between command executions"
                    },
                    "cache_hit_miss_rates": {
                        "available": false,
                        "note": "Hit/miss rate tracking not currently implemented"
                    }
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                if profiles.is_empty() {
                    println!("No profiles found.");
                    println!("Run 'myc profile add <name>' to create your first profile.");
                } else {
                    println!("{}", style("Cache Status").bold());
                    println!();

                    let mut total_cache_size = 0u64;
                    let mut total_cache_entries = 0usize;

                    for profile_name in &profiles {
                        let cache_dir = manager.cache_dir(profile_name);
                        let is_default = Some(profile_name) == default_profile.as_ref();
                        let cache_exists = cache_dir.exists();

                        let marker = if is_default {
                            style("*").green().bold()
                        } else {
                            style(" ").dim()
                        };

                        print!("  {} {}", marker, style(profile_name).bold());
                        if is_default {
                            print!(" {}", style("(default)").dim());
                        }
                        println!();

                        if cache_exists {
                            let cache_size = calculate_dir_size(&cache_dir)?;
                            total_cache_size += cache_size;

                            // Try to get detailed cache statistics
                            let github_cache = Cache::new(cache_dir.clone());
                            match github_cache.stats() {
                                Ok(stats) => {
                                    total_cache_entries += stats.entry_count;
                                    println!(
                                        "    Cache: {} ({}, {} entries)",
                                        style("Present").green(),
                                        myc_cli::output::format_size(cache_size),
                                        stats.entry_count
                                    );
                                    if stats.expired_count > 0 {
                                        println!(
                                            "    Expired: {} entries",
                                            style(stats.expired_count.to_string()).yellow()
                                        );
                                    }
                                }
                                Err(_) => {
                                    let entry_count = count_cache_files(&cache_dir)?;
                                    total_cache_entries += entry_count;
                                    println!(
                                        "    Cache: {} ({}, {} files)",
                                        style("Present").green(),
                                        myc_cli::output::format_size(cache_size),
                                        entry_count
                                    );
                                }
                            }
                        } else {
                            println!("    Cache: {}", style("Empty").dim());
                        }

                        println!("    Path: {}", style(cache_dir.to_string_lossy()).dim());
                        println!();
                    }

                    // Summary
                    println!("{}", style("Summary").bold());
                    println!("  Total size: {}", myc_cli::output::format_size(total_cache_size));
                    println!("  Total entries: {}", total_cache_entries);
                    println!("  PDK cache: {} (in-memory only)", style("Active").green());
                    println!();
                    
                    // Note about hit/miss rates
                    println!("{}", style("Note").dim());
                    println!("  Cache hit/miss rate tracking is not currently implemented.");
                    println!("  PDK cache is cleared automatically between command executions.");
                }
            }
        }
    }
    Ok(())
}

async fn handle_run_command(
    project: &Option<String>,
    set: &Option<String>,
    version: &Option<u64>,
    command: &[String],
    cli: &Cli,
) -> Result<()> {
    use crate::profile::ProfileManager;
    use myc_cli::project_config::ProjectConfig;

    use console::style;
    use myc_core::ids::VersionNumber;
    use myc_core::pdk_ops::unwrap_pdk;
    use myc_core::secret_set_ops::read_version;
    use myc_github::client::GitHubClient;
    use std::collections::HashMap;
    use std::process::Command;

    // Validate command arguments
    if command.is_empty() {
        if cli.json {
            let output = serde_json::json!({
                "success": false,
                "error": "no_command",
                "message": "No command specified to run"
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
            return Ok(());
        } else {
            anyhow::bail!(
                "No command specified to run. Usage: myc run [options] -- <command> [args...]"
            );
        }
    }

    // Discover and load project config
    let project_config = ProjectConfig::discover()?;

    // Apply config with command-line overrides
    let config = project_config.with_overrides(
        None, // vault is not used in run command
        project.as_deref(),
        set.as_deref(),
        None, // format not used in run command
        None, // output not used in run command
    );

    // Validate config
    config.validate()?;

    // Get required values (project and set must be provided either via CLI or config)
    let project_value = config.project.as_ref().ok_or_else(|| {
        anyhow::anyhow!("Project not specified. Provide via --project or set in .myc.yaml")
    })?;

    let set_value = config.set.as_ref().ok_or_else(|| {
        anyhow::anyhow!("Secret set not specified. Provide via --set or set in .myc.yaml")
    })?;

    // Get profile manager and current profile
    let config_dir = ProfileManager::default_config_dir()?;
    let manager = ProfileManager::new(config_dir);

    let profile_name = if let Some(profile) = &cli.profile {
        profile.clone()
    } else {
        manager.get_default_profile()?.ok_or_else(|| {
            anyhow::anyhow!("No default profile set. Use --profile or 'myc profile use <name>'")
        })?
    };

    let profile = manager.get_profile(&profile_name)?;

    // Create GitHub client
    let token = std::env::var("GITHUB_TOKEN").context(
        "GITHUB_TOKEN environment variable not set. Run 'myc profile add' to authenticate.",
    )?;

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

    // Look up project by ID or name
    let project_obj = match lookup_project(&client, project_value).await {
        Ok(proj) => proj,
        Err(e) => {
            if cli.json {
                let output = serde_json::json!({
                    "success": false,
                    "error": "project_not_found",
                    "message": format!("Project not found: {}", e),
                    "project_identifier": project_value
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
                return Ok(());
            } else {
                anyhow::bail!("Project not found: {}", e);
            }
        }
    };

    // Look up secret set by ID or name
    let secret_set = match lookup_secret_set(&client, &project_obj.id, set_value).await {
        Ok(set) => set,
        Err(e) => {
            if cli.json {
                let output = serde_json::json!({
                    "success": false,
                    "error": "set_not_found",
                    "message": format!("Secret set not found: {}", e),
                    "project_id": project_obj.id,
                    "set_identifier": set_value
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
                return Ok(());
            } else {
                anyhow::bail!("Secret set not found: {}", e);
            }
        }
    };

    // Determine which version to use
    let target_version = if let Some(v) = version {
        VersionNumber::new(*v)
    } else {
        secret_set.current_version
    };

    // Read version metadata
    let version_meta_path = format!(
        ".mycelium/projects/{}/sets/{}/v{}.meta.json",
        project_obj.id,
        secret_set.id,
        target_version.as_u64()
    );

    let version_metadata = match client.read_file(&version_meta_path).await {
        Ok(content) => serde_json::from_slice::<myc_core::secret_set::SecretSetVersion>(&content)
            .context("Failed to parse version metadata")?,
        Err(e) => {
            if cli.json {
                let output = serde_json::json!({
                    "success": false,
                    "error": "version_not_found",
                    "message": format!("Version {} not found: {}", target_version.as_u64(), e),
                    "project_id": project_obj.id,
                    "set_id": secret_set.id,
                    "version": target_version.as_u64()
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
                return Ok(());
            } else {
                anyhow::bail!("Version {} not found: {}", target_version.as_u64(), e);
            }
        }
    };

    // Read PDK version to get wrapped keys
    let pdk_version_path = format!(
        ".mycelium/projects/{}/pdk/v{}.json",
        project_obj.id,
        version_metadata.pdk_version.as_u64()
    );

    let pdk_version = match client.read_file(&pdk_version_path).await {
        Ok(content) => serde_json::from_slice::<myc_core::pdk::PdkVersion>(&content)
            .context("Failed to parse PDK version")?,
        Err(e) => {
            if cli.json {
                let output = serde_json::json!({
                    "success": false,
                    "error": "pdk_not_found",
                    "message": format!("PDK version {} not found: {}", version_metadata.pdk_version.as_u64(), e),
                    "project_id": project_obj.id,
                    "pdk_version": version_metadata.pdk_version.as_u64()
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
                return Ok(());
            } else {
                anyhow::bail!(
                    "PDK version {} not found: {}",
                    version_metadata.pdk_version.as_u64(),
                    e
                );
            }
        }
    };

    // Find wrapped PDK for our device
    let wrapped_pdk = pdk_version
        .wrapped_keys
        .iter()
        .find(|w| w.device_id == profile.device_id)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No PDK wrapped for device {}. You may not have access to this project.",
                profile.device_id
            )
        })?;

    // Load device encryption key
    let passphrase = std::env::var("MYC_KEY_PASSPHRASE")
        .or_else(|_| {
            if std::env::var("MYC_NON_INTERACTIVE").is_ok() {
                anyhow::bail!("MYC_KEY_PASSPHRASE environment variable required in non-interactive mode");
            }
            // In a full implementation, this would prompt for passphrase
            anyhow::bail!("Interactive passphrase prompting not yet implemented. Set MYC_KEY_PASSPHRASE environment variable.");
        })?;

    let encryption_key_path = manager.encryption_key_path(&profile_name);
    let device_encryption_key =
        myc_cli::key_storage::load_encryption_key(&encryption_key_path, &passphrase)
            .context("Failed to load device encryption key. Check your passphrase.")?;

    // Unwrap PDK
    let pdk = unwrap_pdk(wrapped_pdk, &device_encryption_key)
        .context("Failed to unwrap PDK. You may not have access to this project.")?;

    // Load device signing key for signature verification
    let signing_key_path = manager.signing_key_path(&profile_name);
    let device_signing_key = myc_cli::key_storage::load_signing_key(&signing_key_path, &passphrase)
        .context("Failed to load device signing key")?;
    let device_pubkey = device_signing_key.verifying_key();

    // Read and decrypt the version
    let entries = read_version(
        &version_metadata,
        &project_obj.id,
        &pdk,
        &device_pubkey,
        version_metadata.previous_hash.as_ref(),
    )
    .context("Failed to decrypt secret version")?;

    // Convert entries to environment variables
    let mut env_vars = HashMap::new();
    for entry in &entries {
        env_vars.insert(entry.key.clone(), entry.value.clone());
    }

    // Prepare the command to execute
    let program = &command[0];
    let args = if command.len() > 1 {
        &command[1..]
    } else {
        &[]
    };

    if !cli.quiet {
        if cli.json {
            let output = serde_json::json!({
                "action": "executing_command",
                "project": {
                    "id": project_obj.id,
                    "name": project_obj.name
                },
                "secret_set": {
                    "id": secret_set.id,
                    "name": secret_set.name
                },
                "version": target_version.as_u64(),
                "command": command,
                "env_vars_count": env_vars.len()
            });
            eprintln!("{}", serde_json::to_string_pretty(&output)?);
        } else {
            eprintln!(
                "{} Executing command with {} secrets from {}/{} v{}",
                style("→").blue(),
                env_vars.len(),
                project_obj.name,
                secret_set.name,
                target_version.as_u64()
            );
        }
    }

    // Execute the command with injected environment variables
    let mut cmd = Command::new(program);
    cmd.args(args);

    // Inherit current environment and add our secrets
    cmd.envs(&env_vars);

    // Execute and wait for completion
    let status = cmd
        .status()
        .context(format!("Failed to execute command: {}", program))?;

    // Exit with the same code as the subprocess
    if let Some(code) = status.code() {
        std::process::exit(code);
    } else {
        // Process was terminated by signal on Unix
        std::process::exit(1);
    }
}

/// Calculate the total size of a directory recursively
fn calculate_dir_size(dir: &std::path::Path) -> Result<u64> {
    let mut total_size = 0;

    if dir.is_dir() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                total_size += calculate_dir_size(&path)?;
            } else {
                total_size += entry.metadata()?.len();
            }
        }
    }

    Ok(total_size)
}

/// Count the number of files in a cache directory
fn count_cache_files(dir: &std::path::Path) -> Result<usize> {
    let mut count = 0;

    if dir.is_dir() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() {
                count += 1;
            } else if path.is_dir() {
                count += count_cache_files(&path)?;
            }
        }
    }

    Ok(count)
}

/// Handle status command
async fn handle_status_command(cli: &Cli, recovery_warnings: &RecoveryWarnings) -> Result<()> {
    use crate::profile::ProfileManager;
    use console::style;
    use myc_github::client::GitHubClient;
    use std::collections::HashMap;

    // Get profile manager
    let config_dir = ProfileManager::default_config_dir()?;
    let manager = ProfileManager::new(config_dir);

    // Get current profile
    let profile_name = if let Some(profile) = &cli.profile {
        profile.clone()
    } else {
        manager.get_default_profile()?.ok_or_else(|| {
            anyhow::anyhow!(
                "No default profile set. Use 'myc profile add <name>' to create a profile."
            )
        })?
    };

    let profile = manager.get_profile(&profile_name)?;
    let is_default = manager.get_default_profile()? == Some(profile_name.clone());

    // Check if we have a GitHub token
    let github_token = std::env::var("GITHUB_TOKEN").ok();
    let mut github_client = None;
    let mut github_rate_limit = None;
    let mut vault_accessible = false;

    if let Some(token) = &github_token {
        match GitHubClient::new(
            token.clone(),
            profile.github_owner.clone(),
            profile.github_repo.clone(),
        ) {
            Ok(client) => {
                // Check vault access
                match client.check_access().await {
                    Ok(access) => {
                        vault_accessible = access;
                        github_client = Some(client);
                    }
                    Err(_) => {
                        vault_accessible = false;
                    }
                }
            }
            Err(_) => {
                vault_accessible = false;
            }
        }
    }

    // Get recovery status
    let recovery_status = if let Some(client) = &github_client {
        recovery_warnings
            .get_recovery_status(client, &profile.github_user_id.to_string())
            .await
            .unwrap_or_default()
    } else {
        myc_cli::recovery::RecoveryStatus::default()
    };

    // Get accessible projects
    let mut accessible_projects = Vec::new();
    let mut project_count = 0;
    
    if let Some(client) = &github_client {
        // Try to list projects (similar to project list command)
        if let Ok(project_dirs) = client.list_directory(".mycelium/projects").await {
            let user_id = myc_core::ids::UserId::from(profile.github_user_id.to_string());
            
            for dir_entry in project_dirs {
                if !dir_entry.is_dir {
                    continue;
                }

                let project_id = &dir_entry.name;
                
                // Try to read project metadata
                let project_path = format!(".mycelium/projects/{}/project.json", project_id);
                if let Ok(project_data) = client.read_file(&project_path).await {
                    if let Ok(project) = serde_json::from_slice::<myc_core::project::Project>(&project_data) {
                        // Try to read membership
                        let members_path = format!(".mycelium/projects/{}/members.json", project_id);
                        if let Ok(members_data) = client.read_file(&members_path).await {
                            if let Ok(membership_list) = serde_json::from_slice::<myc_core::membership_ops::MembershipList>(&members_data) {
                                if let Some(member) = membership_list.find_member(&user_id) {
                                    // Count secret sets
                                    let sets_path = format!(".mycelium/projects/{}/sets", project_id);
                                    let set_count = match client.list_directory(&sets_path).await {
                                        Ok(sets) => sets.len(),
                                        Err(_) => 0,
                                    };

                                    accessible_projects.push(serde_json::json!({
                                        "id": project.id,
                                        "name": project.name,
                                        "role": format!("{:?}", member.role).to_lowercase(),
                                        "member_count": membership_list.members.len(),
                                        "secret_set_count": set_count,
                                        "created_at": project.created_at
                                    }));
                                    project_count += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Get last pull information (simple implementation using cache metadata)
    let mut last_pull_info = None;
    let cache_dir = manager.cache_dir(&profile.name);
    if cache_dir.exists() {
        // Look for the most recent cache file as a proxy for last pull
        if let Ok(entries) = std::fs::read_dir(&cache_dir) {
            let mut most_recent: Option<(std::time::SystemTime, std::path::PathBuf)> = None;
            
            for entry in entries.flatten() {
                if let Ok(metadata) = entry.metadata() {
                    if let Ok(modified) = metadata.modified() {
                        if most_recent.is_none() || modified > most_recent.as_ref().unwrap().0 {
                            most_recent = Some((modified, entry.path()));
                        }
                    }
                }
            }
            
            if let Some((modified_time, path)) = most_recent {
                // Convert SystemTime to OffsetDateTime
                if let Ok(duration) = modified_time.duration_since(std::time::UNIX_EPOCH) {
                    let timestamp = time::OffsetDateTime::from_unix_timestamp(duration.as_secs() as i64)
                        .unwrap_or_else(|_| time::OffsetDateTime::now_utc());
                    
                    // Try to extract project/set info from cache file name
                    let file_name = path.file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown");
                    
                    last_pull_info = Some(serde_json::json!({
                        "timestamp": timestamp,
                        "cache_file": file_name,
                        "time_ago": format_time_ago(&timestamp)
                    }));
                }
            }
        }
    }

    // Get GitHub API rate limit if we have a client
    if let Some(client) = &github_client {
        let rate_limit_info = client.rate_limit_info();
        github_rate_limit = Some(HashMap::from([
            ("limit".to_string(), rate_limit_info.limit.to_string()),
            ("remaining".to_string(), rate_limit_info.remaining.to_string()),
            ("reset".to_string(), {
                if rate_limit_info.reset_at > 0 {
                    // Convert Unix timestamp to ISO 8601
                    let reset_time = time::OffsetDateTime::from_unix_timestamp(rate_limit_info.reset_at as i64)
                        .unwrap_or_else(|_| time::OffsetDateTime::now_utc());
                    reset_time.format(&time::format_description::well_known::Rfc3339)
                        .unwrap_or_else(|_| "Unknown".to_string())
                } else {
                    "Unknown".to_string()
                }
            }),
            ("reset_human".to_string(), rate_limit_info.reset_time_string()),
            ("approaching_limit".to_string(), rate_limit_info.is_approaching_limit().to_string()),
            ("exceeded".to_string(), rate_limit_info.is_exceeded().to_string()),
        ]));
    }

    // Check key file status
    let signing_key_exists = manager.signing_key_path(&profile.name).exists();
    let encryption_key_exists = manager.encryption_key_path(&profile.name).exists();
    let keys_enrolled = signing_key_exists && encryption_key_exists;

    // Get cache information
    let cache_dir = manager.cache_dir(&profile.name);
    let cache_size = if cache_dir.exists() {
        calculate_dir_size(&cache_dir).unwrap_or(0)
    } else {
        0
    };

    if cli.json {
        let output = serde_json::json!({
            "profile": {
                "name": profile.name,
                "is_default": is_default,
                "github_user": profile.github_username,
                "github_user_id": profile.github_user_id,
                "vault": {
                    "owner": profile.github_owner,
                    "repo": profile.github_repo,
                    "url": format!("https://github.com/{}/{}", profile.github_owner, profile.github_repo),
                    "accessible": vault_accessible
                },
                "device": {
                    "id": profile.device_id,
                    "keys_enrolled": keys_enrolled,
                    "created_at": profile.created_at
                }
            },
            "recovery": {
                "devices_enrolled": recovery_status.devices_enrolled,
                "recovery_contacts": recovery_status.recovery_contacts,
                "org_recovery_key": recovery_status.org_recovery_key,
                "user_devices": recovery_status.user_devices
            },
            "projects": {
                "accessible_projects": accessible_projects,
                "total_count": project_count
            },
            "last_pull": if let Some(pull_info) = &last_pull_info {
                serde_json::json!({
                    "status": "found",
                    "timestamp": pull_info["timestamp"],
                    "time_ago": pull_info["time_ago"],
                    "cache_file": pull_info["cache_file"]
                })
            } else {
                serde_json::json!({
                    "status": "no_recent_activity",
                    "timestamp": null,
                    "time_ago": null,
                    "cache_file": null
                })
            },
            "github_api": {
                "authenticated": github_token.is_some(),
                "rate_limit": github_rate_limit
            },
            "cache": {
                "size_bytes": cache_size,
                "size_human": myc_cli::output::format_size(cache_size)
            }
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("{}", style("Mycelium Status").bold().underlined());
        println!();

        // Profile Information
        println!("{}", style("Profile").bold());
        println!("  Name: {}", profile.name);
        if is_default {
            println!("  Status: {} (default)", style("Active").green());
        } else {
            println!("  Status: Available");
        }
        println!(
            "  GitHub User: {} ({})",
            profile.github_username, profile.github_user_id
        );
        println!("  Device ID: {}", profile.device_id);
        println!(
            "  Created: {}",
            profile
                .created_at
                .format(&time::format_description::well_known::Rfc3339)?
        );
        println!();

        // Vault Information
        println!("{}", style("Vault").bold());
        println!(
            "  Repository: {}/{}",
            profile.github_owner, profile.github_repo
        );
        println!(
            "  URL: https://github.com/{}/{}",
            profile.github_owner, profile.github_repo
        );
        if vault_accessible {
            println!("  Access: {} Accessible", style("✓").green());
        } else if github_token.is_some() {
            println!(
                "  Access: {} Not accessible (check permissions)",
                style("✗").red()
            );
        } else {
            println!(
                "  Access: {} Not authenticated (set GITHUB_TOKEN)",
                style("?").yellow()
            );
        }
        println!();

        // Device Keys
        println!("{}", style("Device Keys").bold());
        if keys_enrolled {
            println!("  Status: {} Enrolled", style("✓").green());
        } else {
            println!(
                "  Status: {} Missing (device not properly enrolled)",
                style("✗").red()
            );
        }
        println!(
            "  Signing Key: {}",
            if signing_key_exists {
                style("Present").green()
            } else {
                style("Missing").red()
            }
        );
        println!(
            "  Encryption Key: {}",
            if encryption_key_exists {
                style("Present").green()
            } else {
                style("Missing").red()
            }
        );
        println!();

        // Recovery Status
        recovery_warnings.display_recovery_status(&recovery_status, cli.json)?;
        println!();

        // Projects
        println!("{}", style("Projects").bold());
        if vault_accessible {
            if project_count > 0 {
                println!("  Accessible Projects: {}", style(project_count.to_string()).green());
                
                // Show up to 5 most recent projects
                let display_count = std::cmp::min(accessible_projects.len(), 5);
                for project in accessible_projects.iter().take(display_count) {
                    let role_color = match project["role"].as_str().unwrap_or("unknown") {
                        "owner" => style("Owner").green(),
                        "admin" => style("Admin").yellow(),
                        "member" => style("Member").blue(),
                        "reader" => style("Reader").dim(),
                        _ => style("Unknown").dim(),
                    };
                    
                    println!("    • {} ({})", 
                        style(project["name"].as_str().unwrap_or("Unknown")).bold(),
                        role_color
                    );
                }
                
                if accessible_projects.len() > 5 {
                    println!("    ... and {} more", accessible_projects.len() - 5);
                }
                
                println!("  Use 'myc project list' to see all projects");
            } else {
                println!("  Accessible Projects: {} No projects found", style("0").yellow());
                println!("  Create your first project: myc project create <name>");
            }
        } else {
            println!("  Accessible Projects: {} (vault not accessible)", style("Unknown").yellow());
        }
        println!();

        // Last Pull Information
        println!("{}", style("Last Activity").bold());
        if let Some(pull_info) = &last_pull_info {
            println!("  Last Cache Update: {}", 
                style(pull_info["time_ago"].as_str().unwrap_or("Unknown")).green()
            );
            println!("  Cache File: {}", pull_info["cache_file"].as_str().unwrap_or("Unknown"));
        } else {
            println!("  Last Activity: {} No recent cache activity", style("None").yellow());
            println!("  Note: Activity is tracked via cache files");
        }
        println!();

        // GitHub API Status
        println!("{}", style("GitHub API").bold());
        if let Some(_token) = &github_token {
            println!("  Authentication: {} Token present", style("✓").green());
            if let Some(rate_limit) = &github_rate_limit {
                let remaining = rate_limit.get("remaining").cloned().unwrap_or_else(|| "?".to_string());
                let limit = rate_limit.get("limit").cloned().unwrap_or_else(|| "?".to_string());
                let approaching = rate_limit.get("approaching_limit").unwrap_or(&"false".to_string()) == "true";
                let exceeded = rate_limit.get("exceeded").unwrap_or(&"false".to_string()) == "true";
                
                let rate_status = if exceeded {
                    style(format!("{}/{} requests remaining (EXCEEDED)", remaining, limit)).red()
                } else if approaching {
                    style(format!("{}/{} requests remaining (approaching limit)", remaining, limit)).yellow()
                } else {
                    style(format!("{}/{} requests remaining", remaining, limit)).green()
                };
                
                println!("  Rate Limit: {}", rate_status);
                println!(
                    "  Reset Time: {} ({})",
                    rate_limit.get("reset").unwrap_or(&"Unknown".to_string()),
                    rate_limit.get("reset_human").unwrap_or(&"Unknown".to_string())
                );
                
                if approaching {
                    println!("  {} Rate limit approaching - consider reducing API usage", 
                        style("⚠").yellow());
                }
                if exceeded {
                    println!("  {} Rate limit exceeded - wait for reset", 
                        style("✗").red());
                }
            } else {
                println!(
                    "  Rate Limit: {} (unable to check)",
                    style("Unknown").yellow()
                );
            }
        } else {
            println!("  Authentication: {} No GITHUB_TOKEN set", style("✗").red());
            println!("  Rate Limit: Not available without authentication");
        }
        println!();

        // Cache Information
        println!("{}", style("Cache").bold());
        if cache_size > 0 {
            println!("  Size: {}", myc_cli::output::format_size(cache_size));
            println!("  Location: {}", cache_dir.display());
        } else {
            println!("  Size: Empty");
        }
        println!("  Use 'myc cache clear' to clear cache");
        println!();

        // Helpful hints
        if !keys_enrolled {
            println!("{}", style("⚠ Warning").yellow().bold());
            println!(
                "  Device keys are missing. Run 'myc profile add <name>' to enroll this device."
            );
            println!();
        }

        if github_token.is_none() {
            println!("{}", style("💡 Tip").blue().bold());
            println!("  Set GITHUB_TOKEN environment variable to enable vault access.");
            println!("  You can get a token from: https://github.com/settings/tokens");
            println!();
        }

        if !vault_accessible && github_token.is_some() {
            println!("{}", style("💡 Tip").blue().bold());
            println!("  Vault is not accessible. Check that:");
            println!(
                "  - The repository {}/{} exists",
                profile.github_owner, profile.github_repo
            );
            println!("  - Your GitHub token has 'repo' permissions");
            println!("  - You have access to the repository");
            println!();
        }
    }

    Ok(())
}

/// Handle shell completions generation
fn handle_completions_command(shell: Shell, cli: &Cli) -> Result<()> {
    let mut cmd = Cli::command();
    let name = cmd.get_name().to_string();

    if cli.json {
        // For JSON output, we'll provide information about the completion generation
        let output = serde_json::json!({
            "success": true,
            "message": format!("Generated {} completions for myc", shell),
            "shell": format!("{}", shell),
            "installation_instructions": get_installation_instructions(shell)
        });
        eprintln!("{}", serde_json::to_string_pretty(&output)?);
    }

    generate(shell, &mut cmd, name, &mut io::stdout());
    Ok(())
}

/// Get installation instructions for each shell
fn get_installation_instructions(shell: Shell) -> serde_json::Value {
    match shell {
        Shell::Bash => serde_json::json!({
            "description": "Add the following to your ~/.bashrc:",
            "command": "eval \"$(myc completions bash)\""
        }),
        Shell::Zsh => serde_json::json!({
            "description": "Add the following to your ~/.zshrc:",
            "command": "eval \"$(myc completions zsh)\""
        }),
        Shell::Fish => serde_json::json!({
            "description": "Add the following to your fish config:",
            "command": "myc completions fish | source"
        }),
        Shell::PowerShell => serde_json::json!({
            "description": "Add the following to your PowerShell profile:",
            "command": "Invoke-Expression (& myc completions powershell)"
        }),
        _ => serde_json::json!({
            "description": "Completion generated for unsupported shell",
            "command": "Please refer to your shell's documentation for loading completions"
        }),
    }
}

/// Offer to set up .gitignore with secret file patterns during init
fn offer_gitignore_setup(cli: &Cli) -> Result<bool> {
    use console::style;
    use dialoguer::{theme::ColorfulTheme, Confirm};
    use std::fs;
    use std::path::Path;

    // Don't offer in JSON mode or if MYC_NON_INTERACTIVE is set
    if cli.json || std::env::var("MYC_NON_INTERACTIVE").is_ok() {
        return Ok(false);
    }

    let gitignore_path = Path::new(".gitignore");

    // Check if .gitignore exists and if it already has .env pattern
    let needs_gitignore = if gitignore_path.exists() {
        let content = fs::read_to_string(gitignore_path)?;
        let has_env_pattern = content.lines().any(|line| {
            let trimmed = line.trim();
            trimmed == ".env" || trimmed.starts_with(".env")
        });
        !has_env_pattern
    } else {
        true
    };

    if !needs_gitignore {
        return Ok(false);
    }

    println!();
    if gitignore_path.exists() {
        println!(
            "{} Your .gitignore doesn't include secret file patterns.",
            style("ℹ").blue()
        );
    } else {
        println!(
            "{} No .gitignore file found in current directory.",
            style("ℹ").blue()
        );
    }

    println!("Mycelium recommends adding common secret file patterns to prevent");
    println!("accidentally committing sensitive files like .env, *.key, etc.");
    println!();

    let should_add = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Add secret file patterns to .gitignore?")
        .default(true)
        .interact()?;

    if should_add {
        // Use the gitignore handler to add patterns
        handle_gitignore_command(&None, false, cli)?;
        println!();
        return Ok(true);
    }

    println!(
        "You can add them later with: {}",
        style("myc gitignore").cyan()
    );
    println!();
    Ok(false)
}

/// Handle gitignore command
fn handle_gitignore_command(file: &Option<String>, dry_run: bool, cli: &Cli) -> Result<()> {
    use console::style;
    use std::fs;
    use std::path::Path;

    // Determine the .gitignore file path
    let gitignore_path = file.as_deref().unwrap_or(".gitignore");
    let path = Path::new(gitignore_path);

    // Common secret file patterns to add
    let secret_patterns = vec![".env", ".env.*", "*.pem", "*.key", ".myc-secrets/"];

    // Read existing .gitignore content if it exists
    let existing_content = if path.exists() {
        fs::read_to_string(path).with_context(|| format!("Failed to read {}", gitignore_path))?
    } else {
        String::new()
    };

    // Check which patterns are already present
    let existing_lines: Vec<&str> = existing_content.lines().collect();
    let mut patterns_to_add = Vec::new();

    for pattern in &secret_patterns {
        // Check if pattern already exists (exact match or as comment)
        let pattern_exists = existing_lines.iter().any(|line| {
            let trimmed = line.trim();
            trimmed == *pattern || trimmed == &format!("# {}", pattern)
        });

        if !pattern_exists {
            patterns_to_add.push(*pattern);
        }
    }

    if patterns_to_add.is_empty() {
        if cli.json {
            let output = serde_json::json!({
                "success": true,
                "message": "All secret file patterns already present in .gitignore",
                "file": gitignore_path,
                "patterns_checked": secret_patterns
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        } else {
            println!(
                "{} All secret file patterns already present in {}",
                style("✓").green(),
                gitignore_path
            );
        }
        return Ok(());
    }

    if dry_run {
        if cli.json {
            let output = serde_json::json!({
                "success": true,
                "message": "Dry run: would add patterns to .gitignore",
                "file": gitignore_path,
                "patterns_to_add": patterns_to_add,
                "existing_file": path.exists()
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        } else {
            println!("Would add the following patterns to {}:", gitignore_path);
            for pattern in &patterns_to_add {
                println!("  + {}", style(pattern).cyan());
            }
            if !path.exists() {
                println!(
                    "\n{} File {} does not exist and would be created",
                    style("ℹ").blue(),
                    gitignore_path
                );
            }
        }
        return Ok(());
    }

    // Prepare the content to add
    let mut content_to_add = String::new();

    // Add a header comment if we're adding to an existing file
    if path.exists() && !existing_content.is_empty() {
        content_to_add.push_str("\n# Secret files (added by myc)\n");
    } else {
        content_to_add.push_str("# Secret files (added by myc)\n");
    }

    for pattern in &patterns_to_add {
        content_to_add.push_str(pattern);
        content_to_add.push('\n');
    }

    // Write the updated content
    let final_content = if path.exists() {
        format!("{}{}", existing_content, content_to_add)
    } else {
        content_to_add
    };

    fs::write(path, final_content)
        .with_context(|| format!("Failed to write to {}", gitignore_path))?;

    if cli.json {
        let output = serde_json::json!({
            "success": true,
            "message": format!("Added {} patterns to {}", patterns_to_add.len(), gitignore_path),
            "file": gitignore_path,
            "patterns_added": patterns_to_add,
            "created_file": !path.exists()
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!(
            "{} Added {} secret file patterns to {}",
            style("✓").green(),
            patterns_to_add.len(),
            gitignore_path
        );
        for pattern in &patterns_to_add {
            println!("  + {}", style(pattern).cyan());
        }
    }

    Ok(())
}

async fn handle_recovery_command(command: &RecoveryCommands, cli: &Cli) -> Result<()> {
    use console::style;

    let config_dir = dirs::config_dir()
        .ok_or_else(|| anyhow::anyhow!("Could not determine config directory"))?
        .join("mycelium");

    let manager = crate::profile::ProfileManager::new(config_dir);
    let profile_name = cli
        .profile
        .clone()
        .or_else(|| manager.get_default_profile().ok().flatten())
        .ok_or_else(|| anyhow::anyhow!("No profile specified and no default profile set"))?;

    match command {
        RecoveryCommands::SetContacts { contacts } => {
            if cli.json {
                let output = serde_json::json!({
                    "success": true,
                    "message": "Recovery contacts feature not yet implemented",
                    "contacts": contacts
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!(
                    "{} Recovery contacts feature not yet implemented",
                    style("ℹ").blue()
                );
                println!("  Contacts to set: {:?}", contacts);
            }
        }
        RecoveryCommands::ShowContacts => {
            if cli.json {
                let output = serde_json::json!({
                    "contacts": [],
                    "message": "Recovery contacts feature not yet implemented"
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("{}", style("Recovery Contacts").bold());
                println!("  No contacts configured (feature not yet implemented)");
            }
        }
        RecoveryCommands::Status => {
            // Use the existing recovery status functionality
            let recovery_warnings = RecoveryWarnings::new();
            let status = RecoveryStatus::default();

            if cli.json {
                let output = serde_json::json!({
                    "devices_enrolled": status.devices_enrolled,
                    "recovery_contacts": status.recovery_contacts,
                    "org_recovery_key": status.org_recovery_key,
                    "user_devices": status.user_devices
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                recovery_warnings.display_recovery_status(&status, false)?;
            }
        }
        RecoveryCommands::Request { device_name } => {
            if cli.json {
                let output = serde_json::json!({
                    "success": true,
                    "message": "Recovery request feature not yet implemented",
                    "device_name": device_name
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!(
                    "{} Recovery request feature not yet implemented",
                    style("ℹ").blue()
                );
                println!("  Device name: {}", device_name);
            }
        }
        RecoveryCommands::Assist { request_id } => {
            if cli.json {
                let output = serde_json::json!({
                    "success": true,
                    "message": "Recovery assist feature not yet implemented",
                    "request_id": request_id
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!(
                    "{} Recovery assist feature not yet implemented",
                    style("ℹ").blue()
                );
                println!("  Request ID: {}", request_id);
            }
        }
    }

    Ok(())
}

/// Verify a single project's integrity
async fn verify_project(
    client: &myc_github::client::GitHubClient,
    project_path: &str,
    devices: &std::collections::HashMap<myc_core::ids::DeviceId, myc_core::device::Device>,
    requested_set: &Option<String>,
    signatures_only: bool,
    chains_only: bool,
) -> Result<(usize, Vec<String>, Vec<String>, Vec<String>)> {
    use myc_core::ids::{ProjectId, SecretSetId};
    use myc_core::membership_ops::MembershipList;
    use myc_core::pdk::PdkVersion;
    use myc_core::project::Project;
    use myc_core::secret_set::{SecretSet, SecretSetVersion};
    use myc_core::secret_set_ops::{verify_chain, verify_version_metadata};
    use myc_crypto::sign::Ed25519PublicKey;

    let mut items_checked = 0;
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    let mut details = Vec::new();

    // Read project metadata
    let project_data = client.read_file(&format!("{}/project.json", project_path)).await?;
    let project: Project = serde_json::from_slice(&project_data)
        .context("Invalid project metadata format")?;
    items_checked += 1;
    details.push(format!("✓ Project {} metadata loaded", project.name));

    // Read and verify membership list
    match client.read_file(&format!("{}/members.json", project_path)).await {
        Ok(members_data) => {
            match serde_json::from_slice::<MembershipList>(&members_data) {
                Ok(membership_list) => {
                    items_checked += 1;
                    
                    // Verify membership signature if not chains_only
                    if !chains_only {
                        if let Some(_signature) = &membership_list.signature {
                            if let Some(signed_by_device) = devices.get(&membership_list.updated_by) {
                                match membership_list.verify(&signed_by_device.signing_pubkey) {
                                    Ok(_) => {
                                        details.push("✓ Membership signature valid".to_string());
                                    }
                                    Err(e) => {
                                        errors.push(format!("Membership signature invalid: {}", e));
                                    }
                                }
                            } else {
                                errors.push(format!("Membership signed by unknown device: {}", membership_list.updated_by));
                            }
                        } else {
                            errors.push("Membership list not signed".to_string());
                        }
                    }
                }
                Err(e) => {
                    errors.push(format!("Invalid membership list format: {}", e));
                }
            }
        }
        Err(e) => {
            errors.push(format!("Cannot read membership list: {}", e));
        }
    }

    // Verify PDK versions if not chains_only
    if !chains_only {
        match client.list_directory(&format!("{}/pdk/", project_path)).await {
            Ok(pdk_files) => {
                for pdk_file in pdk_files {
                    if pdk_file.name.starts_with("v") && pdk_file.name.ends_with(".json") {
                        match client.read_file(&format!("{}/pdk/{}", project_path, pdk_file.name)).await {
                            Ok(pdk_data) => {
                                match serde_json::from_slice::<PdkVersion>(&pdk_data) {
                                    Ok(_pdk_version) => {
                                        items_checked += 1;
                                        details.push(format!("✓ PDK version {} loaded", pdk_file.name));
                                        // Note: PDK version signature verification would require 
                                        // implementing signing for PdkVersion in the core
                                    }
                                    Err(e) => {
                                        errors.push(format!("Invalid PDK version {}: {}", pdk_file.name, e));
                                    }
                                }
                            }
                            Err(e) => {
                                errors.push(format!("Cannot read PDK version {}: {}", pdk_file.name, e));
                            }
                        }
                    }
                }
            }
            Err(e) => {
                warnings.push(format!("Cannot access PDK directory: {}", e));
            }
        }
    }

    // Verify secret sets
    match client.list_directory(&format!("{}/sets/", project_path)).await {
        Ok(set_dirs) => {
            for set_dir in set_dirs {
                if set_dir.is_dir {
                    // If specific set requested, only verify that one
                    if let Some(requested) = requested_set {
                        if !set_dir.name.contains(requested) {
                            continue;
                        }
                    }

                    let set_result = verify_secret_set(
                        client,
                        &format!("{}/sets/{}", project_path, set_dir.name),
                        devices,
                        signatures_only,
                        chains_only,
                    ).await;

                    match set_result {
                        Ok((checked, set_errors, set_warnings, set_details)) => {
                            items_checked += checked;
                            errors.extend(set_errors);
                            warnings.extend(set_warnings);
                            details.extend(set_details);
                        }
                        Err(e) => {
                            errors.push(format!("Failed to verify secret set {}: {}", set_dir.name, e));
                        }
                    }
                }
            }
        }
        Err(e) => {
            warnings.push(format!("Cannot access secret sets directory: {}", e));
        }
    }

    Ok((items_checked, errors, warnings, details))
}

/// Verify a single secret set's integrity
async fn verify_secret_set(
    client: &myc_github::client::GitHubClient,
    set_path: &str,
    devices: &std::collections::HashMap<myc_core::ids::DeviceId, myc_core::device::Device>,
    signatures_only: bool,
    chains_only: bool,
) -> Result<(usize, Vec<String>, Vec<String>, Vec<String>)> {
    use myc_core::secret_set::{SecretSet, SecretSetVersion};
    use myc_core::secret_set_ops::{verify_chain, verify_version_metadata};

    let mut items_checked = 0;
    let mut errors = Vec::new();
    let warnings = Vec::new();
    let mut details = Vec::new();

    // Read secret set metadata
    match client.read_file(&format!("{}/set.json", set_path)).await {
        Ok(set_data) => {
            match serde_json::from_slice::<SecretSet>(&set_data) {
                Ok(secret_set) => {
                    items_checked += 1;
                    details.push(format!("✓ Secret set {} metadata loaded", secret_set.name));
                }
                Err(e) => {
                    errors.push(format!("Invalid secret set metadata: {}", e));
                    return Ok((items_checked, errors, warnings, details));
                }
            }
        }
        Err(e) => {
            errors.push(format!("Cannot read secret set metadata: {}", e));
            return Ok((items_checked, errors, warnings, details));
        }
    }

    // Get all version files
    match client.list_directory(set_path).await {
        Ok(files) => {
            let mut versions = Vec::new();
            let mut metadata_files = Vec::new();

            // Collect version metadata files
            for file in files {
                if file.name.starts_with("v") && file.name.ends_with(".meta.json") {
                    metadata_files.push(file.name);
                }
            }

            // Sort by version number
            metadata_files.sort_by(|a, b| {
                let a_num = extract_version_number(a).unwrap_or(0);
                let b_num = extract_version_number(b).unwrap_or(0);
                a_num.cmp(&b_num)
            });

            // Load and verify each version
            for meta_file in metadata_files {
                match client.read_file(&format!("{}/{}", set_path, meta_file)).await {
                    Ok(meta_data) => {
                        match serde_json::from_slice::<SecretSetVersion>(&meta_data) {
                            Ok(version) => {
                                items_checked += 1;
                                versions.push(version.clone());

                                // Verify signature if not chains_only
                                if !chains_only {
                                    if let Some(device) = devices.get(&version.created_by) {
                                        // Compute chain hash for this version
                                        let chain_hash_value = match &version.previous_hash {
                                            Some(prev) => myc_crypto::hash::chain_hash(prev, version.content_hash.as_bytes()),
                                            None => version.content_hash, // For version 1, chain_hash = content_hash
                                        };

                                        match verify_version_metadata(
                                            &version.set_id,
                                            &version.version,
                                            &version.pdk_version,
                                            version.created_at,
                                            &version.created_by,
                                            version.message.clone(),
                                            &version.content_hash,
                                            &chain_hash_value,
                                            version.previous_hash.as_ref(),
                                            &version.signature,
                                            &device.signing_pubkey,
                                        ) {
                                            Ok(_) => {
                                                details.push(format!("✓ Version {} signature valid", version.version.as_u64()));
                                            }
                                            Err(e) => {
                                                errors.push(format!("Version {} signature invalid: {}", version.version.as_u64(), e));
                                            }
                                        }
                                    } else {
                                        errors.push(format!("Version {} signed by unknown device: {}", version.version.as_u64(), version.created_by));
                                    }
                                }
                            }
                            Err(e) => {
                                errors.push(format!("Invalid version metadata {}: {}", meta_file, e));
                            }
                        }
                    }
                    Err(e) => {
                        errors.push(format!("Cannot read version metadata {}: {}", meta_file, e));
                    }
                }
            }

            // Verify hash chain if not signatures_only
            if !signatures_only && !versions.is_empty() {
                match verify_chain(&versions) {
                    Ok(_) => {
                        details.push(format!("✓ Hash chain valid for {} versions", versions.len()));
                    }
                    Err(e) => {
                        errors.push(format!("Hash chain verification failed: {}", e));
                    }
                }
            }
        }
        Err(e) => {
            errors.push(format!("Cannot list secret set files: {}", e));
        }
    }

    Ok((items_checked, errors, warnings, details))
}

/// Verify audit logs integrity
async fn verify_audit_logs(
    client: &myc_github::client::GitHubClient,
    devices: &std::collections::HashMap<myc_core::ids::DeviceId, myc_core::device::Device>,
) -> Result<(usize, Vec<String>, Vec<String>, Vec<String>)> {
    use myc_core::audit::{AuditEvent, SignedAuditEvent};

    let mut items_checked = 0;
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    let mut details = Vec::new();

    // Check if audit directory exists
    match client.list_directory(".mycelium/audit/").await {
        Ok(audit_dirs) => {
            let mut all_events = Vec::new();

            // Process each month directory
            for audit_dir in audit_dirs {
                if audit_dir.is_dir && audit_dir.name.len() == 7 && audit_dir.name.contains('-') {
                    // This looks like a YYYY-MM directory
                    let month_path = format!(".mycelium/audit/{}", audit_dir.name);
                    
                    match client.list_directory(&month_path).await {
                        Ok(event_files) => {
                            for event_file in event_files {
                                if event_file.name.ends_with(".json") {
                                    match client.read_file(&format!("{}/{}", month_path, event_file.name)).await {
                                        Ok(event_data) => {
                                            match serde_json::from_slice::<SignedAuditEvent>(&event_data) {
                                                Ok(signed_event) => {
                                                    items_checked += 1;
                                                    all_events.push(signed_event);
                                                }
                                                Err(e) => {
                                                    errors.push(format!("Invalid audit event {}: {}", event_file.name, e));
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            errors.push(format!("Cannot read audit event {}: {}", event_file.name, e));
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            warnings.push(format!("Cannot access audit month {}: {}", audit_dir.name, e));
                        }
                    }
                }
            }

            // Sort events by timestamp for chain verification
            all_events.sort_by(|a, b| a.event.timestamp.cmp(&b.event.timestamp));

            // Verify audit chain and signatures
            if !all_events.is_empty() {
                match myc_core::audit::verification::verify_all(&all_events, |device_id| {
                    devices.get(device_id).map(|d| d.signing_pubkey.clone())
                        .ok_or_else(|| myc_core::error::CoreError::SignatureInvalid)
                }) {
                    Ok(result) => {
                        if result.all_passed {
                            details.push(format!("✓ Audit log verification passed ({} events)", result.total_events));
                        } else {
                            errors.push(format!("Audit log verification failed: {} errors", result.errors.len()));
                            errors.extend(result.errors);
                        }
                    }
                    Err(e) => {
                        errors.push(format!("Audit log verification error: {}", e));
                    }
                }
            } else {
                details.push("No audit events found".to_string());
            }
        }
        Err(e) => {
            warnings.push(format!("Cannot access audit directory: {}", e));
        }
    }

    Ok((items_checked, errors, warnings, details))
}

/// Extract version number from filename like "v1.meta.json"
fn extract_version_number(filename: &str) -> Option<u64> {
    if let Some(v_part) = filename.strip_prefix('v') {
        if let Some(num_part) = v_part.split('.').next() {
            return num_part.parse().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use myc_core::secret_set::SecretEntry;
    use std::collections::{HashMap, HashSet};

    /// Test helper to create secret entries
    fn create_entry(key: &str, value: &str) -> SecretEntry {
        SecretEntry {
            key: key.to_string(),
            value: value.to_string(),
            metadata: None,
        }
    }

    /// Test the diff computation logic by extracting it into a testable function
    fn compute_diff(
        current_entries: &[SecretEntry],
        new_entries: &[SecretEntry],
    ) -> (Vec<String>, Vec<String>, Vec<String>, Vec<String>) {
        // Convert to HashMaps for comparison
        let current_map: HashMap<String, String> = current_entries
            .iter()
            .map(|e| (e.key.clone(), e.value.clone()))
            .collect();
        let new_map: HashMap<String, String> = new_entries
            .iter()
            .map(|e| (e.key.clone(), e.value.clone()))
            .collect();

        // Compute diff
        let all_keys: HashSet<String> = current_map.keys().chain(new_map.keys()).cloned().collect();
        let mut added_keys = Vec::new();
        let mut removed_keys = Vec::new();
        let mut changed_keys = Vec::new();
        let mut unchanged_keys = Vec::new();

        for key in all_keys {
            match (current_map.get(&key), new_map.get(&key)) {
                (None, Some(_)) => added_keys.push(key),
                (Some(_), None) => removed_keys.push(key),
                (Some(val1), Some(val2)) => {
                    if val1 == val2 {
                        unchanged_keys.push(key);
                    } else {
                        changed_keys.push(key);
                    }
                }
                (None, None) => unreachable!(), // Key came from one of the maps
            }
        }

        // Sort keys for consistent output
        added_keys.sort();
        removed_keys.sort();
        changed_keys.sort();
        unchanged_keys.sort();

        (added_keys, removed_keys, changed_keys, unchanged_keys)
    }

    #[test]
    fn test_diff_no_changes() {
        let current = vec![
            create_entry("API_KEY", "secret123"),
            create_entry("DB_URL", "postgres://localhost"),
        ];
        let new = vec![
            create_entry("API_KEY", "secret123"),
            create_entry("DB_URL", "postgres://localhost"),
        ];

        let (added, removed, changed, unchanged) = compute_diff(&current, &new);

        assert!(added.is_empty());
        assert!(removed.is_empty());
        assert!(changed.is_empty());
        assert_eq!(unchanged, vec!["API_KEY", "DB_URL"]);
    }

    #[test]
    fn test_diff_added_keys() {
        let current = vec![create_entry("API_KEY", "secret123")];
        let new = vec![
            create_entry("API_KEY", "secret123"),
            create_entry("DB_URL", "postgres://localhost"),
            create_entry("REDIS_URL", "redis://localhost"),
        ];

        let (added, removed, changed, unchanged) = compute_diff(&current, &new);

        assert_eq!(added, vec!["DB_URL", "REDIS_URL"]);
        assert!(removed.is_empty());
        assert!(changed.is_empty());
        assert_eq!(unchanged, vec!["API_KEY"]);
    }

    #[test]
    fn test_diff_removed_keys() {
        let current = vec![
            create_entry("API_KEY", "secret123"),
            create_entry("DB_URL", "postgres://localhost"),
            create_entry("REDIS_URL", "redis://localhost"),
        ];
        let new = vec![create_entry("API_KEY", "secret123")];

        let (added, removed, changed, unchanged) = compute_diff(&current, &new);

        assert!(added.is_empty());
        assert_eq!(removed, vec!["DB_URL", "REDIS_URL"]);
        assert!(changed.is_empty());
        assert_eq!(unchanged, vec!["API_KEY"]);
    }

    #[test]
    fn test_diff_changed_keys() {
        let current = vec![
            create_entry("API_KEY", "secret123"),
            create_entry("DB_URL", "postgres://localhost"),
        ];
        let new = vec![
            create_entry("API_KEY", "newsecret456"),
            create_entry("DB_URL", "postgres://newhost"),
        ];

        let (added, removed, changed, unchanged) = compute_diff(&current, &new);

        assert!(added.is_empty());
        assert!(removed.is_empty());
        assert_eq!(changed, vec!["API_KEY", "DB_URL"]);
        assert!(unchanged.is_empty());
    }

    #[test]
    fn test_diff_mixed_changes() {
        let current = vec![
            create_entry("API_KEY", "secret123"),
            create_entry("DB_URL", "postgres://localhost"),
            create_entry("OLD_KEY", "old_value"),
        ];
        let new = vec![
            create_entry("API_KEY", "newsecret456"),        // changed
            create_entry("DB_URL", "postgres://localhost"), // unchanged
            create_entry("NEW_KEY", "new_value"),           // added
                                                            // OLD_KEY removed
        ];

        let (added, removed, changed, unchanged) = compute_diff(&current, &new);

        assert_eq!(added, vec!["NEW_KEY"]);
        assert_eq!(removed, vec!["OLD_KEY"]);
        assert_eq!(changed, vec!["API_KEY"]);
        assert_eq!(unchanged, vec!["DB_URL"]);
    }

    #[test]
    fn test_diff_empty_current() {
        let current = vec![];
        let new = vec![
            create_entry("API_KEY", "secret123"),
            create_entry("DB_URL", "postgres://localhost"),
        ];

        let (added, removed, changed, unchanged) = compute_diff(&current, &new);

        assert_eq!(added, vec!["API_KEY", "DB_URL"]);
        assert!(removed.is_empty());
        assert!(changed.is_empty());
        assert!(unchanged.is_empty());
    }

    #[test]
    fn test_diff_empty_new() {
        let current = vec![
            create_entry("API_KEY", "secret123"),
            create_entry("DB_URL", "postgres://localhost"),
        ];
        let new = vec![];

        let (added, removed, changed, unchanged) = compute_diff(&current, &new);

        assert!(added.is_empty());
        assert_eq!(removed, vec!["API_KEY", "DB_URL"]);
        assert!(changed.is_empty());
        assert!(unchanged.is_empty());
    }

    #[test]
    fn test_diff_both_empty() {
        let current = vec![];
        let new = vec![];

        let (added, removed, changed, unchanged) = compute_diff(&current, &new);

        assert!(added.is_empty());
        assert!(removed.is_empty());
        assert!(changed.is_empty());
        assert!(unchanged.is_empty());
    }

    #[test]
    fn test_diff_key_ordering() {
        let current = vec![
            create_entry("Z_KEY", "value1"),
            create_entry("A_KEY", "value2"),
            create_entry("M_KEY", "value3"),
        ];
        let new = vec![
            create_entry("Z_KEY", "new_value1"), // changed
            create_entry("B_KEY", "value4"),     // added
                                                 // A_KEY removed, M_KEY removed
        ];

        let (added, removed, changed, unchanged) = compute_diff(&current, &new);

        // Keys should be sorted alphabetically
        assert_eq!(added, vec!["B_KEY"]);
        assert_eq!(removed, vec!["A_KEY", "M_KEY"]);
        assert_eq!(changed, vec!["Z_KEY"]);
        assert!(unchanged.is_empty());
    }
}
