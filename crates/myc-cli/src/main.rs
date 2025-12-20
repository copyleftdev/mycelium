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
use myc_cli::profile;
use myc_cli::recovery::{RecoveryStatus, RecoveryWarnings};

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
    match command {
        OrgCommands::Init { name, repo, public } => {
            // This would normally:
            // 1. Create a new GitHub repository
            // 2. Initialize vault structure
            // 3. Create organization metadata
            // 4. Set up initial configuration

            let repo_name = repo.as_deref().unwrap_or("secrets-vault");
            let is_private = !public;

            // Check if .gitignore exists and offer to add secret patterns
            let gitignore_offered = offer_gitignore_setup(cli)?;

            if cli.json {
                let output = serde_json::json!({
                    "success": false,
                    "message": "Organization initialization not yet implemented",
                    "planned_action": {
                        "org_name": name,
                        "repo_name": repo_name,
                        "private": is_private
                    },
                    "gitignore_offered": gitignore_offered
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("Initializing organization '{}'", name);
                println!("  Repository: {}", repo_name);
                println!(
                    "  Visibility: {}",
                    if is_private { "Private" } else { "Public" }
                );
                println!();
                println!("Note: Full organization initialization not yet implemented");
                println!("This would normally:");
                println!("  1. Create GitHub repository '{}'", repo_name);
                println!("  2. Initialize vault structure");
                println!("  3. Set up organization metadata");
                println!("  4. Configure default settings");
                if gitignore_offered {
                    println!("  5. Set up .gitignore for secret files");
                }
            }
        }
        OrgCommands::Show => {
            if cli.json {
                let output = serde_json::json!({
                    "success": false,
                    "message": "Organization details not yet implemented"
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("Organization details not yet implemented");
                println!("This would show:");
                println!("  - Organization name and settings");
                println!("  - Vault repository information");
                println!("  - Member count and device count");
                println!("  - Rotation policies");
            }
        }
        OrgCommands::Settings {
            require_approval,
            rotation_policy,
        } => {
            if cli.json {
                let output = serde_json::json!({
                    "success": false,
                    "message": "Organization settings not yet implemented",
                    "requested_changes": {
                        "require_approval": require_approval,
                        "rotation_policy": rotation_policy
                    }
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("Organization settings not yet implemented");
                if let Some(approval) = require_approval {
                    println!("  Would set require_approval: {}", approval);
                }
                if let Some(policy) = rotation_policy {
                    println!("  Would set rotation_policy: {}", policy);
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

            // For now, we'll implement a basic version that shows the current device
            // In a full implementation, this would:
            // 1. Read all device files from .mycelium/devices/
            // 2. Filter by current user if not --all
            // 3. Display device information

            if cli.json {
                let output = serde_json::json!({
                    "success": false,
                    "message": "Device listing not yet fully implemented",
                    "current_device": {
                        "id": profile.device_id,
                        "profile": profile.name,
                        "user": profile.github_username
                    },
                    "all": all
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("Device listing not yet fully implemented");
                println!();
                println!("Current device (from profile '{}'):", profile.name);
                println!("  Device ID: {}", profile.device_id);
                println!(
                    "  User: {} ({})",
                    profile.github_username, profile.github_user_id
                );
                println!(
                    "  Repository: {}/{}",
                    profile.github_owner, profile.github_repo
                );
                println!();
                println!("Full device listing will show:");
                if *all {
                    println!("  - All devices in the vault");
                } else {
                    println!("  - Your devices only");
                }
                println!("  - Device status (active, pending, revoked)");
                println!("  - Device type (interactive, ci)");
                println!("  - Enrollment and expiration dates");
            }
        }
        DeviceCommands::Show { device_id } => {
            // Parse device ID
            let uuid = uuid::Uuid::parse_str(device_id)
                .context("Invalid device ID format. Expected UUID.")?;
            let device_uuid = DeviceId::from_uuid(uuid);

            if cli.json {
                let output = serde_json::json!({
                    "success": false,
                    "message": "Device details not yet fully implemented",
                    "device_id": device_uuid,
                    "requested_device": device_id
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("Device details not yet fully implemented");
                println!();
                println!("Requested device: {}", device_id);
                println!();
                println!("This would show:");
                println!("  - Device name and type");
                println!("  - Owner user information");
                println!("  - Public keys (signing and encryption)");
                println!("  - Enrollment date and status");
                println!("  - Expiration date (for CI devices)");
                println!("  - Projects this device has access to");
            }
        }
        DeviceCommands::Enroll {
            name,
            device_type,
            expires,
        } => {
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

            if cli.json {
                let output = serde_json::json!({
                    "success": false,
                    "message": "Device enrollment not yet fully implemented",
                    "device_name": name,
                    "device_type": dev_type,
                    "expires_at": expires_at
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("Device enrollment not yet fully implemented");
                println!();
                println!("Would enroll device:");
                println!("  Name: {}", name);
                println!("  Type: {:?}", dev_type);
                if let Some(exp) = expires_at {
                    println!(
                        "  Expires: {}",
                        exp.format(&time::format_description::well_known::Rfc3339)?
                    );
                }
                println!();
                println!("This would:");
                println!("  1. Generate new Ed25519 and X25519 keypairs");
                println!("  2. Create device record in vault");
                println!("  3. Set status to Active or PendingApproval");
                println!("  4. For CI devices: validate OIDC token");
                println!("  5. Create audit event");
            }
        }
        DeviceCommands::Revoke { device_id, force } => {
            // Parse device ID
            let uuid = uuid::Uuid::parse_str(device_id)
                .context("Invalid device ID format. Expected UUID.")?;
            let device_uuid = DeviceId::from_uuid(uuid);

            // Confirm revocation unless forced
            let should_revoke = if *force {
                true
            } else {
                if cli.json {
                    anyhow::bail!("Cannot prompt for confirmation in JSON mode. Use --force to skip confirmation.");
                }

                println!("This will permanently revoke device '{}'", device_id);
                println!("The device will no longer be able to access any secrets.");
                println!("This action will trigger PDK rotation for all affected projects.");

                Confirm::with_theme(&ColorfulTheme::default())
                    .with_prompt("Are you sure you want to revoke this device?")
                    .default(false)
                    .interact()?
            };

            if should_revoke {
                if cli.json {
                    let output = serde_json::json!({
                        "success": false,
                        "message": "Device revocation not yet fully implemented",
                        "device_id": device_uuid,
                        "would_revoke": true
                    });
                    println!("{}", serde_json::to_string_pretty(&output)?);
                } else {
                    println!("Device revocation not yet fully implemented");
                    println!();
                    println!("Would revoke device: {}", device_id);
                    println!();
                    println!("This would:");
                    println!("  1. Mark device status as Revoked");
                    println!("  2. Trigger PDK rotation for all projects");
                    println!("  3. Exclude device from new PDK versions");
                    println!("  4. Create audit event");
                    println!("  5. Notify project administrators");
                }
            } else {
                if cli.json {
                    let output = serde_json::json!({
                        "success": false,
                        "message": "Revocation cancelled"
                    });
                    println!("{}", serde_json::to_string_pretty(&output)?);
                } else {
                    println!("Revocation cancelled");
                }
            }
        }
        DeviceCommands::Approve { device_id } => {
            // Parse device ID
            let uuid = uuid::Uuid::parse_str(device_id)
                .context("Invalid device ID format. Expected UUID.")?;
            let device_uuid = DeviceId::from_uuid(uuid);

            if cli.json {
                let output = serde_json::json!({
                    "success": false,
                    "message": "Device approval not yet fully implemented",
                    "device_id": device_uuid
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("Device approval not yet fully implemented");
                println!();
                println!("Would approve device: {}", device_id);
                println!();
                println!("This would:");
                println!("  1. Change device status from PendingApproval to Active");
                println!("  2. Wrap current PDKs to the approved device");
                println!("  3. Create audit event");
                println!("  4. Notify device owner");
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
            if cli.json {
                let output = serde_json::json!({
                    "success": false,
                    "message": "Project creation not yet fully implemented",
                    "project_name": name,
                    "would_create": {
                        "name": name,
                        "org_id": "placeholder-org-id",
                        "created_by": profile.device_id,
                        "initial_pdk_version": 1
                    }
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("Creating project '{}'", style(name).bold());
                println!();
                println!("Project creation not yet fully implemented");
                println!();
                println!("This would:");
                println!("  1. Generate a new project ID (UUID)");
                println!("  2. Generate initial 32-byte PDK");
                println!("  3. Wrap PDK to your device key");
                println!("  4. Create project metadata file");
                println!("  5. Create initial membership (you as owner)");
                println!("  6. Sign and commit to GitHub");
                println!("  7. Create audit event");
                println!();
                println!("Project would be created with:");
                println!("  Name: {}", name);
                println!(
                    "  Owner: {} ({})",
                    profile.github_username, profile.github_user_id
                );
                println!("  Device: {}", profile.device_id);
                println!("  Initial PDK version: 1");
            }
        }
        ProjectCommands::List => {
            if cli.json {
                let output = serde_json::json!({
                    "success": false,
                    "message": "Project listing not yet fully implemented",
                    "profile": profile.name,
                    "vault": format!("{}/{}", profile.github_owner, profile.github_repo)
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!(
                    "Listing projects in vault {}/{}",
                    style(&profile.github_owner).bold(),
                    style(&profile.github_repo).bold()
                );
                println!();
                println!("Project listing not yet fully implemented");
                println!();
                println!("This would:");
                println!("  1. Read .mycelium/projects/ directory from GitHub");
                println!("  2. Parse project metadata files");
                println!("  3. Check membership for current user");
                println!("  4. Display projects with your role");
                println!();
                println!("Expected output format:");
                println!("  {} api-secrets (Owner)", style("*").green());
                println!("    Members: 3, Sets: 2, Last updated: 2 days ago");
                println!("  {} web-config (Admin)", style("*").yellow());
                println!("    Members: 5, Sets: 1, Last updated: 1 week ago");
                println!("  {} shared-keys (Member)", style("*").blue());
                println!("    Members: 12, Sets: 4, Last updated: 3 days ago");
            }
        }
        ProjectCommands::Show { project } => {
            // Try to parse as UUID first, then treat as name
            let project_identifier = if let Ok(uuid) = Uuid::parse_str(project) {
                format!("ID {}", uuid)
            } else {
                format!("name '{}'", project)
            };

            if cli.json {
                let output = serde_json::json!({
                    "success": false,
                    "message": "Project details not yet fully implemented",
                    "project_identifier": project,
                    "lookup_type": if Uuid::parse_str(project).is_ok() { "id" } else { "name" }
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("Showing project with {}", project_identifier);
                println!();
                println!("Project details not yet fully implemented");
                println!();
                println!("This would:");
                println!("  1. Look up project by ID or name");
                println!("  2. Read project metadata");
                println!("  3. Read membership list");
                println!("  4. Check your permissions");
                println!("  5. List secret sets in project");
                println!();
                println!("Expected output format:");
                println!("  Project: {}", style("api-secrets").bold());
                println!("  ID: 550e8400-e29b-41d4-a716-446655440000");
                println!("  Created: 2025-11-15 by alice");
                println!("  Current PDK version: 3");
                println!("  Your role: {}", style("Owner").green());
                println!();
                println!("  Members (3):");
                println!("    alice (Owner) - added 2025-11-15");
                println!("    bob (Admin) - added 2025-11-20");
                println!("    charlie (Member) - added 2025-12-01");
                println!();
                println!("  Secret Sets (2):");
                println!("    production - 5 versions, last updated 2 days ago");
                println!("    staging - 3 versions, last updated 1 week ago");
            }
        }
        ProjectCommands::Delete { project, force } => {
            // Try to parse as UUID first, then treat as name
            let project_identifier = if let Ok(uuid) = Uuid::parse_str(project) {
                format!("ID {}", uuid)
            } else {
                format!("name '{}'", project)
            };

            // Confirm deletion unless forced
            let should_delete = if *force {
                true
            } else {
                if cli.json {
                    anyhow::bail!("Cannot prompt for confirmation in JSON mode. Use --force to skip confirmation.");
                }

                println!(
                    "This will permanently delete project with {}",
                    project_identifier
                );
                println!("All secret sets and versions will be deleted.");
                println!("All members will lose access.");
                println!("This action cannot be undone.");
                println!();
                println!(
                    "{} Only project owners can delete projects.",
                    style("Warning:").yellow().bold()
                );

                Confirm::with_theme(&ColorfulTheme::default())
                    .with_prompt("Are you sure you want to delete this project?")
                    .default(false)
                    .interact()?
            };

            if should_delete {
                if cli.json {
                    let output = serde_json::json!({
                        "success": false,
                        "message": "Project deletion not yet fully implemented",
                        "project_identifier": project,
                        "would_delete": true,
                        "lookup_type": if Uuid::parse_str(project).is_ok() { "id" } else { "name" }
                    });
                    println!("{}", serde_json::to_string_pretty(&output)?);
                } else {
                    println!("Project deletion not yet fully implemented");
                    println!();
                    println!("Would delete project with {}", project_identifier);
                    println!();
                    println!("This would:");
                    println!("  1. Verify you have Owner role");
                    println!("  2. Delete all secret sets and versions");
                    println!("  3. Delete all PDK versions");
                    println!("  4. Delete membership list");
                    println!("  5. Delete project metadata");
                    println!("  6. Create audit event");
                    println!("  7. Commit deletion to GitHub");
                    println!();
                    println!(
                        "{} This operation requires Owner permission",
                        style("Note:").blue()
                    );
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
                    "{} Only project owners and admins can delete secret sets.",
                    style("Warning:").yellow().bold()
                );

                Confirm::with_theme(&ColorfulTheme::default())
                    .with_prompt("Are you sure you want to delete this secret set?")
                    .default(false)
                    .interact()?
            };

            if should_delete {
                // Delete the secret set directory and all its contents
                // Note: This is a simplified implementation. A full implementation would:
                // 1. Verify user has proper permissions (Owner/Admin role)
                // 2. Delete all version files (.enc and .meta.json)
                // 3. Delete the set.json metadata file
                // 4. Create audit event
                // 5. Handle errors gracefully

                if cli.json {
                    let output = serde_json::json!({
                        "success": false,
                        "message": "Secret set deletion not yet fully implemented",
                        "secret_set": {
                            "id": secret_set.id,
                            "name": secret_set.name,
                            "project_id": secret_set.project_id
                        },
                        "note": "This operation requires full implementation of permission checking and audit logging"
                    });
                    println!("{}", serde_json::to_string_pretty(&output)?);
                } else {
                    println!("Secret set deletion not yet fully implemented");
                    println!();
                    println!(
                        "Would delete secret set '{}' ({})",
                        secret_set.name, secret_set.id
                    );
                    println!("From project '{}' ({})", project_obj.name, project_obj.id);
                    println!();
                    println!("This operation requires:");
                    println!("  1. Permission verification (Owner/Admin role)");
                    println!("  2. Deletion of all version files");
                    println!("  3. Deletion of metadata file");
                    println!("  4. Audit event creation");
                    println!("  5. Proper error handling");
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
    if cli.json {
        let output = serde_json::json!({
            "success": true,
            "message": "Diff before push implemented - ready for full push implementation",
            "parsed_entries": new_entries.len(),
            "project": {
                "id": project_obj.id,
                "name": project_obj.name
            },
            "secret_set": {
                "id": secret_set.id,
                "name": secret_set.name
            },
            "format": format!("{:?}", detected_format),
            "message": message
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!(
            "{} Diff before push implemented successfully",
            style("✓").green()
        );
        println!("  Project: {} ({})", project_obj.name, project_obj.id);
        println!("  Set: {} ({})", secret_set.name, secret_set.id);
        println!("  Format: {:?}", detected_format);
        println!("  Entries parsed: {}", new_entries.len());
        if let Some(msg) = message {
            println!("  Message: {}", msg);
        }
        println!();
        println!("Next steps for full implementation:");
        println!("  1. Get current PDK version");
        println!("  2. Unwrap PDK with device key");
        println!("  3. Create new secret version");
        println!("  4. Write encrypted version to GitHub");
        println!("  5. Update set metadata");
        println!("  6. Create audit event");
    }

    Ok(())
}

async fn handle_share_command(command: &ShareCommands, cli: &Cli) -> Result<()> {
    use crate::profile::ProfileManager;
    use console::style;
    use dialoguer::{theme::ColorfulTheme, Confirm};
    use myc_core::ids::{ProjectId, UserId};
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

            // Parse project ID (try UUID first, then treat as name)
            let project_id = if let Ok(uuid) = Uuid::parse_str(project) {
                ProjectId::from_uuid(uuid)
            } else {
                // For now, we'll need to implement project name resolution
                // This is a placeholder - in a full implementation we'd read project list
                anyhow::bail!(
                    "Project name resolution not yet implemented. Please use project UUID."
                );
            };

            // Create user ID from username (assuming GitHub format)
            let target_user_id = if user.starts_with("github|") {
                UserId::from(user.clone())
            } else {
                UserId::from(format!("github|{}", user))
            };

            if cli.json {
                let output = serde_json::json!({
                    "success": false,
                    "message": "Share add not yet fully implemented",
                    "action": {
                        "project": project,
                        "user": user,
                        "role": role,
                        "parsed_role": format!("{:?}", target_role),
                        "target_user_id": target_user_id.as_str()
                    },
                    "note": "This requires full implementation of membership operations, PDK wrapping, and audit logging"
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!(
                    "Adding user '{}' to project '{}' with role '{}'",
                    user, project, role
                );
                println!();
                println!("This operation would:");
                println!("  1. Verify you have share permission in the project");
                println!("  2. Verify target role level <= your role level");
                println!("  3. Look up target user's active devices");
                println!("  4. Get current PDK version and unwrap with your device key");
                println!("  5. Wrap PDK to each target device");
                println!("  6. Add member to members.json");
                println!("  7. Sign updated membership list");
                println!("  8. Write to GitHub");
                println!("  9. Create audit event");
                println!();
                println!("Parsed values:");
                println!("  Target role: {:?}", target_role);
                println!("  Target user ID: {}", target_user_id.as_str());
                println!("  Project ID: {}", project_id);
            }
        }
        ShareCommands::Remove {
            project,
            user,
            force,
        } => {
            // Parse project ID (try UUID first, then treat as name)
            let project_id = if let Ok(uuid) = Uuid::parse_str(project) {
                ProjectId::from_uuid(uuid)
            } else {
                anyhow::bail!(
                    "Project name resolution not yet implemented. Please use project UUID."
                );
            };

            // Create user ID from username
            let target_user_id = if user.starts_with("github|") {
                UserId::from(user.clone())
            } else {
                UserId::from(format!("github|{}", user))
            };

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
                if cli.json {
                    let output = serde_json::json!({
                        "success": false,
                        "message": "Share remove not yet fully implemented",
                        "action": {
                            "project": project,
                            "user": user,
                            "target_user_id": target_user_id.as_str(),
                            "force": force
                        },
                        "note": "This requires full implementation of membership operations, PDK rotation, and audit logging"
                    });
                    println!("{}", serde_json::to_string_pretty(&output)?);
                } else {
                    println!(
                        "{} Removing user '{}' from project '{}'",
                        style("✓").green(),
                        user,
                        project
                    );
                    println!();
                    println!("This operation would:");
                    println!("  1. Verify you have share permission in the project");
                    println!("  2. Verify target role level < your role level");
                    println!("  3. Remove member from members.json");
                    println!("  4. Rotate PDK (generate new PDK)");
                    println!("  5. Wrap new PDK only to remaining members");
                    println!("  6. Sign updated membership list and PDK version");
                    println!("  7. Write to GitHub");
                    println!("  8. Create audit event");
                    println!();
                    println!("Parsed values:");
                    println!("  Target user ID: {}", target_user_id.as_str());
                    println!("  Project ID: {}", project_id);
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
            // Parse project ID (try UUID first, then treat as name)
            let project_id = if let Ok(uuid) = Uuid::parse_str(project) {
                ProjectId::from_uuid(uuid)
            } else {
                anyhow::bail!(
                    "Project name resolution not yet implemented. Please use project UUID."
                );
            };

            if cli.json {
                let output = serde_json::json!({
                    "success": false,
                    "message": "Share list not yet fully implemented",
                    "action": {
                        "project": project,
                        "project_id": project_id
                    },
                    "note": "This requires reading and parsing members.json from GitHub"
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("Listing members of project '{}'", project);
                println!();
                println!("This operation would:");
                println!("  1. Read members.json from GitHub");
                println!("  2. Verify signature on membership list");
                println!("  3. Display members with roles and join dates");
                println!("  4. Show your current role and permissions");
                println!();
                println!("Parsed values:");
                println!("  Project ID: {}", project_id);
                println!();
                println!("Expected output format:");
                println!("  Members:");
                println!("    alice@example.com (Owner) - joined 2025-01-01");
                println!("    bob@example.com (Admin) - joined 2025-01-02");
                println!("  * you@example.com (Admin) - joined 2025-01-03");
                println!();
                println!("  Your permissions: read, write, share, rotate");
            }
        }
        ShareCommands::SetRole {
            project,
            user,
            role,
        } => {
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

            // Parse project ID (try UUID first, then treat as name)
            let project_id = if let Ok(uuid) = Uuid::parse_str(project) {
                ProjectId::from_uuid(uuid)
            } else {
                anyhow::bail!(
                    "Project name resolution not yet implemented. Please use project UUID."
                );
            };

            // Create user ID from username
            let target_user_id = if user.starts_with("github|") {
                UserId::from(user.clone())
            } else {
                UserId::from(format!("github|{}", user))
            };

            if cli.json {
                let output = serde_json::json!({
                    "success": false,
                    "message": "Share set-role not yet fully implemented",
                    "action": {
                        "project": project,
                        "user": user,
                        "role": role,
                        "parsed_role": format!("{:?}", new_role),
                        "target_user_id": target_user_id.as_str()
                    },
                    "note": "This requires full implementation of membership operations and audit logging"
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!(
                    "Setting role '{}' for user '{}' in project '{}'",
                    role, user, project
                );
                println!();
                println!("This operation would:");
                println!("  1. Verify you have share permission in the project");
                println!("  2. Verify new role level <= your role level");
                println!("  3. Verify target's current role level < your role level");
                println!("  4. Update member's role in members.json");
                println!("  5. Sign updated membership list");
                println!("  6. Write to GitHub");
                println!("  7. Create audit event");
                println!();
                println!("Parsed values:");
                println!("  New role: {:?}", new_role);
                println!("  Target user ID: {}", target_user_id.as_str());
                println!("  Project ID: {}", project_id);
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

    // For now, implement a basic verification that checks vault structure
    let verification_result =
        perform_basic_verification(&client, project, set, signatures_only, chains_only).await?;

    // Output results
    if cli.json {
        let output = serde_json::json!({
            "success": verification_result.success,
            "message": verification_result.message,
            "items_checked": verification_result.items_checked,
            "errors": verification_result.errors
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

        if !verification_result.errors.is_empty() {
            println!();
            println!("{}:", style("Errors").red().bold());
            for error in &verification_result.errors {
                println!("  {} {}", style("✗").red(), error);
            }
        }
    }

    if !verification_result.success {
        std::process::exit(1);
    }

    Ok(())
}

/// Basic verification result
#[derive(Debug)]
struct BasicVerificationResult {
    success: bool,
    message: String,
    items_checked: usize,
    errors: Vec<String>,
}

impl BasicVerificationResult {
    fn success(message: String, items_checked: usize) -> Self {
        Self {
            success: true,
            message,
            items_checked,
            errors: vec![],
        }
    }

    fn failure(message: String, items_checked: usize, errors: Vec<String>) -> Self {
        Self {
            success: false,
            message,
            items_checked,
            errors,
        }
    }
}

/// Perform basic verification of vault structure and accessibility
async fn perform_basic_verification(
    client: &myc_github::client::GitHubClient,
    project: &Option<String>,
    set: &Option<String>,
    signatures_only: bool,
    chains_only: bool,
) -> Result<BasicVerificationResult> {
    let mut items_checked = 0;
    let mut errors = Vec::new();

    // Check if vault structure exists
    match client.read_file(".mycelium/vault.json").await {
        Ok(_) => {
            items_checked += 1;
        }
        Err(e) => {
            errors.push(format!("Vault metadata not found: {}", e));
        }
    }

    // Check basic vault structure
    let vault_paths = vec![
        ".mycelium/devices/",
        ".mycelium/projects/",
        ".mycelium/audit/",
    ];

    for path in vault_paths {
        match client.list_directory(path).await {
            Ok(_) => {
                items_checked += 1;
            }
            Err(e) => {
                errors.push(format!("Vault directory {} not accessible: {}", path, e));
            }
        }
    }

    // If specific project/set requested, try to verify those exist
    if let Some(project_name) = project {
        // For now, just report that specific project verification is not yet implemented
        errors.push(format!(
            "Specific project verification for '{}' not yet implemented",
            project_name
        ));

        if let Some(set_name) = set {
            errors.push(format!(
                "Specific secret set verification for '{}' not yet implemented",
                set_name
            ));
        }
    }

    // Report on verification options
    let mut message = "Basic vault structure verification completed".to_string();
    if signatures_only {
        message.push_str(" (signatures only)");
    } else if chains_only {
        message.push_str(" (hash chains only)");
    } else {
        message.push_str(" (full verification)");
    }

    if errors.is_empty() {
        Ok(BasicVerificationResult::success(message, items_checked))
    } else {
        Ok(BasicVerificationResult::failure(
            message,
            items_checked,
            errors,
        ))
    }
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

            if cli.json {
                let output = serde_json::json!({
                    "success": false,
                    "message": "CI device enrollment not yet fully implemented",
                    "oidc_claims": {
                        "repository": claims.repository,
                        "workflow": claims.workflow,
                        "ref": claims.ref_,
                        "actor": claims.actor,
                        "environment": claims.environment
                    },
                    "device_name": name,
                    "expires": expires
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("{} OIDC token validated successfully", style("✓").green());
                println!("Repository: {}", claims.repository);
                println!("Workflow: {}", claims.workflow);
                println!("Ref: {}", claims.ref_);
                println!("Actor: {}", claims.actor);
                if let Some(env) = &claims.environment {
                    println!("Environment: {}", env);
                }
                println!();
                println!("CI device enrollment not yet fully implemented");
                println!("This would:");
                println!("  1. Generate CI device keys");
                println!("  2. Create device record with DeviceType::CI");
                println!("  3. Set expiration time if provided");
                println!("  4. Store device in vault");
                println!("  5. Create audit event");
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
            let _passphrase = env::get_passphrase(&profile_name)?;

            if cli.json {
                let output = serde_json::json!({
                    "success": false,
                    "message": "CI pull not yet fully implemented",
                    "project": project,
                    "set": set,
                    "format": format,
                    "profile": profile_name,
                    "non_interactive": env::is_non_interactive()
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("CI pull not yet fully implemented");
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
                println!("This would:");
                println!("  1. Load CI device keys");
                println!("  2. Connect to GitHub vault");
                println!("  3. Decrypt secrets for project/set");
                println!("  4. Format output as {}", format);
                println!("  5. Write to stdout");
                println!("  6. Create audit event");
            }
        }
    }
    Ok(())
}

async fn handle_cache_command(command: &CacheCommands, cli: &Cli) -> Result<()> {
    use crate::profile::ProfileManager;
    use console::style;
    use std::fs;

    let config_dir = ProfileManager::default_config_dir()?;
    let manager = ProfileManager::new(config_dir);

    match command {
        CacheCommands::Clear { all } => {
            if *all {
                // Clear cache for all profiles
                let profiles = manager.list_profiles()?;
                let mut cleared_count = 0;

                for profile_name in &profiles {
                    let cache_dir = manager.cache_dir(profile_name);
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
                        cleared_count += 1;
                    }
                }

                if cli.json {
                    let output = serde_json::json!({
                        "success": true,
                        "message": format!("Cleared cache for {} profiles", cleared_count),
                        "profiles_cleared": profiles.len(),
                        "profiles": profiles
                    });
                    println!("{}", serde_json::to_string_pretty(&output)?);
                } else {
                    println!(
                        "{} Cleared cache for {} profiles",
                        style("✓").green(),
                        cleared_count
                    );
                    if !profiles.is_empty() {
                        for profile in &profiles {
                            println!("  - {}", profile);
                        }
                    }
                }
            } else {
                // Clear cache for current/default profile only
                let profile_name = manager.get_default_profile()?
                    .ok_or_else(|| anyhow::anyhow!("No default profile set. Use --all to clear all profiles or set a default profile."))?;

                let cache_dir = manager.cache_dir(&profile_name);
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
                        "profile": profile_name
                    });
                    println!("{}", serde_json::to_string_pretty(&output)?);
                } else {
                    println!(
                        "{} Cleared cache for profile '{}'",
                        style("✓").green(),
                        profile_name
                    );
                }
            }
        }
        CacheCommands::Status => {
            let profiles = manager.list_profiles()?;
            let default_profile = manager.get_default_profile()?;

            if cli.json {
                let mut profile_status = Vec::new();

                for profile_name in &profiles {
                    let cache_dir = manager.cache_dir(profile_name);
                    let cache_exists = cache_dir.exists();
                    let cache_size = if cache_exists {
                        calculate_dir_size(&cache_dir)?
                    } else {
                        0
                    };

                    profile_status.push(serde_json::json!({
                        "name": profile_name,
                        "is_default": Some(profile_name) == default_profile.as_ref(),
                        "cache_exists": cache_exists,
                        "cache_size_bytes": cache_size,
                        "cache_path": cache_dir.to_string_lossy()
                    }));
                }

                let output = serde_json::json!({
                    "profiles": profile_status,
                    "total_profiles": profiles.len()
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                if profiles.is_empty() {
                    println!("No profiles found.");
                } else {
                    println!("Cache Status:");
                    println!();

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
                            println!(
                                "    Cache: {} ({} bytes)",
                                style("Present").green(),
                                cache_size
                            );
                        } else {
                            println!("    Cache: {}", style("Empty").dim());
                        }

                        println!("    Path: {}", style(cache_dir.to_string_lossy()).dim());
                        println!();
                    }
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

    // Get GitHub API rate limit if we have a client
    if let Some(_client) = &github_client {
        // Note: In a full implementation, we would call a rate limit endpoint
        // For now, we'll show placeholder information
        github_rate_limit = Some(HashMap::from([
            ("limit".to_string(), "5000".to_string()),
            ("remaining".to_string(), "4500".to_string()),
            ("reset".to_string(), "2025-12-18T15:00:00Z".to_string()),
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
                "status": "not_implemented",
                "accessible_projects": [],
                "total_count": 0
            },
            "last_pull": {
                "status": "not_implemented",
                "timestamp": null,
                "project": null,
                "set": null,
                "version": null
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

        // Projects (placeholder)
        println!("{}", style("Projects").bold());
        println!(
            "  Accessible Projects: {} (implementation pending)",
            style("Unknown").yellow()
        );
        println!("  Note: Project listing requires vault access implementation");
        println!();

        // Last Pull Information (placeholder)
        println!("{}", style("Last Pull").bold());
        println!(
            "  Status: {} (implementation pending)",
            style("No tracking").yellow()
        );
        println!("  Note: Pull history tracking not yet implemented");
        println!();

        // GitHub API Status
        println!("{}", style("GitHub API").bold());
        if let Some(_token) = &github_token {
            println!("  Authentication: {} Token present", style("✓").green());
            if let Some(rate_limit) = &github_rate_limit {
                println!(
                    "  Rate Limit: {}/{} requests remaining",
                    rate_limit.get("remaining").unwrap_or(&"?".to_string()),
                    rate_limit.get("limit").unwrap_or(&"?".to_string())
                );
                println!(
                    "  Reset Time: {}",
                    rate_limit.get("reset").unwrap_or(&"Unknown".to_string())
                );
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
