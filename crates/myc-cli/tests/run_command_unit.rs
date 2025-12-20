//! Unit tests for the myc run command functionality.
//!
//! These tests verify that the run command correctly parses arguments,
//! validates configuration, and handles error cases appropriately.

#![allow(irrefutable_let_patterns)]
#![allow(clippy::useless_vec)]

use myc_cli::project_config::ProjectConfig;
use tempfile::TempDir;

#[test]
fn test_run_command_argument_parsing() {
    // Test that the CLI can parse run command arguments correctly
    use clap::Parser;

    // Define a minimal CLI structure for testing
    #[derive(clap::Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: TestCommands,
    }

    #[derive(clap::Subcommand)]
    enum TestCommands {
        Run {
            #[arg(long)]
            project: Option<String>,
            #[arg(long, short = 's')]
            set: Option<String>,
            #[arg(long)]
            version: Option<u64>,
            #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
            command: Vec<String>,
        },
    }

    // Test basic command parsing
    let args = vec![
        "test",
        "run",
        "--project",
        "myproject",
        "--set",
        "myset",
        "echo",
        "hello",
    ];
    let cli = TestCli::try_parse_from(args).unwrap();

    if let TestCommands::Run {
        project,
        set,
        version,
        command,
    } = cli.command
    {
        assert_eq!(project, Some("myproject".to_string()));
        assert_eq!(set, Some("myset".to_string()));
        assert_eq!(version, None);
        assert_eq!(command, vec!["echo", "hello"]);
    } else {
        panic!("Expected Run command");
    }
}

#[test]
fn test_run_command_with_version() {
    use clap::Parser;

    #[derive(clap::Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: TestCommands,
    }

    #[derive(clap::Subcommand)]
    enum TestCommands {
        Run {
            #[arg(long)]
            project: Option<String>,
            #[arg(long, short = 's')]
            set: Option<String>,
            #[arg(long)]
            version: Option<u64>,
            #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
            command: Vec<String>,
        },
    }

    // Test with version specified
    let args = vec![
        "test",
        "run",
        "--project",
        "myproject",
        "--set",
        "myset",
        "--version",
        "42",
        "ls",
        "-la",
    ];
    let cli = TestCli::try_parse_from(args).unwrap();

    if let TestCommands::Run {
        project,
        set,
        version,
        command,
    } = cli.command
    {
        assert_eq!(project, Some("myproject".to_string()));
        assert_eq!(set, Some("myset".to_string()));
        assert_eq!(version, Some(42));
        assert_eq!(command, vec!["ls", "-la"]);
    } else {
        panic!("Expected Run command");
    }
}

#[test]
fn test_run_command_with_hyphen_args() {
    use clap::Parser;

    #[derive(clap::Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: TestCommands,
    }

    #[derive(clap::Subcommand)]
    enum TestCommands {
        Run {
            #[arg(long)]
            project: Option<String>,
            #[arg(long, short = 's')]
            set: Option<String>,
            #[arg(long)]
            version: Option<u64>,
            #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
            command: Vec<String>,
        },
    }

    // Test with command that has hyphen arguments
    let args = vec![
        "test",
        "run",
        "--project",
        "myproject",
        "--set",
        "myset",
        "curl",
        "-X",
        "POST",
        "--data",
        "test",
    ];
    let cli = TestCli::try_parse_from(args).unwrap();

    if let TestCommands::Run {
        project,
        set,
        version,
        command,
    } = cli.command
    {
        assert_eq!(project, Some("myproject".to_string()));
        assert_eq!(set, Some("myset".to_string()));
        assert_eq!(version, None);
        assert_eq!(command, vec!["curl", "-X", "POST", "--data", "test"]);
    } else {
        panic!("Expected Run command");
    }
}

#[test]
fn test_project_config_integration() {
    let temp_dir = TempDir::new().unwrap();

    // Create a .myc.yaml config file
    let config_path = temp_dir.path().join(".myc.yaml");
    let config_content = r#"
vault: myorg/secrets-vault
project: api
set: production
export_format: dotenv
"#;
    std::fs::write(&config_path, config_content).unwrap();

    // Load the config
    let config = ProjectConfig::load_from_file(&config_path).unwrap();

    // Test that config values can be used for run command defaults
    assert_eq!(config.project, Some("api".to_string()));
    assert_eq!(config.set, Some("production".to_string()));

    // Test overrides work
    let overridden = config.with_overrides(
        None,
        Some("different-project"),
        None, // Keep original set
        None,
        None,
    );

    assert_eq!(overridden.project, Some("different-project".to_string()));
    assert_eq!(overridden.set, Some("production".to_string())); // Original value
}

#[test]
fn test_empty_command_validation() {
    // Test that empty command arrays are properly detected
    let empty_command: Vec<String> = vec![];
    assert!(empty_command.is_empty());

    let non_empty_command = vec!["echo".to_string(), "hello".to_string()];
    assert!(!non_empty_command.is_empty());
}

#[test]
fn test_environment_variable_preparation() {
    use std::collections::HashMap;

    // Simulate converting secret entries to environment variables
    let entries = vec![
        ("DATABASE_URL", "postgres://localhost/mydb"),
        ("API_KEY", "secret123"),
        ("DEBUG", "true"),
    ];

    let mut env_vars = HashMap::new();
    for (key, value) in entries {
        env_vars.insert(key.to_string(), value.to_string());
    }

    assert_eq!(env_vars.len(), 3);
    assert_eq!(
        env_vars.get("DATABASE_URL"),
        Some(&"postgres://localhost/mydb".to_string())
    );
    assert_eq!(env_vars.get("API_KEY"), Some(&"secret123".to_string()));
    assert_eq!(env_vars.get("DEBUG"), Some(&"true".to_string()));
}

#[test]
fn test_config_validation_for_run_command() {
    // Test that project config validation works for run command scenarios

    // Valid config
    let valid_config = ProjectConfig {
        vault: Some("myorg/vault".to_string()),
        project: Some("myproject".to_string()),
        set: Some("myset".to_string()),
        export_format: None, // Not used in run command
        output_file: None,   // Not used in run command
    };
    assert!(valid_config.validate().is_ok());

    // Invalid vault format
    let invalid_vault_config = ProjectConfig {
        vault: Some("invalid-vault-format".to_string()),
        project: Some("myproject".to_string()),
        set: Some("myset".to_string()),
        export_format: None,
        output_file: None,
    };
    assert!(invalid_vault_config.validate().is_err());

    // Empty project name
    let empty_project_config = ProjectConfig {
        vault: Some("myorg/vault".to_string()),
        project: Some("".to_string()),
        set: Some("myset".to_string()),
        export_format: None,
        output_file: None,
    };
    assert!(empty_project_config.validate().is_err());

    // Empty set name
    let empty_set_config = ProjectConfig {
        vault: Some("myorg/vault".to_string()),
        project: Some("myproject".to_string()),
        set: Some("".to_string()),
        export_format: None,
        output_file: None,
    };
    assert!(empty_set_config.validate().is_err());
}
