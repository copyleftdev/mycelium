#![allow(clippy::needless_borrows_for_generic_args)]

use anyhow::Result;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

// Helper function to get the path to the myc binary
fn get_myc_binary_path() -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // Remove test binary name
    if path.ends_with("deps") {
        path.pop(); // Remove deps directory
    }
    path.push("myc");
    path
}

#[test]
fn test_gitignore_dry_run_empty_directory() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let temp_path = temp_dir.path();
    let binary_path = get_myc_binary_path();

    // Change to temp directory and run gitignore dry-run
    let output = std::process::Command::new(&binary_path)
        .args(&["gitignore", "--dry-run", "--json"])
        .current_dir(temp_path)
        .output()?;

    if !output.status.success() {
        eprintln!("Command failed with exit code: {:?}", output.status.code());
        eprintln!("Stdout: {}", String::from_utf8_lossy(&output.stdout));
        eprintln!("Stderr: {}", String::from_utf8_lossy(&output.stderr));
        eprintln!("Binary path: {:?}", binary_path);
    }
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout)?;
    let json: serde_json::Value = serde_json::from_str(&stdout)?;

    assert_eq!(json["success"], true);
    assert_eq!(json["message"], "Dry run: would add patterns to .gitignore");
    assert_eq!(json["existing_file"], false);

    let patterns = json["patterns_to_add"].as_array().unwrap();
    assert_eq!(patterns.len(), 5);
    assert!(patterns.contains(&serde_json::Value::String(".env".to_string())));
    assert!(patterns.contains(&serde_json::Value::String(".env.*".to_string())));
    assert!(patterns.contains(&serde_json::Value::String("*.pem".to_string())));
    assert!(patterns.contains(&serde_json::Value::String("*.key".to_string())));
    assert!(patterns.contains(&serde_json::Value::String(".myc-secrets/".to_string())));

    Ok(())
}

#[test]
fn test_gitignore_creates_file() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let temp_path = temp_dir.path();
    let gitignore_path = temp_path.join(".gitignore");
    let binary_path = get_myc_binary_path();

    // Run gitignore command
    let output = std::process::Command::new(&binary_path)
        .args(&["gitignore", "--json"])
        .current_dir(temp_path)
        .output()?;

    assert!(output.status.success());

    // Check that .gitignore was created
    assert!(gitignore_path.exists());

    let content = fs::read_to_string(&gitignore_path)?;
    assert!(content.contains("# Secret files (added by myc)"));
    assert!(content.contains(".env"));
    assert!(content.contains(".env.*"));
    assert!(content.contains("*.pem"));
    assert!(content.contains("*.key"));
    assert!(content.contains(".myc-secrets/"));

    Ok(())
}

#[test]
fn test_gitignore_appends_to_existing_file() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let temp_path = temp_dir.path();
    let gitignore_path = temp_path.join(".gitignore");
    let binary_path = get_myc_binary_path();

    // Create existing .gitignore with some content
    fs::write(
        &gitignore_path,
        "# Existing content\nnode_modules/\n*.log\n",
    )?;

    // Run gitignore command
    let output = std::process::Command::new(&binary_path)
        .args(&["gitignore", "--json"])
        .current_dir(temp_path)
        .output()?;

    assert!(output.status.success());

    let content = fs::read_to_string(&gitignore_path)?;

    // Check that existing content is preserved
    assert!(content.contains("# Existing content"));
    assert!(content.contains("node_modules/"));
    assert!(content.contains("*.log"));

    // Check that new content is added
    assert!(content.contains("# Secret files (added by myc)"));
    assert!(content.contains(".env"));
    assert!(content.contains(".env.*"));
    assert!(content.contains("*.pem"));
    assert!(content.contains("*.key"));
    assert!(content.contains(".myc-secrets/"));

    Ok(())
}

#[test]
fn test_gitignore_detects_existing_patterns() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let temp_path = temp_dir.path();
    let gitignore_path = temp_path.join(".gitignore");
    let binary_path = get_myc_binary_path();

    // Create .gitignore with some secret patterns already present
    fs::write(&gitignore_path, "# Existing\n.env\n*.pem\nother_file\n")?;

    // Run gitignore dry-run
    let output = std::process::Command::new(&binary_path)
        .args(&["gitignore", "--dry-run", "--json"])
        .current_dir(temp_path)
        .output()?;

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout)?;
    let json: serde_json::Value = serde_json::from_str(&stdout)?;

    // Should only want to add patterns that aren't already present
    let patterns = json["patterns_to_add"].as_array().unwrap();
    assert_eq!(patterns.len(), 3); // .env.*, *.key, .myc-secrets/
    assert!(!patterns.contains(&serde_json::Value::String(".env".to_string())));
    assert!(!patterns.contains(&serde_json::Value::String("*.pem".to_string())));
    assert!(patterns.contains(&serde_json::Value::String(".env.*".to_string())));
    assert!(patterns.contains(&serde_json::Value::String("*.key".to_string())));
    assert!(patterns.contains(&serde_json::Value::String(".myc-secrets/".to_string())));

    Ok(())
}

#[test]
fn test_gitignore_all_patterns_present() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let temp_path = temp_dir.path();
    let gitignore_path = temp_path.join(".gitignore");
    let binary_path = get_myc_binary_path();

    // Create .gitignore with all secret patterns already present
    fs::write(
        &gitignore_path,
        ".env\n.env.*\n*.pem\n*.key\n.myc-secrets/\n",
    )?;

    // Run gitignore command
    let output = std::process::Command::new(&binary_path)
        .args(&["gitignore", "--json"])
        .current_dir(temp_path)
        .output()?;

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout)?;
    let json: serde_json::Value = serde_json::from_str(&stdout)?;

    assert_eq!(json["success"], true);
    assert_eq!(
        json["message"],
        "All secret file patterns already present in .gitignore"
    );

    Ok(())
}

#[test]
fn test_gitignore_custom_file_path() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let temp_path = temp_dir.path();
    let custom_path = temp_path.join("custom.gitignore");
    let binary_path = get_myc_binary_path();

    // Run gitignore command with custom file path
    let output = std::process::Command::new(&binary_path)
        .args(&["gitignore", "--file", "custom.gitignore", "--json"])
        .current_dir(temp_path)
        .output()?;

    assert!(output.status.success());

    // Check that custom file was created
    assert!(custom_path.exists());

    let content = fs::read_to_string(&custom_path)?;
    assert!(content.contains("# Secret files (added by myc)"));
    assert!(content.contains(".env"));

    Ok(())
}
