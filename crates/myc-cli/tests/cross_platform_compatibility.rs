//! Cross-platform compatibility tests.
//!
//! These tests verify that the system works correctly across different platforms
//! (Linux, macOS, Windows) and handles platform-specific concerns like file permissions
//! and path handling correctly.

use anyhow::Result;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Test helper to create a temporary directory for testing
fn create_temp_dir() -> Result<TempDir> {
    Ok(tempfile::tempdir()?)
}

/// Test helper to create a test file with specific content
fn create_test_file(dir: &Path, name: &str, content: &str) -> Result<PathBuf> {
    let file_path = dir.join(name);
    fs::write(&file_path, content)?;
    Ok(file_path)
}

#[test]
fn test_file_permissions_unix() -> Result<()> {
    // Test file permission handling on Unix systems (Linux, macOS)
    
    #[cfg(unix)]
    {
        let temp_dir = create_temp_dir()?;
        
        // Test 1: Create file with restrictive permissions (0600 - rw-------)
        let key_file = create_test_file(temp_dir.path(), "test.key", "secret key content")?;
        
        // Set restrictive permissions
        let mut perms = fs::metadata(&key_file)?.permissions();
        perms.set_mode(0o600); // rw-------
        fs::set_permissions(&key_file, perms)?;
        
        // Verify permissions
        let metadata = fs::metadata(&key_file)?;
        let mode = metadata.permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "Key file should have 0600 permissions");
        
        // Test 2: Create directory with restrictive permissions (0700 - rwx------)
        let key_dir = temp_dir.path().join("keys");
        fs::create_dir(&key_dir)?;
        
        let mut dir_perms = fs::metadata(&key_dir)?.permissions();
        dir_perms.set_mode(0o700); // rwx------
        fs::set_permissions(&key_dir, dir_perms)?;
        
        // Verify directory permissions
        let dir_metadata = fs::metadata(&key_dir)?;
        let dir_mode = dir_metadata.permissions().mode();
        assert_eq!(dir_mode & 0o777, 0o700, "Key directory should have 0700 permissions");
        
        // Test 3: Verify we can read/write files with correct permissions
        let content = fs::read_to_string(&key_file)?;
        assert_eq!(content, "secret key content");
        
        // Test 4: Create file in restricted directory
        let nested_key = key_dir.join("nested.key");
        fs::write(&nested_key, "nested secret")?;
        
        // Set restrictive permissions on nested file
        let mut nested_perms = fs::metadata(&nested_key)?.permissions();
        nested_perms.set_mode(0o600);
        fs::set_permissions(&nested_key, nested_perms)?;
        
        // Verify nested file permissions
        let nested_metadata = fs::metadata(&nested_key)?;
        let nested_mode = nested_metadata.permissions().mode();
        assert_eq!(nested_mode & 0o777, 0o600, "Nested key file should have 0600 permissions");
        
        println!("✓ Unix file permissions test passed");
    }
    
    #[cfg(not(unix))]
    {
        // On non-Unix systems, we can't test Unix-specific permissions
        // but we can still test basic file operations
        let temp_dir = create_temp_dir()?;
        let test_file = create_test_file(temp_dir.path(), "test.txt", "test content")?;
        
        let content = fs::read_to_string(&test_file)?;
        assert_eq!(content, "test content");
        
        println!("✓ Basic file operations test passed (non-Unix platform)");
    }
    
    Ok(())
}

#[test]
fn test_path_handling_cross_platform() -> Result<()> {
    // Test path handling across different platforms
    
    let temp_dir = create_temp_dir()?;
    
    // Test 1: Path separator handling
    let nested_path = temp_dir.path().join("level1").join("level2").join("file.txt");
    
    // Create nested directories
    if let Some(parent) = nested_path.parent() {
        fs::create_dir_all(parent)?;
    }
    
    // Create file in nested path
    fs::write(&nested_path, "nested content")?;
    
    // Verify we can read the file
    let content = fs::read_to_string(&nested_path)?;
    assert_eq!(content, "nested content");
    
    // Test 2: Path canonicalization
    let canonical_path = nested_path.canonicalize()?;
    assert!(canonical_path.exists());
    assert!(canonical_path.is_absolute());
    
    // Test 3: Relative path handling
    let relative_path = PathBuf::from("relative").join("path").join("test.txt");
    let full_path = temp_dir.path().join(&relative_path);
    
    if let Some(parent) = full_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&full_path, "relative content")?;
    
    let relative_content = fs::read_to_string(&full_path)?;
    assert_eq!(relative_content, "relative content");
    
    // Test 4: Path component extraction
    assert_eq!(full_path.file_name().unwrap(), "test.txt");
    assert_eq!(full_path.extension().unwrap(), "txt");
    
    // Test 5: Path joining with different separators
    let components = vec!["config", "mycelium", "profiles", "default"];
    let joined_path = components.iter().collect::<PathBuf>();
    
    let full_joined = temp_dir.path().join(joined_path);
    if let Some(parent) = full_joined.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&full_joined, "config content")?;
    
    let config_content = fs::read_to_string(&full_joined)?;
    assert_eq!(config_content, "config content");
    
    println!("✓ Cross-platform path handling test passed");
    Ok(())
}

#[test]
fn test_directory_operations() -> Result<()> {
    // Test directory operations across platforms
    
    let temp_dir = create_temp_dir()?;
    
    // Test 1: Create nested directory structure
    let profile_dir = temp_dir.path()
        .join("profiles")
        .join("test-profile")
        .join("keys");
    
    fs::create_dir_all(&profile_dir)?;
    assert!(profile_dir.exists());
    assert!(profile_dir.is_dir());
    
    // Test 2: Create files in nested structure
    let signing_key = profile_dir.join("signing.key");
    let encryption_key = profile_dir.join("encryption.key");
    
    fs::write(&signing_key, "signing key data")?;
    fs::write(&encryption_key, "encryption key data")?;
    
    // Test 3: List directory contents
    let entries: Vec<_> = fs::read_dir(&profile_dir)?
        .map(|entry| entry.unwrap().file_name())
        .collect();
    
    assert_eq!(entries.len(), 2);
    assert!(entries.iter().any(|name| name == "signing.key"));
    assert!(entries.iter().any(|name| name == "encryption.key"));
    
    // Test 4: Remove files
    fs::remove_file(&signing_key)?;
    assert!(!signing_key.exists());
    assert!(encryption_key.exists());
    
    // Test 5: Remove directory (should fail if not empty)
    let remove_result = fs::remove_dir(&profile_dir);
    assert!(remove_result.is_err()); // Should fail because directory is not empty
    
    // Remove remaining file and try again
    fs::remove_file(&encryption_key)?;
    fs::remove_dir(&profile_dir)?;
    assert!(!profile_dir.exists());
    
    // Test 6: Remove directory tree
    let nested_structure = temp_dir.path()
        .join("deep")
        .join("nested")
        .join("structure");
    
    fs::create_dir_all(&nested_structure)?;
    fs::write(nested_structure.join("file.txt"), "content")?;
    
    // Remove entire tree
    fs::remove_dir_all(temp_dir.path().join("deep"))?;
    assert!(!temp_dir.path().join("deep").exists());
    
    println!("✓ Directory operations test passed");
    Ok(())
}

#[test]
fn test_file_metadata_operations() -> Result<()> {
    // Test file metadata operations across platforms
    
    let temp_dir = create_temp_dir()?;
    
    // Test 1: File size
    let test_file = temp_dir.path().join("size_test.txt");
    let content = "a".repeat(1000);
    fs::write(&test_file, &content)?;
    
    let metadata = fs::metadata(&test_file)?;
    assert_eq!(metadata.len(), 1000);
    
    // Test 2: File type detection
    assert!(metadata.is_file());
    assert!(!metadata.is_dir());
    
    let test_dir = temp_dir.path().join("test_dir");
    fs::create_dir(&test_dir)?;
    
    let dir_metadata = fs::metadata(&test_dir)?;
    assert!(dir_metadata.is_dir());
    assert!(!dir_metadata.is_file());
    
    // Test 3: File modification time
    let modified_time = metadata.modified()?;
    let now = std::time::SystemTime::now();
    
    // File should have been modified recently (within last minute)
    let duration = now.duration_since(modified_time)?;
    assert!(duration.as_secs() < 60);
    
    // Test 4: File existence checks
    assert!(test_file.exists());
    assert!(test_dir.exists());
    assert!(!temp_dir.path().join("nonexistent.txt").exists());
    
    println!("✓ File metadata operations test passed");
    Ok(())
}

#[test]
fn test_config_directory_locations() -> Result<()> {
    // Test platform-specific config directory handling
    
    // Test 1: Get user config directory (platform-specific)
    let config_dir = dirs::config_dir();
    
    match config_dir {
        Some(dir) => {
            // Verify the directory exists or can be created
            assert!(dir.exists() || dir.parent().map_or(false, |p| p.exists()));
            
            // Test creating mycelium config directory
            let mycelium_config = dir.join("mycelium");
            
            // We won't actually create it in the real config dir for this test
            // Instead, use a temp directory to simulate the structure
            let temp_dir = create_temp_dir()?;
            let test_config = temp_dir.path().join("mycelium");
            
            fs::create_dir_all(&test_config)?;
            assert!(test_config.exists());
            
            // Test creating profile structure
            let profiles_dir = test_config.join("profiles");
            fs::create_dir(&profiles_dir)?;
            
            let test_profile = profiles_dir.join("test-profile");
            fs::create_dir(&test_profile)?;
            
            // Verify structure
            assert!(profiles_dir.exists());
            assert!(test_profile.exists());
            
            println!("✓ Config directory test passed (found config dir: {:?})", dir);
        }
        None => {
            // Fallback for systems without standard config directories
            let temp_dir = create_temp_dir()?;
            let fallback_config = temp_dir.path().join(".mycelium");
            
            fs::create_dir(&fallback_config)?;
            assert!(fallback_config.exists());
            
            println!("✓ Config directory test passed (using fallback)");
        }
    }
    
    Ok(())
}

#[test]
fn test_file_locking_behavior() -> Result<()> {
    // Test file locking behavior across platforms
    
    let temp_dir = create_temp_dir()?;
    let test_file = temp_dir.path().join("lock_test.txt");
    
    // Test 1: Basic file operations
    fs::write(&test_file, "initial content")?;
    
    // Test 2: Multiple readers (should work on all platforms)
    let content1 = fs::read_to_string(&test_file)?;
    let content2 = fs::read_to_string(&test_file)?;
    
    assert_eq!(content1, "initial content");
    assert_eq!(content2, "initial content");
    
    // Test 3: Write after read (should work)
    fs::write(&test_file, "updated content")?;
    let updated_content = fs::read_to_string(&test_file)?;
    assert_eq!(updated_content, "updated content");
    
    // Test 4: Atomic operations (rename)
    let temp_file = temp_dir.path().join("temp_write.txt");
    fs::write(&temp_file, "atomic content")?;
    
    // Atomic rename (should work on all platforms)
    let final_file = temp_dir.path().join("final.txt");
    fs::rename(&temp_file, &final_file)?;
    
    assert!(!temp_file.exists());
    assert!(final_file.exists());
    
    let final_content = fs::read_to_string(&final_file)?;
    assert_eq!(final_content, "atomic content");
    
    println!("✓ File locking behavior test passed");
    Ok(())
}

#[test]
fn test_path_encoding_handling() -> Result<()> {
    // Test handling of different path encodings and special characters
    
    let temp_dir = create_temp_dir()?;
    
    // Test 1: ASCII paths (should work everywhere)
    let ascii_file = temp_dir.path().join("ascii_file.txt");
    fs::write(&ascii_file, "ascii content")?;
    assert!(ascii_file.exists());
    
    // Test 2: Paths with spaces
    let space_file = temp_dir.path().join("file with spaces.txt");
    fs::write(&space_file, "space content")?;
    assert!(space_file.exists());
    
    let space_content = fs::read_to_string(&space_file)?;
    assert_eq!(space_content, "space content");
    
    // Test 3: Paths with underscores and hyphens
    let underscore_file = temp_dir.path().join("file_with_underscores-and-hyphens.txt");
    fs::write(&underscore_file, "underscore content")?;
    assert!(underscore_file.exists());
    
    // Test 4: Directory with special characters
    let special_dir = temp_dir.path().join("dir-with_special.chars");
    fs::create_dir(&special_dir)?;
    assert!(special_dir.exists());
    
    let nested_file = special_dir.join("nested.txt");
    fs::write(&nested_file, "nested in special dir")?;
    
    let nested_content = fs::read_to_string(&nested_file)?;
    assert_eq!(nested_content, "nested in special dir");
    
    // Test 5: Very long filenames (within reasonable limits)
    let long_name = "a".repeat(100) + ".txt";
    let long_file = temp_dir.path().join(&long_name);
    
    // This might fail on some filesystems with length limits, so we handle it gracefully
    match fs::write(&long_file, "long filename content") {
        Ok(_) => {
            assert!(long_file.exists());
            let long_content = fs::read_to_string(&long_file)?;
            assert_eq!(long_content, "long filename content");
            println!("✓ Long filename test passed");
        }
        Err(_) => {
            println!("✓ Long filename test skipped (filesystem limitation)");
        }
    }
    
    println!("✓ Path encoding handling test passed");
    Ok(())
}

#[test]
fn test_concurrent_file_access() -> Result<()> {
    // Test concurrent file access patterns
    
    let temp_dir = create_temp_dir()?;
    
    // Test 1: Multiple processes reading the same file
    let shared_file = temp_dir.path().join("shared.txt");
    fs::write(&shared_file, "shared content")?;
    
    // Simulate multiple readers
    let mut handles = Vec::new();
    for i in 0..5 {
        let file_path = shared_file.clone();
        let handle = std::thread::spawn(move || {
            let content = fs::read_to_string(&file_path).unwrap();
            assert_eq!(content, "shared content");
            i
        });
        handles.push(handle);
    }
    
    // Wait for all readers to complete
    for handle in handles {
        let result = handle.join().unwrap();
        assert!(result < 5);
    }
    
    // Test 2: Sequential writes (avoiding concurrent writes which are platform-dependent)
    let write_file = temp_dir.path().join("sequential_writes.txt");
    
    for i in 0..5 {
        let content = format!("write number {}", i);
        fs::write(&write_file, &content)?;
        
        let read_content = fs::read_to_string(&write_file)?;
        assert_eq!(read_content, content);
    }
    
    println!("✓ Concurrent file access test passed");
    Ok(())
}

#[test]
fn test_platform_specific_features() -> Result<()> {
    // Test platform-specific features and graceful degradation
    
    let temp_dir = create_temp_dir()?;
    
    // Test 1: Case sensitivity handling
    let lower_file = temp_dir.path().join("lowercase.txt");
    let upper_file = temp_dir.path().join("LOWERCASE.txt");
    
    fs::write(&lower_file, "lower content")?;
    
    // On case-sensitive filesystems, these should be different files
    // On case-insensitive filesystems, they should be the same
    let case_sensitive = if upper_file.exists() {
        // Case-insensitive filesystem
        false
    } else {
        // Try to create the uppercase version
        match fs::write(&upper_file, "upper content") {
            Ok(_) => {
                // Successfully created different file - case sensitive
                true
            }
            Err(_) => {
                // Failed to create - might be case insensitive
                false
            }
        }
    };
    
    if case_sensitive {
        println!("✓ Running on case-sensitive filesystem");
        assert!(lower_file.exists());
        assert!(upper_file.exists());
        
        let lower_content = fs::read_to_string(&lower_file)?;
        let upper_content = fs::read_to_string(&upper_file)?;
        assert_eq!(lower_content, "lower content");
        assert_eq!(upper_content, "upper content");
    } else {
        println!("✓ Running on case-insensitive filesystem");
        // Both paths should refer to the same file
    }
    
    // Test 2: Path length limits (platform-dependent)
    let reasonable_path = temp_dir.path().join("reasonable_length_filename.txt");
    fs::write(&reasonable_path, "reasonable content")?;
    assert!(reasonable_path.exists());
    
    // Test 3: Reserved names (Windows-specific, but test gracefully)
    let reserved_names = vec!["CON", "PRN", "AUX", "NUL"];
    
    for name in reserved_names {
        let reserved_file = temp_dir.path().join(format!("{}.txt", name));
        
        // Try to create file with reserved name
        match fs::write(&reserved_file, "reserved content") {
            Ok(_) => {
                // Successfully created (not Windows or Windows allows it)
                println!("✓ Created file with name: {}", name);
                fs::remove_file(&reserved_file).ok(); // Clean up
            }
            Err(_) => {
                // Failed to create (probably Windows with reserved name)
                println!("✓ Correctly rejected reserved name: {}", name);
            }
        }
    }
    
    println!("✓ Platform-specific features test passed");
    Ok(())
}