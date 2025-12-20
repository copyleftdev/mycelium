//! Secret import and export format handling.
//!
//! This module provides parsers and formatters for various secret formats:
//! - Dotenv (.env files)
//! - JSON
//! - Shell export format
//! - YAML

use crate::error::{Result, ValidationError};
use crate::secret_set::SecretEntry;

/// Supported secret formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretFormat {
    /// Dotenv format (KEY=value)
    Dotenv,
    /// JSON format ({"KEY": "value"})
    Json,
    /// Shell export format (export KEY='value')
    Shell,
    /// YAML format (KEY: value)
    Yaml,
}

impl SecretFormat {
    /// Detect format from file extension.
    pub fn from_extension(extension: &str) -> Option<Self> {
        match extension.to_lowercase().as_str() {
            "env" => Some(Self::Dotenv),
            "json" => Some(Self::Json),
            "sh" | "bash" => Some(Self::Shell),
            "yaml" | "yml" => Some(Self::Yaml),
            _ => None,
        }
    }

    /// Get the default file extension for this format.
    pub fn default_extension(&self) -> &'static str {
        match self {
            Self::Dotenv => "env",
            Self::Json => "json",
            Self::Shell => "sh",
            Self::Yaml => "yaml",
        }
    }
}

/// Parse dotenv format content into secret entries.
///
/// Supports:
/// - KEY=value lines
/// - Quoted values (single and double quotes)
/// - Comments (lines starting with #)
/// - Escape sequences in quoted values
/// - Empty lines
pub fn parse_dotenv(content: &str) -> Result<Vec<SecretEntry>> {
    let mut entries = Vec::new();

    for (line_num, line) in content.lines().enumerate() {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Find the first '=' character
        let eq_pos = line
            .find('=')
            .ok_or_else(|| ValidationError::InvalidFormat {
                format: "dotenv".to_string(),
                reason: format!("Line {}: Missing '=' separator", line_num + 1),
            })?;

        let key = line[..eq_pos].trim();
        let value_part = &line[eq_pos + 1..];

        // Validate key
        if key.is_empty() {
            return Err(ValidationError::InvalidFormat {
                format: "dotenv".to_string(),
                reason: format!("Line {}: Empty key", line_num + 1),
            }
            .into());
        }

        // Parse value (handle quotes and escaping)
        let value = parse_dotenv_value(value_part, line_num + 1)?;

        entries.push(SecretEntry::new(key.to_string(), value));
    }

    Ok(entries)
}

/// Parse JSON format content into secret entries.
///
/// Expects a JSON object with string keys and values: {"KEY": "value"}
pub fn parse_json(content: &str) -> Result<Vec<SecretEntry>> {
    let json_value: serde_json::Value =
        serde_json::from_str(content).map_err(|e| ValidationError::InvalidFormat {
            format: "json".to_string(),
            reason: format!("Invalid JSON: {}", e),
        })?;

    let obj = json_value
        .as_object()
        .ok_or_else(|| ValidationError::InvalidFormat {
            format: "json".to_string(),
            reason: "Expected JSON object, got other type".to_string(),
        })?;

    let mut entries = Vec::new();

    for (key, value) in obj {
        let value_str = value
            .as_str()
            .ok_or_else(|| ValidationError::InvalidFormat {
                format: "json".to_string(),
                reason: format!("Value for key '{}' must be a string", key),
            })?;

        entries.push(SecretEntry::new(key.clone(), value_str.to_string()));
    }

    // Sort entries by key for consistent ordering
    entries.sort_by(|a, b| a.key.cmp(&b.key));

    Ok(entries)
}

/// Parse a dotenv value, handling quotes and escape sequences.
fn parse_dotenv_value(value_part: &str, line_num: usize) -> Result<String> {
    let value_part = value_part.trim();

    if value_part.is_empty() {
        return Ok(String::new());
    }

    // Handle quoted values
    if (value_part.starts_with('"') && value_part.ends_with('"') && value_part.len() >= 2)
        || (value_part.starts_with('\'') && value_part.ends_with('\'') && value_part.len() >= 2)
    {
        let quote_char = value_part.chars().next().unwrap();
        let inner = &value_part[1..value_part.len() - 1];

        // Handle escape sequences in double quotes
        if quote_char == '"' {
            parse_escaped_string(inner, line_num)
        } else {
            // Single quotes: no escape processing
            Ok(inner.to_string())
        }
    } else {
        // Unquoted value
        Ok(value_part.to_string())
    }
}

/// Parse escape sequences in a double-quoted string.
fn parse_escaped_string(s: &str, line_num: usize) -> Result<String> {
    let mut result = String::new();
    let mut chars = s.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some('n') => result.push('\n'),
                Some('r') => result.push('\r'),
                Some('t') => result.push('\t'),
                Some('\\') => result.push('\\'),
                Some('"') => result.push('"'),
                Some('\'') => result.push('\''),
                Some(other) => {
                    return Err(ValidationError::InvalidFormat {
                        format: "dotenv".to_string(),
                        reason: format!("Line {}: Invalid escape sequence '\\{}'", line_num, other),
                    }
                    .into());
                }
                None => {
                    return Err(ValidationError::InvalidFormat {
                        format: "dotenv".to_string(),
                        reason: format!("Line {}: Trailing backslash", line_num),
                    }
                    .into());
                }
            }
        } else {
            result.push(ch);
        }
    }

    Ok(result)
}

/// Format secret entries as dotenv format.
///
/// Produces KEY=value lines with proper quoting for values containing spaces or special characters.
pub fn format_dotenv(entries: &[SecretEntry]) -> String {
    let mut lines = Vec::new();

    for entry in entries {
        let formatted_value = if needs_quoting(&entry.value) {
            format!("\"{}\"", escape_for_dotenv(&entry.value))
        } else {
            entry.value.clone()
        };

        lines.push(format!("{}={}", entry.key, formatted_value));
    }

    lines.join("\n")
}

/// Check if a value needs to be quoted in dotenv format.
fn needs_quoting(value: &str) -> bool {
    value.is_empty()
        || value.contains(' ')
        || value.contains('\t')
        || value.contains('\n')
        || value.contains('\r')
        || value.contains('"')
        || value.contains('\'')
        || value.contains('\\')
        || value.starts_with('#')
}

/// Escape special characters for dotenv format.
fn escape_for_dotenv(value: &str) -> String {
    let mut result = String::new();

    for ch in value.chars() {
        match ch {
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            '\\' => result.push_str("\\\\"),
            '"' => result.push_str("\\\""),
            other => result.push(other),
        }
    }

    result
}

/// Format secret entries as JSON format.
///
/// Produces a pretty-printed JSON object with string keys and values.
pub fn format_json(entries: &[SecretEntry]) -> Result<String> {
    use std::collections::BTreeMap;

    let mut map = BTreeMap::new();
    for entry in entries {
        map.insert(&entry.key, &entry.value);
    }

    serde_json::to_string_pretty(&map).map_err(|e| {
        ValidationError::InvalidFormat {
            format: "json".to_string(),
            reason: format!("Failed to serialize JSON: {}", e),
        }
        .into()
    })
}

/// Format secret entries as shell export format.
///
/// Produces export KEY='value' lines with proper shell escaping.
pub fn format_shell(entries: &[SecretEntry]) -> String {
    let mut lines = Vec::new();

    for entry in entries {
        let escaped_value = escape_for_shell(&entry.value);
        lines.push(format!("export {}='{}'", entry.key, escaped_value));
    }

    lines.join("\n")
}

/// Escape a value for shell single quotes.
/// In single quotes, only single quotes need escaping (by ending the quote, adding escaped quote, starting new quote).
fn escape_for_shell(value: &str) -> String {
    value.replace('\'', "'\"'\"'")
}

/// Format secret entries as YAML format.
///
/// Produces KEY: value lines with proper YAML escaping.
pub fn format_yaml(entries: &[SecretEntry]) -> String {
    let mut lines = Vec::new();

    for entry in entries {
        let formatted_value = if needs_yaml_quoting(&entry.value) {
            format!("\"{}\"", escape_for_yaml(&entry.value))
        } else {
            entry.value.clone()
        };

        lines.push(format!("{}: {}", entry.key, formatted_value));
    }

    lines.join("\n")
}

/// Check if a value needs to be quoted in YAML format.
fn needs_yaml_quoting(value: &str) -> bool {
    value.is_empty()
        || value.contains('\n')
        || value.contains('\r')
        || value.contains('\t')
        || value.contains('"')
        || value.contains('\\')
        || value.starts_with(' ')
        || value.ends_with(' ')
        || value.starts_with('#')
        || value.starts_with('!')
        || value.starts_with('&')
        || value.starts_with('*')
        || value.starts_with('[')
        || value.starts_with(']')
        || value.starts_with('{')
        || value.starts_with('}')
        || value.starts_with('|')
        || value.starts_with('>')
        || value.contains(": ")
        || value == "true"
        || value == "false"
        || value == "null"
        || value == "~"
        || value.parse::<f64>().is_ok()
}

/// Escape special characters for YAML format.
fn escape_for_yaml(value: &str) -> String {
    let mut result = String::new();

    for ch in value.chars() {
        match ch {
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            '\\' => result.push_str("\\\\"),
            '"' => result.push_str("\\\""),
            other => result.push(other),
        }
    }

    result
}

/// Detect format from file path.
///
/// Looks at the file extension to determine the format.
/// Returns None if the format cannot be determined.
pub fn detect_format_from_path(path: &str) -> Option<SecretFormat> {
    std::path::Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .and_then(SecretFormat::from_extension)
}

/// Parse secrets from content using the specified format.
pub fn parse_secrets(content: &str, format: SecretFormat) -> Result<Vec<SecretEntry>> {
    match format {
        SecretFormat::Dotenv => parse_dotenv(content),
        SecretFormat::Json => parse_json(content),
        SecretFormat::Shell => Err(ValidationError::InvalidFormat {
            format: "shell".to_string(),
            reason: "Shell format is output-only and cannot be parsed".to_string(),
        }
        .into()),
        SecretFormat::Yaml => Err(ValidationError::InvalidFormat {
            format: "yaml".to_string(),
            reason: "YAML parsing not yet implemented".to_string(),
        }
        .into()),
    }
}

/// Format secrets to string using the specified format.
pub fn format_secrets(entries: &[SecretEntry], format: SecretFormat) -> Result<String> {
    match format {
        SecretFormat::Dotenv => Ok(format_dotenv(entries)),
        SecretFormat::Json => format_json(entries),
        SecretFormat::Shell => Ok(format_shell(entries)),
        SecretFormat::Yaml => Ok(format_yaml(entries)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dotenv_simple() {
        let content = "KEY1=value1\nKEY2=value2";
        let entries = parse_dotenv(content).unwrap();

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key, "KEY1");
        assert_eq!(entries[0].value, "value1");
        assert_eq!(entries[1].key, "KEY2");
        assert_eq!(entries[1].value, "value2");
    }

    #[test]
    fn test_parse_dotenv_with_comments() {
        let content = r#"
# This is a comment
KEY1=value1
# Another comment
KEY2=value2
"#;
        let entries = parse_dotenv(content).unwrap();

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key, "KEY1");
        assert_eq!(entries[0].value, "value1");
        assert_eq!(entries[1].key, "KEY2");
        assert_eq!(entries[1].value, "value2");
    }

    #[test]
    fn test_parse_dotenv_quoted_values() {
        let content = r#"KEY1="quoted value"
KEY2='single quoted'
KEY3="value with spaces"
KEY4='another value'"#;

        let entries = parse_dotenv(content).unwrap();

        assert_eq!(entries.len(), 4);
        assert_eq!(entries[0].key, "KEY1");
        assert_eq!(entries[0].value, "quoted value");
        assert_eq!(entries[1].key, "KEY2");
        assert_eq!(entries[1].value, "single quoted");
        assert_eq!(entries[2].key, "KEY3");
        assert_eq!(entries[2].value, "value with spaces");
        assert_eq!(entries[3].key, "KEY4");
        assert_eq!(entries[3].value, "another value");
    }

    #[test]
    fn test_parse_dotenv_escape_sequences() {
        let content = r#"KEY1="line1\nline2"
KEY2="tab\there"
KEY3="quote\"here"
KEY4="backslash\\here""#;

        let entries = parse_dotenv(content).unwrap();

        assert_eq!(entries.len(), 4);
        assert_eq!(entries[0].key, "KEY1");
        assert_eq!(entries[0].value, "line1\nline2");
        assert_eq!(entries[1].key, "KEY2");
        assert_eq!(entries[1].value, "tab\there");
        assert_eq!(entries[2].key, "KEY3");
        assert_eq!(entries[2].value, "quote\"here");
        assert_eq!(entries[3].key, "KEY4");
        assert_eq!(entries[3].value, "backslash\\here");
    }

    #[test]
    fn test_parse_dotenv_empty_values() {
        let content = "KEY1=\nKEY2=\"\"\nKEY3=''";
        let entries = parse_dotenv(content).unwrap();

        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].key, "KEY1");
        assert_eq!(entries[0].value, "");
        assert_eq!(entries[1].key, "KEY2");
        assert_eq!(entries[1].value, "");
        assert_eq!(entries[2].key, "KEY3");
        assert_eq!(entries[2].value, "");
    }

    #[test]
    fn test_parse_dotenv_whitespace() {
        let content = "  KEY1  =  value1  \n\t KEY2\t=\tvalue2\t";
        let entries = parse_dotenv(content).unwrap();

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key, "KEY1");
        assert_eq!(entries[0].value, "value1");
        assert_eq!(entries[1].key, "KEY2");
        assert_eq!(entries[1].value, "value2");
    }

    #[test]
    fn test_parse_dotenv_invalid_no_equals() {
        let content = "INVALID_LINE";
        let result = parse_dotenv(content);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_dotenv_invalid_empty_key() {
        let content = "=value";
        let result = parse_dotenv(content);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_dotenv_invalid_escape() {
        let content = r#"KEY="invalid\x""#;
        let result = parse_dotenv(content);
        assert!(result.is_err());
    }

    #[test]
    fn test_format_from_extension() {
        assert_eq!(
            SecretFormat::from_extension("env"),
            Some(SecretFormat::Dotenv)
        );
        assert_eq!(
            SecretFormat::from_extension("json"),
            Some(SecretFormat::Json)
        );
        assert_eq!(
            SecretFormat::from_extension("sh"),
            Some(SecretFormat::Shell)
        );
        assert_eq!(
            SecretFormat::from_extension("yaml"),
            Some(SecretFormat::Yaml)
        );
        assert_eq!(
            SecretFormat::from_extension("yml"),
            Some(SecretFormat::Yaml)
        );
        assert_eq!(SecretFormat::from_extension("txt"), None);
    }

    #[test]
    fn test_format_default_extension() {
        assert_eq!(SecretFormat::Dotenv.default_extension(), "env");
        assert_eq!(SecretFormat::Json.default_extension(), "json");
        assert_eq!(SecretFormat::Shell.default_extension(), "sh");
        assert_eq!(SecretFormat::Yaml.default_extension(), "yaml");
    }

    #[test]
    fn test_parse_json_simple() {
        let content = r#"{"KEY1": "value1", "KEY2": "value2"}"#;
        let entries = parse_json(content).unwrap();

        assert_eq!(entries.len(), 2);
        // Entries should be sorted by key
        assert_eq!(entries[0].key, "KEY1");
        assert_eq!(entries[0].value, "value1");
        assert_eq!(entries[1].key, "KEY2");
        assert_eq!(entries[1].value, "value2");
    }

    #[test]
    fn test_parse_json_empty_object() {
        let content = "{}";
        let entries = parse_json(content).unwrap();
        assert_eq!(entries.len(), 0);
    }

    #[test]
    fn test_parse_json_with_special_characters() {
        let content = r#"{"KEY_WITH_UNDERSCORE": "value with spaces", "KEY.WITH.DOTS": "value\nwith\nnewlines"}"#;
        let entries = parse_json(content).unwrap();

        assert_eq!(entries.len(), 2);
        // Should be sorted by key
        assert_eq!(entries[0].key, "KEY.WITH.DOTS");
        assert_eq!(entries[0].value, "value\nwith\nnewlines");
        assert_eq!(entries[1].key, "KEY_WITH_UNDERSCORE");
        assert_eq!(entries[1].value, "value with spaces");
    }

    #[test]
    fn test_parse_json_empty_values() {
        let content = r#"{"KEY1": "", "KEY2": "value"}"#;
        let entries = parse_json(content).unwrap();

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key, "KEY1");
        assert_eq!(entries[0].value, "");
        assert_eq!(entries[1].key, "KEY2");
        assert_eq!(entries[1].value, "value");
    }

    #[test]
    fn test_parse_json_invalid_syntax() {
        let content = r#"{"KEY1": "value1", "KEY2":}"#; // Missing value
        let result = parse_json(content);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_json_not_object() {
        let content = r#"["array", "not", "object"]"#;
        let result = parse_json(content);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_json_non_string_value() {
        let content = r#"{"KEY1": "value1", "KEY2": 123}"#;
        let result = parse_json(content);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_json_nested_object() {
        let content = r#"{"KEY1": "value1", "KEY2": {"nested": "object"}}"#;
        let result = parse_json(content);
        assert!(result.is_err());
    }

    #[test]
    fn test_format_dotenv_simple() {
        let entries = vec![
            SecretEntry::new("KEY1".to_string(), "value1".to_string()),
            SecretEntry::new("KEY2".to_string(), "value2".to_string()),
        ];

        let formatted = format_dotenv(&entries);
        assert_eq!(formatted, "KEY1=value1\nKEY2=value2");
    }

    #[test]
    fn test_format_dotenv_empty() {
        let entries = vec![];
        let formatted = format_dotenv(&entries);
        assert_eq!(formatted, "");
    }

    #[test]
    fn test_format_dotenv_with_spaces() {
        let entries = vec![
            SecretEntry::new("KEY1".to_string(), "value with spaces".to_string()),
            SecretEntry::new("KEY2".to_string(), "simple".to_string()),
        ];

        let formatted = format_dotenv(&entries);
        assert_eq!(formatted, "KEY1=\"value with spaces\"\nKEY2=simple");
    }

    #[test]
    fn test_format_dotenv_with_special_chars() {
        let entries = vec![
            SecretEntry::new("KEY1".to_string(), "line1\nline2".to_string()),
            SecretEntry::new("KEY2".to_string(), "tab\there".to_string()),
            SecretEntry::new("KEY3".to_string(), "quote\"here".to_string()),
            SecretEntry::new("KEY4".to_string(), "backslash\\here".to_string()),
        ];

        let formatted = format_dotenv(&entries);
        let expected = "KEY1=\"line1\\nline2\"\nKEY2=\"tab\\there\"\nKEY3=\"quote\\\"here\"\nKEY4=\"backslash\\\\here\"";
        assert_eq!(formatted, expected);
    }

    #[test]
    fn test_format_dotenv_empty_values() {
        let entries = vec![
            SecretEntry::new("KEY1".to_string(), "".to_string()),
            SecretEntry::new("KEY2".to_string(), "value".to_string()),
        ];

        let formatted = format_dotenv(&entries);
        assert_eq!(formatted, "KEY1=\"\"\nKEY2=value");
    }

    #[test]
    fn test_format_dotenv_comment_like() {
        let entries = vec![
            SecretEntry::new("KEY1".to_string(), "#not a comment".to_string()),
            SecretEntry::new("KEY2".to_string(), "normal".to_string()),
        ];

        let formatted = format_dotenv(&entries);
        assert_eq!(formatted, "KEY1=\"#not a comment\"\nKEY2=normal");
    }

    #[test]
    fn test_needs_quoting() {
        assert!(needs_quoting(""));
        assert!(needs_quoting("value with spaces"));
        assert!(needs_quoting("value\twith\ttabs"));
        assert!(needs_quoting("value\nwith\nnewlines"));
        assert!(needs_quoting("value\"with\"quotes"));
        assert!(needs_quoting("value'with'quotes"));
        assert!(needs_quoting("value\\with\\backslashes"));
        assert!(needs_quoting("#starts with hash"));

        assert!(!needs_quoting("simple"));
        assert!(!needs_quoting("simple_value"));
        assert!(!needs_quoting("123"));
        assert!(!needs_quoting("value-with-dashes"));
    }

    #[test]
    fn test_format_json_simple() {
        let entries = vec![
            SecretEntry::new("KEY1".to_string(), "value1".to_string()),
            SecretEntry::new("KEY2".to_string(), "value2".to_string()),
        ];

        let formatted = format_json(&entries).unwrap();
        let expected = "{\n  \"KEY1\": \"value1\",\n  \"KEY2\": \"value2\"\n}";
        assert_eq!(formatted, expected);
    }

    #[test]
    fn test_format_json_empty() {
        let entries = vec![];
        let formatted = format_json(&entries).unwrap();
        assert_eq!(formatted, "{}");
    }

    #[test]
    fn test_format_json_with_special_chars() {
        let entries = vec![
            SecretEntry::new("KEY1".to_string(), "line1\nline2".to_string()),
            SecretEntry::new("KEY2".to_string(), "quote\"here".to_string()),
        ];

        let formatted = format_json(&entries).unwrap();
        let expected = "{\n  \"KEY1\": \"line1\\nline2\",\n  \"KEY2\": \"quote\\\"here\"\n}";
        assert_eq!(formatted, expected);
    }

    #[test]
    fn test_format_json_sorted_keys() {
        let entries = vec![
            SecretEntry::new("ZZZ".to_string(), "last".to_string()),
            SecretEntry::new("AAA".to_string(), "first".to_string()),
            SecretEntry::new("MMM".to_string(), "middle".to_string()),
        ];

        let formatted = format_json(&entries).unwrap();
        let expected = "{\n  \"AAA\": \"first\",\n  \"MMM\": \"middle\",\n  \"ZZZ\": \"last\"\n}";
        assert_eq!(formatted, expected);
    }

    #[test]
    fn test_format_json_empty_values() {
        let entries = vec![
            SecretEntry::new("KEY1".to_string(), "".to_string()),
            SecretEntry::new("KEY2".to_string(), "value".to_string()),
        ];

        let formatted = format_json(&entries).unwrap();
        let expected = "{\n  \"KEY1\": \"\",\n  \"KEY2\": \"value\"\n}";
        assert_eq!(formatted, expected);
    }

    #[test]
    fn test_format_shell_simple() {
        let entries = vec![
            SecretEntry::new("KEY1".to_string(), "value1".to_string()),
            SecretEntry::new("KEY2".to_string(), "value2".to_string()),
        ];

        let formatted = format_shell(&entries);
        assert_eq!(formatted, "export KEY1='value1'\nexport KEY2='value2'");
    }

    #[test]
    fn test_format_shell_empty() {
        let entries = vec![];
        let formatted = format_shell(&entries);
        assert_eq!(formatted, "");
    }

    #[test]
    fn test_format_shell_with_spaces() {
        let entries = vec![
            SecretEntry::new("KEY1".to_string(), "value with spaces".to_string()),
            SecretEntry::new("KEY2".to_string(), "simple".to_string()),
        ];

        let formatted = format_shell(&entries);
        assert_eq!(
            formatted,
            "export KEY1='value with spaces'\nexport KEY2='simple'"
        );
    }

    #[test]
    fn test_format_shell_with_single_quotes() {
        let entries = vec![
            SecretEntry::new("KEY1".to_string(), "value'with'quotes".to_string()),
            SecretEntry::new("KEY2".to_string(), "don't".to_string()),
        ];

        let formatted = format_shell(&entries);
        assert_eq!(
            formatted,
            "export KEY1='value'\"'\"'with'\"'\"'quotes'\nexport KEY2='don'\"'\"'t'"
        );
    }

    #[test]
    fn test_format_shell_with_special_chars() {
        let entries = vec![
            SecretEntry::new("KEY1".to_string(), "line1\nline2".to_string()),
            SecretEntry::new("KEY2".to_string(), "tab\there".to_string()),
            SecretEntry::new("KEY3".to_string(), "$VAR".to_string()),
            SecretEntry::new("KEY4".to_string(), "`command`".to_string()),
        ];

        let formatted = format_shell(&entries);
        let expected = "export KEY1='line1\nline2'\nexport KEY2='tab\there'\nexport KEY3='$VAR'\nexport KEY4='`command`'";
        assert_eq!(formatted, expected);
    }

    #[test]
    fn test_format_shell_empty_values() {
        let entries = vec![
            SecretEntry::new("KEY1".to_string(), "".to_string()),
            SecretEntry::new("KEY2".to_string(), "value".to_string()),
        ];

        let formatted = format_shell(&entries);
        assert_eq!(formatted, "export KEY1=''\nexport KEY2='value'");
    }

    #[test]
    fn test_escape_for_shell() {
        assert_eq!(escape_for_shell("simple"), "simple");
        assert_eq!(escape_for_shell("value with spaces"), "value with spaces");
        assert_eq!(
            escape_for_shell("value'with'quotes"),
            "value'\"'\"'with'\"'\"'quotes"
        );
        assert_eq!(escape_for_shell("don't"), "don'\"'\"'t");
        assert_eq!(escape_for_shell("'"), "'\"'\"'");
        assert_eq!(escape_for_shell(""), "");
    }

    #[test]
    fn test_format_yaml_simple() {
        let entries = vec![
            SecretEntry::new("KEY1".to_string(), "value1".to_string()),
            SecretEntry::new("KEY2".to_string(), "value2".to_string()),
        ];

        let formatted = format_yaml(&entries);
        assert_eq!(formatted, "KEY1: value1\nKEY2: value2");
    }

    #[test]
    fn test_format_yaml_empty() {
        let entries = vec![];
        let formatted = format_yaml(&entries);
        assert_eq!(formatted, "");
    }

    #[test]
    fn test_format_yaml_with_special_chars() {
        let entries = vec![
            SecretEntry::new("KEY1".to_string(), "line1\nline2".to_string()),
            SecretEntry::new("KEY2".to_string(), "tab\there".to_string()),
            SecretEntry::new("KEY3".to_string(), "quote\"here".to_string()),
            SecretEntry::new("KEY4".to_string(), "backslash\\here".to_string()),
        ];

        let formatted = format_yaml(&entries);
        let expected = "KEY1: \"line1\\nline2\"\nKEY2: \"tab\\there\"\nKEY3: \"quote\\\"here\"\nKEY4: \"backslash\\\\here\"";
        assert_eq!(formatted, expected);
    }

    #[test]
    fn test_format_yaml_empty_values() {
        let entries = vec![
            SecretEntry::new("KEY1".to_string(), "".to_string()),
            SecretEntry::new("KEY2".to_string(), "value".to_string()),
        ];

        let formatted = format_yaml(&entries);
        assert_eq!(formatted, "KEY1: \"\"\nKEY2: value");
    }

    #[test]
    fn test_format_yaml_yaml_keywords() {
        let entries = vec![
            SecretEntry::new("KEY1".to_string(), "true".to_string()),
            SecretEntry::new("KEY2".to_string(), "false".to_string()),
            SecretEntry::new("KEY3".to_string(), "null".to_string()),
            SecretEntry::new("KEY4".to_string(), "123".to_string()),
            SecretEntry::new("KEY5".to_string(), "3.14".to_string()),
        ];

        let formatted = format_yaml(&entries);
        let expected =
            "KEY1: \"true\"\nKEY2: \"false\"\nKEY3: \"null\"\nKEY4: \"123\"\nKEY5: \"3.14\"";
        assert_eq!(formatted, expected);
    }

    #[test]
    fn test_format_yaml_special_prefixes() {
        let entries = vec![
            SecretEntry::new("KEY1".to_string(), "#comment".to_string()),
            SecretEntry::new("KEY2".to_string(), "!tag".to_string()),
            SecretEntry::new("KEY3".to_string(), "&anchor".to_string()),
            SecretEntry::new("KEY4".to_string(), "*reference".to_string()),
        ];

        let formatted = format_yaml(&entries);
        let expected =
            "KEY1: \"#comment\"\nKEY2: \"!tag\"\nKEY3: \"&anchor\"\nKEY4: \"*reference\"";
        assert_eq!(formatted, expected);
    }

    #[test]
    fn test_format_yaml_with_colons() {
        let entries = vec![
            SecretEntry::new("KEY1".to_string(), "key: value".to_string()),
            SecretEntry::new("KEY2".to_string(), "simple".to_string()),
        ];

        let formatted = format_yaml(&entries);
        assert_eq!(formatted, "KEY1: \"key: value\"\nKEY2: simple");
    }

    #[test]
    fn test_needs_yaml_quoting() {
        // Should be quoted
        assert!(needs_yaml_quoting(""));
        assert!(needs_yaml_quoting("true"));
        assert!(needs_yaml_quoting("false"));
        assert!(needs_yaml_quoting("null"));
        assert!(needs_yaml_quoting("123"));
        assert!(needs_yaml_quoting("3.14"));
        assert!(needs_yaml_quoting("#comment"));
        assert!(needs_yaml_quoting("!tag"));
        assert!(needs_yaml_quoting("&anchor"));
        assert!(needs_yaml_quoting("*reference"));
        assert!(needs_yaml_quoting("key: value"));
        assert!(needs_yaml_quoting(" starts with space"));
        assert!(needs_yaml_quoting("ends with space "));
        assert!(needs_yaml_quoting("line1\nline2"));
        assert!(needs_yaml_quoting("tab\there"));
        assert!(needs_yaml_quoting("quote\"here"));
        assert!(needs_yaml_quoting("backslash\\here"));

        // Should not be quoted
        assert!(!needs_yaml_quoting("simple"));
        assert!(!needs_yaml_quoting("simple_value"));
        assert!(!needs_yaml_quoting("value-with-dashes"));
        assert!(!needs_yaml_quoting("value.with.dots"));
        assert!(!needs_yaml_quoting("value/with/slashes"));
    }

    #[test]
    fn test_detect_format_from_path() {
        assert_eq!(
            detect_format_from_path("secrets.env"),
            Some(SecretFormat::Dotenv)
        );
        assert_eq!(
            detect_format_from_path("config.json"),
            Some(SecretFormat::Json)
        );
        assert_eq!(
            detect_format_from_path("export.sh"),
            Some(SecretFormat::Shell)
        );
        assert_eq!(
            detect_format_from_path("values.yaml"),
            Some(SecretFormat::Yaml)
        );
        assert_eq!(
            detect_format_from_path("values.yml"),
            Some(SecretFormat::Yaml)
        );

        // Case insensitive
        assert_eq!(
            detect_format_from_path("CONFIG.JSON"),
            Some(SecretFormat::Json)
        );
        assert_eq!(
            detect_format_from_path("EXPORT.SH"),
            Some(SecretFormat::Shell)
        );

        // No extension
        assert_eq!(detect_format_from_path("secrets"), None);

        // Unknown extension
        assert_eq!(detect_format_from_path("secrets.txt"), None);

        // Path with directories
        assert_eq!(
            detect_format_from_path("/path/to/secrets.env"),
            Some(SecretFormat::Dotenv)
        );
        assert_eq!(
            detect_format_from_path("./config/app.json"),
            Some(SecretFormat::Json)
        );
    }

    #[test]
    fn test_parse_secrets() {
        // Test dotenv parsing
        let content = "KEY1=value1\nKEY2=value2";
        let entries = parse_secrets(content, SecretFormat::Dotenv).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key, "KEY1");
        assert_eq!(entries[0].value, "value1");

        // Test JSON parsing
        let content = r#"{"KEY1": "value1", "KEY2": "value2"}"#;
        let entries = parse_secrets(content, SecretFormat::Json).unwrap();
        assert_eq!(entries.len(), 2);

        // Test shell parsing (should fail)
        let result = parse_secrets("export KEY=value", SecretFormat::Shell);
        assert!(result.is_err());

        // Test YAML parsing (should fail - not implemented)
        let result = parse_secrets("KEY: value", SecretFormat::Yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_format_secrets() {
        let entries = vec![
            SecretEntry::new("KEY1".to_string(), "value1".to_string()),
            SecretEntry::new("KEY2".to_string(), "value2".to_string()),
        ];

        // Test dotenv formatting
        let formatted = format_secrets(&entries, SecretFormat::Dotenv).unwrap();
        assert_eq!(formatted, "KEY1=value1\nKEY2=value2");

        // Test JSON formatting
        let formatted = format_secrets(&entries, SecretFormat::Json).unwrap();
        assert!(formatted.contains("\"KEY1\": \"value1\""));
        assert!(formatted.contains("\"KEY2\": \"value2\""));

        // Test shell formatting
        let formatted = format_secrets(&entries, SecretFormat::Shell).unwrap();
        assert_eq!(formatted, "export KEY1='value1'\nexport KEY2='value2'");

        // Test YAML formatting
        let formatted = format_secrets(&entries, SecretFormat::Yaml).unwrap();
        assert_eq!(formatted, "KEY1: value1\nKEY2: value2");
    }
}
