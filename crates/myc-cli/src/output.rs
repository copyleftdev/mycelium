//! Output formatting for the Mycelium CLI.
//!
//! This module provides formatters for both human-readable and JSON output,
//! with support for colored output, tables, and progress indicators.

use anyhow::Result;
use console::{style, Color, Style, Term};
use indicatif::{ProgressBar, ProgressStyle};
use serde_json::Value;
use std::collections::HashMap;
use std::env;

use std::time::Duration;

/// Output formatter that handles both human-readable and JSON output.
pub struct OutputFormatter {
    /// Whether to output JSON format
    json_mode: bool,
    /// Whether to suppress non-essential output
    quiet: bool,
    /// Whether colors are enabled
    colors_enabled: bool,
    /// Terminal for output
    term: Term,
}

impl OutputFormatter {
    /// Create a new output formatter.
    pub fn new(json_mode: bool, quiet: bool, no_color: bool) -> Self {
        let colors_enabled = !no_color
            && env::var("NO_COLOR").is_err()
            && env::var("TERM").map_or(true, |term| term != "dumb");

        Self {
            json_mode,
            quiet,
            colors_enabled,
            term: Term::stdout(),
        }
    }

    /// Check if we're in JSON mode.
    pub fn is_json_mode(&self) -> bool {
        self.json_mode
    }

    /// Check if we're in quiet mode.
    pub fn is_quiet(&self) -> bool {
        self.quiet
    }

    /// Print a success message.
    pub fn success(&self, message: &str) -> Result<()> {
        if self.json_mode {
            let output = serde_json::json!({
                "success": true,
                "message": message
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        } else if !self.quiet {
            let checkmark = if self.colors_enabled {
                style("✓").green()
            } else {
                style("✓")
            };
            println!("{} {}", checkmark, message);
        }
        Ok(())
    }

    /// Print an error message.
    pub fn error(&self, message: &str) -> Result<()> {
        if self.json_mode {
            let output = serde_json::json!({
                "success": false,
                "error": "general_error",
                "message": message
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        } else {
            let x_mark = if self.colors_enabled {
                style("✗").red()
            } else {
                style("✗")
            };
            eprintln!("{} {}", x_mark, message);
        }
        Ok(())
    }

    /// Print a warning message.
    pub fn warning(&self, message: &str) -> Result<()> {
        if self.json_mode {
            let output = serde_json::json!({
                "warning": true,
                "message": message
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        } else if !self.quiet {
            let warning = if self.colors_enabled {
                style("⚠").yellow()
            } else {
                style("⚠")
            };
            println!("{} {}", warning, message);
        }
        Ok(())
    }

    /// Print an info message.
    pub fn info(&self, message: &str) -> Result<()> {
        if !self.json_mode && !self.quiet {
            println!("{}", message);
        }
        Ok(())
    }

    /// Print a verbose message (only shown in verbose mode).
    pub fn verbose(&self, message: &str, verbose_level: u8) -> Result<()> {
        if !self.json_mode && !self.quiet && verbose_level > 0 {
            let info = if self.colors_enabled {
                style("ℹ").blue()
            } else {
                style("ℹ")
            };
            println!("{} {}", info, message);
        }
        Ok(())
    }

    /// Print a table with headers and rows.
    pub fn table(&self, headers: &[&str], rows: &[Vec<String>]) -> Result<()> {
        if self.json_mode {
            let mut table_data = Vec::new();
            for row in rows {
                let mut row_obj = HashMap::new();
                for (i, header) in headers.iter().enumerate() {
                    if let Some(value) = row.get(i) {
                        row_obj.insert(header.to_string(), value.clone());
                    }
                }
                table_data.push(row_obj);
            }
            let output = serde_json::json!({
                "table": table_data
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        } else if !self.quiet {
            self.print_table(headers, rows)?;
        }
        Ok(())
    }

    /// Print a list of items with optional markers.
    pub fn list(&self, items: &[(String, Option<String>)]) -> Result<()> {
        if self.json_mode {
            let list_data: Vec<_> = items
                .iter()
                .map(|(item, marker)| {
                    serde_json::json!({
                        "item": item,
                        "marker": marker
                    })
                })
                .collect();
            let output = serde_json::json!({
                "list": list_data
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        } else if !self.quiet {
            for (item, marker) in items {
                if let Some(marker_text) = marker {
                    let styled_marker = if self.colors_enabled {
                        match marker_text.as_str() {
                            "*" => style("*").green(),
                            "!" => style("!").yellow(),
                            "x" => style("x").red(),
                            _ => style(marker_text.as_str()),
                        }
                    } else {
                        style(marker_text.as_str())
                    };
                    println!("  {} {}", styled_marker, item);
                } else {
                    println!("  {}", item);
                }
            }
        }
        Ok(())
    }

    /// Create a progress bar for long-running operations.
    pub fn progress_bar(&self, message: &str, total: Option<u64>) -> Option<ProgressBar> {
        if self.json_mode || self.quiet {
            return None;
        }

        let pb = if let Some(total) = total {
            ProgressBar::new(total)
        } else {
            ProgressBar::new_spinner()
        };

        let style = if total.is_some() {
            ProgressStyle::with_template(
                "{spinner:.green} {msg} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} ({eta})"
            )
        } else {
            ProgressStyle::with_template(
                "{spinner:.green} {msg} [{elapsed_precise}]"
            )
        }.unwrap_or_else(|_| ProgressStyle::default_bar());

        pb.set_style(style);
        pb.set_message(message.to_string());
        pb.enable_steady_tick(Duration::from_millis(100));

        Some(pb)
    }

    /// Create a spinner for indeterminate progress.
    pub fn spinner(&self, message: &str) -> Option<ProgressBar> {
        if self.json_mode || self.quiet {
            return None;
        }

        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::with_template("{spinner:.green} {msg}")
                .unwrap_or_else(|_| ProgressStyle::default_spinner()),
        );
        pb.set_message(message.to_string());
        pb.enable_steady_tick(Duration::from_millis(100));

        Some(pb)
    }

    /// Print JSON output for structured data.
    pub fn json(&self, data: &Value) -> Result<()> {
        if self.json_mode {
            println!("{}", serde_json::to_string_pretty(data)?);
        }
        Ok(())
    }

    /// Print structured output (JSON in JSON mode, formatted in human mode).
    pub fn output<T: serde::Serialize>(&self, data: &T) -> Result<()> {
        if self.json_mode {
            println!("{}", serde_json::to_string_pretty(data)?);
        } else {
            // For human-readable mode, we'd need specific formatting logic
            // This is a fallback that converts to JSON and prints
            let json_value = serde_json::to_value(data)?;
            self.print_human_readable(&json_value)?;
        }
        Ok(())
    }

    /// Print a key-value pair.
    pub fn field(&self, key: &str, value: &str) -> Result<()> {
        if !self.json_mode && !self.quiet {
            let key_style = if self.colors_enabled {
                style(key).bold()
            } else {
                style(key)
            };
            println!("  {}: {}", key_style, value);
        }
        Ok(())
    }

    /// Print a section header.
    pub fn section(&self, title: &str) -> Result<()> {
        if !self.json_mode && !self.quiet {
            let title_style = if self.colors_enabled {
                style(title).bold().underlined()
            } else {
                style(title).bold()
            };
            println!("{}", title_style);
        }
        Ok(())
    }

    /// Print an empty line (for spacing).
    pub fn newline(&self) -> Result<()> {
        if !self.json_mode && !self.quiet {
            println!();
        }
        Ok(())
    }

    /// Internal method to print a table in human-readable format.
    fn print_table(&self, headers: &[&str], rows: &[Vec<String>]) -> Result<()> {
        if headers.is_empty() || rows.is_empty() {
            return Ok(());
        }

        // Calculate column widths
        let mut widths = headers.iter().map(|h| h.len()).collect::<Vec<_>>();
        for row in rows {
            for (i, cell) in row.iter().enumerate() {
                if let Some(width) = widths.get_mut(i) {
                    *width = (*width).max(cell.len());
                }
            }
        }

        // Print headers
        let header_style = if self.colors_enabled {
            Style::new().bold()
        } else {
            Style::new()
        };

        for (i, header) in headers.iter().enumerate() {
            if i > 0 {
                print!("  ");
            }
            print!(
                "{:<width$}",
                header_style.apply_to(header),
                width = widths[i]
            );
        }
        println!();

        // Print separator
        for (i, &width) in widths.iter().enumerate() {
            if i > 0 {
                print!("  ");
            }
            print!("{}", "-".repeat(width));
        }
        println!();

        // Print rows
        for row in rows {
            for (i, cell) in row.iter().enumerate() {
                if i > 0 {
                    print!("  ");
                }
                if let Some(&width) = widths.get(i) {
                    print!("{:<width$}", cell, width = width);
                }
            }
            println!();
        }

        Ok(())
    }

    /// Internal method to print JSON in a human-readable format.
    fn print_human_readable(&self, value: &Value) -> Result<()> {
        match value {
            Value::Object(map) => {
                for (key, val) in map {
                    match val {
                        Value::String(s) => self.field(key, s)?,
                        Value::Number(n) => self.field(key, &n.to_string())?,
                        Value::Bool(b) => self.field(key, &b.to_string())?,
                        Value::Null => self.field(key, "null")?,
                        _ => self.field(key, &serde_json::to_string(val)?)?,
                    }
                }
            }
            _ => {
                println!("{}", serde_json::to_string_pretty(value)?);
            }
        }
        Ok(())
    }
}

/// Helper function to create a styled string based on color preferences.
pub fn styled_text(text: &str, color: Color, bold: bool, colors_enabled: bool) -> String {
    if colors_enabled {
        let mut style = Style::new().fg(color);
        if bold {
            style = style.bold();
        }
        style.apply_to(text).to_string()
    } else {
        text.to_string()
    }
}

/// Helper function to format duration in human-readable format.
pub fn format_duration(duration: Duration) -> String {
    let secs = duration.as_secs();
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    }
}

/// Helper function to format file sizes in human-readable format.
pub fn format_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("{} {}", bytes, UNITS[unit_index])
    } else {
        format!("{:.1} {}", size, UNITS[unit_index])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(Duration::from_secs(30)), "30s");
        assert_eq!(format_duration(Duration::from_secs(90)), "1m 30s");
        assert_eq!(format_duration(Duration::from_secs(3661)), "1h 1m");
    }

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(1536), "1.5 KB");
        assert_eq!(format_size(1048576), "1.0 MB");
        assert_eq!(format_size(1073741824), "1.0 GB");
    }

    #[test]
    fn test_output_formatter_creation() {
        let formatter = OutputFormatter::new(false, false, false);
        assert!(!formatter.is_json_mode());
        assert!(!formatter.is_quiet());

        let json_formatter = OutputFormatter::new(true, false, false);
        assert!(json_formatter.is_json_mode());
    }
}
