//! Mycelium CLI library.
//!
//! This library provides the core functionality for the Mycelium CLI,
//! including device key management, profile management, and enrollment.

#![allow(clippy::too_many_arguments)]
#![allow(clippy::ptr_arg)]
#![allow(clippy::bool_assert_comparison)]
#![allow(clippy::collapsible_else_if)]
#![allow(dead_code)]
#![allow(unexpected_cfgs)]

pub mod audit;
pub mod device;
pub mod enrollment;
pub mod env;
pub mod error_formatting;
pub mod exit_codes;
pub mod json_output;
pub mod key_storage;
pub mod non_interactive;
pub mod output;
pub mod profile;
pub mod project_config;
pub mod prompts;
pub mod recovery;
pub mod retry;
