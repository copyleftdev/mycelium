//! Core domain types and business logic for Mycelium.
//!
//! This crate defines all domain types with versioned serialization and validation.
//! It depends only on `myc-crypto` for cryptographic types and performs no I/O operations.
//!
//! # Modules
//!
//! - `ids`: Type-safe identifiers (OrgId, ProjectId, etc.)
//! - `org`: Organization types
//! - `project`: Project and membership types
//! - `secret_set`: Secret set and version types
//! - `device`: Device identity types
//! - `pdk`: PDK versioning and wrapping
//! - `formats`: Secret import/export format handling
//! - `canonical`: Canonical JSON for signing
//! - `recovery`: Key recovery mechanisms and types
//! - `error`: Core error types

#![deny(missing_docs)]
#![deny(clippy::all)]

pub mod audit;
pub mod canonical;
pub mod device;
pub mod error;
pub mod formats;
pub mod ids;
pub mod membership_ops;
pub mod org;
pub mod pdk;
pub mod pdk_cache;
pub mod pdk_ops;
pub mod project;
pub mod recovery;
pub mod recovery_ops;
pub mod rotation;
pub mod secret_set;
pub mod secret_set_ops;
