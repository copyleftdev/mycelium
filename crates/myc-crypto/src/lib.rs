//! Pure cryptographic primitives for Mycelium.
//!
//! This crate provides opinionated wrappers around RustCrypto and dalek primitives
//! with a focus on security and usability. All secret key types implement `Zeroize`
//! and `ZeroizeOnDrop` to ensure secure memory clearing.
//!
//! # Modules
//!
//! - `aead`: ChaCha20-Poly1305 authenticated encryption
//! - `kex`: X25519 key exchange
//! - `sign`: Ed25519 signatures
//! - `kdf`: HKDF key derivation
//! - `hash`: BLAKE3 hashing and hash chains
//! - `random`: Secure random byte generation
//! - `error`: Cryptographic error types

#![deny(missing_docs)]
#![deny(clippy::all)]

pub mod aead;
pub mod error;
pub mod hash;
pub mod kdf;
pub mod kex;
pub mod random;
pub mod sign;
