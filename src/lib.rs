//! # mykey
//!
//! A Rust implementation of MIKEY (Multimedia Internet KEYing, RFC 3830)
//! for SRTP key exchange.
//!
//! Supports:
//! - Pre-shared key (PSK) mode
//! - Diffie-Hellman (DH) key exchange mode
//! - SRTP key material derivation

pub mod crypto;
pub mod error;
pub mod message;
pub mod payload;
pub mod srtp;

pub use error::MikeyError;
pub use message::{KeyExchangeMethod, MikeyMessage};
pub use srtp::SrtpKeyMaterial;
