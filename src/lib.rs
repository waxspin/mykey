//! # mykey
//!
//! A Rust implementation of MIKEY (Multimedia Internet KEYing, RFC 3830)
//! for SRTP key exchange.
//!
//! Supports:
//! - Pre-shared key (PSK) mode
//! - Diffie-Hellman (DH) key exchange mode (X25519)
//! - SRTP key material derivation
//! - Security policy for SRTP parameters
//! - SAP integration with SDP `a=key-mgmt:mikey` attribute (RFC 4567)
//! - Message parsing and serialization (wire format)

pub mod crypto;
pub mod error;
pub mod message;
pub mod payload;
pub mod policy;
pub mod sap;
pub mod srtp;

pub use error::MikeyError;
pub use message::{DhInitiator, DhResponder, KeyExchangeMethod, MikeyMessage};
pub use policy::SrtpPolicy;
pub use sap::{build_sap_with_mikey, mikey_from_sdp_attribute, mikey_to_sdp_attribute, SapPacket};
pub use srtp::SrtpKeyMaterial;
