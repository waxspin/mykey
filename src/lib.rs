#![warn(missing_docs)]

//! # mykey
//!
//! A Rust implementation of [MIKEY] (Multimedia Internet KEYing, [RFC 3830])
//! for SRTP key exchange in AES67 and SMPTE ST 2110 environments.
//!
//! [MIKEY]: https://datatracker.ietf.org/doc/rfc3830/
//! [RFC 3830]: https://datatracker.ietf.org/doc/rfc3830/
//!
//! > **Warning:** This crate is unaudited and experimental. It has not been
//! > professionally reviewed for security vulnerabilities, timing attacks, or
//! > logical flaws. Do not use it in production environments or to protect
//! > sensitive data.
//!
//! ## Key exchange modes
//!
//! By default, all DH key exchanges use **ephemeral keys** (`EphemeralSecret`).
//! Each session generates a fresh keypair that is discarded after use. This
//! provides forward secrecy but no identity verification — suitable for
//! trusted or isolated networks (e.g., dedicated AES67 media VLANs).
//!
//! For environments where MITM protection is needed, the optional
//! [`identity`] module provides **persistent keypairs** with **peer key
//! pinning** (similar to SSH `known_hosts`). This is opt-in and requires
//! explicit use of [`Identity`] and [`PinnedPeer`].
//!
//! ## Features
//!
//! - Ephemeral Diffie-Hellman key exchange (X25519) — **default**
//! - Pre-shared key (PSK) mode
//! - Optional persistent identity with peer key pinning (MITM protection)
//! - SRTP key material derivation
//! - Security policy for SRTP parameters ([RFC 3830] §6.10.1)
//! - SAP integration with SDP `a=key-mgmt:mikey` attribute ([RFC 4567])
//! - Message parsing and serialization (wire format)
//!
//! [RFC 4567]: https://datatracker.ietf.org/doc/rfc4567/

/// MIKEY PRF, DH key pair, and MAC primitives.
pub mod crypto;
/// Error type returned by all fallible operations.
pub mod error;
/// Persistent X25519 identity keypairs and peer key pinning (opt-in MITM protection).
pub mod identity;
/// MIKEY message builder, parser, and high-level DH/PSK exchange types.
pub mod message;
/// Low-level RFC 3830 wire-format payload types.
pub mod payload;
/// SRTP security policy builder and parser.
pub mod policy;
/// SAP packet builder/parser and SDP `a=key-mgmt:mikey` helpers.
pub mod sap;
/// SRTP key material and crypto suite definitions.
pub mod srtp;

pub use error::MikeyError;
pub use identity::{Identity, PinnedPeer};
pub use message::{DhInitiator, DhResponder, KeyExchangeMethod, MikeyMessage};
pub use policy::SrtpPolicy;
pub use sap::{
    build_sap_with_mikey, mikey_from_sdp_attribute, mikey_from_sdp_body, mikey_to_sdp_attribute,
    SapPacket,
};
pub use srtp::SrtpKeyMaterial;
