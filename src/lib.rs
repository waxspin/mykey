//! # mykey
//!
//! A Rust implementation of MIKEY (Multimedia Internet KEYing, RFC 3830)
//! for SRTP key exchange.
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
//! - Security policy for SRTP parameters
//! - SAP integration with SDP `a=key-mgmt:mikey` attribute (RFC 4567)
//! - Message parsing and serialization (wire format)

pub mod crypto;
pub mod error;
pub mod identity;
pub mod message;
pub mod payload;
pub mod policy;
pub mod sap;
pub mod srtp;

pub use error::MikeyError;
pub use identity::{Identity, PinnedPeer};
pub use message::{DhInitiator, DhResponder, KeyExchangeMethod, MikeyMessage};
pub use policy::SrtpPolicy;
pub use sap::{build_sap_with_mikey, mikey_from_sdp_attribute, mikey_to_sdp_attribute, SapPacket};
pub use srtp::SrtpKeyMaterial;
