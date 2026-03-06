//! Error types returned by mykey.

use thiserror::Error;

/// All errors that mykey operations can produce.
#[derive(Debug, Error)]
pub enum MikeyError {
    /// The MIKEY version byte was not `1`.
    #[error("invalid MIKEY version: {0}")]
    InvalidVersion(u8),

    /// The data type byte does not correspond to a known MIKEY message type.
    #[error("unsupported data type: {0}")]
    UnsupportedDataType(u8),

    /// The key exchange method byte is not recognized.
    #[error("unsupported key exchange method: {0}")]
    UnsupportedKeyExchange(u8),

    /// A payload type byte is outside the set of known types.
    #[error("invalid payload type: {0}")]
    InvalidPayloadType(u8),

    /// The message buffer is shorter than the minimum required length.
    #[error("message too short: expected at least {expected} bytes, got {actual}")]
    MessageTooShort {
        /// Minimum expected byte count.
        expected: usize,
        /// Actual byte count received.
        actual: usize,
    },

    /// HMAC-SHA-256 verification failed (wrong PSK or tampered message).
    #[error("invalid MAC: verification failed")]
    InvalidMac,

    /// The DH value bytes are not a valid X25519 public key.
    #[error("invalid DH value")]
    InvalidDhValue,

    /// A payload required by the operation was absent from the message.
    #[error("missing required payload: {0}")]
    MissingPayload(&'static str),

    /// A low-level cryptographic operation failed.
    #[error("crypto error: {0}")]
    Crypto(String),

    /// The DH public key received from a peer did not match the pinned key.
    #[error("peer key mismatch for '{peer}': expected {expected}, received {received}")]
    PeerKeyMismatch {
        /// Name of the expected peer.
        peer: String,
        /// Hex-encoded expected public key.
        expected: String,
        /// Hex-encoded received public key.
        received: String,
    },

    /// Wire-format parsing failed.
    #[error("parse error: {0}")]
    Parse(String),
}

/// Convenience alias for `Result<T, MikeyError>`.
pub type Result<T> = std::result::Result<T, MikeyError>;
