use thiserror::Error;

#[derive(Debug, Error)]
pub enum MikeyError {
    #[error("invalid MIKEY version: {0}")]
    InvalidVersion(u8),

    #[error("unsupported data type: {0}")]
    UnsupportedDataType(u8),

    #[error("unsupported key exchange method: {0}")]
    UnsupportedKeyExchange(u8),

    #[error("invalid payload type: {0}")]
    InvalidPayloadType(u8),

    #[error("message too short: expected at least {expected} bytes, got {actual}")]
    MessageTooShort { expected: usize, actual: usize },

    #[error("invalid MAC: verification failed")]
    InvalidMac,

    #[error("invalid DH value")]
    InvalidDhValue,

    #[error("missing required payload: {0}")]
    MissingPayload(&'static str),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("peer key mismatch for '{peer}': expected {expected}, received {received}")]
    PeerKeyMismatch {
        peer: String,
        expected: String,
        received: String,
    },

    #[error("parse error: {0}")]
    Parse(String),
}

pub type Result<T> = std::result::Result<T, MikeyError>;
