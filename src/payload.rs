#![allow(missing_docs)]

/// MIKEY payload types as defined in RFC 3830 Section 6.1
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PayloadType {
    /// Common header payload
    Hdr = 0,
    /// Key data transport (KEMAC)
    Kemac = 1,
    /// Envelope data (PKE)
    Pke = 2,
    /// DH data
    Dh = 3,
    /// Signature
    Sign = 4,
    /// Timestamp
    T = 5,
    /// ID payload
    Id = 6,
    /// Certificate payload
    Cert = 7,
    /// CHASH — hash of cert chain
    Chash = 8,
    /// Verification message (V)
    V = 9,
    /// Security policy (SP)
    Sp = 10,
    /// RAND payload
    Rand = 11,
    /// Error payload
    Err = 12,
    /// Key data sub-payload
    KeyData = 20,
    /// General extension
    GeneralExt = 21,
    /// Last payload marker
    Last = 255,
}

impl PayloadType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Hdr),
            1 => Some(Self::Kemac),
            2 => Some(Self::Pke),
            3 => Some(Self::Dh),
            4 => Some(Self::Sign),
            5 => Some(Self::T),
            6 => Some(Self::Id),
            7 => Some(Self::Cert),
            8 => Some(Self::Chash),
            9 => Some(Self::V),
            10 => Some(Self::Sp),
            11 => Some(Self::Rand),
            12 => Some(Self::Err),
            20 => Some(Self::KeyData),
            21 => Some(Self::GeneralExt),
            255 => Some(Self::Last),
            _ => None,
        }
    }
}

/// MIKEY Common Header (RFC 3830 Section 6.1)
#[derive(Debug, Clone)]
pub struct CommonHeader {
    pub version: u8,
    pub data_type: DataType,
    pub next_payload: u8,
    pub v_flag: bool,
    pub prf_func: PrfFunc,
    pub csc_id: u32,
    pub cs_count: u8,
    pub cs_id_map_type: u8,
    /// SRTP-ID entries (when cs_id_map_type == 0)
    pub cs_id_map: Vec<SrtpId>,
}

/// SRTP-ID map entry (RFC 3830 Section 6.1.1)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrtpId {
    pub policy_no: u8,
    pub ssrc: u32,
    pub roc: u32,
}

/// MIKEY data types (key exchange methods)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DataType {
    /// Pre-shared key initiator
    PskInit = 0,
    /// Pre-shared key responder
    PskResp = 1,
    /// Public key initiator
    PkInit = 2,
    /// Public key responder
    PkResp = 3,
    /// DH initiator
    DhInit = 4,
    /// DH responder
    DhResp = 5,
    /// Error message
    Error = 6,
}

impl DataType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::PskInit),
            1 => Some(Self::PskResp),
            2 => Some(Self::PkInit),
            3 => Some(Self::PkResp),
            4 => Some(Self::DhInit),
            5 => Some(Self::DhResp),
            6 => Some(Self::Error),
            _ => None,
        }
    }
}

/// PRF function identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PrfFunc {
    MikeyPrfHmacSha256 = 0,
}

impl PrfFunc {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::MikeyPrfHmacSha256),
            _ => None,
        }
    }
}

/// Timestamp payload (RFC 3830 Section 6.6)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimestampPayload {
    pub next_payload: u8,
    pub ts_type: TimestampType,
    pub ts_value: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TimestampType {
    Ntp64 = 0,
    NtpShort = 1,
    Counter = 2,
}

impl TimestampType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Ntp64),
            1 => Some(Self::NtpShort),
            2 => Some(Self::Counter),
            _ => None,
        }
    }

    /// Size of the timestamp value in bytes
    pub fn value_len(&self) -> usize {
        match self {
            Self::Ntp64 => 8,
            Self::NtpShort => 4,
            Self::Counter => 4,
        }
    }
}

/// RAND payload (RFC 3830 Section 6.11)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RandPayload {
    pub next_payload: u8,
    pub rand: Vec<u8>,
}

/// DH data payload (RFC 3830 Section 6.4)
///
/// Wire format: next_payload(1) | DH-Group(1) | DH-value(group_len) | KV-type(1) [| KV-data]
/// Note: DH-value length is implied by DH-Group, not explicitly encoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhPayload {
    pub next_payload: u8,
    pub dh_group: DhGroup,
    pub dh_value: Vec<u8>,
    pub kv_type: u8,
    pub kv_data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DhGroup {
    /// OAKLEY group 5 (1536-bit MODP)
    Oakley5 = 0,
    /// OAKLEY group 1 (768-bit MODP)
    Oakley1 = 1,
    /// OAKLEY group 2 (1024-bit MODP)
    Oakley2 = 2,
    /// X25519 (modern curve)
    X25519 = 255,
}

impl DhGroup {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Oakley5),
            1 => Some(Self::Oakley1),
            2 => Some(Self::Oakley2),
            255 => Some(Self::X25519),
            _ => None,
        }
    }

    pub fn key_len(&self) -> usize {
        match self {
            Self::Oakley5 => 192,
            Self::Oakley1 => 96,
            Self::Oakley2 => 128,
            Self::X25519 => 32,
        }
    }
}

/// KEMAC payload (RFC 3830 Section 6.2)
///
/// Wire format: next_payload(1) | enc_alg(1) | enc_data_len(2) | enc_data(N) | mac_alg(1) | MAC(M)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KemacPayload {
    pub next_payload: u8,
    pub enc_alg: EncAlg,
    pub mac_alg: MacAlg,
    pub enc_data: Vec<u8>,
    pub mac: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EncAlg {
    Null = 0,
    AesCm128 = 1,
    AesKw128 = 2,
}

impl EncAlg {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Null),
            1 => Some(Self::AesCm128),
            2 => Some(Self::AesKw128),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MacAlg {
    Null = 0,
    HmacSha1160 = 1,
}

impl MacAlg {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Null),
            1 => Some(Self::HmacSha1160),
            _ => None,
        }
    }

    pub fn mac_len(&self) -> usize {
        match self {
            Self::HmacSha1160 => 20, // HMAC-SHA-1-160 per RFC 3830
            Self::Null => 0,
        }
    }
}

/// Security Policy payload (RFC 3830 Section 6.10)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpPayload {
    pub next_payload: u8,
    pub policy_no: u8,
    pub proto_type: u8,
    pub params: Vec<SpParam>,
}

/// Security policy parameter (TLV)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpParam {
    pub param_type: u8,
    pub param_len: u8,
    pub param_value: Vec<u8>,
}

/// SRTP security policy parameter types (RFC 3830 Section 6.10.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SrtpParamType {
    EncryptionAlg = 0,
    SessionEncKeyLen = 1,
    AuthAlg = 2,
    SessionAuthKeyLen = 3,
    SessionSaltKeyLen = 4,
    PrfAlg = 5,
    KeyDerivRate = 6,
    SrtpEncryption = 7,
    SrtcpEncryption = 8,
    FecOrder = 9,
    SrtpAuthentication = 10,
    AuthTagLen = 11,
    SrtpPrefixLen = 12,
}

/// ID payload (RFC 3830 Section 6.7)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdPayload {
    pub next_payload: u8,
    pub id_type: u8,
    pub id_data: Vec<u8>,
}

/// Verification payload (RFC 3830 Section 6.9)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationPayload {
    pub next_payload: u8,
    pub mac: Vec<u8>,
}

/// A generic parsed MIKEY payload
#[derive(Debug, Clone)]
pub enum Payload {
    Header(CommonHeader),
    Kemac(KemacPayload),
    Dh(DhPayload),
    Timestamp(TimestampPayload),
    Id(IdPayload),
    Sp(SpPayload),
    Rand(RandPayload),
    Verification(VerificationPayload),
}

impl Payload {
    /// Get the next_payload field from any payload variant
    pub fn next_payload_type(&self) -> u8 {
        match self {
            Payload::Kemac(p) => p.next_payload,
            Payload::Dh(p) => p.next_payload,
            Payload::Timestamp(p) => p.next_payload,
            Payload::Id(p) => p.next_payload,
            Payload::Sp(p) => p.next_payload,
            Payload::Rand(p) => p.next_payload,
            Payload::Verification(p) => p.next_payload,
            Payload::Header(h) => h.next_payload,
        }
    }
}
