#![allow(missing_docs)]

use crate::error::{MikeyError, Result};

/// MIKEY `Next Payload` values as defined in RFC 3830 Section 6.1, Table 6.1.b.
///
/// Note that the table assigns no value to the common header — `HDR` is never a
/// `Next Payload` value — and that "Last payload" is **0**, the value that
/// terminates a payload chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PayloadType {
    /// Last payload — terminates the payload chain
    Last = 0,
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
}

impl PayloadType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Last),
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
    MikeyPrfHmacSha1 = 0,
}

impl PrfFunc {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::MikeyPrfHmacSha1),
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

/// Timestamp types from RFC 3830 §6.6, Table 6.6.
///
/// NTP-UTC and NTP are both 64-bit and mandatory to implement; COUNTER is 32-bit
/// and optional.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TimestampType {
    /// NTP timestamp in UTC (64-bit), mandatory
    NtpUtc = 0,
    /// NTP timestamp (64-bit), mandatory
    Ntp = 1,
    /// Counter (32-bit), optional
    Counter = 2,
}

impl TimestampType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::NtpUtc),
            1 => Some(Self::Ntp),
            2 => Some(Self::Counter),
            _ => None,
        }
    }

    /// Size of the timestamp value in bytes, per Table 6.6.
    pub fn value_len(&self) -> usize {
        match self {
            Self::NtpUtc | Self::Ntp => 8,
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

/// Kind of key carried in a Key data sub-payload (RFC 3830 §6.13, Table 6.13.a).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KeyDataType {
    /// TEK Generation Key
    Tgk = 0,
    /// TGK with an accompanying salt
    TgkSalt = 1,
    /// Traffic-Encrypting Key, sent directly
    Tek = 2,
    /// TEK with an accompanying salt
    TekSalt = 3,
}

impl KeyDataType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Tgk),
            1 => Some(Self::TgkSalt),
            2 => Some(Self::Tek),
            3 => Some(Self::TekSalt),
            _ => None,
        }
    }

    /// Whether this type carries a salt field after the key data.
    pub fn has_salt(&self) -> bool {
        matches!(self, Self::TgkSalt | Self::TekSalt)
    }
}

/// Key validity period type (RFC 3830 §6.13, Table 6.13.b).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KeyValidityType {
    /// No specific usage rule
    Null = 0,
    /// Key is associated with an SPI or, for SRTP, an MKI
    Spi = 1,
    /// Key has a start and expiration point
    Interval = 2,
}

impl KeyValidityType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Null),
            1 => Some(Self::Spi),
            2 => Some(Self::Interval),
            _ => None,
        }
    }
}

/// Key validity data (RFC 3830 §6.14).
///
/// Not a standalone payload — it appears inside a Key data sub-payload, and its
/// shape is selected by that payload's `KV` field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyValidity {
    /// `KV = Null`: no validity data is present.
    None,
    /// `KV = SPI`: an SPI, or an MKI in the SRTP case.
    Spi(Vec<u8>),
    /// `KV = Interval`: the range over which the key is valid.
    Interval {
        /// Start point — sequence number, index or timestamp.
        valid_from: Vec<u8>,
        /// Expiry point, in the same units as `valid_from`.
        valid_to: Vec<u8>,
    },
}

impl KeyValidity {
    /// The `KV` field value that selects this shape.
    pub fn kv_type(&self) -> KeyValidityType {
        match self {
            Self::None => KeyValidityType::Null,
            Self::Spi(_) => KeyValidityType::Spi,
            Self::Interval { .. } => KeyValidityType::Interval,
        }
    }
}

/// Key data sub-payload (RFC 3830 §6.13).
///
/// Carries key material inside a KEMAC payload. Never sent in the clear — these
/// are the structures that appear in the KEMAC's encrypted `enc_data`.
///
/// Wire format: `next_payload(1) | type:4 kv:4 | key_data_len(2) | key_data(N)
/// [| salt_len(2) | salt(M)] [| kv_data]`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyDataSubPayload {
    pub next_payload: u8,
    pub key_type: KeyDataType,
    pub key_data: Vec<u8>,
    /// Present only when `key_type` carries a salt.
    pub salt: Option<Vec<u8>>,
    pub validity: KeyValidity,
}

impl KeyDataSubPayload {
    /// A TGK with no salt and no validity constraint — the simplest conformant
    /// form, and what the pre-shared key method sends.
    pub fn tgk(key_data: Vec<u8>) -> Self {
        Self {
            next_payload: PayloadType::Last as u8,
            key_type: KeyDataType::Tgk,
            key_data,
            salt: None,
            validity: KeyValidity::None,
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
///
/// Wire format: `next_payload(1) | auth_alg(1) | ver_data(N)`, where `N` is
/// implicit from the authentication algorithm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationPayload {
    pub next_payload: u8,
    /// MAC algorithm used for the verification message (§6.2 values).
    pub auth_alg: MacAlg,
    /// The verification message data — a MAC over the responder's message plus
    /// the identities and timestamp (§5.2).
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

impl KeyDataSubPayload {
    /// Serialize this sub-payload (RFC 3830 §6.13) onto `buf`.
    pub fn serialize(&self, buf: &mut Vec<u8>) {
        buf.push(self.next_payload);
        // Type occupies the high nibble, KV the low nibble.
        buf.push(((self.key_type as u8) << 4) | (self.validity.kv_type() as u8 & 0x0F));
        buf.extend_from_slice(&(self.key_data.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.key_data);

        if let Some(salt) = &self.salt {
            buf.extend_from_slice(&(salt.len() as u16).to_be_bytes());
            buf.extend_from_slice(salt);
        }

        match &self.validity {
            KeyValidity::None => {}
            KeyValidity::Spi(spi) => {
                buf.push(spi.len() as u8);
                buf.extend_from_slice(spi);
            }
            KeyValidity::Interval {
                valid_from,
                valid_to,
            } => {
                buf.push(valid_from.len() as u8);
                buf.extend_from_slice(valid_from);
                buf.push(valid_to.len() as u8);
                buf.extend_from_slice(valid_to);
            }
        }
    }

    /// Parse one sub-payload, returning it and the number of bytes consumed.
    pub fn parse(data: &[u8]) -> Result<(Self, usize)> {
        // next_payload(1) + type/kv(1) + key_data_len(2)
        let mut pos = 4;
        if data.len() < pos {
            return Err(MikeyError::MessageTooShort {
                expected: pos,
                actual: data.len(),
            });
        }

        let next_payload = data[0];
        let key_type = KeyDataType::from_u8(data[1] >> 4)
            .ok_or_else(|| MikeyError::Parse(format!("invalid key data type: {}", data[1] >> 4)))?;
        let kv_type = KeyValidityType::from_u8(data[1] & 0x0F)
            .ok_or_else(|| MikeyError::Parse(format!("invalid KV type: {}", data[1] & 0x0F)))?;
        let key_data_len = u16::from_be_bytes([data[2], data[3]]) as usize;

        let key_data = take(data, &mut pos, key_data_len, "key data")?;

        let salt = if key_type.has_salt() {
            let salt_len = take_u16(data, &mut pos, "salt len")?;
            Some(take(data, &mut pos, salt_len, "salt data")?)
        } else {
            None
        };

        let validity = match kv_type {
            KeyValidityType::Null => KeyValidity::None,
            KeyValidityType::Spi => {
                let len = take_u8(data, &mut pos, "SPI len")?;
                KeyValidity::Spi(take(data, &mut pos, len, "SPI")?)
            }
            KeyValidityType::Interval => {
                let vf_len = take_u8(data, &mut pos, "VF len")?;
                let valid_from = take(data, &mut pos, vf_len, "Valid From")?;
                let vt_len = take_u8(data, &mut pos, "VT len")?;
                let valid_to = take(data, &mut pos, vt_len, "Valid To")?;
                KeyValidity::Interval {
                    valid_from,
                    valid_to,
                }
            }
        };

        Ok((
            Self {
                next_payload,
                key_type,
                key_data,
                salt,
                validity,
            },
            pos,
        ))
    }

    /// Parse a chain of sub-payloads, as found in a decrypted KEMAC.
    ///
    /// The chain ends when a sub-payload declares "Last payload"; trailing bytes
    /// after that point are rejected, since a decrypted KEMAC should contain
    /// nothing else.
    pub fn parse_chain(data: &[u8]) -> Result<Vec<Self>> {
        let mut out = Vec::new();
        let mut pos = 0;

        loop {
            if pos >= data.len() {
                return Err(MikeyError::Parse(
                    "key data chain ended without a Last payload marker".into(),
                ));
            }
            let (sub, consumed) = Self::parse(&data[pos..])?;
            pos += consumed;
            let next = sub.next_payload;
            out.push(sub);

            if next == PayloadType::Last as u8 {
                break;
            }
            if next != PayloadType::KeyData as u8 {
                return Err(MikeyError::Parse(format!(
                    "unexpected next payload {next} inside key data chain"
                )));
            }
        }

        if pos != data.len() {
            return Err(MikeyError::Parse(format!(
                "{} trailing byte(s) after key data chain",
                data.len() - pos
            )));
        }

        Ok(out)
    }
}

/// Read `len` bytes at `pos`, advancing it.
fn take(data: &[u8], pos: &mut usize, len: usize, what: &str) -> Result<Vec<u8>> {
    let end = pos
        .checked_add(len)
        .ok_or_else(|| MikeyError::Parse(format!("{what} length overflows the message offset")))?;
    if data.len() < end {
        return Err(MikeyError::MessageTooShort {
            expected: end,
            actual: data.len(),
        });
    }
    let out = data[*pos..end].to_vec();
    *pos = end;
    Ok(out)
}

/// Read a u8 length prefix at `pos`, advancing it.
fn take_u8(data: &[u8], pos: &mut usize, what: &str) -> Result<usize> {
    if data.len() < *pos + 1 {
        return Err(MikeyError::MessageTooShort {
            expected: *pos + 1,
            actual: data.len(),
        });
    }
    let _ = what;
    let v = data[*pos] as usize;
    *pos += 1;
    Ok(v)
}

/// Read a u16 length prefix at `pos`, advancing it.
fn take_u16(data: &[u8], pos: &mut usize, what: &str) -> Result<usize> {
    if data.len() < *pos + 2 {
        return Err(MikeyError::MessageTooShort {
            expected: *pos + 2,
            actual: data.len(),
        });
    }
    let _ = what;
    let v = u16::from_be_bytes([data[*pos], data[*pos + 1]]) as usize;
    *pos += 2;
    Ok(v)
}
