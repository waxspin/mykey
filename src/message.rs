use crate::crypto::{self, DhKeyPair};
use crate::error::{MikeyError, Result};
use crate::payload::*;
use crate::srtp::{self, SrtpCryptoSuite, SrtpKeyMaterial};

/// Key exchange method selection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyExchangeMethod {
    /// Pre-shared key
    Psk,
    /// Diffie-Hellman with X25519
    DhX25519,
}

/// High-level MIKEY message builder and parser
#[derive(Debug)]
pub struct MikeyMessage {
    /// Parsed MIKEY common header.
    pub header: CommonHeader,
    /// Ordered list of payloads following the header.
    pub payloads: Vec<Payload>,
    raw: Vec<u8>,
}

impl MikeyMessage {
    /// Parse a MIKEY message from wire bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 10 {
            return Err(MikeyError::MessageTooShort {
                expected: 10,
                actual: data.len(),
            });
        }

        let (header, mut pos) = Self::parse_header(data)?;
        let mut payloads = Vec::new();
        let mut next = header.next_payload;

        while next != PayloadType::Last as u8 && pos < data.len() {
            let payload_type =
                PayloadType::from_u8(next).ok_or(MikeyError::InvalidPayloadType(next))?;
            let (payload, consumed) = Self::parse_payload(payload_type, &data[pos..])?;
            next = payload.next_payload_type();
            payloads.push(payload);
            pos += consumed;
        }

        Ok(Self {
            header,
            payloads,
            raw: data.to_vec(),
        })
    }

    fn parse_header(data: &[u8]) -> Result<(CommonHeader, usize)> {
        let version = data[0];
        if version != 1 {
            return Err(MikeyError::InvalidVersion(version));
        }

        let data_type =
            DataType::from_u8(data[1]).ok_or(MikeyError::UnsupportedDataType(data[1]))?;
        let next_payload = data[2];
        let v_flag = (data[3] & 0x80) != 0;
        let prf_func = PrfFunc::from_u8(data[3] & 0x7F)
            .ok_or(MikeyError::Parse("unsupported PRF function".into()))?;
        let csc_id = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let cs_count = data[8];
        let cs_id_map_type = data[9];

        let mut pos = 10;
        let mut cs_id_map = Vec::with_capacity(cs_count as usize);

        if cs_id_map_type == 0 {
            // SRTP-ID map: 9 bytes per entry
            for _ in 0..cs_count {
                if pos + 9 > data.len() {
                    return Err(MikeyError::MessageTooShort {
                        expected: pos + 9,
                        actual: data.len(),
                    });
                }
                let policy_no = data[pos];
                let ssrc = u32::from_be_bytes([
                    data[pos + 1],
                    data[pos + 2],
                    data[pos + 3],
                    data[pos + 4],
                ]);
                let roc = u32::from_be_bytes([
                    data[pos + 5],
                    data[pos + 6],
                    data[pos + 7],
                    data[pos + 8],
                ]);
                cs_id_map.push(SrtpId {
                    policy_no,
                    ssrc,
                    roc,
                });
                pos += 9;
            }
        }

        let header = CommonHeader {
            version,
            data_type,
            next_payload,
            v_flag,
            prf_func,
            csc_id,
            cs_count,
            cs_id_map_type,
            cs_id_map,
        };

        Ok((header, pos))
    }

    fn parse_payload(payload_type: PayloadType, data: &[u8]) -> Result<(Payload, usize)> {
        match payload_type {
            PayloadType::T => Self::parse_timestamp(data),
            PayloadType::Rand => Self::parse_rand(data),
            PayloadType::Dh => Self::parse_dh(data),
            PayloadType::Kemac => Self::parse_kemac(data),
            PayloadType::Id => Self::parse_id(data),
            PayloadType::Sp => Self::parse_sp(data),
            PayloadType::V => Self::parse_verification(data),
            _ => Err(MikeyError::InvalidPayloadType(payload_type as u8)),
        }
    }

    fn parse_timestamp(data: &[u8]) -> Result<(Payload, usize)> {
        if data.len() < 2 {
            return Err(MikeyError::MessageTooShort {
                expected: 2,
                actual: data.len(),
            });
        }
        let next_payload = data[0];
        let ts_type =
            TimestampType::from_u8(data[1]).ok_or(MikeyError::Parse("invalid TS type".into()))?;
        let val_len = ts_type.value_len();
        if data.len() < 2 + val_len {
            return Err(MikeyError::MessageTooShort {
                expected: 2 + val_len,
                actual: data.len(),
            });
        }
        let ts_value = data[2..2 + val_len].to_vec();
        Ok((
            Payload::Timestamp(TimestampPayload {
                next_payload,
                ts_type,
                ts_value,
            }),
            2 + val_len,
        ))
    }

    fn parse_rand(data: &[u8]) -> Result<(Payload, usize)> {
        if data.len() < 2 {
            return Err(MikeyError::MessageTooShort {
                expected: 2,
                actual: data.len(),
            });
        }
        let next_payload = data[0];
        let rand_len = data[1] as usize;
        if data.len() < 2 + rand_len {
            return Err(MikeyError::MessageTooShort {
                expected: 2 + rand_len,
                actual: data.len(),
            });
        }
        let rand = data[2..2 + rand_len].to_vec();
        Ok((
            Payload::Rand(RandPayload { next_payload, rand }),
            2 + rand_len,
        ))
    }

    fn parse_dh(data: &[u8]) -> Result<(Payload, usize)> {
        if data.len() < 2 {
            return Err(MikeyError::MessageTooShort {
                expected: 2,
                actual: data.len(),
            });
        }
        let next_payload = data[0];
        let dh_group =
            DhGroup::from_u8(data[1]).ok_or(MikeyError::Parse("invalid DH group".into()))?;
        let key_len = dh_group.key_len();
        if data.len() < 2 + key_len + 1 {
            return Err(MikeyError::MessageTooShort {
                expected: 2 + key_len + 1,
                actual: data.len(),
            });
        }
        let dh_value = data[2..2 + key_len].to_vec();
        let kv_type = data[2 + key_len];
        // KV type 0 = Null (no data follows)
        let kv_data = Vec::new();
        let consumed = 2 + key_len + 1;
        Ok((
            Payload::Dh(DhPayload {
                next_payload,
                dh_group,
                dh_value,
                kv_type,
                kv_data,
            }),
            consumed,
        ))
    }

    fn parse_kemac(data: &[u8]) -> Result<(Payload, usize)> {
        // Wire: next_payload(1) | enc_alg(1) | enc_data_len(2) | enc_data(N) | mac_alg(1) | MAC(M)
        if data.len() < 5 {
            return Err(MikeyError::MessageTooShort {
                expected: 5,
                actual: data.len(),
            });
        }
        let next_payload = data[0];
        let enc_alg =
            EncAlg::from_u8(data[1]).ok_or(MikeyError::Parse("invalid enc alg".into()))?;
        let enc_data_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        if data.len() < 4 + enc_data_len + 1 {
            return Err(MikeyError::MessageTooShort {
                expected: 4 + enc_data_len + 1,
                actual: data.len(),
            });
        }
        let enc_data = data[4..4 + enc_data_len].to_vec();
        let mac_alg = MacAlg::from_u8(data[4 + enc_data_len])
            .ok_or(MikeyError::Parse("invalid mac alg".into()))?;
        let mac_len = mac_alg.mac_len();
        let mac_start = 4 + enc_data_len + 1;
        if data.len() < mac_start + mac_len {
            return Err(MikeyError::MessageTooShort {
                expected: mac_start + mac_len,
                actual: data.len(),
            });
        }
        let mac = data[mac_start..mac_start + mac_len].to_vec();
        Ok((
            Payload::Kemac(KemacPayload {
                next_payload,
                enc_alg,
                mac_alg,
                enc_data,
                mac,
            }),
            mac_start + mac_len,
        ))
    }

    fn parse_id(data: &[u8]) -> Result<(Payload, usize)> {
        if data.len() < 4 {
            return Err(MikeyError::MessageTooShort {
                expected: 4,
                actual: data.len(),
            });
        }
        let next_payload = data[0];
        let id_type = data[1];
        let id_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        if data.len() < 4 + id_len {
            return Err(MikeyError::MessageTooShort {
                expected: 4 + id_len,
                actual: data.len(),
            });
        }
        let id_data = data[4..4 + id_len].to_vec();
        Ok((
            Payload::Id(IdPayload {
                next_payload,
                id_type,
                id_data,
            }),
            4 + id_len,
        ))
    }

    fn parse_sp(data: &[u8]) -> Result<(Payload, usize)> {
        // Wire: next_payload(1) | policy_no(1) | prot_type(1) | policy_params(TLV...)
        if data.len() < 3 {
            return Err(MikeyError::MessageTooShort {
                expected: 3,
                actual: data.len(),
            });
        }
        let next_payload = data[0];
        let policy_no = data[1];
        let proto_type = data[2];

        // Read TLV params greedily. We stop when we can't form a valid TLV
        // (need at least 2 bytes for type+length) or when the param type
        // is outside the SRTP range (0-12).
        let mut params = Vec::new();
        let mut pos = 3;
        while pos + 2 <= data.len() {
            let param_type = data[pos];
            let param_len = data[pos + 1];
            // SRTP param types are 0-12; anything else signals end of SP
            if param_type > 12 {
                break;
            }
            if pos + 2 + param_len as usize > data.len() {
                break;
            }
            let param_value = data[pos + 2..pos + 2 + param_len as usize].to_vec();
            params.push(SpParam {
                param_type,
                param_len,
                param_value,
            });
            pos += 2 + param_len as usize;
        }

        Ok((
            Payload::Sp(SpPayload {
                next_payload,
                policy_no,
                proto_type,
                params,
            }),
            pos,
        ))
    }

    fn parse_verification(data: &[u8]) -> Result<(Payload, usize)> {
        if data.is_empty() {
            return Err(MikeyError::MessageTooShort {
                expected: 1,
                actual: 0,
            });
        }
        let next_payload = data[0];
        // MAC is 20 bytes (HMAC-SHA-256 truncated to 160 bits)
        let mac_len = 20;
        if data.len() < 1 + mac_len {
            return Err(MikeyError::MessageTooShort {
                expected: 1 + mac_len,
                actual: data.len(),
            });
        }
        let mac = data[1..1 + mac_len].to_vec();
        Ok((
            Payload::Verification(VerificationPayload { next_payload, mac }),
            1 + mac_len,
        ))
    }

    /// Build a DH initiator message (data_type = 4)
    pub fn new_dh_init(
        csc_id: u32,
        ssrc: u32,
        rand_bytes: &[u8],
        dh_public: &[u8; 32],
    ) -> Result<Self> {
        let header = CommonHeader {
            version: 1,
            data_type: DataType::DhInit,
            next_payload: PayloadType::T as u8,
            v_flag: false,
            prf_func: PrfFunc::MikeyPrfHmacSha256,
            csc_id,
            cs_count: 1,
            cs_id_map_type: 0,
            cs_id_map: vec![SrtpId {
                policy_no: 0,
                ssrc,
                roc: 0,
            }],
        };

        let timestamp = TimestampPayload {
            next_payload: PayloadType::Rand as u8,
            ts_type: TimestampType::Counter,
            ts_value: csc_id.to_be_bytes().to_vec(),
        };

        let rand = RandPayload {
            next_payload: PayloadType::Dh as u8,
            rand: rand_bytes.to_vec(),
        };

        let dh = DhPayload {
            next_payload: PayloadType::Last as u8,
            dh_group: DhGroup::X25519,
            dh_value: dh_public.to_vec(),
            kv_type: 0,
            kv_data: vec![],
        };

        let payloads = vec![
            Payload::Timestamp(timestamp),
            Payload::Rand(rand),
            Payload::Dh(dh),
        ];

        let raw = Self::serialize(&header, &payloads);

        Ok(Self {
            header,
            payloads,
            raw,
        })
    }

    /// Build a DH initiator message with security policy (data_type = 4)
    pub fn new_dh_init_with_sp(
        csc_id: u32,
        ssrc: u32,
        rand_bytes: &[u8],
        dh_public: &[u8; 32],
        sp: SpPayload,
    ) -> Result<Self> {
        let header = CommonHeader {
            version: 1,
            data_type: DataType::DhInit,
            next_payload: PayloadType::T as u8,
            v_flag: false,
            prf_func: PrfFunc::MikeyPrfHmacSha256,
            csc_id,
            cs_count: 1,
            cs_id_map_type: 0,
            cs_id_map: vec![SrtpId {
                policy_no: 0,
                ssrc,
                roc: 0,
            }],
        };

        let timestamp = TimestampPayload {
            next_payload: PayloadType::Rand as u8,
            ts_type: TimestampType::Counter,
            ts_value: csc_id.to_be_bytes().to_vec(),
        };

        let rand = RandPayload {
            next_payload: PayloadType::Sp as u8,
            rand: rand_bytes.to_vec(),
        };

        let mut sp = sp;
        sp.next_payload = PayloadType::Dh as u8;

        let dh = DhPayload {
            next_payload: PayloadType::Last as u8,
            dh_group: DhGroup::X25519,
            dh_value: dh_public.to_vec(),
            kv_type: 0,
            kv_data: vec![],
        };

        let payloads = vec![
            Payload::Timestamp(timestamp),
            Payload::Rand(rand),
            Payload::Sp(sp),
            Payload::Dh(dh),
        ];

        let raw = Self::serialize(&header, &payloads);

        Ok(Self {
            header,
            payloads,
            raw,
        })
    }

    /// Build a DH responder message (data_type = 5)
    pub fn new_dh_resp(csc_id: u32, dh_public: &[u8; 32]) -> Result<Self> {
        let header = CommonHeader {
            version: 1,
            data_type: DataType::DhResp,
            next_payload: PayloadType::Dh as u8,
            v_flag: false,
            prf_func: PrfFunc::MikeyPrfHmacSha256,
            csc_id,
            cs_count: 0,
            cs_id_map_type: 0,
            cs_id_map: vec![],
        };

        let dh = DhPayload {
            next_payload: PayloadType::Last as u8,
            dh_group: DhGroup::X25519,
            dh_value: dh_public.to_vec(),
            kv_type: 0,
            kv_data: vec![],
        };

        let payloads = vec![Payload::Dh(dh)];
        let raw = Self::serialize(&header, &payloads);

        Ok(Self {
            header,
            payloads,
            raw,
        })
    }

    /// Build a PSK initiator message (data_type = 0)
    pub fn new_psk_init(csc_id: u32, ssrc: u32, rand_bytes: &[u8], psk: &[u8]) -> Result<Self> {
        let header = CommonHeader {
            version: 1,
            data_type: DataType::PskInit,
            next_payload: PayloadType::T as u8,
            v_flag: false,
            prf_func: PrfFunc::MikeyPrfHmacSha256,
            csc_id,
            cs_count: 1,
            cs_id_map_type: 0,
            cs_id_map: vec![SrtpId {
                policy_no: 0,
                ssrc,
                roc: 0,
            }],
        };

        let timestamp = TimestampPayload {
            next_payload: PayloadType::Rand as u8,
            ts_type: TimestampType::Counter,
            ts_value: csc_id.to_be_bytes().to_vec(),
        };

        let rand = RandPayload {
            next_payload: PayloadType::Kemac as u8,
            rand: rand_bytes.to_vec(),
        };

        // Derive TGK from PSK
        let tgk = crypto::derive_tgk(psk, rand_bytes, 32)?;
        let auth_key = crypto::derive_auth_key(&tgk, rand_bytes, 32)?;

        // KEMAC with null encryption (TGK sent as key data)
        let kemac = KemacPayload {
            next_payload: PayloadType::Last as u8,
            enc_alg: EncAlg::Null,
            mac_alg: MacAlg::HmacSha256,
            enc_data: tgk.clone(),
            mac: vec![], // placeholder — computed below
        };

        let payloads = vec![
            Payload::Timestamp(timestamp),
            Payload::Rand(rand),
            Payload::Kemac(kemac),
        ];

        let mut raw = Self::serialize(&header, &payloads);

        // Compute and append MAC over the serialized message
        let mac = crypto::compute_mac(&auth_key, &raw)?;
        raw.extend_from_slice(&mac);

        Ok(Self {
            header,
            payloads,
            raw,
        })
    }

    /// Get the RAND bytes from this message
    pub fn rand_bytes(&self) -> Option<&[u8]> {
        for p in &self.payloads {
            if let Payload::Rand(r) = p {
                return Some(&r.rand);
            }
        }
        None
    }

    /// Get the DH public value from this message
    pub fn dh_public(&self) -> Option<&[u8]> {
        for p in &self.payloads {
            if let Payload::Dh(dh) = p {
                return Some(&dh.dh_value);
            }
        }
        None
    }

    /// Get the security policy payload
    pub fn security_policy(&self) -> Option<&SpPayload> {
        for p in &self.payloads {
            if let Payload::Sp(sp) = p {
                return Some(sp);
            }
        }
        None
    }

    /// Serialize to bytes for wire transmission
    pub fn to_bytes(&self) -> &[u8] {
        &self.raw
    }

    fn serialize(header: &CommonHeader, payloads: &[Payload]) -> Vec<u8> {
        let mut buf = Vec::new();

        // Common header (RFC 3830 Section 6.1)
        buf.push(header.version);
        buf.push(header.data_type as u8);
        buf.push(header.next_payload);
        buf.push(if header.v_flag { 0x80 } else { 0x00 } | (header.prf_func as u8 & 0x7F));
        buf.extend_from_slice(&header.csc_id.to_be_bytes());
        buf.push(header.cs_count);
        buf.push(header.cs_id_map_type);

        // CS ID map entries
        for entry in &header.cs_id_map {
            buf.push(entry.policy_no);
            buf.extend_from_slice(&entry.ssrc.to_be_bytes());
            buf.extend_from_slice(&entry.roc.to_be_bytes());
        }

        // Serialize payloads
        for p in payloads {
            Self::serialize_payload(&mut buf, p);
        }

        buf
    }

    fn serialize_payload(buf: &mut Vec<u8>, payload: &Payload) {
        match payload {
            Payload::Timestamp(ts) => {
                buf.push(ts.next_payload);
                buf.push(ts.ts_type as u8);
                buf.extend_from_slice(&ts.ts_value);
            }
            Payload::Rand(r) => {
                buf.push(r.next_payload);
                buf.push(r.rand.len() as u8);
                buf.extend_from_slice(&r.rand);
            }
            Payload::Dh(dh) => {
                // RFC 3830 Section 6.4: next_payload | DH-Group | DH-value | KV
                // DH-value length is implied by group, no explicit length field
                buf.push(dh.next_payload);
                buf.push(dh.dh_group as u8);
                buf.extend_from_slice(&dh.dh_value);
                buf.push(dh.kv_type);
                buf.extend_from_slice(&dh.kv_data);
            }
            Payload::Kemac(k) => {
                // RFC 3830 Section 6.2:
                // next_payload | enc_alg | enc_data_len(2) | enc_data | mac_alg | MAC
                buf.push(k.next_payload);
                buf.push(k.enc_alg as u8);
                buf.extend_from_slice(&(k.enc_data.len() as u16).to_be_bytes());
                buf.extend_from_slice(&k.enc_data);
                buf.push(k.mac_alg as u8);
                // MAC appended separately for PSK (computed over whole message)
            }
            Payload::Id(id) => {
                buf.push(id.next_payload);
                buf.push(id.id_type);
                buf.extend_from_slice(&(id.id_data.len() as u16).to_be_bytes());
                buf.extend_from_slice(&id.id_data);
            }
            Payload::Sp(sp) => {
                buf.push(sp.next_payload);
                buf.push(sp.policy_no);
                buf.push(sp.proto_type);
                for param in &sp.params {
                    buf.push(param.param_type);
                    buf.push(param.param_len);
                    buf.extend_from_slice(&param.param_value);
                }
            }
            Payload::Verification(v) => {
                buf.push(v.next_payload);
                buf.extend_from_slice(&v.mac);
            }
            Payload::Header(_) => {} // header serialized separately
        }
    }
}

/// Perform a complete DH key exchange (initiator side).
///
/// Uses **ephemeral keys** by default — a fresh X25519 keypair is generated
/// on construction and consumed when [`complete()`](DhInitiator::complete) derives
/// the SRTP keys. This provides forward secrecy but no identity verification.
///
/// For MITM-resistant exchanges with peer key pinning, use
/// [`Identity`](crate::identity::Identity) and
/// [`PinnedPeer`](crate::identity::PinnedPeer) instead.
pub struct DhInitiator {
    keypair: Option<DhKeyPair>,
    rand_bytes: Vec<u8>,
    csc_id: u32,
    ssrc: u32,
}

impl DhInitiator {
    /// Create a new initiator with a fresh ephemeral keypair and random RAND nonce.
    pub fn new(csc_id: u32, ssrc: u32) -> Self {
        let mut rand_bytes = vec![0u8; 16];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut rand_bytes);

        Self {
            keypair: Some(DhKeyPair::generate()),
            rand_bytes,
            csc_id,
            ssrc,
        }
    }

    /// Build the init message to send to the responder
    pub fn init_message(&self) -> Result<MikeyMessage> {
        let public = self
            .keypair
            .as_ref()
            .ok_or(MikeyError::Crypto("keypair already consumed".into()))?
            .public;

        MikeyMessage::new_dh_init(self.csc_id, self.ssrc, &self.rand_bytes, public.as_bytes())
    }

    /// Build the init message with security policy
    pub fn init_message_with_sp(&self, sp: SpPayload) -> Result<MikeyMessage> {
        let public = self
            .keypair
            .as_ref()
            .ok_or(MikeyError::Crypto("keypair already consumed".into()))?
            .public;

        MikeyMessage::new_dh_init_with_sp(
            self.csc_id,
            self.ssrc,
            &self.rand_bytes,
            public.as_bytes(),
            sp,
        )
    }

    /// Process the responder's message and derive SRTP keys
    pub fn complete(
        mut self,
        resp: &MikeyMessage,
        suite: SrtpCryptoSuite,
    ) -> Result<SrtpKeyMaterial> {
        let peer_pub = resp.dh_public().ok_or(MikeyError::MissingPayload("DH"))?;

        if peer_pub.len() != 32 {
            return Err(MikeyError::InvalidDhValue);
        }

        let mut peer_bytes = [0u8; 32];
        peer_bytes.copy_from_slice(peer_pub);

        let keypair = self
            .keypair
            .take()
            .ok_or(MikeyError::Crypto("keypair already consumed".into()))?;

        let shared_secret = keypair.diffie_hellman(&peer_bytes);
        let tgk = crypto::derive_tgk(&shared_secret, &self.rand_bytes, 32)?;

        srtp::derive_srtp_keys(&tgk, &self.rand_bytes, 0, suite)
    }
}

/// Perform a complete DH key exchange (responder side).
///
/// Uses **ephemeral keys** by default — a fresh X25519 keypair is generated
/// on construction and consumed when [`complete()`](DhResponder::complete) derives
/// the SRTP keys. This provides forward secrecy but no identity verification.
///
/// For MITM-resistant exchanges with peer key pinning, use
/// [`Identity`](crate::identity::Identity) and
/// [`PinnedPeer`](crate::identity::PinnedPeer) instead.
pub struct DhResponder {
    keypair: Option<DhKeyPair>,
}

impl DhResponder {
    /// Create a new responder with a fresh ephemeral keypair.
    pub fn new() -> Self {
        Self {
            keypair: Some(DhKeyPair::generate()),
        }
    }

    /// Build the response message
    pub fn resp_message(&self, csc_id: u32) -> Result<MikeyMessage> {
        let public = self
            .keypair
            .as_ref()
            .ok_or(MikeyError::Crypto("keypair already consumed".into()))?
            .public;

        MikeyMessage::new_dh_resp(csc_id, public.as_bytes())
    }

    /// Process the initiator's message and derive SRTP keys
    pub fn complete(
        mut self,
        init: &MikeyMessage,
        suite: SrtpCryptoSuite,
    ) -> Result<SrtpKeyMaterial> {
        let peer_pub = init.dh_public().ok_or(MikeyError::MissingPayload("DH"))?;
        let rand = init
            .rand_bytes()
            .ok_or(MikeyError::MissingPayload("RAND"))?;

        if peer_pub.len() != 32 {
            return Err(MikeyError::InvalidDhValue);
        }

        let mut peer_bytes = [0u8; 32];
        peer_bytes.copy_from_slice(peer_pub);

        let keypair = self
            .keypair
            .take()
            .ok_or(MikeyError::Crypto("keypair already consumed".into()))?;

        let shared_secret = keypair.diffie_hellman(&peer_bytes);
        let tgk = crypto::derive_tgk(&shared_secret, rand, 32)?;

        srtp::derive_srtp_keys(&tgk, rand, 0, suite)
    }
}

impl Default for DhResponder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dh_full_exchange() {
        // Initiator side
        let initiator = DhInitiator::new(1, 0x12345678);
        let init_msg = initiator.init_message().unwrap();

        // Responder side
        let responder = DhResponder::new();
        let resp_msg = responder.resp_message(1).unwrap();

        assert!(init_msg.dh_public().is_some());
        assert!(init_msg.rand_bytes().is_some());
        assert!(resp_msg.dh_public().is_some());
        assert_eq!(init_msg.dh_public().unwrap().len(), 32);
        assert_eq!(resp_msg.dh_public().unwrap().len(), 32);
    }

    #[test]
    fn test_dh_keys_match() {
        let suite = SrtpCryptoSuite::AES_128_CM_SHA1_80;

        let alice = crypto::DhKeyPair::generate();
        let bob = crypto::DhKeyPair::generate();

        let alice_pub = *alice.public.as_bytes();
        let bob_pub = *bob.public.as_bytes();

        let rand = vec![0xABu8; 16];

        let shared_a = alice.diffie_hellman(&bob_pub);
        let shared_b = bob.diffie_hellman(&alice_pub);
        assert_eq!(shared_a, shared_b);

        let tgk_a = crypto::derive_tgk(&shared_a, &rand, 32).unwrap();
        let tgk_b = crypto::derive_tgk(&shared_b, &rand, 32).unwrap();
        assert_eq!(tgk_a, tgk_b);

        let keys_a = srtp::derive_srtp_keys(&tgk_a, &rand, 0, suite).unwrap();
        let keys_b = srtp::derive_srtp_keys(&tgk_b, &rand, 0, suite).unwrap();

        assert_eq!(keys_a.master_key, keys_b.master_key);
        assert_eq!(keys_a.master_salt, keys_b.master_salt);
    }

    #[test]
    fn test_dh_init_roundtrip() {
        let initiator = DhInitiator::new(42, 0xDEADBEEF);
        let msg = initiator.init_message().unwrap();
        let bytes = msg.to_bytes();

        // Parse it back
        let parsed = MikeyMessage::from_bytes(bytes).unwrap();

        assert_eq!(parsed.header.version, 1);
        assert_eq!(parsed.header.data_type, DataType::DhInit);
        assert_eq!(parsed.header.csc_id, 42);
        assert_eq!(parsed.header.cs_count, 1);
        assert_eq!(parsed.header.cs_id_map[0].ssrc, 0xDEADBEEF);

        // Check payloads parsed correctly
        assert_eq!(parsed.payloads.len(), 3);
        assert!(parsed.rand_bytes().is_some());
        assert!(parsed.dh_public().is_some());
        assert_eq!(parsed.dh_public().unwrap().len(), 32);

        // DH public key should match
        assert_eq!(msg.dh_public().unwrap(), parsed.dh_public().unwrap());
        assert_eq!(msg.rand_bytes().unwrap(), parsed.rand_bytes().unwrap());
    }

    #[test]
    fn test_dh_resp_roundtrip() {
        let responder = DhResponder::new();
        let msg = responder.resp_message(99).unwrap();
        let bytes = msg.to_bytes();

        let parsed = MikeyMessage::from_bytes(bytes).unwrap();

        assert_eq!(parsed.header.data_type, DataType::DhResp);
        assert_eq!(parsed.header.csc_id, 99);
        assert_eq!(parsed.header.cs_count, 0);
        assert_eq!(parsed.payloads.len(), 1);
        assert_eq!(parsed.dh_public().unwrap(), msg.dh_public().unwrap());
    }

    #[test]
    fn test_psk_init_roundtrip() {
        let psk = b"shared_secret_key_for_testing!!";
        let rand_bytes = vec![0x42u8; 16];
        let msg = MikeyMessage::new_psk_init(7, 0xCAFEBABE, &rand_bytes, psk).unwrap();
        let bytes = msg.to_bytes();

        // PSK message has MAC appended, so it's longer than just the serialized payloads
        assert!(bytes.len() > 40);

        // Parse the message (without the trailing MAC for now, since KEMAC
        // already contains mac_alg + MAC inline)
        let parsed = MikeyMessage::from_bytes(bytes).unwrap();
        assert_eq!(parsed.header.data_type, DataType::PskInit);
        assert_eq!(parsed.header.csc_id, 7);
        assert_eq!(parsed.rand_bytes().unwrap(), &rand_bytes);
    }

    #[test]
    fn test_dh_init_with_sp_roundtrip() {
        use crate::policy::SrtpPolicy;

        let initiator = DhInitiator::new(10, 0x11223344);
        let sp = SrtpPolicy::aes_128_default().to_sp_payload(0);
        let msg = initiator.init_message_with_sp(sp).unwrap();
        let bytes = msg.to_bytes();

        let parsed = MikeyMessage::from_bytes(bytes).unwrap();

        assert_eq!(parsed.header.data_type, DataType::DhInit);
        assert_eq!(parsed.payloads.len(), 4); // T, RAND, SP, DH

        let sp = parsed.security_policy().unwrap();
        assert_eq!(sp.proto_type, 0); // SRTP
        assert!(!sp.params.is_empty());
    }

    #[test]
    fn test_invalid_version() {
        let mut data = vec![0u8; 20];
        data[0] = 2; // invalid version
        assert!(MikeyMessage::from_bytes(&data).is_err());
    }

    #[test]
    fn test_truncated_message() {
        let data = vec![1, 4, 5]; // version=1, data_type=DH_init, next=T, but too short
        assert!(MikeyMessage::from_bytes(&data).is_err());
    }
}
