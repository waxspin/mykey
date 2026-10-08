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

/// Length of the randomly generated TGK transported in PSK mode.
///
/// RFC 3830 does not fix a TGK length — §4.1.1 just takes `inkey_len` as "bit
/// length of TGK" — but §9 requires the TGK to be sized against the security
/// level wanted from the media protection. Two things pin it to 32 bytes here:
///
/// * **The crypto suite is not known when the TGK is generated.**
///   [`new_psk_init`](MikeyMessage::new_psk_init) takes no suite; the caller
///   chooses one later in [`complete_psk`](MikeyMessage::complete_psk). The TGK
///   must therefore cover the largest master key any supported suite can ask
///   for, which is 32 bytes for `AES_256_CM_SHA1_80`. A shorter TGK would
///   silently cap a 256-bit master key's real entropy.
///   `test_psk_tgk_len_covers_every_suite` enforces this.
/// * **32 bytes is exactly one PRF input block.** The §4.1.2 PRF splits its
///   input key into 256-bit blocks and XORs the per-block outputs, so 32 bytes
///   means one whole block — no partial block, and no extra blocks whose XOR
///   would not raise the bounded output entropy anyway.
///
/// This governs only what mykey *emits*. Received key data is variable length
/// (§6.13), so peers are free to send other sizes.
const PSK_TGK_LEN: usize = 32;

/// Length of the MIKEY message authentication key derived per RFC 3830 §4.1.4.
const PSK_AUTH_KEY_LEN: usize = 32;

/// High-level MIKEY message builder and parser
#[derive(Debug)]
pub struct MikeyMessage {
    /// Parsed MIKEY common header.
    pub header: CommonHeader,
    /// Ordered list of payloads following the header.
    pub payloads: Vec<Payload>,
    raw: Vec<u8>,
    /// Byte offset at which the trailing MAC field begins — a KEMAC's MAC in a
    /// PSK-Init, or a V payload's verification data in a PSK-Resp.
    ///
    /// RFC 3830 §5.2 computes the MAC over the entire message except the MAC
    /// field itself, so this records where that coverage ends. Tracked during
    /// parsing rather than inferred from the message length, so that trailing
    /// bytes cannot shift it.
    mac_offset: Option<usize>,
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
        let mut mac_offset = None;

        // The chain ends when a payload declares "Last payload" (0, per RFC 3830
        // Table 6.1.b). Running out of bytes while the chain still points at
        // another payload means the message is truncated, not finished.
        while next != PayloadType::Last as u8 {
            if pos >= data.len() {
                return Err(MikeyError::MessageTooShort {
                    expected: pos + 1,
                    actual: data.len(),
                });
            }
            let payload_type =
                PayloadType::from_u8(next).ok_or(MikeyError::InvalidPayloadType(next))?;
            let (payload, consumed) = Self::parse_payload(payload_type, &data[pos..])?;

            // Record where the trailing MAC field starts, so verification can
            // reproduce the §5.2 coverage exactly.
            match &payload {
                Payload::Kemac(k) if !k.mac.is_empty() => {
                    mac_offset = Some(pos + consumed - k.mac.len());
                }
                Payload::Verification(v) if !v.mac.is_empty() => {
                    mac_offset = Some(pos + consumed - v.mac.len());
                }
                _ => {}
            }

            next = payload.next_payload_type();
            payloads.push(payload);
            pos += consumed;
        }

        Ok(Self {
            header,
            payloads,
            raw: data.to_vec(),
            mac_offset,
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
        // Wire: next_payload(1) | policy_no(1) | proto_type(1) | policy_param_length(2) | params(...)
        if data.len() < 5 {
            return Err(MikeyError::MessageTooShort {
                expected: 5,
                actual: data.len(),
            });
        }
        let next_payload = data[0];
        let policy_no = data[1];
        let proto_type = data[2];
        let _params_len = u16::from_be_bytes([data[3], data[4]]) as usize;

        // Read TLV params greedily. We stop when we can't form a valid TLV
        // (need at least 2 bytes for type+length) or when the param type
        // is outside the SRTP range (0-12).
        let mut params = Vec::new();
        let mut pos = 5;
        while pos < 5 + _params_len && pos + 2 <= data.len() {
            let param_type = data[pos];
            let param_len = data[pos + 1];
            // SRTP param types are 0-12; anything else signals end of SP
            if param_type > 12 {
                break;
            }
            if pos + 2 + param_len as usize > 5 + _params_len
                || pos + 2 + param_len as usize > data.len()
            {
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
        // Wire: next_payload(1) | auth_alg(1) | ver_data(N)
        if data.len() < 2 {
            return Err(MikeyError::MessageTooShort {
                expected: 2,
                actual: data.len(),
            });
        }
        let next_payload = data[0];
        let auth_alg =
            MacAlg::from_u8(data[1]).ok_or(MikeyError::Parse("invalid auth alg".into()))?;
        let mac_len = auth_alg.mac_len();
        if data.len() < 2 + mac_len {
            return Err(MikeyError::MessageTooShort {
                expected: 2 + mac_len,
                actual: data.len(),
            });
        }
        let mac = data[2..2 + mac_len].to_vec();
        Ok((
            Payload::Verification(VerificationPayload {
                next_payload,
                auth_alg,
                mac,
            }),
            2 + mac_len,
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
            prf_func: PrfFunc::MikeyPrfHmacSha1,
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
            mac_offset: None,
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
            prf_func: PrfFunc::MikeyPrfHmacSha1,
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
            mac_offset: None,
        })
    }

    /// Build a DH responder message (data_type = 5)
    pub fn new_dh_resp(csc_id: u32, dh_public: &[u8; 32]) -> Result<Self> {
        let header = CommonHeader {
            version: 1,
            data_type: DataType::DhResp,
            next_payload: PayloadType::Dh as u8,
            v_flag: false,
            prf_func: PrfFunc::MikeyPrfHmacSha1,
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
            mac_offset: None,
        })
    }

    /// Build a PSK initiator message (data_type = 0).
    ///
    /// The responder is not asked for a verification message, so the exchange is
    /// one-way: the responder authenticates the initiator, but not the reverse.
    /// This suits offline distribution, where the message is written to an SDP
    /// file or announced over SAP and no reply is possible. For mutual
    /// authentication use
    /// [`new_psk_init_requiring_verification`](MikeyMessage::new_psk_init_requiring_verification).
    pub fn new_psk_init(csc_id: u32, ssrc: u32, rand_bytes: &[u8], psk: &[u8]) -> Result<Self> {
        Self::build_psk_init(csc_id, ssrc, rand_bytes, psk, false)
    }

    /// Build a PSK initiator message that requests a verification message in
    /// reply, setting the V flag in the common header (RFC 3830 §3.1).
    ///
    /// The responder answers with
    /// [`new_psk_verification`](MikeyMessage::new_psk_verification), which the
    /// initiator checks with
    /// [`verify_psk_verification`](MikeyMessage::verify_psk_verification) to
    /// obtain mutual authentication. Requires a bidirectional channel.
    pub fn new_psk_init_requiring_verification(
        csc_id: u32,
        ssrc: u32,
        rand_bytes: &[u8],
        psk: &[u8],
    ) -> Result<Self> {
        Self::build_psk_init(csc_id, ssrc, rand_bytes, psk, true)
    }

    fn build_psk_init(
        csc_id: u32,
        ssrc: u32,
        rand_bytes: &[u8],
        psk: &[u8],
        require_verification: bool,
    ) -> Result<Self> {
        let header = CommonHeader {
            version: 1,
            data_type: DataType::PskInit,
            next_payload: PayloadType::T as u8,
            v_flag: require_verification,
            prf_func: PrfFunc::MikeyPrfHmacSha1,
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

        // RFC 3830 §3.1: the initiator chooses the TGK at random and transports
        // it, rather than both sides deriving it from the pre-shared key.
        let mut tgk = vec![0u8; PSK_TGK_LEN];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut tgk);

        // Frame it as a Key data sub-payload (§6.13) and encrypt under the keys
        // derived from the pre-shared key (§4.1.4), using AES-CM (§4.2.3).
        let mut enc_data = Vec::new();
        KeyDataSubPayload::tgk(tgk.clone()).serialize(&mut enc_data);

        let enc_key = crypto::derive_enc_key(psk, csc_id, rand_bytes, crypto::KEMAC_ENC_KEY_LEN)?;
        let salt_key = crypto::derive_salt_key(psk, csc_id, rand_bytes, crypto::KEMAC_SALT_LEN)?;
        let iv = crypto::kemac_iv(&salt_key, csc_id, &timestamp.ts_value)?;
        crypto::aes_cm_apply(&enc_key, &iv, &mut enc_data)?;

        let auth_key = crypto::derive_auth_key(psk, csc_id, rand_bytes, PSK_AUTH_KEY_LEN)?;

        let kemac = KemacPayload {
            next_payload: PayloadType::Last as u8,
            enc_alg: EncAlg::AesCm128,
            mac_alg: MacAlg::HmacSha1160,
            enc_data,
            mac: vec![], // filled in below, after the MAC is computed over it
        };

        let payloads = vec![
            Payload::Timestamp(timestamp),
            Payload::Rand(rand),
            Payload::Kemac(kemac),
        ];

        // §5.2: concatenate the MAC payload with the MAC field empty, compute the
        // MAC over the whole message, then fill the field in.
        let mut raw = Self::serialize(&header, &payloads);
        let mac_offset = raw.len();
        let mac = crypto::compute_mac(&auth_key, &raw)?;
        raw.extend_from_slice(&mac);

        let mut payloads = payloads;
        if let Some(Payload::Kemac(k)) = payloads.last_mut() {
            k.mac = mac;
        }

        Ok(Self {
            header,
            payloads,
            raw,
            mac_offset: Some(mac_offset),
        })
    }

    /// Verify a PSK message's MAC and recover the transported TGK.
    ///
    /// Per RFC 3830 §3.1 the TGK is chosen by the initiator and carried in the
    /// KEMAC payload, so this verifies the message authentication code (§5.2)
    /// and then decrypts the key data (§4.2.3, §6.13).
    ///
    /// The MAC is checked **before** anything is decrypted, so a message that
    /// fails authentication yields no key material at all.
    ///
    /// # Errors
    ///
    /// Returns [`MikeyError::InvalidMac`] if the MAC is wrong, absent, or the
    /// payload declares `MacAlg::Null`; [`MikeyError::MissingPayload`] if a
    /// required payload is absent; and a parse error if the decrypted key data
    /// is malformed.
    pub fn verify_and_extract_tgk(&self, psk: &[u8]) -> Result<Vec<u8>> {
        let rand = self
            .rand_bytes()
            .ok_or(MikeyError::MissingPayload("RAND"))?
            .to_vec();
        let ts_value = self
            .timestamp_value()
            .ok_or(MikeyError::MissingPayload("T"))?
            .to_vec();
        let kemac = self
            .kemac()
            .ok_or(MikeyError::MissingPayload("KEMAC"))?
            .clone();
        let csb_id = self.header.csc_id;

        // ── Authenticate before touching the ciphertext ──────────────────────
        //
        // A NULL MAC algorithm cannot authenticate anything, so it is refused
        // rather than treated as "no check required".
        if kemac.mac_alg == MacAlg::Null || kemac.mac.is_empty() {
            return Err(MikeyError::InvalidMac);
        }
        let mac_offset = self.mac_offset.ok_or(MikeyError::InvalidMac)?;
        if mac_offset > self.raw.len() {
            return Err(MikeyError::InvalidMac);
        }

        let auth_key = crypto::derive_auth_key(psk, csb_id, &rand, PSK_AUTH_KEY_LEN)?;
        crypto::verify_mac(&auth_key, &self.raw[..mac_offset], &kemac.mac)?;

        // ── Decrypt the key data ────────────────────────────────────────────
        let mut plaintext = kemac.enc_data.clone();
        match kemac.enc_alg {
            EncAlg::AesCm128 => {
                let enc_key =
                    crypto::derive_enc_key(psk, csb_id, &rand, crypto::KEMAC_ENC_KEY_LEN)?;
                let salt_key = crypto::derive_salt_key(psk, csb_id, &rand, crypto::KEMAC_SALT_LEN)?;
                let iv = crypto::kemac_iv(&salt_key, csb_id, &ts_value)?;
                crypto::aes_cm_apply(&enc_key, &iv, &mut plaintext)?;
            }
            EncAlg::Null => {
                // Permitted by §4.2.3 only where the transport is already
                // secure. The MAC above has been verified, so this is an
                // integrity-protected but unencrypted TGK.
            }
            EncAlg::AesKw128 => {
                return Err(MikeyError::Parse(
                    "AES key wrap (enc alg 2) is not implemented".into(),
                ));
            }
        }

        let subs = KeyDataSubPayload::parse_chain(&plaintext)?;
        let tgk = subs
            .iter()
            .find(|s| matches!(s.key_type, KeyDataType::Tgk | KeyDataType::TgkSalt))
            .ok_or(MikeyError::MissingPayload("TGK key data"))?;

        Ok(tgk.key_data.clone())
    }

    /// Verify a PSK message and derive SRTP key material from the TGK it carries.
    ///
    /// This is the PSK equivalent of [`DhInitiator::complete`] and
    /// [`DhResponder::complete`]. Both the initiator (who built the message with
    /// [`new_psk_init`](MikeyMessage::new_psk_init)) and the responder call it
    /// with the same `psk`; the initiator recovers the TGK from its own KEMAC,
    /// so both arrive at identical keys.
    ///
    /// # Errors
    ///
    /// As [`verify_and_extract_tgk`](MikeyMessage::verify_and_extract_tgk) —
    /// notably [`MikeyError::InvalidMac`] when the message does not
    /// authenticate, in which case no keys are produced.
    pub fn complete_psk(&self, psk: &[u8], suite: SrtpCryptoSuite) -> Result<SrtpKeyMaterial> {
        let tgk = self.verify_and_extract_tgk(psk)?;
        let rand = self
            .rand_bytes()
            .ok_or(MikeyError::MissingPayload("RAND"))?;
        srtp::derive_srtp_keys(&tgk, rand, 0, self.header.csc_id, suite)
    }

    /// Whether the initiator requested a verification message in reply.
    ///
    /// Signalled by the V flag in the common header (RFC 3830 §3.1, §6.1).
    pub fn requires_verification(&self) -> bool {
        self.header.v_flag
    }

    /// Build the responder's verification message for a PSK exchange
    /// (RFC 3830 §3.1, data type 1).
    ///
    /// ```text
    /// R_MESSAGE = HDR, T, [IDr], V
    /// ```
    ///
    /// The timestamp is copied from the initiator's message — §5.2 requires the
    /// responder to reuse it rather than mint a new one — and the verification
    /// MAC covers the response followed by `IDi || IDr || Timestamp`.
    ///
    /// Sending this proves possession of the pre-shared key, which is what gives
    /// the exchange mutual authentication. The caller should verify the
    /// initiator's message first, e.g. via
    /// [`complete_psk`](MikeyMessage::complete_psk).
    ///
    /// # Errors
    ///
    /// Returns [`MikeyError::MissingPayload`] if the initiator's message has no
    /// RAND or T payload.
    pub fn new_psk_verification(init: &MikeyMessage, psk: &[u8]) -> Result<Self> {
        let rand = init
            .rand_bytes()
            .ok_or(MikeyError::MissingPayload("RAND"))?
            .to_vec();
        let ts = init
            .timestamp_payload()
            .ok_or(MikeyError::MissingPayload("T"))?
            .clone();
        let csb_id = init.header.csc_id;

        let header = CommonHeader {
            version: 1,
            data_type: DataType::PskResp,
            next_payload: PayloadType::T as u8,
            v_flag: false,
            prf_func: PrfFunc::MikeyPrfHmacSha1,
            csc_id: csb_id,
            cs_count: init.header.cs_count,
            cs_id_map_type: init.header.cs_id_map_type,
            cs_id_map: init.header.cs_id_map.clone(),
        };

        let timestamp = TimestampPayload {
            next_payload: PayloadType::V as u8,
            ts_type: ts.ts_type,
            ts_value: ts.ts_value.clone(),
        };

        let verification = VerificationPayload {
            next_payload: PayloadType::Last as u8,
            auth_alg: MacAlg::HmacSha1160,
            mac: vec![], // filled in below
        };

        let payloads = vec![
            Payload::Timestamp(timestamp),
            Payload::Verification(verification),
        ];

        // §5.2: the MAC covers the message with the verification field empty,
        // immediately followed by IDi || IDr || Timestamp.
        let mut raw = Self::serialize(&header, &payloads);
        let mac_offset = raw.len();

        let auth_key = crypto::derive_auth_key(psk, csb_id, &rand, PSK_AUTH_KEY_LEN)?;
        let mut mac_input = raw.clone();
        mac_input.extend_from_slice(&Self::verification_identities(init, &payloads));
        mac_input.extend_from_slice(&ts.ts_value);

        let mac = crypto::compute_mac(&auth_key, &mac_input)?;
        raw.extend_from_slice(&mac);

        let mut payloads = payloads;
        if let Some(Payload::Verification(v)) = payloads.last_mut() {
            v.mac = mac;
        }

        Ok(Self {
            header,
            payloads,
            raw,
            mac_offset: Some(mac_offset),
        })
    }

    /// Verify a responder's verification message against the initiator's message.
    ///
    /// Call this on the received PSK-Resp, passing the PSK-Init that was sent.
    /// Success proves the responder holds the same pre-shared key.
    ///
    /// # Errors
    ///
    /// Returns [`MikeyError::InvalidMac`] if the verification data is wrong,
    /// absent, or declares `MacAlg::Null`; [`MikeyError::MissingPayload`] if a
    /// required payload is absent; and [`MikeyError::Parse`] if the responder
    /// echoed a different timestamp than the one sent.
    pub fn verify_psk_verification(&self, init: &MikeyMessage, psk: &[u8]) -> Result<()> {
        let rand = init
            .rand_bytes()
            .ok_or(MikeyError::MissingPayload("RAND"))?
            .to_vec();
        let init_ts = init
            .timestamp_value()
            .ok_or(MikeyError::MissingPayload("T"))?
            .to_vec();

        let v = self
            .payloads
            .iter()
            .find_map(|p| match p {
                Payload::Verification(v) => Some(v),
                _ => None,
            })
            .ok_or(MikeyError::MissingPayload("V"))?;

        if v.auth_alg == MacAlg::Null || v.mac.is_empty() {
            return Err(MikeyError::InvalidMac);
        }

        // §5.2: the responder must echo the initiator's timestamp. A different
        // one would let a responder substitute its own replay context.
        let resp_ts = self
            .timestamp_value()
            .ok_or(MikeyError::MissingPayload("T"))?;
        if resp_ts != init_ts.as_slice() {
            return Err(MikeyError::Parse(
                "verification message echoed a different timestamp".into(),
            ));
        }

        let mac_offset = self.mac_offset.ok_or(MikeyError::InvalidMac)?;
        if mac_offset > self.raw.len() {
            return Err(MikeyError::InvalidMac);
        }

        let auth_key = crypto::derive_auth_key(psk, init.header.csc_id, &rand, PSK_AUTH_KEY_LEN)?;
        let mut mac_input = self.raw[..mac_offset].to_vec();
        mac_input.extend_from_slice(&Self::verification_identities(init, &self.payloads));
        mac_input.extend_from_slice(&init_ts);

        crypto::verify_mac(&auth_key, &mac_input, &v.mac)
    }

    /// `IDi || IDr` for the verification MAC (RFC 3830 §5.2).
    ///
    /// The initiator's identity comes from its message and the responder's from
    /// the response. §3.1 makes both optional, so when neither party sends an ID
    /// payload this contributes nothing and the MAC covers the message and
    /// timestamp alone.
    fn verification_identities(init: &MikeyMessage, resp_payloads: &[Payload]) -> Vec<u8> {
        let mut out = Vec::new();
        if let Some(id_i) = init.payloads.iter().find_map(|p| match p {
            Payload::Id(id) => Some(&id.id_data),
            _ => None,
        }) {
            out.extend_from_slice(id_i);
        }
        if let Some(id_r) = resp_payloads.iter().find_map(|p| match p {
            Payload::Id(id) => Some(&id.id_data),
            _ => None,
        }) {
            out.extend_from_slice(id_r);
        }
        out
    }

    /// Get the T payload from this message.
    pub fn timestamp_payload(&self) -> Option<&TimestampPayload> {
        self.payloads.iter().find_map(|p| match p {
            Payload::Timestamp(t) => Some(t),
            _ => None,
        })
    }

    /// Get the KEMAC payload from this message.
    pub fn kemac(&self) -> Option<&KemacPayload> {
        self.payloads.iter().find_map(|p| match p {
            Payload::Kemac(k) => Some(k),
            _ => None,
        })
    }

    /// Get the raw timestamp value from this message's T payload.
    pub fn timestamp_value(&self) -> Option<&[u8]> {
        self.payloads.iter().find_map(|p| match p {
            Payload::Timestamp(t) => Some(t.ts_value.as_slice()),
            _ => None,
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
                // Wire: next_payload(1) | policy_no(1) | proto_type(1) | policy_param_length(2) | params(...)
                buf.push(sp.next_payload);
                buf.push(sp.policy_no);
                buf.push(sp.proto_type);
                let params_len: usize = sp.params.iter().map(|p| 2 + p.param_len as usize).sum();
                buf.extend_from_slice(&(params_len as u16).to_be_bytes());
                for param in &sp.params {
                    buf.push(param.param_type);
                    buf.push(param.param_len);
                    buf.extend_from_slice(&param.param_value);
                }
            }
            Payload::Verification(v) => {
                buf.push(v.next_payload);
                buf.push(v.auth_alg as u8);
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
        rand::rng().fill_bytes(&mut rand_bytes);

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

        srtp::derive_srtp_keys(&tgk, &self.rand_bytes, 0, self.csc_id, suite)
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

        // The CSB ID is chosen by the initiator and carried in its header.
        srtp::derive_srtp_keys(&tgk, rand, 0, init.header.csc_id, suite)
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

        let keys_a = srtp::derive_srtp_keys(&tgk_a, &rand, 0, 1, suite).unwrap();
        let keys_b = srtp::derive_srtp_keys(&tgk_b, &rand, 0, 1, suite).unwrap();

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

    // --- New tests ---

    #[test]
    fn test_dh_exchange_via_wire_bytes() {
        // Full end-to-end exchange: messages travel as raw bytes through from_bytes
        let suite = SrtpCryptoSuite::AES_128_CM_SHA1_80;

        let initiator = DhInitiator::new(0x1234, 0xABCD);
        let init_bytes = initiator.init_message().unwrap().to_bytes().to_vec();

        let responder = DhResponder::new();
        let parsed_init = MikeyMessage::from_bytes(&init_bytes).unwrap();

        let resp_bytes = responder.resp_message(0x1234).unwrap().to_bytes().to_vec();
        let parsed_resp = MikeyMessage::from_bytes(&resp_bytes).unwrap();

        let init_keys = initiator.complete(&parsed_resp, suite).unwrap();
        let resp_keys = responder.complete(&parsed_init, suite).unwrap();

        assert_eq!(init_keys.master_key, resp_keys.master_key);
        assert_eq!(init_keys.master_salt, resp_keys.master_salt);
        assert_eq!(init_keys.master_key.len(), 16);
        assert_eq!(init_keys.master_salt.len(), 14);
    }

    #[test]
    fn test_dh_exchange_aes256_via_wire_bytes() {
        let suite = SrtpCryptoSuite::AES_256_CM_SHA1_80;

        let initiator = DhInitiator::new(0x5555, 0x9999);
        let init_bytes = initiator.init_message().unwrap().to_bytes().to_vec();

        let responder = DhResponder::new();
        let parsed_init = MikeyMessage::from_bytes(&init_bytes).unwrap();

        let resp_bytes = responder.resp_message(0x5555).unwrap().to_bytes().to_vec();
        let parsed_resp = MikeyMessage::from_bytes(&resp_bytes).unwrap();

        let init_keys = initiator.complete(&parsed_resp, suite).unwrap();
        let resp_keys = responder.complete(&parsed_init, suite).unwrap();

        assert_eq!(init_keys.master_key, resp_keys.master_key);
        assert_eq!(init_keys.master_salt, resp_keys.master_salt);
        assert_eq!(init_keys.master_key.len(), 32);
        assert_eq!(init_keys.master_salt.len(), 14);
    }

    #[test]
    fn test_dh_with_sp_produces_correct_keys() {
        use crate::policy::SrtpPolicy;
        let suite = SrtpCryptoSuite::AES_128_CM_SHA1_80;

        let initiator = DhInitiator::new(0xABCD, 0x1234);
        let sp = SrtpPolicy::aes_128_default().to_sp_payload(0);
        let init_bytes = initiator
            .init_message_with_sp(sp)
            .unwrap()
            .to_bytes()
            .to_vec();

        let responder = DhResponder::new();
        let parsed_init = MikeyMessage::from_bytes(&init_bytes).unwrap();

        let resp_bytes = responder.resp_message(0xABCD).unwrap().to_bytes().to_vec();
        let parsed_resp = MikeyMessage::from_bytes(&resp_bytes).unwrap();

        let init_keys = initiator.complete(&parsed_resp, suite).unwrap();
        let resp_keys = responder.complete(&parsed_init, suite).unwrap();

        assert_eq!(init_keys.master_key, resp_keys.master_key);
        assert_eq!(init_keys.master_salt, resp_keys.master_salt);

        // SP survives the round-trip
        let sp_back = parsed_init.security_policy().unwrap();
        assert_eq!(sp_back.proto_type, 0); // SRTP
        assert!(!sp_back.params.is_empty());
    }

    #[test]
    fn test_psk_mac_tamper_detected() {
        // Build a PSK message, tamper with the trailing MAC, and verify
        // that manual verification catches the corruption.
        let psk = b"super-secret-psk-key-32-bytes!!!";
        let rand_bytes = vec![0x77u8; 16];
        let msg = MikeyMessage::new_psk_init(1, 0x1111, &rand_bytes, psk).unwrap();
        let original = msg.to_bytes();

        // The last 20 bytes are the appended HMAC-SHA-1-160 MAC.
        let len = original.len();
        let mac_start = len - 20;

        // Derive auth_key the same way new_psk_init does: from the PSK and the
        // CSB ID passed to the builder above, per RFC 3830 §4.1.4.
        let auth_key = crypto::derive_auth_key(psk, 1, &rand_bytes, 32).unwrap();

        // Original message verifies correctly.
        crypto::verify_mac(&auth_key, &original[..mac_start], &original[mac_start..]).unwrap();

        // Tamper: flip the last byte of the MAC.
        let mut tampered = original.to_vec();
        tampered[len - 1] ^= 0xFF;
        let result = crypto::verify_mac(&auth_key, &tampered[..mac_start], &tampered[mac_start..]);
        assert!(result.is_err(), "tampered MAC should fail verification");
    }

    #[test]
    fn test_different_rand_produces_different_keys() {
        let rand_a = vec![0xAAu8; 16];
        let rand_b = vec![0xBBu8; 16];
        let psk = b"same-psk-key-for-both-sessions!!";

        let tgk_a = crypto::derive_tgk(psk, &rand_a, 32).unwrap();
        let tgk_b = crypto::derive_tgk(psk, &rand_b, 32).unwrap();

        let keys_a =
            srtp::derive_srtp_keys(&tgk_a, &rand_a, 0, 1, SrtpCryptoSuite::AES_128_CM_SHA1_80)
                .unwrap();
        let keys_b =
            srtp::derive_srtp_keys(&tgk_b, &rand_b, 0, 1, SrtpCryptoSuite::AES_128_CM_SHA1_80)
                .unwrap();

        assert_ne!(keys_a.master_key, keys_b.master_key);
        assert_ne!(keys_a.master_salt, keys_b.master_salt);
    }

    #[test]
    fn test_bad_next_payload_type_rejected() {
        let initiator = DhInitiator::new(1, 2);
        let msg = initiator.init_message().unwrap();
        let mut bytes = msg.to_bytes().to_vec();
        // Header byte 2 is next_payload — corrupt it to an unknown type
        bytes[2] = 99;
        assert!(MikeyMessage::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_unknown_dh_group_rejected() {
        let initiator = DhInitiator::new(1, 2);
        let msg = initiator.init_message().unwrap();
        let mut bytes = msg.to_bytes().to_vec();
        // DH-Init layout (no SP):
        //   header(10) + cs_map_1_entry(9) = 19 bytes
        //   T payload: next(1)+ts_type(1)+ts_value(4) = 6 bytes  [19..25]
        //   RAND payload: next(1)+len(1)+rand(16) = 18 bytes      [25..43]
        //   DH payload: next(1)+dh_group(1)+...                  [43..]
        // bytes[43] = next_payload (0=Last), bytes[44] = dh_group (255=X25519)
        bytes[44] = 50; // not a known DH group
        assert!(MikeyMessage::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_truncated_rand_rejected() {
        let initiator = DhInitiator::new(1, 2);
        let msg = initiator.init_message().unwrap();
        let mut bytes = msg.to_bytes().to_vec();
        // RAND payload starts at offset 25.
        // bytes[25] = next_payload, bytes[26] = rand_len (16).
        // Claim 200 bytes — far more than available.
        bytes[26] = 200;
        assert!(MikeyMessage::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_csb_id_preserved_through_wire() {
        let csc_id = 0xDEAD_BEEF_u32;
        let initiator = DhInitiator::new(csc_id, 0x1111);
        let msg = initiator.init_message().unwrap();
        let parsed = MikeyMessage::from_bytes(msg.to_bytes()).unwrap();
        assert_eq!(parsed.header.csc_id, csc_id);
    }

    // ── "Last payload" terminator (RFC 3830 §6.1, Table 6.1.b) ──────────────
    //
    // Table 6.1.b assigns 0 to "Last payload" and assigns nothing to HDR. mykey
    // previously used 255, which the table does not define, so no message it
    // emitted was conformant and a conformant 0 terminator resolved to `Hdr`.

    /// Build a conformant message by hand: HDR, T(COUNTER), RAND, terminated
    /// with next_payload = 0. Byte sequences are written out rather than
    /// produced by the builders, so this tests the wire format itself.
    fn conformant_bytes(rand_len: u8, terminator: u8) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&[1, DataType::PskInit as u8, PayloadType::T as u8, 0]);
        m.extend_from_slice(&0x1234_5678u32.to_be_bytes()); // CSB ID
        m.push(1); // #CS
        m.push(0); // CS ID map type = SRTP-ID
        m.push(0); // policy_no
        m.extend_from_slice(&0xDEAD_BEEFu32.to_be_bytes()); // SSRC
        m.extend_from_slice(&0u32.to_be_bytes()); // ROC

        m.push(PayloadType::Rand as u8); // T.next_payload
        m.push(TimestampType::Counter as u8);
        m.extend_from_slice(&[0, 0, 0, 1]);

        m.push(terminator); // RAND.next_payload
        m.push(rand_len);
        m.extend_from_slice(&vec![0xAA; rand_len as usize]);
        m
    }

    // ── PSK mode: §3.1 key transport ────────────────────────────────────────

    const TEST_PSK: &[u8] = b"a-shared-secret-of-some-length!!";

    #[test]
    fn test_psk_kemac_is_encrypted_and_structured() {
        let rand = [0x5Au8; 16];
        let msg = MikeyMessage::new_psk_init(0x1234, 0xABCD, &rand, TEST_PSK).unwrap();
        let kemac = msg.kemac().unwrap();

        // §4.2.3: the key data must be AES-CM encrypted, not sent in the clear.
        assert_eq!(kemac.enc_alg, EncAlg::AesCm128);
        assert_eq!(kemac.mac_alg, MacAlg::HmacSha1160);

        // The transported TGK must not be recoverable from the wire bytes.
        let tgk = msg.verify_and_extract_tgk(TEST_PSK).unwrap();
        assert_eq!(tgk.len(), PSK_TGK_LEN);
        let wire = msg.to_bytes();
        assert!(
            !wire.windows(tgk.len()).any(|w| w == tgk.as_slice()),
            "the TGK must not appear anywhere in the serialized message"
        );

        // §6.13: the plaintext is a framed Key data sub-payload, not bare bytes.
        assert_ne!(kemac.enc_data, tgk, "enc_data must not be the raw TGK");
        assert!(
            kemac.enc_data.len() > tgk.len(),
            "enc_data should carry sub-payload framing around the key"
        );
    }

    #[test]
    fn test_psk_tgk_is_random_per_message() {
        // §3.1 has the initiator choose the TGK at random, so two messages with
        // the same PSK and RAND must still carry different keys. Under the old
        // derive-from-PSK design these were identical.
        let rand = [0x11u8; 16];
        let a = MikeyMessage::new_psk_init(1, 2, &rand, TEST_PSK).unwrap();
        let b = MikeyMessage::new_psk_init(1, 2, &rand, TEST_PSK).unwrap();

        assert_ne!(
            a.verify_and_extract_tgk(TEST_PSK).unwrap(),
            b.verify_and_extract_tgk(TEST_PSK).unwrap()
        );
    }

    #[test]
    fn test_psk_roundtrip_over_the_wire() {
        let rand = [0x77u8; 16];
        let suite = SrtpCryptoSuite::AES_128_CM_SHA1_80;
        let init = MikeyMessage::new_psk_init(0xFEED, 0xBEEF, &rand, TEST_PSK).unwrap();

        let initiator_keys = init.complete_psk(TEST_PSK, suite).unwrap();

        // Responder sees only the bytes.
        let parsed = MikeyMessage::from_bytes(init.to_bytes()).unwrap();
        let responder_keys = parsed.complete_psk(TEST_PSK, suite).unwrap();

        assert_eq!(initiator_keys.master_key, responder_keys.master_key);
        assert_eq!(initiator_keys.master_salt, responder_keys.master_salt);
    }

    #[test]
    fn test_psk_wrong_key_rejected() {
        let rand = [0x33u8; 16];
        let init = MikeyMessage::new_psk_init(1, 2, &rand, TEST_PSK).unwrap();
        let parsed = MikeyMessage::from_bytes(init.to_bytes()).unwrap();

        match parsed.complete_psk(
            b"not-the-right-shared-secret-xxxx",
            SrtpCryptoSuite::AES_128_CM_SHA1_80,
        ) {
            Err(MikeyError::InvalidMac) => {}
            other => panic!("expected InvalidMac, got {other:?}"),
        }
    }

    #[test]
    fn test_psk_tampered_ciphertext_rejected_before_decryption() {
        // The MAC covers the ciphertext, so flipping a bit in enc_data must be
        // caught by authentication rather than surfacing as a parse error from
        // the decrypted key data.
        let rand = [0x44u8; 16];
        let init = MikeyMessage::new_psk_init(1, 2, &rand, TEST_PSK).unwrap();
        let mut bytes = init.to_bytes().to_vec();

        // KEMAC starts at 43: next(1) enc_alg(1) len(2), so enc_data at 47.
        bytes[47] ^= 0xFF;

        match MikeyMessage::from_bytes(&bytes)
            .unwrap()
            .complete_psk(TEST_PSK, SrtpCryptoSuite::AES_128_CM_SHA1_80)
        {
            Err(MikeyError::InvalidMac) => {}
            other => panic!("expected InvalidMac, got {other:?}"),
        }
    }

    #[test]
    fn test_psk_null_mac_alg_refused() {
        // A NULL MAC cannot authenticate anything, so it must be refused rather
        // than treated as "no check needed".
        let rand = [0x55u8; 16];
        let init = MikeyMessage::new_psk_init(1, 2, &rand, TEST_PSK).unwrap();
        let mut bytes = init.to_bytes().to_vec();

        // mac_alg sits immediately after enc_data in the KEMAC.
        let enc_len = init.kemac().unwrap().enc_data.len();
        bytes[43 + 4 + enc_len] = MacAlg::Null as u8;

        // Parsing may fail outright (the MAC length changes), but if it parses,
        // completing must refuse.
        if let Ok(parsed) = MikeyMessage::from_bytes(&bytes) {
            match parsed.complete_psk(TEST_PSK, SrtpCryptoSuite::AES_128_CM_SHA1_80) {
                Err(MikeyError::InvalidMac) => {}
                other => panic!("expected InvalidMac, got {other:?}"),
            }
        }
    }

    #[test]
    fn test_psk_tampered_timestamp_rejected() {
        // The timestamp feeds the AES-CM IV (§4.2.3) and is MAC-covered, so
        // altering it must fail authentication.
        let rand = [0x66u8; 16];
        let init = MikeyMessage::new_psk_init(1, 2, &rand, TEST_PSK).unwrap();
        let mut bytes = init.to_bytes().to_vec();
        bytes[21] ^= 0x01; // inside the T payload's value

        match MikeyMessage::from_bytes(&bytes)
            .unwrap()
            .complete_psk(TEST_PSK, SrtpCryptoSuite::AES_128_CM_SHA1_80)
        {
            Err(MikeyError::InvalidMac) => {}
            other => panic!("expected InvalidMac, got {other:?}"),
        }
    }

    // ── Verification message (§6.9) ─────────────────────────────────────────

    #[test]
    fn test_v_flag_signals_verification_request() {
        let rand = [0x88u8; 16];
        assert!(!MikeyMessage::new_psk_init(1, 2, &rand, TEST_PSK)
            .unwrap()
            .requires_verification());

        let requesting =
            MikeyMessage::new_psk_init_requiring_verification(1, 2, &rand, TEST_PSK).unwrap();
        assert!(requesting.requires_verification());

        // And it survives the wire.
        assert!(MikeyMessage::from_bytes(requesting.to_bytes())
            .unwrap()
            .requires_verification());
    }

    #[test]
    fn test_verification_message_roundtrip() {
        let rand = [0x99u8; 16];
        let init =
            MikeyMessage::new_psk_init_requiring_verification(0xAAAA, 0xBBBB, &rand, TEST_PSK)
                .unwrap();

        // Responder parses the init, then answers.
        let parsed_init = MikeyMessage::from_bytes(init.to_bytes()).unwrap();
        let resp = MikeyMessage::new_psk_verification(&parsed_init, TEST_PSK).unwrap();
        assert_eq!(resp.header.data_type, DataType::PskResp);

        // Initiator checks the reply as received bytes.
        let parsed_resp = MikeyMessage::from_bytes(resp.to_bytes()).unwrap();
        parsed_resp
            .verify_psk_verification(&init, TEST_PSK)
            .expect("verification message must authenticate");
    }

    #[test]
    fn test_verification_message_wrong_psk_rejected() {
        let rand = [0xA1u8; 16];
        let init =
            MikeyMessage::new_psk_init_requiring_verification(1, 2, &rand, TEST_PSK).unwrap();
        let resp =
            MikeyMessage::new_psk_verification(&init, b"a-different-shared-secret-abcde!").unwrap();
        let parsed = MikeyMessage::from_bytes(resp.to_bytes()).unwrap();

        assert!(parsed.verify_psk_verification(&init, TEST_PSK).is_err());
    }

    #[test]
    fn test_verification_message_tamper_rejected() {
        let rand = [0xA2u8; 16];
        let init =
            MikeyMessage::new_psk_init_requiring_verification(1, 2, &rand, TEST_PSK).unwrap();
        let resp = MikeyMessage::new_psk_verification(&init, TEST_PSK).unwrap();

        let mut bytes = resp.to_bytes().to_vec();
        let len = bytes.len();
        bytes[len - 1] ^= 0xFF; // last byte of the verification data

        match MikeyMessage::from_bytes(&bytes)
            .unwrap()
            .verify_psk_verification(&init, TEST_PSK)
        {
            Err(MikeyError::InvalidMac) => {}
            other => panic!("expected InvalidMac, got {other:?}"),
        }
    }

    #[test]
    fn test_verification_message_echoes_initiator_timestamp() {
        // §5.2: the responder reuses the initiator's timestamp rather than
        // minting its own, and a substituted one must be rejected.
        let rand = [0xA3u8; 16];
        let init =
            MikeyMessage::new_psk_init_requiring_verification(1, 2, &rand, TEST_PSK).unwrap();
        let resp = MikeyMessage::new_psk_verification(&init, TEST_PSK).unwrap();

        assert_eq!(resp.timestamp_value(), init.timestamp_value());

        // Rewrite the echoed timestamp; the mismatch must be caught.
        let mut bytes = resp.to_bytes().to_vec();
        bytes[21] ^= 0x01;
        assert!(MikeyMessage::from_bytes(&bytes)
            .unwrap()
            .verify_psk_verification(&init, TEST_PSK)
            .is_err());
    }

    #[test]
    fn test_verification_payload_carries_auth_alg() {
        // §6.9 puts an Auth alg byte between next_payload and the data; it was
        // previously omitted from both parse and serialize.
        let rand = [0xA4u8; 16];
        let init =
            MikeyMessage::new_psk_init_requiring_verification(1, 2, &rand, TEST_PSK).unwrap();
        let resp = MikeyMessage::new_psk_verification(&init, TEST_PSK).unwrap();
        let parsed = MikeyMessage::from_bytes(resp.to_bytes()).unwrap();

        let v = parsed
            .payloads
            .iter()
            .find_map(|p| match p {
                Payload::Verification(v) => Some(v),
                _ => None,
            })
            .expect("V payload");
        assert_eq!(v.auth_alg, MacAlg::HmacSha1160);
        assert_eq!(v.mac.len(), 20);
    }

    // ── Key data sub-payload (§6.13) ────────────────────────────────────────

    #[test]
    fn test_key_data_subpayload_roundtrip() {
        for sub in [
            KeyDataSubPayload::tgk(vec![0x42; 32]),
            KeyDataSubPayload {
                next_payload: PayloadType::Last as u8,
                key_type: KeyDataType::TgkSalt,
                key_data: vec![0x11; 16],
                salt: Some(vec![0x22; 14]),
                validity: KeyValidity::Spi(vec![0x01, 0x02]),
            },
            KeyDataSubPayload {
                next_payload: PayloadType::Last as u8,
                key_type: KeyDataType::Tek,
                key_data: vec![0x33; 16],
                salt: None,
                validity: KeyValidity::Interval {
                    valid_from: vec![0; 6],
                    valid_to: vec![0xFF; 6],
                },
            },
        ] {
            let mut buf = Vec::new();
            sub.serialize(&mut buf);
            let (parsed, consumed) = KeyDataSubPayload::parse(&buf).unwrap();
            assert_eq!(consumed, buf.len(), "parse must consume exactly");
            assert_eq!(parsed, sub);
        }
    }

    #[test]
    fn test_key_data_chain_requires_terminator() {
        // A chain that never declares Last must be rejected rather than parsed
        // as far as the bytes allow.
        let mut buf = Vec::new();
        let mut sub = KeyDataSubPayload::tgk(vec![0x42; 32]);
        sub.next_payload = PayloadType::KeyData as u8;
        sub.serialize(&mut buf);
        assert!(KeyDataSubPayload::parse_chain(&buf).is_err());
    }

    #[test]
    fn test_key_data_chain_rejects_trailing_bytes() {
        let mut buf = Vec::new();
        KeyDataSubPayload::tgk(vec![0x42; 32]).serialize(&mut buf);
        buf.push(0x00);
        assert!(KeyDataSubPayload::parse_chain(&buf).is_err());
    }

    /// The transported TGK must be at least as long as the largest SRTP master
    /// key any supported suite can request, because the suite is chosen after
    /// the TGK has already been generated. Adding a longer-keyed suite without
    /// raising `PSK_TGK_LEN` would silently cap that key's entropy, so this
    /// fails rather than letting it pass unnoticed.
    #[test]
    fn test_psk_tgk_len_covers_every_suite() {
        for suite in [
            SrtpCryptoSuite::AES_128_CM_SHA1_80,
            SrtpCryptoSuite::AES_256_CM_SHA1_80,
        ] {
            assert!(
                PSK_TGK_LEN >= suite.master_key_len,
                "PSK_TGK_LEN ({PSK_TGK_LEN}) is shorter than a suite's master key ({})",
                suite.master_key_len
            );
        }
    }

    /// 32 bytes is exactly one RFC 3830 §4.1.2 PRF input block (256 bits).
    #[test]
    fn test_psk_tgk_len_is_one_prf_block() {
        assert_eq!(PSK_TGK_LEN, 32);
    }

    #[test]
    fn test_last_payload_value_is_zero() {
        assert_eq!(PayloadType::Last as u8, 0);
        assert_eq!(PayloadType::from_u8(0), Some(PayloadType::Last));
        // 255 is not a defined Next Payload value.
        assert_eq!(PayloadType::from_u8(255), None);
    }

    #[test]
    fn test_emitted_messages_terminate_with_zero() {
        // DH-Init: header(10) + cs_map(9) + T(6) + RAND(18) => DH payload at 43,
        // whose next_payload is the chain terminator.
        let dh = DhInitiator::new(1, 2).init_message().unwrap();
        assert_eq!(dh.to_bytes()[43], 0, "DH-Init must terminate with 0");

        // PSK-Init has the same prefix layout, with KEMAC in place of DH.
        let psk = MikeyMessage::new_psk_init(1, 2, &[0x55; 16], b"psk").unwrap();
        assert_eq!(psk.to_bytes()[43], 0, "PSK-Init must terminate with 0");
    }

    #[test]
    fn test_parses_conformant_zero_terminator() {
        let bytes = conformant_bytes(16, PayloadType::Last as u8);
        let msg = MikeyMessage::from_bytes(&bytes).expect("conformant message must parse");
        assert_eq!(msg.payloads.len(), 2, "expected T and RAND");
        assert_eq!(msg.rand_bytes(), Some(&[0xAAu8; 16][..]));
    }

    #[test]
    fn test_rejects_legacy_255_terminator() {
        // Messages from mykey <= 1.0.0 terminated with 255. That value is not in
        // Table 6.1.b, so it must now be rejected rather than silently accepted.
        // Trailing bytes are appended so the parser reaches the type lookup
        // rather than stopping at the end of the buffer first — this pins the
        // rejection to the undefined value, not to truncation.
        let mut bytes = conformant_bytes(16, 255);
        bytes.extend_from_slice(&[0x99; 20]);
        match MikeyMessage::from_bytes(&bytes) {
            Err(MikeyError::InvalidPayloadType(255)) => {}
            other => panic!("expected InvalidPayloadType(255), got {other:?}"),
        }
    }

    #[test]
    fn test_truncated_chain_rejected() {
        // The chain points at another payload, but the buffer ends. Previously
        // the loop's `pos < data.len()` guard made this parse as if complete.
        let mut bytes = conformant_bytes(16, PayloadType::Kemac as u8);
        // Leave the RAND intact but provide no KEMAC at all.
        assert!(
            MikeyMessage::from_bytes(&bytes).is_err(),
            "truncated chain must be rejected, not treated as terminated"
        );

        // Same message, but terminated properly, parses.
        bytes = conformant_bytes(16, PayloadType::Last as u8);
        assert!(MikeyMessage::from_bytes(&bytes).is_ok());
    }

    #[test]
    fn test_trailing_bytes_after_terminator_are_ignored() {
        // PSK mode appends the message MAC after the payload chain, so bytes
        // beyond the terminator are normal and must not cause a parse failure.
        let mut bytes = conformant_bytes(16, PayloadType::Last as u8);
        bytes.extend_from_slice(&[0x99; 20]);
        let msg = MikeyMessage::from_bytes(&bytes).expect("trailing MAC must not break parsing");
        assert_eq!(msg.payloads.len(), 2);
    }
}
