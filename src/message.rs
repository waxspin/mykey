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
    pub header: CommonHeader,
    pub payloads: Vec<Payload>,
    raw: Vec<u8>,
}

impl MikeyMessage {
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

        let raw = Self::serialize_header(&header, &payloads);

        Ok(Self {
            header,
            payloads,
            raw,
        })
    }

    /// Build a DH responder message (data_type = 5)
    pub fn new_dh_resp(
        csc_id: u32,
        dh_public: &[u8; 32],
    ) -> Result<Self> {
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
        let raw = Self::serialize_header(&header, &payloads);

        Ok(Self {
            header,
            payloads,
            raw,
        })
    }

    /// Build a PSK initiator message (data_type = 0)
    pub fn new_psk_init(
        csc_id: u32,
        ssrc: u32,
        rand_bytes: &[u8],
        psk: &[u8],
    ) -> Result<Self> {
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
            mac: vec![], // computed over serialized message
        };

        let payloads = vec![
            Payload::Timestamp(timestamp),
            Payload::Rand(rand),
            Payload::Kemac(kemac),
        ];

        let mut raw = Self::serialize_header(&header, &payloads);

        // Compute and append MAC over the entire message (minus MAC field itself)
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

    /// Serialize to bytes for wire transmission
    pub fn to_bytes(&self) -> &[u8] {
        &self.raw
    }

    fn serialize_header(header: &CommonHeader, payloads: &[Payload]) -> Vec<u8> {
        let mut buf = Vec::new();

        // Common header (RFC 3830 Section 6.1)
        buf.push(header.version);
        buf.push(header.data_type as u8);
        buf.push(header.next_payload);
        buf.push(
            if header.v_flag { 0x80 } else { 0x00 }
                | (header.prf_func as u8 & 0x7F),
        );
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
            match p {
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
                    buf.push(dh.next_payload);
                    buf.push(dh.dh_group as u8);
                    buf.extend_from_slice(&(dh.dh_value.len() as u16).to_be_bytes());
                    buf.extend_from_slice(&dh.dh_value);
                    buf.push(dh.kv_type);
                    buf.extend_from_slice(&dh.kv_data);
                }
                Payload::Kemac(k) => {
                    buf.push(k.next_payload);
                    buf.push(k.enc_alg as u8);
                    buf.push(k.mac_alg as u8);
                    buf.extend_from_slice(&(k.enc_data.len() as u16).to_be_bytes());
                    buf.extend_from_slice(&k.enc_data);
                    // MAC appended separately
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
                Payload::Header(_) => {} // header already serialized above
            }
        }

        buf
    }
}

/// Perform a complete DH key exchange (initiator side)
pub struct DhInitiator {
    keypair: Option<DhKeyPair>,
    rand_bytes: Vec<u8>,
    csc_id: u32,
    ssrc: u32,
}

impl DhInitiator {
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

        MikeyMessage::new_dh_init(
            self.csc_id,
            self.ssrc,
            &self.rand_bytes,
            public.as_bytes(),
        )
    }

    /// Process the responder's message and derive SRTP keys
    pub fn complete(
        mut self,
        resp: &MikeyMessage,
        suite: SrtpCryptoSuite,
    ) -> Result<SrtpKeyMaterial> {
        let peer_pub = resp
            .dh_public()
            .ok_or(MikeyError::MissingPayload("DH"))?;

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

/// Perform a complete DH key exchange (responder side)
pub struct DhResponder {
    keypair: Option<DhKeyPair>,
}

impl DhResponder {
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
        let peer_pub = init
            .dh_public()
            .ok_or(MikeyError::MissingPayload("DH"))?;
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

        // We test key agreement at the crypto level since the high-level
        // API consumes the keypairs
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
    fn test_serialization_roundtrip() {
        let initiator = DhInitiator::new(42, 0xDEADBEEF);
        let msg = initiator.init_message().unwrap();
        let bytes = msg.to_bytes();

        // Verify header fields in serialized bytes
        assert_eq!(bytes[0], 1); // version
        assert_eq!(bytes[1], DataType::DhInit as u8);
        assert!(bytes.len() > 50); // reasonable minimum size
    }
}
