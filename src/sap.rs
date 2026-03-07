use crate::error::{MikeyError, Result};
use crate::message::MikeyMessage;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

/// SAP (Session Announcement Protocol, RFC 2974) packet with MIKEY support.
///
/// SAP is used for multicast session announcements. MIKEY key material
/// can be embedded either:
/// 1. In the SDP payload via `a=key-mgmt:mikey <base64>` (RFC 4567)
/// 2. In the SAP authentication/encryption data field
///
/// For AES67/ST 2110, approach #1 (SDP key-mgmt) is standard.
#[derive(Debug, Clone)]
pub struct SapPacket {
    /// SAP version (always 1)
    pub version: u8,
    /// Address type: false = IPv4, true = IPv6
    pub address_type_ipv6: bool,
    /// Message type: false = announcement, true = deletion
    pub deletion: bool,
    /// Encryption flag
    pub encrypted: bool,
    /// Compressed flag
    pub compressed: bool,
    /// Authentication length (in 32-bit words)
    pub auth_len: u8,
    /// Message ID hash
    pub msg_id_hash: u16,
    /// Originating source IP (4 or 16 bytes)
    pub origin: Vec<u8>,
    /// Optional authentication data
    pub auth_data: Vec<u8>,
    /// Payload type (e.g., "application/sdp")
    pub payload_type: String,
    /// SDP payload
    pub payload: String,
}

impl SapPacket {
    /// Create a new SAP announcement packet
    pub fn new_announcement(origin_ipv4: [u8; 4], msg_id_hash: u16, sdp: String) -> Self {
        Self {
            version: 1,
            address_type_ipv6: false,
            deletion: false,
            encrypted: false,
            compressed: false,
            auth_len: 0,
            msg_id_hash,
            origin: origin_ipv4.to_vec(),
            auth_data: Vec::new(),
            payload_type: "application/sdp".into(),
            payload: sdp,
        }
    }

    /// Serialize to wire bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // First byte: V(3) | A(1) | R(1) | T(1) | E(1) | C(1)
        let byte0 = (self.version & 0x07) << 5
            | if self.address_type_ipv6 { 0x10 } else { 0 }
            | if self.deletion { 0x04 } else { 0 }
            | if self.encrypted { 0x02 } else { 0 }
            | if self.compressed { 0x01 } else { 0 };
        buf.push(byte0);
        buf.push(self.auth_len);
        buf.extend_from_slice(&self.msg_id_hash.to_be_bytes());
        buf.extend_from_slice(&self.origin);
        buf.extend_from_slice(&self.auth_data);

        // Payload type (null-terminated)
        buf.extend_from_slice(self.payload_type.as_bytes());
        buf.push(0);

        // SDP payload
        buf.extend_from_slice(self.payload.as_bytes());

        buf
    }

    /// Parse from wire bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(MikeyError::MessageTooShort {
                expected: 4,
                actual: data.len(),
            });
        }

        let version = (data[0] >> 5) & 0x07;
        let address_type_ipv6 = (data[0] & 0x10) != 0;
        let deletion = (data[0] & 0x04) != 0;
        let encrypted = (data[0] & 0x02) != 0;
        let compressed = (data[0] & 0x01) != 0;
        let auth_len = data[1];
        let msg_id_hash = u16::from_be_bytes([data[2], data[3]]);

        let addr_len = if address_type_ipv6 { 16 } else { 4 };
        let origin_end = 4 + addr_len;
        if data.len() < origin_end {
            return Err(MikeyError::MessageTooShort {
                expected: origin_end,
                actual: data.len(),
            });
        }
        let origin = data[4..origin_end].to_vec();

        let auth_data_len = auth_len as usize * 4;
        let auth_end = origin_end + auth_data_len;
        if data.len() < auth_end {
            return Err(MikeyError::MessageTooShort {
                expected: auth_end,
                actual: data.len(),
            });
        }
        let auth_data = data[origin_end..auth_end].to_vec();

        // Find null-terminated payload type string
        let type_start = auth_end;
        let null_pos = data[type_start..]
            .iter()
            .position(|&b| b == 0)
            .ok_or(MikeyError::Parse(
                "missing payload type null terminator".into(),
            ))?;
        let payload_type = String::from_utf8(data[type_start..type_start + null_pos].to_vec())
            .map_err(|e| MikeyError::Parse(e.to_string()))?;

        let payload_start = type_start + null_pos + 1;
        let payload = String::from_utf8(data[payload_start..].to_vec())
            .map_err(|e| MikeyError::Parse(e.to_string()))?;

        Ok(Self {
            version,
            address_type_ipv6,
            deletion,
            encrypted,
            compressed,
            auth_len,
            msg_id_hash,
            origin,
            auth_data,
            payload_type,
            payload,
        })
    }
}

/// Embed a MIKEY message into SDP using the `a=key-mgmt` attribute (RFC 4567).
///
/// Returns an SDP line like: `a=key-mgmt:mikey <base64-encoded MIKEY message>`
pub fn mikey_to_sdp_attribute(msg: &MikeyMessage) -> String {
    let encoded = BASE64.encode(msg.to_bytes());
    format!("a=key-mgmt:mikey {encoded}")
}

/// Extract and parse a MIKEY message from an SDP `a=key-mgmt:mikey` attribute line.
pub fn mikey_from_sdp_attribute(line: &str) -> Result<MikeyMessage> {
    let line = line.trim();
    let b64 = line
        .strip_prefix("a=key-mgmt:mikey ")
        .ok_or(MikeyError::Parse("not a key-mgmt:mikey attribute".into()))?;

    let bytes = BASE64
        .decode(b64.trim())
        .map_err(|e| MikeyError::Parse(format!("base64 decode: {e}")))?;

    MikeyMessage::from_bytes(&bytes)
}

/// Build a complete SAP packet with MIKEY embedded in SDP.
///
/// Takes an SDP template and a MIKEY message, inserts the `a=key-mgmt` line,
/// and wraps it in a SAP announcement.
pub fn build_sap_with_mikey(
    origin_ipv4: [u8; 4],
    msg_id_hash: u16,
    sdp: &str,
    mikey_msg: &MikeyMessage,
) -> SapPacket {
    let key_mgmt_line = mikey_to_sdp_attribute(mikey_msg);
    // Insert the key-mgmt attribute at the session level (before first m= line)
    let sdp_with_mikey = insert_sdp_attribute(sdp, &key_mgmt_line);
    SapPacket::new_announcement(origin_ipv4, msg_id_hash, sdp_with_mikey)
}

/// Insert an SDP attribute line at session level (before the first `m=` line)
fn insert_sdp_attribute(sdp: &str, attribute: &str) -> String {
    let mut result = String::new();
    let mut inserted = false;

    for line in sdp.lines() {
        if !inserted && line.starts_with("m=") {
            result.push_str(attribute);
            result.push_str("\r\n");
            inserted = true;
        }
        result.push_str(line);
        result.push_str("\r\n");
    }

    // If no m= line found, append at end
    if !inserted {
        result.push_str(attribute);
        result.push_str("\r\n");
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::DhInitiator;

    #[test]
    fn test_sap_roundtrip() {
        let sdp = "v=0\r\no=- 0 0 IN IP4 192.168.1.1\r\ns=Test\r\n".to_string();
        let packet = SapPacket::new_announcement([192, 168, 1, 1], 0x1234, sdp.clone());
        let bytes = packet.to_bytes();

        let parsed = SapPacket::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.version, 1);
        assert!(!parsed.address_type_ipv6);
        assert!(!parsed.deletion);
        assert_eq!(parsed.msg_id_hash, 0x1234);
        assert_eq!(parsed.origin, vec![192, 168, 1, 1]);
        assert_eq!(parsed.payload_type, "application/sdp");
        assert_eq!(parsed.payload, sdp);
    }

    #[test]
    fn test_mikey_sdp_attribute_roundtrip() {
        let initiator = DhInitiator::new(1, 0x12345678);
        let msg = initiator.init_message().unwrap();

        let attr = mikey_to_sdp_attribute(&msg);
        assert!(attr.starts_with("a=key-mgmt:mikey "));

        let parsed = mikey_from_sdp_attribute(&attr).unwrap();
        assert_eq!(parsed.header.data_type, crate::payload::DataType::DhInit);
        assert_eq!(parsed.dh_public().unwrap(), msg.dh_public().unwrap());
    }

    #[test]
    fn test_build_sap_with_mikey() {
        let sdp =
            "v=0\r\no=- 0 0 IN IP4 192.168.1.1\r\ns=AES67 Stream\r\nm=audio 5004 RTP/AVP 96\r\n";
        let initiator = DhInitiator::new(1, 0xAABBCCDD);
        let msg = initiator.init_message().unwrap();

        let sap = build_sap_with_mikey([192, 168, 1, 1], 0x5678, sdp, &msg);
        let bytes = sap.to_bytes();

        let parsed_sap = SapPacket::from_bytes(&bytes).unwrap();
        assert!(parsed_sap.payload.contains("a=key-mgmt:mikey "));

        // The key-mgmt line should appear before the m= line
        let key_pos = parsed_sap.payload.find("a=key-mgmt").unwrap();
        let media_pos = parsed_sap.payload.find("m=audio").unwrap();
        assert!(key_pos < media_pos);

        // Extract and verify the MIKEY message from the SDP
        let key_mgmt_line = parsed_sap
            .payload
            .lines()
            .find(|l| l.starts_with("a=key-mgmt:mikey"))
            .unwrap();
        let parsed_mikey = mikey_from_sdp_attribute(key_mgmt_line).unwrap();
        assert_eq!(parsed_mikey.dh_public().unwrap(), msg.dh_public().unwrap());
    }

    #[test]
    fn test_invalid_sdp_attribute() {
        assert!(mikey_from_sdp_attribute("a=rtpmap:96 L24/48000/2").is_err());
        assert!(mikey_from_sdp_attribute("a=key-mgmt:mikey !!!invalid!!!").is_err());
    }

    #[test]
    fn test_sap_deletion_packet() {
        let sdp = "v=0\r\no=- 0 0 IN IP4 192.168.1.1\r\ns=Test\r\n".to_string();
        let mut packet = SapPacket::new_announcement([192, 168, 1, 1], 0xABCD, sdp.clone());
        packet.deletion = true;

        let bytes = packet.to_bytes();
        let parsed = SapPacket::from_bytes(&bytes).unwrap();

        assert!(parsed.deletion);
        assert_eq!(parsed.msg_id_hash, 0xABCD);
        assert_eq!(parsed.payload, sdp);
    }

    #[test]
    fn test_sp_survives_sap_sdp_roundtrip() {
        use crate::payload::DataType;
        use crate::policy::SrtpPolicy;

        let initiator = DhInitiator::new(1, 0x1234);
        let sp = SrtpPolicy::aes_128_default().to_sp_payload(0);
        let mikey_msg = initiator.init_message_with_sp(sp).unwrap();

        let sdp = "v=0\r\no=- 0 0 IN IP4 192.168.1.1\r\ns=Test\r\nm=audio 5004 RTP/AVP 96\r\n";
        let sap = build_sap_with_mikey([192, 168, 1, 1], 0x0001, sdp, &mikey_msg);
        let sap_bytes = sap.to_bytes();

        let parsed_sap = SapPacket::from_bytes(&sap_bytes).unwrap();
        let key_line = parsed_sap
            .payload
            .lines()
            .find(|l| l.starts_with("a=key-mgmt:mikey"))
            .unwrap();
        let parsed_mikey = mikey_from_sdp_attribute(key_line).unwrap();

        assert_eq!(parsed_mikey.header.data_type, DataType::DhInit);

        let sp_back = parsed_mikey.security_policy().unwrap();
        assert_eq!(sp_back.proto_type, 0); // SRTP

        let policy = SrtpPolicy::from_sp_payload(sp_back).unwrap();
        assert_eq!(policy.enc_key_len, 16);
        assert_eq!(policy.auth_tag_len, 10);
    }
}
