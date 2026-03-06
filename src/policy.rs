use crate::payload::{SpParam, SpPayload, SrtpParamType};

/// SRTP encryption algorithms for security policy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SrtpEncAlg {
    /// No encryption.
    Null = 0,
    /// AES Counter Mode (standard for SRTP).
    AesCm = 1,
    /// AES f8 mode.
    AesF8 = 2,
}

/// SRTP authentication algorithms for security policy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SrtpAuthAlg {
    /// No authentication.
    Null = 0,
    /// HMAC-SHA-1 (standard for SRTP).
    HmacSha1 = 1,
}

/// Builder for SRTP security policy (RFC 3830 Section 6.10.1)
#[derive(Debug, Clone)]
pub struct SrtpPolicy {
    /// Encryption algorithm.
    pub enc_alg: SrtpEncAlg,
    /// Encryption key length in bytes.
    pub enc_key_len: u8,
    /// Authentication algorithm.
    pub auth_alg: SrtpAuthAlg,
    /// Authentication key length in bytes.
    pub auth_key_len: u8,
    /// Salt key length in bytes.
    pub salt_key_len: u8,
    /// Whether SRTP encryption is enabled.
    pub srtp_encryption: bool,
    /// Whether SRTCP encryption is enabled.
    pub srtcp_encryption: bool,
    /// Whether SRTP authentication is enabled.
    pub srtp_authentication: bool,
    /// Authentication tag length in bytes.
    pub auth_tag_len: u8,
}

impl SrtpPolicy {
    /// AES-128-CM with HMAC-SHA1-80 — the standard AES67 profile
    pub fn aes_128_default() -> Self {
        Self {
            enc_alg: SrtpEncAlg::AesCm,
            enc_key_len: 16,
            auth_alg: SrtpAuthAlg::HmacSha1,
            auth_key_len: 20,
            salt_key_len: 14,
            srtp_encryption: true,
            srtcp_encryption: true,
            srtp_authentication: true,
            auth_tag_len: 10, // 80 bits
        }
    }

    /// AES-256-CM with HMAC-SHA1-80
    pub fn aes_256_default() -> Self {
        Self {
            enc_alg: SrtpEncAlg::AesCm,
            enc_key_len: 32,
            auth_alg: SrtpAuthAlg::HmacSha1,
            auth_key_len: 20,
            salt_key_len: 14,
            srtp_encryption: true,
            srtcp_encryption: true,
            srtp_authentication: true,
            auth_tag_len: 10,
        }
    }

    /// Convert to an SpPayload for inclusion in a MIKEY message
    pub fn to_sp_payload(&self, policy_no: u8) -> SpPayload {
        let params = vec![
            sp_param(SrtpParamType::EncryptionAlg, self.enc_alg as u8),
            sp_param(SrtpParamType::SessionEncKeyLen, self.enc_key_len),
            sp_param(SrtpParamType::AuthAlg, self.auth_alg as u8),
            sp_param(SrtpParamType::SessionAuthKeyLen, self.auth_key_len),
            sp_param(SrtpParamType::SessionSaltKeyLen, self.salt_key_len),
            sp_param(SrtpParamType::SrtpEncryption, self.srtp_encryption as u8),
            sp_param(SrtpParamType::SrtcpEncryption, self.srtcp_encryption as u8),
            sp_param(
                SrtpParamType::SrtpAuthentication,
                self.srtp_authentication as u8,
            ),
            sp_param(SrtpParamType::AuthTagLen, self.auth_tag_len),
        ];

        SpPayload {
            next_payload: 0, // caller sets this based on message structure
            policy_no,
            proto_type: 0, // 0 = SRTP
            params,
        }
    }

    /// Parse from an SpPayload
    pub fn from_sp_payload(sp: &SpPayload) -> Option<Self> {
        if sp.proto_type != 0 {
            return None; // not SRTP
        }

        let mut policy = Self::aes_128_default(); // start with defaults

        for param in &sp.params {
            match param.param_type {
                t if t == SrtpParamType::EncryptionAlg as u8 => {
                    if let Some(&v) = param.param_value.first() {
                        policy.enc_alg = match v {
                            0 => SrtpEncAlg::Null,
                            1 => SrtpEncAlg::AesCm,
                            2 => SrtpEncAlg::AesF8,
                            _ => return None,
                        };
                    }
                }
                t if t == SrtpParamType::SessionEncKeyLen as u8 => {
                    if let Some(&v) = param.param_value.first() {
                        policy.enc_key_len = v;
                    }
                }
                t if t == SrtpParamType::AuthAlg as u8 => {
                    if let Some(&v) = param.param_value.first() {
                        policy.auth_alg = match v {
                            0 => SrtpAuthAlg::Null,
                            1 => SrtpAuthAlg::HmacSha1,
                            _ => return None,
                        };
                    }
                }
                t if t == SrtpParamType::SessionAuthKeyLen as u8 => {
                    if let Some(&v) = param.param_value.first() {
                        policy.auth_key_len = v;
                    }
                }
                t if t == SrtpParamType::SessionSaltKeyLen as u8 => {
                    if let Some(&v) = param.param_value.first() {
                        policy.salt_key_len = v;
                    }
                }
                t if t == SrtpParamType::SrtpEncryption as u8 => {
                    if let Some(&v) = param.param_value.first() {
                        policy.srtp_encryption = v != 0;
                    }
                }
                t if t == SrtpParamType::SrtcpEncryption as u8 => {
                    if let Some(&v) = param.param_value.first() {
                        policy.srtcp_encryption = v != 0;
                    }
                }
                t if t == SrtpParamType::SrtpAuthentication as u8 => {
                    if let Some(&v) = param.param_value.first() {
                        policy.srtp_authentication = v != 0;
                    }
                }
                t if t == SrtpParamType::AuthTagLen as u8 => {
                    if let Some(&v) = param.param_value.first() {
                        policy.auth_tag_len = v;
                    }
                }
                _ => {} // ignore unknown params
            }
        }

        Some(policy)
    }
}

fn sp_param(param_type: SrtpParamType, value: u8) -> SpParam {
    SpParam {
        param_type: param_type as u8,
        param_len: 1,
        param_value: vec![value],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes128_policy_roundtrip() {
        let policy = SrtpPolicy::aes_128_default();
        let sp = policy.to_sp_payload(0);

        assert_eq!(sp.proto_type, 0);
        assert_eq!(sp.params.len(), 9);

        let parsed = SrtpPolicy::from_sp_payload(&sp).unwrap();
        assert_eq!(parsed.enc_alg, SrtpEncAlg::AesCm);
        assert_eq!(parsed.enc_key_len, 16);
        assert_eq!(parsed.auth_alg, SrtpAuthAlg::HmacSha1);
        assert_eq!(parsed.auth_key_len, 20);
        assert_eq!(parsed.salt_key_len, 14);
        assert!(parsed.srtp_encryption);
        assert!(parsed.srtcp_encryption);
        assert!(parsed.srtp_authentication);
        assert_eq!(parsed.auth_tag_len, 10);
    }

    #[test]
    fn test_aes256_policy() {
        let policy = SrtpPolicy::aes_256_default();
        let sp = policy.to_sp_payload(1);
        assert_eq!(sp.policy_no, 1);

        let parsed = SrtpPolicy::from_sp_payload(&sp).unwrap();
        assert_eq!(parsed.enc_key_len, 32);
    }

    #[test]
    fn test_non_srtp_proto_returns_none() {
        let sp = SpPayload {
            next_payload: 0,
            policy_no: 0,
            proto_type: 1, // not SRTP
            params: vec![],
        };
        assert!(SrtpPolicy::from_sp_payload(&sp).is_none());
    }
}
