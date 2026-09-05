use crate::crypto::{label_from_tgk, mikey_prf, CONST_SALT_FROM_TGK, CONST_TEK};
use crate::error::Result;

/// SRTP key material derived from a MIKEY exchange
#[derive(Debug, Clone)]
pub struct SrtpKeyMaterial {
    /// SRTP master key (typically 16 bytes for AES-128)
    pub master_key: Vec<u8>,
    /// SRTP master salt (typically 14 bytes)
    pub master_salt: Vec<u8>,
}

/// SRTP crypto suite parameters
#[derive(Debug, Clone, Copy)]
pub struct SrtpCryptoSuite {
    /// Length of the SRTP master key in bytes (16 for AES-128, 32 for AES-256).
    pub master_key_len: usize,
    /// Length of the SRTP master salt in bytes (14 for AES-CM profiles).
    pub master_salt_len: usize,
}

impl SrtpCryptoSuite {
    /// AES-128-CM with HMAC-SHA1-80 (most common for AES67)
    pub const AES_128_CM_SHA1_80: Self = Self {
        master_key_len: 16,
        master_salt_len: 14,
    };

    /// AES-256-CM with HMAC-SHA1-80
    pub const AES_256_CM_SHA1_80: Self = Self {
        master_key_len: 32,
        master_salt_len: 14,
    };
}

/// Derive SRTP key material from a TGK (TEK Generation Key), per RFC 3830 §4.1.3.
///
/// The SRTP master key is the TEK (constant `0x2AD01C64`) and the master salt is
/// the salting key (constant `0x39A2C14B`), each derived with the label
/// `constant || cs_id || csb_id || RAND`.
///
/// `csb_id` is the Crypto Session Bundle ID from the MIKEY common header, and
/// `cs_id` identifies the crypto session within that bundle.
pub fn derive_srtp_keys(
    tgk: &[u8],
    rand: &[u8],
    cs_id: u8,
    csb_id: u32,
    suite: SrtpCryptoSuite,
) -> Result<SrtpKeyMaterial> {
    let key_label = label_from_tgk(CONST_TEK, cs_id, csb_id, rand);
    let salt_label = label_from_tgk(CONST_SALT_FROM_TGK, cs_id, csb_id, rand);

    let master_key = mikey_prf(tgk, &key_label, suite.master_key_len)?;
    let master_salt = mikey_prf(tgk, &salt_label, suite.master_salt_len)?;

    Ok(SrtpKeyMaterial {
        master_key,
        master_salt,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_srtp_keys_aes128() {
        let tgk = vec![0x42u8; 32];
        let rand = vec![0x13u8; 16];

        let keys =
            derive_srtp_keys(&tgk, &rand, 0, 1, SrtpCryptoSuite::AES_128_CM_SHA1_80).unwrap();

        assert_eq!(keys.master_key.len(), 16);
        assert_eq!(keys.master_salt.len(), 14);
    }

    #[test]
    fn test_derive_srtp_keys_aes256() {
        let tgk = vec![0x42u8; 32];
        let rand = vec![0x13u8; 16];

        let keys =
            derive_srtp_keys(&tgk, &rand, 0, 1, SrtpCryptoSuite::AES_256_CM_SHA1_80).unwrap();

        assert_eq!(keys.master_key.len(), 32);
        assert_eq!(keys.master_salt.len(), 14);
    }

    #[test]
    fn test_master_key_and_salt_differ() {
        let tgk = vec![0x42u8; 32];
        let rand = vec![0x13u8; 16];

        let keys =
            derive_srtp_keys(&tgk, &rand, 0, 1, SrtpCryptoSuite::AES_256_CM_SHA1_80).unwrap();

        // Distinct RFC constants (TEK vs salting key) must give unrelated output.
        assert_ne!(keys.master_key[..14], keys.master_salt[..]);
    }

    #[test]
    fn test_different_cs_id_gives_different_keys() {
        let tgk = vec![0x42u8; 32];
        let rand = vec![0x13u8; 16];

        let keys0 =
            derive_srtp_keys(&tgk, &rand, 0, 1, SrtpCryptoSuite::AES_128_CM_SHA1_80).unwrap();
        let keys1 =
            derive_srtp_keys(&tgk, &rand, 1, 1, SrtpCryptoSuite::AES_128_CM_SHA1_80).unwrap();

        assert_ne!(keys0.master_key, keys1.master_key);
        assert_ne!(keys0.master_salt, keys1.master_salt);
    }

    #[test]
    fn test_different_csb_id_gives_different_keys() {
        let tgk = vec![0x42u8; 32];
        let rand = vec![0x13u8; 16];

        let keys0 =
            derive_srtp_keys(&tgk, &rand, 0, 1, SrtpCryptoSuite::AES_128_CM_SHA1_80).unwrap();
        let keys1 =
            derive_srtp_keys(&tgk, &rand, 0, 2, SrtpCryptoSuite::AES_128_CM_SHA1_80).unwrap();

        assert_ne!(keys0.master_key, keys1.master_key);
        assert_ne!(keys0.master_salt, keys1.master_salt);
    }
}
