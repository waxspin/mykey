use crate::crypto::mikey_prf;
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

/// Derive SRTP key material from TGK (TEK Generation Key)
///
/// Per RFC 3830 Section 4.1.3, the TEK is derived from TGK using the PRF.
pub fn derive_srtp_keys(
    tgk: &[u8],
    rand: &[u8],
    cs_id: u8,
    suite: SrtpCryptoSuite,
) -> Result<SrtpKeyMaterial> {
    // TEK = PRF(TGK, label, key_len)
    // label = cs_id || RAND for uniqueness per crypto session
    let mut key_label = vec![cs_id];
    key_label.extend_from_slice(rand);
    key_label.extend_from_slice(b"SRTP_KEY");

    let mut salt_label = vec![cs_id];
    salt_label.extend_from_slice(rand);
    salt_label.extend_from_slice(b"SRTP_SALT");

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

        let keys = derive_srtp_keys(&tgk, &rand, 0, SrtpCryptoSuite::AES_128_CM_SHA1_80).unwrap();

        assert_eq!(keys.master_key.len(), 16);
        assert_eq!(keys.master_salt.len(), 14);
    }

    #[test]
    fn test_derive_srtp_keys_aes256() {
        let tgk = vec![0x42u8; 32];
        let rand = vec![0x13u8; 16];

        let keys = derive_srtp_keys(&tgk, &rand, 0, SrtpCryptoSuite::AES_256_CM_SHA1_80).unwrap();

        assert_eq!(keys.master_key.len(), 32);
        assert_eq!(keys.master_salt.len(), 14);
    }

    #[test]
    fn test_different_cs_id_gives_different_keys() {
        let tgk = vec![0x42u8; 32];
        let rand = vec![0x13u8; 16];

        let keys0 = derive_srtp_keys(&tgk, &rand, 0, SrtpCryptoSuite::AES_128_CM_SHA1_80).unwrap();
        let keys1 = derive_srtp_keys(&tgk, &rand, 1, SrtpCryptoSuite::AES_128_CM_SHA1_80).unwrap();

        assert_ne!(keys0.master_key, keys1.master_key);
        assert_ne!(keys0.master_salt, keys1.master_salt);
    }
}
