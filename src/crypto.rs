use hmac::{Hmac, Mac};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::error::{MikeyError, Result};

type HmacSha256 = Hmac<Sha256>;

/// MIKEY PRF (RFC 3830 Section 4.1.2)
/// PRF(key, label) = HMAC-SHA-256(key, label || 0x00 || iter || length)
pub fn mikey_prf(key: &[u8], label: &[u8], output_len: usize) -> Result<Vec<u8>> {
    let mut result = Vec::with_capacity(output_len);
    let iterations = output_len.div_ceil(32); // SHA-256 output = 32 bytes

    for i in 0..iterations {
        let mut mac =
            HmacSha256::new_from_slice(key).map_err(|e| MikeyError::Crypto(e.to_string()))?;

        mac.update(label);
        mac.update(&[0x00]); // separator
        mac.update(&(i as u8).to_be_bytes());
        mac.update(&(output_len as u16).to_be_bytes());

        result.extend_from_slice(&mac.finalize().into_bytes());
    }

    result.truncate(output_len);
    Ok(result)
}

/// Compute HMAC-SHA-256, truncated to 160 bits (20 bytes) per RFC 3830
pub fn compute_mac(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|e| MikeyError::Crypto(e.to_string()))?;
    mac.update(data);
    let result = mac.finalize().into_bytes();
    Ok(result[..20].to_vec())
}

/// Verify HMAC-SHA-256 (truncated to 160 bits)
pub fn verify_mac(key: &[u8], data: &[u8], expected: &[u8]) -> Result<()> {
    let computed = compute_mac(key, data)?;
    if computed != expected {
        return Err(MikeyError::InvalidMac);
    }
    Ok(())
}

/// Ephemeral X25519 Diffie-Hellman key pair.
///
/// This is the **default** key exchange primitive used by [`DhInitiator`] and
/// [`DhResponder`]. Each call to [`generate()`](DhKeyPair::generate) creates a
/// fresh keypair; the secret is consumed on [`diffie_hellman()`](DhKeyPair::diffie_hellman)
/// and cannot be reused, providing forward secrecy.
///
/// For persistent keys with peer pinning (opt-in MITM protection), see
/// [`Identity`](crate::identity::Identity) instead.
///
/// [`DhInitiator`]: crate::message::DhInitiator
/// [`DhResponder`]: crate::message::DhResponder
pub struct DhKeyPair {
    secret: EphemeralSecret,
    pub public: PublicKey,
}

impl DhKeyPair {
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random_from_rng(rand::thread_rng());
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Perform DH exchange, consuming the ephemeral secret. Returns shared secret.
    pub fn diffie_hellman(self, peer_public: &[u8; 32]) -> Vec<u8> {
        let peer = PublicKey::from(*peer_public);
        let shared = self.secret.diffie_hellman(&peer);
        shared.as_bytes().to_vec()
    }
}

/// Derive TGK (TEK Generation Key) from DH shared secret and RAND
/// using the MIKEY PRF
pub fn derive_tgk(shared_secret: &[u8], rand: &[u8], tgk_len: usize) -> Result<Vec<u8>> {
    // s = shared_secret
    // TGK = PRF(s, label="TGK" || RAND, tgk_len)
    let mut label = b"TGK".to_vec();
    label.extend_from_slice(rand);
    mikey_prf(shared_secret, &label, tgk_len)
}

/// Derive auth_key from TGK for MAC computation
pub fn derive_auth_key(tgk: &[u8], rand: &[u8], auth_key_len: usize) -> Result<Vec<u8>> {
    let mut label = b"AUTH".to_vec();
    label.extend_from_slice(rand);
    mikey_prf(tgk, &label, auth_key_len)
}

/// Derive encryption key from TGK for KEMAC payload encryption
pub fn derive_enc_key(tgk: &[u8], rand: &[u8], enc_key_len: usize) -> Result<Vec<u8>> {
    let mut label = b"ENC".to_vec();
    label.extend_from_slice(rand);
    mikey_prf(tgk, &label, enc_key_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prf_deterministic() {
        let key = b"test_key";
        let label = b"test_label";
        let out1 = mikey_prf(key, label, 32).unwrap();
        let out2 = mikey_prf(key, label, 32).unwrap();
        assert_eq!(out1, out2);
        assert_eq!(out1.len(), 32);
    }

    #[test]
    fn test_prf_different_lengths() {
        let key = b"test_key";
        let label = b"test_label";
        let out16 = mikey_prf(key, label, 16).unwrap();
        let out48 = mikey_prf(key, label, 48).unwrap();
        assert_eq!(out16.len(), 16);
        assert_eq!(out48.len(), 48);
    }

    #[test]
    fn test_mac_verify() {
        let key = b"mac_key_for_test";
        let data = b"some data to authenticate";
        let mac = compute_mac(key, data).unwrap();
        assert_eq!(mac.len(), 20);
        verify_mac(key, data, &mac).unwrap();
    }

    #[test]
    fn test_mac_invalid() {
        let key = b"mac_key_for_test";
        let data = b"some data";
        let mut mac = compute_mac(key, data).unwrap();
        mac[0] ^= 0xff;
        assert!(verify_mac(key, data, &mac).is_err());
    }

    #[test]
    fn test_dh_key_exchange() {
        let alice = DhKeyPair::generate();
        let bob = DhKeyPair::generate();

        let alice_pub = *alice.public.as_bytes();
        let bob_pub = *bob.public.as_bytes();

        let shared_a = alice.diffie_hellman(&bob_pub);
        let shared_b = bob.diffie_hellman(&alice_pub);

        assert_eq!(shared_a, shared_b);
        assert_eq!(shared_a.len(), 32);
    }
}
