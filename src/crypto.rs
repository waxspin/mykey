#![allow(missing_docs)]

use hmac::{Hmac, Mac};
use sha1::Sha1;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::error::{MikeyError, Result};

type HmacSha1 = Hmac<Sha1>;

/// SHA-1 output size in bytes (160 bits) — the PRF's output block size.
const SHA1_OUT_LEN: usize = 20;

/// PRF input-key block size in bytes (256 bits), per RFC 3830 §4.1.2.
const PRF_BLOCK_LEN: usize = 32;

/// The P-function of RFC 3830 §4.1.2, defined similarly to TLS:
///
/// ```text
/// P(s, label, m) = HMAC(s, A_1 || label) || HMAC(s, A_2 || label) || ...
///                                        || HMAC(s, A_m || label)
///     where A_0 = label,  A_i = HMAC(s, A_(i-1))
/// ```
///
/// Note the feedback: each `A_i` is the HMAC of the *previous* `A`, so blocks
/// cannot be computed independently.
fn p_func(s: &[u8], label: &[u8], m: usize) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(m * SHA1_OUT_LEN);
    let mut a = label.to_vec(); // A_0 = label

    for _ in 0..m {
        a = compute_mac(s, &a)?; // A_i = HMAC(s, A_(i-1))

        let mut block = a.clone();
        block.extend_from_slice(label);
        out.extend_from_slice(&compute_mac(s, &block)?); // HMAC(s, A_i || label)
    }

    Ok(out)
}

/// MIKEY-1 default PRF (RFC 3830 §4.1.2).
///
/// The input key is split into 256-bit blocks `inkey = s_1 || ... || s_n`; the
/// output is the `outkey_len` most significant bytes of
///
/// ```text
/// PRF(inkey, label) = P(s_1, label, m) XOR ... XOR P(s_n, label, m)
/// ```
///
/// where `m = outkey_len / 160 bits`, rounded up.
///
/// # Errors
///
/// Returns [`MikeyError::Crypto`] if `inkey` is empty. An empty input key would
/// otherwise produce no `P` terms at all and silently return an all-zero key.
pub fn mikey_prf(inkey: &[u8], label: &[u8], outkey_len: usize) -> Result<Vec<u8>> {
    if inkey.is_empty() {
        return Err(MikeyError::Crypto("PRF input key is empty".into()));
    }

    let m = outkey_len.div_ceil(SHA1_OUT_LEN);
    let mut outkey = vec![0u8; m * SHA1_OUT_LEN];

    for s in inkey.chunks(PRF_BLOCK_LEN) {
        for (acc, byte) in outkey.iter_mut().zip(p_func(s, label, m)?) {
            *acc ^= byte;
        }
    }

    outkey.truncate(outkey_len);
    Ok(outkey)
}

/// Compute HMAC-SHA-1-160 (20 bytes) per RFC 3830 Section 6.2
pub fn compute_mac(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let mut mac = HmacSha1::new_from_slice(key).map_err(|e| MikeyError::Crypto(e.to_string()))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Verify HMAC-SHA-1-160 per RFC 3830 Section 6.2.
///
/// Uses constant-time comparison to avoid leaking byte-position information
/// about a forged MAC via response timing.
pub fn verify_mac(key: &[u8], data: &[u8], expected: &[u8]) -> Result<()> {
    let mut mac = HmacSha1::new_from_slice(key).map_err(|e| MikeyError::Crypto(e.to_string()))?;
    mac.update(data);
    mac.verify_slice(expected)
        .map_err(|_| MikeyError::InvalidMac)
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
        let secret = EphemeralSecret::random_from_rng(rand_core::OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Perform the DH exchange, consuming the ephemeral secret.
    ///
    /// # Errors
    ///
    /// Returns [`MikeyError::InvalidDhValue`] if the peer's public key has small
    /// order. RFC 7748 §7 notes that such a value "will eliminate any
    /// contribution from the other party's private key", producing an all-zero
    /// shared secret that the peer can predict. Checking is optional in
    /// RFC 7748 §6.1; mykey rejects it.
    pub fn diffie_hellman(self, peer_public: &[u8; 32]) -> Result<Vec<u8>> {
        let peer = PublicKey::from(*peer_public);
        let shared = self.secret.diffie_hellman(&peer);
        if !shared.was_contributory() {
            return Err(MikeyError::InvalidDhValue);
        }
        Ok(shared.as_bytes().to_vec())
    }
}

// ── Key-derivation label constants ───────────────────────────────────────────
//
// The 32-bit constants below are taken from consecutive nine-digit chunks of the
// decimal expansion of e, as specified by RFC 3830 (e.g. 718281828 = 0x2AD01C64).

/// Constant for deriving a TEK from a TGK (RFC 3830 §4.1.3).
pub const CONST_TEK: u32 = 0x2AD0_1C64;
/// Constant for deriving an authentication key from a TGK (RFC 3830 §4.1.3).
pub const CONST_AUTH_FROM_TGK: u32 = 0x1B5C_7973;
/// Constant for deriving an encryption key from a TGK (RFC 3830 §4.1.3).
pub const CONST_ENC_FROM_TGK: u32 = 0x1579_8CEF;
/// Constant for deriving a salting key from a TGK (RFC 3830 §4.1.3).
pub const CONST_SALT_FROM_TGK: u32 = 0x39A2_C14B;

/// Constant for deriving an encryption key from an envelope/pre-shared key
/// (RFC 3830 §4.1.4).
pub const CONST_ENC_FROM_PSK: u32 = 0x1505_33E1;
/// Constant for deriving an authentication key from an envelope/pre-shared key
/// (RFC 3830 §4.1.4).
pub const CONST_AUTH_FROM_PSK: u32 = 0x2D22_AC75;
/// Constant for deriving a salt key from an envelope/pre-shared key
/// (RFC 3830 §4.1.4).
pub const CONST_SALT_FROM_PSK: u32 = 0x29B8_8916;

/// Build the PRF label for a key derived from a TGK (RFC 3830 §4.1.3):
/// `constant || cs_id || csb_id || RAND`.
pub fn label_from_tgk(constant: u32, cs_id: u8, csb_id: u32, rand: &[u8]) -> Vec<u8> {
    let mut label = Vec::with_capacity(9 + rand.len());
    label.extend_from_slice(&constant.to_be_bytes());
    label.push(cs_id);
    label.extend_from_slice(&csb_id.to_be_bytes());
    label.extend_from_slice(rand);
    label
}

/// Build the PRF label for a key derived from an envelope or pre-shared key
/// (RFC 3830 §4.1.4): `constant || 0xFF || csb_id || RAND`.
///
/// The `0xFF` sits in the `cs_id` position: these keys protect the MIKEY message
/// itself, so unlike TGK-derived keys they are not bound to a single crypto
/// session.
pub fn label_from_psk(constant: u32, csb_id: u32, rand: &[u8]) -> Vec<u8> {
    label_from_tgk(constant, 0xFF, csb_id, rand)
}

/// PRF label prefix for the X25519 TGK derivation.
///
/// Deliberately not an RFC constant: this derivation has no RFC counterpart, and
/// a descriptive ASCII label makes that visible at a glance.
const X25519_TGK_LABEL: &[u8] = b"MIKEY-X25519-TGK";

/// Derive a TGK (TEK Generation Key) from an X25519 exchange.
///
/// ```text
/// TGK = PRF(K, "MIKEY-X25519-TGK" || K_initiator || K_responder || RAND)
/// ```
///
/// **This is a deliberate deviation from RFC 3830**, which has no such step — in
/// the DH method the TGK *is* the raw DH result `g^(xi*xr)` (§3.3). But §3.3 was
/// written for MODP groups, and applying it literally to X25519 would mean using
/// a raw curve point as key material, which
/// [RFC 7748](https://datatracker.ietf.org/doc/rfc7748/) §6.1 advises against:
/// "Alice and Bob can then use a key-derivation function that includes K, K_A,
/// and K_B to derive a symmetric key." Since no elliptic-curve group is
/// registered for MIKEY, there is no conformant X25519 mode to conform to.
///
/// Both public keys are bound in, as §6.1 asks. §7 explains why it matters:
/// equivalent public keys produce identical shared secrets, so "using a public
/// key as an identifier and knowledge of a shared secret as proof of ownership
/// (without including the public keys in the key derivation) might lead to
/// subtle vulnerabilities" — and [`PinnedPeer`](crate::identity::PinnedPeer)
/// uses public keys as identifiers.
///
/// The keys are ordered by **protocol role**, not by who is calling, so both
/// sides compute the same label: MIKEY names an initiator and a responder, and
/// each party knows which it is.
///
/// See the "Deviations from RFC 3830" chapter of the book.
pub fn derive_tgk_x25519(
    shared_secret: &[u8],
    initiator_public: &[u8; 32],
    responder_public: &[u8; 32],
    rand: &[u8],
    tgk_len: usize,
) -> Result<Vec<u8>> {
    let mut label = X25519_TGK_LABEL.to_vec();
    label.extend_from_slice(initiator_public);
    label.extend_from_slice(responder_public);
    label.extend_from_slice(rand);
    mikey_prf(shared_secret, &label, tgk_len)
}

/// Derive a TGK from a raw input key and RAND, without binding any public keys.
///
/// Retained for callers that have no DH public keys to bind — notably tests and
/// any non-X25519 input. For an X25519 exchange use
/// [`derive_tgk_x25519`], which binds both peers' public keys per RFC 7748 §6.1.
pub fn derive_tgk(inkey: &[u8], rand: &[u8], tgk_len: usize) -> Result<Vec<u8>> {
    // TGK = PRF(inkey, "TGK" || RAND, tgk_len)
    let mut label = b"TGK".to_vec();
    label.extend_from_slice(rand);
    mikey_prf(inkey, &label, tgk_len)
}

/// Derive the MIKEY message authentication key from an envelope or pre-shared
/// key, per RFC 3830 §4.1.4.
pub fn derive_auth_key(
    psk: &[u8],
    csb_id: u32,
    rand: &[u8],
    auth_key_len: usize,
) -> Result<Vec<u8>> {
    let label = label_from_psk(CONST_AUTH_FROM_PSK, csb_id, rand);
    mikey_prf(psk, &label, auth_key_len)
}

/// Derive the KEMAC payload encryption key from an envelope or pre-shared key,
/// per RFC 3830 §4.1.4.
pub fn derive_enc_key(psk: &[u8], csb_id: u32, rand: &[u8], enc_key_len: usize) -> Result<Vec<u8>> {
    let label = label_from_psk(CONST_ENC_FROM_PSK, csb_id, rand);
    mikey_prf(psk, &label, enc_key_len)
}

/// Derive the KEMAC salting key from an envelope or pre-shared key, per
/// RFC 3830 §4.1.4.
///
/// §4.2.3 uses a 112-bit (14-byte) salt, which is [`KEMAC_SALT_LEN`].
pub fn derive_salt_key(
    psk: &[u8],
    csb_id: u32,
    rand: &[u8],
    salt_key_len: usize,
) -> Result<Vec<u8>> {
    let label = label_from_psk(CONST_SALT_FROM_PSK, csb_id, rand);
    mikey_prf(psk, &label, salt_key_len)
}

/// Key length for AES-CM key wrapping of the KEMAC payload (RFC 3830 §4.2.3).
pub const KEMAC_ENC_KEY_LEN: usize = 16;

/// Salt length for AES-CM key wrapping of the KEMAC payload — 112 bits.
pub const KEMAC_SALT_LEN: usize = 14;

/// Build the AES-CM initialisation vector for KEMAC key transport, per
/// RFC 3830 §4.2.3:
///
/// ```text
/// IV = (S XOR (0x0000 || CSB ID || T)) || 0x0000
/// ```
///
/// `S` is the 112-bit salting key from [`derive_salt_key`] and `T` is the 64-bit
/// timestamp sent by the initiator. A shorter timestamp — a 32-bit COUNTER — is
/// left-padded with zeros to 64 bits, following the same convention §6.6 gives
/// for COUNTER as PRF input.
pub fn kemac_iv(salt: &[u8], csb_id: u32, timestamp: &[u8]) -> Result<[u8; 16]> {
    if salt.len() != KEMAC_SALT_LEN {
        return Err(MikeyError::Crypto(format!(
            "KEMAC salt must be {KEMAC_SALT_LEN} bytes, got {}",
            salt.len()
        )));
    }
    if timestamp.len() > 8 {
        return Err(MikeyError::Crypto(format!(
            "timestamp must be at most 8 bytes, got {}",
            timestamp.len()
        )));
    }

    // 0x0000 || CSB ID || T, with T right-aligned in its 8 bytes.
    let mut block = [0u8; KEMAC_SALT_LEN];
    block[2..6].copy_from_slice(&csb_id.to_be_bytes());
    block[KEMAC_SALT_LEN - timestamp.len()..].copy_from_slice(timestamp);

    let mut iv = [0u8; 16];
    for i in 0..KEMAC_SALT_LEN {
        iv[i] = salt[i] ^ block[i];
    }
    // Trailing 0x0000 is already zero from initialisation.
    Ok(iv)
}

/// Apply AES-128 in counter mode to `data` in place (RFC 3830 §4.2.3).
///
/// CTR is its own inverse, so this both encrypts and decrypts.
pub fn aes_cm_apply(key: &[u8], iv: &[u8; 16], data: &mut [u8]) -> Result<()> {
    use ctr::cipher::{KeyIvInit, StreamCipher};
    type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;

    if key.len() != KEMAC_ENC_KEY_LEN {
        return Err(MikeyError::Crypto(format!(
            "AES-CM key must be {KEMAC_ENC_KEY_LEN} bytes, got {}",
            key.len()
        )));
    }

    let mut cipher = Aes128Ctr::new_from_slices(key, iv)
        .map_err(|e| MikeyError::Crypto(format!("AES-CM init: {e}")))?;
    cipher.apply_keystream(data);
    Ok(())
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

    /// Independent reimplementation of the RFC 3830 §4.1.2 P-function, written
    /// straight from the RFC text rather than from `p_func`, so that the two
    /// cannot drift into agreement by sharing a bug.
    fn reference_p(s: &[u8], label: &[u8], m: usize) -> Vec<u8> {
        let hmac = |key: &[u8], data: &[u8]| -> Vec<u8> {
            let mut mac = HmacSha1::new_from_slice(key).unwrap();
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        };

        let mut out = Vec::new();
        let mut a = label.to_vec();
        for _ in 0..m {
            a = hmac(s, &a);
            let mut input = a.clone();
            input.extend_from_slice(label);
            out.extend_from_slice(&hmac(s, &input));
        }
        out
    }

    /// Locks in the feedback construction of RFC 3830 §4.1.2 for a single-block
    /// input key. Regression test for the counter-mode PRF (issue #22), which
    /// computed `HMAC(key, label || 0x00 || i || len)` per block instead.
    #[test]
    fn test_prf_matches_rfc_p_function() {
        let key = [0x0bu8; 20]; // < 32 bytes, so exactly one s_i block
        let label = b"prf-test";

        for &outkey_len in &[16usize, 20, 48] {
            let mut expected = reference_p(&key, label, outkey_len.div_ceil(20));
            expected.truncate(outkey_len);

            assert_eq!(mikey_prf(&key, label, outkey_len).unwrap(), expected);
        }
    }

    /// Locks in the input-key splitting and XOR combination: an input key longer
    /// than 256 bits must be split into `s_1 || s_2` and the two P-function
    /// outputs XORed together.
    #[test]
    fn test_prf_splits_and_xors_long_inkey() {
        let mut key = vec![0xA5u8; 32];
        key.extend_from_slice(&[0x5Au8; 12]); // 44 bytes => two blocks
        let label = b"split-test";
        let outkey_len = 20usize;

        let p1 = reference_p(&key[..32], label, 1);
        let p2 = reference_p(&key[32..], label, 1);
        let expected: Vec<u8> = p1.iter().zip(&p2).map(|(a, b)| a ^ b).collect();

        assert_eq!(mikey_prf(&key, label, outkey_len).unwrap(), expected);

        // The XOR must actually mix in the second block.
        let mut truncated = mikey_prf(&key[..32], label, outkey_len).unwrap();
        truncated.truncate(outkey_len);
        assert_ne!(mikey_prf(&key, label, outkey_len).unwrap(), truncated);
    }

    /// An empty input key would produce no P terms and silently yield an
    /// all-zero output key; it must be rejected instead.
    #[test]
    fn test_prf_rejects_empty_inkey() {
        assert!(mikey_prf(&[], b"label", 16).is_err());
    }

    /// The old counter-mode PRF repeated its keystream every 256 blocks because
    /// the block counter was truncated to `u8`. The feedback construction has no
    /// counter, so long outputs must not repeat.
    #[test]
    fn test_prf_long_output_does_not_repeat() {
        let out = mikey_prf(b"k", b"L", 5140).unwrap();
        assert_ne!(&out[0..20], &out[5120..5140]);
    }

    /// Locks in the RFC 3830 §4.1.3 label layout: `constant || cs_id || csb_id || RAND`.
    #[test]
    fn test_label_from_tgk_layout() {
        let label = label_from_tgk(CONST_TEK, 0x07, 0xDEAD_BEEF, &[0x11, 0x22]);
        assert_eq!(
            label,
            vec![0x2A, 0xD0, 0x1C, 0x64, 0x07, 0xDE, 0xAD, 0xBE, 0xEF, 0x11, 0x22]
        );
    }

    /// Locks in the RFC 3830 §4.1.4 label layout: `constant || 0xFF || csb_id || RAND`.
    #[test]
    fn test_label_from_psk_layout() {
        let label = label_from_psk(CONST_AUTH_FROM_PSK, 0x0000_0001, &[0x33]);
        assert_eq!(
            label,
            vec![0x2D, 0x22, 0xAC, 0x75, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x33]
        );
    }

    /// The constants are the decimal digits of e, in nine-digit chunks.
    #[test]
    fn test_label_constants_match_rfc_tables() {
        assert_eq!(CONST_TEK, 718_281_828);
        assert_eq!(CONST_AUTH_FROM_TGK, 0x1B5C_7973);
        assert_eq!(CONST_ENC_FROM_TGK, 0x1579_8CEF);
        assert_eq!(CONST_SALT_FROM_TGK, 0x39A2_C14B);
        assert_eq!(CONST_ENC_FROM_PSK, 0x1505_33E1);
        assert_eq!(CONST_AUTH_FROM_PSK, 0x2D22_AC75);
        assert_eq!(CONST_SALT_FROM_PSK, 0x29B8_8916);
    }

    /// Distinct key types must not collide, and both `cs_id` and `csb_id` must
    /// actually reach the derived key.
    #[test]
    fn test_derived_keys_are_domain_separated() {
        let psk = b"pre-shared-key";
        let rand = [0x42u8; 16];

        let auth = derive_auth_key(psk, 1, &rand, 32).unwrap();
        let enc = derive_enc_key(psk, 1, &rand, 32).unwrap();
        assert_ne!(auth, enc, "auth and enc keys must differ");

        assert_ne!(
            auth,
            derive_auth_key(psk, 2, &rand, 32).unwrap(),
            "csb_id must be bound into the key"
        );

        let tgk = [0x99u8; 32];
        assert_ne!(
            mikey_prf(&tgk, &label_from_tgk(CONST_TEK, 0, 1, &rand), 16).unwrap(),
            mikey_prf(&tgk, &label_from_tgk(CONST_TEK, 1, 1, &rand), 16).unwrap(),
            "cs_id must be bound into the key"
        );
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
    fn test_mac_wrong_length_rejected() {
        let key = b"mac_key_for_test";
        let data = b"some data";
        let mac = compute_mac(key, data).unwrap();
        // Truncate to 19 bytes — must be rejected, not silently accepted.
        assert!(verify_mac(key, data, &mac[..19]).is_err());
        // Append a byte — must also be rejected.
        let mut too_long = mac.clone();
        too_long.push(0x00);
        assert!(verify_mac(key, data, &too_long).is_err());
    }

    /// RFC 2202 test case 1: locks in HMAC-SHA-1 (not truncated HMAC-SHA-256).
    /// Regression test for the bug where compute_mac used HMAC-SHA-256 truncated
    /// to 160 bits, which is non-compliant with RFC 3830 §6.2 (MAC alg = 1 →
    /// HMAC-SHA-1-160).
    #[test]
    fn test_mac_is_hmac_sha1_kat() {
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let expected = hex::decode("b617318655057264e28bc0b6fb378c8ef146be00").unwrap();
        let mac = compute_mac(&key, data).unwrap();
        assert_eq!(mac, expected);
        verify_mac(&key, data, &expected).unwrap();
    }

    #[test]
    fn test_dh_key_exchange() {
        let alice = DhKeyPair::generate();
        let bob = DhKeyPair::generate();

        let alice_pub = *alice.public.as_bytes();
        let bob_pub = *bob.public.as_bytes();

        let shared_a = alice.diffie_hellman(&bob_pub).unwrap();
        let shared_b = bob.diffie_hellman(&alice_pub).unwrap();

        assert_eq!(shared_a, shared_b);
        assert_eq!(shared_a.len(), 32);
    }

    // ── RFC 7748 hardening ──────────────────────────────────────────────────

    /// X25519 points of small order. Each drives the shared secret to all-zero,
    /// eliminating the local party's contribution (RFC 7748 §7), so every one
    /// must be refused.
    ///
    /// Each entry was confirmed non-contributory against this build of
    /// `x25519-dalek` rather than copied from a blacklist — several values that
    /// appear in published blacklists are non-canonical encodings above `p`
    /// which reduce to valid points, and are *not* small order.
    const SMALL_ORDER_POINTS: &[&str] = &[
        // order 1: the identity
        "0000000000000000000000000000000000000000000000000000000000000000",
        // order 1
        "0100000000000000000000000000000000000000000000000000000000000000",
        // order 8
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        // order 4
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        // p - 1
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        // p
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        // p + 1
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        // order 8, high bit set — masked off, so equivalent to the entry above
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880",
        // order 4, high bit set
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7",
    ];

    #[test]
    fn test_small_order_peer_keys_rejected() {
        for point in SMALL_ORDER_POINTS {
            let bytes: [u8; 32] = hex::decode(point).unwrap().try_into().unwrap();
            let kp = DhKeyPair::generate();
            match kp.diffie_hellman(&bytes) {
                Err(MikeyError::InvalidDhValue) => {}
                other => panic!("small-order point {point} must be rejected, got {other:?}"),
            }
        }
    }

    /// The same check must guard the persistent-identity path, which has its own
    /// `diffie_hellman` over a `StaticSecret`.
    #[test]
    fn test_small_order_rejected_for_identity_too() {
        use crate::identity::Identity;
        let id = Identity::generate();
        for point in SMALL_ORDER_POINTS {
            let bytes: [u8; 32] = hex::decode(point).unwrap().try_into().unwrap();
            assert!(
                id.diffie_hellman(&bytes).is_err(),
                "identity must reject small-order point {point}"
            );
        }
    }

    #[test]
    fn test_honest_peer_key_accepted() {
        // The contributory check must not reject legitimate exchanges.
        for _ in 0..16 {
            let a = DhKeyPair::generate();
            let b = DhKeyPair::generate();
            let b_pub = *b.public.as_bytes();
            assert!(a.diffie_hellman(&b_pub).is_ok());
        }
    }

    #[test]
    fn test_tgk_binds_both_public_keys() {
        // RFC 7748 §6.1 asks for a KDF over K, K_A and K_B. Changing either
        // bound key must change the derived TGK, even with K and RAND fixed.
        let shared = [0x42u8; 32];
        let rand = [0x13u8; 16];
        let k_a = [0x01u8; 32];
        let k_b = [0x02u8; 32];

        let base = derive_tgk_x25519(&shared, &k_a, &k_b, &rand, 32).unwrap();

        let other_a = derive_tgk_x25519(&shared, &[0x03u8; 32], &k_b, &rand, 32).unwrap();
        let other_b = derive_tgk_x25519(&shared, &k_a, &[0x04u8; 32], &rand, 32).unwrap();
        assert_ne!(base, other_a, "initiator key must be bound in");
        assert_ne!(base, other_b, "responder key must be bound in");

        // Order matters: swapping the roles must not collide, or the binding
        // would not distinguish initiator from responder.
        let swapped = derive_tgk_x25519(&shared, &k_b, &k_a, &rand, 32).unwrap();
        assert_ne!(base, swapped, "role ordering must be significant");
    }

    #[test]
    fn test_tgk_x25519_differs_from_unbound_derivation() {
        // Regression guard: the bound derivation must not coincide with the
        // old unbound `derive_tgk`.
        let shared = [0x42u8; 32];
        let rand = [0x13u8; 16];
        assert_ne!(
            derive_tgk_x25519(&shared, &[0x01u8; 32], &[0x02u8; 32], &rand, 32).unwrap(),
            derive_tgk(&shared, &rand, 32).unwrap()
        );
    }
}
