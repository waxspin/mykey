# Security Policy

A Security Policy (SP) payload carries SRTP cipher and authentication parameters alongside the key exchange. When included in a MIKEY message, it tells the peer exactly which algorithms to use for the SRTP session.

SP is optional — if omitted, both sides must agree on the cipher suite through some other means (e.g., out-of-band configuration or SDP negotiation). Including SP in the message makes the exchange self-contained.

## Attaching SP to a DH-Init

```rust
use mykey::{DhInitiator, SrtpPolicy};

let initiator = DhInitiator::new(csc_id, ssrc);
let sp = SrtpPolicy::aes_128_default().to_sp_payload(0);
let init_msg = initiator.init_message_with_sp(sp)?;
```

The `policy_no` argument to `to_sp_payload()` links the SP to a specific crypto session. Use `0` unless you are managing multiple crypto sessions within a single CSB.

## Reading SP from a parsed message

```rust
use mykey::policy::SrtpPolicy;

let parsed = MikeyMessage::from_bytes(&wire_bytes)?;

if let Some(sp) = parsed.security_policy() {
    let policy = SrtpPolicy::from_sp_payload(sp).unwrap();
    println!("enc_alg:      {:?}", policy.enc_alg);
    println!("enc_key_len:  {} bytes", policy.enc_key_len);
    println!("auth_alg:     {:?}", policy.auth_alg);
    println!("auth_key_len: {} bytes", policy.auth_key_len);
    println!("auth_tag_len: {} bytes", policy.auth_tag_len);
    println!("srtp_prefix:  {} bytes", policy.srtp_prefix_len);
}
```

## Built-in presets

```rust
use mykey::policy::SrtpPolicy;

// AES-128-CM + HMAC-SHA1-80 — matches AES67 default profile
let policy = SrtpPolicy::aes_128_default();

// AES-256-CM + HMAC-SHA1-80 — for compliance requirements
let policy = SrtpPolicy::aes_256_default();
```

Both presets set `srtp_on = true`, `srtcp_on = false`, `fec_order = FEC_SRTP`, and `replay_window_size = 64`.

## Custom policy

Build a policy by setting fields directly:

```rust
use mykey::policy::{SrtpPolicy, SrtpEncAlg, SrtpAuthAlg};

let policy = SrtpPolicy {
    enc_alg: SrtpEncAlg::AesCm,
    enc_key_len: 32,         // AES-256
    auth_alg: SrtpAuthAlg::HmacSha1,
    auth_key_len: 20,
    auth_tag_len: 10,        // 80-bit tag
    srtp_prefix_len: 0,
    srtp_on: true,
    srtcp_on: false,
    fec_order: 0,
    replay_window_size: 64,
    ..Default::default()
};

let sp = policy.to_sp_payload(0);
```

## Wire encoding

SP parameters are TLV-encoded (type 1 byte, length 1 byte, value). SRTP parameter types follow RFC 3830 §6.10.1:

| Type | Name | Bytes | Preset value (AES-128) |
|---|---|---|---|
| 0 | Encryption algorithm | 1 | `1` (AES-CM) |
| 1 | Session encryption key length | 1 | `16` |
| 2 | Authentication algorithm | 1 | `1` (HMAC-SHA-1) |
| 3 | Session authentication key length | 1 | `20` |
| 4 | Session salt key length | 1 | `14` |
| 5 | SRTP pseudo-random function | 1 | `0` (AES-CM) |
| 6 | Key derivation rate | 1 | `0` |
| 7 | SRTP enabled | 1 | `1` |
| 8 | SRTCP enabled | 1 | `0` |
| 9 | FEC order | 1 | `0` |
| 10 | SRTP auth tag length | 1 | `10` |
| 11 | SRTP prefix length | 1 | `0` |
| 12 | Replay window size | 2 | `64` |

A full 9-parameter SP payload adds approximately 21 bytes to the message (3-byte header + 9 params × 2 bytes each, plus the 2-byte replay window param).
