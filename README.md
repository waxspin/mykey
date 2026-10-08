![Status: Experimental](https://img.shields.io/badge/status-experimental-orange)
![CI](https://github.com/waxspin/mykey/actions/workflows/ci.yml/badge.svg)

# mykey

> **Warning:** This crate is unaudited and experimental. It has not been professionally reviewed for security vulnerabilities, timing attacks, or logical flaws. Do not use it in production environments or to protect sensitive data.

A Rust implementation of **MIKEY** (Multimedia Internet KEYing, [RFC 3830](https://datatracker.ietf.org/doc/rfc3830/)) for SRTP key exchange in AES67 and SMPTE ST 2110 environments.

**[Documentation & Book](https://waxspin.github.io/mykey)**

## Features

- Ephemeral Diffie-Hellman key exchange (X25519) — **default**
- Pre-shared key (PSK) mode with RFC 3830 §3.1 key transport — the TGK is randomly generated and AES-CM encrypted, and the message MAC is verified before decryption
- Optional verification messages (RFC 3830 §6.9) for mutual authentication
- SRTP key material derivation
- Security policy payload (RFC 3830 §6.10.1 — all SRTP parameters)
- SAP integration with `a=key-mgmt:mikey` SDP attribute (RFC 4567)
- Message parsing and serialization (wire format)
- Optional persistent identity keypairs with peer key pinning (MITM protection)

## Interoperability

mykey is not a complete MIKEY implementation.

**PSK mode** — the only method RFC 3830 makes mandatory to implement — follows the spec for key transport (§3.1), key wrapping (§4.2.3), key data framing (§6.13), MAC computation (§5.2) and verification messages (§6.9). Two gaps remain: the timestamp is the optional COUNTER type rather than a mandatory NTP type, and there is no replay protection.

**DH mode** will not interoperate. It uses X25519 on a private-use DH-Group rather than an OAKLEY group, and omits the SIGN payload the RFC requires. This is deliberate — see the chapter below.

Every known departure is catalogued in **[Deviations from RFC 3830](https://waxspin.github.io/mykey/concepts/rfc-deviations.html)** — read it before assuming a mykey exchange will interoperate with another MIKEY stack.

## Add to your project

```toml
[dependencies]
mykey = "1.0.0"
```

or to get whatever the latest in Crates.io is, just type:

```bash
cargo add mykey
```


## Quick start

### Ephemeral DH key exchange

```rust
use mykey::{DhInitiator, DhResponder, srtp::SrtpCryptoSuite};

let suite = SrtpCryptoSuite::AES_128_CM_SHA1_80;

// --- Initiator side ---
let initiator = DhInitiator::new(csc_id, ssrc);
let init_msg = initiator.init_message()?;

// Send init_msg.to_bytes() to the responder over the network / SDP

// --- Responder side ---
let responder = DhResponder::new();
let resp_msg = responder.resp_message(csc_id)?;

// Send resp_msg.to_bytes() back to the initiator

// Both sides derive the same SRTP keys
let keys = initiator.complete(&resp_msg, suite)?;
```

### PSK mode

```rust
use mykey::message::MikeyMessage;

let psk = b"shared-secret-key";
let rand_bytes = [0x42u8; 16]; // use rand::rng() in practice
let msg = MikeyMessage::new_psk_init(csc_id, ssrc, &rand_bytes, psk)?;
```

### SAP / SDP integration

```rust
use mykey::{DhInitiator, sap::{build_sap_with_mikey, mikey_to_sdp_attribute}};

let initiator = DhInitiator::new(1, 0xDEADBEEF);
let msg = initiator.init_message()?;

// RFC 4567: a=key-mgmt:mikey <base64>
let sdp_line = mikey_to_sdp_attribute(&msg);

// Or wrap in a full SAP packet (origin is the announcer's IPv4 address)
let sap = build_sap_with_mikey([192, 168, 1, 10], 0x1234, &sdp_body, &msg);
```

### Peer key pinning (opt-in MITM protection)

```rust
use std::path::Path;
use mykey::identity::{Identity, PinnedPeer};

// Generate or load a persistent keypair
let my_id = Identity::load_or_generate(Path::new("/etc/mykey"))?;

// Load a peer's public key distributed out-of-band (rsync, scp, etc.)
let peer = PinnedPeer::from_file("studio-b", Path::new("/etc/mykey/peers/studio-b.pub"))?;

// After receiving a MIKEY message, verify the DH public matches the pin
peer.verify(received_msg.dh_public().unwrap())?;
```

## Key exchange mode summary

| Mode | MITM protection | Pre-shared material | Forward secrecy |
|---|---|---|---|
| Ephemeral DH (default) | No | None | Yes |
| PSK | Initiator only — the responder authenticates the initiator, not the reverse | Shared key | No |
| PSK + verification message | Yes, mutual (both sides prove they hold the key) | Shared key | No |
| Ephemeral DH + pinning | Yes (pinned public key) | Public key only | Yes |

No mode currently provides replay protection — a captured message can be replayed and will be accepted. See [Deviations from RFC 3830](https://waxspin.github.io/mykey/concepts/rfc-deviations.html).

## Dependencies

| Crate | Purpose |
|---|---|
| [`x25519-dalek`](https://crates.io/crates/x25519-dalek) | X25519 DH key exchange |
| [`hmac`](https://crates.io/crates/hmac) + [`sha1`](https://crates.io/crates/sha1) | MIKEY-1 PRF and KEMAC MAC (HMAC-SHA-1, per RFC 3830) |
| [`aes`](https://crates.io/crates/aes) + [`ctr`](https://crates.io/crates/ctr) | AES-CM key wrapping of the KEMAC payload (RFC 3830 §4.2.3) |
| [`base64`](https://crates.io/crates/base64) | SDP `a=key-mgmt:mikey` encoding |
| [`hex`](https://crates.io/crates/hex) | Identity key file encoding |
| [`rand`](https://crates.io/crates/rand) ≥ 0.9 + [`rand_core`](https://crates.io/crates/rand_core) | RAND nonce generation; `OsRng` (direct OS entropy) for X25519 keypairs. 0.9+ required to address [RUSTSEC-2026-0097](https://rustsec.org/advisories/RUSTSEC-2026-0097). |
 [`thiserror`](https://crates.io/crates/thiserror) | Error types |

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT) at your option.
