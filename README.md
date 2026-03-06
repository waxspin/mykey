# mykey

A Rust implementation of **MIKEY** (Multimedia Internet KEYing, [RFC 3830](https://datatracker.ietf.org/doc/rfc3830/)) for SRTP key exchange.

**[Documentation](https://waxspin.github.io/mykey)**

mykey provides MIKEY message building, parsing, and key derivation for securing real-time audio streams with SRTP — including SAP/SDP integration for AES67 and SMPTE ST 2110 environments.

## Features

- Ephemeral Diffie-Hellman key exchange (X25519) — **default**
- Pre-shared key (PSK) mode
- SRTP key material derivation
- Security policy payload (RFC 3830 §6.10.1 — all SRTP parameters)
- SAP integration with `a=key-mgmt:mikey` SDP attribute (RFC 4567)
- Message parsing and serialization (wire format)
- Optional persistent identity keypairs with peer key pinning (MITM protection)

## Add to your project

```toml
[dependencies]
mykey = { path = "../mykey" }
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
// (using shared RAND from init message and exchanged DH publics)
```

### PSK mode

```rust
use mykey::message::MikeyMessage;

let psk = b"shared-secret-key";
let rand_bytes = [0x42u8; 16]; // use rand::thread_rng() in practice
let msg = MikeyMessage::new_psk_init(csc_id, ssrc, &rand_bytes, psk)?;
```

### SAP / SDP integration

```rust
use mykey::{DhInitiator, sap::{build_sap_with_mikey, mikey_to_sdp_attribute}};

let initiator = DhInitiator::new(1, 0xDEADBEEF);
let msg = initiator.init_message()?;

// RFC 4567: a=key-mgmt:mikey <base64>
let sdp_line = mikey_to_sdp_attribute(&msg);

// Or wrap in a full SAP packet
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
| PSK | Yes (key is shared secret) | Shared key | No |
| Ephemeral DH + pinning | Yes (pinned public key) | Public key only | Yes |

## Dependencies

| Crate | Purpose |
|---|---|
| [`x25519-dalek`](https://crates.io/crates/x25519-dalek) | X25519 DH key exchange |
| [`hmac`](https://crates.io/crates/hmac) + [`sha2`](https://crates.io/crates/sha2) | MIKEY PRF and MAC (HMAC-SHA-256) |
| [`aes`](https://crates.io/crates/aes) + [`ctr`](https://crates.io/crates/ctr) | AES-CM for KEMAC payload encryption |
| [`hkdf`](https://crates.io/crates/hkdf) | Key derivation |
| [`base64`](https://crates.io/crates/base64) | SDP `a=key-mgmt:mikey` encoding |
| [`hex`](https://crates.io/crates/hex) | Identity key file encoding |
| [`rand`](https://crates.io/crates/rand) | RAND payload and keypair generation |
| [`thiserror`](https://crates.io/crates/thiserror) | Error types |

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT) at your option.
