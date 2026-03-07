# Introduction

**mykey** is a Rust implementation of MIKEY (Multimedia Internet KEYing, [RFC 3830](https://datatracker.ietf.org/doc/rfc3830/)) — the key management protocol used to negotiate SRTP session keys for real-time audio and video streams.

At its core, mykey gives you:

- **DH key exchange** — ephemeral X25519, generating fresh keys per session with forward secrecy
- **PSK mode** — pre-shared key exchange for controlled environments
- **SRTP key derivation** — produces master key and salt ready to hand to an SRTP library
- **SAP/SDP integration** — embeds MIKEY in session announcements per RFC 4567
- **Security policy** — carries SRTP cipher and authentication parameters alongside the keys
- **Peer key pinning** — opt-in MITM protection without a full PKI

---

## When to reach for mykey

**When you are building an AES67 or SMPTE ST 2110 endpoint in Rust** and need to negotiate SRTP keys as part of session setup — either via SAP announcements or direct signalling.

**When you want to add SRTP encryption to an existing RTP stream** and need the key management layer that the SRTP spec leaves out.

**When you need a standalone MIKEY implementation** — there are no other Rust crates that implement RFC 3830. mykey is the only one.

---

## Default behaviour: ephemeral keys

By default, mykey uses **ephemeral X25519 keys**. A fresh keypair is generated for every session. The private key is discarded after the DH exchange, providing forward secrecy — compromising one session's key material reveals nothing about past or future sessions.

Ephemeral DH alone does not verify the identity of the peer. For trusted, isolated networks (dedicated AES67 VLANs, studio infrastructure) this is typically sufficient — MITM is already prevented at the network layer. For open or shared networks, see [Identity & Peer Pinning](identity/overview.md).

---

## Quick orientation

```rust,ignore
use mykey::{DhInitiator, DhResponder, srtp::SrtpCryptoSuite};

let suite = SrtpCryptoSuite::AES_128_CM_SHA1_80;

// Initiator builds and sends a MIKEY DH-Init message
let initiator = DhInitiator::new(csc_id, ssrc);
let init_msg = initiator.init_message()?;
// → send init_msg.to_bytes() to peer

// Responder builds a DH-Resp message
let responder = DhResponder::new();
let resp_msg = responder.resp_message(csc_id)?;
// → send resp_msg.to_bytes() back to initiator

// Each side derives the same SRTP master key and salt
```

---

## Documentation map

| Resource | What's in it |
|---|---|
| This book | Narrative guide, concepts, examples, cookbook |
| [API reference (rustdoc)](../doc/mykey/index.html) | Every public type, trait, and function |
| README | Quick-start, feature summary, dependency table |

The rustdoc API reference is the authoritative reference for the library's public surface.
