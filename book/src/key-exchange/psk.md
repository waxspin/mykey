# PSK (Pre-Shared Key)

PSK mode uses a secret key that both sides already know before the session begins. Following RFC 3830 §3.1, the initiator generates a random TGK and **transports** it inside the KEMAC payload, encrypted with AES-CM under keys derived from the pre-shared key (§4.1.4, §4.2.3). A MAC over the whole message authenticates it. There is no DH negotiation.

The receiver verifies the MAC *before* decrypting anything, so a message that fails authentication yields no key material at all.

> **Note:** mykey ≤ 1.0.0 behaved differently — it derived the TGK from the pre-shared key on both sides and sent it in the KEMAC *in the clear*, while never verifying the MAC on receive. Anyone who could read a PSK-Init could recover the SRTP master key without knowing the PSK. If you are on 1.0.0, upgrade; see [Deviations from RFC 3830](../concepts/rfc-deviations.md).

## When to use PSK

PSK mode is the right choice when:

- You control both endpoints and can securely distribute a shared key out of band
- You need mutual authentication without any PKI
- You are operating in a closed deployment where key distribution is a solved problem (e.g., a device management system pre-provisions all endpoints)

PSK mode provides **no forward secrecy** — if the shared key is ever exposed, all sessions that used it are exposed. This is the main reason ephemeral DH is the default.

## Basic exchange

```rust
# extern crate mykey;
# extern crate rand;
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use mykey::message::MikeyMessage;
use mykey::srtp::SrtpCryptoSuite;
# use mykey::MikeyError;

# let csc_id: u32 = 1;
# let ssrc: u32 = 0x12345678;
let psk: &[u8] = b"my-shared-secret-key-32-bytes!!!";
let suite = SrtpCryptoSuite::AES_128_CM_SHA1_80;

// --- Initiator ---
// Generate a random 16-byte RAND nonce
let mut rand_bytes = [0u8; 16];
rand::RngCore::fill_bytes(&mut rand::rng(), &mut rand_bytes);

let init_msg = MikeyMessage::new_psk_init(csc_id, ssrc, &rand_bytes, psk)?;
let init_bytes = init_msg.to_bytes().to_vec();

// send init_bytes to responder ...

// --- Responder ---
let parsed = MikeyMessage::from_bytes(&init_bytes)?;
let _rand = parsed.rand_bytes().ok_or(MikeyError::MissingPayload("RAND"))?;

// Derive SRTP keys from the PSK and RAND
let responder_keys = parsed.complete_psk(psk, suite)?;

// --- Initiator ---
let initiator_keys = init_msg.complete_psk(psk, suite)?;

assert_eq!(initiator_keys.master_key, responder_keys.master_key);
assert_eq!(initiator_keys.master_salt, responder_keys.master_salt);
# Ok(())
# }
```

## Key distribution

PSK mode shifts the security problem from the protocol layer to key distribution. The shared key must reach both sides through a channel that is:

- **Confidential** — an eavesdropper who learns the PSK can decrypt all past and future sessions
- **Authenticated** — an attacker who can substitute a PSK they control performs a MITM

Common distribution approaches:

| Approach | Notes |
|---|---|
| Device provisioning at manufacture or install time | Good for closed ecosystems |
| Encrypted config file deployed via configuration management (Ansible, Salt) | Requires securing the config pipeline |
| Hardware security module (HSM) or secrets manager | Strongest option; more operational overhead |
| SSH/scp to a known-good location | Acceptable for small deployments with controlled infrastructure |

Never transmit a PSK over the same network path that carries the SRTP media stream.

## Security properties

| Property | PSK |
|---|---|
| Forward secrecy | No — PSK compromise exposes all recorded sessions |
| Key confidentiality | Yes — the TGK is AES-CM encrypted under a key derived from the PSK (§4.2.3) |
| Initiator authentication | Yes — the MAC is verified before any decryption, so an unauthenticated message yields no keys |
| Mutual authentication | Only with a verification message — see below |
| MITM protection | Yes, assuming PSK distribution was secure |
| Replay protection | **Partial** — a fresh RAND gives each session distinct keys, but nothing tracks or rejects a replayed init message |

Replay remains the open gap: mykey emits the optional COUNTER timestamp rather than a mandatory NTP type, and keeps no record of timestamps or RAND values it has seen. A captured PSK-Init can be replayed, and the receiver will accept it and derive the same keys. Do not rely on PSK mode alone to guarantee session freshness.

## Mutual authentication

By default `new_psk_init` does not request a reply, so the exchange is one-way: the responder authenticates the initiator, but the initiator learns nothing about the responder. That suits offline distribution, where the message is written to an SDP file or announced over SAP and no reply is possible.

For mutual authentication, request a verification message (RFC 3830 §6.9). The responder's reply is a MAC over its own message plus the identities and the initiator's timestamp, so producing it proves possession of the PSK:

```rust,ignore
// Initiator — sets the V flag in the header
let init = MikeyMessage::new_psk_init_requiring_verification(csc_id, ssrc, &rand, psk)?;

// Responder — verify, derive keys, then answer
let keys = init_received.complete_psk(psk, suite)?;
let resp = MikeyMessage::new_psk_verification(&init_received, psk)?;

// Initiator — check the reply before trusting the peer
resp_received.verify_psk_verification(&init, psk)?;
```

`requires_verification()` tells a responder whether the initiator asked for one. This requires a bidirectional channel.

## Comparison with ephemeral DH

Ephemeral DH requires no pre-shared material and provides forward secrecy. PSK requires secure key distribution but provides mutual authentication without any additional mechanism. They are complementary: DH is better for spontaneous or low-friction setup; PSK is better when you have an existing key management infrastructure.

For MITM protection on top of DH without a full PSK distribution system, see [Identity & Peer Pinning](../identity/overview.md).
