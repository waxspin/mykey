# PSK (Pre-Shared Key)

PSK mode uses a secret key that both sides already know before the session begins. The TGK is derived from the shared key and RAND using the MIKEY PRF, and a MAC over the message authenticates the exchange. There is no DH negotiation.

> **Warning:** PSK mode is currently **not confidential and not authenticated**. `new_psk_init` places the TGK in the KEMAC payload in the clear, so anyone who can read the message can recover the SRTP master key without knowing the PSK; and no receive path verifies the message MAC. Do not send a mykey PSK-Init over any channel you would not be willing to send the SRTP master key over directly. See [Deviations from RFC 3830](../concepts/rfc-deviations.md).

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
| Forward secrecy | No — PSK compromise exposes all sessions |
| Key confidentiality | **No** — the TGK is sent in the clear in the KEMAC payload |
| Mutual authentication | **No** — a MAC is computed and appended, but no receive path verifies it |
| MITM protection | **No** — follows from the above |
| Replay protection | Partial — a fresh RAND gives each session distinct keys, but nothing tracks or rejects a replayed init message |

The first three are implementation gaps, not properties of the RFC's PSK method, which encrypts the TGK under a key derived from the PSK (§4.1.4) and verifies the MAC on receipt. Until they are closed, treat PSK mode as providing key *agreement* only, on an already-secure channel.

## Comparison with ephemeral DH

Ephemeral DH requires no pre-shared material and provides forward secrecy. PSK requires secure key distribution but provides mutual authentication without any additional mechanism. They are complementary: DH is better for spontaneous or low-friction setup; PSK is better when you have an existing key management infrastructure.

For MITM protection on top of DH without a full PSK distribution system, see [Identity & Peer Pinning](../identity/overview.md).
