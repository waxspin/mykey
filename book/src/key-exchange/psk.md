# PSK (Pre-Shared Key)

PSK mode uses a secret key that both sides already know before the session begins. The TGK is derived from the shared key and RAND using the MIKEY PRF, and a MAC over the message authenticates the exchange. There is no DH negotiation.

## When to use PSK

PSK mode is the right choice when:

- You control both endpoints and can securely distribute a shared key out of band
- You need mutual authentication without any PKI
- You are operating in a closed deployment where key distribution is a solved problem (e.g., a device management system pre-provisions all endpoints)

PSK mode provides **no forward secrecy** — if the shared key is ever exposed, all sessions that used it are exposed. This is the main reason ephemeral DH is the default.

## Basic exchange

```rust
use mykey::message::MikeyMessage;
use mykey::srtp::SrtpCryptoSuite;

let psk: &[u8] = b"my-shared-secret-key-32-bytes!!!";
let suite = SrtpCryptoSuite::AES_128_CM_SHA1_80;

// --- Initiator ---
// Generate a random 16-byte RAND nonce
let mut rand_bytes = [0u8; 16];
rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut rand_bytes);

let init_msg = MikeyMessage::new_psk_init(csc_id, ssrc, &rand_bytes, psk)?;
let init_bytes = init_msg.to_bytes();

// send init_bytes to responder ...

// --- Responder ---
let parsed = MikeyMessage::from_bytes(&init_bytes)?;
let rand = parsed.rand_bytes().ok_or(MikeyError::MissingPayload)?;

// Derive SRTP keys from the PSK and RAND
let responder_keys = parsed.derive_psk_keys(psk, suite)?;

// --- Initiator ---
let initiator_keys = init_msg.derive_psk_keys(psk, suite)?;

assert_eq!(initiator_keys.master_key, responder_keys.master_key);
assert_eq!(initiator_keys.master_salt, responder_keys.master_salt);
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
| Mutual authentication | Yes — both sides must know the PSK to produce a valid MAC |
| MITM protection | Yes — assuming PSK distribution was secure |
| Replay protection | RAND nonce prevents replay of the same init message |

## Comparison with ephemeral DH

Ephemeral DH requires no pre-shared material and provides forward secrecy. PSK requires secure key distribution but provides mutual authentication without any additional mechanism. They are complementary: DH is better for spontaneous or low-friction setup; PSK is better when you have an existing key management infrastructure.

For MITM protection on top of DH without a full PSK distribution system, see [Identity & Peer Pinning](../identity/overview.md).
