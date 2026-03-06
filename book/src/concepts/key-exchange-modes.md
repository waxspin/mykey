# Key Exchange Modes

mykey supports two MIKEY key exchange methods. The right choice depends on your threat model and deployment environment.

## Comparison

| | Ephemeral DH (default) | PSK |
|---|---|---|
| **RFC 3830 data type** | DH-Init / DH-Resp (4/5) | PSK-Init / PSK-Resp (0/1) |
| **Key agreement** | X25519 Diffie-Hellman | Shared secret |
| **Pre-shared material** | None | A shared key both sides know |
| **Forward secrecy** | Yes — each session uses a new keypair | No — compromise of PSK exposes all sessions |
| **MITM protection** | No (unless combined with peer pinning) | Yes — PSK itself is the authenticator |
| **Best for** | Isolated media networks, low-friction setup | Controlled deployments where PSK distribution is feasible |

## Ephemeral DH — the default

```rust
use mykey::{DhInitiator, DhResponder};

let initiator = DhInitiator::new(csc_id, ssrc);
let responder = DhResponder::new();
```

`DhInitiator` and `DhResponder` each generate a fresh X25519 keypair on construction using `EphemeralSecret`. The secret is consumed during the exchange and cannot be reused. This is the only mode that provides forward secrecy.

**Ephemeral DH does not verify peer identity.** An active attacker on the network could intercept the DH exchange and substitute their own public key. For isolated broadcast infrastructure (dedicated VLANs, physical studio networks) this is typically acceptable — the network layer already prevents MITM. For open or shared networks, combine DH with [peer key pinning](../identity/pinning.md).

## PSK — Pre-shared Key

```rust
use mykey::message::MikeyMessage;

let msg = MikeyMessage::new_psk_init(csc_id, ssrc, &rand_bytes, psk)?;
```

Both sides must be configured with the same secret key before the session begins. The PSK is used to derive the TGK via the MIKEY PRF, and a MAC over the message authenticates the exchange. This provides mutual authentication — only someone who knows the PSK can produce a valid message.

PSK mode provides no forward secrecy: if the shared key is ever compromised, all past and future sessions encrypted with it are exposed.

## Adding MITM protection to DH

The [Identity & Peer Pinning](../identity/overview.md) section describes how to add MITM protection to ephemeral DH without a full PKI, using persistent keypairs and out-of-band public key distribution.
