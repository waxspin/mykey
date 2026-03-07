# Peer Key Pinning

This page shows how to use `Identity` and `PinnedPeer` to add MITM protection to ephemeral DH.

## Generating and loading an identity

`Identity::load_or_generate` is the standard entry point. It loads an existing keypair from disk, or generates a new one if none exists:

```rust,no_run
# extern crate mykey;
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use std::path::Path;
use mykey::Identity;

// Load from a directory (creates it if needed)
let identity = Identity::load_or_generate(Path::new("/etc/myapp/keys"))?;

println!("my public key: {}", identity.public_key_hex());
# Ok(())
# }
```

The keypair is stored as two files:

| File | Contents |
|---|---|
| `mykey.key` | Private key — 32-byte hex, newline-terminated, mode 0600 |
| `mykey.pub` | Public key — 32-byte hex, newline-terminated |

The private key file is set to mode `0600` on Unix systems. Keep it out of version control and backups that are accessible to others.

## Distributing your public key

Copy `mykey.pub` to any peer that needs to verify your identity. This can be done with any trusted channel:

```bash
# Copy your public key to a peer
scp ~/.config/mykey/mykey.pub user@peer-device:/etc/myapp/peers/studio-rack-01.pub

# Or via rsync
rsync -av ~/.config/mykey/mykey.pub user@peer-device:/etc/myapp/peers/
```

The public key is just a 64-character hex string followed by a newline. It is safe to store in version control or configuration management as long as the corresponding private key is not also present.

## Pinning a peer's public key

Load a peer's public key using `PinnedPeer::from_file` or `PinnedPeer::from_hex`:

```rust
# extern crate mykey;
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use mykey::PinnedPeer;

// Or inline from a hex string (e.g., from a config file)
let _peer = PinnedPeer::from_hex(
    "studio-rack-01",
    "4a7f3c2b1e9d8a056f4e3c2a1b0d9e8f7c6b5a4d3e2f1a0b9c8d7e6f5a4b3c2d",
)?;
# Ok(())
# }
```

## Using identity during a DH exchange

### Initiator with identity

```rust,ignore
use mykey::{DhInitiator, Identity, PinnedPeer, srtp::SrtpCryptoSuite};

let suite = SrtpCryptoSuite::AES_128_CM_SHA1_80;
let my_identity = Identity::load_or_generate(std::path::Path::new("/etc/myapp/keys"))?;
let peer = PinnedPeer::from_file("responder", "/etc/myapp/peers/responder.pub")?;

let initiator = DhInitiator::new(csc_id, ssrc);
let init_msg = initiator.init_message()?;

// send init_msg to responder ...

// Receive resp_msg, then verify peer identity before completing the exchange
let resp_msg = MikeyMessage::from_bytes(&resp_bytes)?;
let peer_pub = resp_msg.dh_public().ok_or(MikeyError::MissingPayload("DH"))?;
peer.verify(peer_pub)?;  // returns Err(MikeyError::PeerKeyMismatch) if wrong

let keys = initiator.complete(&resp_msg, suite)?;
```

### Responder with identity

```rust,ignore
use mykey::{DhResponder, Identity, PinnedPeer, srtp::SrtpCryptoSuite};

let suite = SrtpCryptoSuite::AES_128_CM_SHA1_80;
let peer = PinnedPeer::from_file("initiator", "/etc/myapp/peers/initiator.pub")?;

let init_msg = MikeyMessage::from_bytes(&init_bytes)?;

// Verify the initiator's identity before responding
let peer_pub = init_msg.dh_public().ok_or(MikeyError::MissingPayload("DH"))?;
peer.verify(peer_pub)?;

let responder = DhResponder::new();
let resp_msg = responder.resp_message(csc_id)?;

// send resp_msg to initiator ...

let keys = responder.complete(&init_msg, suite)?;
```

## What `verify` checks

`PinnedPeer::verify` compares the received DH public key byte-for-byte against the stored pinned key using a constant-time comparison. If they differ, it returns:

```text
MikeyError::PeerKeyMismatch {
    peer: "studio-rack-01",
    expected: "4a7f3c...",
    received: "b92e1f...",
}
```

This error is actionable: it tells you exactly which peer name was expected, what key you stored, and what key arrived. Log it and reject the session.

## Key rotation

When a device needs a new keypair (after a suspected compromise, or as part of a periodic rotation policy):

1. Delete the old `mykey.key` and `mykey.pub` files on that device
2. Call `Identity::load_or_generate` — it will generate a new keypair
3. Distribute the new `mykey.pub` to all peers that pin this device
4. Update peer pin files on all peers

There is no automated rotation mechanism in mykey. Key rotation is an operational procedure.

## Security notes

- The private key (`mykey.key`) is the trust anchor. Protect it with filesystem permissions, and consider encrypting the disk at rest.
- The public key distribution channel does not need to be confidential, but it must be **authenticated**. An attacker who can inject a public key file into your distribution pipeline can pin their own key and perform a MITM.
- Pinning adds per-session latency only for the verify call (a constant-time byte comparison — nanoseconds). There is no performance concern.
- mykey does not pin the RAND or timestamp from the MIKEY message — only the DH public key. The public key is the stable identity; the other fields change per session.
