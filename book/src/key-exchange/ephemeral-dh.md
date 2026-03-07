# Ephemeral DH (default)

Ephemeral Diffie-Hellman is the default and recommended key exchange method in mykey. Both sides generate fresh X25519 keypairs for each session. The private key is consumed during the exchange and discarded — it cannot be reused, which provides forward secrecy.

## How it works

1. **Initiator** generates a random keypair and a 16-byte RAND nonce. Builds a DH-Init message containing the public key and RAND, and sends it to the responder.
2. **Responder** generates its own keypair. Builds a DH-Resp message containing its public key, and sends it back.
3. **Both sides** compute `shared_secret = DH(my_secret, peer_public)`, then derive the TGK and SRTP keys using the MIKEY PRF with the RAND from the init message.

The RAND ensures that even if the same keypairs were somehow reused, each session produces different key material.

## Basic exchange

```rust
# extern crate mykey;
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use mykey::{DhInitiator, DhResponder, srtp::SrtpCryptoSuite, message::MikeyMessage};

let suite = SrtpCryptoSuite::AES_128_CM_SHA1_80;

// --- Initiator ---
# let csc_id: u32 = 1;
# let ssrc: u32 = 0x12345678;
let initiator = DhInitiator::new(csc_id, ssrc);
let init_bytes = initiator.init_message()?.to_bytes().to_vec();

// send init_bytes to responder over network / SDP ...

// --- Responder ---
let init_msg = MikeyMessage::from_bytes(&init_bytes)?;
let responder = DhResponder::new();
let resp_bytes = responder.resp_message(csc_id)?.to_bytes().to_vec();

// send resp_bytes back to initiator ...

// --- Initiator completes exchange ---
let resp_msg = MikeyMessage::from_bytes(&resp_bytes)?;
let initiator_keys = initiator.complete(&resp_msg, suite)?;

// --- Responder completes exchange ---
// (responder holds the init_msg separately)
let responder_keys = responder.complete(&init_msg, suite)?;

// initiator_keys and responder_keys are identical
assert_eq!(initiator_keys.master_key, responder_keys.master_key);
assert_eq!(initiator_keys.master_salt, responder_keys.master_salt);
# Ok(())
# }
```

## With security policy

Include an SP payload to declare the SRTP cipher suite to the peer:

```rust
# extern crate mykey;
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use mykey::{DhInitiator, SrtpPolicy};

# let csc_id: u32 = 1;
# let ssrc: u32 = 0x12345678;
let initiator = DhInitiator::new(csc_id, ssrc);
let sp = SrtpPolicy::aes_128_default().to_sp_payload(0);
let _init_msg = initiator.init_message_with_sp(sp)?;
# Ok(())
# }
```

The responder can read the policy back from the parsed message:

```rust
# extern crate mykey;
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use mykey::policy::SrtpPolicy;
# use mykey::DhInitiator;
# let csc_id: u32 = 1;
# let sp_payload = SrtpPolicy::aes_128_default().to_sp_payload(0);
# let parsed_msg = DhInitiator::new(csc_id, 0x12345678).init_message_with_sp(sp_payload)?;

if let Some(sp) = parsed_msg.security_policy() {
    let policy = SrtpPolicy::from_sp_payload(sp).unwrap();
    println!("enc key len: {}", policy.enc_key_len);
    println!("auth tag len: {}", policy.auth_tag_len);
}
# Ok(())
# }
```

## Choosing a crypto suite

| Constant | Key | Salt | Profile |
|---|---|---|---|
| `AES_128_CM_SHA1_80` | 16 bytes | 14 bytes | AES-128-CM + HMAC-SHA1-80 (recommended) |
| `AES_256_CM_SHA1_80` | 32 bytes | 14 bytes | AES-256-CM + HMAC-SHA1-80 |

```rust
# extern crate mykey;
use mykey::srtp::SrtpCryptoSuite;

// AES-128 (default for AES67)
let _suite = SrtpCryptoSuite::AES_128_CM_SHA1_80;

// AES-256 for compliance requirements
let _suite = SrtpCryptoSuite::AES_256_CM_SHA1_80;
```

## Using the derived keys

The `SrtpKeyMaterial` returned by `complete()` contains the master key and salt ready to pass to an SRTP library:

```rust,ignore
let keys = initiator.complete(&resp_msg, suite)?;

println!("master_key: {}", hex::encode(&keys.master_key));
println!("master_salt: {}", hex::encode(&keys.master_salt));

// Pass to your SRTP library, e.g.:
// srtp_context.set_key(&keys.master_key, &keys.master_salt);
```

## Limitations

Ephemeral DH alone does not verify that you are exchanging keys with the intended peer. An attacker on the network who can intercept and replace packets could substitute their own DH public key and negotiate separate keys with each side.

For isolated networks (dedicated AES67 VLANs, physically secured infrastructure) this is typically not a concern. For shared or open networks, add peer key pinning — see [Identity & Peer Pinning](../identity/overview.md).
