# Cookbook

Short, self-contained recipes for common tasks.

---

## Complete DH exchange (minimal)

```rust
use mykey::{DhInitiator, DhResponder, srtp::SrtpCryptoSuite, message::MikeyMessage};

let suite = SrtpCryptoSuite::AES_128_CM_SHA1_80;
let csc_id: u32 = 0xdeadbeef;
let ssrc: u32 = 12345;

// Initiator
let initiator = DhInitiator::new(csc_id, ssrc);
let init_bytes = initiator.init_message()?.to_bytes();

// Responder
let init_msg = MikeyMessage::from_bytes(&init_bytes)?;
let responder = DhResponder::new();
let resp_bytes = responder.resp_message(csc_id)?.to_bytes();

// Initiator completes
let resp_msg = MikeyMessage::from_bytes(&resp_bytes)?;
let init_keys = initiator.complete(&resp_msg, suite)?;

// Responder completes
let resp_keys = responder.complete(&init_msg, suite)?;

assert_eq!(init_keys.master_key, resp_keys.master_key);
```

---

## DH exchange with security policy

```rust
use mykey::{DhInitiator, DhResponder, srtp::SrtpCryptoSuite};
use mykey::policy::SrtpPolicy;

let suite = SrtpCryptoSuite::AES_128_CM_SHA1_80;
let initiator = DhInitiator::new(csc_id, ssrc);
let sp = SrtpPolicy::aes_128_default().to_sp_payload(0);
let init_msg = initiator.init_message_with_sp(sp)?;

// Responder reads the SP back
if let Some(sp_payload) = init_msg_parsed.security_policy() {
    let policy = SrtpPolicy::from_sp_payload(sp_payload)?;
    println!("enc_key_len: {}", policy.enc_key_len);
}
```

---

## PSK key exchange

```rust
use mykey::message::MikeyMessage;
use mykey::srtp::SrtpCryptoSuite;

let psk = b"32-byte-shared-secret-key-here!!";
let suite = SrtpCryptoSuite::AES_128_CM_SHA1_80;

let mut rand = [0u8; 16];
rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut rand);

let msg = MikeyMessage::new_psk_init(csc_id, ssrc, &rand, psk)?;
let keys = msg.derive_psk_keys(psk, suite)?;
```

---

## Encode and decode a MIKEY message for SDP

```rust
use mykey::sap::{mikey_to_sdp_attribute, mikey_from_sdp_attribute};

// Encode
let attr = mikey_to_sdp_attribute(&msg);
// → "a=key-mgmt:mikey AQAABAAA..."

// Decode
let decoded = mikey_from_sdp_attribute(&attr)?;
```

---

## Build a SAP announcement packet

```rust
use mykey::sap::build_sap_with_mikey;

let sdp = "v=0\r\no=- 1 0 IN IP4 192.168.1.10\r\ns=Studio Feed\r\n\
           c=IN IP4 239.0.0.1/32\r\nt=0 0\r\n\
           m=audio 5004 RTP/AVP 96\r\na=rtpmap:96 L24/48000/8\r\n";

let sap = build_sap_with_mikey("192.168.1.10", 0x0001, sdp, &init_msg)?;
// Send sap on UDP multicast 239.255.255.255:9875
```

---

## Parse a received SAP packet

```rust
use mykey::sap::{SapPacket, mikey_from_sdp_attribute};

let pkt = SapPacket::from_bytes(&udp_buf)?;
if pkt.is_deletion() { return Ok(()); }

let sdp = pkt.payload_str()?;
for line in sdp.lines() {
    if line.starts_with("a=key-mgmt:mikey") {
        let mikey = mikey_from_sdp_attribute(line)?;
        // handle mikey...
        break;
    }
}
```

---

## Generate and save a persistent identity

```rust
use mykey::Identity;

let id = Identity::load_or_generate(None)?;
println!("{}", id.public_key_hex());
// Distribute this hex string or mykey.pub to peers
```

---

## Verify a pinned peer during DH

```rust
use mykey::{PinnedPeer, MikeyError};

let peer = PinnedPeer::from_file("rack-01", "/etc/myapp/peers/rack-01.pub")?;

let dh_pub = incoming_msg.dh_public().ok_or(MikeyError::MissingPayload)?;
peer.verify(dh_pub)?;   // Err if the key doesn't match
```

---

## Inspect a raw MIKEY message

```rust
use mykey::message::MikeyMessage;

let msg = MikeyMessage::from_bytes(&wire_bytes)?;

println!("data_type: {:?}", msg.header.data_type);
println!("csc_id:    {:#010x}", msg.header.csc_id);
println!("rand:      {:?}", msg.rand_bytes().map(hex::encode));
println!("dh_pub:    {:?}", msg.dh_public().map(hex::encode));

if let Some(sp) = msg.security_policy() {
    println!("sp params: {} entries", sp.params.len());
}
```

---

## Use AES-256 instead of AES-128

```rust
use mykey::srtp::SrtpCryptoSuite;
use mykey::policy::SrtpPolicy;

let suite = SrtpCryptoSuite::AES_256_CM_SHA1_80;
let sp = SrtpPolicy::aes_256_default().to_sp_payload(0);

let init_msg = initiator.init_message_with_sp(sp)?;
let keys = initiator.complete(&resp_msg, suite)?;

assert_eq!(keys.master_key.len(), 32);  // AES-256 key
assert_eq!(keys.master_salt.len(), 14);
```

---

## Error handling pattern

All fallible functions return `Result<T, MikeyError>`. The `MikeyError` type implements `std::error::Error` and can be used with `?` in any context that accepts it:

```rust
use mykey::{DhInitiator, MikeyError};

fn setup_session(csc_id: u32, ssrc: u32) -> Result<Vec<u8>, MikeyError> {
    let initiator = DhInitiator::new(csc_id, ssrc);
    let msg = initiator.init_message()?;
    Ok(msg.to_bytes())
}

// With anyhow
fn setup_session_anyhow(csc_id: u32, ssrc: u32) -> anyhow::Result<Vec<u8>> {
    let initiator = DhInitiator::new(csc_id, ssrc);
    let msg = initiator.init_message()?;
    Ok(msg.to_bytes())
}
```
