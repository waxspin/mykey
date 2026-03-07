# Cookbook

Short, self-contained recipes for common tasks.

---

## Complete DH exchange (minimal)

```rust
# extern crate mykey;
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use mykey::{DhInitiator, DhResponder, srtp::SrtpCryptoSuite, message::MikeyMessage};

let suite = SrtpCryptoSuite::AES_128_CM_SHA1_80;
let csc_id: u32 = 0xdeadbeef;
let ssrc: u32 = 12345;

// Initiator
let initiator = DhInitiator::new(csc_id, ssrc);
let init_bytes = initiator.init_message()?.to_bytes().to_vec();

// Responder
let init_msg = MikeyMessage::from_bytes(&init_bytes)?;
let responder = DhResponder::new();
let resp_bytes = responder.resp_message(csc_id)?.to_bytes().to_vec();

// Initiator completes
let resp_msg = MikeyMessage::from_bytes(&resp_bytes)?;
let init_keys = initiator.complete(&resp_msg, suite)?;

// Responder completes
let resp_keys = responder.complete(&init_msg, suite)?;

assert_eq!(init_keys.master_key, resp_keys.master_key);
# Ok(())
# }
```

---

## DH exchange with security policy

```rust
# extern crate mykey;
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use mykey::{DhInitiator, srtp::SrtpCryptoSuite};
use mykey::policy::SrtpPolicy;

# let csc_id: u32 = 1;
# let ssrc: u32 = 0x12345678;
let _suite = SrtpCryptoSuite::AES_128_CM_SHA1_80;
let initiator = DhInitiator::new(csc_id, ssrc);
let sp = SrtpPolicy::aes_128_default().to_sp_payload(0);
let init_msg = initiator.init_message_with_sp(sp)?;

// Responder reads the SP back
if let Some(sp_payload) = init_msg.security_policy() {
    let policy = SrtpPolicy::from_sp_payload(sp_payload).unwrap();
    println!("enc_key_len: {}", policy.enc_key_len);
}
# Ok(())
# }
```

---

## PSK key exchange

```rust
# extern crate mykey;
# extern crate rand;
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use mykey::message::MikeyMessage;
use mykey::srtp::SrtpCryptoSuite;

# let csc_id: u32 = 1;
# let ssrc: u32 = 0x12345678;
let psk = b"32-byte-shared-secret-key-here!!";
let suite = SrtpCryptoSuite::AES_128_CM_SHA1_80;

let mut rand_bytes = [0u8; 16];
rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut rand_bytes);

let msg = MikeyMessage::new_psk_init(csc_id, ssrc, &rand_bytes, psk)?;
let _keys = msg.complete_psk(psk, suite)?;
# Ok(())
# }
```

---

## Encode and decode a MIKEY message for SDP

```rust
# extern crate mykey;
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use mykey::sap::{mikey_to_sdp_attribute, mikey_from_sdp_attribute};
# let msg = mykey::DhInitiator::new(1, 0x12345678).init_message()?;

// Encode
let attr = mikey_to_sdp_attribute(&msg);
// → "a=key-mgmt:mikey AQAABAAA..."

// Decode
let _decoded = mikey_from_sdp_attribute(&attr)?;
# Ok(())
# }
```

---

## Build a SAP announcement packet

```rust
# extern crate mykey;
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use mykey::sap::build_sap_with_mikey;
# let init_msg = mykey::DhInitiator::new(1, 0x12345678).init_message()?;

let sdp = "v=0\r\no=- 1 0 IN IP4 192.168.1.10\r\ns=Studio Feed\r\n\
           c=IN IP4 239.0.0.1/32\r\nt=0 0\r\n\
           m=audio 5004 RTP/AVP 96\r\na=rtpmap:96 L24/48000/8\r\n";

let sap = build_sap_with_mikey([192, 168, 1, 10], 0x0001, sdp, &init_msg);
let _sap_bytes = sap.to_bytes();
// Send sap_bytes on UDP multicast 239.255.255.255:9875
# Ok(())
# }
```

---

## Parse a received SAP packet

```rust
# extern crate mykey;
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use mykey::sap::{SapPacket, mikey_from_sdp_attribute};
# let init_msg = mykey::DhInitiator::new(1, 0x12345678).init_message()?;
# let sdp_src = "v=0\r\no=- 1 0 IN IP4 192.168.1.1\r\ns=T\r\nm=audio 5004 RTP/AVP 96\r\n";
# let sap_pkt = mykey::sap::build_sap_with_mikey([192, 168, 1, 1], 1, sdp_src, &init_msg);
# let udp_buf = sap_pkt.to_bytes();

let pkt = SapPacket::from_bytes(&udp_buf)?;
if pkt.deletion { return Ok(()); }

let sdp = &pkt.payload;
for line in sdp.lines() {
    if line.starts_with("a=key-mgmt:mikey") {
        let _mikey = mikey_from_sdp_attribute(line)?;
        // handle mikey...
        break;
    }
}
# Ok(())
# }
```

---

## Generate and save a persistent identity

```rust,no_run
# extern crate mykey;
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use std::path::Path;
use mykey::Identity;

let id = Identity::load_or_generate(Path::new("/etc/myapp/keys"))?;
println!("{}", id.public_key_hex());
// Distribute this hex string or mykey.pub to peers
# Ok(())
# }
```

---

## Verify a pinned peer during DH

```rust,ignore
use mykey::{PinnedPeer, MikeyError};

let peer = PinnedPeer::from_file("rack-01", "/etc/myapp/peers/rack-01.pub")?;

let dh_pub = incoming_msg.dh_public().ok_or(MikeyError::MissingPayload("DH"))?;
peer.verify(dh_pub)?;   // Err if the key doesn't match
```

---

## Inspect a raw MIKEY message

```rust
# extern crate mykey;
# extern crate hex;
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use mykey::message::MikeyMessage;
# let wire_bytes = mykey::DhInitiator::new(1, 0x12345678).init_message()?.to_bytes().to_vec();

let msg = MikeyMessage::from_bytes(&wire_bytes)?;

println!("data_type: {:?}", msg.header.data_type);
println!("csc_id:    {:#010x}", msg.header.csc_id);
println!("rand:      {:?}", msg.rand_bytes().map(hex::encode));
println!("dh_pub:    {:?}", msg.dh_public().map(hex::encode));

if let Some(sp) = msg.security_policy() {
    println!("sp params: {} entries", sp.params.len());
}
# Ok(())
# }
```

---

## Use AES-256 instead of AES-128

```rust,ignore
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
# extern crate mykey;
use mykey::{DhInitiator, MikeyError};

fn setup_session(csc_id: u32, ssrc: u32) -> Result<Vec<u8>, MikeyError> {
    let initiator = DhInitiator::new(csc_id, ssrc);
    let msg = initiator.init_message()?;
    Ok(msg.to_bytes().to_vec())
}
```
