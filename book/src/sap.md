# SAP / SDP Integration

MIKEY messages travel in SDP session descriptions, not as a standalone transport protocol. In an AES67 deployment, session announcements are broadcast over **SAP** (Session Announcement Protocol, RFC 2974), and the MIKEY key management message is embedded in the SDP body as an `a=key-mgmt:mikey` attribute per RFC 4567.

mykey provides helpers to build and parse both layers.

## SDP attribute

The `a=key-mgmt:mikey` attribute carries the MIKEY message as base64:

```
a=key-mgmt:mikey <base64-encoded MIKEY message>
```

```rust
use mykey::sap::{mikey_to_sdp_attribute, mikey_from_sdp_attribute};

// Encode a message into an SDP attribute line
let attr_line = mikey_to_sdp_attribute(&init_msg);
// → "a=key-mgmt:mikey AQAABAAA..."

// Parse an attribute line back into a MikeyMessage
let msg = mikey_from_sdp_attribute(&attr_line)?;
```

## Building a SAP packet

`build_sap_with_mikey` takes an SDP body, inserts the `a=key-mgmt:mikey` attribute before the first `m=` line, and wraps the whole thing in a SAP packet:

```rust
use mykey::sap::build_sap_with_mikey;

let sdp = "v=0\r\no=- 0 0 IN IP4 192.168.1.10\r\ns=My Stream\r\n\
           c=IN IP4 239.0.0.1/32\r\nt=0 0\r\n\
           m=audio 5004 RTP/AVP 96\r\n\
           a=rtpmap:96 L24/48000/8\r\n";

let sap_packet = build_sap_with_mikey(
    "192.168.1.10",   // originating source (used in SAP header)
    0x1234,           // message ID hash
    sdp,
    &init_msg,
)?;

// Broadcast over UDP multicast to 239.255.255.255:9875 (SAP multicast address)
socket.send_to(&sap_packet, "239.255.255.255:9875")?;
```

## Parsing an incoming SAP packet

```rust
use mykey::sap::SapPacket;

let pkt = SapPacket::from_bytes(&udp_payload)?;

println!("msg_id:    {:#06x}", pkt.msg_id_hash);
println!("origin:    {:?}", pkt.originating_source);
println!("deletion:  {}", pkt.is_deletion());

let sdp_body = pkt.payload_str()?;
println!("{}", sdp_body);
```

## Extracting the MIKEY message from SDP

Once you have the SDP body, find the `a=key-mgmt:mikey` line and parse it:

```rust
use mykey::sap::mikey_from_sdp_attribute;

for line in sdp_body.lines() {
    if line.starts_with("a=key-mgmt:mikey") {
        let mikey_msg = mikey_from_sdp_attribute(line)?;
        // Use mikey_msg to complete the DH exchange...
        break;
    }
}
```

## Full initiator flow with SAP

```rust
use mykey::{DhInitiator, srtp::SrtpCryptoSuite};
use mykey::sap::build_sap_with_mikey;

let suite = SrtpCryptoSuite::AES_128_CM_SHA1_80;
let initiator = DhInitiator::new(csc_id, ssrc);
let init_msg = initiator.init_message()?;

let sdp = format!(
    "v=0\r\no=- {csc_id} 0 IN IP4 {src}\r\ns=My Stream\r\n\
     c=IN IP4 239.0.0.1/32\r\nt=0 0\r\n\
     m=audio 5004 RTP/AVP 96\r\na=rtpmap:96 L24/48000/8\r\n",
    src = "192.168.1.10"
);

let sap_bytes = build_sap_with_mikey("192.168.1.10", 0x1234, &sdp, &init_msg)?;
// broadcast sap_bytes on 239.255.255.255:9875
```

## Full responder flow with SAP

```rust
use mykey::{DhResponder, srtp::SrtpCryptoSuite, message::MikeyMessage};
use mykey::sap::{SapPacket, mikey_from_sdp_attribute};

let suite = SrtpCryptoSuite::AES_128_CM_SHA1_80;

// Received SAP packet from multicast
let pkt = SapPacket::from_bytes(&udp_payload)?;
let sdp = pkt.payload_str()?;

let mut init_msg = None;
for line in sdp.lines() {
    if line.starts_with("a=key-mgmt:mikey") {
        init_msg = Some(mikey_from_sdp_attribute(line)?);
        break;
    }
}
let init_msg = init_msg.ok_or(MikeyError::MissingPayload)?;

let responder = DhResponder::new();
let resp_msg = responder.resp_message(csc_id)?;
// Send resp_msg back to initiator (e.g., via unicast SDP answer)

let keys = responder.complete(&init_msg, suite)?;
// keys.master_key and keys.master_salt are ready for your SRTP library
```

## SAP multicast addresses

| Scope | Address | Port |
|---|---|---|
| Global | `224.2.127.254` | `9875` |
| Administrative | `239.255.255.255` | `9875` |
| AES67 (common practice) | Site-local multicast | `9875` |

The SAP port is always 9875. The multicast group depends on the scope of the announcement. For AES67 studio environments, use the appropriate site-local multicast address per your network plan.
