# Wire Format

mykey serializes and parses the MIKEY binary wire format defined in RFC 3830. This page describes the layout of the key message types produced by the library, which is useful for debugging, interoperability testing, and understanding what goes on the wire.

## Common Header

Every MIKEY message starts with a common header (RFC 3830 §6.1).

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
!  version (8)  !  data type(8) ! next payload  !V! PRF func   !
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
!                         CSB ID (32)                           !
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
!   #CS (8)     ! CS ID map type!  CS ID map info               ~
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Value |
|---|---|
| `version` | Always `1` |
| `data type` | `4` = DH-Init, `5` = DH-Resp, `0` = PSK-Init |
| `next payload` | Type of the first payload that follows |
| `V` flag | Set when a verification payload is present |
| `PRF func` | `0` = MIKEY-PRF-HMAC-SHA-256 |
| `CSB ID` | Crypto Session Bundle ID — identifies the session |

The CS ID map (when `#CS > 0` and `CS ID map type = 0`) adds 9 bytes per crypto session:

```text
! policy_no (8) !           SSRC (32)                          !
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
!                            ROC (32)                           !
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

## Payload Chain

Payloads follow the header as a linked list. Each payload starts with a `next_payload` byte identifying the type of the payload that follows it. A value of `255` signals the last payload.

### Timestamp (type 5)

```text
! next_payload  !  TS type (8)  !  TS value (32 or 64 bits)   ~
```

mykey uses `TS type = 2` (Counter), encoding the CSB ID as a 4-byte counter value.

### RAND (type 11)

```text
! next_payload  !  RAND len (8) !  RAND value (len bytes)     ~
```

A session-unique random nonce. mykey generates 16 bytes of RAND per session.

### DH (type 3)

```text
! next_payload  !  DH-Group (8) !  DH-value (group_len bytes) ~
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+--...--+-+-+-+-+-+-+-+-+-+-+-+
!  KV type (8)  !  (KV data if type != 0)                     ~
```

The DH-value length is **implied by the group** — there is no explicit length field. For X25519 (`DH-Group = 255`) the DH-value is always 32 bytes. `KV type = 0` means no key validity data follows.

### KEMAC (type 1)

```text
! next_payload  !  enc_alg (8)  !  enc_data_len (16)          !
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
!  enc_data (enc_data_len bytes)                               ~
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
!  mac_alg (8)  !  MAC (mac_alg_len bytes)                     ~
```

Used in PSK mode to carry the TGK. `enc_alg = 0` means null encryption (plaintext TGK). `mac_alg = 0` means HMAC-SHA-256 truncated to 160 bits.

### Security Policy (type 10)

```text
! next_payload  ! policy_no (8) !  prot_type (8)  ! SP params ~
```

Followed by TLV-encoded security parameters:

```text
!  param_type(8)! param_len (8) !  param_value (param_len)    ~
```

SRTP parameter types run from 0 (encryption algorithm) to 12 (prefix length). See RFC 3830 §6.10.1.

## DH-Init message layout

A DH-Init message produced by mykey (without SP) has this layout:

```text
[CommonHeader] → T → RAND → DH → (Last)
```

Total minimum size: 10 (header) + 9 (CS ID map) + 6 (T) + 18 (RAND) + 35 (DH) = **78 bytes**

With a full 9-parameter SRTP security policy inserted before DH:

```text
[CommonHeader] → T → RAND → SP → DH → (Last)
```

The SP payload adds approximately 21 bytes (3-byte header + 9 params × 2 bytes each).

## Parsing

`MikeyMessage::from_bytes()` parses any of these formats:

```rust
# extern crate mykey;
# fn main() -> Result<(), Box<dyn std::error::Error>> {
# use mykey::message::MikeyMessage;
# let wire_bytes = mykey::DhInitiator::new(1, 0x12345678).init_message().unwrap().to_bytes().to_vec();
let msg = MikeyMessage::from_bytes(&wire_bytes)?;

println!("data_type: {:?}", msg.header.data_type);
println!("csc_id: {:#010x}", msg.header.csc_id);
println!("rand: {:?}", msg.rand_bytes());
println!("dh_pub: {:?}", msg.dh_public().map(|b| format!("{b:02x?}")));
# Ok(())
# }
```
