# API Reference

The authoritative API reference is the **rustdoc** documentation generated from the source code. It covers every public type, function, trait, and method with inline documentation.

To view it locally:

```bash
cargo doc --open
```

This page provides a navigational index of the public surface.

---

## Top-level exports (`mykey::`)

| Item | Kind | Description |
|---|---|---|
| `DhInitiator` | struct | Ephemeral DH initiator — generates fresh X25519 keypair, builds DH-Init, completes exchange |
| `DhResponder` | struct | Ephemeral DH responder — generates fresh X25519 keypair, builds DH-Resp, completes exchange |
| `Identity` | struct | Persistent X25519 keypair for peer key pinning (opt-in, not the default mode) |
| `PinnedPeer` | struct | Holds a peer's known public key; verifies incoming DH public keys |
| `MikeyError` | enum | All error variants returned by the library |
| `SrtpPolicy` | struct | SRTP cipher and authentication parameters; converts to/from SP payload |
| `SrtpKeyMaterial` | struct | Derived SRTP master key and salt, ready to pass to an SRTP library |

---

## `mykey::message`

| Item | Description |
|---|---|
| `MikeyMessage` | Parsed or constructed MIKEY message; `from_bytes()`, `to_bytes()`, accessors |
| `MikeyMessage::from_bytes` | Parse a wire-format MIKEY message |
| `MikeyMessage::new_dh_init` | Build a DH-Init message |
| `MikeyMessage::new_dh_resp` | Build a DH-Resp message |
| `MikeyMessage::new_psk_init` | Build a PSK-Init message |
| `MikeyMessage::rand_bytes` | Extract the RAND payload bytes |
| `MikeyMessage::dh_public` | Extract the DH public key from the DH payload |
| `MikeyMessage::security_policy` | Extract the SP payload if present |
| `MikeyMessage::derive_psk_keys` | Derive SRTP key material from a PSK message |

---

## `mykey::srtp`

| Item | Description |
|---|---|
| `SrtpCryptoSuite` | Describes a key/salt length pair; includes `AES_128_CM_SHA1_80` and `AES_256_CM_SHA1_80` |
| `SrtpKeyMaterial` | Holds `master_key: Vec<u8>` and `master_salt: Vec<u8>` |
| `derive_srtp_keys` | Low-level: derive key material from TGK + RAND + CS ID + suite |

---

## `mykey::policy`

| Item | Description |
|---|---|
| `SrtpPolicy` | Builder for SRTP security parameters |
| `SrtpPolicy::aes_128_default` | Preset: AES-128-CM + HMAC-SHA1-80 |
| `SrtpPolicy::aes_256_default` | Preset: AES-256-CM + HMAC-SHA1-80 |
| `SrtpPolicy::to_sp_payload` | Serialize to a `SpPayload` for inclusion in a message |
| `SrtpPolicy::from_sp_payload` | Deserialize from a parsed `SpPayload` |
| `SrtpEncAlg` | Encryption algorithm enum (`AesCm`, `AesF8`, `Null`) |
| `SrtpAuthAlg` | Authentication algorithm enum (`HmacSha1`, `Null`) |

---

## `mykey::sap`

| Item | Description |
|---|---|
| `SapPacket` | RFC 2974 SAP packet — build or parse |
| `SapPacket::from_bytes` | Parse a raw UDP payload |
| `SapPacket::is_deletion` | True if this is a session deletion announcement |
| `SapPacket::payload_str` | Extract the SDP body as a string |
| `build_sap_with_mikey` | Build a complete SAP packet with SDP body + embedded MIKEY attribute |
| `mikey_to_sdp_attribute` | Encode a MikeyMessage as an `a=key-mgmt:mikey` SDP attribute line |
| `mikey_from_sdp_attribute` | Parse an `a=key-mgmt:mikey` SDP attribute line into a MikeyMessage |

---

## `mykey::identity`

| Item | Description |
|---|---|
| `Identity` | Persistent X25519 keypair |
| `Identity::load_or_generate` | Load from disk, or generate and save if not present |
| `Identity::load` | Load only — error if not present |
| `Identity::generate` | Generate a new keypair (does not save) |
| `Identity::save` | Save keypair to disk |
| `Identity::public_key_hex` | Return the public key as a 64-character hex string |
| `Identity::public_key_bytes` | Return the public key as 32 bytes |
| `Identity::diffie_hellman` | Perform DH with a peer public key (takes `&self`, non-consuming) |
| `Identity::default_dir` | Platform default directory for key storage |
| `PinnedPeer` | A peer's known public key |
| `PinnedPeer::from_file` | Load from a file containing a hex-encoded public key |
| `PinnedPeer::from_hex` | Construct from a hex string |
| `PinnedPeer::verify` | Verify a received DH public key against the pinned key |

---

## `mykey::payload`

Low-level payload types. Most users should not need these directly — they are used internally by `MikeyMessage`.

| Item | Description |
|---|---|
| `CommonHeader` | MIKEY common header (RFC 3830 §6.1) |
| `DataType` | Message type enum (DH-Init, DH-Resp, PSK-Init, …) |
| `TimestampPayload` | TS payload (type 5) |
| `RandPayload` | RAND nonce payload (type 11) |
| `DhPayload` | DH public key payload (type 3) |
| `DhGroup` | DH group enum; `X25519 = 255` |
| `KemacPayload` | KEMAC payload (type 1) — carries the TGK in PSK mode |
| `SpPayload` | Security Policy payload (type 10) |
| `SpParam` | A single TLV parameter within an SP payload |
| `SrtpParamType` | SRTP parameter type codes (RFC 3830 §6.10.1) |
| `IdPayload` | Identity payload (type 6) |
| `Payload` | Enum over all payload variants |

---

## `mykey::error`

| Variant | Meaning |
|---|---|
| `ParseError(String)` | Malformed wire-format message |
| `MissingPayload` | Required payload absent from message |
| `InvalidDhGroup` | Unknown or unsupported DH group byte |
| `InvalidMacAlg` | Unknown MAC algorithm byte |
| `MacVerificationFailed` | HMAC check failed (PSK or KEMAC) |
| `PeerKeyMismatch { peer, expected, received }` | Received DH public key did not match the pinned key |
| `IoError(io::Error)` | File I/O error (identity key files) |
| `HexDecodeError` | Invalid hex in a key file or string |
| `Base64DecodeError` | Invalid base64 in an SDP attribute |
