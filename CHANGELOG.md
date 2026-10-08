# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- PSK mode now supports RFC 3830 §6.9 verification messages for mutual
  authentication, as an opt-in: `new_psk_init_requiring_verification` sets the V
  flag, `new_psk_verification` builds the responder's reply, and
  `verify_psk_verification` checks it. `requires_verification` reads the flag.
  The default `new_psk_init` still requests no reply, so one-way distribution
  over SDP or SAP is unaffected ([#24]).
- `KeyDataSubPayload` implements the §6.13 key data sub-payload, including §6.14
  key validity data in both SPI/MKI and interval forms.
- `verify_and_extract_tgk` exposes MAC verification and TGK recovery separately
  from SRTP key derivation, alongside `kemac`, `timestamp_payload` and
  `timestamp_value` accessors.
- `aes` and `ctr` dependencies, for the §4.2.3 AES-CM key wrap.

### Security

- **PSK mode no longer transmits the TGK in the clear.** Following §3.1, the
  initiator now generates a random TGK and transports it encrypted with AES-CM
  (§4.2.3) under an encryption key and 112-bit salt derived from the pre-shared
  key (§4.1.4). Previously both sides derived the TGK from the PSK and it was
  sent with NULL encryption, so anyone who could read a PSK-Init recovered the
  SRTP master key without knowing the PSK (GHSA-fwjg-cm92-j3hj).
- **The message MAC is now verified on receive**, before any decryption, so a
  message that fails authentication yields no key material. A `MacAlg::Null`
  payload, an absent MAC and a truncated MAC are all refused rather than treated
  as "no check required" (GHSA-xq78-wvcv-hqvj). The MAC-covered byte range is
  recorded while parsing, so trailing bytes cannot shift it.

### Changed

- **BREAKING:** `complete_psk` now verifies the message MAC and decrypts the
  transported TGK instead of re-deriving it from the pre-shared key. It returns
  `InvalidMac` for a message that does not authenticate. Both ends of an
  exchange must be upgraded together.
- **BREAKING:** `VerificationPayload` gained the `auth_alg` field that §6.9
  places between `Next Payload` and the verification data. It was previously
  omitted from the wire format entirely, with a hardcoded 20-byte MAC.
- **BREAKING:** `TimestampType` variants renamed — `Ntp64` and `NtpShort` are
  now `NtpUtc` and `Ntp`, matching Table 6.6.
- **BREAKING:** the payload chain terminator is now `0`, per RFC 3830 §6.1
  Table 6.1.b. `PayloadType::Last` was `255`, a value the table does not define,
  so no message mykey emitted was conformant; inbound, a conformant `0`
  terminator resolved to `Hdr` and parsing only succeeded when the chain happened
  to end exactly at the end of the buffer. Messages from 1.0.0 are now rejected
  with `InvalidPayloadType(255)`, so both ends of an exchange must be upgraded
  together ([#24]).
- **BREAKING:** `PayloadType::Hdr` has been removed. Table 6.1.b assigns no
  `Next Payload` value to the common header, and nothing in the crate referenced
  the variant; `Payload::Header` is unaffected.
- **BREAKING:** a message whose payload chain points at another payload after the
  buffer has been exhausted is now rejected as truncated. Previously the parse
  loop stopped on buffer exhaustion and reported success.
- **BREAKING:** `mikey_prf` now implements the RFC 3830 §4.1.2 PRF. The previous
  implementation was a counter-mode KDF that matched no other MIKEY
  implementation ([#22]). Every key derived by mykey changes value; an exchange
  between this version and 1.0.0 will not produce matching SRTP keys.
- **BREAKING:** key derivation now uses the RFC 3830 §4.1.3 and §4.1.4 label
  layouts and constants in place of ad-hoc ASCII labels. The SRTP master key and
  salt are the TEK (`0x2AD01C64`) and salting key (`0x39A2C14B`).
- **BREAKING:** `derive_srtp_keys` takes a `csb_id: u32` argument, and
  `derive_auth_key` / `derive_enc_key` take `(inkey, csb_id, rand, len)`. The CSB
  ID was previously not mixed into any derived key; it is now threaded from the
  MIKEY common header.
- **BREAKING:** the PSK message authentication key is derived from the pre-shared
  key per §4.1.4 rather than from the TGK. Deriving it from the TGK left the MAC
  key recoverable by anyone who could read the TGK, which PSK mode sends in the
  clear.
- `mikey_prf` rejects an empty input key instead of silently returning an
  all-zero key.

### Fixed

- The PRF block counter was truncated to `u8` and wrapped after 256 blocks,
  repeating its keystream for outputs longer than 5120 bytes. The RFC
  construction has no counter, so this is gone.
- `TimestampType::value_len()` reported 4 bytes for type 1 where Table 6.6
  specifies 64 bits. Since the value also advances the payload cursor, a type 1
  timestamp was read four bytes short and every following payload parsed from
  the wrong offset. Types 0 and 2 were unaffected, and type 1 failed closed.

### Documentation

- New [Deviations from RFC 3830](book/src/concepts/rfc-deviations.md) chapter
  cataloguing every known departure: the non-RFC TGK derivation, X25519 in place
  of OAKLEY 5, the absent SIGN payload in DH mode, and the PSK mode gaps below.
- Corrected the PSK chapter, which claimed mutual authentication and MITM
  protection. Neither holds: the TGK is sent in the clear in the KEMAC payload,
  and no receive path verifies the message MAC.

[#22]: https://github.com/waxspin/mykey/issues/22
[#24]: https://github.com/waxspin/mykey/issues/24

## [1.0.0] - 2026-05-02

Initial 1.0 release.
