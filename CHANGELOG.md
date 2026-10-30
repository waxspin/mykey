# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **Require `crypto-bigint` 0.7.10 or later**, which also brings in `ctutils`
  0.4.6 or later. Earlier versions could branch on secret values in operations
  meant to be constant-time, including Montgomery multiplication
  ([RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387.html),
  [RUSTSEC-2026-0385](https://rustsec.org/advisories/RUSTSEC-2026-0385.html)).
  mykey uses these operations for OAKLEY modular exponentiation with the private
  DH exponent, so OAKLEY and DHHMAC exchanges in 2.1.0–2.3.0 were exposed,
  depending on compiler and target CPU. X25519 and PSK modes do not use
  `crypto-bigint`.

## [2.3.0] - 2026-10-22

### Added

- **Interoperability vectors for the §4.1.2 PRF, from an independent
  implementation.** RFC 3830 ships no test vectors, so key derivation was until
  now verified only against a reading of the RFC. `tests/interop_libmikey.rs`
  pins it against libmikey's output instead, and `interop/libmikey/` holds the
  harness that regenerates them.

  The harness compiles libmikey's own `p()` and `prf()` — extracted verbatim
  from csd/minisip — and diffs 58 vectors. **39 are byte-identical**, including
  all seven derivation constants and the label layout, confirming mykey's
  §4.1.3/§4.1.4 derivation against a second implementation.

  The 19 that differ are exactly those whose input-key length is a multiple of
  32 bytes, where libmikey passes `inkeyLength % 32` (zero) as the final block
  length and so HMACs with an empty key. RFC 3830 §4.1.2 permits a short final
  block but does not require one, so mykey's behaviour is correct and unchanged.
  `prf_is_key_sensitive_at_multiples_of_32` pins down the property libmikey
  loses.

  Practical consequence, documented in the new
  [Interoperability](book/src/concepts/interop.md) chapter: against libmikey the
  handshake and DH exchange both succeed while the derived TEK differs, because
  every OAKLEY MODP secret and minisip's default TGK are multiples of 32 bytes.
  No code changes — this is test and documentation only.

- **Wire-format validation against an independent parser.** Conformant byte
  layout is a separate claim from correct key derivation, so it gets a separate
  oracle: `examples/interop_pcap.rs` writes ten representative messages to a
  pcap on UDP 2269 for Wireshark's `packet-mikey.c` to read back.

  **Nine of the ten dissect completely** against Wireshark 4.2.2, with no
  malformed packets and no expert infos: PSK init with and without the `V` flag,
  PSK verification, DH init on OAKLEY 5/1/2, DH init carrying a Security Policy,
  and DHHMAC init and response. Field values are read back as written, including
  the §6.10 SRTP policy parameters, the `Last payload` terminator, and the
  DH-Group numbering — where RFC 3830's order is unrelated to the OAKLEY names
  (0 is OAKLEY 5), so a round-trip test could not have caught an error.

  The tenth frame is the X25519 message on private-use DH-Group 255, which
  Wireshark stops partway through. That is structural: the DH payload has no
  length field, so the DH-value length is implied by the group, and no
  third-party parser can read a private-use group. Both results are recorded in
  the Interoperability chapter.

- `payload::Timestamp` — `Ntp(SystemTime)` or `Counter(u32)` — to choose what an
  initiator sends in its T payload, via `with_timestamp` on `DhInitiator`,
  `ModpInitiator` and `DhHmacInitiator`, and the new
  `MikeyMessage::new_psk_init_at` and
  `new_psk_init_requiring_verification_at`. Supply one when the host has a
  better wall clock than `SystemTime::now()` (a PTP-derived one, say), or use
  `Counter` for offline SDP/SAP distribution, where no clock relates the two
  ends.

### Changed

- **Initiator messages now carry an NTP-UTC timestamp** instead of a COUNTER
  holding the CSB ID ([#24]). RFC 3830 §6.6 makes the NTP types mandatory and
  COUNTER optional, and §5.2 requires every initiator message to carry a unique
  timestamp, which `COUNTER(csb_id)` broke whenever a CSB was re-keyed.

  **Wire-compatible in both directions** — no signatures change, and no major
  version is needed. Every 2.x receiver already parses NTP-UTC, and the §4.2.3
  KEMAC IV is built from whichever T arrives, so both ends derive the same keys.
  COUNTER from older senders is still accepted. Explicit
  `Timestamp::Counter(csb_id)` reproduces the 2.2 bytes exactly.

  **One deployment-visible effect:** a receiver already calling `verify_fresh`
  previously got `Freshness::ReplayOnly` from mykey senders, so clock skew never
  mattered to it. Once a sender upgrades, its timestamps are checked against the
  window, and badly synchronized clocks will surface as `StaleTimestamp`. That
  is the feature working as intended — mykey-to-mykey exchanges can now return
  `Freshness::Verified` — but check clock sync before upgrading senders, or have
  them send `Timestamp::Counter` until you have.

  Builder output is no longer byte-for-byte reproducible across calls, since
  the timestamp changes; pass an explicit `Timestamp` where that matters.

### Fixed

- **The DHHMAC response now echoes the initiator's timestamp**, as RFC 3830
  §5.2 requires: "The Responder does not create a new timestamp, but uses the
  timestamp used by the Initiator." It previously minted its own
  `COUNTER(csb_id)`, which matched the initiator's only by coincidence.
- **The 2036 NTP rollover** (§4.2.8). `ntp_to_system_time` resolves the era with
  the RFC 4330 §3 convention — most significant bit set is 1968–2036, clear is
  2036–2104 — so timestamps after 2036-02-07 no longer decode as 1900.
  `system_time_to_ntp` returns an error past 2104-02-26 instead of emitting a
  value that would decode 136 years early.
- Documentation links to the "Deviations from RFC 3830" chapter, in the README
  and the crate docs, pointed at a path the docs site does not serve; they now
  include `/book/`.

## [2.2.0] - 2026-10-20

### Added

- **Replay protection** (RFC 3830 §5.4) as an opt-in: `replay::ReplayCache`
  plus `MikeyMessage::verify_fresh`. Additive — no existing signature changes
  ([#24]).

  mykey deliberately does not read the clock: it cannot know the accuracy of
  the host's time source, so the caller supplies a `SystemTime` and the window.
  §5.4 puts the allowable skew under "local policy", and §4.2.8 asks for the NTP
  *format* rather than the NTP *protocol* — so a PTP-locked host can supply the
  time, provided it derives a wall clock and not only a media clock.

  `verify_fresh` returns `Freshness::Verified` only when the message carried an
  NTP-format timestamp inside the window. **mykey still emits COUNTER**, so a
  mykey-to-mykey exchange returns `Freshness::ReplayOnly` — replays are rejected
  while the cache holds the entry, but freshness is not established. NTP-format
  emission is a breaking change and is deferred.

  Call it *after* verifying the MAC: §5.4 scopes the cache to successfully
  authenticated messages, and caching unauthenticated ones would let an
  attacker poison it against a legitimate exchange.

  Under overload the cache rejects rather than evicting, as §5.4 prescribes;
  evicting would let a flood of unique RANDs re-enable replays. Memory is
  bounded by arrival rate × window, capped by `DEFAULT_MAX_ENTRIES`.

  Note the inherent limit: once an entry expires, that message is admissible
  again. §5.4 frames this as "a tradeoff between the size of the replay cache
  and the required synchronization".

- `replay::ntp_to_system_time` and `replay::system_time_to_ntp` for the §4.2.8
  64-bit NTP timestamp format.
- `MikeyError::ReplayDetected`, `StaleTimestamp` and `ReplayCacheFull`.


## [2.1.0] - 2026-10-17

### Added

- **HMAC-authenticated Diffie-Hellman (RFC 4650, MIKEY-DHHMAC)** via
  `DhHmacInitiator` / `DhHmacResponder`, data types 7 and 8. The DH half-keys
  are authenticated with an HMAC keyed from a pre-shared secret instead of a
  signature, giving forward secrecy **and** mutual authentication with no PKI —
  the mode that makes the OAKLEY groups useful, since plain DH mode is
  unauthenticated ([#24]).

  Unlike PSK mode the pre-shared secret never encrypts the session key, so
  compromising it later does not expose recorded sessions.

  The HMAC is verified **before** the DH computation, so an unauthenticated
  message yields no key material. The TGK is the raw `g^(xi*xr)` per §3 and
  RFC 3830 §3.3.

  **Note:** RFC 4650 §4.2 states `Encr alg` should be "2 (NULL)" and gives a
  MAC alg table with HMAC-SHA-1 = 0 / NULL = 1. Both contradict RFC 3830 §6.2,
  which normatively defines these fields as NULL = 0 and HMAC-SHA-1-160 = 1.
  mykey follows RFC 3830, as libmikey and Wireshark both do. The MAC alg swap
  is security-relevant — reading a peer's "HMAC present" as "no MAC" — so
  `MAC alg = 0` is treated as NULL and refused rather than accepted.

- `MikeyMessage::new_dhhmac_init`, `new_dhhmac_resp` and `verify_dhhmac` for
  building and authenticating DHHMAC messages directly.
- `DataType::DhHmacInit` (7) and `DataType::DhHmacResp` (8).

- **OAKLEY MODP Diffie-Hellman groups** (RFC 3830 §4.2.7): group 5 (1536-bit),
  group 1 (768-bit) and group 2 (1024-bit), via the new `modp` module and
  `ModpInitiator` / `ModpResponder`. Additive — X25519 remains the default on
  private-use DH-Group 255, and the existing `DhInitiator` / `DhResponder` and
  `DhKeyPair` are untouched ([#24]).

  Peer values get NIST SP 800-56A full public key validation for safe-prime
  groups: `1 < y < p-1` plus `y^q mod p == 1` for order-`q` subgroup membership.
  The ephemeral exponent is 256 bits, above the 180-240 RFC 3526 §8 recommends
  for the strongest group offered. Arithmetic is `crypto-bigint`'s constant-time
  `BoxedMontyForm::pow`.

  Note that in these groups the TGK is the **raw** DH result, as §3.3 requires —
  the PRF wrapping mykey applies for X25519 is an X25519-only deviation and
  applying it here would break interoperability.

  DH mode remains **unauthenticated**: §3.3 expects a SIGN payload, which mykey
  does not implement, so a conformant peer will still reject these messages.
  OAKLEY is the groundwork for RFC 4650 (MIKEY-DHHMAC), which authenticates the
  exchange from a pre-shared key instead of signatures.

- `MikeyMessage::new_dh_init_modp`, `new_dh_init_modp_with_sp` and
  `new_dh_resp_modp` for building MODP DH messages, plus
  `MikeyMessage::dh_group` to read the group a message signals.
- `MikeyError::InvalidDhGroup`, returned when a peer answers in a different
  group than was offered.
- `crypto-bigint` dependency, for constant-time modular exponentiation.


## [2.0.0] - 2026-10-09

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

- **Small-order X25519 peer keys are now rejected.** `DhKeyPair::diffie_hellman`
  and `Identity::diffie_hellman` check `was_contributory()`, so a peer cannot
  force an all-zero shared secret that it can predict. RFC 7748 §7 notes such a
  value "will eliminate any contribution from the other party's private key";
  checking is optional in §6.1, and mykey rejects with `InvalidDhValue`. Nine
  small-order points are covered by tests, each confirmed non-contributory
  against the current `x25519-dalek` rather than copied from a blacklist.
- **Both public keys are bound into the X25519 TGK derivation**, as RFC 7748
  §6.1 asks ("a key-derivation function that includes K, K_A, and K_B").
  Previously only the shared secret and RAND were used, which §7 warns against
  where public keys serve as identifiers — as they do in `PinnedPeer`.
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

- **BREAKING:** `DhKeyPair::diffie_hellman` and `Identity::diffie_hellman` now
  return `Result<Vec<u8>>` instead of `Vec<u8>`, so a small-order peer key can
  be reported rather than silently producing a predictable secret.
- **BREAKING:** the X25519 TGK is now derived by `derive_tgk_x25519`, which
  takes both peers' public keys and binds them into the PRF label. Every
  DH-mode key changes value. `derive_tgk` remains for inputs with no public
  keys to bind.
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

<!-- Version links. The marker below is where cargo-release inserts the link for
     each newly released version; see pre-release-replacements in Cargo.toml. -->
[Unreleased]: https://github.com/waxspin/mykey/compare/v2.3.0...HEAD
<!-- next-compare -->
[2.3.0]: https://github.com/waxspin/mykey/compare/v2.2.0...v2.3.0
[2.2.0]: https://github.com/waxspin/mykey/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/waxspin/mykey/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/waxspin/mykey/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/waxspin/mykey/releases/tag/v1.0.0
