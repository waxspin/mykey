# Interoperability

RFC 3830 ships no test vectors. Every claim that mykey computes the right bytes
therefore rests either on reading the RFC or on agreeing with somebody else's
independent implementation. This chapter records the second kind of evidence.

## The reference implementation

[libmikey], part of the [minisip] softphone, is the only implementation found
that actually *performs* DHHMAC — Wireshark dissects MIKEY but does not derive
keys, and GStreamer's MIKEY support does not implement DHHMAC at all. That makes
libmikey the natural oracle for the key-derivation path.

libmikey's RFC 3830 §4.1.2 PRF needs almost nothing from the rest of the minisip
tree: one typedef, two constants, and `hmac_sha1`, which is a bare OpenSSL
`HMAC()` call. So rather than build a 2010-vintage autotools C++ project, the
harness in [`interop/libmikey/`][harness] extracts `p()` and `prf()` *verbatim*
from a fresh clone and compiles them against OpenSSL directly. The functions
under test are never edited, so the comparison is against real libmikey code.

```sh
./interop/libmikey/run.sh
```

The harness derives 58 vectors from both implementations — the raw PRF across
input-key lengths from 1 to 96 bytes and output lengths from 16 to 46 bytes, plus
full key derivation for all seven RFC 3830 constants — and diffs them.

## Result

**39 of 58 vectors are byte-identical.** All seven derivation constants and the
label layout (`constant || cs_id || csb_id || RAND`) match exactly, confirming
mykey's §4.1.3/§4.1.4 labels against an independent implementation.

The 19 divergent vectors share one property, exactly: the input-key length is a
multiple of 32 bytes. Every length that is *not* a multiple of 32 agrees.

| Input key length | mod 32 | Agreement |
|---|---|---|
| 1, 16, 20, 31, 33, 40, 63, 65 | ≠ 0 | byte-identical |
| 32, 64, 96 | 0 | divergent |

The agreeing vectors are committed as golden test data in
[`tests/interop_libmikey.rs`][test], so the derivation path cannot silently drift
away from an independently-verified reference.

## Why the divergence: a defect in libmikey

RFC 3830 §4.1.2 defines the PRF over the input key as:

> * let n = inkey_len / 256, rounded up to the nearest integer if not already an
>   integer
> * split the inkey into n blocks, inkey = s_1 || ... || s_n, where all s_i,
>   **except possibly s_n**, are 256 bits each

"Except possibly" permits a short final block; it does not require one. A 32-byte
key is `n = 1` block of exactly 256 bits, used whole.

libmikey computes the final block's length as a modulus:

```c
/* libmikey/keyagreement/KeyAgreement.cxx */
p( &inkey[ (n-1)*PRF_KEY_CHUNK_LENGTH ], inkeyLength % PRF_KEY_CHUNK_LENGTH,
   label, labelLength, m, p_output );
```

When `inkeyLength` is an exact multiple of `PRF_KEY_CHUNK_LENGTH` (32), that
modulus is **0**, so the final `p()` call runs with a zero-length HMAC key. The
final 32 bytes of the input key are discarded and replaced by a constant
`P(empty_key, label, m)` term.

At `inkeyLength == 32` the degenerate call is the *only* call — `n == 1`, so the
preceding loop never executes. The key is ignored in its entirety, and the
derived keys become a function of the label alone: a 4-byte constant, `cs_id`,
`csb_id`, and RAND. `csb_id` travels in the MIKEY common header and RAND in the
RAND payload, both in cleartext, so every input to the derivation is visible to a
passive observer.

The harness demonstrates this rather than asserting it — two entirely different
32-byte keys produce identical output, and flipping the whole final 32-byte block
changes nothing at any multiple of 32, while a single flipped byte does change
the output at 31, 33, 95 and 97 bytes.

This is a defect and not a deliberate deviation. There is no sentinel
interpretation available: `hmac_sha1` passes its length straight to OpenSSL's
`HMAC()`, where a key length of 0 means an empty key, and the demonstration above
shows the key bytes are never read. Structurally it is an off-by-one between two
inconsistent conventions — `n = ceil(len / 32)` counts only non-empty blocks,
while the loop over `1..n-1` followed by an unconditional trailing "remainder"
call is correct only if a non-empty remainder always exists. The comment directly
above the function reads "Described in rfc3830.txt Section 4.1.2", so the
intention was to implement the RFC.

mykey follows the RFC. `prf_is_key_sensitive_at_multiples_of_32` in the interop
test pins down the property libmikey loses.

## How much this matters to libmikey itself

Mostly not much, which is worth stating plainly: the defect is deterministic and
symmetric, so two libmikey peers derive the same wrong keys and interoperate with
each other perfectly. It only becomes visible against an implementation that
follows the RFC, and for DHHMAC there was effectively none at the time.

The amount of key material actually lost depends on `n`. minisip's TGK is 192
bytes — `generateTgk(uint32_t tgkLength = 192)`, called with no argument — and
every OAKLEY MODP secret is 96, 128 or 192 bytes, so `n` is 3, 4 or 6. Blocks 1
through `n-1` still contribute; only the final 32 bytes are discarded. A TEK
derived from 160 remaining bytes of a 192-byte secret is not meaningfully
weakened.

The one case that is not benign is `n == 1`, where the whole key is dropped.
libmikey reaches it when the PSK is exactly 32 bytes long, because the transport
keys are derived from the PSK directly:

```c
/* KeyAgreementPSK::genTranspEncrKey */
keyDeriv( 0xFF, csbId(), pskPtr, pskLengthValue, ... );
```

The PSK is a passphrase typed into the GUI and used verbatim — `setPsk(string
key){ psk = key; }`, with `pskLengthValue` its byte length — so a 32-character
passphrase makes `enc_key`, `auth_key` and `salt_key` computable from public wire
data alone, defeating both the confidentiality of the transported TGK and the
authenticity of the MIKEY message. A 64-character passphrase instead reduces the
PSK to its first 32 bytes. Neither is the default: minisip ships
`psk = "Unspecified PSK"` (15 bytes) with `psk_enabled = false`.

Given how little is exposed, this is recorded as interoperability analysis rather
than filed as an advisory. minisip's last commit was in 2010; it is in neither
Debian nor Ubuntu, and while a package recipe survives in OpenMandriva — touched
as recently as July 2026 — the `minisip.org` host its `Source:` URL points at no
longer resolves.

## What this means in practice

Divergence in the PRF matters only where an exchange actually feeds it a key
whose length is a multiple of 32. Two of the three places it is used always do:

| Derivation | PRF input key | Length | Interoperates? |
|---|---|---|---|
| PSK transport keys (enc, auth, salt) | the PSK | user-chosen | yes, unless the PSK length is a multiple of 32 |
| DHHMAC `auth_key` | the PSK | user-chosen | yes, unless the PSK length is a multiple of 32 |
| TEK and SRTP salt, PSK mode | the TGK | 32 (`PSK_TGK_LEN`) | **no** |
| TEK and SRTP salt, DH and DHHMAC | the DH shared secret | 96 / 128 / 192 | **no** |

Every OAKLEY MODP modulus is a whole number of 32-byte blocks — 768, 1024 and
1536 bits are 96, 128 and 192 bytes — and libmikey sets the TGK length to the
modulus size (`setTgk(NULL, dh->secretLength())`). mykey's `PSK_TGK_LEN` is 32.
So TEK derivation disagrees in every mode.

The practical failure mode against libmikey is therefore an unhelpful one:

* the MIKEY handshake **succeeds** — the MAC verifies, because `auth_key` comes
  from the PSK, whose length is usually not a multiple of 32;
* the Diffie-Hellman exchange **succeeds** — the TGK is the raw shared secret,
  with no PRF involved on either side;
* the derived TEK and salt **differ**, so SRTP fails to decrypt.

Key management appears to complete, and the media is silent.

## mykey's position

mykey implements RFC 3830 as written and does not reproduce the defect. Being
bug-compatible would mean discarding the last 256 bits of every Diffie-Hellman
shared secret, and ignoring the PSK entirely whenever it happened to be 32 bytes,
in order to match a project last committed to in 2010. That trade is not worth
making, and any peer that follows the RFC would then fail to interoperate
instead.

If interoperability with libmikey specifically is required, the constraint is on
libmikey's side and the fix there is one expression:

```c
unsigned tail = inkeyLength % PRF_KEY_CHUNK_LENGTH;
if( tail == 0 ) tail = PRF_KEY_CHUNK_LENGTH;
```

[libmikey]: https://github.com/csd/minisip/tree/master/libmikey
[minisip]: https://github.com/csd/minisip
[harness]: https://github.com/waxspin/mykey/tree/main/interop/libmikey
[test]: https://github.com/waxspin/mykey/blob/main/tests/interop_libmikey.rs
