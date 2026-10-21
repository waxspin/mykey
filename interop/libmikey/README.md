# libmikey interoperability harness

Compares mykey's RFC 3830 §4.1.2 PRF and key derivation against [libmikey]'s,
by compiling libmikey's own `p()` and `prf()` and diffing the two
implementations' output on fixed inputs.

```sh
./run.sh
```

Requires `git`, `g++`, `libssl-dev` and `cargo`. Nothing is installed and
nothing outside `$TMPDIR/mykey-libmikey-interop` is written.

## Why it is built this way

libmikey is part of minisip, a 2010-vintage autotools C++ project whose README
lists gcc 3.3 as its latest tested compiler. Building it in full would mean
reviving dead toolchains and OpenSSL APIs that were removed in 3.x.

That turns out to be unnecessary. libmikey's PRF depends on almost nothing from
the rest of the tree — a `byte_t` typedef, two constants, and `hmac_sha1`, which
is a one-line wrapper over OpenSSL's `HMAC()`. `oracle_prologue.h` supplies those
four things and nothing else, so the PRF can be compiled directly.

`run.sh` extracts `p()` and `prf()` *verbatim* from a fresh shallow clone
(`KeyAgreement.cxx` lines 132-222) into `oracle_prf_verbatim.inc` and refuses to
continue if that line range no longer begins with the expected comment. The
functions under test are never edited, so the comparison is against real
libmikey code rather than a reimplementation of it.

## Files

| File | Role |
|---|---|
| `run.sh` | clone, extract, build, run, diff |
| `oracle_prologue.h` | the four shims libmikey's PRF needs |
| `oracle_main.cxx` | emits 58 PRF and key-derivation vectors |
| `oracle_zero2.cxx` | demonstrates the defect described below |

The mykey side is `examples/interop_prf_vectors.rs`, which prints the same
format. The vectors the two agree on are committed as golden test data in
`tests/interop_libmikey.rs` and run as part of `cargo test`, so this harness is
only needed to regenerate or re-audit them.

## Result

39 of 58 vectors are byte-identical. The 19 that differ are exactly those whose
input-key length is a multiple of 32 bytes, where libmikey passes `inkeyLength %
32` — zero — as the length of the final block and so HMACs with an empty key.

Full analysis, including what this means for interoperating with libmikey and
how much it matters to libmikey itself, is in `book/src/concepts/interop.md`.

## The other half: structural validation against Wireshark

libmikey is an oracle for key *derivation*. It says nothing about whether the
bytes mykey puts on the wire parse correctly, because the harness never builds a
message.

`examples/interop_pcap.rs` is the second, independent check for that: it writes
ten representative messages — PSK init with and without the V flag, the
verification message, X25519 and all three OAKLEY groups, and DHHMAC init and
response — into a pcap as UDP to port 2269, which is where Wireshark's
`packet-mikey.c` dissector registers.

```sh
cargo run --example interop_pcap -- /tmp/mykey-interop.pcap
tshark -r /tmp/mykey-interop.pcap -V -d udp.port==2269,mikey
```

Against Wireshark 4.2.2, nine of the ten frames dissect completely with no
malformed packets and no expert infos. The tenth is the X25519 message on
private-use DH-Group 255, which no third-party parser can read, because the DH
payload carries no length field and the DH-value length is implied by the group.
Both results are analysed in `book/src/concepts/interop.md`.

To check for malformed fields specifically, rather than reading the whole tree:

```sh
tshark -r /tmp/mykey-interop.pcap -d udp.port==2269,mikey -Y '_ws.malformed'
tshark -r /tmp/mykey-interop.pcap -d udp.port==2269,mikey -z expert -q
```

[libmikey]: https://github.com/csd/minisip/tree/master/libmikey
