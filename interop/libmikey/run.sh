#!/usr/bin/env bash
# Compare mykey's RFC 3830 §4.1.2 PRF against libmikey's, by compiling
# libmikey's own p()/prf() and diffing the two implementations' output.
#
# libmikey's PRF needs nothing from the rest of the minisip tree except a
# typedef, two constants and hmac_sha1 (a bare OpenSSL HMAC call), all supplied
# by oracle_prologue.h. The functions under test are extracted verbatim from the
# clone, never edited, so the comparison is against real libmikey code.
#
# Requires: git, g++, libssl-dev, cargo.
set -euo pipefail

MINISIP_COMMIT=6f449fb
PRF_FIRST_LINE=132
PRF_LAST_LINE=222

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
work="${TMPDIR:-/tmp}/mykey-libmikey-interop"
mkdir -p "$work"
cd "$work"

if [ ! -d minisip ]; then
    echo "== cloning csd/minisip"
    git clone -q --depth 1 https://github.com/csd/minisip.git
fi
got="$(git -C minisip rev-parse --short HEAD)"
if [ "$got" != "$MINISIP_COMMIT" ]; then
    echo "note: minisip HEAD is $got, vectors were generated against $MINISIP_COMMIT" >&2
fi

src=minisip/libmikey/keyagreement/KeyAgreement.cxx
# Guard the line range: if upstream ever moves, fail loudly instead of
# silently extracting the wrong code.
if ! sed -n "${PRF_FIRST_LINE}p" "$src" | grep -q 'Described in rfc3830.txt Section 4.1.2'; then
    echo "error: line $PRF_FIRST_LINE of $src is not the start of the PRF block" >&2
    exit 1
fi

echo "== extracting p()/prf() verbatim (lines ${PRF_FIRST_LINE}-${PRF_LAST_LINE})"
sed -n "${PRF_FIRST_LINE},${PRF_LAST_LINE}p" "$src" > oracle_prf_verbatim.inc
wc -l < oracle_prf_verbatim.inc | sed 's/^/   lines extracted: /'

cp "$here"/oracle_prologue.h "$here"/oracle_main.cxx "$here"/oracle_zero2.cxx .

echo "== building oracles"
g++ -O1 -w -o oracle      oracle_main.cxx  -lcrypto
g++ -O1 -w -o oracle_zero oracle_zero2.cxx -lcrypto

echo "== libmikey vectors"
./oracle > libmikey_vectors.txt
echo "== mykey vectors"
( cd "$repo" && cargo run -q --example interop_prf_vectors ) > mykey_vectors.txt

total=$(wc -l < libmikey_vectors.txt)
agree=$(comm -12 <(sort libmikey_vectors.txt) <(sort mykey_vectors.txt) | wc -l)
echo
echo "vectors: $total   byte-identical: $agree   divergent: $((total - agree))"
echo
echo "== divergent input lengths, with length mod 32"
# diff exits 1 when the files differ, and grep exits 1 on no match; neither is
# an error here, so keep both out of pipefail's way.
divergent=$( { diff libmikey_vectors.txt mykey_vectors.txt || true; } \
    | { grep '^<' || true; } \
    | { grep -o 'inlen=[0-9]*' || true; } | sed 's/inlen=//' | sort -un )
if [ -z "$divergent" ]; then
    echo "   (none)"
else
    while read -r n; do
        printf '   inlen=%-4s mod32=%s\n' "$n" "$((n % 32))"
    done <<< "$divergent"
fi
echo
echo "== demonstration of the libmikey defect"
./oracle_zero
echo
echo "Full analysis: book/src/concepts/interop.md"
