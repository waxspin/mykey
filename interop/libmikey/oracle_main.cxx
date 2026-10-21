// Oracle: libmikey's own RFC 3830 §4.1.2 PRF, compiled standalone and run to
// emit test vectors for comparison against mykey.
//
// p() and prf() are included verbatim from a fresh clone of csd/minisip
// (libmikey/keyagreement/KeyAgreement.cxx:132-222, commit 6f449fb). Nothing in
// that region is modified.

#include "oracle_prologue.h"
#include "oracle_prf_verbatim.inc"

// Label construction from KeyAgreement::keyDeriv (same file, line 224 on):
//   label = 4-byte constant || csId || csbId (big endian) || RAND
static const struct { const char *name; unsigned char c[4]; } LABELS[] = {
    { "SALT",       {0x39,0xA2,0xC1,0x4B} },  // KEY_DERIV_SALT
    { "TEK",        {0x2A,0xD0,0x1C,0x64} },  // KEY_DERIV_TEK
    { "TRANS_ENCR", {0x15,0x05,0x33,0xE1} },  // KEY_DERIV_TRANS_ENCR
    { "TRANS_SALT", {0x29,0xB8,0x89,0x16} },  // KEY_DERIV_TRANS_SALT
    { "TRANS_AUTH", {0x2D,0x22,0xAC,0x75} },  // KEY_DERIV_TRANS_AUTH
    { "ENCR",       {0x15,0x79,0x8C,0xEF} },  // KEY_DERIV_ENCR
    { "AUTH",       {0x1B,0x5C,0x79,0x73} },  // KEY_DERIV_AUTH
};

static void put_hex(const unsigned char *b, unsigned n) {
    for (unsigned i = 0; i < n; i++) printf("%02x", b[i]);
}

int main(void) {
    // Deterministic inputs so mykey can reproduce them exactly.
    unsigned char inkey[128], rand16[16];
    for (unsigned i = 0; i < sizeof inkey; i++) inkey[i] = (unsigned char)(i * 7 + 1);
    for (unsigned i = 0; i < sizeof rand16; i++) rand16[i] = (unsigned char)(0x5A);

    // Raw PRF. Key lengths straddle PRF_KEY_CHUNK_LENGTH (32) deliberately:
    // 32 and 64 are exact multiples, where the final p() call in prf() is
    // invoked with inkeyLength % 32 == 0.
    const unsigned in_lens[]  = { 1, 16, 20, 31, 32, 33, 40, 63, 64, 65, 96 };
    const unsigned out_lens[] = { 16, 20, 32, 46 };

    unsigned char label[9 + 16];
    memcpy(label, LABELS[1].c, 4);          // TEK constant, arbitrary for raw PRF
    label[4] = 0x00;
    label[5] = 0x12; label[6] = 0x34; label[7] = 0x56; label[8] = 0x78;
    memcpy(&label[9], rand16, 16);

    for (unsigned a = 0; a < sizeof in_lens / sizeof *in_lens; a++) {
        for (unsigned b = 0; b < sizeof out_lens / sizeof *out_lens; b++) {
            unsigned il = in_lens[a], ol = out_lens[b];
            unsigned char out[64];
            prf(inkey, il, label, sizeof label, out, ol);
            printf("PRF inlen=%u outlen=%u ", il, ol);
            put_hex(out, ol);
            printf("\n");
        }
    }

    // Full keyDeriv, as libmikey would call it: csId 0xFF and csbId for the
    // transport keys, csId 0 for the TEK/SRTP keys.
    for (unsigned t = 0; t < sizeof LABELS / sizeof *LABELS; t++) {
        for (unsigned il = 16; il <= 32; il += 16) {
            unsigned char l[9 + 16], out[20];
            unsigned char csId = (t >= 2 && t <= 4) ? 0xFF : 0x00;
            memcpy(l, LABELS[t].c, 4);
            l[4] = csId;
            l[5] = 0x12; l[6] = 0x34; l[7] = 0x56; l[8] = 0x78;
            memcpy(&l[9], rand16, 16);
            prf(inkey, il, l, sizeof l, out, 20);
            printf("DERIV %s csId=%02x inlen=%u ", LABELS[t].name, csId, il);
            put_hex(out, 20);
            printf("\n");
        }
    }
    return 0;
}
