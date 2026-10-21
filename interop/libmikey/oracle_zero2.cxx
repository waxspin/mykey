// Rigorous version: non-uniform, distinct keys, so XOR cancellation between
// equal chunks cannot confound the result.
//
// Two claims under test, for inkeyLength a multiple of 32:
//   (A) at inkeyLength == 32 exactly (n == 1) the key is entirely ignored;
//   (B) in general the FINAL 32-byte block is dropped and replaced by
//       P(empty-key), so mutating only the last 32 bytes changes nothing.
#include "oracle_prologue.h"
#include "oracle_prf_verbatim.inc"

static void derive(unsigned char *k, unsigned len, unsigned char *out) {
    unsigned char label[9 + 16];
    memcpy(label, "\x2A\xD0\x1C\x64", 4);
    label[4] = 0;
    label[5] = 0x12; label[6] = 0x34; label[7] = 0x56; label[8] = 0x78;
    memset(&label[9], 0x5A, 16);
    prf(k, len, label, sizeof label, out, 20);
}
static void pr(const char *tag, unsigned char *o) {
    printf("  %-34s ", tag);
    for (unsigned i = 0; i < 20; i++) printf("%02x", o[i]);
    printf("\n");
}

int main(void) {
    unsigned char k1[256], k2[256], out1[20], out2[20];
    // Non-uniform and distinct: every byte differs between k1 and k2.
    for (unsigned i = 0; i < 256; i++) {
        k1[i] = (unsigned char)(i * 31 + 7);
        k2[i] = (unsigned char)(i * 131 + 200);
    }

    printf("(A) two entirely different 32-byte keys\n");
    derive(k1, 32, out1); pr("key1", out1);
    derive(k2, 32, out2); pr("key2", out2);
    printf("  => %s\n\n", memcmp(out1, out2, 20) == 0
        ? "IDENTICAL: the 32-byte key is ignored completely" : "differ");

    printf("(B) mutate ONLY the final 32 bytes, at each multiple of 32\n");
    const unsigned lens[] = { 32, 64, 96, 128, 192, 256 };
    for (unsigned i = 0; i < sizeof lens / sizeof *lens; i++) {
        unsigned L = lens[i];
        unsigned char m[256];
        memcpy(m, k1, L);
        for (unsigned j = L - 32; j < L; j++) m[j] ^= 0xFF;  // flip last block
        derive(k1, L, out1);
        derive(m,  L, out2);
        printf("  len=%-4u last-block mutation => %s\n", L,
            memcmp(out1, out2, 20) == 0 ? "NO CHANGE (final block discarded)"
                                        : "changes output");
    }

    printf("\n(C) control: lengths that are NOT multiples of 32\n");
    const unsigned ctl[] = { 31, 33, 95, 97 };
    for (unsigned i = 0; i < sizeof ctl / sizeof *ctl; i++) {
        unsigned L = ctl[i];
        unsigned char m[256];
        memcpy(m, k1, L);
        for (unsigned j = L - 1; j + 1 > L - 1 && j < L; j++) m[j] ^= 0xFF;
        m[L - 1] = k1[L - 1] ^ 0xFF;  // flip the very last byte
        derive(k1, L, out1);
        derive(m,  L, out2);
        printf("  len=%-4u last-byte mutation  => %s\n", L,
            memcmp(out1, out2, 20) == 0 ? "NO CHANGE" : "changes output (correct)");
    }
    return 0;
}
