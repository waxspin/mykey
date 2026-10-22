//! Emit RFC 3830 §4.1.2 PRF vectors in the same format as the libmikey oracle,
//! so the two can be diffed. See `book/src/concepts/interop.md`.

use mykey::crypto::{
    mikey_prf, CONST_AUTH_FROM_PSK, CONST_AUTH_FROM_TGK, CONST_ENC_FROM_PSK, CONST_ENC_FROM_TGK,
    CONST_SALT_FROM_PSK, CONST_SALT_FROM_TGK, CONST_TEK,
};

const LABELS: &[(&str, u32)] = &[
    ("SALT", CONST_SALT_FROM_TGK),
    ("TEK", CONST_TEK),
    ("TRANS_ENCR", CONST_ENC_FROM_PSK),
    ("TRANS_SALT", CONST_SALT_FROM_PSK),
    ("TRANS_AUTH", CONST_AUTH_FROM_PSK),
    ("ENCR", CONST_ENC_FROM_TGK),
    ("AUTH", CONST_AUTH_FROM_TGK),
];

/// label = 4-byte constant || cs_id || csb_id (big endian) || RAND
fn label(constant: u32, cs_id: u8, csb_id: u32, rand: &[u8]) -> Vec<u8> {
    let mut l = Vec::with_capacity(9 + rand.len());
    l.extend_from_slice(&constant.to_be_bytes());
    l.push(cs_id);
    l.extend_from_slice(&csb_id.to_be_bytes());
    l.extend_from_slice(rand);
    l
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Must match oracle_main.cxx exactly.
    let inkey: Vec<u8> = (0..128u32).map(|i| (i * 7 + 1) as u8).collect();
    let rand = [0x5Au8; 16];

    let in_lens = [1usize, 16, 20, 31, 32, 33, 40, 63, 64, 65, 96];
    let out_lens = [16usize, 20, 32, 46];

    let raw_label = label(CONST_TEK, 0x00, 0x1234_5678, &rand);
    for il in in_lens {
        for ol in out_lens {
            let out = mikey_prf(&inkey[..il], &raw_label, ol)?;
            println!("PRF inlen={il} outlen={ol} {}", hex(&out));
        }
    }

    for (t, (name, constant)) in LABELS.iter().enumerate() {
        for il in [16usize, 32] {
            let cs_id = if (2..=4).contains(&t) { 0xFFu8 } else { 0x00 };
            let l = label(*constant, cs_id, 0x1234_5678, &rand);
            let out = mikey_prf(&inkey[..il], &l, 20)?;
            println!("DERIV {name} csId={cs_id:02x} inlen={il} {}", hex(&out));
        }
    }
    Ok(())
}
