//! Emit representative MIKEY messages as a pcap, for dissection by an
//! independent implementation.
//!
//! RFC 3830 publishes no test vectors, so the only way to turn "conformant by
//! construction" into "conformant, demonstrated" is to have someone else's
//! parser read what mykey produces. Wireshark's `packet-mikey.c` is a good
//! oracle: it is independent, it knows DHHMAC (data types 7 and 8), and it
//! registers on UDP port 2269.
//!
//! ```sh
//! cargo run --example interop_pcap -- /tmp/mykey-interop.pcap
//! tshark -r /tmp/mykey-interop.pcap -V -d udp.port==2269,mikey
//! ```
//!
//! This validates the wire *format* only. MAC verification and key-agreement
//! equivalence need a peer that performs the exchange, such as libmikey.

use std::io::Write;

use mykey::{
    message::{DhHmacInitiator, DhInitiator, MikeyMessage, ModpInitiator},
    payload::DhGroup,
    policy::SrtpPolicy,
};

const MIKEY_PORT: u16 = 2269;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "mykey-interop.pcap".to_string());

    let psk: &[u8] = b"an-interop-pre-shared-secret!!!!";
    let rand = [0x5Au8; 16];

    let mut msgs: Vec<(&str, Vec<u8>)> = Vec::new();

    // Pre-shared key mode — the only method RFC 3830 makes mandatory, so the
    // most important one to get right.
    msgs.push((
        "PSK-Init",
        MikeyMessage::new_psk_init(0x1234_5678, 0xDEAD_BEEF, &rand, psk)?
            .to_bytes()
            .to_vec(),
    ));

    // Same, requesting a verification message (V flag set).
    msgs.push((
        "PSK-Init (V flag)",
        MikeyMessage::new_psk_init_requiring_verification(0x1234_5678, 0xDEAD_BEEF, &rand, psk)?
            .to_bytes()
            .to_vec(),
    ));

    // The responder's verification message, data type 1.
    let init = MikeyMessage::new_psk_init_requiring_verification(0x1234_5678, 1, &rand, psk)?;
    msgs.push((
        "PSK verification",
        MikeyMessage::new_psk_verification(&init, psk)?
            .to_bytes()
            .to_vec(),
    ));

    // X25519 DH on private-use group 255. A conformant dissector should still
    // parse the message even though the group is not one it knows.
    let x = DhInitiator::new(0x0102_0304, 0x0A0B_0C0D);
    msgs.push((
        "DH-Init (X25519, group 255)",
        x.init_message()?.to_bytes().to_vec(),
    ));

    // OAKLEY MODP groups, with and without a security policy.
    for (label, group) in [
        ("DH-Init (OAKLEY 5)", DhGroup::Oakley5),
        ("DH-Init (OAKLEY 1)", DhGroup::Oakley1),
        ("DH-Init (OAKLEY 2)", DhGroup::Oakley2),
    ] {
        let m = ModpInitiator::new(0x1111_2222, 0x3333_4444, group)?;
        msgs.push((label, m.init_message()?.to_bytes().to_vec()));
    }

    let m = ModpInitiator::new(0x1111_2222, 0x3333_4444, DhGroup::Oakley5)?;
    msgs.push((
        "DH-Init (OAKLEY 5, with SP)",
        m.init_message_with_sp(SrtpPolicy::aes_128_default().to_sp_payload(0))?
            .to_bytes()
            .to_vec(),
    ));

    // DHHMAC, data types 7 and 8 — the interoperable authenticated mode.
    let d = DhHmacInitiator::new(0x5566_7788, 0x99AA_BBCC, DhGroup::Oakley5, psk)?;
    let d_init = d.init_message()?;
    msgs.push(("DHHMAC-Init (type 7)", d_init.to_bytes().to_vec()));

    let dr = mykey::message::DhHmacResponder::new(DhGroup::Oakley5, psk)?;
    msgs.push((
        "DHHMAC-Resp (type 8)",
        dr.resp_message(&d_init)?.to_bytes().to_vec(),
    ));

    let mut out = std::fs::File::create(&path)?;
    write_pcap_header(&mut out)?;
    for (i, (label, bytes)) in msgs.iter().enumerate() {
        write_udp_packet(&mut out, i as u32, bytes)?;
        println!("frame {:>2}  {:>5} bytes  {}", i + 1, bytes.len(), label);
    }

    println!("\nwrote {} frames to {path}", msgs.len());
    println!("inspect with:\n  tshark -r {path} -V -d udp.port=={MIKEY_PORT},mikey");
    Ok(())
}

/// pcap global header, little-endian, LINKTYPE_ETHERNET.
fn write_pcap_header(w: &mut impl Write) -> std::io::Result<()> {
    w.write_all(&0xa1b2_c3d4u32.to_le_bytes())?; // magic
    w.write_all(&2u16.to_le_bytes())?; // version major
    w.write_all(&4u16.to_le_bytes())?; // version minor
    w.write_all(&0i32.to_le_bytes())?; // thiszone
    w.write_all(&0u32.to_le_bytes())?; // sigfigs
    w.write_all(&65535u32.to_le_bytes())?; // snaplen
    w.write_all(&1u32.to_le_bytes())?; // LINKTYPE_ETHERNET
    Ok(())
}

/// One Ethernet + IPv4 + UDP frame carrying `payload` to the MIKEY port.
fn write_udp_packet(w: &mut impl Write, seq: u32, payload: &[u8]) -> std::io::Result<()> {
    let udp_len = 8 + payload.len();
    let ip_len = 20 + udp_len;

    let mut eth = Vec::new();
    eth.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x02]); // dst MAC
    eth.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]); // src MAC
    eth.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4

    let mut ip = Vec::new();
    ip.push(0x45); // version 4, IHL 5
    ip.push(0); // DSCP/ECN
    ip.extend_from_slice(&(ip_len as u16).to_be_bytes());
    ip.extend_from_slice(&(seq as u16).to_be_bytes()); // identification
    ip.extend_from_slice(&0x4000u16.to_be_bytes()); // don't fragment
    ip.push(64); // TTL
    ip.push(17); // UDP
    ip.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    ip.extend_from_slice(&[10, 0, 0, 1]); // src
    ip.extend_from_slice(&[10, 0, 0, 2]); // dst

    // IPv4 header checksum. Wireshark will flag a bad one, which would be noise
    // in the dissection output we are trying to read.
    let mut sum = 0u32;
    for pair in ip.chunks(2) {
        sum += u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let cksum = !(sum as u16);
    ip[10..12].copy_from_slice(&cksum.to_be_bytes());

    let mut udp = Vec::new();
    udp.extend_from_slice(&MIKEY_PORT.to_be_bytes()); // src port
    udp.extend_from_slice(&MIKEY_PORT.to_be_bytes()); // dst port
    udp.extend_from_slice(&(udp_len as u16).to_be_bytes());
    udp.extend_from_slice(&0u16.to_be_bytes()); // checksum 0 = not computed
    udp.extend_from_slice(payload);

    let frame: Vec<u8> = eth.iter().chain(&ip).chain(&udp).copied().collect();

    w.write_all(&seq.to_le_bytes())?; // ts_sec
    w.write_all(&0u32.to_le_bytes())?; // ts_usec
    w.write_all(&(frame.len() as u32).to_le_bytes())?; // incl_len
    w.write_all(&(frame.len() as u32).to_le_bytes())?; // orig_len
    w.write_all(&frame)?;
    Ok(())
}
