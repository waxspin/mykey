# MIKEY & SRTP

## SRTP

**SRTP** (Secure Real-time Transport Protocol, [RFC 3711](https://datatracker.ietf.org/doc/rfc3711/)) encrypts and authenticates RTP packets. It is the standard way to secure real-time audio and video streams, used in AES67, SIP, WebRTC, and SMPTE ST 2110.

SRTP requires two pieces of key material to start a session:

- **Master key** — 16 bytes (AES-128) or 32 bytes (AES-256)
- **Master salt** — 14 bytes for AES-CM profiles

These derive the session encryption key, session authentication key, and session salt through the SRTP key derivation function. Once established, both sender and receiver use the same master key and salt independently — SRTP itself has no handshake. This is where MIKEY comes in.

## MIKEY

**MIKEY** (Multimedia Internet KEYing, [RFC 3830](https://datatracker.ietf.org/doc/rfc3830/)) is the key management protocol that negotiates the master key and salt before SRTP begins. It defines binary message formats and multiple key exchange methods, then specifies how to derive SRTP key material from the negotiated secret.

MIKEY messages are compact binary structures designed for embedding in SDP session descriptions or SAP announcements — not for use as a standalone transport protocol.

### What MIKEY does

1. **Negotiates a TGK** (TEK Generation Key) using one of several key exchange methods
2. **Carries a RAND** payload — a fresh random nonce per session
3. **Derives SRTP keys** from TGK + RAND using the MIKEY PRF (HMAC-SHA-256 based)
4. **Carries security policy** — tells the peer which SRTP cipher and authentication algorithm to use

### What MIKEY does not do

- It does not encrypt the RTP stream itself — that is SRTP's job
- It does not provide a transport — messages travel in SDP, SAP, or SIP
- It does not authenticate peers by default in DH mode — see [Identity & Peer Pinning](../identity/overview.md) for that

## The MIKEY PRF

The key derivation in mykey follows RFC 3830 Section 4.1.2. Given a key and a label, it produces an output of arbitrary length using iterated HMAC-SHA-256:

```
PRF(key, label) = HMAC-SHA-256(key, label || 0x00 || i || output_len)
                  for i = 0, 1, 2, ... until enough bytes are produced
```

All SRTP key material — TGK, auth key, enc key, SRTP master key, and SRTP salt — is derived through this function.

## MIKEY in the AES67 stack

In an AES67 deployment, the flow looks like this:

```
[Initiator]                               [Responder]
    │                                          │
    │── DH-Init (MIKEY message in SDP) ───────>│
    │                                          │  ← derives TGK from shared secret + RAND
    │<─ DH-Resp (MIKEY message in SDP) ────────│
    │                                          │
    │  derives TGK from shared secret + RAND   │
    │                                          │
    │  SRTP master key ← PRF(TGK, RAND)       │  same key on both sides
    │                                          │
    │══════════ SRTP-encrypted RTP ═══════════│
```

The MIKEY messages travel in the SDP `a=key-mgmt:mikey` attribute, announced over SAP or exchanged via SIP/RTSP.
