# Identity & Peer Pinning

## The problem

Ephemeral DH provides forward secrecy but does not verify who you are talking to. An attacker on the network who can intercept and replace packets — a man-in-the-middle — can substitute their own X25519 public key in the DH-Init or DH-Resp message and negotiate separate keys with each side. Both sides believe they have a secure session with the other, but all media flows through the attacker.

For **isolated networks** (dedicated AES67 VLANs, physically secured studio infrastructure) this is typically not a concern. The network topology itself prevents MITM: a device on the VLAN that sends a fake DH-Init would be visible and attributable. For **open or shared networks**, you need a way to verify that the DH public key you received actually came from the peer you intended.

## The solution: persistent keypairs and out-of-band distribution

mykey solves this problem without certificates or a PKI, using the same approach as SSH known_hosts:

1. **Each device generates a persistent X25519 keypair** at first run and saves it to disk. The private key never leaves the device. The public key is a 32-byte value encoded as a hex string.

2. **Public keys are distributed out of band** — copied to a known location on each peer (via `scp`, `rsync`, a config management system, or any other trusted channel). Each device stores the public keys of the peers it expects to talk to.

3. **During the DH exchange**, each side verifies that the DH public key received in the MIKEY message matches the pinned key for that peer. If it does not match, the exchange is rejected.

This is strictly opt-in. The default `DhInitiator` / `DhResponder` use ephemeral keys and perform no identity check. Identity checking is layered on top when you use `Identity` and `PinnedPeer`.

## Components

| Component | Role |
|---|---|
| `Identity` | Holds the local persistent keypair (`mykey.key` + `mykey.pub`) |
| `PinnedPeer` | Holds a peer's known public key; verifies incoming DH public keys |

See [Peer Key Pinning](pinning.md) for code examples and key distribution guidance.

## Threat model

Peer key pinning protects against:

- An attacker who can intercept and modify network traffic (classic MITM)
- A rogue device on the network that injects forged MIKEY messages

Peer key pinning does **not** protect against:

- Compromise of a pinned device's private key file (the attacker can impersonate the device)
- Compromise of the out-of-band distribution channel (the attacker can pin their own key)
- Denial of service (the attacker can drop all MIKEY messages)

For the threat models above, a full PKI with certificate authorities and revocation is the appropriate tool. mykey does not currently implement MIKEY-CERT mode. For AES67 studio deployments, peer key pinning is typically sufficient.
