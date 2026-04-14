# Security Policy

## Scope

mykey is a cryptographic library. Security issues in this project include:

- Incorrect implementation of RFC 3830 (MIKEY) that could leak key material
- Flaws in the MIKEY PRF or SRTP key derivation
- Vulnerabilities in the X25519 DH exchange or PSK MAC verification
- Timing side-channels in MAC verification or key comparison
- Weaknesses in the persistent identity / peer key pinning logic
- Unsafe handling of private key files (permissions, exposure in logs or errors)
- Parsing bugs that could cause panics, memory corruption, or acceptance of invalid messages

Issues in downstream dependencies (x25519-dalek, hmac, sha2, aes, rand) should be reported to those projects directly. If you believe a dependency issue has a specific impact on mykey, include that context in your report.

## Dependency Advisories

Known advisories that have been addressed in this project:

| Advisory | Affected crate | Fixed in mykey |
|---|---|---|
| [RUSTSEC-2026-0097](https://rustsec.org/advisories/RUSTSEC-2026-0097) — rand unsound with custom logger | `rand` < 0.9 | 0.2.1 (upgraded to rand 0.9) |

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Report security issues privately via GitHub's Security Advisory feature:

1. Go to the [Security tab](https://github.com/waxspin/mykey/security) of the repository
2. Click **"Report a vulnerability"**
3. Fill in the details — a clear description, reproduction steps, and your assessment of impact

You should receive an acknowledgement within **72 hours**. If you do not hear back, follow up by opening a blank issue noting that you have submitted a private report.

## What to Include

A useful report contains:

- A description of the vulnerability and the conditions under which it is exploitable
- A minimal reproducer (code or message bytes) if possible
- Your assessment of severity and impact
- Whether you have a proposed fix — patches are welcome but not required

## Disclosure Policy

- We will acknowledge receipt within 72 hours
- We will confirm whether the issue is valid and in scope within 7 days
- We aim to release a fix within 30 days of confirmation for issues with known exploits
- We will coordinate a disclosure date with you before publishing details publicly
- Credit will be given in the release notes and changelog unless you prefer to remain anonymous

## Cryptographic Design Notes

A few properties of the library that are relevant to assessing severity:

**Ephemeral DH mode** provides forward secrecy but no peer authentication by default. An active MITM is possible if peer key pinning is not used. This is a documented design decision, not a vulnerability — but a bug that silently bypasses pinning when it is configured would be a serious issue.

**PSK mode** relies entirely on the security of the shared key and the integrity of how it was distributed. A bug in the MAC verification that accepted messages with a wrong or absent MAC would be critical.

**Key files** (`mykey.key`) are the trust anchor for persistent identity. Any bug that causes private key material to be written to an unprotected location, logged, or included in error messages should be treated as high severity.

## Supported Versions

Only the latest released version on crates.io is actively supported with security fixes. If you are running an older version, upgrade first and verify whether the issue is still present.
