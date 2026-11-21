<!-- Developed by Syed Muhammad Tayyab -->
# 🔐 Security policy

Cyber Hub is a security tool, so its own security matters a lot. Thank you for helping keep it safe.

## Supported versions
| Version | Supported |
|---|:-:|
| 1.0.x | ✅ |
| < 1.0 (build parts) | ❌ |

## Reporting a vulnerability
**Please do not open a public issue.** Report it privately through
**[GitHub Security Advisories](https://github.com/Syed-Muhammad-Tayyab/Cyber-Hub/security/advisories/new)**.

Please include:
- what an attacker could do, and under which conditions (local user? another website? the network?)
- steps to reproduce, or a proof of concept
- the Cyber Hub and Windows versions

You can expect a first reply within **7 days**. Once a fix is released you'll be credited, if you wish.

## In scope
- Ways for another website, program or user to use the engine's API without the token or a session
- Reading vault items, keys or quarantined files without the right password or key
- Command or script injection (PowerShell, SQL, CSV)
- Lowering protection without administrator rights
- Anything that makes Cyber Hub send data online when that feature is switched off

## Out of scope
- Attacks that already need administrator rights or full control of the user's account
- Missing hardening that is documented as a known limit (for example: real-time protection scans files after they are written, it does not block them before they are opened)

---
<sub>Cyber Hub · Developed by Syed Muhammad Tayyab</sub>
