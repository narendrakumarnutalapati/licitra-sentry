# Security Policy

## Supported Versions

| Version       | Supported |
|---------------|-----------|
| 0.1.x (MVP)  | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in LICITRA-SENTRY, please report
it responsibly:

1. **Do NOT open a public GitHub issue.**
2. Email: **narendra.nutalapati@outlook.com**
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
4. You will receive an acknowledgment within 48 hours.

## Scope

LICITRA-SENTRY is a research prototype demonstrating zero-trust governance
for agentic AI systems. It is designed for controlled environments and
academic evaluation. Do not deploy in production without additional
hardening (TLS, secret management, rate limiting, etc.).

## Cryptographic Assumptions

- **Identity layer**: Ed25519 signing via the cryptography library.
  Keys are held in-memory for the MVP. Production deployments should use
  HSM-backed key storage.
- **Audit integrity**: All audit events are committed to LICITRA-MMR
  (SHA-256, Merkle Mountain Range, epoch anchoring). LICITRA-SENTRY
  never stores its own ledger.
- **Content inspection**: Regex-based pattern matching only.
  Deterministic, no LLM dependency, no external API calls.
