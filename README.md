# LICITRA-SENTRY v0.2.0

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.18860290.svg)](https://doi.org/10.5281/zenodo.18860290)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Research](https://img.shields.io/badge/type-security--research-blue)]()
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)]()
[![Tests](https://img.shields.io/badge/experiments-13%2F13%20pass-brightgreen)]()

**LICITRA-SENTRY is a runtime enforcement layer for AI agents that cryptographically binds authorization decisions to the exact request executed by a tool.**

SENTRY is an open-source pre-execution authorization pipeline that enforces identity verification, content inspection, semantic contracts, and authority enforcement before any agent action executes. Every decision — approved or rejected — is committed to an append-only hash-chained audit ledger and witnessed by an independent transparency log.

![Architecture](docs/architecture.png)

## Core Security Invariant

SENTRY enforces the following property for every agent tool execution:

```
H(authorized_request) = H(executed_request)
```

If the request reaching the tool differs from the request approved by the authorization pipeline, execution is rejected.

This prevents:
- **Payload modification** after authorization
- **Execution ticket replay**
- **Unauthorized tool invocation**
- **Delegation privilege escalation**

## Why This System Exists

Most AI security tooling focuses on **model behavior testing**: prompt injection testing, jailbreak detection, LLM red-teaming.

These approaches answer:

> *Can the model be tricked?*

Production systems must answer a different question:

> *Did the system execute exactly what was authorized?*

SENTRY provides a runtime enforcement layer that guarantees tool execution matches the authorization decision. No existing AI agent framework provides this property.

## What's New in v0.2

- **Execution Ticket System**: Ed25519-signed tickets cryptographically bind authorization decisions to exact request payloads
- **Tool Proxy Gateway**: Mandatory mediation layer — no tool execution without a valid ticket
- **Replay Protection**: SQLite-backed JTI tracking prevents ticket reuse
- **Witnessed Transparency Layer**: CT-style Signed Inclusion Receipts from an independent witness — external auditors verify without trusting the operator
- **Policy Version Checking**: Tickets issued under old policies are rejected when policy updates
- **Security Hardening**: Rate limiting, payload size limits, content inspection patterns

## Architecture

```
Agent Request
     │
     ▼
┌─────────────────────────────────────────┐
│  SENTRY Authorization Pipeline          │
│                                         │
│  Gate 1: Identity Verification          │
│  Gate 2: Content Inspection             │
│  Gate 3: Semantic Contract Validation   │
│  Gate 4: Authority Enforcement          │
│  Gate 5: Cryptographic Commit + Ticket  │
└───────────────┬─────────────────────────┘
                │
                ▼
      Execution Ticket (Ed25519 signed)
                │
                ▼
┌─────────────────────────────────────────┐
│  Tool Proxy Gateway                     │
│                                         │
│  1. Verify Ed25519 signature            │
│  2. Check expiration (60s max TTL)      │
│  3. Match audience (tool_id)            │
│  4. Verify request hash (SHA-256)       │
│  5. Check policy version                │
│  6. Reject replays (JTI store)          │
└───────────────┬─────────────────────────┘
                │
                ▼
           Tool Execution
                │
                ▼
        Audit Ledger Commit (MMR)
                │
                ▼
     Witness Transparency Receipt (CT-style)
```

## Quick Start

```bash
pip install -r requirements.txt

# Run all tests (13/13)
python tests/test_sentry_v02.py
python tests/test_witness.py

# Run demos
python demo_ticket_execution.py
python demo_witness.py
```

## Demo Scenarios

### Payload Modification Attack

```
Authorized:  send_email(to="alice@example.com", body="Meeting at 3pm")
Modified:    send_email(to="attacker@evil.com", body="Send credentials")

Result: REJECTED — request hash mismatch (SHA-256 divergence)
```

### Replay Attack

```
First use:   Ticket accepted, tool executed
Second use:  REJECTED — JTI already used

Result: Replay blocked
```

### Delegation Escalation

```
Agent-alpha: authorized for email-sender
Agent-beta:  delegated from alpha, contract allows only db-reader

Agent-beta attempts email-sender → REJECTED (contract violation, no ticket issued)
```

## Threat Model

### Without witnesses
- Detects DB tampering if keys intact and operator honest
- Operator can rewrite history undetectably

### With witnesses (CT-style receipts)
- Detects DB tampering even under operator compromise
- Rewriting history requires ALL witnesses to collude
- External auditors verify independently using witness public key only

## Test Suite (13 Experiments)

| ID  | Scenario | Security Property Validated |
|-----|----------|----------------------------|
| E01 | Authorized ticket flow | End-to-end pipeline → ticket → proxy → execute |
| E02 | Proxy bypass attempt | Execution requires valid Ed25519 signature |
| E03 | Replay attack | JTI uniqueness prevents ticket reuse |
| E04 | Payload modification | SHA-256 hash binding detects changes |
| E05 | Expired ticket | 60-second TTL enforced |
| E06 | Delegation escalation | Permission intersection prevents escalation |
| E07 | PII exfiltration | Content inspection blocks SSN/CC patterns |
| E08 | Audit chain integrity | Hash chain verified across all events |
| E09 | Epoch witnessed | CT-style receipt issued and verified |
| E10 | Operator rewrite detected | Tampered root mismatches witness receipt |
| E11 | Auditor verification | Evidence bundle verified independently |
| E12 | Tampered receipt rejected | Forged witness signature detected |
| E13 | Chain break detected | Modified epoch chain flagged |

## Execution Ticket Protocol

Each ticket contains:

| Field | Purpose |
|-------|---------|
| `sub` | Agent identity |
| `aud` | Target tool |
| `jti` | Unique ticket ID (UUID v4) |
| `exp` | Expiration (max 60s TTL) |
| `request_hash` | SHA-256 of canonicalized request |
| `policy_version` | Policy version at authorization time |
| `contract_id` | Semantic contract evaluated |
| `mmr_commit_id` | Audit ledger commit hash |

Modifying any byte of the request after authorization invalidates the hash. The proxy rejects it.

## Witnessed Transparency Layer

Every N audit events, an epoch finalizes and is submitted to an independent transparency log.

**What gets witnessed:**
- `epoch_root` — MMR root hash (current audit state)
- `prev_epoch_root` — chain link to previous epoch
- `policy_hash` — SHA-256 of active policy bundle
- `sentry_build_hash` — git commit of running code
- `event_count`, `timestamp`, `operator_id`

**What comes back:**
- Signed Inclusion Receipt (Ed25519, separate key from SENTRY)
- Log sequence number (monotonic)
- Log timestamp

**Auditor workflow:**
1. Receive evidence bundle (epoch records + receipts)
2. Receive transparency log public key
3. Run `WitnessVerifier` — checks signatures, digests, chain continuity
4. No trust in operator required

## Attacks Prevented

- **Unauthorized tool invocation** — no valid ticket, no execution
- **Payload modification** — hash mismatch detected
- **Ticket replay** — JTI already used
- **Privilege escalation via delegation** — contract + authority bounds
- **PII/credential exfiltration** — content inspection blocks patterns
- **Audit tampering** — hash chain detects modification
- **Expired authorization** — TTL enforced
- **Operator history rewrite** — witness receipt contradicts

## Attacks NOT Prevented

- Full witness collusion
- Semantic bypass of content inspection (regex, not semantic)
- SENTRY key compromise (witness key remains safe — separate key)
- Compromised tool behavior (request integrity, not response integrity)
- Ticket revocation before expiry (bounded by 60s TTL)
- Adversarial load attacks (not benchmarked)
- **Decision correctness** — system guarantees `authorized_action == executed_action` but NOT that the authorized action is safe

## Position in the AI Security Stack

| Layer | Example Tools | Purpose |
|-------|--------------|---------|
| Model testing | Promptfoo, Garak | Detect prompt vulnerabilities |
| Policy evaluation | Guardrails, Cedar engines | Check if a request should be allowed |
| **Runtime enforcement** | **LICITRA-SENTRY** | **Guarantee authorized request = executed request** |
| Audit transparency | CT logs, witness services | Provide independently verifiable history |

## OWASP Agentic Top 10 Mapping

| ASI Category | SENTRY Control | Effectiveness |
|-------------|----------------|---------------|
| ASI01: Agent Goal Hijack | Semantic contract limits scope | Partial |
| ASI02: Tool Misuse | Ticket request hash + content inspection | **Strong** |
| ASI03: Identity & Privilege Abuse | Identity + authority with delegation bounds | **Strong** |
| ASI04: Supply Chain | Identity rejects unregistered components | Partial |
| ASI05: Unexpected Code Execution | Content inspection + contract scope | Moderate |
| ASI06: Memory & Context Poisoning | Hash-chained audit + witness receipts | **Strong** |
| ASI07: Insecure Inter-Agent Comm. | Identity at every boundary + audit | Moderate |
| ASI08: Cascading Failures | Per-gate audit for failure tracing | Moderate |
| ASI09: Human-Agent Trust Exploitation | Authorization committed as verifiable artifacts | **Strong** |
| ASI10: Rogue Agents | Contract + authority + audit trail | Moderate |

## Project Structure

```
app/
  key_manager.py        # Ed25519 key generation and management
  ticket.py             # Execution ticket issuance and verification
  tool_proxy.py         # Mandatory mediation proxy gateway
  witness.py            # Witnessed transparency layer
  identity.py           # Agent identity verification (Gate 1)
  content_inspector.py  # Content inspection (Gate 2)
  contract.py           # Semantic contract validation (Gate 3)
  authority.py          # Authority enforcement (Gate 4)
  audit_bridge.py       # Audit ledger interface (Gate 5)
  anchor.py             # External anchoring interface
  orchestrator.py       # Pipeline orchestration

tests/
  test_sentry_v02.py    # Core experiments (E01-E08)
  test_witness.py       # Witness experiments (E09-E13)

demo_ticket_execution.py  # Interactive execution ticket demo
demo_witness.py           # Interactive witness transparency demo
```

## Technical Reports

- **SENTRY v0.2** — Execution tickets + witnessed transparency: [DOI 10.5281/zenodo.18860290](https://doi.org/10.5281/zenodo.18860290)
- **SENTRY v0.1** — Chain of Intent authorization pipeline: [DOI 10.5281/zenodo.18843784](https://doi.org/10.5281/zenodo.18843784)
- **MMR Core** — Tamper-evident audit ledger: [DOI 10.5281/zenodo.18843032](https://doi.org/10.5281/zenodo.18843032)

## Citation

If you use LICITRA-SENTRY in research, please cite:

```bibtex
@misc{licitra_sentry_v02,
  author = {Narendra Kumar Nutalapati},
  title  = {LICITRA-SENTRY v0.2: Execution Ticket System and Witnessed Transparency for Agentic AI Authorization},
  year   = {2026},
  doi    = {10.5281/zenodo.18860290},
  url    = {https://github.com/narendrakumarnutalapati/licitra-sentry}
}
```

## References

- [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [Certificate Transparency — RFC 6962](https://datatracker.ietf.org/doc/html/rfc6962)
- [Saltzer & Schroeder — Protection of Information in Computer Systems (1975)](https://ieeexplore.ieee.org/document/1451869)
- [Crosby & Wallach — Efficient Data Structures for Tamper-Evident Logging (2009)](https://www.usenix.org/legacy/events/sec09/tech/full_papers/crosby.pdf)

## License

[MIT License](LICENSE)

## Author

Narendra Kumar Nutalapati
- GitHub: [narendrakumarnutalapati](https://github.com/narendrakumarnutalapati)
- LinkedIn: [narendralicitra](https://linkedin.com/in/narendralicitra)
- OWASP: [Issue #802 — ASI01-ASI10 Runtime Enforcement Mapping](https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/issues/802)
