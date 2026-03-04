# LICITRA-SENTRY v0.2.0

**Runtime Authorization, Tamper-Evident Audit, and Witnessed Transparency for Agentic AI Systems**

SENTRY is an open-source pre-execution authorization pipeline that cryptographically binds identity, content, semantic contracts, and authority enforcement before any agent action executes. Every decision — approved or rejected — is committed to an append-only hash-chained audit ledger and witnessed by an independent transparency log.

## What's New in v0.2

- **Execution Ticket System**: Ed25519-signed tickets cryptographically bind authorization decisions to exact request payloads
- **Tool Proxy Gateway**: Mandatory mediation layer — no tool execution without a valid ticket
- **Replay Protection**: SQLite-backed JTI tracking prevents ticket reuse
- **Witnessed Transparency Layer**: CT-style Signed Inclusion Receipts from an independent witness — external auditors verify without trusting the operator
- **Security Hardening**: Rate limiting, payload size limits, content inspection patterns

## Architecture

```
Agent Request
     │
┌────▼──────────────────────────────────────┐
│  SENTRY Authorization Pipeline            │
│                                           │
│  Gate 1: Identity Verification            │
│  Gate 2: Content Inspection               │
│  Gate 3: Semantic Contract Validation     │
│  Gate 4: Authority Enforcement            │
│  Gate 5: Cryptographic Commit + Ticket    │
└────┬──────────────────────────────────────┘
     │
     ▼ Execution Ticket (Ed25519 signed)
     │
┌────▼──────────────────────────────────────┐
│  Tool Proxy Gateway                       │
│                                           │
│  1. Verify signature                      │
│  2. Check expiration (60s max TTL)        │
│  3. Match audience (tool_id)              │
│  4. Match request hash (SHA-256)          │
│  5. Reject replays (JTI check)            │
└────┬──────────────────────────────────────┘
     │
     ▼ Tool Execution
     │
     ▼ Audit Event Committed
     │
     ▼ Epoch Witnessed (CT-style receipt)
```

## Threat Model

**Without witnesses:**
- Detects DB tampering if keys intact and operator honest
- Operator can rewrite history undetectably

**With witnesses (CT-style receipts):**
- Detects DB tampering even under operator compromise
- Rewriting history requires ALL witnesses to collude
- External auditors verify independently

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

## Test Suite (13 experiments)

| ID | Scenario | Tests |
|----|----------|-------|
| E01 | Authorized ticket flow | Full pipeline → ticket → proxy → execute |
| E02 | Proxy bypass attempt | Fake ticket rejected (signature invalid) |
| E03 | Replay attack | Reused ticket rejected (JTI already seen) |
| E04 | Payload modification | Modified request rejected (hash mismatch) |
| E05 | Expired ticket | TTL exceeded → rejected |
| E06 | Delegation escalation | Delegated agent blocked from unauthorized tool |
| E07 | PII exfiltration | SSN/CC patterns blocked by content inspection |
| E08 | Audit chain integrity | Hash chain verified across all events |
| E09 | Epoch witnessed | CT-style receipt issued, signature valid |
| E10 | Operator rewrite detected | Tampered root mismatches witness receipt |
| E11 | Auditor verification | Evidence bundle verified independently |
| E12 | Tampered receipt rejected | Forged witness signature detected |
| E13 | Chain break detected | Modified epoch chain flagged by verifier |

## Witnessed Transparency Layer

Every N audit events, an epoch finalizes and is submitted to an independent transparency log:

**What gets witnessed:**
- `epoch_root` — MMR root hash (audit state)
- `prev_epoch_root` — chain link to previous epoch
- `policy_hash` — SHA-256 of policy bundle (what rules were active)
- `sentry_build_hash` — git commit (what code was running)
- `event_count`, `timestamp`, `operator_id`

**What comes back:**
- Signed Inclusion Receipt (Ed25519, separate key from SENTRY)
- Log sequence number (monotonic)
- Log timestamp

**Auditor workflow:**
1. Receive evidence bundle (epoch records + receipts)
2. Receive transparency log's public key
3. Run `WitnessVerifier` — checks signatures, digests, chain continuity, monotonic ordering
4. No trust in operator required

## Execution Ticket Protocol

Each ticket contains:

| Field | Purpose |
|-------|---------|
| `sub` | Agent identity |
| `aud` | Target tool |
| `jti` | Unique ticket ID (replay protection) |
| `exp` | Expiration (max 60s TTL) |
| `request_hash` | SHA-256 of canonicalized request payload |
| `contract_id` | Semantic contract evaluated |
| `policy_version` | Policy version at authorization time |
| `mmr_commit_id` | Audit ledger commit for this authorization |

Modifying any byte of the request after authorization invalidates the hash. The proxy rejects it.

## Attacks Prevented

1. **Unauthorized tool invocation** — no valid ticket, no execution (E02)
2. **Payload modification** — hash mismatch detected (E04)
3. **Ticket replay** — JTI already used (E03)
4. **Privilege escalation via delegation** — contract + authority bounds (E06)
5. **PII/credential exfiltration** — content inspection blocks patterns (E07)
6. **Audit tampering** — hash chain detects modification (E08)
7. **Expired authorization** — 60s TTL enforced (E05)
8. **Operator history rewrite** — witness receipt contradicts (E10)

## Attacks NOT Prevented

1. **Full witness collusion** — if ALL witnesses collude with operator, history can be rewritten
2. **Semantic bypass** — content inspection is pattern-based, not semantic
3. **Key compromise** — forged tickets possible (but NOT forged witness receipts — separate key)
4. **Compromised tool** — proxy can't detect malicious behavior inside the tool
5. **Ticket revocation** — no revocation mechanism; 60s TTL bounds the risk
6. **Adversarial load** — not benchmarked under sustained attack

## Project Structure

```
app/
  key_manager.py        # Ed25519 key lifecycle (abstract KeyProvider interface)
  ticket.py             # Execution ticket issuance and verification
  tool_proxy.py         # Mandatory mediation gateway with replay protection
  witness.py            # CT-style transparency log + receipts + auditor verifier
  identity.py           # Gate 1: Identity verification
  content_inspector.py  # Gate 2: Content inspection
  contract.py           # Gate 3: Semantic contract validation
  authority.py          # Gate 4: Authority enforcement
  audit_bridge.py       # Gate 5: Cryptographic commit + epoch witnessing
  anchor.py             # External anchor module (pluggable)
  orchestrator.py       # Five-gate pipeline orchestrator

tests/
  test_sentry_v02.py    # 8 experiments (E01-E08)
  test_witness.py       # 5 experiments (E09-E13)

demo_ticket_execution.py  # Authorized send, PII blocked, delegation blocked
demo_witness.py           # Witnessed epochs, attack detection, auditor verification
```

## OWASP Agentic Top 10 Mapping

| ASI Category | SENTRY Control |
|-------------|----------------|
| ASI01: Agent Goal Hijack | Semantic contract limits scope |
| ASI02: Tool Misuse | Ticket request hash + content inspection |
| ASI03: Identity & Privilege Abuse | Identity + authority with delegation bounds |
| ASI04: Supply Chain | Identity rejects unregistered components |
| ASI05: Unexpected Code Execution | Content inspection + contract |
| ASI06: Memory & Context Poisoning | Hash-chained audit + witness receipts |
| ASI07: Insecure Inter-Agent Comm. | Identity at every boundary + audit |
| ASI08: Cascading Failures | Per-gate audit for failure tracing |
| ASI09: Human-Agent Trust | Authorization committed as verifiable artifacts |
| ASI10: Rogue Agents | Contract + authority + audit trail |

## References

- LICITRA-SENTRY v0.1 TR: [doi.org/10.5281/zenodo.18843784](https://doi.org/10.5281/zenodo.18843784)
- LICITRA-MMR TR: [doi.org/10.5281/zenodo.18843032](https://doi.org/10.5281/zenodo.18843032)
- OWASP Top 10 for Agentic Applications (2026): [genai.owasp.org](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)

## License

MIT License. See [LICENSE](LICENSE).

## Author

Narendra Kumar Nutalapati
- GitHub: [github.com/narendrakumarnutalapati](https://github.com/narendrakumarnutalapati)
