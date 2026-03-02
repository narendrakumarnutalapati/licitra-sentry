# LICITRA-SENTRY

**Zero-Trust Inter-Agent Communication Control Plane**

Part of the [LICITRA Research Program](https://github.com/narendrakumarnutalapati/licitra-mmr-core) for cryptographic runtime governance of agentic AI systems.

## LICITRA Research Program
```
LICITRA (umbrella research program)
├── LICITRA-MMR     → Integrity Layer
│                     Merkle Mountain Range, epoch anchoring,
│                     tamper-evident audit storage
│                     Status: COMPLETE, production-grade, 11/11 tests
│                     Paper: ACNS-ISC 2026 Submission 10
│
└── LICITRA-SENTRY  → Zero-Trust Control Plane (THIS REPO)
                      Identity attestation, content inspection,
                      semantic contracts, authority enforcement,
                      orchestration guard, audit bridge to MMR
                      Status: COMPLETE, 9/9 tests, 10/10 OWASP
```

## Chain of Intent

Every inter-agent communication passes through sequential cryptographic gates, each recorded in LICITRA-MMR:
```
┌──────────────────────────────────────────────────────────────┐
│                      LICITRA-SENTRY                          │
│  Identity   Content    Contract   Authority   Orchestration  │
│  Notary     Inspector  Engine     Gate        Guard          │
│     │          │          │          │            │           │
│     ▼          ▼          ▼          ▼            ▼           │
│  Ed25519    Regex      Pydantic   Token +     Delegation     │
│  tokens     patterns   semantic   contract    policy +       │
│  (ASI03)    (ASI01)    validation enforcement privilege      │
│                        (ASI01,02) (ASI02)     check (ASI05)  │
└──────────────────────────────┬───────────────────────────────┘
                               │ POST /agent/propose
                               │ POST /agent/commit/{staged_id}
┌──────────────────────────────▼───────────────────────────────┐
│                      LICITRA-MMR                             │
│  Canonical JSON → SHA-256 → MMR → Epoch Chain                │
│  Tamper-evident, cryptographically verifiable                │
└──────────────────────────────────────────────────────────────┘
```

If any gate deviates, the audit trail in LICITRA-MMR exposes the mismatch. The chain is only as strong as its weakest link — and every link is cryptographically recorded.

## OWASP Agentic Top 10 Coverage

| OWASP ID | Category | LICITRA-SENTRY Gate | Status |
|----------|----------|-------------------|--------|
| ASI01 | Prompt Injection / Relay Injection | Content Inspector + Contract Engine | ✅ Covered |
| ASI02 | Excessive Agency | Contract Engine + Authority Gate | ✅ Covered |
| ASI03 | Agent Impersonation | Identity Notary (Ed25519) | ✅ Covered |
| ASI04 | Insecure Output Handling | Audit Bridge → MMR | ✅ Covered |
| ASI05 | Improper Multi-Agent Orchestration | Orchestration Guard (delegation policy + privilege non-escalation) | ✅ Covered |
| ASI06 | Sensitive Data Exposure | Content Inspector + Contract Engine | ✅ Covered |
| ASI07 | Inter-Agent Communication Integrity | Middleware Pipeline + MMR | ✅ Covered |
| ASI08 | Audit and Logging Failures | Audit Bridge + LICITRA-MMR | ✅ Covered |
| ASI09 | Insufficient Access Controls | Authority Gate (least-privilege per agent) | ✅ Covered |
| ASI10 | Uncontrolled Agent Proliferation | Identity Registry | ✅ Covered |

**Coverage: 10/10 categories explicitly addressed.**

## Competitive Comparison vs Oktsec

| Capability | Oktsec (Go, GPL-3.0) | LICITRA-SENTRY (Python, MIT) |
|-----------|---------------------|---------------------------|
| Identity layer | Ed25519 | Ed25519 |
| Content inspection | YAML rule-based | YAML rule-based (22 rules) |
| Hash logging | SHA-256 flat log | SHA-256 → MMR → Epoch chain |
| Audit structure | Flat append log | Merkle Mountain Range |
| Proof size | O(n) | O(log n) |
| Pre-execution validation | No | Semantic contract engine |
| Parameter shape validation | No | Pydantic-based |
| Proof of authorization | No | Authority gate + MMR |
| Delegation control | No | Orchestration guard |
| Formal intent validation | No | Contract validator |
| OWASP coverage | 7/10 | 10/10 |
| License | GPL-3.0 | MIT |

## Architectural Differentiation

LICITRA-SENTRY implements everything Oktsec does and goes further. Where Oktsec provides proof of message (did this message pass through the filter?), LICITRA-SENTRY provides proof of authorization (was this agent allowed to perform this action, and was the decision cryptographically anchored?). The semantic contract engine validates intents before execution, not just content after arrival.

The MMR-backed audit layer provides logarithmic proof size for any single event, meaning verification cost grows as O(log n) rather than O(n). Combined with epoch anchoring from LICITRA-MMR, any auditor can prove the complete state of the ledger at any point in time without replaying the entire history. The orchestration guard prevents privilege laundering across agent boundaries — an agent cannot delegate tasks it is not itself authorized to perform.

## Components

| Module | Purpose | OWASP |
|--------|---------|-------|
| `app/identity.py` | Ed25519 identity attestation, short-lived tokens | ASI03, ASI10 |
| `app/content_inspector.py` | Regex-based content inspection (22 rules) | ASI01, ASI06, ASI07 |
| `app/contract.py` | Pydantic semantic contract validation | ASI01, ASI02, ASI06 |
| `app/authority.py` | Authority gate (token + contract enforcement) | ASI02, ASI09 |
| `app/orchestration.py` | Delegation policy + privilege non-escalation | ASI05 |
| `app/middleware.py` | Chain of Intent pipeline | ASI07 |
| `app/audit_bridge.py` | 2-phase commit bridge to LICITRA-MMR | ASI04, ASI08 |

## Reproducible Experiments

Individual experiment scripts are in the `experiments/` folder. Each is standalone and self-contained.

| Script | Experiment | OWASP |
|--------|-----------|-------|
| `experiments/run_exp01_happy_path.py` | EXP-01: Happy Path — Approved | ASI07 |
| `experiments/run_exp02_contract_rejection.py` | EXP-02: Contract Rejection | ASI02 |
| `experiments/run_exp03_identity_expiry.py` | EXP-03: Identity Expiry Rejection | ASI03 |
| `experiments/run_exp04_relay_injection.py` | EXP-04: Relay Injection Blocked | ASI01 |
| `experiments/run_exp05_pii_exfiltration.py` | EXP-05: PII Exfiltration Blocked | ASI06 |
| `experiments/run_exp06_unauthorized_delegation.py` | EXP-06: Unauthorized Delegation Blocked | ASI05 |

Run a single experiment:
```bash
python experiments/run_exp01_happy_path.py
```

Run all 6 experiments:
```bash
python experiments/run_all_experiments.py
```

Each experiment prints its decision, gate fired, MMR leaf_hash, and verdict (CONFIRMED/FAILED).

## Quickstart

### Prerequisites

- Python 3.12+
- LICITRA-MMR running at `http://localhost:8000`

### Install
```bash
cd licitra-sentry
pip install -r requirements.txt
```

### Start LICITRA-MMR (separate terminal)
```bash
cd licitra-mmr-core
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### Run Demo
```bash
python demo_swarm.py
```

### Run Tests
```powershell
powershell -ExecutionPolicy Bypass -File tests\run_all_tests.ps1
```

## Demo Scenarios

| Scenario | Agent | Intent | Expected | OWASP |
|----------|-------|--------|----------|-------|
| S1 | Researcher | READ | APPROVED | ASI07 |
| S2 | Researcher | FILE_WRITE | REJECTED (contract) | ASI02 |
| S3 | Researcher | READ (expired token) | REJECTED (identity) | ASI03 |
| S4 | Researcher | READ (relay injection) | REJECTED (inspector) | ASI01 |
| S5 | Researcher | SUMMARIZE (SSN in msg) | REJECTED (inspector) | ASI06 |
| S6 | Coder | FILE_WRITE (delegate to researcher) | REJECTED (orchestration) | ASI05 |

## Test Results

| Test | Description | Status |
|------|------------|--------|
| t01_identity | Token issuance, verification, expiry, unknown agent | ✅ PASS |
| t02_contract | Allowed/unknown intent, tool, parameter shape | ✅ PASS |
| t03_authority | Approved path, expired token, disallowed intent/tool | ✅ PASS |
| t04_content_inspector | Clean msg, relay injection, PII, prompt injection, privilege escalation | ✅ PASS |
| t05_middleware | Approved path, rejected path, inspection blocked, all to MMR | ✅ PASS |
| t06_audit_bridge | Emit produces staged_id + event_id, leaf_hash 64 hex | ✅ PASS |
| t07_swarm_scenarios | All 6 scenarios, MMR leaf_hash confirmed | ✅ PASS |
| t08_determinism | Same inputs → same outputs always | ✅ PASS |
| t09_owasp_coverage | ASI01-ASI10 all gates confirmed, MMR leaf_hash per block | ✅ PASS |

**9/9 tests passing.**


## MMR Paper Future Scope Fulfillment

The LICITRA-MMR paper (ACNS-ISC 2026, Submission 10) identified four limitations in Section 10. LICITRA-SENTRY directly addresses two of them:

| MMR Paper Section | Limitation | Addressed By | Status |
|------------------|-----------|-------------|--------|
| 10.1 | Float Normalization Gap (RFC 8785 S3.2.2) | LICITRA-MMR v1.1 (planned) | Future |
| 10.2 | Unsigned Epoch Roots (Ed25519 signing) | SENTRY `app/identity.py` - Ed25519 CovenantNotary | Implemented |
| 10.3 | Single-Operator Trust (multi-party witnessing) | Multi-party witnessing protocol (planned) | Future |
| 10.4 | Pre-Execution Integrity (semantic contracts) | SENTRY Chain of Intent - full pipeline | Implemented |

**Section 10.2 - Ed25519 Identity:** The MMR paper noted epoch hashes were not signed. SENTRY introduces Ed25519 cryptographic signing at the agent session level via the CovenantNotary.

**Section 10.4 - Chain of Intent:** The MMR paper explicitly identified SENTRY as the solution: LICITRA-SENTRY intercepts agent actions before they reach the commit pipeline, evaluates them against declarative per-agent semantic contracts, and binds the authorization decision to the MMR record in the same transaction. This is exactly what the Chain of Intent pipeline implements with commitment-before-execution and cryptographic evidence of policy evaluation.

## License

MIT — see [LICENSE](LICENSE).

## Author

Narendra Kumar Nutalapati

## Related

- [LICITRA-MMR](https://github.com/narendrakumarnutalapati/licitra-mmr-core) — Cryptographic integrity layer
- [LICITRA-SENTRY Evidence](https://github.com/narendrakumarnutalapati/licitra-sentry-evidence) — Reproducible experiments and evidence bundles
