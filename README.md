# LICITRA-SENTRY v0.2

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.18860290.svg)](https://doi.org/10.5281/zenodo.18860290)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)]()
[![Tests](https://img.shields.io/badge/tests-13%2F13%20pass-brightgreen)]()
[![Experiments](https://img.shields.io/badge/experiments-10%2F10%20pass-brightgreen)]()

**LICITRA-SENTRY enforces execution integrity for AI agents: if a request changes after authorization, execution is cryptographically rejected.**

Every authorization decision — approved or rejected — is recorded in a tamper-evident audit chain and can be independently verified through witness receipts.

---

## Core Security Invariant

```text
H(authorized_request) = H(executed_request)
```

**This enforces:**

- No payload modification after authorization
- No execution ticket replay
- No unauthorized tool invocation
- No delegation privilege escalation

In most agent architectures, authorization and execution are decoupled — a request can be modified between policy evaluation and tool invocation without detection. SENTRY binds them cryptographically.

---

## Architecture

![LICITRA-SENTRY Architecture](docs/architecture.png)

*Figure 1 — LICITRA-SENTRY authorization pipeline enforcing complete mediation for AI agent tool execution.*

The pipeline enforces mandatory mediation: no tool is reachable without passing through the full authorization chain. Every tool invocation traverses identity verification → content inspection → semantic contract validation → authority enforcement → audit commitment. After authorization, an Ed25519-signed `ExecutionTicket` binds the decision to the exact request payload. The `ToolProxy` recomputes the hash at execution time.

If the proxy is bypassed (e.g., an agent reaches a tool directly), the enforcement model collapses. Network-level isolation (Kubernetes NetworkPolicy, Docker network segmentation) is required to close this gap in production.

**Core components:**

| Component | Role |
|---|---|
| `IdentityVerifier` | Gate 1 — agent identity verification |
| `ContentInspector` | Gate 2 — content inspection (PII, injection) |
| `ContractValidator` | Gate 3 — semantic policy enforcement |
| `AuthorityEnforcer` | Gate 4 — permission and delegation control |
| `SentryOrchestrator` | End-to-end pipeline orchestration |
| `ExecutionTicket` | Ed25519-signed authorization bound to request |
| `ToolProxy` | Mandatory mediation gateway |
| `AuditBridge` | Append-only audit commit and epoch anchoring |
| `WitnessClient` / `WitnessVerifier` | External verifiability layer |

---

## Validation Model

LICITRA-SENTRY has two validation layers. Understanding the boundary is essential for reproducibility.

**Test suite (E01–E13):** Validates enforcement logic. Does not require LICITRA-MMR. Deterministic under the supported repository setup (Python 3.10+, dependencies from `requirements.txt`, Windows/PowerShell and Linux shell environments).

**Experiment suite (EXP-01–EXP-10):** Validates the full integrated system including audit commitment to LICITRA-MMR. EXP-07 and EXP-10 require a running MMR instance. Results are mode-dependent (see [Experiment Mode Behavior](#experiment-mode-behavior)).

The test suite proves enforcement logic is correct. The experiment suite proves it holds under real audit infrastructure. Both are necessary.

---

## Quick Start

LICITRA-SENTRY depends on LICITRA-MMR for audit commitment and proof generation. Without MMR, enforcement works — but audit verifiability is incomplete.

```bash
pip install -r requirements.txt
```

**Start LICITRA-MMR** (required for full experiment coverage):

```powershell
cd licitra-mmr-core

# Select environment mode:

# Production-like mode (no dev endpoints)
.\scripts\switch_env.ps1 -mode default

# OR: Experiment mode (required for full SENTRY experiment coverage)
.\scripts\switch_env.ps1 -mode experiment

# Start MMR server
.\scripts\run_server.ps1
```

> **Important:**
>
> - LICITRA-MMR must be running continuously while executing SENTRY experiments.
> - `experiment` mode is the recommended setup for EXP-07 and EXP-10 because it sets `BLOCK_SIZE=2`, making MMR proofs immediately available.
> - `default` mode will cause these experiments to be skipped due to block finalization constraints.

Verify: `curl http://localhost:8000/health` or `Invoke-RestMethod http://localhost:8000/health`

Expected response (experiment mode):

```json
{
  "status": "ok",
  "ledger_version": "mmr-v0.1",
  "block_size": 2,
  "dev_mode": true,
  "ledger_mode": "experiment"
}
```

Expected response (default mode):

```json
{
  "status": "ok",
  "ledger_version": "mmr-v0.1",
  "block_size": 1000,
  "dev_mode": false,
  "ledger_mode": "default"
}
```

**Run validation** (from the `licitra-sentry` repository root):

```bash
# Tests (no MMR required)
powershell -ExecutionPolicy Bypass -File .\tests\run_all_tests.ps1

# Experiments (MMR required for full coverage)
python -m experiments.run_all_experiments

# Benchmarks
python -m experiments.benchmark_suite

# Demos
python demo_ticket_execution.py
python demo_witness.py
```

> The test suite (E01–E13) does not require LICITRA-MMR. Only the experiment suite requires it for full coverage.

---

## One-Command Pipeline (Recommended)

LICITRA-SENTRY provides a fully reproducible end-to-end pipeline. This is the authoritative way to evaluate the system.

Run the complete system (tests, experiments, benchmarks, and evidence) with a single command:

```bash
python scripts/run_all.py
```

This executes:

1. Runtime validation tests (E01–E13)
2. Security experiment suite (EXP-01–EXP-10)
3. Performance benchmarks
4. Evidence bundle generation (JSON + PDF per test, experiment, and benchmark)
5. Evidence manifest generation

All artifacts are written to:

```
artifacts/runs/<run_id>/
```

Latest results are mirrored to:

```
artifacts/latest/
```

Evidence manifest: `artifacts/latest/evidence_manifest.json`

> **Note:** LICITRA-MMR must be running for full experiment coverage. Tests run regardless of MMR availability.

---

## Experiment Mode Behavior

Experiments are designed to be run with LICITRA-MMR active.

### Default Mode (`BLOCK_SIZE=1000`, `DEV_MODE=false`)

| Experiment | Result | Notes |
|---|---|---|
| EXP-01 through EXP-06 | **pass** | Enforcement logic validated; audit committed |
| EXP-07 | **skipped** | Block not finalized at `BLOCK_SIZE=1000` |
| EXP-08, EXP-09 | **pass** | Replay and tampering detection validated |
| EXP-10 | **skipped** | Requires finalized MMR proof |

### Experiment Mode (`BLOCK_SIZE=2`, `DEV_MODE=true`)

| Experiment | Result | Notes |
|---|---|---|
| EXP-01 through EXP-10 | **all pass** | Full end-to-end validation including MMR proofs |

EXP-07 and EXP-10 require a finalized MMR block. At `BLOCK_SIZE=1000`, the block won't finalize until 1000 events are committed. At `BLOCK_SIZE=2`, proofs are immediately available. The skip in default mode is a timing constraint, not a failure. Enforcement correctness is independent of MMR mode; only proof availability is mode-dependent.

---

## Test Suite (13 Security Tests)

```powershell
powershell -ExecutionPolicy Bypass -File .\tests\run_all_tests.ps1
```

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

Legacy compatibility tests are retained under `tests/legacy/` for historical reference only.

---

## Experiment Suite (10 Experiments)

```bash
python -m experiments.run_all_experiments
```

| ID | Scenario | Security Property | MMR Required |
|---|---|---|---|
| EXP-01 | Authorized execution path | Full pipeline success | No |
| EXP-02 | Contract rejection | Semantic policy enforcement | No |
| EXP-03 | Identity expiration | Credential validity enforcement | No |
| EXP-04 | Relay injection attack | Unauthorized execution blocked | No |
| EXP-05 | PII exfiltration attempt | Content inspection protection | No |
| EXP-06 | Unauthorized delegation | Delegation privilege bounds | No |
| EXP-07 | End-to-end MMR proof validation | Cryptographic audit commitment | **Yes** |
| EXP-08 | Ticket replay attack | JTI replay protection | No |
| EXP-09 | Payload tampering | Request hash binding | No |
| EXP-10 | Audit tampering attempt | Hash-chain integrity detection | **Yes** |

---

## Performance Benchmarks

```bash
python -m experiments.benchmark_suite
```

Representative benchmarks from a local development run (`artifacts/latest/benchmarks/benchmark_report.json`):

| Benchmark | Result |
|---|---|
| Sequential full pipeline | 221 requests/sec |
| Concurrent full pipeline | 329 requests/sec |
| Replay second execution | rejected |
| Payload tampering | rejected |

| Metric | Sequential | Concurrent |
|---|---|---|
| p50 | 4.352 ms | 60.087 ms |
| p95 | 5.850 ms | 66.833 ms |
| p99 | 7.450 ms | 79.836 ms |

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

## Witnessed Transparency Layer

Every N audit events, an epoch finalizes and is submitted to an independent transparency log.

**What gets witnessed:** `epoch_root`, `prev_epoch_root`, `policy_hash`, `sentry_build_hash`, `event_count`, `timestamp`, `operator_id`

**What comes back:** Signed Inclusion Receipt (Ed25519, separate key from SENTRY), log sequence number, log timestamp.

**Auditor workflow:** Receive evidence bundle → receive transparency log public key → run `WitnessVerifier` → verify signatures, digests, and chain continuity without trusting the operator.

---

## Threat Model

| Scenario | Without Witnesses | With Witnesses |
|---|---|---|
| DB tampering | Detectable if keys intact and operator honest | Detectable even under operator compromise |
| History rewrite | Operator can potentially rewrite history undetected | Detectable unless operator and witness collude |
| External audit | Relies on operator trust | Independent verification possible |

---

## Attacks Prevented

| Attack | Mechanism | Tests |
|---|---|---|
| Unauthorized tool invocation | No valid ticket → no execution | E02 / EXP-04 |
| Payload modification | Hash mismatch detected | E04 / EXP-09 |
| Ticket replay | JTI already used | E03 / EXP-08 |
| Privilege escalation via delegation | Contract + authority bounds | E06 / EXP-06 |
| PII/credential exfiltration | Content inspection blocks patterns | E07 / EXP-05 |
| Audit tampering | Hash chain detects modification | E08 / EXP-10 |
| Expired authorization | TTL enforced | E05 / EXP-03 |
| Operator history rewrite | Witness receipt contradicts tampered epoch | E10 |

**Attacks NOT prevented:** full witness collusion, semantic bypass of regex-based content inspection, authorization key compromise, compromised tool behavior after valid execution, immediate ticket revocation before expiry, adversarial load beyond benchmark scope, decision correctness itself — SENTRY guarantees `authorized_request == executed_request`, not that every authorization is inherently safe.

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

See also: [OWASP Issue #802 — Runtime Enforcement Mapping](https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/issues/802)

---

## Project Structure

```text
licitra-sentry/
├── app/                                # Core runtime authorization system
│   ├── __init__.py
│   ├── identity.py                     # Gate 1: Agent identity verification
│   ├── content_inspector.py            # Gate 2: Content inspection (PII, injection)
│   ├── contract.py                     # Gate 3: Semantic contract validation
│   ├── authority.py                    # Gate 4: Authority + delegation enforcement
│   ├── audit_bridge.py                 # Gate 5: Audit ledger integration
│   ├── orchestrator.py                 # Chain-of-Intent pipeline orchestration
│   ├── orchestration.py                # Multi-agent orchestration support
│   ├── middleware.py                   # Request middleware layer
│   ├── key_manager.py                  # Ed25519 key management
│   ├── ticket.py                       # Execution ticket issuance and signing
│   ├── tool_proxy.py                   # Mandatory mediation gateway
│   ├── witness.py                      # Witnessed transparency layer
│   ├── anchor.py                       # External anchoring interface
│   └── version.py                      # Version metadata
│
├── tests/                              # Authoritative runtime validation
│   ├── test_sentry_v02.py              # E01–E08 runtime enforcement tests
│   ├── test_witness.py                 # E09–E13 witness transparency tests
│   ├── run_all_tests.ps1               # Test runner
│   └── legacy/                         # Legacy v0.1 compatibility tests
│
├── experiments/                        # Security experiments and benchmarks
│   ├── run_all_experiments.py
│   ├── benchmark_suite.py
│   ├── benchmark_results.json
│   ├── run_exp01_happy_path.py ... run_exp10_audit_tampering.py
│   └── evidence/                       # Reproducible experiment artifacts
│
├── scripts/                            # Reproducible pipeline orchestration
│   ├── run_all.py                      # Full pipeline orchestrator
│   ├── evidence.py                     # JSON + PDF evidence bundle generator
│   └── build_evidence_manifest.py      # Unified artifact manifest builder
│
├── artifacts/                          # Pipeline output artifacts
│   ├── runs/                           # Timestamped run directories
│   └── latest/                         # Mirror of latest run results
│
├── data/
│   └── audit_log.jsonl
├── keys/
│   └── manifest.json
├── docs/
│   └── architecture.png
├── paper/
│   ├── licitra_sentry_TR-2026-02_v0.1_FINAL.tex   # Historical reference only
│   └── licitra_sentry_TR-2026-02_v0.1_FINAL.pdf   # Historical reference only
│
├── demo_ticket_execution.py
├── demo_witness.py
├── demo_swarm.py
├── content_rules.yaml
├── requirements.txt
├── pyproject.toml
├── CHANGELOG.md
├── MIGRATION.md
├── SECURITY.md
└── LICENSE
```

---

## Citation

```bibtex
@misc{licitra_sentry_v02,
  author = {Narendra Kumar Nutalapati},
  title = {LICITRA-SENTRY v0.2: Execution Ticket System and Witnessed
           Transparency for Agentic AI Authorization},
  year = {2026},
  doi = {10.5281/zenodo.18860290},
  url = {https://github.com/narendrakumarnutalapati/licitra-sentry}
}
```

---

## References

- [LICITRA-SENTRY v0.2 — Zenodo](https://doi.org/10.5281/zenodo.18860290)
- [LICITRA-MMR v0.1 — Zenodo](https://doi.org/10.5281/zenodo.18843032)
- [OWASP Top 10 for Agentic Applications (2026)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [OWASP Issue #802 — Runtime Enforcement Mapping](https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/issues/802)
- [LICITRA-SENTRY v0.1 Technical Report](paper/licitra_sentry_TR-2026-02_v0.1_FINAL.pdf) — historical reference only; not authoritative for v0.2 runtime behavior
- [LICITRA-MMR](https://github.com/narendrakumarnutalapati/licitra-mmr-core) — append-only Merkle Mountain Range audit ledger

---

## License

MIT License

---

## Author

**Narendra Kumar Nutalapati**  
[GitHub](https://github.com/narendrakumarnutalapati) · [LinkedIn](https://www.linkedin.com/in/narendralicitra)
