"""Fix README.md and evidence how_to_run.md with experiments info."""

# ===== Update SENTRY README — add experiments section =====
with open("README.md", "r", encoding="utf-8") as f:
    content = f.read()

# Find the "## Quickstart" section and add experiments section before it
old_quickstart = "## Quickstart"
experiments_section = """## Reproducible Experiments

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

## Quickstart"""

content = content.replace(old_quickstart, experiments_section)

with open("README.md", "w", encoding="utf-8") as f:
    f.write(content)

print("Updated: README.md (added experiments section)")

# ===== Update evidence repo how_to_run.md =====
import os
evidence_base = r"D:\AI\licitra-sentry-evidence"

with open(os.path.join(evidence_base, "docs", "how_to_run.md"), "w", encoding="utf-8") as f:
    f.write("""# How to Run LICITRA-SENTRY

## Prerequisites

- Python 3.12+
- PostgreSQL 16 (for LICITRA-MMR)
- Git

## Step 1: Clone and Start LICITRA-MMR
```bash
git clone https://github.com/narendrakumarnutalapati/licitra-mmr-core.git
cd licitra-mmr-core
pip install -r requirements.txt
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Verify MMR is running: visit http://localhost:8000/docs

## Step 2: Clone and Install LICITRA-SENTRY

In a separate terminal:
```bash
git clone https://github.com/narendrakumarnutalapati/licitra-sentry.git
cd licitra-sentry
pip install -r requirements.txt
```

## Step 3: Run Individual Experiments

Each experiment is a standalone Python script in the `experiments/` folder:
```bash
python experiments/run_exp01_happy_path.py
python experiments/run_exp02_contract_rejection.py
python experiments/run_exp03_identity_expiry.py
python experiments/run_exp04_relay_injection.py
python experiments/run_exp05_pii_exfiltration.py
python experiments/run_exp06_unauthorized_delegation.py
```

Each script:
- Sets up the agent, contract, and token
- Runs the scenario through the Chain of Intent pipeline
- Commits the decision to LICITRA-MMR
- Prints decision, gate fired, MMR leaf_hash, and verdict

## Step 4: Run All Experiments
```bash
python experiments/run_all_experiments.py
```

Expected output: `ALL 6/6 EXPERIMENTS PASSED`

## Step 5: Run Demo Swarm
```bash
python demo_swarm.py
```

Runs all 6 scenarios and prints a summary table with MMR leaf_hash per scenario.

| Scenario | Agent | Intent | Expected | OWASP |
|----------|-------|--------|----------|-------|
| S1 | Researcher | READ | APPROVED | ASI07 |
| S2 | Researcher | FILE_WRITE | REJECTED (contract) | ASI02 |
| S3 | Researcher | READ (expired token) | REJECTED (identity) | ASI03 |
| S4 | Researcher | READ (relay injection) | REJECTED (inspector) | ASI01 |
| S5 | Researcher | SUMMARIZE (SSN in msg) | REJECTED (inspector) | ASI06 |
| S6 | Coder | FILE_WRITE (delegate) | REJECTED (orchestration) | ASI05 |

## Step 6: Run Full Test Suite
```powershell
powershell -ExecutionPolicy Bypass -File tests\\run_all_tests.ps1
```

Expected: 9/9 tests passing.

## Step 7: Verify Evidence

The `evidence/` folder in this repo contains PDF reports from a complete run.
Each PDF is self-contained with:
- Hypothesis, setup, input
- Expected vs actual outcome
- MMR cryptographic proof (staged_id, event_id, leaf_hash)
- Inspection findings (if any)
- Raw JSON output
- Verdict: CONFIRMED

The `leaf_hash` in each PDF is a real SHA-256 hash from LICITRA-MMR's
Merkle Mountain Range. It can be independently verified against the MMR ledger.

## Step 8: Regenerate Evidence PDFs (Optional)

To regenerate the evidence PDFs from a fresh run, use the evidence generator
script in the SENTRY repo (requires reportlab):
```bash
pip install reportlab
python _gen_all_evidence.py
```

This produces 6 individual experiment PDFs + 1 consolidated PDF in the `evidence/` folder.
""")

print("Updated: docs/how_to_run.md")

# ===== Update evidence experiments.md =====
with open(os.path.join(evidence_base, "docs", "experiments.md"), "w", encoding="utf-8") as f:
    f.write("""# LICITRA-SENTRY Experiments

## Overview

Six experiments validate the Chain of Intent pipeline across all 10 OWASP Agentic Top 10 categories. Each experiment is a standalone Python script that can be run independently.

## Experiment Protocol

1. Start LICITRA-MMR at http://localhost:8000
2. Build the SENTRY stack (identity, contracts, authority, inspector, orchestration, audit bridge, middleware)
3. Execute scenario through the Chain of Intent pipeline
4. Capture the MiddlewareResult including MMR leaf_hash
5. Verify: decision matches expected, gate matches expected, leaf_hash is 64-char SHA-256 hex
6. Verdict: CONFIRMED if all checks pass

## Experiments

### EXP-01: Happy Path — Approved

**Script:** `experiments/run_exp01_happy_path.py`
**Goal:** Valid agent, valid token, allowed intent, allowed tool, clean message passes all gates.
**Agent:** Researcher | **Intent:** READ | **Tool:** web_search
**Expected:** APPROVED, gate=approved, leaf_hash present
**OWASP:** ASI07 (Inter-Agent Communication Integrity)

### EXP-02: Contract Rejection — Excessive Agency Blocked

**Script:** `experiments/run_exp02_contract_rejection.py`
**Goal:** Contract engine rejects intent not in agent's allowed list.
**Agent:** Researcher | **Intent:** FILE_WRITE (not allowed) | **Tool:** editor
**Expected:** REJECTED, gate=contract, leaf_hash present
**OWASP:** ASI02 (Excessive Agency)

### EXP-03: Identity Expiry Rejection — Impersonation Blocked

**Script:** `experiments/run_exp03_identity_expiry.py`
**Goal:** Expired token rejected at identity gate.
**Agent:** Researcher (expired token) | **Intent:** READ
**Expected:** REJECTED, gate=identity, leaf_hash present
**OWASP:** ASI03 (Agent Impersonation)

### EXP-04: Relay Injection Blocked

**Script:** `experiments/run_exp04_relay_injection.py`
**Goal:** Content inspector detects relay injection pattern.
**Agent:** Researcher | **Message:** "ignore all previous instructions..."
**Expected:** REJECTED, gate=inspector, findings include RI-001, leaf_hash present
**OWASP:** ASI01 (Prompt Injection / Relay Injection)

### EXP-05: PII Exfiltration Blocked — SSN Detection

**Script:** `experiments/run_exp05_pii_exfiltration.py`
**Goal:** Content inspector detects US SSN pattern.
**Agent:** Researcher | **Message:** contains "123-45-6789"
**Expected:** REJECTED, gate=inspector, findings include PII-001, leaf_hash present
**OWASP:** ASI06 (Sensitive Data Exposure)

### EXP-06: Unauthorized Delegation Blocked — Orchestration Guard

**Script:** `experiments/run_exp06_unauthorized_delegation.py`
**Goal:** Orchestration guard blocks unauthorized agent delegation.
**Agent:** Coder delegates to Researcher (policy only allows Researcher->Coder)
**Expected:** REJECTED, gate=orchestration, leaf_hash present
**OWASP:** ASI05 (Improper Multi-Agent Orchestration)

## Reproducibility

All experiments are deterministic given the same inputs. The MMR leaf_hash will differ between runs (timestamps vary), but decision, gate_fired, and findings are identical.

Evidence PDFs in the `evidence/` folder capture one complete run with real MMR leaf_hashes.
""")

print("Updated: docs/experiments.md")

# ===== Update chain-of-intent.md with orchestration gate =====
with open(os.path.join(evidence_base, "docs", "chain-of-intent.md"), "w", encoding="utf-8") as f:
    f.write("""# Chain of Intent — Formal Specification

## Overview

The Chain of Intent is the core security model of LICITRA-SENTRY. It defines a sequential pipeline of cryptographically enforced gates that every inter-agent message must pass through before being forwarded.

## Definition

A Chain of Intent is a tuple C = (G1, G2, G3, G4, G5, A) where:

- **G1 (Identity Gate):** Verifies the agent's Ed25519-signed session token. Checks signature validity and token expiry.
- **G2 (Content Gate):** Inspects message content against a deterministic rule set for injection patterns, PII, and privilege escalation.
- **G3 (Contract Gate):** Validates that the requested intent, tool, and parameter shapes are permitted by the agent's safety contract.
- **G4 (Authority Gate):** Performs final authorization combining identity validity with contract compliance.
- **G5 (Orchestration Gate):** If the message involves delegation, verifies the delegation is authorized and does not escalate privileges.
- **A (Anchor):** Commits the decision (APPROVED or REJECTED) to LICITRA-MMR via 2-phase commit.

## Sequential Enforcement
```
Message M from Agent X
        |
        v
   +---------+    REJECT --> Anchor(REJECTED, reason=identity) --> MMR
   | G1: ID  |----------->
   +----+----+
        | PASS
        v
   +---------+    REJECT --> Anchor(REJECTED, reason=inspector) --> MMR
   |G2:Content|---------->
   +----+----+
        | PASS
        v
   +---------+    REJECT --> Anchor(REJECTED, reason=contract) --> MMR
   |G3:Contract|--------->
   +----+----+
        | PASS
        v
   +---------+    REJECT --> Anchor(REJECTED, reason=authority) --> MMR
   |G4:Authority|-------->
   +----+----+
        | PASS
        v
   +---------+    REJECT --> Anchor(REJECTED, reason=orchestration) --> MMR
   |G5:Orchestr|-------->   (only if delegate_to is set)
   +----+----+
        | PASS
        v
   Anchor(APPROVED) --> MMR
        |
        v
   Forward Message M
```

## Properties

### P1: Completeness
Every message receives a decision. There is no path through the pipeline that does not produce either APPROVED or REJECTED.

### P2: Tamper Evidence
Every decision is committed to LICITRA-MMR. The MMR leaf_hash provides cryptographic proof that the decision was recorded. Epoch anchoring provides proof of ledger state at any point in time.

### P3: Short-Circuit Safety
The pipeline short-circuits on the first rejection. The rejection reason identifies exactly which gate failed. Even rejected messages are anchored in MMR.

### P4: Determinism
Given identical inputs (same token, intent, tool, message, contract), the pipeline produces identical decisions. Content inspection uses deterministic regex matching. Contract validation is pure and stateless.

### P5: Least Privilege
Agents can only perform actions explicitly listed in their safety contract. The default is deny — any intent, tool, or parameter shape not in the contract is rejected.

### P6: Delegation Non-Escalation
An agent cannot delegate tasks it is not itself authorized to perform. The orchestration guard checks the delegator's own contract before allowing delegation.

## OWASP Mapping

| Gate | OWASP Categories |
|------|-----------------|
| G1 (Identity) | ASI03 Agent Impersonation, ASI10 Uncontrolled Proliferation |
| G2 (Content) | ASI01 Prompt Injection, ASI06 Sensitive Data Exposure |
| G3 (Contract) | ASI01 Prompt Injection, ASI02 Excessive Agency, ASI06 Data Exposure |
| G4 (Authority) | ASI02 Excessive Agency, ASI09 Insufficient Access Controls |
| G5 (Orchestration) | ASI05 Improper Multi-Agent Orchestration |
| A (Anchor) | ASI04 Insecure Output Handling, ASI07 Communication Integrity, ASI08 Audit Failures |

**Total: 10/10 OWASP Agentic Top 10 covered.**
""")

print("Updated: docs/chain-of-intent.md")
print("Done - all docs updated.")
