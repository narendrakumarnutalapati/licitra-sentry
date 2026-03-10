# Migration Guide: v0.1 -> v0.2

## Overview

LICITRA-SENTRY v0.2 preserves the original five-gate Chain-of-Intent model, but adds a new enforcement guarantee:

    authorized_request == executed_request

This is achieved through:

- Ed25519-signed execution tickets
- mandatory tool mediation through `ToolProxy`
- replay protection via JTI tracking
- append-only audit commitment
- optional witnessed transparency for external verification

v0.2 should be treated as the authoritative runtime API.

The older v0.1-style components remain in the repository only as a compatibility layer for legacy experiments and migration support.

---

## API Status

### Authoritative v0.2 Runtime API

Use these components for all new integrations:

- `IdentityVerifier`
- `ContentInspector`
- `SemanticContract`
- `ContractValidator`
- `AuthorityEnforcer`
- `SentryOrchestrator`
- `ExecutionTicket`
- `ToolProxy`
- `AuditBridge`
- `WitnessClient`
- `WitnessVerifier`

### Legacy Compatibility API

The following components remain only for backward compatibility and experiment reproducibility:

- `CovenantNotary`
- `SignedToken`
- `AgenticSafetyContract`
- legacy PowerShell tests under `tests/legacy/`

These should not be used for new runtime integrations.

---

## What Changed

### 1. New Requirement: Key Provider

v0.2 requires an Ed25519 key provider for ticket signing.

~~~python
from app.key_manager import FileKeyProvider

key_provider = FileKeyProvider("keys/")
key_provider.generate_key_pair("sentry")
~~~

### 2. Orchestrator Now Issues Execution Tickets

`SentryOrchestrator` now requires a `key_provider` parameter and returns an `ExecutionTicket` in `AuthorizationResult` for approved requests.

~~~python
# v0.1-style initialization
sentry = SentryOrchestrator(identity, inspector, contracts, authority, audit)

# v0.2 initialization
sentry = SentryOrchestrator(
    identity_verifier=identity,
    content_inspector=inspector,
    contract_validator=contracts,
    authority_enforcer=authority,
    audit_bridge=audit,
    key_provider=key_provider,
)
~~~

### 3. Tool Execution Must Go Through ToolProxy

In v0.1-style flows, a tool could be invoked directly after authorization.

In v0.2, every tool invocation must pass through `ToolProxy`.

~~~python
from app.tool_proxy import ToolProxy, ReplayStore

proxy = ToolProxy(
    key_provider=key_provider,
    replay_store=ReplayStore(),
)

proxy.register_tool("my-tool", my_tool_handler)

result = proxy.execute(
    ticket=auth_result.ticket,
    tool_id="my-tool",
    request=request,
)
~~~

### 4. Replay Protection Is Now Enforced

Execution tickets are single-use.

Replay protection is enforced through JTI tracking in `ReplayStore`.

A previously used ticket will be rejected with:

~~~text
REPLAY_DETECTED
~~~

### 5. Request Hash Binding Is Now Enforced

The execution ticket contains a SHA-256 hash of the canonicalized authorized request.

If the request is changed after authorization, proxy verification fails with:

~~~text
TICKET_INVALID: Request hash mismatch
~~~

### 6. Audit Commitment Is Part of Authorization

Successful authorization now produces an audit commit ID, which is embedded into the execution ticket as `mmr_commit_id`.

This links:

- authorization decision
- execution ticket
- audit record

### 7. Optional Witness Transparency Layer

v0.2 adds witnessed transparency support through:

- `WitnessClient`
- `FileTransparencyLog`
- `WitnessVerifier`

This allows external auditors to verify epoch receipts and detect operator history rewrites.

### 8. Content Inspector Threshold Change

Email address detection risk level changed from `high` to `medium` to reduce false positives for expected email workflows.

---

## Repository Structure Changes

### Current Validation

The authoritative current validation suite is:

- `tests/test_sentry_v02.py`
- `tests/test_witness.py`

Run both through:

~~~powershell
powershell -ExecutionPolicy Bypass -File .\tests\run_all_tests.ps1
~~~

### Legacy Tests

Older compatibility tests were moved to:

~~~text
tests/legacy/
~~~

These are retained only for historical compatibility and migration reference.

### Experiments

Runtime attack simulations are located in:

~~~text
experiments/
~~~

This includes:

- `run_exp01_happy_path.py` through `run_exp10_audit_tampering.py`
- `benchmark_suite.py`
- `benchmark_results.json`
- `evidence/`

---

## Migration Steps

1. Generate an Ed25519 key pair with `FileKeyProvider`
2. Update `SentryOrchestrator` initialization to include `key_provider`
3. Register tool handlers in `ToolProxy`
4. Route all tool executions through `ToolProxy`
5. Verify replay protection and request binding behavior
6. Run the authoritative v0.2 tests:
   - `tests/test_sentry_v02.py`
   - `tests/test_witness.py`
7. Run the experiment suite:
   - `python experiments/run_all_experiments.py`

---

## Minimal v0.2 Flow

~~~python
auth_result = sentry.authorize(
    AuthorizationRequest(
        agent_id="agent-alpha",
        credential="secret-alpha",
        tool_id="db-reader",
        action="read",
        request={"action": "read", "table": "dataset"},
    )
)

if auth_result.authorized:
    result = proxy.execute(
        ticket=auth_result.ticket,
        tool_id="db-reader",
        request={"action": "read", "table": "dataset"},
    )
~~~

---

## Summary

v0.2 is not just a policy-evaluation release.

It changes LICITRA-SENTRY from:

- authorization decision system

into:

- cryptographically enforced runtime authorization system

The key migration requirement is simple:

> do not execute tools directly after authorization;
> always execute through `ToolProxy` using the issued `ExecutionTicket`.
