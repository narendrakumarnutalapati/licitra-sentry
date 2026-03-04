#!/usr/bin/env python3
"""
LICITRA-SENTRY v0.2 — Demo: Execution Ticket System

Demonstrates three scenarios:
  A. Authorized email send (full pipeline → ticket → execution)
  B. PII exfiltration attempt (blocked at Gate 2)
  C. Unauthorized delegation (blocked at Gate 3/4)

All scenarios show MMR audit events and chain integrity verification.

Usage:
    python demo_ticket_execution.py

Author: Narendra Kumar Nutalapati
License: MIT
"""

import sys
import os
import json
import hashlib
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.key_manager import FileKeyProvider
from app.identity import IdentityVerifier, AgentIdentity
from app.content_inspector import ContentInspector
from app.contract import ContractValidator, SemanticContract
from app.authority import AuthorityEnforcer
from app.audit_bridge import AuditBridge
from app.anchor import FileAnchorProvider, AnchorManager
from app.tool_proxy import ToolProxy, ReplayStore
from app.orchestrator import SentryOrchestrator, AuthorizationRequest


def setup():
    """Initialize all SENTRY components."""
    tmpdir = tempfile.mkdtemp(prefix="licitra-demo-")

    # Keys
    key_provider = FileKeyProvider(os.path.join(tmpdir, "keys"))
    key_provider.generate_key_pair("sentry")

    # Identity registry
    identity = IdentityVerifier()
    identity.register_agent(AgentIdentity(
        agent_id="finance-agent",
        agent_type="llm_agent",
        credential_hash=hashlib.sha256(b"finance-cred").hexdigest(),
        organization="acme-corp",
    ))
    identity.register_agent(AgentIdentity(
        agent_id="intern-agent",
        agent_type="llm_agent",
        credential_hash=hashlib.sha256(b"intern-cred").hexdigest(),
        organization="acme-corp",
        delegator_id="finance-agent",
    ))

    # Content inspector
    inspector = ContentInspector()

    # Contracts
    contracts = ContractValidator()
    contracts.register_contract(SemanticContract(
        contract_id="finance-contract-v1",
        contract_version="1.0",
        agent_id="finance-agent",
        allowed_tools={"email-sender", "ledger-reader"},
        allowed_actions={"send", "read"},
        value_limits={"max_amount": 10000},
    ))
    contracts.register_contract(SemanticContract(
        contract_id="intern-contract-v1",
        contract_version="1.0",
        agent_id="intern-agent",
        allowed_tools={"ledger-reader"},
        allowed_actions={"read"},
    ))

    # Authority
    authority = AuthorityEnforcer()
    authority.register_permissions("finance-agent", {
        "email-sender:send", "ledger-reader:read",
    })
    authority.register_permissions("intern-agent", {
        "ledger-reader:read",
    })
    authority.register_delegation("intern-agent", "finance-agent")

    # Audit with anchoring
    anchor_provider = FileAnchorProvider(os.path.join(tmpdir, "anchors"))
    anchor_manager = AnchorManager(anchor_provider, anchor_interval=10)
    audit = AuditBridge(
        log_path=os.path.join(tmpdir, "audit.jsonl"),
        anchor_manager=anchor_manager,
    )

    # Orchestrator
    sentry = SentryOrchestrator(
        identity_verifier=identity,
        content_inspector=inspector,
        contract_validator=contracts,
        authority_enforcer=authority,
        audit_bridge=audit,
        key_provider=key_provider,
    )

    # Tool proxy
    replay_store = ReplayStore(os.path.join(tmpdir, "replay.db"))
    proxy = ToolProxy(
        key_provider=key_provider,
        replay_store=replay_store,
        audit_callback=lambda e: None,  # proxy audit handled separately
    )
    proxy.register_tool("email-sender", lambda r: {
        "status": "sent",
        "message_id": "msg-" + hashlib.sha256(json.dumps(r).encode()).hexdigest()[:8],
    })
    proxy.register_tool("ledger-reader", lambda r: {
        "rows": [{"account": "ACC-001", "balance": 42500.00}],
    })

    return sentry, proxy, audit, tmpdir


def print_header(title):
    print()
    print("=" * 70)
    print(f"  {title}")
    print("=" * 70)


def print_gates(gates):
    for g in gates:
        status = "✓ PASS" if g.passed else "✗ FAIL"
        print(f"    Gate [{g.gate:20s}] {status}")
        if g.details:
            for k, v in g.details.items():
                if v:
                    print(f"      {k}: {v}")


def run_demo():
    sentry, proxy, audit, tmpdir = setup()

    try:
        # ============================================================
        # SCENARIO A: Authorized Email Send
        # ============================================================
        print_header("SCENARIO A: Authorized Email Send")
        print()
        print("  finance-agent requests to send quarterly report via email.")
        print("  Expected: All 5 gates pass → ticket issued → tool executes.")
        print()

        request_a = {
            "action": "send",
            "to": "cfo@acme-corp.internal",
            "subject": "Q1 2026 Financial Summary",
            "body": "Please find the quarterly financial summary attached.",
        }

        auth_a = sentry.authorize(AuthorizationRequest(
            agent_id="finance-agent",
            credential="finance-cred",
            tool_id="email-sender",
            action="send",
            request=request_a,
        ))

        print(f"  Authorization: {'APPROVED' if auth_a.authorized else 'DENIED'}")
        print(f"  Processing time: {auth_a.processing_time_ms:.1f}ms")
        print_gates(auth_a.gates)

        if auth_a.ticket:
            print()
            print(f"  Ticket issued:")
            print(f"    JTI: {auth_a.ticket.claims.jti}")
            print(f"    Agent: {auth_a.ticket.claims.sub}")
            print(f"    Tool: {auth_a.ticket.claims.aud}")
            print(f"    Request hash: {auth_a.ticket.claims.request_hash[:16]}...")
            print(f"    Expires in: {auth_a.ticket.claims.exp - auth_a.ticket.claims.iat:.0f}s")
            print(f"    MMR commit: {auth_a.ticket.claims.mmr_commit_id[:16]}...")

            # Execute through proxy
            exec_a = proxy.execute(
                ticket=auth_a.ticket,
                tool_id="email-sender",
                request=request_a,
            )
            print()
            print(f"  Proxy execution: {'SUCCESS' if exec_a.allowed else 'REJECTED'}")
            if exec_a.tool_output:
                print(f"    Tool output: {exec_a.tool_output}")

        # ============================================================
        # SCENARIO B: PII Exfiltration Attempt
        # ============================================================
        print_header("SCENARIO B: PII Exfiltration Attempt")
        print()
        print("  finance-agent attempts to send email containing SSN and")
        print("  credit card numbers — content inspection blocks it.")
        print()

        request_b = {
            "action": "send",
            "to": "external@competitor.com",
            "subject": "Customer Data Export",
            "body": "Customer records: SSN 123-45-6789, CC 4111-1111-1111-1111",
        }

        auth_b = sentry.authorize(AuthorizationRequest(
            agent_id="finance-agent",
            credential="finance-cred",
            tool_id="email-sender",
            action="send",
            request=request_b,
        ))

        print(f"  Authorization: {'APPROVED' if auth_b.authorized else 'DENIED'}")
        print_gates(auth_b.gates)
        if auth_b.rejection_reason:
            print()
            print(f"  Rejection: {auth_b.rejection_reason}")
        print()
        print("  → No ticket issued. No tool execution possible.")

        # ============================================================
        # SCENARIO C: Unauthorized Delegation
        # ============================================================
        print_header("SCENARIO C: Unauthorized Delegation Attempt")
        print()
        print("  intern-agent (delegated from finance-agent) attempts to")
        print("  send email — but intern's contract only allows ledger-reader.")
        print("  Delegation cannot escalate privileges.")
        print()

        request_c = {
            "action": "send",
            "to": "vendor@supplier.com",
            "subject": "Payment Confirmation",
            "body": "Payment of 50000 confirmed.",
        }

        auth_c = sentry.authorize(AuthorizationRequest(
            agent_id="intern-agent",
            credential="intern-cred",
            tool_id="email-sender",
            action="send",
            request=request_c,
        ))

        print(f"  Authorization: {'APPROVED' if auth_c.authorized else 'DENIED'}")
        print_gates(auth_c.gates)
        if auth_c.rejection_reason:
            print()
            print(f"  Rejection: {auth_c.rejection_reason}")
        print()
        print("  → No ticket issued. Delegation did not escalate privileges.")

        # ============================================================
        # AUDIT VERIFICATION
        # ============================================================
        print_header("AUDIT CHAIN VERIFICATION")
        print()

        valid, error = audit.verify_chain()
        event_count = audit.get_event_count()
        root_hash = audit.get_current_root()

        print(f"  Chain integrity: {'VALID' if valid else 'BROKEN'}")
        if error:
            print(f"  Error: {error}")
        print(f"  Total audit events: {event_count}")
        print(f"  Current root hash: {root_hash[:32]}...")
        print()
        print("  Every gate decision — approved and rejected — is")
        print("  committed to the append-only hash-chained audit ledger.")
        print("  Modifying any event invalidates all subsequent hashes.")

        print()
        print("=" * 70)
        print("  DEMO COMPLETE")
        print("=" * 70)
        print()

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    run_demo()
