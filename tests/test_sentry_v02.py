"""
LICITRA-SENTRY v0.2 — Test Suite

Tests for the execution ticket system, tool proxy, and attack scenarios.

Experiments:
  E01: Authorized ticket flow (end-to-end)
  E02: Direct tool call without ticket (proxy bypass attempt)
  E03: Ticket replay attack
  E04: Payload modification after authorization (hash mismatch)
  E05: Expired ticket rejection
  E06: Delegation privilege escalation attempt
  E07: PII exfiltration blocked by content inspection
  E08: Audit chain integrity verification

Author: Narendra Kumar Nutalapati
License: MIT
"""

import sys
import os
import time
import json
import hashlib
import tempfile
import shutil

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.key_manager import FileKeyProvider
from app.ticket import issue_ticket, verify_ticket, hash_request, ExecutionTicket
from app.tool_proxy import ToolProxy, ReplayStore, RateLimiter
from app.identity import IdentityVerifier, AgentIdentity
from app.content_inspector import ContentInspector
from app.contract import ContractValidator, SemanticContract
from app.authority import AuthorityEnforcer
from app.audit_bridge import AuditBridge, AuditEvent
from app.anchor import FileAnchorProvider, AnchorManager
from app.orchestrator import SentryOrchestrator, AuthorizationRequest


# --------------------------------------------------------------------------- #
#  Test infrastructure
# --------------------------------------------------------------------------- #

class TestContext:
    """Shared test setup."""

    def __init__(self):
        self.tmpdir = tempfile.mkdtemp(prefix="licitra-test-")
        self.keys_dir = os.path.join(self.tmpdir, "keys")
        self.data_dir = os.path.join(self.tmpdir, "data")
        os.makedirs(self.data_dir, exist_ok=True)

        # Key provider
        self.key_provider = FileKeyProvider(self.keys_dir)
        self.kid = self.key_provider.generate_key_pair("test-sentry")

        # Identity
        self.identity = IdentityVerifier()
        self.identity.register_agent(AgentIdentity(
            agent_id="agent-alpha",
            agent_type="llm_agent",
            credential_hash=hashlib.sha256(b"secret-alpha").hexdigest(),
            organization="test-org",
        ))
        self.identity.register_agent(AgentIdentity(
            agent_id="agent-beta",
            agent_type="llm_agent",
            credential_hash=hashlib.sha256(b"secret-beta").hexdigest(),
            organization="test-org",
            delegator_id="agent-alpha",
        ))

        # Content inspector
        self.inspector = ContentInspector()

        # Contracts
        self.contracts = ContractValidator()
        self.contracts.register_contract(SemanticContract(
            contract_id="contract-001",
            contract_version="1.0",
            agent_id="agent-alpha",
            allowed_tools={"email-sender", "db-reader"},
            allowed_actions={"send", "read"},
            scope_restrictions={"region": ["US-WEST", "US-EAST"]},
            value_limits={"max_amount": 10000},
        ))
        self.contracts.register_contract(SemanticContract(
            contract_id="contract-002",
            contract_version="1.0",
            agent_id="agent-beta",
            allowed_tools={"db-reader"},
            allowed_actions={"read"},
        ))

        # Authority
        self.authority = AuthorityEnforcer()
        self.authority.register_permissions("agent-alpha", {
            "email-sender:send", "db-reader:read",
        })
        self.authority.register_permissions("agent-beta", {
            "db-reader:read",
        })
        self.authority.register_delegation("agent-beta", "agent-alpha")

        # Audit
        anchor_provider = FileAnchorProvider(os.path.join(self.data_dir, "anchors"))
        self.anchor_manager = AnchorManager(anchor_provider, anchor_interval=5)
        self.audit = AuditBridge(
            log_path=os.path.join(self.data_dir, "audit.jsonl"),
            anchor_manager=self.anchor_manager,
        )

        # Replay store
        self.replay_store = ReplayStore(
            db_path=os.path.join(self.data_dir, "replay.db")
        )

        # Orchestrator
        self.sentry = SentryOrchestrator(
            identity_verifier=self.identity,
            content_inspector=self.inspector,
            contract_validator=self.contracts,
            authority_enforcer=self.authority,
            audit_bridge=self.audit,
            key_provider=self.key_provider,
        )

        # Tool proxy
        self.audit_events = []
        self.proxy = ToolProxy(
            key_provider=self.key_provider,
            replay_store=self.replay_store,
            audit_callback=lambda e: self.audit_events.append(e),
        )

        # Register mock tools
        self.proxy.register_tool("email-sender", self._mock_email_tool)
        self.proxy.register_tool("db-reader", self._mock_db_tool)

    def _mock_email_tool(self, request):
        return {"status": "sent", "message_id": "msg-12345"}

    def _mock_db_tool(self, request):
        return {"rows": [{"id": 1, "name": "test"}]}

    def cleanup(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)


# --------------------------------------------------------------------------- #
#  Test functions
# --------------------------------------------------------------------------- #

def test_e01_authorized_ticket_flow():
    """E01: Full authorized flow — authorize → ticket → proxy → execute."""
    ctx = TestContext()
    try:
        request = {
            "action": "send",
            "to": "user@internal.example.com",
            "subject": "Q3 Report",
            "body": "Attached is the quarterly report.",
        }

        # Step 1: Authorize through SENTRY
        auth_result = ctx.sentry.authorize(AuthorizationRequest(
            agent_id="agent-alpha",
            credential="secret-alpha",
            tool_id="email-sender",
            action="send",
            request=request,
        ))

        assert auth_result.authorized, f"Authorization failed: {auth_result.rejection_reason}"
        assert auth_result.ticket is not None
        assert len(auth_result.gates) == 5
        assert all(g.passed for g in auth_result.gates)

        # Step 2: Execute through proxy with ticket
        proxy_result = ctx.proxy.execute(
            ticket=auth_result.ticket,
            tool_id="email-sender",
            request=request,
        )

        assert proxy_result.allowed, f"Proxy rejected: {proxy_result.error}"
        assert proxy_result.tool_output["status"] == "sent"
        assert len(ctx.audit_events) == 1
        assert ctx.audit_events[0]["result"] == "success"

        print("  [PASS] E01: Authorized ticket flow — end-to-end success")
        return True
    finally:
        ctx.cleanup()


def test_e02_proxy_bypass_attempt():
    """E02: Agent attempts direct tool call without ticket — rejected."""
    ctx = TestContext()
    try:
        request = {"action": "send", "to": "attacker@evil.com", "body": "data"}

        # Create a fake ticket (not signed by SENTRY)
        from app.ticket import TicketHeader, TicketClaims
        fake_ticket = ExecutionTicket(
            header=TicketHeader(kid="nonexistent-key"),
            claims=TicketClaims(
                sub="agent-alpha",
                aud="email-sender",
                jti="fake-jti",
                iat=time.time(),
                exp=time.time() + 60,
                request_hash=hash_request(request),
            ),
            signature="AAAA",  # invalid signature
        )

        proxy_result = ctx.proxy.execute(
            ticket=fake_ticket,
            tool_id="email-sender",
            request=request,
        )

        assert not proxy_result.allowed
        assert "TICKET_INVALID" in proxy_result.error

        print("  [PASS] E02: Proxy bypass attempt — correctly rejected")
        return True
    finally:
        ctx.cleanup()


def test_e03_replay_attack():
    """E03: Agent reuses a ticket — replay detected and rejected."""
    ctx = TestContext()
    try:
        request = {
            "action": "send",
            "to": "user@internal.example.com",
            "subject": "Report",
            "body": "Content",
        }

        # Authorize
        auth_result = ctx.sentry.authorize(AuthorizationRequest(
            agent_id="agent-alpha",
            credential="secret-alpha",
            tool_id="email-sender",
            action="send",
            request=request,
        ))
        assert auth_result.authorized

        # First execution — should succeed
        result1 = ctx.proxy.execute(
            ticket=auth_result.ticket,
            tool_id="email-sender",
            request=request,
        )
        assert result1.allowed

        # Second execution with same ticket — replay attack
        result2 = ctx.proxy.execute(
            ticket=auth_result.ticket,
            tool_id="email-sender",
            request=request,
        )
        assert not result2.allowed
        assert "REPLAY_DETECTED" in result2.error

        print("  [PASS] E03: Replay attack — correctly detected and rejected")
        return True
    finally:
        ctx.cleanup()


def test_e04_payload_modification():
    """E04: Agent modifies payload after authorization — hash mismatch."""
    ctx = TestContext()
    try:
        original_request = {
            "action": "send",
            "to": "user@internal.example.com",
            "subject": "Report",
            "body": "Legitimate content",
        }

        # Authorize with original request
        auth_result = ctx.sentry.authorize(AuthorizationRequest(
            agent_id="agent-alpha",
            credential="secret-alpha",
            tool_id="email-sender",
            action="send",
            request=original_request,
        ))
        assert auth_result.authorized

        # Modify the request after authorization
        modified_request = {
            "action": "send",
            "to": "attacker@evil.com",  # CHANGED
            "subject": "Report",
            "body": "Exfiltrated data: SSN 123-45-6789",  # CHANGED
        }

        # Attempt execution with modified payload
        proxy_result = ctx.proxy.execute(
            ticket=auth_result.ticket,
            tool_id="email-sender",
            request=modified_request,
        )

        assert not proxy_result.allowed
        assert "TICKET_INVALID" in proxy_result.error
        assert "hash mismatch" in proxy_result.error.lower() or "Request hash" in proxy_result.error

        print("  [PASS] E04: Payload modification — hash mismatch detected")
        return True
    finally:
        ctx.cleanup()


def test_e05_expired_ticket():
    """E05: Ticket with expired TTL — rejected."""
    ctx = TestContext()
    try:
        request = {"action": "read", "table": "users"}

        # Issue ticket with 1-second TTL
        ticket = issue_ticket(
            key_provider=ctx.key_provider,
            agent_id="agent-alpha",
            tool_id="db-reader",
            request=request,
            policy_version="1.0",
            contract_id="contract-001",
            contract_version="1.0",
            mmr_commit_id="test-commit",
            ttl_seconds=1,
        )

        # Wait for expiration
        time.sleep(1.5)

        proxy_result = ctx.proxy.execute(
            ticket=ticket,
            tool_id="db-reader",
            request=request,
        )

        assert not proxy_result.allowed
        assert "TICKET_INVALID" in proxy_result.error
        assert "expired" in proxy_result.error.lower()

        print("  [PASS] E05: Expired ticket — correctly rejected")
        return True
    finally:
        ctx.cleanup()


def test_e06_delegation_escalation():
    """E06: Delegated agent attempts action beyond delegator's permissions."""
    ctx = TestContext()
    try:
        request = {
            "action": "send",
            "to": "user@internal.example.com",
            "body": "Content",
        }

        # agent-beta (delegated from agent-alpha) tries to use email-sender
        # agent-beta only has db-reader:read permission
        auth_result = ctx.sentry.authorize(AuthorizationRequest(
            agent_id="agent-beta",
            credential="secret-beta",
            tool_id="email-sender",
            action="send",
            request=request,
        ))

        assert not auth_result.authorized
        # Should be rejected at Gate 3 (contract: email-sender not allowed)
        # or Gate 4 (authority: no email-sender permission)
        assert auth_result.rejection_reason is not None

        print("  [PASS] E06: Delegation escalation — correctly blocked")
        print(f"         Reason: {auth_result.rejection_reason[:80]}...")
        return True
    finally:
        ctx.cleanup()


def test_e07_pii_exfiltration_blocked():
    """E07: Request containing PII patterns — blocked by content inspection."""
    ctx = TestContext()
    try:
        request = {
            "action": "send",
            "to": "user@internal.example.com",
            "body": "Customer SSN: 123-45-6789 and CC: 4111-1111-1111-1111",
        }

        auth_result = ctx.sentry.authorize(AuthorizationRequest(
            agent_id="agent-alpha",
            credential="secret-alpha",
            tool_id="email-sender",
            action="send",
            request=request,
        ))

        assert not auth_result.authorized
        assert "Gate 2" in auth_result.rejection_reason

        print("  [PASS] E07: PII exfiltration — blocked by content inspection")
        return True
    finally:
        ctx.cleanup()


def test_e08_audit_chain_integrity():
    """E08: Verify audit log hash chain integrity after multiple operations."""
    ctx = TestContext()
    try:
        # Run several operations to build up the audit chain
        for i in range(3):
            request = {"action": "read", "table": f"dataset_{i}"}
            auth_result = ctx.sentry.authorize(AuthorizationRequest(
                agent_id="agent-alpha",
                credential="secret-alpha",
                tool_id="db-reader",
                action="read",
                request=request,
            ))
            assert auth_result.authorized

        # Verify chain integrity
        valid, error = ctx.audit.verify_chain()
        assert valid, f"Chain integrity check failed: {error}"

        # Verify event count (5 gates per auth * 3 requests = 15 events,
        # plus commit events)
        assert ctx.audit.get_event_count() > 0

        print(f"  [PASS] E08: Audit chain integrity — {ctx.audit.get_event_count()} events verified")
        return True
    finally:
        ctx.cleanup()


# --------------------------------------------------------------------------- #
#  Runner
# --------------------------------------------------------------------------- #

def run_all_tests():
    print("=" * 70)
    print("LICITRA-SENTRY v0.2 — Test Suite")
    print("=" * 70)
    print()

    tests = [
        ("E01", "Authorized Ticket Flow", test_e01_authorized_ticket_flow),
        ("E02", "Proxy Bypass Attempt", test_e02_proxy_bypass_attempt),
        ("E03", "Replay Attack", test_e03_replay_attack),
        ("E04", "Payload Modification", test_e04_payload_modification),
        ("E05", "Expired Ticket", test_e05_expired_ticket),
        ("E06", "Delegation Escalation", test_e06_delegation_escalation),
        ("E07", "PII Exfiltration Blocked", test_e07_pii_exfiltration_blocked),
        ("E08", "Audit Chain Integrity", test_e08_audit_chain_integrity),
    ]

    results = []
    for eid, name, fn in tests:
        print(f"[{eid}] {name}")
        try:
            passed = fn()
            results.append((eid, name, passed))
        except Exception as e:
            print(f"  [FAIL] {eid}: {e}")
            import traceback
            traceback.print_exc()
            results.append((eid, name, False))
        print()

    # Summary
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    passed = sum(1 for _, _, p in results if p)
    total = len(results)
    for eid, name, p in results:
        status = "PASS" if p else "FAIL"
        print(f"  [{status}] {eid}: {name}")
    print()
    print(f"  Result: {passed}/{total} tests passed")
    print("=" * 70)

    return passed == total


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
