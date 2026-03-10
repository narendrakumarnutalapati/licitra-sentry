"""
EXP-08: Ticket Replay Attack
Reuse of a valid execution ticket after successful use.
Expected: rejected (JTI already used).
Validates v0.2 replay protection in ToolProxy / ReplayStore.
"""

import json
import hashlib
import tempfile
import shutil
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.key_manager import FileKeyProvider
from app.identity import IdentityVerifier, AgentIdentity
from app.content_inspector import ContentInspector
from app.contract import ContractValidator, SemanticContract
from app.authority import AuthorityEnforcer
from app.audit_bridge import AuditBridge
from app.orchestrator import SentryOrchestrator, AuthorizationRequest
from app.tool_proxy import ToolProxy, ReplayStore

ORG_ID = "sentry-exp08"


def main():
    tmpdir = tempfile.mkdtemp(prefix="licitra-exp08-")
    try:
        key_provider = FileKeyProvider(os.path.join(tmpdir, "keys"))
        key_provider.generate_key_pair("sentry")

        identity = IdentityVerifier()
        identity.register_agent(AgentIdentity(
            agent_id="researcher",
            agent_type="llm_agent",
            credential_hash=hashlib.sha256(b"secret").hexdigest(),
            organization="licitra-lab",
        ))

        inspector = ContentInspector()

        contracts = ContractValidator()
        contracts.register_contract(SemanticContract(
            contract_id="exp08-contract",
            contract_version="1.0",
            agent_id="researcher",
            allowed_tools={"web_search"},
            allowed_actions={"READ"},
        ))

        authority = AuthorityEnforcer()
        authority.register_permissions("researcher", {"web_search:READ"})

        audit = AuditBridge(
            mmr_base_url="http://localhost:8000",
            org_id=ORG_ID,
            log_path=os.path.join(tmpdir, "audit.jsonl"),
        )

        sentry = SentryOrchestrator(
            identity_verifier=identity,
            content_inspector=inspector,
            contract_validator=contracts,
            authority_enforcer=authority,
            audit_bridge=audit,
            key_provider=key_provider,
        )

        replay_store = ReplayStore(os.path.join(tmpdir, "replay.db"))
        proxy = ToolProxy(
            key_provider=key_provider,
            replay_store=replay_store,
            audit_callback=lambda e: None,
        )

        proxy.register_tool("web_search", lambda request: {
            "status": "ok",
            "query": request.get("query"),
        })

        request_payload = {"query": "quarterly earnings report"}

        auth = sentry.authorize(AuthorizationRequest(
            agent_id="researcher",
            credential="secret",
            tool_id="web_search",
            action="READ",
            request=request_payload,
        ))

        if not auth.authorized or auth.ticket is None:
            print(json.dumps({
                "experiment": "EXP-08",
                "title": "Ticket Replay Attack",
                "error": "authorization_failed",
                "authorized": auth.authorized,
                "rejection_reason": auth.rejection_reason,
                "verdict": "FAILED",
            }, indent=2))
            sys.exit(1)

        first = proxy.execute(
            ticket=auth.ticket,
            tool_id="web_search",
            request=request_payload,
        )

        replay = proxy.execute(
            ticket=auth.ticket,
            tool_id="web_search",
            request=request_payload,
        )

        verdict = "CONFIRMED" if (
            first.allowed is True
            and replay.allowed is False
            and replay.error is not None
            and "REPLAY_DETECTED" in replay.error
        ) else "FAILED"

        print(json.dumps({
            "experiment": "EXP-08",
            "title": "Ticket Replay Attack",
            "authorized": auth.authorized,
            "ticket_jti": auth.ticket.claims.jti,
            "first_allowed": first.allowed,
            "first_output": first.tool_output,
            "replay_allowed": replay.allowed,
            "replay_error": replay.error,
            "verdict": verdict,
        }, indent=2))

        sys.exit(0 if verdict == "CONFIRMED" else 1)

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    main()
