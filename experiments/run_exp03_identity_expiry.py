"""
EXP-03: Identity Expiry Rejection — Impersonation Blocked
Hypothesis: An expired token is rejected at the identity gate.
            Rejection is anchored in LICITRA-MMR.
OWASP: ASI03 (Agent Impersonation)
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json, time
from app.identity import CovenantNotary, SignedToken
from app.contract import AgenticSafetyContract, ContractValidator
from app.authority import AuthorityGate
from app.content_inspector import ContentInspector
from app.audit_bridge import AuditBridge
from app.middleware import SentryMiddleware
from app.orchestration import OrchestrationGuard

print("\n  EXP-03: Identity Expiry Rejection - Impersonation Blocked")
print("  " + "=" * 50)

notary = CovenantNotary(ttl_seconds=60)
notary.register_agent("researcher")
cv = ContractValidator()
cv.register_contract(AgenticSafetyContract(
    agent_id="researcher",
    allowed_intents=["READ"],
    allowed_tools=["web_search"],
))
gate = AuthorityGate(notary, cv)
inspector = ContentInspector()
orchestration = OrchestrationGuard(cv)
audit = AuditBridge(mmr_base_url="http://localhost:8000", org_id="sentry-exp03")
mw = SentryMiddleware(notary, cv, gate, inspector, audit, orchestration)

expired_token = SignedToken(
    agent_id="researcher",
    issued_at=time.time() - 120,
    expires_at=time.time() - 60,
    allowed_contract_version="v1",
    signature_hex="00" * 64,
    payload_hash="00" * 32,
)

result = mw.process(
    token=expired_token,
    intent="READ",
    tool="web_search",
    message="Read something with expired token.",
)

output = {
    "experiment": "EXP-03",
    "title": "Identity Expiry Rejection - Impersonation Blocked",
    "agent_id": "researcher",
    "intent": "READ",
    "tool": "web_search",
    "message": "Read something with expired token.",
    "expected_decision": "REJECTED",
    "expected_gate": "identity",
    "actual_decision": result.decision,
    "actual_gate": result.gate_fired,
    "reason": result.reason,
    "owasp": "ASI03 (Agent Impersonation)",
    "mmr_staged_id": result.mmr_staged_id,
    "mmr_event_id": result.mmr_event_id,
    "leaf_hash": result.mmr_leaf_hash,
    "timestamp": time.time(),
}

verdict = result.decision == "REJECTED" and result.gate_fired == "identity"
has_leaf = result.mmr_leaf_hash is not None and len(result.mmr_leaf_hash) == 64
output["verdict"] = "CONFIRMED" if verdict and has_leaf else "FAILED"

print("  Decision:  " + result.decision)
print("  Gate:      " + result.gate_fired)
print("  Reason:    " + result.reason)
print("  Leaf Hash: " + str(result.mmr_leaf_hash))
print("  Verdict:   " + output["verdict"])
print(json.dumps(output, indent=2, default=str))
