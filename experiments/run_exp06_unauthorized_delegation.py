"""
EXP-06: Unauthorized Delegation Blocked — Orchestration Guard
Hypothesis: The orchestration guard blocks an agent from delegating
            to another agent when not explicitly authorized.
OWASP: ASI05 (Improper Multi-Agent Orchestration)
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json, time
from app.identity import CovenantNotary
from app.contract import AgenticSafetyContract, ContractValidator
from app.authority import AuthorityGate
from app.content_inspector import ContentInspector
from app.audit_bridge import AuditBridge
from app.middleware import SentryMiddleware
from app.orchestration import OrchestrationGuard

print("\n  EXP-06: Unauthorized Delegation Blocked - Orchestration Guard")
print("  " + "=" * 50)

notary = CovenantNotary(ttl_seconds=60)
notary.register_agent("researcher")
notary.register_agent("coder")
cv = ContractValidator()
cv.register_contract(AgenticSafetyContract(
    agent_id="researcher",
    allowed_intents=["READ", "SUMMARIZE"],
    allowed_tools=["web_search", "doc_reader"],
))
cv.register_contract(AgenticSafetyContract(
    agent_id="coder",
    allowed_intents=["FILE_WRITE", "RUN_TEST"],
    allowed_tools=["editor", "test_runner"],
))
gate = AuthorityGate(notary, cv)
inspector = ContentInspector()
orchestration = OrchestrationGuard(cv)
# Only allow researcher -> coder, NOT coder -> researcher
orchestration.allow_delegation("researcher", "coder")

audit = AuditBridge(mmr_base_url="http://localhost:8000", org_id="sentry-exp06")
mw = SentryMiddleware(notary, cv, gate, inspector, audit, orchestration)

token = notary.issue_token("coder")
result = mw.process(
    token=token,
    intent="FILE_WRITE",
    tool="editor",
    message="Delegate file write task to researcher",
    delegate_to="researcher",
)

output = {
    "experiment": "EXP-06",
    "title": "Unauthorized Delegation Blocked - Orchestration Guard",
    "agent_id": "coder",
    "intent": "FILE_WRITE",
    "tool": "editor",
    "message": "Delegate file write task to researcher",
    "delegate_to": "researcher",
    "expected_decision": "REJECTED",
    "expected_gate": "orchestration",
    "actual_decision": result.decision,
    "actual_gate": result.gate_fired,
    "reason": result.reason,
    "owasp": "ASI05 (Improper Multi-Agent Orchestration)",
    "mmr_staged_id": result.mmr_staged_id,
    "mmr_event_id": result.mmr_event_id,
    "leaf_hash": result.mmr_leaf_hash,
    "timestamp": time.time(),
}

verdict = result.decision == "REJECTED" and result.gate_fired == "orchestration"
has_leaf = result.mmr_leaf_hash is not None and len(result.mmr_leaf_hash) == 64
output["verdict"] = "CONFIRMED" if verdict and has_leaf else "FAILED"

print("  Decision:  " + result.decision)
print("  Gate:      " + result.gate_fired)
print("  Reason:    " + result.reason)
print("  Leaf Hash: " + str(result.mmr_leaf_hash))
print("  Verdict:   " + output["verdict"])
print(json.dumps(output, indent=2, default=str))
