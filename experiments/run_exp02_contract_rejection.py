"""
EXP-02: Contract Rejection — Excessive Agency Blocked
Hypothesis: The contract engine rejects an intent not in the agent's
            allowed list. Rejection is anchored in LICITRA-MMR.
OWASP: ASI02 (Excessive Agency)
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

print("\n  EXP-02: Contract Rejection - Excessive Agency Blocked")
print("  " + "=" * 50)

notary = CovenantNotary(ttl_seconds=60)
notary.register_agent("researcher")
cv = ContractValidator()
cv.register_contract(AgenticSafetyContract(
    agent_id="researcher",
    allowed_intents=["READ", "SUMMARIZE"],
    allowed_tools=["web_search", "doc_reader"],
))
gate = AuthorityGate(notary, cv)
inspector = ContentInspector()
orchestration = OrchestrationGuard(cv)
audit = AuditBridge(mmr_base_url="http://localhost:8000", org_id="sentry-exp02")
mw = SentryMiddleware(notary, cv, gate, inspector, audit, orchestration)

token = notary.issue_token("researcher")
result = mw.process(
    token=token,
    intent="FILE_WRITE",
    tool="editor",
    message="Write results to /tmp/output.txt",
)

output = {
    "experiment": "EXP-02",
    "title": "Contract Rejection - Excessive Agency Blocked",
    "agent_id": "researcher",
    "intent": "FILE_WRITE",
    "tool": "editor",
    "message": "Write results to /tmp/output.txt",
    "expected_decision": "REJECTED",
    "expected_gate": "contract",
    "actual_decision": result.decision,
    "actual_gate": result.gate_fired,
    "reason": result.reason,
    "owasp": "ASI02 (Excessive Agency)",
    "mmr_staged_id": result.mmr_staged_id,
    "mmr_event_id": result.mmr_event_id,
    "leaf_hash": result.mmr_leaf_hash,
    "timestamp": time.time(),
}

verdict = result.decision == "REJECTED" and result.gate_fired == "contract"
has_leaf = result.mmr_leaf_hash is not None and len(result.mmr_leaf_hash) == 64
output["verdict"] = "CONFIRMED" if verdict and has_leaf else "FAILED"

print("  Decision:  " + result.decision)
print("  Gate:      " + result.gate_fired)
print("  Reason:    " + result.reason)
print("  Leaf Hash: " + str(result.mmr_leaf_hash))
print("  Verdict:   " + output["verdict"])
print(json.dumps(output, indent=2, default=str))
