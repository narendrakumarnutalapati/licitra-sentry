"""
EXP-01: Happy Path — Approved
Hypothesis: A valid agent with allowed intent, tool, and clean message
            passes all gates and is anchored in LICITRA-MMR.
OWASP: ASI07 (Inter-Agent Communication Integrity)
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json, time
from app.identity import CovenantNotary
from app.contract import AgenticSafetyContract, ContractValidator, ParameterShape
from app.authority import AuthorityGate
from app.content_inspector import ContentInspector
from app.audit_bridge import AuditBridge
from app.middleware import SentryMiddleware
from app.orchestration import OrchestrationGuard

print("\n  EXP-01: Happy Path - Approved")
print("  " + "=" * 50)

notary = CovenantNotary(ttl_seconds=60)
notary.register_agent("researcher")
cv = ContractValidator()
cv.register_contract(AgenticSafetyContract(
    agent_id="researcher",
    allowed_intents=["READ", "SUMMARIZE"],
    allowed_tools=["web_search", "doc_reader"],
    parameter_shapes={"READ": [ParameterShape(name="source", type="str")]},
))
gate = AuthorityGate(notary, cv)
inspector = ContentInspector()
orchestration = OrchestrationGuard(cv)
audit = AuditBridge(mmr_base_url="http://localhost:8000", org_id="sentry-exp01")
mw = SentryMiddleware(notary, cv, gate, inspector, audit, orchestration)

token = notary.issue_token("researcher")
result = mw.process(
    token=token,
    intent="READ",
    tool="web_search",
    message="Please read the quarterly earnings report for Q4.",
    params={"source": "quarterly_report.pdf"},
)

output = {
    "experiment": "EXP-01",
    "title": "Happy Path - Approved",
    "agent_id": "researcher",
    "intent": "READ",
    "tool": "web_search",
    "message": "Please read the quarterly earnings report for Q4.",
    "expected_decision": "APPROVED",
    "expected_gate": "approved",
    "actual_decision": result.decision,
    "actual_gate": result.gate_fired,
    "reason": result.reason,
    "owasp": "ASI07 (Inter-Agent Communication Integrity)",
    "mmr_staged_id": result.mmr_staged_id,
    "mmr_event_id": result.mmr_event_id,
    "leaf_hash": result.mmr_leaf_hash,
    "timestamp": time.time(),
}

verdict = result.decision == "APPROVED" and result.gate_fired == "approved"
has_leaf = result.mmr_leaf_hash is not None and len(result.mmr_leaf_hash) == 64
output["verdict"] = "CONFIRMED" if verdict and has_leaf else "FAILED"

print("  Decision:  " + result.decision)
print("  Gate:      " + result.gate_fired)
print("  Leaf Hash: " + str(result.mmr_leaf_hash))
print("  Verdict:   " + output["verdict"])
print(json.dumps(output, indent=2, default=str))
