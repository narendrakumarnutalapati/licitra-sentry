import json
import hashlib
import urllib.request
from app.identity import CovenantNotary
from app.contract import AgenticSafetyContract, ContractValidator, ParameterShape
from app.authority import AuthorityGate
from app.content_inspector import ContentInspector
from app.audit_bridge import AuditBridge
from app.middleware import SentryMiddleware
from app.orchestration import OrchestrationGuard

ORG_ID = "sentry-e2e-proof"
MMR_BASE = "http://localhost:8000"


def get_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))


def post_empty(url: str) -> dict:
    req = urllib.request.Request(url=url, data=b"", method="POST")
    with urllib.request.urlopen(req, timeout=15) as resp:
        raw = resp.read().decode("utf-8").strip()
        return json.loads(raw) if raw else {}


# reset org in DEV_MODE
post_empty(f"{MMR_BASE}/dev/reset/{ORG_ID}")

notary = CovenantNotary(ttl_seconds=60)
notary.register_agent("researcher")

cv = ContractValidator()
cv.register_contract(AgenticSafetyContract(
    agent_id="researcher",
    allowed_intents=["READ"],
    allowed_tools=["web_search"],
    parameter_shapes={"READ": [ParameterShape(name="source", type="str")]},
))

gate = AuthorityGate(notary, cv)
inspector = ContentInspector()
orchestration = OrchestrationGuard(cv)
audit = AuditBridge(mmr_base_url=MMR_BASE, org_id=ORG_ID)
mw = SentryMiddleware(notary, cv, gate, inspector, audit, orchestration)

token = notary.issue_token("researcher")

result = mw.process(
    token=token,
    intent="READ",
    tool="web_search",
    message="Please read the quarterly earnings report for Q4.",
    params={"source": "quarterly_report.pdf"},
)

if result.decision != "APPROVED":
    raise SystemExit(f"SENTRY did not approve request: {result.reason}")

# second event to force epoch finalization when BLOCK_SIZE=2
audit.emit({
    "agent_id": "researcher",
    "intent": "READ",
    "tool": "web_search",
    "decision": "APPROVED",
    "gate_fired": "approved",
    "reason": "epoch finalize trigger",
})

verify = get_json(f"{MMR_BASE}/verify/{ORG_ID}")
proof = get_json(f"{MMR_BASE}/proof/{ORG_ID}/{result.mmr_event_id}")

output = {
    "experiment": "EXP-E2E-MMR-PROOF",
    "org_id": ORG_ID,
    "decision": result.decision,
    "gate": result.gate_fired,
    "mmr_staged_id": result.mmr_staged_id,
    "mmr_event_id": result.mmr_event_id,
    "leaf_hash": result.mmr_leaf_hash,
    "verify_ok": verify.get("ok"),
    "verify_epochs": verify.get("epochs"),
    "verify_total_events": verify.get("total_events"),
    "last_epoch_hash": verify.get("last_epoch_hash"),
    "proof_event_id": proof.get("event_id"),
    "proof_leaf_hash": proof.get("leaf_hash"),
    "proof_mmr_root": proof.get("mmr_root"),
    "proof_epoch_hash": proof.get("epoch_hash"),
    "proof_path_len": len(proof.get("proof_path", [])),
    "verdict": "CONFIRMED" if (
        result.decision == "APPROVED"
        and verify.get("ok") is True
        and proof.get("event_id") == result.mmr_event_id
        and proof.get("leaf_hash") == result.mmr_leaf_hash
    ) else "FAILED",
}

print(json.dumps(output, indent=2))
