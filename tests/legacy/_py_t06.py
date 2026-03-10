import sys
from app.audit_bridge import AuditBridge

test = sys.argv[1]
bridge = AuditBridge(mmr_base_url="http://localhost:8000", org_id="sentry-test-t06")

if test == "1":
    r = bridge.emit({"agent_id": "test-agent", "intent": "READ", "decision": "APPROVED", "reason": "test"})
    has_staged = r.staged_id is not None
    has_event = r.event_id is not None
    has_leaf = r.leaf_hash is not None and len(r.leaf_hash) == 64
    print(str(r.success) + "|" + str(has_staged) + "|" + str(has_event) + "|" + str(has_leaf))

elif test == "2":
    r = bridge.emit({"agent_id": "test-agent", "intent": "DELETE", "decision": "REJECTED", "reason": "not allowed"})
    has_leaf = r.leaf_hash is not None and len(r.leaf_hash) == 64
    print(str(r.success) + "|" + r.decision if hasattr(r, "decision") else str(r.success) + "|" + str(has_leaf))

elif test == "3":
    r = bridge.emit({"agent_id": "test-agent", "intent": "READ", "decision": "REJECTED", "reason": "inspection block", "inspection_findings": [{"rule_id": "RI-001"}]})
    has_leaf = r.leaf_hash is not None and len(r.leaf_hash) == 64
    print(str(r.success) + "|" + str(has_leaf))
