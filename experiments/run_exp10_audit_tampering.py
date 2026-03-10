"""
EXP-10: Audit Ledger Tampering
Stored event record modified directly.
Expected: ledger verification failed (root mismatch / integrity failure).
Validates LICITRA-MMR tamper-evident integrity.
"""

import json
import urllib.request
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.audit_bridge import AuditBridge

ORG_ID = "sentry-exp10"
MMR_BASE = "http://localhost:8000"


def get_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))


def post_empty(url: str) -> dict:
    req = urllib.request.Request(url=url, data=b"", method="POST")
    with urllib.request.urlopen(req, timeout=15) as resp:
        raw = resp.read().decode("utf-8").strip()
        return json.loads(raw) if raw else {}


def main():
    # clean org
    post_empty(f"{MMR_BASE}/dev/reset/{ORG_ID}")

    audit = AuditBridge(mmr_base_url=MMR_BASE, org_id=ORG_ID)

    # event 1
    r1 = audit.emit({
        "agent_id": "researcher",
        "intent": "READ",
        "tool": "web_search",
        "decision": "APPROVED",
        "gate_fired": "approved",
        "reason": "baseline event one",
    })

    # event 2 -> finalize epoch because BLOCK_SIZE=2
    r2 = audit.emit({
        "agent_id": "researcher",
        "intent": "READ",
        "tool": "web_search",
        "decision": "APPROVED",
        "gate_fired": "approved",
        "reason": "baseline event two",
    })

    verify_before = get_json(f"{MMR_BASE}/verify/{ORG_ID}")

    # tamper first committed event directly in DEV_MODE
    tamper_result = post_empty(f"{MMR_BASE}/tamper/{ORG_ID}/{r1.event_id}")

    verify_after = get_json(f"{MMR_BASE}/verify/{ORG_ID}")

    verdict = "CONFIRMED" if (
        verify_before.get("ok") is True
        and verify_after.get("ok") is False
    ) else "FAILED"

    print(json.dumps({
        "experiment": "EXP-10",
        "title": "Audit Ledger Tampering",
        "org_id": ORG_ID,
        "event_id_tampered": r1.event_id,
        "leaf_hash_before_tamper": r1.leaf_hash,
        "verify_before": verify_before,
        "tamper_result": tamper_result,
        "verify_after": verify_after,
        "verdict": verdict,
    }, indent=2))

    sys.exit(0 if verdict == "CONFIRMED" else 1)


if __name__ == "__main__":
    main()
