import json
import urllib.request
import urllib.error

from app.identity import CovenantNotary
from app.contract import AgenticSafetyContract, ContractValidator, ParameterShape
from app.authority import AuthorityGate
from app.content_inspector import ContentInspector
from app.audit_bridge import AuditBridge
from app.middleware import SentryMiddleware
from app.orchestration import OrchestrationGuard
from experiments._common import PreflightError, require_mmr_block_size

ORG_ID = "sentry-audit-tamper"
MMR_BASE = "http://localhost:8000"


def get_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))


def post_empty(url: str) -> dict:
    req = urllib.request.Request(url=url, data=b"", method="POST")
    with urllib.request.urlopen(req, timeout=15) as resp:
        raw = resp.read().decode("utf-8").strip()
        return json.loads(raw) if raw else {}


def main() -> None:
    try:
        mmr_health = require_mmr_block_size(2, mmr_base=MMR_BASE)
        print(
            f"[PRECHECK] MMR OK: block_size={mmr_health['block_size']} "
            f"ledger_mode={mmr_health['ledger_mode']} "
            f"dev_mode={mmr_health['dev_mode']}"
        )

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
            message="Read the security assessment.",
            params={"source": "security_assessment.pdf"},
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

        verify_before = get_json(f"{MMR_BASE}/verify/{ORG_ID}")

        tamper_response = post_empty(f"{MMR_BASE}/tamper/{ORG_ID}/{result.mmr_event_id}")

        verify_after = get_json(f"{MMR_BASE}/verify/{ORG_ID}")

        verify_before_ok = verify_before.get("ok")
        verify_after_ok = verify_after.get("ok")

        output = {
            "experiment": "EXP-AUDIT-TAMPERING",
            "org_id": ORG_ID,
            "decision": result.decision,
            "gate": result.gate_fired,
            "mmr_health_status": mmr_health.get("status"),
            "mmr_block_size": mmr_health.get("block_size"),
            "mmr_ledger_mode": mmr_health.get("ledger_mode"),
            "mmr_dev_mode": mmr_health.get("dev_mode"),
            "mmr_ledger_version": mmr_health.get("ledger_version"),
            "mmr_event_id": result.mmr_event_id,
            "verify_before_ok": verify_before_ok,
            "verify_before_epochs": verify_before.get("epochs"),
            "verify_before_total_events": verify_before.get("total_events"),
            "tamper_ok": tamper_response.get("ok"),
            "tamper_action": tamper_response.get("action"),
            "tamper_note": tamper_response.get("note"),
            "verify_after_ok": verify_after_ok,
            "verify_after_epochs": verify_after.get("epochs"),
            "verify_after_total_events": verify_after.get("total_events"),
            "verdict": "CONFIRMED" if (
                result.decision == "APPROVED"
                and verify_before_ok is True
                and tamper_response.get("ok") is True
                and verify_after_ok is False
            ) else "FAILED",
        }

        print(json.dumps(output, indent=2))

    except PreflightError as exc:
        result = {
            "experiment": "EXP-AUDIT-TAMPERING",
            "verdict": "INVALID",
            "stage": "preflight",
            "reason": str(exc),
        }
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
