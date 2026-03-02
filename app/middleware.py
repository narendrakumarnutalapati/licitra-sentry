"""
LICITRA-SENTRY Middleware Pipeline.

Orchestrates the full Chain of Intent - every inter-agent message
passes through sequential gates:

    1. validate_token       - identity check (CovenantNotary)
    2. inspect_content      - content inspection (ContentInspector)
    3. validate_contract    - semantic check (ContractValidator)
    4. validate_authority   - authority check (AuthorityGate)
    5. check_orchestration  - delegation guard (OrchestrationGuard)
       (only when delegate_to is specified)
    6. emit audit event     - anchor in LICITRA-MMR (AuditBridge)

If any gate rejects, the pipeline short-circuits and the rejection
is still committed to LICITRA-MMR for tamper-evident audit.

OWASP Agentic Coverage:
    ASI07 - Inter-Agent Communication Integrity: Every inter-agent
            message passes through the full Chain of Intent pipeline
            before forwarding. All decisions cryptographically
            anchored in MMR.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Optional

from app.identity import CovenantNotary, SignedToken
from app.contract import ContractValidator
from app.authority import AuthorityGate
from app.content_inspector import ContentInspector, Finding
from app.audit_bridge import AuditBridge, AuditResult
from app.orchestration import OrchestrationGuard


# ---------------------------------------------------------------------------
# Pipeline result
# ---------------------------------------------------------------------------

@dataclass
class MiddlewareResult:
    """Outcome of the full SENTRY middleware pipeline."""
    forwarded: bool
    decision: str                          # "APPROVED" | "REJECTED"
    reason: str
    gate_fired: str                        # which gate produced the decision
    inspection_findings: list[Finding] = field(default_factory=list)
    mmr_staged_id: Optional[int] = None
    mmr_event_id: Optional[str] = None
    mmr_leaf_hash: Optional[str] = None


# ---------------------------------------------------------------------------
# SentryMiddleware
# ---------------------------------------------------------------------------

class SentryMiddleware:
    """
    Chain of Intent pipeline.

    OWASP: ASI07 (Inter-Agent Communication Integrity)
    """

    def __init__(
        self,
        notary: CovenantNotary,
        contract_validator: ContractValidator,
        authority_gate: AuthorityGate,
        content_inspector: ContentInspector,
        audit_bridge: AuditBridge,
        orchestration_guard: Optional[OrchestrationGuard] = None,
    ) -> None:
        self._notary = notary
        self._contract_validator = contract_validator
        self._authority_gate = authority_gate
        self._inspector = content_inspector
        self._audit = audit_bridge
        self._orchestration = orchestration_guard

    def process(
        self,
        token: SignedToken,
        intent: str,
        tool: str,
        message: str,
        params: Optional[dict[str, Any]] = None,
        delegate_to: Optional[str] = None,
    ) -> MiddlewareResult:
        """
        Run the full pipeline.

        Steps:
            1. Identity   - validate token via Notary
            2. Inspection - scan message content
            3. Contract   - validate intent + tool + params
            4. Authority  - final authorization check
            5. Orchestration - delegation guard (if delegate_to set)
            6. Audit      - emit decision to LICITRA-MMR

        Returns MiddlewareResult with the decision and MMR anchoring info.
        """

        # -- Gate 1: Identity --------------------------------------------------
        token_valid, token_reason = self._notary.validate_token(token)
        if not token_valid:
            return self._finalize(
                forwarded=False,
                decision="REJECTED",
                reason="Identity check failed: " + token_reason,
                gate_fired="identity",
                token=token, intent=intent, tool=tool,
                message=message, delegate_to=delegate_to,
            )

        # -- Gate 2: Content Inspection ----------------------------------------
        inspection = self._inspector.inspect(message)
        if not inspection.clean:
            return self._finalize(
                forwarded=False,
                decision="REJECTED",
                reason="Content inspection blocked: " + inspection.severity + " severity finding(s)",
                gate_fired="inspector",
                token=token, intent=intent, tool=tool,
                message=message, delegate_to=delegate_to,
                findings=inspection.findings,
            )

        # -- Gate 3: Contract Validation ---------------------------------------
        contract_result = self._contract_validator.validate_full(
            agent_id=token.agent_id,
            intent=intent,
            tool=tool,
            params=params,
        )
        if not contract_result.ok:
            return self._finalize(
                forwarded=False,
                decision="REJECTED",
                reason="Contract validation failed: " + contract_result.reason,
                gate_fired="contract",
                token=token, intent=intent, tool=tool,
                message=message, delegate_to=delegate_to,
            )

        # -- Gate 4: Authority Check -------------------------------------------
        authority = self._authority_gate.check(token, intent, tool)
        if authority.decision != "APPROVED":
            return self._finalize(
                forwarded=False,
                decision="REJECTED",
                reason="Authority check failed: " + authority.reason,
                gate_fired="authority",
                token=token, intent=intent, tool=tool,
                message=message, delegate_to=delegate_to,
            )

        # -- Gate 5: Orchestration Guard (if delegation) -----------------------
        if delegate_to is not None and self._orchestration is not None:
            delegation = self._orchestration.check_delegation(
                from_agent=token.agent_id,
                to_agent=delegate_to,
                intent=intent,
            )
            if not delegation.ok:
                return self._finalize(
                    forwarded=False,
                    decision="REJECTED",
                    reason="Orchestration check failed: " + delegation.reason,
                    gate_fired="orchestration",
                    token=token, intent=intent, tool=tool,
                    message=message, delegate_to=delegate_to,
                )

        # -- Gate 6: Approved - emit to MMR ------------------------------------
        return self._finalize(
            forwarded=True,
            decision="APPROVED",
            reason="All gates passed",
            gate_fired="approved",
            token=token, intent=intent, tool=tool,
            message=message, delegate_to=delegate_to,
        )

    def _finalize(
        self,
        forwarded: bool,
        decision: str,
        reason: str,
        gate_fired: str,
        token: SignedToken,
        intent: str,
        tool: str,
        message: str,
        delegate_to: Optional[str] = None,
        findings: Optional[list[Finding]] = None,
    ) -> MiddlewareResult:
        """Build audit event and emit to LICITRA-MMR."""
        findings = findings or []

        audit_event = {
            "agent_id": token.agent_id,
            "intent": intent,
            "tool": tool,
            "message_preview": message[:200],
            "decision": decision,
            "reason": reason,
            "gate_fired": gate_fired,
            "delegate_to": delegate_to,
            "inspection_findings": [
                {
                    "rule_id": f.rule_id,
                    "rule_name": f.rule_name,
                    "category": f.category,
                    "severity": f.severity,
                    "action": f.action,
                }
                for f in findings
            ],
            "timestamp": time.time(),
        }

        audit_result: AuditResult = self._audit.emit(audit_event)

        return MiddlewareResult(
            forwarded=forwarded,
            decision=decision,
            reason=reason,
            gate_fired=gate_fired,
            inspection_findings=findings,
            mmr_staged_id=audit_result.staged_id,
            mmr_event_id=audit_result.event_id,
            mmr_leaf_hash=audit_result.leaf_hash,
        )
