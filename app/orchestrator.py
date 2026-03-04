"""
LICITRA-SENTRY v0.2 — Authorization Orchestrator

Orchestrates the five-gate Chain of Intent pipeline and issues
execution tickets upon successful authorization.

Pipeline:
  Gate 1: Identity Verification
  Gate 2: Content Inspection
  Gate 3: Semantic Contract Validation
  Gate 4: Authority Enforcement
  Gate 5: Cryptographic Commit (audit + ticket issuance)

Every gate decision — approved or rejected — is committed to the
audit ledger before the pipeline continues.

Author: Narendra Kumar Nutalapati
License: MIT
"""

import time
import uuid
import json
from dataclasses import dataclass, field
from typing import Optional

from app.identity import IdentityVerifier, IdentityResult
from app.content_inspector import ContentInspector, InspectionResult
from app.contract import ContractValidator, ContractResult
from app.authority import AuthorityEnforcer, AuthorityResult
from app.audit_bridge import AuditBridge, AuditEvent
from app.ticket import ExecutionTicket, issue_ticket
from app.key_manager import KeyProvider


@dataclass
class AuthorizationRequest:
    """Incoming authorization request from an agent."""
    agent_id: str
    credential: str
    tool_id: str
    action: str
    request: dict
    policy_version: str = "1.0"


@dataclass
class GateDecision:
    gate: str
    passed: bool
    details: dict = field(default_factory=dict)


@dataclass
class AuthorizationResult:
    authorized: bool
    request_id: str
    agent_id: str
    tool_id: str
    gates: list[GateDecision] = field(default_factory=list)
    ticket: Optional[ExecutionTicket] = None
    rejection_reason: Optional[str] = None
    mmr_commit_id: str = ""
    processing_time_ms: float = 0.0


class SentryOrchestrator:
    """
    The SENTRY authorization orchestrator.

    Evaluates all five gates in sequence. If any gate rejects,
    the pipeline stops and the rejection is committed to audit.
    If all gates pass, an execution ticket is issued.
    """

    def __init__(
        self,
        identity_verifier: IdentityVerifier,
        content_inspector: ContentInspector,
        contract_validator: ContractValidator,
        authority_enforcer: AuthorityEnforcer,
        audit_bridge: AuditBridge,
        key_provider: KeyProvider,
    ):
        self.identity = identity_verifier
        self.inspector = content_inspector
        self.contract = contract_validator
        self.authority = authority_enforcer
        self.audit = audit_bridge
        self.key_provider = key_provider

    def authorize(self, req: AuthorizationRequest) -> AuthorizationResult:
        """
        Run the full five-gate authorization pipeline.

        Returns an AuthorizationResult with the ticket if approved,
        or the rejection reason if denied.
        """
        start = time.time()
        request_id = str(uuid.uuid4())
        gates = []

        # ====== GATE 1: Identity Verification ======
        id_result = self.identity.verify(req.agent_id, req.credential)
        gate1 = GateDecision(
            gate="identity",
            passed=id_result.authenticated,
            details={"error": id_result.error} if id_result.error else {},
        )
        gates.append(gate1)
        self._commit_gate_event(request_id, req, gate1)

        if not id_result.authenticated:
            return self._reject(request_id, req, gates, start,
                                f"Gate 1 (Identity): {id_result.error}")

        # ====== GATE 2: Content Inspection ======
        insp_result = self.inspector.inspect(req.request)
        gate2 = GateDecision(
            gate="content_inspection",
            passed=insp_result.passed,
            details={
                "risk_level": insp_result.risk_level,
                "findings_count": len(insp_result.findings),
            },
        )
        gates.append(gate2)
        self._commit_gate_event(request_id, req, gate2)

        if not insp_result.passed:
            return self._reject(request_id, req, gates, start,
                                f"Gate 2 (Content): risk={insp_result.risk_level}, "
                                f"findings={insp_result.findings}")

        # ====== GATE 3: Semantic Contract Validation ======
        contract_result = self.contract.validate(
            req.agent_id, req.tool_id, req.action, req.request,
        )
        gate3 = GateDecision(
            gate="contract",
            passed=contract_result.permitted,
            details={
                "contract_id": contract_result.contract_id,
                "contract_version": contract_result.contract_version,
                "violations": contract_result.violations,
            },
        )
        gates.append(gate3)
        self._commit_gate_event(request_id, req, gate3)

        if not contract_result.permitted:
            return self._reject(request_id, req, gates, start,
                                f"Gate 3 (Contract): {contract_result.violations}")

        # ====== GATE 4: Authority Enforcement ======
        auth_result = self.authority.evaluate(
            req.agent_id, req.action, req.tool_id,
        )
        gate4 = GateDecision(
            gate="authority",
            passed=auth_result.authorized,
            details={
                "delegation_chain": auth_result.delegation_chain,
                "violations": auth_result.violations,
            },
        )
        gates.append(gate4)
        self._commit_gate_event(request_id, req, gate4)

        if not auth_result.authorized:
            return self._reject(request_id, req, gates, start,
                                f"Gate 4 (Authority): {auth_result.violations}")

        # ====== GATE 5: Cryptographic Commit + Ticket Issuance ======
        commit_event = AuditEvent(
            event_id=f"{request_id}-commit",
            event_type="authorization_commit",
            timestamp=time.time(),
            agent_id=req.agent_id,
            tool_id=req.tool_id,
            gate="commit",
            decision="approved",
            details={
                "request_id": request_id,
                "action": req.action,
                "policy_version": req.policy_version,
                "contract_id": contract_result.contract_id,
                "contract_version": contract_result.contract_version,
            },
        )
        mmr_commit_id = self.audit.commit(commit_event)

        gate5 = GateDecision(
            gate="commit",
            passed=True,
            details={"mmr_commit_id": mmr_commit_id},
        )
        gates.append(gate5)

        # Issue execution ticket
        ticket = issue_ticket(
            key_provider=self.key_provider,
            agent_id=req.agent_id,
            tool_id=req.tool_id,
            request=req.request,
            policy_version=req.policy_version,
            contract_id=contract_result.contract_id,
            contract_version=contract_result.contract_version,
            mmr_commit_id=mmr_commit_id,
        )

        elapsed = (time.time() - start) * 1000

        return AuthorizationResult(
            authorized=True,
            request_id=request_id,
            agent_id=req.agent_id,
            tool_id=req.tool_id,
            gates=gates,
            ticket=ticket,
            mmr_commit_id=mmr_commit_id,
            processing_time_ms=elapsed,
        )

    def _reject(
        self,
        request_id: str,
        req: AuthorizationRequest,
        gates: list,
        start: float,
        reason: str,
    ) -> AuthorizationResult:
        elapsed = (time.time() - start) * 1000
        return AuthorizationResult(
            authorized=False,
            request_id=request_id,
            agent_id=req.agent_id,
            tool_id=req.tool_id,
            gates=gates,
            rejection_reason=reason,
            processing_time_ms=elapsed,
        )

    def _commit_gate_event(
        self,
        request_id: str,
        req: AuthorizationRequest,
        gate: GateDecision,
    ):
        event = AuditEvent(
            event_id=f"{request_id}-{gate.gate}",
            event_type=f"gate_{gate.gate}",
            timestamp=time.time(),
            agent_id=req.agent_id,
            tool_id=req.tool_id,
            gate=gate.gate,
            decision="passed" if gate.passed else "rejected",
            details=gate.details,
        )
        self.audit.commit(event)
