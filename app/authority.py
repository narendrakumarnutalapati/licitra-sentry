"""
LICITRA-SENTRY Authority Gate.

Final authorization check before an agent's action is forwarded.
Combines identity token validation with contract enforcement to
produce a single APPROVED/REJECTED decision.

OWASP Agentic Coverage:
    ASI02 - Excessive Agency: Authority gate enforces least-privilege
            per agent. Agents cannot invoke tools outside their
            explicit allowed_tools list.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from app.identity import CovenantNotary, SignedToken
from app.contract import ContractValidator, ValidationResult


# ---------------------------------------------------------------------------
# Decision model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AuthorityDecision:
    """Outcome of the authority gate check."""
    decision: str          # "APPROVED" | "REJECTED"
    reason: str
    checked_at: float


# ---------------------------------------------------------------------------
# AuthorityGate
# ---------------------------------------------------------------------------

class AuthorityGate:
    """
    Validates that an agent holds a valid token AND that the requested
    intent and tool are permitted by the agent's contract.

    OWASP: ASI02 (Excessive Agency)
    """

    def __init__(
        self,
        notary: CovenantNotary,
        contract_validator: ContractValidator,
    ) -> None:
        self._notary = notary
        self._contract_validator = contract_validator

    def check(
        self,
        token: SignedToken,
        intent: str,
        tool: str,
    ) -> AuthorityDecision:
        """
        Run the authority check.

        Steps:
            1. Validate the token (signature + expiry) via CovenantNotary.
            2. Validate intent is in contract via ContractValidator.
            3. Validate tool is in contract via ContractValidator.

        Returns AuthorityDecision with the first failure reason,
        or APPROVED if all checks pass.
        """
        now = time.time()

        # 1. Token validation
        token_valid, token_reason = self._notary.validate_token(token)
        if not token_valid:
            return AuthorityDecision(
                decision="REJECTED",
                reason=f"Identity check failed: {token_reason}",
                checked_at=now,
            )

        # 2. Intent validation
        intent_result: ValidationResult = self._contract_validator.validate_intent(
            token.agent_id, intent
        )
        if not intent_result.ok:
            return AuthorityDecision(
                decision="REJECTED",
                reason=f"Contract check failed: {intent_result.reason}",
                checked_at=now,
            )

        # 3. Tool validation
        tool_result: ValidationResult = self._contract_validator.validate_tool(
            token.agent_id, tool
        )
        if not tool_result.ok:
            return AuthorityDecision(
                decision="REJECTED",
                reason=f"Contract check failed: {tool_result.reason}",
                checked_at=now,
            )

        return AuthorityDecision(
            decision="APPROVED",
            reason="Authority check passed: token valid, intent and tool allowed",
            checked_at=now,
        )
