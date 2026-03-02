"""
LICITRA-SENTRY Orchestration Guard.

Prevents improper multi-agent delegation by enforcing:
    1. Explicit delegation policies (who can delegate to whom)
    2. Privilege non-escalation (delegated task cannot exceed
       the delegator's own contract permissions)

OWASP Agentic Coverage:
    ASI05 - Improper Multi-Agent Orchestration: Delegation is only
            permitted when explicitly configured, and the delegated
            intent must be within the delegator's own allowed set.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from app.contract import ContractValidator


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DelegationResult:
    """Outcome of a delegation check."""
    ok: bool
    decision: str          # "APPROVED" | "REJECTED"
    reason: str


# ---------------------------------------------------------------------------
# OrchestrationGuard
# ---------------------------------------------------------------------------

class OrchestrationGuard:
    """
    Controls inter-agent delegation.

    Delegation policy is a dict mapping delegator agent_id to a set
    of agent_ids they are allowed to delegate to.

    Privilege non-escalation: the delegated intent must exist in the
    delegator's own contract. An agent cannot launder privileges by
    delegating tasks it is not itself permitted to perform.

    OWASP: ASI05 (Improper Multi-Agent Orchestration)
    """

    def __init__(self, contract_validator: ContractValidator) -> None:
        self._contract_validator = contract_validator
        self._delegation_policy: dict[str, set[str]] = {}

    def allow_delegation(self, from_agent: str, to_agent: str) -> None:
        """Permit from_agent to delegate tasks to to_agent."""
        if from_agent not in self._delegation_policy:
            self._delegation_policy[from_agent] = set()
        self._delegation_policy[from_agent].add(to_agent)

    def is_delegation_allowed(self, from_agent: str, to_agent: str) -> bool:
        """Check if from_agent is allowed to delegate to to_agent."""
        return to_agent in self._delegation_policy.get(from_agent, set())

    def check_delegation(
        self,
        from_agent: str,
        to_agent: str,
        intent: str,
    ) -> DelegationResult:
        """
        Validate a delegation request.

        Checks:
            1. Is from_agent allowed to delegate to to_agent?
            2. Is the intent within from_agent's own contract?
               (privilege non-escalation)
            3. Is to_agent registered with a contract?

        Returns DelegationResult with first failure, or APPROVED.
        """
        # 1. Delegation policy check
        if not self.is_delegation_allowed(from_agent, to_agent):
            return DelegationResult(
                ok=False,
                decision="REJECTED",
                reason=(
                    f"Agent '{from_agent}' is not authorized to delegate "
                    f"to agent '{to_agent}'"
                ),
            )

        # 2. Privilege non-escalation: delegator must own the intent
        delegator_check = self._contract_validator.validate_intent(
            from_agent, intent
        )
        if not delegator_check.ok:
            return DelegationResult(
                ok=False,
                decision="REJECTED",
                reason=(
                    f"Privilege escalation blocked: agent '{from_agent}' "
                    f"cannot delegate intent '{intent}' because it is not "
                    f"in their own contract. {delegator_check.reason}"
                ),
            )

        # 3. Target agent must have a contract
        target_contract = self._contract_validator.get_contract(to_agent)
        if target_contract is None:
            return DelegationResult(
                ok=False,
                decision="REJECTED",
                reason=f"Target agent '{to_agent}' has no registered contract",
            )

        return DelegationResult(
            ok=True,
            decision="APPROVED",
            reason=(
                f"Delegation approved: '{from_agent}' -> '{to_agent}' "
                f"for intent '{intent}'"
            ),
        )
