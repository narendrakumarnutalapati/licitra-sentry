"""
LICITRA-SENTRY v0.2 — Gate 4: Authority Enforcement

Enforces the rule: delegation cannot escalate privileges.

When Agent A delegates to Agent B, Agent B's effective permissions
are bounded by Agent A's permissions. This prevents privilege
laundering through delegation chains.

Author: Narendra Kumar Nutalapati
License: MIT
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AuthorityResult:
    authorized: bool
    effective_permissions: set = field(default_factory=set)
    delegation_chain: list[str] = field(default_factory=list)
    violations: list[str] = field(default_factory=list)
    error: Optional[str] = None


class AuthorityEnforcer:
    """
    Gate 4: Enforce authority constraints on delegation.

    Rules:
      1. An agent can only perform actions within its own permissions.
      2. When delegating, the delegatee's permissions are the INTERSECTION
         of the delegator's permissions and the delegatee's own permissions.
      3. Delegation depth is bounded (default: 3 levels).
    """

    MAX_DELEGATION_DEPTH = 3

    def __init__(self):
        self._permissions: dict[str, set] = {}
        self._delegations: dict[str, str] = {}  # agent -> delegator

    def register_permissions(self, agent_id: str, permissions: set):
        self._permissions[agent_id] = permissions

    def register_delegation(self, delegatee_id: str, delegator_id: str):
        self._delegations[delegatee_id] = delegator_id

    def evaluate(
        self,
        agent_id: str,
        requested_action: str,
        tool_id: str,
    ) -> AuthorityResult:
        """
        Evaluate whether an agent has authority for the requested action,
        considering the full delegation chain.
        """
        # Build delegation chain
        chain = [agent_id]
        current = agent_id
        while current in self._delegations:
            delegator = self._delegations[current]
            chain.append(delegator)
            current = delegator
            if len(chain) > self.MAX_DELEGATION_DEPTH + 1:
                return AuthorityResult(
                    authorized=False,
                    delegation_chain=chain,
                    violations=[
                        f"Delegation depth {len(chain)-1} exceeds maximum "
                        f"{self.MAX_DELEGATION_DEPTH}"
                    ],
                )

        # Compute effective permissions (intersection along chain)
        effective = None
        violations = []

        for aid in chain:
            perms = self._permissions.get(aid, set())
            if effective is None:
                effective = set(perms)
            else:
                effective = effective.intersection(perms)

        effective = effective or set()

        # Check if requested action + tool is within effective permissions
        action_key = f"{tool_id}:{requested_action}"
        tool_wildcard = f"{tool_id}:*"
        global_wildcard = "*:*"

        has_permission = (
            action_key in effective
            or tool_wildcard in effective
            or global_wildcard in effective
        )

        if not has_permission:
            violations.append(
                f"Action '{action_key}' not in effective permissions. "
                f"Effective: {effective}"
            )

        return AuthorityResult(
            authorized=has_permission,
            effective_permissions=effective,
            delegation_chain=chain,
            violations=violations,
        )

# ---------------------------------------------------------------------------
# Legacy compatibility API (v0.1-compat)
# ---------------------------------------------------------------------------

@dataclass
class AuthorityDecision:
    decision: str
    reason: str
    effective_permissions: set = field(default_factory=set)
    delegation_chain: list[str] = field(default_factory=list)


class AuthorityGate:
    """
    Legacy middleware-compatible authority facade.

    Uses the registered contract as the approval source for the older
    experiment pipeline. This is additive and does not replace the
    v0.2 AuthorityEnforcer path.
    """

    def __init__(self, notary, contract_validator):
        self._notary = notary
        self._contract_validator = contract_validator

    def check(self, token, intent: str, tool: str) -> AuthorityDecision:
        contract = None
        if hasattr(self._contract_validator, "_contracts"):
            contract = self._contract_validator._contracts.get(token.agent_id)

        if contract is None:
            return AuthorityDecision(
                decision="REJECTED",
                reason=f"No contract registered for agent {token.agent_id}",
            )

        allowed_intents = getattr(contract, "allowed_intents", None)
        if allowed_intents is None and hasattr(contract, "allowed_actions"):
            allowed_intents = list(contract.allowed_actions)

        allowed_tools = getattr(contract, "allowed_tools", None)
        if allowed_tools is None:
            allowed_tools = []

        if allowed_intents and intent not in allowed_intents:
            return AuthorityDecision(
                decision="REJECTED",
                reason=f"Intent '{intent}' not allowed for agent {token.agent_id}",
            )

        if allowed_tools and tool not in allowed_tools:
            return AuthorityDecision(
                decision="REJECTED",
                reason=f"Tool '{tool}' not allowed for agent {token.agent_id}",
            )

        return AuthorityDecision(
            decision="APPROVED",
            reason="Authority granted",
        )
