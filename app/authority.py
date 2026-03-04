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
