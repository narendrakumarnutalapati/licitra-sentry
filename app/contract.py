"""
LICITRA-SENTRY v0.2 — Gate 3: Semantic Contract Validation

Evaluates whether an agent's requested action falls within its
defined semantic contract — a machine-evaluable specification of
what the agent is permitted to do.

Author: Narendra Kumar Nutalapati
License: MIT
"""

import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SemanticContract:
    """
    A semantic contract defines the boundaries of an agent's permitted actions.

    Fields:
        contract_id: Unique identifier.
        contract_version: Version string.
        agent_id: The agent this contract governs.
        allowed_tools: Set of tool IDs the agent may invoke.
        allowed_actions: Set of action types (e.g., "read", "write", "delete").
        scope_restrictions: Key-value constraints (e.g., {"region": "US-WEST"}).
        value_limits: Numeric constraints (e.g., {"max_amount": 10000}).
        temporal_restrictions: Time-based constraints (e.g., business hours).
        target_restrictions: Allowed targets (e.g., {"apis": ["internal.*"]}).
    """
    contract_id: str
    contract_version: str
    agent_id: str
    allowed_tools: set = field(default_factory=set)
    allowed_actions: set = field(default_factory=set)
    scope_restrictions: dict = field(default_factory=dict)
    value_limits: dict = field(default_factory=dict)
    temporal_restrictions: dict = field(default_factory=dict)
    target_restrictions: dict = field(default_factory=dict)


@dataclass
class ContractResult:
    permitted: bool
    contract_id: str
    contract_version: str
    violations: list[str] = field(default_factory=list)
    error: Optional[str] = None


class ContractValidator:
    """
    Gate 3: Validate tool requests against semantic contracts.

    The contract defines what an agent CAN do. The validator checks
    whether a specific request falls within those bounds.
    """

    def __init__(self):
        self._contracts: dict[str, SemanticContract] = {}

    def register_contract(self, contract: SemanticContract):
        self._contracts[contract.agent_id] = contract

    def validate(
        self,
        agent_id: str,
        tool_id: str,
        action: str,
        request: dict,
    ) -> ContractResult:
        """
        Validate a request against the agent's semantic contract.

        Checks:
          1. Agent has a registered contract
          2. Tool is in allowed_tools
          3. Action is in allowed_actions
          4. Scope restrictions are satisfied
          5. Value limits are respected
        """
        if agent_id not in self._contracts:
            return ContractResult(
                permitted=False,
                contract_id="",
                contract_version="",
                error=f"No contract found for agent: {agent_id}",
            )

        contract = self._contracts[agent_id]
        violations = []

        # Check tool allowlist
        if contract.allowed_tools and tool_id not in contract.allowed_tools:
            violations.append(
                f"Tool '{tool_id}' not in allowed_tools: {contract.allowed_tools}"
            )

        # Check action allowlist
        if contract.allowed_actions and action not in contract.allowed_actions:
            violations.append(
                f"Action '{action}' not in allowed_actions: {contract.allowed_actions}"
            )

        # Check scope restrictions
        for key, allowed_value in contract.scope_restrictions.items():
            request_value = request.get(key)
            if request_value is not None:
                if isinstance(allowed_value, list):
                    if request_value not in allowed_value:
                        violations.append(
                            f"Scope violation: {key}={request_value}, "
                            f"allowed={allowed_value}"
                        )
                elif request_value != allowed_value:
                    violations.append(
                        f"Scope violation: {key}={request_value}, "
                        f"allowed={allowed_value}"
                    )

        # Check value limits
        for key, max_val in contract.value_limits.items():
            request_value = request.get(key)
            if request_value is not None:
                try:
                    if float(request_value) > float(max_val):
                        violations.append(
                            f"Value limit exceeded: {key}={request_value}, "
                            f"max={max_val}"
                        )
                except (ValueError, TypeError):
                    pass

        return ContractResult(
            permitted=len(violations) == 0,
            contract_id=contract.contract_id,
            contract_version=contract.contract_version,
            violations=violations,
        )

    def get_contract(self, agent_id: str) -> Optional[SemanticContract]:
        return self._contracts.get(agent_id)
