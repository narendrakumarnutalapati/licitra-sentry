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

# ---------------------------------------------------------------------------
# Legacy compatibility API (v0.1-compat)
# ---------------------------------------------------------------------------

@dataclass
class ParameterShape:
    name: str
    type: str


@dataclass
class AgenticSafetyContract:
    agent_id: str
    allowed_intents: list[str] = field(default_factory=list)
    allowed_tools: list[str] = field(default_factory=list)
    parameter_shapes: dict[str, list[ParameterShape]] = field(default_factory=dict)
    contract_id: str = ""
    contract_version: str = "v1"

    def to_semantic_contract(self) -> SemanticContract:
        return SemanticContract(
            contract_id=self.contract_id or f"legacy-{self.agent_id}",
            contract_version=self.contract_version,
            agent_id=self.agent_id,
            allowed_tools=set(self.allowed_tools),
            allowed_actions=set(self.allowed_intents),
        )


@dataclass
class LegacyValidationResult:
    ok: bool
    reason: str = ""


def _normalize_type_name(value) -> str:
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int) and not isinstance(value, bool):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "str"
    if isinstance(value, dict):
        return "dict"
    if isinstance(value, list):
        return "list"
    return type(value).__name__


def _register_contract_compat(self, contract):
    if isinstance(contract, AgenticSafetyContract):
        self._contracts[contract.agent_id] = contract
    else:
        self._contracts[contract.agent_id] = contract


def _validate_intent_compat(self, agent_id: str, intent: str) -> LegacyValidationResult:
    contract = self._contracts.get(agent_id)
    if contract is None:
        return LegacyValidationResult(ok=False, reason=f"No contract found for agent: {agent_id}")

    if isinstance(contract, AgenticSafetyContract):
        if intent not in contract.allowed_intents:
            return LegacyValidationResult(
                ok=False,
                reason=f"Intent '{intent}' not allowed for agent {agent_id}"
            )
        return LegacyValidationResult(ok=True, reason="OK")

    if isinstance(contract, SemanticContract):
        if contract.allowed_actions and intent not in contract.allowed_actions:
            return LegacyValidationResult(
                ok=False,
                reason=f"Action '{intent}' not allowed for agent {agent_id}"
            )
        return LegacyValidationResult(ok=True, reason="OK")

    return LegacyValidationResult(ok=False, reason="Unsupported contract type")


def _validate_full_compat(
    self,
    agent_id: str,
    intent: str,
    tool: str,
    params: Optional[dict] = None,
) -> LegacyValidationResult:
    contract = self._contracts.get(agent_id)
    if contract is None:
        return LegacyValidationResult(ok=False, reason=f"No contract found for agent: {agent_id}")

    params = params or {}

    if isinstance(contract, AgenticSafetyContract):
        if intent not in contract.allowed_intents:
            return LegacyValidationResult(
                ok=False,
                reason=f"Intent '{intent}' not allowed for agent {agent_id}"
            )

        if tool not in contract.allowed_tools:
            return LegacyValidationResult(
                ok=False,
                reason=f"Tool '{tool}' not allowed for agent {agent_id}"
            )

        expected_shapes = contract.parameter_shapes.get(intent, [])
        for shape in expected_shapes:
            if shape.name not in params:
                return LegacyValidationResult(
                    ok=False,
                    reason=f"Missing required parameter '{shape.name}' for intent '{intent}'"
                )

            actual_type = _normalize_type_name(params[shape.name])
            if actual_type != shape.type:
                return LegacyValidationResult(
                    ok=False,
                    reason=(
                        f"Parameter '{shape.name}' has type '{actual_type}', "
                        f"expected '{shape.type}'"
                    ),
                )

        return LegacyValidationResult(ok=True, reason="OK")

    if isinstance(contract, SemanticContract):
        result = self.validate(
            agent_id=agent_id,
            tool_id=tool,
            action=intent,
            request=params,
        )
        if result.permitted:
            return LegacyValidationResult(ok=True, reason="OK")
        if result.error:
            return LegacyValidationResult(ok=False, reason=result.error)
        return LegacyValidationResult(
            ok=False,
            reason="; ".join(result.violations) if result.violations else "Contract validation failed",
        )

    return LegacyValidationResult(ok=False, reason="Unsupported contract type")


# Monkey-patch compatibility methods onto ContractValidator without
# disturbing the current v0.2 validate(...) API.
ContractValidator.register_contract = _register_contract_compat
ContractValidator.validate_intent = _validate_intent_compat
ContractValidator.validate_full = _validate_full_compat
