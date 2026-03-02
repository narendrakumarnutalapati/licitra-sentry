"""
LICITRA-SENTRY Semantic Contract Engine.

Defines AgenticSafetyContract and ContractValidator. Every agent is
bound to a contract that specifies exactly which intents, tools, and
parameter shapes it may use. Validation is pure and deterministic -
no LLM calls, no network calls.

OWASP Agentic Coverage:
    ASI01 - Prompt Injection / Relay Injection: Contract engine rejects
            intents not in the agent's allowed list; an injected
            instruction cannot forge a valid contract entry.
    ASI02 - Excessive Agency: Allowed tools and parameter shapes enforce
            least-privilege at the semantic level.
    ASI06 - Sensitive Data Exposure: Parameter shape validation blocks
            unauthorized data access patterns at the intent level.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Contract schema (Pydantic)
# ---------------------------------------------------------------------------

class ParameterShape(BaseModel):
    """
    Defines an allowed parameter shape for a given intent.

    name    - parameter name (e.g. "path")
    type    - expected Python type name ("str", "int", "bool", "float")
    pattern - optional regex the string value must match
    """
    name: str
    type: str = "str"
    pattern: Optional[str] = None


class AgenticSafetyContract(BaseModel):
    """
    A safety contract binding an agent to a specific set of capabilities.

    Fields:
        version          - contract schema version (e.g. "v1")
        agent_id         - the agent this contract is bound to
        allowed_intents  - list of intent verbs this agent may use
        allowed_tools    - list of tools this agent may invoke
        parameter_shapes - per-intent parameter constraints
    """
    version: str = "v1"
    agent_id: str
    allowed_intents: list[str] = Field(default_factory=list)
    allowed_tools: list[str] = Field(default_factory=list)
    parameter_shapes: dict[str, list[ParameterShape]] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Validation result
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ValidationResult:
    """Outcome of contract validation."""
    ok: bool
    decision: str          # "APPROVED" | "REJECTED"
    reason: str


# ---------------------------------------------------------------------------
# ContractValidator
# ---------------------------------------------------------------------------

_TYPE_MAP: dict[str, type] = {
    "str": str,
    "int": int,
    "float": float,
    "bool": bool,
}


class ContractValidator:
    """
    Pure, deterministic validator for AgenticSafetyContract.

    OWASP: ASI01 (Prompt/Relay Injection), ASI02 (Excessive Agency),
           ASI06 (Sensitive Data Exposure)
    """

    def __init__(self) -> None:
        self._contracts: dict[str, AgenticSafetyContract] = {}

    def register_contract(self, contract: AgenticSafetyContract) -> None:
        """Bind a contract to its agent_id."""
        self._contracts[contract.agent_id] = contract

    def get_contract(self, agent_id: str) -> Optional[AgenticSafetyContract]:
        """Retrieve the contract for an agent, or None."""
        return self._contracts.get(agent_id)

    def validate_intent(
        self,
        agent_id: str,
        intent: str,
    ) -> ValidationResult:
        """Check whether an intent is allowed for the given agent."""
        contract = self._contracts.get(agent_id)
        if contract is None:
            return ValidationResult(
                ok=False,
                decision="REJECTED",
                reason=f"No contract registered for agent '{agent_id}'",
            )

        if intent not in contract.allowed_intents:
            return ValidationResult(
                ok=False,
                decision="REJECTED",
                reason=(
                    f"Intent '{intent}' is not allowed for agent '{agent_id}'. "
                    f"Allowed: {contract.allowed_intents}"
                ),
            )

        return ValidationResult(ok=True, decision="APPROVED", reason="Intent is allowed")

    def validate_tool(
        self,
        agent_id: str,
        tool: str,
    ) -> ValidationResult:
        """Check whether a tool is allowed for the given agent."""
        contract = self._contracts.get(agent_id)
        if contract is None:
            return ValidationResult(
                ok=False,
                decision="REJECTED",
                reason=f"No contract registered for agent '{agent_id}'",
            )

        if tool not in contract.allowed_tools:
            return ValidationResult(
                ok=False,
                decision="REJECTED",
                reason=(
                    f"Tool '{tool}' is not allowed for agent '{agent_id}'. "
                    f"Allowed: {contract.allowed_tools}"
                ),
            )

        return ValidationResult(ok=True, decision="APPROVED", reason="Tool is allowed")

    def validate_parameters(
        self,
        agent_id: str,
        intent: str,
        params: dict[str, Any],
    ) -> ValidationResult:
        """
        Validate parameter shapes for a given intent.

        Checks:
            1. Each parameter's type matches the shape spec.
            2. If a regex pattern is defined, the value must match.
        """
        contract = self._contracts.get(agent_id)
        if contract is None:
            return ValidationResult(
                ok=False,
                decision="REJECTED",
                reason=f"No contract registered for agent '{agent_id}'",
            )

        shapes = contract.parameter_shapes.get(intent)
        if shapes is None:
            # No parameter constraints defined - pass through
            return ValidationResult(
                ok=True,
                decision="APPROVED",
                reason="No parameter shapes defined for this intent",
            )

        for shape in shapes:
            value = params.get(shape.name)
            if value is None:
                return ValidationResult(
                    ok=False,
                    decision="REJECTED",
                    reason=f"Missing required parameter '{shape.name}' for intent '{intent}'",
                )

            expected_type = _TYPE_MAP.get(shape.type)
            if expected_type is not None and not isinstance(value, expected_type):
                return ValidationResult(
                    ok=False,
                    decision="REJECTED",
                    reason=(
                        f"Parameter '{shape.name}' expected type '{shape.type}', "
                        f"got '{type(value).__name__}'"
                    ),
                )

            if shape.pattern is not None and isinstance(value, str):
                if not re.match(shape.pattern, value):
                    return ValidationResult(
                        ok=False,
                        decision="REJECTED",
                        reason=(
                            f"Parameter '{shape.name}' value '{value}' does not match "
                            f"pattern '{shape.pattern}'"
                        ),
                    )

        return ValidationResult(
            ok=True,
            decision="APPROVED",
            reason="All parameter shapes valid",
        )

    def validate_full(
        self,
        agent_id: str,
        intent: str,
        tool: str,
        params: Optional[dict[str, Any]] = None,
    ) -> ValidationResult:
        """
        Full contract validation: intent + tool + parameter shapes.
        Short-circuits on first failure.
        """
        result = self.validate_intent(agent_id, intent)
        if not result.ok:
            return result

        result = self.validate_tool(agent_id, tool)
        if not result.ok:
            return result

        if params is not None:
            result = self.validate_parameters(agent_id, intent, params)
            if not result.ok:
                return result

        return ValidationResult(
            ok=True,
            decision="APPROVED",
            reason="Contract validation passed",
        )
