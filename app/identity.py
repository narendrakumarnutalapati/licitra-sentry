"""
LICITRA-SENTRY v0.2 — Gate 1: Identity Verification

Authenticates the requesting agent before any other processing.
In v0.2, identity verification is a prerequisite for ticket issuance.

Author: Narendra Kumar Nutalapati
License: MIT
"""

import hashlib
import time
from dataclasses import dataclass
from typing import Optional


@dataclass
class AgentIdentity:
    agent_id: str
    agent_type: str         # e.g., "llm_agent", "human_proxy", "service"
    credential_hash: str    # SHA-256 of the credential (never store raw)
    organization: str = ""
    delegator_id: Optional[str] = None  # who delegated authority to this agent


@dataclass
class IdentityResult:
    authenticated: bool
    agent_id: str
    error: Optional[str] = None
    timestamp: float = 0.0


class IdentityVerifier:
    """
    Gate 1: Verify agent identity via credential lookup.

    In production, this would integrate with mTLS, OAuth, or
    organizational identity providers. This reference implementation
    uses a simple registry for demonstration.
    """

    def __init__(self):
        self._registry: dict[str, AgentIdentity] = {}

    def register_agent(self, identity: AgentIdentity):
        self._registry[identity.agent_id] = identity

    def verify(self, agent_id: str, credential: str) -> IdentityResult:
        now = time.time()

        if agent_id not in self._registry:
            return IdentityResult(
                authenticated=False,
                agent_id=agent_id,
                error=f"Unknown agent: {agent_id}",
                timestamp=now,
            )

        expected = self._registry[agent_id]
        presented_hash = hashlib.sha256(credential.encode()).hexdigest()

        if presented_hash != expected.credential_hash:
            return IdentityResult(
                authenticated=False,
                agent_id=agent_id,
                error="Credential mismatch",
                timestamp=now,
            )

        return IdentityResult(
            authenticated=True,
            agent_id=agent_id,
            timestamp=now,
        )

    def get_agent(self, agent_id: str) -> Optional[AgentIdentity]:
        return self._registry.get(agent_id)
