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
# ---------------------------------------------------------------------------
# Legacy compatibility API (v0.1-compat)
# ---------------------------------------------------------------------------

import hmac


@dataclass
class SignedToken:
    agent_id: str
    issued_at: float
    expires_at: float
    allowed_contract_version: str = "v1"
    signature_hex: str = ""
    payload_hash: str = ""


class CovenantNotary:
    """
    Legacy compatibility shim for experiment-era token issuance/validation.

    Preserves:
      - register_agent("agent_id")
      - issue_token("agent_id")
      - validate_token(token)

    This does NOT replace the v0.2 IdentityVerifier path.
    """

    def __init__(self, ttl_seconds: int = 60, secret: str = "licitra-sentry-notary"):
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be > 0")
        self.ttl_seconds = ttl_seconds
        self._secret = secret.encode("utf-8")
        self._registered_agents: set[str] = set()

    def register_agent(self, agent_id: str) -> None:
        self._registered_agents.add(agent_id)

    def issue_token(
        self,
        agent_id: str,
        allowed_contract_version: str = "v1",
        payload_hash: str = "",
    ) -> SignedToken:
        if agent_id not in self._registered_agents:
            raise ValueError(f"Agent not registered: {agent_id}")

        now = time.time()
        expires_at = now + self.ttl_seconds
        payload_hash = payload_hash or ("0" * 64)

        signature_hex = self._sign_fields(
            agent_id=agent_id,
            issued_at=now,
            expires_at=expires_at,
            allowed_contract_version=allowed_contract_version,
            payload_hash=payload_hash,
        )

        return SignedToken(
            agent_id=agent_id,
            issued_at=now,
            expires_at=expires_at,
            allowed_contract_version=allowed_contract_version,
            signature_hex=signature_hex,
            payload_hash=payload_hash,
        )

    def validate_token(self, token: SignedToken) -> tuple[bool, str]:
        if not isinstance(token, SignedToken):
            return False, "Invalid token object"

        if token.agent_id not in self._registered_agents:
            return False, f"Unknown agent: {token.agent_id}"

        now = time.time()

        # Expiry check first so EXP-03 deterministically fails at identity
        if now > token.expires_at:
            return False, "Token expired"

        if token.issued_at > token.expires_at:
            return False, "Token timestamps invalid"

        expected_signature = self._sign_fields(
            agent_id=token.agent_id,
            issued_at=token.issued_at,
            expires_at=token.expires_at,
            allowed_contract_version=token.allowed_contract_version,
            payload_hash=token.payload_hash,
        )

        if not hmac.compare_digest(token.signature_hex, expected_signature):
            return False, "Invalid token signature"

        return True, "OK"

    def _sign_fields(
        self,
        agent_id: str,
        issued_at: float,
        expires_at: float,
        allowed_contract_version: str,
        payload_hash: str,
    ) -> str:
        raw = (
            f"{agent_id}|{issued_at:.6f}|{expires_at:.6f}|"
            f"{allowed_contract_version}|{payload_hash}"
        ).encode("utf-8")
        return hmac.new(self._secret, raw, hashlib.sha256).hexdigest()
