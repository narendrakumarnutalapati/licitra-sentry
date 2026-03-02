"""
LICITRA-SENTRY Identity Layer - CovenantNotary.

Ed25519-based identity attestation and short-lived session tokens
for agentic AI systems. Every agent must register and receive a
signed token before participating in inter-agent communication.

OWASP Agentic Coverage:
    ASI03 - Agent Impersonation: Ed25519 signed tokens prevent forgery.
    ASI10 - Uncontrolled Agent Proliferation: Registry controls which
            agents are recognized; unknown agents receive no token.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AgentRegistration:
    """An agent registered with the Notary."""
    agent_id: str
    public_key_pem: str
    allowed_contract_version: str


@dataclass(frozen=True)
class SignedToken:
    """Short-lived session token issued by the CovenantNotary."""
    agent_id: str
    issued_at: float
    expires_at: float
    allowed_contract_version: str
    signature_hex: str
    payload_hash: str


# ---------------------------------------------------------------------------
# CovenantNotary
# ---------------------------------------------------------------------------

class CovenantNotary:
    """
    Identity attestation service for LICITRA-SENTRY.

    Responsibilities:
        1. Generate and hold the Notary's Ed25519 signing key.
        2. Maintain an in-memory agent registry.
        3. Issue short-lived signed session tokens.
        4. Verify tokens presented by agents.

    OWASP: ASI03 (Agent Impersonation), ASI10 (Uncontrolled Proliferation)
    """

    DEFAULT_TTL_SECONDS: int = 60

    def __init__(self, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> None:
        self._private_key: Ed25519PrivateKey = Ed25519PrivateKey.generate()
        self._public_key: Ed25519PublicKey = self._private_key.public_key()
        self._registry: dict[str, AgentRegistration] = {}
        self._ttl: int = ttl_seconds

    # -- Registry management ------------------------------------------------

    def register_agent(
        self,
        agent_id: str,
        allowed_contract_version: str = "v1",
    ) -> AgentRegistration:
        """
        Register a new agent with the Notary.

        Returns an AgentRegistration containing the agent's generated
        Ed25519 public key (PEM). The private key is only used internally
        for issuing tokens - in production, agents would hold their own
        key pairs and present CSRs.
        """
        agent_key = Ed25519PrivateKey.generate()
        public_pem = agent_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

        registration = AgentRegistration(
            agent_id=agent_id,
            public_key_pem=public_pem,
            allowed_contract_version=allowed_contract_version,
        )
        self._registry[agent_id] = registration
        return registration

    def is_registered(self, agent_id: str) -> bool:
        """Check whether an agent is in the registry."""
        return agent_id in self._registry

    def get_registration(self, agent_id: str) -> Optional[AgentRegistration]:
        """Retrieve an agent's registration record, or None."""
        return self._registry.get(agent_id)

    # -- Token issuance -----------------------------------------------------

    def issue_token(self, agent_id: str) -> SignedToken:
        """
        Issue a short-lived Ed25519-signed session token for a registered
        agent. Raises ValueError if the agent is not registered.

        Token payload (canonical JSON, sorted keys, no whitespace):
            {agent_id, allowed_contract_version, expires_at, issued_at}

        The Notary signs SHA-256(payload) with its private key.
        """
        reg = self._registry.get(agent_id)
        if reg is None:
            raise ValueError(f"Agent '{agent_id}' is not registered")

        now = time.time()
        payload = {
            "agent_id": agent_id,
            "allowed_contract_version": reg.allowed_contract_version,
            "expires_at": now + self._ttl,
            "issued_at": now,
        }

        payload_bytes = json.dumps(
            payload, sort_keys=True, separators=(",", ":")
        ).encode()
        payload_hash = hashlib.sha256(payload_bytes).hexdigest()

        signature = self._private_key.sign(payload_bytes)
        signature_hex = signature.hex()

        return SignedToken(
            agent_id=payload["agent_id"],
            issued_at=payload["issued_at"],
            expires_at=payload["expires_at"],
            allowed_contract_version=payload["allowed_contract_version"],
            signature_hex=signature_hex,
            payload_hash=payload_hash,
        )

    # -- Token verification -------------------------------------------------

    def validate_token(self, token: SignedToken) -> tuple[bool, str]:
        """
        Verify a token's cryptographic signature and expiry.

        Returns:
            (True, "valid") on success.
            (False, <reason>) on failure.
        """
        # 1. Check agent is still registered
        if not self.is_registered(token.agent_id):
            return False, f"Agent '{token.agent_id}' is not registered"

        # 2. Check expiry
        if time.time() > token.expires_at:
            return False, "Token has expired"

        # 3. Reconstruct payload and verify signature
        payload = {
            "agent_id": token.agent_id,
            "allowed_contract_version": token.allowed_contract_version,
            "expires_at": token.expires_at,
            "issued_at": token.issued_at,
        }
        payload_bytes = json.dumps(
            payload, sort_keys=True, separators=(",", ":")
        ).encode()

        try:
            self._public_key.verify(
                bytes.fromhex(token.signature_hex),
                payload_bytes,
            )
        except InvalidSignature:
            return False, "Invalid signature"

        return True, "valid"

    # -- Convenience --------------------------------------------------------

    def notary_public_key_pem(self) -> str:
        """Return the Notary's public key in PEM form."""
        return self._public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
