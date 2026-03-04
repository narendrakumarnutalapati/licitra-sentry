"""
LICITRA-SENTRY v0.2 — Execution Ticket System

Issues and verifies signed execution tickets that cryptographically bind
authorization decisions to specific tool requests.

A ticket proves:
  1. SENTRY authorized the exact request (request_hash)
  2. Authorization occurred at a specific time (iat)
  3. Authorization is bound to a specific agent and tool (sub, aud)
  4. The policy state at authorization time is recorded (policy_version, contract_id)
  5. The audit commitment exists (mmr_commit_id)

Ticket format follows a compact JSON structure signed with Ed25519.

Author: Narendra Kumar Nutalapati
License: MIT
"""

import json
import uuid
import time
import hashlib
import base64
from dataclasses import dataclass, asdict
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

from app.key_manager import KeyProvider


# --------------------------------------------------------------------------- #
#  Canonical serialization
# --------------------------------------------------------------------------- #

def canonicalize_request(request: dict) -> str:
    """
    Produce a deterministic canonical JSON string from a tool request.

    Rules:
      - Keys sorted recursively
      - No whitespace
      - Unicode escapes normalized
      - Deterministic float representation

    This ensures the same logical request always produces the same hash,
    regardless of key ordering or formatting in the original payload.
    """
    return json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def hash_request(request: dict) -> str:
    """SHA-256 hash of the canonicalized request."""
    canonical = canonicalize_request(request)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
#  Ticket data structures
# --------------------------------------------------------------------------- #

@dataclass
class TicketHeader:
    alg: str = "Ed25519"
    typ: str = "licitra-ticket"
    kid: str = ""


@dataclass
class TicketClaims:
    iss: str = "licitra-sentry"
    sub: str = ""          # agent_id
    aud: str = ""          # tool_id
    jti: str = ""          # unique ticket ID
    iat: float = 0.0       # issued at (unix timestamp)
    exp: float = 0.0       # expiration (unix timestamp)
    request_hash: str = "" # SHA-256 of canonicalized request
    policy_version: str = ""
    contract_id: str = ""
    contract_version: str = ""
    mmr_commit_id: str = ""


@dataclass
class ExecutionTicket:
    header: TicketHeader
    claims: TicketClaims
    signature: str = ""    # base64url-encoded Ed25519 signature

    def to_dict(self) -> dict:
        return {
            "header": asdict(self.header),
            "claims": asdict(self.claims),
            "signature": self.signature,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_dict(cls, data: dict) -> "ExecutionTicket":
        return cls(
            header=TicketHeader(**data["header"]),
            claims=TicketClaims(**data["claims"]),
            signature=data.get("signature", ""),
        )

    @classmethod
    def from_json(cls, raw: str) -> "ExecutionTicket":
        return cls.from_dict(json.loads(raw))


# --------------------------------------------------------------------------- #
#  Signing payload construction
# --------------------------------------------------------------------------- #

def _build_signing_input(header: TicketHeader, claims: TicketClaims) -> bytes:
    """
    Construct the exact bytes that are signed / verified.

    Format: canonical(header) + "." + canonical(claims)
    This mirrors JWT-style signing but with deterministic JSON.
    """
    h = json.dumps(asdict(header), sort_keys=True, separators=(",", ":"))
    c = json.dumps(asdict(claims), sort_keys=True, separators=(",", ":"))
    return f"{h}.{c}".encode("utf-8")


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


# --------------------------------------------------------------------------- #
#  Issue ticket
# --------------------------------------------------------------------------- #

def issue_ticket(
    key_provider: KeyProvider,
    agent_id: str,
    tool_id: str,
    request: dict,
    policy_version: str,
    contract_id: str,
    contract_version: str,
    mmr_commit_id: str,
    ttl_seconds: int = 60,
) -> ExecutionTicket:
    """
    Issue a signed execution ticket after SENTRY authorization.

    Args:
        key_provider: Provider for signing keys.
        agent_id: Authenticated agent identity.
        tool_id: Target tool identifier.
        request: The exact tool request payload to be authorized.
        policy_version: Version of the policy evaluated.
        contract_id: Semantic contract identifier.
        contract_version: Semantic contract version.
        mmr_commit_id: MMR commit ID for the authorization event.
        ttl_seconds: Ticket lifetime in seconds (default 60, max 60).

    Returns:
        Signed ExecutionTicket.
    """
    if ttl_seconds > 60:
        raise ValueError("Ticket TTL cannot exceed 60 seconds")

    now = time.time()
    kid = key_provider.get_active_kid()

    header = TicketHeader(kid=kid)

    claims = TicketClaims(
        sub=agent_id,
        aud=tool_id,
        jti=str(uuid.uuid4()),
        iat=now,
        exp=now + ttl_seconds,
        request_hash=hash_request(request),
        policy_version=policy_version,
        contract_id=contract_id,
        contract_version=contract_version,
        mmr_commit_id=mmr_commit_id,
    )

    # Sign
    signing_input = _build_signing_input(header, claims)
    private_key = key_provider.get_private_key(kid)
    sig_bytes = private_key.sign(signing_input)
    signature = _b64url_encode(sig_bytes)

    return ExecutionTicket(header=header, claims=claims, signature=signature)


# --------------------------------------------------------------------------- #
#  Verify ticket
# --------------------------------------------------------------------------- #

@dataclass
class VerificationResult:
    valid: bool
    error: Optional[str] = None
    claims: Optional[TicketClaims] = None


def verify_ticket(
    key_provider: KeyProvider,
    ticket: ExecutionTicket,
    expected_tool_id: str,
    presented_request: dict,
) -> VerificationResult:
    """
    Verify an execution ticket at the Tool Proxy.

    Checks:
      1. Signature validity (Ed25519)
      2. Expiration (ticket not expired)
      3. Audience match (ticket.aud == expected tool)
      4. Request hash match (payload hasn't been modified)

    Note: Replay protection (jti check) is handled by the ToolProxy,
    not in this function, because it requires stateful storage.

    Args:
        key_provider: Provider for verification keys.
        ticket: The ticket to verify.
        expected_tool_id: The tool ID the proxy is guarding.
        presented_request: The request payload presented alongside the ticket.

    Returns:
        VerificationResult with validity status and any error.
    """
    # 1. Signature verification
    try:
        kid = ticket.header.kid
        public_key = key_provider.get_public_key(kid)
        signing_input = _build_signing_input(ticket.header, ticket.claims)
        sig_bytes = _b64url_decode(ticket.signature)
        public_key.verify(sig_bytes, signing_input)
    except (KeyError, InvalidSignature, Exception) as e:
        return VerificationResult(valid=False, error=f"Signature verification failed: {e}")

    # 2. Expiration check
    now = time.time()
    if now > ticket.claims.exp:
        return VerificationResult(
            valid=False,
            error=f"Ticket expired: exp={ticket.claims.exp}, now={now}",
        )

    # 3. Audience match
    if ticket.claims.aud != expected_tool_id:
        return VerificationResult(
            valid=False,
            error=f"Audience mismatch: ticket.aud={ticket.claims.aud}, expected={expected_tool_id}",
        )

    # 4. Request hash match
    presented_hash = hash_request(presented_request)
    if presented_hash != ticket.claims.request_hash:
        return VerificationResult(
            valid=False,
            error="Request hash mismatch: payload modified after authorization",
        )

    return VerificationResult(valid=True, claims=ticket.claims)
