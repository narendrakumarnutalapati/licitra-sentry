"""
LICITRA-SENTRY v0.2 — Tool Proxy Gateway

The proxy sits between agents and tools, enforcing mandatory mediation.
No tool execution occurs without a valid, unexpired, non-replayed ticket.

Architecture:
    Agent → SENTRY (authorize) → Ticket issued → Tool Proxy (verify) → Tool

The proxy verifies:
  1. Ticket signature (Ed25519)
  2. Ticket expiration
  3. Audience match (correct tool)
  4. Request hash match (payload integrity)
  5. Replay protection (jti uniqueness via SQLite)

On success: execute tool, commit execution event to audit.
On failure: reject with structured error, commit rejection event to audit.

Author: Narendra Kumar Nutalapati
License: MIT
"""

import json
import time
import sqlite3
import hashlib
import logging
import threading
from dataclasses import dataclass, asdict, field
from typing import Callable, Optional, Any
from pathlib import Path

from app.ticket import (
    ExecutionTicket,
    verify_ticket,
    VerificationResult,
    hash_request,
)
from app.key_manager import KeyProvider


logger = logging.getLogger("licitra.proxy")


# --------------------------------------------------------------------------- #
#  Replay store
# --------------------------------------------------------------------------- #

class ReplayStore:
    """
    SQLite-based replay protection.

    Stores ticket JTIs with expiration timestamps.
    Rejects any ticket whose JTI has been seen before.
    Periodically purges expired entries.
    """

    def __init__(self, db_path: str = "data/replay.db"):
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.conn = sqlite3.connect(db_path, check_same_thread=False, timeout=30.0)
        with self._lock:
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS used_tickets (
                    jti TEXT PRIMARY KEY,
                    exp REAL NOT NULL,
                    used_at REAL NOT NULL
                )
            """)
            self.conn.commit()

    def check_and_mark(self, jti: str, exp: float) -> bool:
        """
        Check if JTI has been used. If not, mark it as used.

        Returns:
            True if the ticket is fresh (not replayed).
            False if the JTI was already used (replay detected).
        """
        with self._lock:
            try:
                self.conn.execute(
                    "INSERT INTO used_tickets (jti, exp, used_at) VALUES (?, ?, ?)",
                    (jti, exp, time.time()),
                )
                self.conn.commit()
                return True
            except sqlite3.IntegrityError:
                return False

    def purge_expired(self):
        """Remove entries for tickets that have expired (housekeeping)."""
        with self._lock:
            self.conn.execute(
                "DELETE FROM used_tickets WHERE exp < ?", (time.time(),)
            )
            self.conn.commit()

    def close(self):
        with self._lock:
            self.conn.close()


# --------------------------------------------------------------------------- #
#  Execution result
# --------------------------------------------------------------------------- #

@dataclass
class ProxyResult:
    allowed: bool
    tool_id: str
    agent_id: str = ""
    ticket_jti: str = ""
    error: Optional[str] = None
    tool_output: Any = None
    execution_time_ms: float = 0.0
    audit_event: Optional[dict] = None


# --------------------------------------------------------------------------- #
#  Rate limiter
# --------------------------------------------------------------------------- #

class RateLimiter:
    """Simple in-memory sliding window rate limiter per agent."""

    def __init__(self, max_requests: int = 100, window_seconds: float = 60.0):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._windows: dict[str, list[float]] = {}

    def check(self, agent_id: str) -> bool:
        now = time.time()
        cutoff = now - self.window_seconds
        if agent_id not in self._windows:
            self._windows[agent_id] = []

        # Prune old entries
        self._windows[agent_id] = [
            t for t in self._windows[agent_id] if t > cutoff
        ]

        if len(self._windows[agent_id]) >= self.max_requests:
            return False

        self._windows[agent_id].append(now)
        return True


# --------------------------------------------------------------------------- #
#  Tool Proxy
# --------------------------------------------------------------------------- #

# Maximum payload size: 1 MB
MAX_PAYLOAD_BYTES = 1_048_576


class ToolProxy:
    """
    Mandatory mediation gateway between agents and tools.

    Every tool invocation must pass through the proxy with a valid
    execution ticket issued by SENTRY.
    """

    def __init__(
        self,
        key_provider: KeyProvider,
        replay_store: Optional[ReplayStore] = None,
        rate_limiter: Optional[RateLimiter] = None,
        audit_callback: Optional[Callable[[dict], None]] = None,
    ):
        self.key_provider = key_provider
        self.replay_store = replay_store or ReplayStore()
        self.rate_limiter = rate_limiter or RateLimiter()
        self.audit_callback = audit_callback
        self._tools: dict[str, Callable] = {}

    def register_tool(self, tool_id: str, handler: Callable):
        """Register a tool handler that the proxy can invoke."""
        self._tools[tool_id] = handler
        logger.info(f"Registered tool: {tool_id}")

    def execute(
        self,
        ticket: ExecutionTicket,
        tool_id: str,
        request: dict,
    ) -> ProxyResult:
        """
        Execute a tool request with full ticket verification.

        Steps:
          1. Payload size check
          2. Rate limit check
          3. Ticket cryptographic verification
          4. Replay protection
          5. Tool existence check
          6. Tool execution
          7. Audit event emission

        Args:
            ticket: Signed execution ticket from SENTRY.
            tool_id: Target tool identifier.
            request: The exact request payload (must match ticket hash).

        Returns:
            ProxyResult with execution outcome.
        """
        agent_id = ticket.claims.sub
        jti = ticket.claims.jti

        # --- Step 1: Payload size ---
        request_bytes = json.dumps(request).encode("utf-8")
        if len(request_bytes) > MAX_PAYLOAD_BYTES:
            return self._reject(
                tool_id, agent_id, jti,
                "PAYLOAD_TOO_LARGE",
                f"Request payload exceeds {MAX_PAYLOAD_BYTES} bytes",
            )

        # --- Step 2: Rate limiting ---
        if not self.rate_limiter.check(agent_id):
            return self._reject(
                tool_id, agent_id, jti,
                "RATE_LIMITED",
                f"Agent {agent_id} exceeded rate limit",
            )

        # --- Step 3: Ticket verification ---
        result = verify_ticket(
            key_provider=self.key_provider,
            ticket=ticket,
            expected_tool_id=tool_id,
            presented_request=request,
        )

        if not result.valid:
            return self._reject(
                tool_id, agent_id, jti,
                "TICKET_INVALID",
                result.error,
            )

        # --- Step 4: Replay protection ---
        if not self.replay_store.check_and_mark(jti, ticket.claims.exp):
            return self._reject(
                tool_id, agent_id, jti,
                "REPLAY_DETECTED",
                f"Ticket {jti} has already been used",
            )

        # --- Step 5: Tool existence ---
        if tool_id not in self._tools:
            return self._reject(
                tool_id, agent_id, jti,
                "TOOL_NOT_FOUND",
                f"Tool {tool_id} is not registered",
            )

        # --- Step 6: Execute tool ---
        start = time.time()
        try:
            tool_output = self._tools[tool_id](request)
            exec_ms = (time.time() - start) * 1000
        except Exception as e:
            exec_ms = (time.time() - start) * 1000
            return self._reject(
                tool_id, agent_id, jti,
                "TOOL_EXECUTION_ERROR",
                f"Tool raised exception: {type(e).__name__}: {e}",
                exec_ms=exec_ms,
            )

        # --- Step 7: Audit ---
        audit_event = {
            "event_type": "tool_execution",
            "timestamp": time.time(),
            "agent_id": agent_id,
            "tool_id": tool_id,
            "ticket_jti": jti,
            "request_hash": ticket.claims.request_hash,
            "contract_id": ticket.claims.contract_id,
            "policy_version": ticket.claims.policy_version,
            "mmr_commit_id": ticket.claims.mmr_commit_id,
            "result": "success",
            "execution_time_ms": exec_ms,
            "output_hash": hashlib.sha256(
                json.dumps(tool_output, sort_keys=True, default=str).encode()
            ).hexdigest(),
        }

        if self.audit_callback:
            self.audit_callback(audit_event)

        logger.info(
            f"EXECUTED tool={tool_id} agent={agent_id} jti={jti} "
            f"time={exec_ms:.1f}ms"
        )

        return ProxyResult(
            allowed=True,
            tool_id=tool_id,
            agent_id=agent_id,
            ticket_jti=jti,
            tool_output=tool_output,
            execution_time_ms=exec_ms,
            audit_event=audit_event,
        )

    def _reject(
        self,
        tool_id: str,
        agent_id: str,
        jti: str,
        error_code: str,
        error_detail: str,
        exec_ms: float = 0.0,
    ) -> ProxyResult:
        """Reject a request and emit rejection audit event."""
        audit_event = {
            "event_type": "tool_execution_rejected",
            "timestamp": time.time(),
            "agent_id": agent_id,
            "tool_id": tool_id,
            "ticket_jti": jti,
            "error_code": error_code,
            "error_detail": error_detail,
            "result": "rejected",
        }

        if self.audit_callback:
            self.audit_callback(audit_event)

        logger.warning(
            f"REJECTED tool={tool_id} agent={agent_id} "
            f"error={error_code}: {error_detail}"
        )

        return ProxyResult(
            allowed=False,
            tool_id=tool_id,
            agent_id=agent_id,
            ticket_jti=jti,
            error=f"{error_code}: {error_detail}",
            execution_time_ms=exec_ms,
            audit_event=audit_event,
        )


