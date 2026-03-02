"""
LICITRA-SENTRY Audit Bridge - LICITRA-MMR Integration.

Bridges every SENTRY decision (approved AND rejected) into LICITRA-MMR
via its 2-phase commit API. LICITRA-SENTRY never stores its own ledger;
all integrity flows through LICITRA-MMR.

API contract:
    POST /agent/propose         -> {staged_id, status, ...}
    POST /agent/commit/{id}     -> {event_id, leaf_hash, ...}

OWASP Agentic Coverage:
    ASI04 - Insecure Output Handling: All outputs committed to MMR
            for tamper-evident record of every decision.
    ASI08 - Audit and Logging Failures: MMR-backed tamper-evident
            audit with epoch anchoring proves ledger state at any
            point in time.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any, Optional

import requests


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AuditResult:
    """Outcome of emitting an audit event to LICITRA-MMR."""
    success: bool
    staged_id: Optional[int]
    event_id: Optional[str]
    leaf_hash: Optional[str]
    error: Optional[str]


# ---------------------------------------------------------------------------
# AuditBridge
# ---------------------------------------------------------------------------

class AuditBridge:
    """
    2-phase commit bridge to LICITRA-MMR.

    propose() -> POST /agent/propose
    commit()  -> POST /agent/commit/{staged_id}
    emit()    -> propose + commit in sequence

    OWASP: ASI04 (Insecure Output Handling), ASI08 (Audit/Logging Failures)
    """

    def __init__(
        self,
        mmr_base_url: str = "http://localhost:8000",
        org_id: str = "sentry-org",
    ) -> None:
        self._base_url = mmr_base_url.rstrip("/")
        self._org_id = org_id

    def _build_proposed_json(self, event: dict[str, Any]) -> str:
        """
        Build a valid proposed_json string for LICITRA-MMR.

        MMR requires: action_type, agent_id, timestamp.
        We inject these if not already present, then serialize to
        canonical JSON string.
        """
        enriched = dict(event)
        if "action_type" not in enriched:
            enriched["action_type"] = "AUDIT"
        if "agent_id" not in enriched:
            enriched["agent_id"] = "sentry"
        if "timestamp" not in enriched:
            enriched["timestamp"] = time.time()
        return json.dumps(enriched, sort_keys=True, separators=(",", ":"))

    def propose(self, event: dict[str, Any]) -> dict[str, Any]:
        """
        Phase 1: Propose an audit event to LICITRA-MMR.

        POST /agent/propose
        Body: {org_id, agent_id, proposed_json (string)}

        Returns the raw JSON response from MMR.
        Raises RuntimeError on HTTP failure.
        """
        proposed_json_str = self._build_proposed_json(event)
        payload = {
            "org_id": self._org_id,
            "agent_id": event.get("agent_id", "sentry"),
            "proposed_json": proposed_json_str,
        }
        resp = requests.post(
            f"{self._base_url}/agent/propose",
            json=payload,
            timeout=10,
        )
        if resp.status_code != 200:
            raise RuntimeError(
                f"MMR propose failed (HTTP {resp.status_code}): {resp.text}"
            )
        return resp.json()

    def commit(self, staged_id: int) -> dict[str, Any]:
        """
        Phase 2: Commit a staged event in LICITRA-MMR.

        POST /agent/commit/{staged_id}

        Returns the raw JSON response from MMR.
        Raises RuntimeError on HTTP failure.
        """
        resp = requests.post(
            f"{self._base_url}/agent/commit/{staged_id}",
            timeout=10,
        )
        if resp.status_code != 200:
            raise RuntimeError(
                f"MMR commit failed (HTTP {resp.status_code}): {resp.text}"
            )
        return resp.json()

    def emit(self, event: dict[str, Any]) -> AuditResult:
        """
        Full 2-phase commit: propose then commit.

        Returns AuditResult with staged_id, event_id, and leaf_hash
        on success, or error details on failure.
        """
        try:
            propose_resp = self.propose(event)
            staged_id = propose_resp.get("staged_id")
            if staged_id is None:
                return AuditResult(
                    success=False,
                    staged_id=None,
                    event_id=None,
                    leaf_hash=None,
                    error="MMR propose response missing staged_id",
                )

            # MMR may reject at propose stage
            if propose_resp.get("status") != "APPROVED":
                return AuditResult(
                    success=False,
                    staged_id=staged_id,
                    event_id=None,
                    leaf_hash=None,
                    error=f"MMR rejected proposal: {propose_resp.get('decision_reason')}",
                )

            commit_resp = self.commit(staged_id)
            return AuditResult(
                success=True,
                staged_id=staged_id,
                event_id=commit_resp.get("event_id"),
                leaf_hash=commit_resp.get("leaf_hash"),
                error=None,
            )
        except Exception as exc:
            return AuditResult(
                success=False,
                staged_id=None,
                event_id=None,
                leaf_hash=None,
                error=str(exc),
            )
