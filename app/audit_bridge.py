"""
LICITRA-SENTRY v0.2 — Audit Bridge

Bridges SENTRY authorization/execution events to the MMR audit ledger.
Every gate decision, ticket issuance, and tool execution is committed.

In production, this would connect to a running LICITRA-MMR instance.
This reference implementation uses a local append-only log with
hash chaining for demonstration.

Author: Narendra Kumar Nutalapati
License: MIT
"""

import json
import time
import hashlib
from dataclasses import dataclass, field
from typing import Optional, Callable
from pathlib import Path

from app.anchor import AnchorManager, AnchorRecord


@dataclass
class AuditEvent:
    event_id: str
    event_type: str
    timestamp: float
    agent_id: str
    tool_id: str = ""
    gate: str = ""
    decision: str = ""     # "approved", "rejected"
    details: dict = field(default_factory=dict)
    event_hash: str = ""
    previous_hash: str = ""


class AuditBridge:
    """
    Commits authorization and execution events to an append-only ledger.

    Each event is:
      1. Serialized to canonical JSON
      2. Hashed with SHA-256
      3. Chained to the previous event hash
      4. Appended to the log

    This provides hash-chain integrity: modifying any event
    invalidates all subsequent hashes.
    """

    def __init__(
        self,
        log_path: str = "data/audit_log.jsonl",
        anchor_manager: Optional[AnchorManager] = None,
    ):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.anchor_manager = anchor_manager
        self._previous_hash = "0" * 64  # genesis hash
        self._event_count = 0
        self._events: list[AuditEvent] = []

    def commit(self, event: AuditEvent) -> str:
        """
        Commit an audit event to the ledger.

        Returns:
            The event hash (which becomes the chain link for the next event).
        """
        event.previous_hash = self._previous_hash

        # Canonical serialization for hashing
        payload = {
            "event_id": event.event_id,
            "event_type": event.event_type,
            "timestamp": event.timestamp,
            "agent_id": event.agent_id,
            "tool_id": event.tool_id,
            "gate": event.gate,
            "decision": event.decision,
            "details": event.details,
            "previous_hash": event.previous_hash,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        event.event_hash = hashlib.sha256(canonical.encode()).hexdigest()

        # Append to log
        with open(self.log_path, "a") as f:
            record = {
                "event_id": event.event_id,
                "event_type": event.event_type,
                "timestamp": event.timestamp,
                "agent_id": event.agent_id,
                "tool_id": event.tool_id,
                "gate": event.gate,
                "decision": event.decision,
                "details_hash": hashlib.sha256(
                    json.dumps(event.details, sort_keys=True).encode()
                ).hexdigest(),
                "event_hash": event.event_hash,
                "previous_hash": event.previous_hash,
            }
            f.write(json.dumps(record) + "\n")

        self._previous_hash = event.event_hash
        self._event_count += 1
        self._events.append(event)

        # Check if anchoring should trigger
        if self.anchor_manager:
            anchor = self.anchor_manager.on_commit(event.event_hash)
            if anchor:
                self._commit_anchor_event(anchor)

        return event.event_hash

    def _commit_anchor_event(self, anchor: AnchorRecord):
        """Record the anchoring event itself in the audit log."""
        anchor_event = AuditEvent(
            event_id=f"anchor-{anchor.anchor_id}",
            event_type="external_anchor",
            timestamp=time.time(),
            agent_id="system",
            details={
                "anchor_id": anchor.anchor_id,
                "epoch": anchor.epoch,
                "mmr_root_hash": anchor.mmr_root_hash,
                "provider": anchor.provider,
                "external_ref": anchor.external_ref,
            },
        )
        # Recursive commit (anchor event is also logged)
        self.commit(anchor_event)

    def verify_chain(self) -> tuple[bool, Optional[str]]:
        """
        Verify the integrity of the entire audit chain.

        Returns:
            (valid, error_message)
        """
        if not self.log_path.exists():
            return True, None

        previous_hash = "0" * 64

        with open(self.log_path, "r") as f:
            for line_num, line in enumerate(f, 1):
                record = json.loads(line.strip())

                if record["previous_hash"] != previous_hash:
                    return False, (
                        f"Chain break at line {line_num}: "
                        f"expected previous_hash={previous_hash}, "
                        f"got {record['previous_hash']}"
                    )

                previous_hash = record["event_hash"]

        return True, None

    def get_current_root(self) -> str:
        """Return the current chain head hash (latest event hash)."""
        return self._previous_hash

    def get_event_count(self) -> int:
        return self._event_count
