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

# Optional witness import — gracefully degrade if not configured
try:
    from app.witness import WitnessClient, SignedInclusionReceipt
except ImportError:
    WitnessClient = None
    SignedInclusionReceipt = None


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
        witness_client: Optional["WitnessClient"] = None,
        epoch_size: int = 10,
        mmr_base_url: Optional[str] = None,
        org_id: Optional[str] = None,
    ):
        """
        Supports both:
          v0.2 core API
          v0.1-compat experiment API
        """

        # Legacy experiment parameters are accepted but ignored
        self.mmr_base_url = mmr_base_url
        self.org_id = org_id

        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.anchor_manager = anchor_manager
        self.witness_client = witness_client
        self.epoch_size = epoch_size
        self._previous_hash = "0" * 64  # genesis hash
        self._event_count = 0
        self._epoch_event_count = 0
        self._current_epoch = 0
        self._prev_epoch_root = "0" * 64
        self._events: list[AuditEvent] = []
        self._receipts: list = []

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
        self._epoch_event_count += 1
        self._events.append(event)

        # Check if anchoring should trigger
        if self.anchor_manager:
            anchor = self.anchor_manager.on_commit(event.event_hash)
            if anchor:
                self._commit_anchor_event(anchor)

        # Check if epoch should finalize and be witnessed
        if self.witness_client and self._epoch_event_count >= self.epoch_size:
            self._finalize_and_witness_epoch()

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

    def _finalize_and_witness_epoch(self):
        """Finalize the current epoch and submit to transparency log."""
        self._current_epoch += 1
        epoch_root = self._previous_hash  # current chain head

        receipt = self.witness_client.witness_epoch(
            epoch_id=self._current_epoch,
            epoch_root=epoch_root,
            prev_epoch_root=self._prev_epoch_root,
            event_count=self._epoch_event_count,
        )

        self._receipts.append(receipt)
        self._prev_epoch_root = epoch_root
        self._epoch_event_count = 0

        # Log the witness event itself
        witness_event = AuditEvent(
            event_id=f"witness-epoch-{self._current_epoch}",
            event_type="epoch_witnessed",
            timestamp=time.time(),
            agent_id="system",
            details={
                "epoch_id": self._current_epoch,
                "epoch_root": epoch_root,
                "receipt_id": receipt.receipt_id,
                "log_id": receipt.log_id,
                "log_sequence": receipt.log_sequence,
            },
        )
        self.commit(witness_event)

    def get_receipts(self) -> list:
        """Return all witness receipts collected so far."""
        return list(self._receipts)

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


# ---------------------------------------------------------------------------
# Legacy compatibility API (v0.1-compat)
# ---------------------------------------------------------------------------

@dataclass
class AuditResult:
    staged_id: int
    event_id: str
    leaf_hash: str


def emit(self, event: dict) -> AuditResult:
    """
    Legacy middleware-compatible audit emitter.

    Converts a dict event into an AuditEvent and commits it to the
    append-only audit chain. Returns a structure compatible with
    the older experiment suite.
    """
    audit_event = AuditEvent(
        event_id=f"legacy-{int(time.time() * 1000)}",
        event_type="middleware_event",
        timestamp=time.time(),
        agent_id=event.get("agent_id", "unknown"),
        tool_id=event.get("tool", ""),
        gate=event.get("gate_fired", ""),
        decision=event.get("decision", "").lower(),
        details=event,
    )

    leaf_hash = self.commit(audit_event)

    return AuditResult(
        staged_id=self._event_count,
        event_id=audit_event.event_id,
        leaf_hash=leaf_hash,
    )


AuditBridge.emit = emit
