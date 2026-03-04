"""
LICITRA-SENTRY v0.2 — External Anchor Module

Pluggable anchoring system for MMR root hashes.

Every N commits (configurable, default 100), the MMR root hash is
anchored externally, creating an independent witness that the audit
state existed at a specific point in time.

This module provides:
  - Abstract AnchorProvider interface
  - FileAnchorProvider (reference implementation)
  - AnchorManager (orchestrates periodic anchoring)

Future providers: Bitcoin OP_RETURN, Ethereum calldata, RFC 3161
timestamp authority, Certificate Transparency log.

Author: Narendra Kumar Nutalapati
License: MIT
"""

import json
import time
import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional


@dataclass
class AnchorRecord:
    """Represents an external anchor commitment."""
    anchor_id: str
    mmr_root_hash: str
    epoch: int
    event_count: int
    timestamp: float
    provider: str
    external_ref: str    # provider-specific reference (tx hash, filename, etc.)
    anchor_hash: str     # SHA-256 of the anchor payload itself


@dataclass
class AnchorVerification:
    """Result of anchor verification."""
    valid: bool
    anchor_id: str
    error: Optional[str] = None


class AnchorProvider(ABC):
    """Abstract interface for external anchoring backends."""

    @abstractmethod
    def anchor(self, mmr_root_hash: str, epoch: int, event_count: int) -> AnchorRecord:
        """Anchor an MMR root hash externally."""
        ...

    @abstractmethod
    def verify(self, record: AnchorRecord) -> AnchorVerification:
        """Verify an anchor record against the external store."""
        ...

    @abstractmethod
    def provider_name(self) -> str:
        ...


class FileAnchorProvider(AnchorProvider):
    """
    File-based anchor provider for development and testing.

    Writes signed anchor records to a local directory.
    Each anchor is a JSON file containing the root hash and metadata.

    In production, this would be replaced by a blockchain or
    timestamp authority provider.
    """

    def __init__(self, anchor_dir: str = "data/anchors"):
        self.anchor_dir = Path(anchor_dir)
        self.anchor_dir.mkdir(parents=True, exist_ok=True)

    def provider_name(self) -> str:
        return "file"

    def anchor(self, mmr_root_hash: str, epoch: int, event_count: int) -> AnchorRecord:
        timestamp = time.time()
        anchor_id = f"anchor-{epoch}-{int(timestamp)}"

        # Build the anchor payload
        payload = {
            "mmr_root_hash": mmr_root_hash,
            "epoch": epoch,
            "event_count": event_count,
            "timestamp": timestamp,
            "provider": self.provider_name(),
        }
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        anchor_hash = hashlib.sha256(payload_json.encode()).hexdigest()

        # Write anchor file
        anchor_path = self.anchor_dir / f"{anchor_id}.json"
        record = AnchorRecord(
            anchor_id=anchor_id,
            mmr_root_hash=mmr_root_hash,
            epoch=epoch,
            event_count=event_count,
            timestamp=timestamp,
            provider=self.provider_name(),
            external_ref=str(anchor_path),
            anchor_hash=anchor_hash,
        )
        with open(anchor_path, "w") as f:
            json.dump(asdict(record), f, indent=2)

        return record

    def verify(self, record: AnchorRecord) -> AnchorVerification:
        anchor_path = Path(record.external_ref)
        if not anchor_path.exists():
            return AnchorVerification(
                valid=False,
                anchor_id=record.anchor_id,
                error=f"Anchor file not found: {anchor_path}",
            )

        with open(anchor_path, "r") as f:
            stored = json.load(f)

        # Recompute anchor hash
        payload = {
            "mmr_root_hash": stored["mmr_root_hash"],
            "epoch": stored["epoch"],
            "event_count": stored["event_count"],
            "timestamp": stored["timestamp"],
            "provider": stored["provider"],
        }
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        computed_hash = hashlib.sha256(payload_json.encode()).hexdigest()

        if computed_hash != stored["anchor_hash"]:
            return AnchorVerification(
                valid=False,
                anchor_id=record.anchor_id,
                error="Anchor hash mismatch: file may have been tampered with",
            )

        if stored["mmr_root_hash"] != record.mmr_root_hash:
            return AnchorVerification(
                valid=False,
                anchor_id=record.anchor_id,
                error="MMR root hash does not match stored anchor",
            )

        return AnchorVerification(valid=True, anchor_id=record.anchor_id)


class AnchorManager:
    """
    Orchestrates periodic anchoring of MMR root hashes.

    Tracks commit count and triggers anchoring every N commits.
    """

    def __init__(
        self,
        provider: AnchorProvider,
        anchor_interval: int = 100,
    ):
        self.provider = provider
        self.anchor_interval = anchor_interval
        self._commit_count = 0
        self._current_epoch = 0
        self._anchors: list[AnchorRecord] = []

    def on_commit(self, mmr_root_hash: str) -> Optional[AnchorRecord]:
        """
        Called after each MMR commit.

        Returns an AnchorRecord if anchoring was triggered, else None.
        """
        self._commit_count += 1

        if self._commit_count >= self.anchor_interval:
            self._current_epoch += 1
            record = self.provider.anchor(
                mmr_root_hash=mmr_root_hash,
                epoch=self._current_epoch,
                event_count=self._commit_count,
            )
            self._anchors.append(record)
            self._commit_count = 0
            return record

        return None

    def get_anchors(self) -> list[AnchorRecord]:
        return list(self._anchors)

    def verify_all(self) -> list[AnchorVerification]:
        return [self.provider.verify(a) for a in self._anchors]
