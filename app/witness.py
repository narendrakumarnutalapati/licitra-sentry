"""
LICITRA-SENTRY v0.2 — Witness Client

Implements a Certificate Transparency-style witnessed epoch finality system.

Every epoch, the MMR root hash (plus metadata) is submitted to a Transparency
Log (TL). The TL returns a Signed Inclusion Receipt (SIR) — a co-signature
from an independent party proving the epoch root was observed at a specific
time. This receipt is stored alongside the local audit log.

Security property:
  Without witnesses: detects DB tampering if keys intact and operator honest.
  With witnesses: detects DB tampering even under operator compromise,
  unless ALL witnesses collude.

This module provides:
  - Abstract WitnessProvider interface
  - SignedInclusionReceipt data structure
  - FileTransparencyLog (reference implementation for testing)
  - WitnessClient (orchestrates submission and verification)
  - WitnessVerifier (standalone verification for auditors)

In production, the FileTransparencyLog would be replaced by:
  - A public CT-style log server
  - A third-party witness service
  - A community-operated log (e.g., OWASP-hosted)

Author: Narendra Kumar Nutalapati
License: MIT
"""

import json
import time
import hashlib
import uuid
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict, field
from typing import Optional
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

import base64


def _b64_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


# --------------------------------------------------------------------------- #
#  Epoch Record — what gets witnessed
# --------------------------------------------------------------------------- #

@dataclass
class EpochRecord:
    """
    The data structure submitted to the transparency log.

    Binds runtime decisions to:
      - Chain continuity (epoch_id, prev_epoch_root)
      - Policy version (policy_hash)
      - Code version (sentry_build_hash)
      - Audit state (epoch_root = MMR root hash)
    """
    epoch_id: int
    epoch_root: str           # MMR root hash for this epoch
    prev_epoch_root: str      # Previous epoch's root (chain link)
    policy_hash: str          # SHA-256 of policy bundle
    sentry_build_hash: str    # Git commit or build provenance hash
    event_count: int          # Number of events in this epoch
    timestamp: float          # When epoch was finalized
    operator_id: str = ""     # Identifies the SENTRY operator

    def canonical(self) -> str:
        """Deterministic serialization for hashing."""
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))

    def digest(self) -> str:
        """SHA-256 of the canonical epoch record."""
        return hashlib.sha256(self.canonical().encode()).hexdigest()


# --------------------------------------------------------------------------- #
#  Signed Inclusion Receipt (SIR)
# --------------------------------------------------------------------------- #

@dataclass
class SignedInclusionReceipt:
    """
    CT-style receipt proving that a transparency log observed an epoch root.

    Fields:
        receipt_id: Unique identifier for this receipt.
        epoch_digest: SHA-256 of the canonical EpochRecord.
        log_id: Identifier of the transparency log.
        log_timestamp: When the log recorded this entry.
        log_sequence: Monotonic sequence number in the log.
        signature: Ed25519 signature by the log over the receipt payload.
        public_key_fingerprint: SHA-256 prefix of the log's public key.
    """
    receipt_id: str
    epoch_digest: str
    log_id: str
    log_timestamp: float
    log_sequence: int
    signature: str            # base64url-encoded Ed25519 signature
    public_key_fingerprint: str

    def signing_payload(self) -> bytes:
        """The exact bytes that are signed by the log."""
        payload = {
            "receipt_id": self.receipt_id,
            "epoch_digest": self.epoch_digest,
            "log_id": self.log_id,
            "log_timestamp": self.log_timestamp,
            "log_sequence": self.log_sequence,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "SignedInclusionReceipt":
        return cls(**data)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, indent=2)

    @classmethod
    def from_json(cls, raw: str) -> "SignedInclusionReceipt":
        return cls.from_dict(json.loads(raw))


# --------------------------------------------------------------------------- #
#  Abstract Witness Provider
# --------------------------------------------------------------------------- #

class WitnessProvider(ABC):
    """Abstract interface for transparency log backends."""

    @abstractmethod
    def submit(self, epoch_record: EpochRecord) -> SignedInclusionReceipt:
        """Submit an epoch record and receive a signed receipt."""
        ...

    @abstractmethod
    def verify_receipt(
        self, receipt: SignedInclusionReceipt, epoch_record: EpochRecord
    ) -> bool:
        """Verify that a receipt is valid for the given epoch record."""
        ...

    @abstractmethod
    def get_log_entries(self, start: int = 0, end: int = -1) -> list[dict]:
        """Retrieve log entries by sequence range."""
        ...

    @abstractmethod
    def get_log_public_key(self) -> bytes:
        """Return the log's public key (PEM bytes)."""
        ...

    @abstractmethod
    def get_log_id(self) -> str:
        """Return the log's unique identifier."""
        ...


# --------------------------------------------------------------------------- #
#  File-based Transparency Log (reference implementation)
# --------------------------------------------------------------------------- #

class FileTransparencyLog(WitnessProvider):
    """
    File-based transparency log for testing and demonstration.

    In production, this would be an independent server operated by a
    third party. The reference implementation runs locally but uses
    a SEPARATE Ed25519 key pair from SENTRY's signing key, simulating
    an independent witness.

    Key separation is critical: the witness key must NOT be the same
    as SENTRY's ticket-signing key. Otherwise, compromising SENTRY
    also compromises the witness, defeating the purpose.
    """

    def __init__(self, log_dir: str = "data/transparency_log"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.log_id = "licitra-tl-local"
        self._sequence = 0
        self._entries: list[dict] = []

        # Generate SEPARATE witness key (independent from SENTRY)
        self._private_key, self._public_key, self._fingerprint = (
            self._load_or_generate_keys()
        )

        # Load existing entries
        self._load_log()

    def _load_or_generate_keys(self):
        priv_path = self.log_dir / "witness_private.pem"
        pub_path = self.log_dir / "witness_public.pem"

        if priv_path.exists() and pub_path.exists():
            with open(priv_path, "rb") as f:
                private_key = serialization.load_pem_private_key(f.read(), password=None)
            public_key = private_key.public_key()
        else:
            private_key = Ed25519PrivateKey.generate()
            public_key = private_key.public_key()

            priv_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            pub_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            with open(priv_path, "wb") as f:
                f.write(priv_pem)
            os.chmod(priv_path, 0o600)

            with open(pub_path, "wb") as f:
                f.write(pub_pem)

        pub_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        fingerprint = hashlib.sha256(pub_pem).hexdigest()[:16]

        return private_key, public_key, fingerprint

    def _load_log(self):
        log_file = self.log_dir / "log.jsonl"
        if log_file.exists():
            with open(log_file, "r") as f:
                for line in f:
                    entry = json.loads(line.strip())
                    self._entries.append(entry)
                    self._sequence = max(self._sequence, entry["sequence"] + 1)

    def _append_to_log(self, entry: dict):
        log_file = self.log_dir / "log.jsonl"
        with open(log_file, "a") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")
        self._entries.append(entry)

    def submit(self, epoch_record: EpochRecord) -> SignedInclusionReceipt:
        epoch_digest = epoch_record.digest()
        now = time.time()
        receipt_id = f"sir-{uuid.uuid4().hex[:12]}"

        receipt = SignedInclusionReceipt(
            receipt_id=receipt_id,
            epoch_digest=epoch_digest,
            log_id=self.log_id,
            log_timestamp=now,
            log_sequence=self._sequence,
            signature="",  # filled below
            public_key_fingerprint=self._fingerprint,
        )

        # Sign the receipt payload
        payload_bytes = receipt.signing_payload()
        sig_bytes = self._private_key.sign(payload_bytes)
        receipt.signature = _b64_encode(sig_bytes)

        # Append to log
        log_entry = {
            "sequence": self._sequence,
            "epoch_id": epoch_record.epoch_id,
            "epoch_digest": epoch_digest,
            "epoch_root": epoch_record.epoch_root,
            "timestamp": now,
            "receipt_id": receipt_id,
        }
        self._append_to_log(log_entry)
        self._sequence += 1

        return receipt

    def verify_receipt(
        self, receipt: SignedInclusionReceipt, epoch_record: EpochRecord
    ) -> bool:
        # Check epoch digest matches
        expected_digest = epoch_record.digest()
        if receipt.epoch_digest != expected_digest:
            return False

        # Check log_id
        if receipt.log_id != self.log_id:
            return False

        # Verify signature
        try:
            payload_bytes = receipt.signing_payload()
            sig_bytes = _b64_decode(receipt.signature)
            self._public_key.verify(sig_bytes, payload_bytes)
            return True
        except (InvalidSignature, Exception):
            return False

    def get_log_entries(self, start: int = 0, end: int = -1) -> list[dict]:
        if end == -1:
            return self._entries[start:]
        return self._entries[start:end]

    def get_log_public_key(self) -> bytes:
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def get_log_id(self) -> str:
        return self.log_id


# --------------------------------------------------------------------------- #
#  Witness Client
# --------------------------------------------------------------------------- #

class WitnessClient:
    """
    Orchestrates epoch witnessing.

    Called by the AuditBridge after each epoch finalization.
    Submits the epoch record to the transparency log and stores
    the receipt alongside the local audit data.
    """

    def __init__(
        self,
        provider: WitnessProvider,
        receipts_dir: str = "data/receipts",
        policy_hash: str = "0" * 64,
        sentry_build_hash: str = "0" * 64,
        operator_id: str = "default-operator",
    ):
        self.provider = provider
        self.receipts_dir = Path(receipts_dir)
        self.receipts_dir.mkdir(parents=True, exist_ok=True)
        self.policy_hash = policy_hash
        self.sentry_build_hash = sentry_build_hash
        self.operator_id = operator_id
        self._receipts: list[SignedInclusionReceipt] = []

    def witness_epoch(
        self,
        epoch_id: int,
        epoch_root: str,
        prev_epoch_root: str,
        event_count: int,
    ) -> SignedInclusionReceipt:
        """
        Submit an epoch to the transparency log and store the receipt.

        Args:
            epoch_id: Epoch sequence number.
            epoch_root: MMR root hash for this epoch.
            prev_epoch_root: Previous epoch's root hash.
            event_count: Number of events in this epoch.

        Returns:
            SignedInclusionReceipt from the transparency log.
        """
        epoch_record = EpochRecord(
            epoch_id=epoch_id,
            epoch_root=epoch_root,
            prev_epoch_root=prev_epoch_root,
            policy_hash=self.policy_hash,
            sentry_build_hash=self.sentry_build_hash,
            event_count=event_count,
            timestamp=time.time(),
            operator_id=self.operator_id,
        )

        # Submit to transparency log
        receipt = self.provider.submit(epoch_record)

        # Store receipt locally
        receipt_path = self.receipts_dir / f"epoch-{epoch_id}-receipt.json"
        with open(receipt_path, "w") as f:
            json.dump({
                "epoch_record": asdict(epoch_record),
                "receipt": receipt.to_dict(),
            }, f, indent=2)

        self._receipts.append(receipt)
        return receipt

    def get_receipts(self) -> list[SignedInclusionReceipt]:
        return list(self._receipts)

    def load_receipt(self, epoch_id: int) -> Optional[dict]:
        """Load a stored receipt + epoch record by epoch ID."""
        receipt_path = self.receipts_dir / f"epoch-{epoch_id}-receipt.json"
        if not receipt_path.exists():
            return None
        with open(receipt_path, "r") as f:
            return json.load(f)


# --------------------------------------------------------------------------- #
#  Witness Verifier (standalone, for external auditors)
# --------------------------------------------------------------------------- #

@dataclass
class VerificationReport:
    """Result of a full witness verification audit."""
    valid: bool
    epochs_checked: int
    receipts_verified: int
    chain_intact: bool
    errors: list[str] = field(default_factory=list)


class WitnessVerifier:
    """
    Standalone verifier for external auditors.

    Given:
      - A set of epoch records + receipts
      - The transparency log's public key

    Verifies:
      1. Each receipt signature is valid
      2. Each receipt's epoch_digest matches the epoch record
      3. Epoch chain is continuous (prev_epoch_root links)
      4. Log sequence numbers are monotonically increasing
      5. Timestamps are non-decreasing
    """

    def __init__(self, log_public_key_pem: bytes):
        self._public_key = serialization.load_pem_public_key(log_public_key_pem)

    def verify_receipt_signature(
        self, receipt: SignedInclusionReceipt
    ) -> bool:
        """Verify a single receipt's signature against the log's public key."""
        try:
            payload_bytes = receipt.signing_payload()
            sig_bytes = _b64_decode(receipt.signature)
            self._public_key.verify(sig_bytes, payload_bytes)
            return True
        except (InvalidSignature, Exception):
            return False

    def verify_all(
        self, evidence: list[dict]
    ) -> VerificationReport:
        """
        Verify a complete evidence bundle.

        Args:
            evidence: List of dicts, each containing 'epoch_record' and 'receipt'.

        Returns:
            VerificationReport with detailed results.
        """
        errors = []
        receipts_verified = 0
        chain_intact = True
        prev_root = "0" * 64
        prev_sequence = -1
        prev_timestamp = 0.0

        for i, item in enumerate(evidence):
            epoch_data = item["epoch_record"]
            receipt_data = item["receipt"]

            epoch_record = EpochRecord(**epoch_data)
            receipt = SignedInclusionReceipt.from_dict(receipt_data)

            # 1. Verify receipt signature
            if not self.verify_receipt_signature(receipt):
                errors.append(
                    f"Epoch {epoch_record.epoch_id}: Receipt signature INVALID"
                )
                continue

            # 2. Verify epoch digest matches
            expected_digest = epoch_record.digest()
            if receipt.epoch_digest != expected_digest:
                errors.append(
                    f"Epoch {epoch_record.epoch_id}: Epoch digest mismatch "
                    f"(receipt={receipt.epoch_digest[:16]}..., "
                    f"computed={expected_digest[:16]}...)"
                )
                continue

            receipts_verified += 1

            # 3. Chain continuity
            if i > 0 and epoch_record.prev_epoch_root != prev_root:
                errors.append(
                    f"Epoch {epoch_record.epoch_id}: Chain break — "
                    f"prev_epoch_root doesn't match previous epoch's root"
                )
                chain_intact = False

            # 4. Monotonic sequence
            if receipt.log_sequence <= prev_sequence:
                errors.append(
                    f"Epoch {epoch_record.epoch_id}: Log sequence not monotonic "
                    f"({receipt.log_sequence} <= {prev_sequence})"
                )

            # 5. Non-decreasing timestamps
            if receipt.log_timestamp < prev_timestamp:
                errors.append(
                    f"Epoch {epoch_record.epoch_id}: Timestamp regression "
                    f"({receipt.log_timestamp} < {prev_timestamp})"
                )

            prev_root = epoch_record.epoch_root
            prev_sequence = receipt.log_sequence
            prev_timestamp = receipt.log_timestamp

        return VerificationReport(
            valid=len(errors) == 0,
            epochs_checked=len(evidence),
            receipts_verified=receipts_verified,
            chain_intact=chain_intact,
            errors=errors,
        )
