"""
LICITRA-SENTRY v0.2 — Witness Tests

Tests for the witnessed transparency layer:

  E09: Epoch witnessed with valid receipt
  E10: Operator rewrite attack — detected via witness mismatch
  E11: External auditor verifies complete evidence bundle
  E12: Tampered receipt rejected (signature invalid)
  E13: Chain break detected across witnessed epochs

Author: Narendra Kumar Nutalapati
License: MIT
"""

import sys
import os
import time
import json
import hashlib
import tempfile
import shutil
from dataclasses import asdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.key_manager import FileKeyProvider
from app.identity import IdentityVerifier, AgentIdentity
from app.content_inspector import ContentInspector
from app.contract import ContractValidator, SemanticContract
from app.authority import AuthorityEnforcer
from app.audit_bridge import AuditBridge
from app.anchor import FileAnchorProvider, AnchorManager
from app.orchestrator import SentryOrchestrator, AuthorizationRequest
from app.witness import (
    FileTransparencyLog,
    WitnessClient,
    WitnessVerifier,
    EpochRecord,
    SignedInclusionReceipt,
)


class WitnessTestContext:
    """Shared test setup with witness infrastructure."""

    def __init__(self, epoch_size=5):
        self.tmpdir = tempfile.mkdtemp(prefix="licitra-witness-test-")

        # Key provider (SENTRY keys)
        self.key_provider = FileKeyProvider(os.path.join(self.tmpdir, "keys"))
        self.key_provider.generate_key_pair("test-sentry")

        # Transparency log (SEPARATE keys from SENTRY)
        self.tl = FileTransparencyLog(
            log_dir=os.path.join(self.tmpdir, "transparency_log")
        )

        # Witness client
        self.witness_client = WitnessClient(
            provider=self.tl,
            receipts_dir=os.path.join(self.tmpdir, "receipts"),
            policy_hash=hashlib.sha256(b"test-policy-v1").hexdigest(),
            sentry_build_hash="578ecb9",
            operator_id="test-operator",
        )

        # Identity
        self.identity = IdentityVerifier()
        self.identity.register_agent(AgentIdentity(
            agent_id="agent-alpha",
            agent_type="llm_agent",
            credential_hash=hashlib.sha256(b"secret-alpha").hexdigest(),
        ))

        # Content inspector
        self.inspector = ContentInspector()

        # Contracts
        self.contracts = ContractValidator()
        self.contracts.register_contract(SemanticContract(
            contract_id="contract-001",
            contract_version="1.0",
            agent_id="agent-alpha",
            allowed_tools={"db-reader"},
            allowed_actions={"read"},
        ))

        # Authority
        self.authority = AuthorityEnforcer()
        self.authority.register_permissions("agent-alpha", {"db-reader:read"})

        # Audit bridge WITH witness client
        self.audit = AuditBridge(
            log_path=os.path.join(self.tmpdir, "audit.jsonl"),
            witness_client=self.witness_client,
            epoch_size=epoch_size,
        )

        # Orchestrator
        self.sentry = SentryOrchestrator(
            identity_verifier=self.identity,
            content_inspector=self.inspector,
            contract_validator=self.contracts,
            authority_enforcer=self.authority,
            audit_bridge=self.audit,
            key_provider=self.key_provider,
        )

    def run_authorized_requests(self, count=1):
        """Run N authorized requests to generate audit events."""
        results = []
        for i in range(count):
            result = self.sentry.authorize(AuthorizationRequest(
                agent_id="agent-alpha",
                credential="secret-alpha",
                tool_id="db-reader",
                action="read",
                request={"action": "read", "table": f"dataset_{i}"},
            ))
            results.append(result)
        return results

    def cleanup(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)


# --------------------------------------------------------------------------- #
#  Tests
# --------------------------------------------------------------------------- #

def test_e09_epoch_witnessed():
    """E09: Epoch finalization triggers witness submission with valid receipt."""
    ctx = WitnessTestContext(epoch_size=5)
    try:
        # Each authorized request generates ~6 audit events (5 gates + 1 commit)
        # With epoch_size=5, first epoch should finalize within first request
        ctx.run_authorized_requests(count=3)

        receipts = ctx.audit.get_receipts()
        assert len(receipts) > 0, "No receipts generated"

        # Verify each receipt
        for receipt in receipts:
            assert receipt.receipt_id.startswith("sir-")
            assert receipt.log_id == "licitra-tl-local"
            assert receipt.signature != ""
            assert receipt.epoch_digest != ""

        # Verify receipt against transparency log
        stored = ctx.witness_client.load_receipt(1)
        assert stored is not None
        epoch_record = EpochRecord(**stored["epoch_record"])
        receipt = SignedInclusionReceipt.from_dict(stored["receipt"])
        assert ctx.tl.verify_receipt(receipt, epoch_record)

        print(f"  [PASS] E09: Epoch witnessed — {len(receipts)} receipts generated")
        return True
    finally:
        ctx.cleanup()


def test_e10_operator_rewrite_detected():
    """E10: Operator rewrites history — witness receipt detects the fraud."""
    ctx = WitnessTestContext(epoch_size=5)
    try:
        ctx.run_authorized_requests(count=3)

        # Get the original receipt for epoch 1
        stored = ctx.witness_client.load_receipt(1)
        assert stored is not None

        original_epoch = EpochRecord(**stored["epoch_record"])
        original_receipt = SignedInclusionReceipt.from_dict(stored["receipt"])

        # ATTACK: Operator rewrites epoch root (simulating DB compromise)
        tampered_epoch = EpochRecord(
            epoch_id=original_epoch.epoch_id,
            epoch_root=hashlib.sha256(b"rewritten-fake-root").hexdigest(),  # FORGED
            prev_epoch_root=original_epoch.prev_epoch_root,
            policy_hash=original_epoch.policy_hash,
            sentry_build_hash=original_epoch.sentry_build_hash,
            event_count=original_epoch.event_count,
            timestamp=original_epoch.timestamp,
            operator_id=original_epoch.operator_id,
        )

        # Verification against original receipt should FAIL
        # because the epoch digest no longer matches
        is_valid = ctx.tl.verify_receipt(original_receipt, tampered_epoch)
        assert not is_valid, "Tampered epoch should NOT verify against original receipt"

        # Original should still verify
        is_valid_original = ctx.tl.verify_receipt(original_receipt, original_epoch)
        assert is_valid_original, "Original epoch should still verify"

        print("  [PASS] E10: Operator rewrite detected — witness receipt caught the fraud")
        return True
    finally:
        ctx.cleanup()


def test_e11_auditor_verification():
    """E11: External auditor independently verifies the complete evidence bundle."""
    ctx = WitnessTestContext(epoch_size=5)
    try:
        # Generate enough events for multiple epochs
        ctx.run_authorized_requests(count=5)

        receipts = ctx.audit.get_receipts()
        assert len(receipts) >= 2, f"Need >=2 epochs, got {len(receipts)}"

        # Collect evidence bundle (what the auditor receives)
        evidence = []
        for i in range(1, len(receipts) + 1):
            stored = ctx.witness_client.load_receipt(i)
            if stored:
                evidence.append(stored)

        # External auditor creates verifier with ONLY the log's public key
        log_pub_key = ctx.tl.get_log_public_key()
        verifier = WitnessVerifier(log_pub_key)

        # Verify complete evidence bundle
        report = verifier.verify_all(evidence)

        assert report.valid, f"Verification failed: {report.errors}"
        assert report.epochs_checked == len(evidence)
        assert report.receipts_verified == len(evidence)
        assert report.chain_intact

        print(f"  [PASS] E11: Auditor verification — {report.epochs_checked} epochs, "
              f"{report.receipts_verified} receipts, chain intact")
        return True
    finally:
        ctx.cleanup()


def test_e12_tampered_receipt_rejected():
    """E12: Receipt with forged signature is rejected."""
    ctx = WitnessTestContext(epoch_size=5)
    try:
        ctx.run_authorized_requests(count=2)

        stored = ctx.witness_client.load_receipt(1)
        assert stored is not None

        epoch_record = EpochRecord(**stored["epoch_record"])
        receipt = SignedInclusionReceipt.from_dict(stored["receipt"])

        # ATTACK: Forge the signature
        tampered_receipt = SignedInclusionReceipt(
            receipt_id=receipt.receipt_id,
            epoch_digest=receipt.epoch_digest,
            log_id=receipt.log_id,
            log_timestamp=receipt.log_timestamp,
            log_sequence=receipt.log_sequence,
            signature="AAAA_forged_signature_AAAA",  # FORGED
            public_key_fingerprint=receipt.public_key_fingerprint,
        )

        # Should fail verification
        is_valid = ctx.tl.verify_receipt(tampered_receipt, epoch_record)
        assert not is_valid, "Tampered receipt should NOT verify"

        # External verifier should also reject
        verifier = WitnessVerifier(ctx.tl.get_log_public_key())
        assert not verifier.verify_receipt_signature(tampered_receipt)

        print("  [PASS] E12: Tampered receipt rejected — forged signature detected")
        return True
    finally:
        ctx.cleanup()


def test_e13_chain_break_detected():
    """E13: Modified epoch chain (skipped/altered epoch) detected by auditor."""
    ctx = WitnessTestContext(epoch_size=5)
    try:
        ctx.run_authorized_requests(count=5)

        receipts = ctx.audit.get_receipts()
        assert len(receipts) >= 2

        # Collect evidence
        evidence = []
        for i in range(1, len(receipts) + 1):
            stored = ctx.witness_client.load_receipt(i)
            if stored:
                evidence.append(stored)

        # ATTACK: Modify the second epoch's prev_epoch_root to break the chain
        if len(evidence) >= 2:
            evidence[1]["epoch_record"]["prev_epoch_root"] = hashlib.sha256(
                b"fake-previous-root"
            ).hexdigest()

            # Re-sign won't work because the epoch_digest will now mismatch
            # the receipt's epoch_digest

        verifier = WitnessVerifier(ctx.tl.get_log_public_key())
        report = verifier.verify_all(evidence)

        # Should detect either digest mismatch or chain break
        assert not report.valid, f"Should detect tampering, but got valid. Errors: {report.errors}"
        assert len(report.errors) > 0

        print(f"  [PASS] E13: Chain break detected — {len(report.errors)} error(s) found")
        return True
    finally:
        ctx.cleanup()


# --------------------------------------------------------------------------- #
#  Runner
# --------------------------------------------------------------------------- #

def run_witness_tests():
    print("=" * 70)
    print("LICITRA-SENTRY v0.2 — Witness Tests")
    print("=" * 70)
    print()

    tests = [
        ("E09", "Epoch Witnessed with Receipt", test_e09_epoch_witnessed),
        ("E10", "Operator Rewrite Detected", test_e10_operator_rewrite_detected),
        ("E11", "External Auditor Verification", test_e11_auditor_verification),
        ("E12", "Tampered Receipt Rejected", test_e12_tampered_receipt_rejected),
        ("E13", "Chain Break Detected", test_e13_chain_break_detected),
    ]

    results = []
    for eid, name, fn in tests:
        print(f"[{eid}] {name}")
        try:
            passed = fn()
            results.append((eid, name, passed))
        except Exception as e:
            print(f"  [FAIL] {eid}: {e}")
            import traceback
            traceback.print_exc()
            results.append((eid, name, False))
        print()

    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    passed = sum(1 for _, _, p in results if p)
    total = len(results)
    for eid, name, p in results:
        status = "PASS" if p else "FAIL"
        print(f"  [{status}] {eid}: {name}")
    print()
    print(f"  Result: {passed}/{total} witness tests passed")
    print("=" * 70)

    return passed == total


if __name__ == "__main__":
    success = run_witness_tests()
    sys.exit(0 if success else 1)
