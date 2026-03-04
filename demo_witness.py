#!/usr/bin/env python3
"""
LICITRA-SENTRY v0.2 — Demo: Witnessed Transparency Layer

Demonstrates:
  A. Normal operation: epochs witnessed with CT-style receipts
  B. ATTACK: Operator rewrites history — witness detects fraud
  C. External auditor independently verifies evidence bundle

Usage:
    python demo_witness.py

Author: Narendra Kumar Nutalapati
License: MIT
"""

import sys
import os
import json
import hashlib
import tempfile
import shutil
from dataclasses import asdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.key_manager import FileKeyProvider
from app.identity import IdentityVerifier, AgentIdentity
from app.content_inspector import ContentInspector
from app.contract import ContractValidator, SemanticContract
from app.authority import AuthorityEnforcer
from app.audit_bridge import AuditBridge
from app.orchestrator import SentryOrchestrator, AuthorizationRequest
from app.witness import (
    FileTransparencyLog,
    WitnessClient,
    WitnessVerifier,
    EpochRecord,
    SignedInclusionReceipt,
)


def setup():
    tmpdir = tempfile.mkdtemp(prefix="licitra-witness-demo-")

    key_provider = FileKeyProvider(os.path.join(tmpdir, "keys"))
    key_provider.generate_key_pair("sentry")

    # Transparency log (INDEPENDENT keys from SENTRY)
    tl = FileTransparencyLog(os.path.join(tmpdir, "transparency_log"))

    witness_client = WitnessClient(
        provider=tl,
        receipts_dir=os.path.join(tmpdir, "receipts"),
        policy_hash=hashlib.sha256(b"production-policy-v2.1").hexdigest(),
        sentry_build_hash="578ecb9",
        operator_id="acme-corp",
    )

    identity = IdentityVerifier()
    identity.register_agent(AgentIdentity(
        agent_id="finance-agent",
        agent_type="llm_agent",
        credential_hash=hashlib.sha256(b"finance-cred").hexdigest(),
    ))

    inspector = ContentInspector()

    contracts = ContractValidator()
    contracts.register_contract(SemanticContract(
        contract_id="finance-v2",
        contract_version="2.0",
        agent_id="finance-agent",
        allowed_tools={"ledger-reader", "report-generator"},
        allowed_actions={"read", "generate"},
    ))

    authority = AuthorityEnforcer()
    authority.register_permissions("finance-agent", {
        "ledger-reader:read", "report-generator:generate",
    })

    audit = AuditBridge(
        log_path=os.path.join(tmpdir, "audit.jsonl"),
        witness_client=witness_client,
        epoch_size=6,  # finalize epoch every 6 events
    )

    sentry = SentryOrchestrator(
        identity_verifier=identity,
        content_inspector=inspector,
        contract_validator=contracts,
        authority_enforcer=authority,
        audit_bridge=audit,
        key_provider=key_provider,
    )

    return sentry, audit, tl, witness_client, tmpdir


def print_header(title):
    print()
    print("=" * 70)
    print(f"  {title}")
    print("=" * 70)


def run_demo():
    sentry, audit, tl, witness_client, tmpdir = setup()

    try:
        # ============================================================
        # SCENARIO A: Normal Operation with Witnessed Epochs
        # ============================================================
        print_header("SCENARIO A: Normal Operation — Witnessed Epochs")
        print()
        print("  Running 4 authorized requests through SENTRY pipeline.")
        print("  Each request generates ~6 audit events.")
        print("  Epochs finalize every 6 events and are witnessed.")
        print()

        for i in range(4):
            request = {"action": "read", "table": f"transactions_q{i+1}"}
            result = sentry.authorize(AuthorizationRequest(
                agent_id="finance-agent",
                credential="finance-cred",
                tool_id="ledger-reader",
                action="read",
                request=request,
            ))
            print(f"  Request {i+1}: {'APPROVED' if result.authorized else 'DENIED'} "
                  f"(processing: {result.processing_time_ms:.1f}ms)")

        receipts = audit.get_receipts()
        print()
        print(f"  Epochs finalized: {len(receipts)}")
        print(f"  Total audit events: {audit.get_event_count()}")
        print()

        for receipt in receipts:
            stored = witness_client.load_receipt(
                # find epoch_id from receipt
                int(receipt.receipt_id.split("-")[1][:4]) if False else
                receipts.index(receipt) + 1
            )
            if stored:
                er = stored["epoch_record"]
                print(f"  Epoch {er['epoch_id']}:")
                print(f"    Root hash:    {er['epoch_root'][:32]}...")
                print(f"    Events:       {er['event_count']}")
                print(f"    Receipt ID:   {receipt.receipt_id}")
                print(f"    Log sequence: {receipt.log_sequence}")
                print(f"    Signature:    {receipt.signature[:32]}...")
                print()

        # ============================================================
        # SCENARIO B: Operator Rewrite Attack
        # ============================================================
        print_header("SCENARIO B: ATTACK — Operator Rewrites History")
        print()
        print("  Day 1: Epoch 1 was witnessed with a receipt.")
        print("  Day 10: Attacker compromises the database and")
        print("  rewrites epoch 1's root hash to hide evidence.")
        print()

        stored = witness_client.load_receipt(1)
        original_epoch = EpochRecord(**stored["epoch_record"])
        original_receipt = SignedInclusionReceipt.from_dict(stored["receipt"])

        print(f"  Original epoch root:  {original_epoch.epoch_root[:32]}...")

        # Simulate the attack
        tampered_epoch = EpochRecord(
            epoch_id=original_epoch.epoch_id,
            epoch_root=hashlib.sha256(b"REWRITTEN-BY-ATTACKER").hexdigest(),
            prev_epoch_root=original_epoch.prev_epoch_root,
            policy_hash=original_epoch.policy_hash,
            sentry_build_hash=original_epoch.sentry_build_hash,
            event_count=original_epoch.event_count,
            timestamp=original_epoch.timestamp,
            operator_id=original_epoch.operator_id,
        )

        print(f"  Tampered epoch root:  {tampered_epoch.epoch_root[:32]}...")
        print()

        # Try to verify tampered epoch against original receipt
        valid = tl.verify_receipt(original_receipt, tampered_epoch)
        print(f"  Verify tampered epoch against witness receipt: {'VALID' if valid else 'INVALID'}")
        print()

        if not valid:
            print("  → FRAUD DETECTED. The witness log recorded the original root.")
            print("    Even with full database access, the attacker cannot rewrite")
            print("    the witness receipt without the witness's private key.")
            print("    The witness contradicts the attacker's claimed history.")

        # ============================================================
        # SCENARIO C: External Auditor Verification
        # ============================================================
        print_header("SCENARIO C: External Auditor Verification")
        print()
        print("  An auditor receives:")
        print("    1. Local audit records (epoch records)")
        print("    2. Witness receipts for each epoch")
        print("    3. The transparency log's public key")
        print()
        print("  The auditor does NOT need to trust the operator.")
        print("  The auditor verifies independently.")
        print()

        # Collect evidence bundle
        evidence = []
        for i in range(1, len(receipts) + 1):
            stored = witness_client.load_receipt(i)
            if stored:
                evidence.append(stored)

        # Auditor has only the log's public key
        log_pub_key = tl.get_log_public_key()
        verifier = WitnessVerifier(log_pub_key)
        report = verifier.verify_all(evidence)

        print(f"  Verification result:   {'VALID' if report.valid else 'INVALID'}")
        print(f"  Epochs checked:        {report.epochs_checked}")
        print(f"  Receipts verified:     {report.receipts_verified}")
        print(f"  Chain integrity:       {'INTACT' if report.chain_intact else 'BROKEN'}")
        if report.errors:
            for e in report.errors:
                print(f"  Error: {e}")
        print()
        print("  → The auditor independently verified that:")
        print("    - All epoch roots were witnessed by the transparency log")
        print("    - All receipt signatures are valid")
        print("    - The epoch chain is continuous (no gaps or rewrites)")
        print("    - Timestamps and sequence numbers are monotonic")
        print()
        print("  The auditor does not need to trust the operator's repo,")
        print("  PDF, or database. They verify against the witness log.")

        # ============================================================
        # SUMMARY
        # ============================================================
        print_header("THREAT MODEL COMPARISON")
        print()
        print("  WITHOUT witnesses:")
        print("    - Detects DB tampering IF keys intact AND operator honest")
        print("    - Operator can rewrite history undetectably")
        print()
        print("  WITH witnesses (CT-style receipts):")
        print("    - Detects DB tampering EVEN UNDER operator compromise")
        print("    - Rewriting history requires ALL witnesses to collude")
        print("    - External auditors verify independently")
        print()

        print("=" * 70)
        print("  DEMO COMPLETE")
        print("=" * 70)
        print()

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    run_demo()
