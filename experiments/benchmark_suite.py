#!/usr/bin/env python3
"""
LICITRA-SENTRY Benchmark Suite v0.2

Benchmarks the real v0.2 runtime path:

  authorize(...) -> execution ticket -> proxy.execute(...)

This replaces the older token-era benchmark that bypassed
execution-ticket enforcement and replay protection.
"""

import sys
import os
import json
import time
import statistics
import tempfile
import shutil
import hashlib
import threading
import concurrent.futures
from typing import Any, Dict

import requests

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from app.key_manager import FileKeyProvider
from app.identity import IdentityVerifier, AgentIdentity
from app.content_inspector import ContentInspector
from app.contract import ContractValidator, SemanticContract
from app.authority import AuthorityEnforcer
from app.audit_bridge import AuditBridge
from app.orchestrator import SentryOrchestrator, AuthorizationRequest
from app.tool_proxy import ToolProxy, ReplayStore


MMR_BASE_URL = os.environ.get("LICITRA_MMR_BASE_URL", "http://localhost:8000")


def get_mmr_context() -> Dict[str, Any]:
    """
    Best-effort fetch of LICITRA-MMR /health so benchmark output records
    the ledger context under which measurements were taken.
    """
    url = f"{MMR_BASE_URL.rstrip('/')}/health"
    try:
        resp = requests.get(url, timeout=3)
        resp.raise_for_status()
        data = resp.json()
        return {
            "reachable": True,
            "base_url": MMR_BASE_URL,
            "status": data.get("status"),
            "service": data.get("service"),
            "ledger_version": data.get("ledger_version"),
            "block_size": data.get("block_size"),
            "dev_mode": data.get("dev_mode"),
            "ledger_mode": data.get("ledger_mode"),
            "timestamp_utc": data.get("timestamp_utc"),
        }
    except Exception as exc:
        return {
            "reachable": False,
            "base_url": MMR_BASE_URL,
            "error": str(exc),
        }


def print_mmr_context() -> Dict[str, Any]:
    context = get_mmr_context()
    print("[MMR CONTEXT]")
    print(json.dumps(context, indent=2))
    print()
    return context


class BenchmarkContext:
    def __init__(self):
        self.tmpdir = tempfile.mkdtemp(prefix="licitra-bench-")
        self.keys_dir = os.path.join(self.tmpdir, "keys")
        self.data_dir = os.path.join(self.tmpdir, "data")
        os.makedirs(self.data_dir, exist_ok=True)

        self.key_provider = FileKeyProvider(self.keys_dir)
        self.key_provider.generate_key_pair("bench-sentry")

        self.identity = IdentityVerifier()
        self.contracts = ContractValidator()
        self.authority = AuthorityEnforcer()
        self.inspector = ContentInspector()
        self.audit = AuditBridge(
            log_path=os.path.join(self.data_dir, "audit.jsonl"),
            epoch_size=1000,
        )
        self.replay_store = ReplayStore(
            db_path=os.path.join(self.data_dir, "replay.db")
        )

        self.sentry = SentryOrchestrator(
            identity_verifier=self.identity,
            content_inspector=self.inspector,
            contract_validator=self.contracts,
            authority_enforcer=self.authority,
            audit_bridge=self.audit,
            key_provider=self.key_provider,
        )

        self.proxy = ToolProxy(
            key_provider=self.key_provider,
            replay_store=self.replay_store,
            audit_callback=lambda e: None,
        )

        self.proxy.register_tool("email-sender", self._mock_email_tool)
        self.proxy.register_tool("db-reader", self._mock_db_tool)

        self._register_agents()

    def _register_agents(self):
        for i in range(100):
            agent_id = f"agent-{i:03d}"
            credential = f"secret-{i:03d}"
            credential_hash = hashlib.sha256(credential.encode()).hexdigest()

            self.identity.register_agent(AgentIdentity(
                agent_id=agent_id,
                agent_type="llm_agent",
                credential_hash=credential_hash,
                organization="bench-org",
            ))

            if i % 2 == 0:
                self.contracts.register_contract(SemanticContract(
                    contract_id=f"contract-{i:03d}",
                    contract_version="1.0",
                    agent_id=agent_id,
                    allowed_tools={"db-reader"},
                    allowed_actions={"read"},
                ))
                self.authority.register_permissions(agent_id, {"db-reader:read"})
            else:
                self.contracts.register_contract(SemanticContract(
                    contract_id=f"contract-{i:03d}",
                    contract_version="1.0",
                    agent_id=agent_id,
                    allowed_tools={"email-sender"},
                    allowed_actions={"send"},
                ))
                self.authority.register_permissions(agent_id, {"email-sender:send"})

    def _mock_email_tool(self, request):
        return {"status": "sent", "to": request.get("to", "")}

    def _mock_db_tool(self, request):
        return {"rows": [{"table": request.get("table", "unknown"), "id": 1}]}

    def cleanup(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)


def make_valid_request(i: int):
    agent_id = f"agent-{i:03d}"
    credential = f"secret-{i:03d}"

    if i % 2 == 0:
        return {
            "agent_id": agent_id,
            "credential": credential,
            "tool_id": "db-reader",
            "action": "read",
            "request": {"action": "read", "table": f"dataset_{i}"},
        }

    return {
        "agent_id": agent_id,
        "credential": credential,
        "tool_id": "email-sender",
        "action": "send",
        "request": {
            "action": "send",
            "to": f"user{i}@internal.example.com",
            "subject": "Benchmark",
            "body": "Test message",
        },
    }


def run_full_pipeline(ctx: BenchmarkContext, payload: dict):
    t0 = time.perf_counter()

    auth = ctx.sentry.authorize(AuthorizationRequest(
        agent_id=payload["agent_id"],
        credential=payload["credential"],
        tool_id=payload["tool_id"],
        action=payload["action"],
        request=payload["request"],
    ))

    if not auth.authorized:
        return {
            "decision": "REJECTED",
            "stage": "authorize",
            "latency_ms": (time.perf_counter() - t0) * 1000,
            "reason": auth.rejection_reason,
        }

    proxy = ctx.proxy.execute(
        ticket=auth.ticket,
        tool_id=payload["tool_id"],
        request=payload["request"],
    )

    return {
        "decision": "APPROVED" if proxy.allowed else "REJECTED",
        "stage": "execute" if proxy.allowed else "proxy_reject",
        "latency_ms": (time.perf_counter() - t0) * 1000,
        "error": proxy.error,
        "mmr_commit_id": auth.mmr_commit_id,
    }


def benchmark_sequential(ctx: BenchmarkContext, count=1000):
    print("=" * 70)
    print("BENCHMARK 1: v0.2 Full Pipeline Sequential")
    print("=" * 70)

    latencies = []
    decisions = {"APPROVED": 0, "REJECTED": 0}

    t0 = time.perf_counter()
    for n in range(count):
        payload = make_valid_request(n % 100)
        result = run_full_pipeline(ctx, payload)
        latencies.append(result["latency_ms"])
        decisions[result["decision"]] += 1
    elapsed = time.perf_counter() - t0

    sl = sorted(latencies)
    out = {
        "count": count,
        "rps": round(count / elapsed),
        "p50_ms": round(statistics.median(latencies), 3),
        "p95_ms": round(sl[int(0.95 * len(sl))], 3),
        "p99_ms": round(sl[int(0.99 * len(sl))], 3),
        "decisions": decisions,
        "audit_events": ctx.audit.get_event_count(),
    }

    print(f"  {out['rps']} RPS | p50={out['p50_ms']}ms p95={out['p95_ms']}ms p99={out['p99_ms']}ms")
    print(f"  Decisions: {out['decisions']} | Audit events: {out['audit_events']}")
    return out


def benchmark_concurrent(ctx: BenchmarkContext, count=1000, threads=20):
    print("\n" + "=" * 70)
    print("BENCHMARK 2: v0.2 Full Pipeline Concurrent")
    print("=" * 70)

    latencies = []
    decisions = {"APPROVED": 0, "REJECTED": 0}
    lock = threading.Lock()

    def worker(n):
        payload = make_valid_request(n % 100)
        result = run_full_pipeline(ctx, payload)
        with lock:
            latencies.append(result["latency_ms"])
            decisions[result["decision"]] += 1

    t0 = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        list(ex.map(worker, range(count)))
    elapsed = time.perf_counter() - t0

    sl = sorted(latencies)
    out = {
        "count": count,
        "threads": threads,
        "rps": round(count / elapsed),
        "p50_ms": round(statistics.median(latencies), 3),
        "p95_ms": round(sl[int(0.95 * len(sl))], 3),
        "p99_ms": round(sl[int(0.99 * len(sl))], 3),
        "decisions": decisions,
        "audit_events": ctx.audit.get_event_count(),
    }

    print(f"  {out['rps']} RPS | p50={out['p50_ms']}ms p95={out['p95_ms']}ms p99={out['p99_ms']}ms")
    print(f"  Decisions: {out['decisions']} | Audit events: {out['audit_events']}")
    return out


def benchmark_security_failures(ctx: BenchmarkContext):
    print("\n" + "=" * 70)
    print("BENCHMARK 3: v0.2 Security Failure Checks")
    print("=" * 70)

    base = make_valid_request(1)

    auth = ctx.sentry.authorize(AuthorizationRequest(
        agent_id=base["agent_id"],
        credential=base["credential"],
        tool_id=base["tool_id"],
        action=base["action"],
        request=base["request"],
    ))
    assert auth.authorized

    first = ctx.proxy.execute(auth.ticket, base["tool_id"], base["request"])
    second = ctx.proxy.execute(auth.ticket, base["tool_id"], base["request"])

    tampered_request = dict(base["request"])
    tampered_request["body"] = "tampered"

    auth2 = ctx.sentry.authorize(AuthorizationRequest(
        agent_id=base["agent_id"],
        credential=base["credential"],
        tool_id=base["tool_id"],
        action=base["action"],
        request=base["request"],
    ))
    assert auth2.authorized

    tampered = ctx.proxy.execute(auth2.ticket, base["tool_id"], tampered_request)

    out = {
        "replay_first_allowed": first.allowed,
        "replay_second_allowed": second.allowed,
        "replay_second_error": second.error,
        "tamper_allowed": tampered.allowed,
        "tamper_error": tampered.error,
    }

    print(f"  Replay first allowed: {out['replay_first_allowed']}")
    print(f"  Replay second allowed: {out['replay_second_allowed']} | {out['replay_second_error']}")
    print(f"  Tamper allowed: {out['tamper_allowed']} | {out['tamper_error']}")
    return out


if __name__ == "__main__":
    print(f"LICITRA-SENTRY Benchmark Suite v0.2\nPython {sys.version}\n")
    mmr_context = print_mmr_context()

    ctx = BenchmarkContext()
    try:
        results = {
            "metadata": {
                "python": sys.version,
                "platform": sys.platform,
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "benchmark_version": "v0.2",
                "mmr_context": mmr_context,
            }
        }
        results["b1_sequential_full_pipeline"] = benchmark_sequential(ctx, count=1000)
        results["b2_concurrent_full_pipeline"] = benchmark_concurrent(ctx, count=1000, threads=20)
        results["b3_security_failure_checks"] = benchmark_security_failures(ctx)

        out_path = os.path.join(PROJECT_ROOT, "experiments", "benchmark_results.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)

        print("\n" + "=" * 70)
        print("SUMMARY")
        print("=" * 70)
        print(f"[B1] {results['b1_sequential_full_pipeline']['rps']} RPS seq")
        print(f"[B2] {results['b2_concurrent_full_pipeline']['rps']} RPS concurrent")
        print(f"[B3] replay_second_allowed={results['b3_security_failure_checks']['replay_second_allowed']}")
        print(f"[B3] tamper_allowed={results['b3_security_failure_checks']['tamper_allowed']}")
        print(f"\nResults: {out_path}")
    finally:
        ctx.cleanup()