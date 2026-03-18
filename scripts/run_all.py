from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


TEST_SPECS = [
    ("TEST-001", "test_sentry_v02", "tests/test_sentry_v02.py"),
    ("TEST-002", "test_witness", "tests/test_witness.py"),
]

EXPERIMENT_SPECS = [
    ("EXP-01", "experiments.run_exp01_happy_path", "experiments/run_exp01_happy_path.py"),
    ("EXP-02", "experiments.run_exp02_contract_rejection", "experiments/run_exp02_contract_rejection.py"),
    ("EXP-03", "experiments.run_exp03_identity_expiry", "experiments/run_exp03_identity_expiry.py"),
    ("EXP-04", "experiments.run_exp04_relay_injection", "experiments/run_exp04_relay_injection.py"),
    ("EXP-05", "experiments.run_exp05_pii_exfiltration", "experiments/run_exp05_pii_exfiltration.py"),
    ("EXP-06", "experiments.run_exp06_unauthorized_delegation", "experiments/run_exp06_unauthorized_delegation.py"),
    ("EXP-07", "experiments.run_exp07_e2e_mmr_proof", "experiments/run_exp07_e2e_mmr_proof.py"),
    ("EXP-08", "experiments.run_exp08_ticket_replay", "experiments/run_exp08_ticket_replay.py"),
    ("EXP-09", "experiments.run_exp09_payload_tampering", "experiments/run_exp09_payload_tampering.py"),
    ("EXP-10", "experiments.run_exp10_audit_tampering", "experiments/run_exp10_audit_tampering.py"),
]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def make_run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def copy_tree(src: Path, dst: Path) -> None:
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst)


def run_command(cmd: list[str], cwd: Path, env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def parse_test_checks(stdout: str) -> list[dict]:
    checks_by_id = {}

    header_pattern = re.compile(r"^\[(E\d+)\]\s+(.+)$")
    result_pattern = re.compile(r"^\[(PASS|FAIL)\]\s+(E\d+):\s+(.+)$")

    for raw_line in stdout.splitlines():
        line = raw_line.strip()

        header_match = header_pattern.match(line)
        if header_match:
            check_id, name = header_match.groups()
            checks_by_id.setdefault(check_id, {
                "check_id": check_id,
                "name": name.strip(),
                "status": "FAIL",
            })
            continue

        result_match = result_pattern.match(line)
        if result_match:
            status, check_id, fallback_name = result_match.groups()
            if check_id in checks_by_id:
                checks_by_id[check_id]["status"] = status
            else:
                checks_by_id[check_id] = {
                    "check_id": check_id,
                    "name": fallback_name.strip(),
                    "status": status,
                }

    def sort_key(item: dict) -> int:
        return int(item["check_id"][1:])

    return sorted(checks_by_id.values(), key=sort_key)


def extract_last_json_object(text: str) -> dict:
    decoder = json.JSONDecoder()
    for idx, ch in enumerate(text):
        if ch != "{":
            continue
        try:
            obj, end = decoder.raw_decode(text[idx:])
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            continue
    raise ValueError("Could not find JSON object in command stdout")


def run_tests(project_root: Path, run_root: Path, latest_root: Path) -> str:
    tests_root = run_root / "tests"
    tests_root.mkdir(parents=True, exist_ok=True)

    items = []
    total_checks = 0
    passed_checks = 0
    failed_checks = 0

    for record_id, name, rel_path in TEST_SPECS:
        started_at = utc_now_iso()
        t0 = time.perf_counter()
        result = run_command([sys.executable, str(project_root / rel_path)], cwd=project_root)
        duration_ms = int(round((time.perf_counter() - t0) * 1000))
        finished_at = utc_now_iso()

        parsed_checks = parse_test_checks(result.stdout)
        status = "PASS" if result.returncode == 0 else "FAIL"

        total_checks += len(parsed_checks)
        passed_checks += sum(1 for c in parsed_checks if c["status"] == "PASS")
        failed_checks += sum(1 for c in parsed_checks if c["status"] != "PASS")

        items.append({
            "record_id": record_id,
            "name": name,
            "file": rel_path.replace("\\", "/"),
            "status": status,
            "exit_code": result.returncode,
            "duration_ms": duration_ms,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "parsed_checks": parsed_checks,
            "started_at_utc": started_at,
            "finished_at_utc": finished_at,
        })

    overall_status = "PASS" if all(item["status"] == "PASS" for item in items) else "FAIL"
    run_id = run_root.name

    test_report = {
        "schema_version": "1.0.0",
        "artifact_type": "test_report",
        "run_id": run_id,
        "timestamp_utc": utc_now_iso(),
        "status": overall_status,
        "total": total_checks,
        "passed": passed_checks,
        "failed": failed_checks,
        "items": items,
    }

    summary = {
        "schema_version": "1.0.0",
        "artifact_type": "test_summary",
        "run_id": run_id,
        "timestamp_utc": test_report["timestamp_utc"],
        "status": overall_status,
        "total": total_checks,
        "passed": passed_checks,
        "failed": failed_checks,
        "items": [
            {
                "record_id": item["record_id"],
                "name": item["name"],
                "file": item["file"],
                "status": item["status"],
                "duration_ms": item["duration_ms"],
                "parsed_checks": item["parsed_checks"],
            }
            for item in items
        ],
    }

    write_json(tests_root / "test_report.json", test_report)
    write_json(tests_root / "summary.json", summary)

    latest_tests = latest_root / "tests"
    latest_tests.mkdir(parents=True, exist_ok=True)
    write_json(latest_tests / "test_report.json", test_report)
    write_json(latest_tests / "summary.json", summary)

    return overall_status


def run_experiments(project_root: Path, run_root: Path, latest_root: Path) -> str:
    experiments_root = run_root / "experiments"
    experiments_root.mkdir(parents=True, exist_ok=True)

    items = []

    for record_id, module_name, source_script in EXPERIMENT_SPECS:
        result = run_command([sys.executable, "-m", module_name], cwd=project_root)
        raw_output = extract_last_json_object(result.stdout)
        status = "PASS" if result.returncode == 0 else "FAIL"

        experiment_output = {
            "schema_version": "1.0.0",
            "artifact_type": "experiment_output",
            "experiment_id": record_id,
            "timestamp_utc": utc_now_iso(),
            "status": status,
            "source_script": source_script.replace("\\", "/"),
            "raw_output": raw_output,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "exit_code": result.returncode,
        }

        out_dir = experiments_root / record_id
        out_dir.mkdir(parents=True, exist_ok=True)
        write_json(out_dir / "experiment_output.json", experiment_output)

        latest_dir = latest_root / "experiments" / record_id
        latest_dir.mkdir(parents=True, exist_ok=True)
        write_json(latest_dir / "experiment_output.json", experiment_output)

        items.append({
            "record_id": record_id,
            "status": status,
            "path": f"artifacts/runs/{run_root.name}/experiments/{record_id}/experiment_output.json",
        })

    passed = sum(1 for item in items if item["status"] == "PASS")
    failed = sum(1 for item in items if item["status"] == "FAIL")
    overall_status = "PASS" if failed == 0 else "FAIL"

    summary = {
        "schema_version": "1.0.0",
        "artifact_type": "experiment_summary",
        "run_id": run_root.name,
        "timestamp_utc": utc_now_iso(),
        "status": overall_status,
        "total": len(items),
        "passed": passed,
        "failed": failed,
        "items": items,
    }

    write_json(experiments_root / "summary.json", summary)

    latest_experiments = latest_root / "experiments"
    latest_experiments.mkdir(parents=True, exist_ok=True)
    write_json(latest_experiments / "summary.json", summary)

    return overall_status


def run_benchmarks(project_root: Path, run_root: Path, latest_root: Path) -> str:
    benchmarks_root = run_root / "benchmarks"
    benchmarks_root.mkdir(parents=True, exist_ok=True)

    result = run_command([sys.executable, str(project_root / "experiments" / "benchmark_suite.py")], cwd=project_root)
    raw_output = load_json(project_root / "experiments" / "benchmark_results.json")
    status = "PASS" if result.returncode == 0 else "FAIL"

    benchmark_report = {
        "schema_version": "1.0.0",
        "artifact_type": "benchmark_report",
        "run_id": run_root.name,
        "timestamp_utc": utc_now_iso(),
        "status": status,
        "source_script": "experiments/benchmark_suite.py",
        "raw_output": raw_output,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "exit_code": result.returncode,
    }

    write_json(benchmarks_root / "benchmark_report.json", benchmark_report)

    items = [
        {
            "record_id": "BENCH-001",
            "name": "sequential_full_pipeline",
            "status": "PASS" if result.returncode == 0 else "FAIL",
            "metric": "rps",
            "value": raw_output["b1_sequential_full_pipeline"]["rps"],
            "path": f"artifacts/runs/{run_root.name}/benchmarks/benchmark_report.json",
        },
        {
            "record_id": "BENCH-002",
            "name": "concurrent_full_pipeline",
            "status": "PASS" if result.returncode == 0 else "FAIL",
            "metric": "rps",
            "value": raw_output["b2_concurrent_full_pipeline"]["rps"],
            "path": f"artifacts/runs/{run_root.name}/benchmarks/benchmark_report.json",
        },
        {
            "record_id": "BENCH-003",
            "name": "security_failure_checks",
            "status": "PASS" if (
                result.returncode == 0
                and raw_output["b3_security_failure_checks"]["replay_second_allowed"] is False
                and raw_output["b3_security_failure_checks"]["tamper_allowed"] is False
            ) else "FAIL",
            "metric": "security_checks",
            "value": "ok" if (
                raw_output["b3_security_failure_checks"]["replay_second_allowed"] is False
                and raw_output["b3_security_failure_checks"]["tamper_allowed"] is False
            ) else "not_ok",
            "path": f"artifacts/runs/{run_root.name}/benchmarks/benchmark_report.json",
        },
    ]

    summary_status = "PASS" if all(item["status"] == "PASS" for item in items) else "FAIL"
    summary = {
        "schema_version": "1.0.0",
        "artifact_type": "benchmark_summary",
        "run_id": run_root.name,
        "timestamp_utc": benchmark_report["timestamp_utc"],
        "status": summary_status,
        "items": items,
    }

    write_json(benchmarks_root / "summary.json", summary)

    latest_benchmarks = latest_root / "benchmarks"
    latest_benchmarks.mkdir(parents=True, exist_ok=True)
    write_json(latest_benchmarks / "benchmark_report.json", benchmark_report)
    write_json(latest_benchmarks / "summary.json", summary)

    return summary_status


def main() -> int:
    project_root = Path(__file__).resolve().parent.parent
    artifacts_root = project_root / "artifacts"
    runs_root = artifacts_root / "runs"
    latest_root = artifacts_root / "latest"

    runs_root.mkdir(parents=True, exist_ok=True)
    latest_root.mkdir(parents=True, exist_ok=True)

    run_id = make_run_id()
    run_root = runs_root / run_id
    run_root.mkdir(parents=True, exist_ok=True)

    print(f"Run ID: {run_id}")

    test_status = run_tests(project_root, run_root, latest_root)
    if test_status != "PASS":
        print("Test stage failed.")
        return 1

    experiment_status = run_experiments(project_root, run_root, latest_root)
    if experiment_status != "PASS":
        print("Experiment stage failed.")
        return 1

    benchmark_status = run_benchmarks(project_root, run_root, latest_root)
    if benchmark_status != "PASS":
        print("Benchmark stage failed.")
        return 1

    evidence_result = run_command([sys.executable, str(project_root / "scripts" / "evidence.py")], cwd=project_root)
    sys.stdout.write(evidence_result.stdout)
    sys.stderr.write(evidence_result.stderr)
    if evidence_result.returncode != 0:
        print("Evidence stage failed.")
        return evidence_result.returncode

    manifest_result = run_command([sys.executable, str(project_root / "scripts" / "build_evidence_manifest.py")], cwd=project_root)
    sys.stdout.write(manifest_result.stdout)
    sys.stderr.write(manifest_result.stderr)
    if manifest_result.returncode != 0:
        print("Manifest stage failed.")
        return manifest_result.returncode

    print("Pipeline completed successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
