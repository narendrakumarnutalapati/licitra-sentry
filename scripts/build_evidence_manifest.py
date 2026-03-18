from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def main() -> int:
    project_root = Path(__file__).resolve().parent.parent
    artifacts_root = project_root / "artifacts"
    latest_root = artifacts_root / "latest"

    tests_summary_path = latest_root / "tests" / "summary.json"
    experiments_summary_path = latest_root / "experiments" / "summary.json"
    benchmarks_summary_path = latest_root / "benchmarks" / "summary.json"
    evidence_index_path = latest_root / "evidence" / "index.json"

    if not tests_summary_path.exists():
        raise FileNotFoundError("missing latest test summary")
    if not experiments_summary_path.exists():
        raise FileNotFoundError("missing latest experiment summary")
    if not benchmarks_summary_path.exists():
        raise FileNotFoundError("missing latest benchmark summary")
    if not evidence_index_path.exists():
        raise FileNotFoundError("missing latest evidence index")

    tests_summary = load_json(tests_summary_path)
    experiments_summary = load_json(experiments_summary_path)
    benchmarks_summary = load_json(benchmarks_summary_path)
    evidence_index = load_json(evidence_index_path)

    run_id = tests_summary["run_id"]

    if experiments_summary["run_id"] != run_id or benchmarks_summary["run_id"] != run_id:
        raise ValueError("latest test/experiment/benchmark summaries are not aligned to the same run_id")

    if evidence_index["run_id"] != run_id:
        raise ValueError("latest evidence index is not aligned to the same run_id")

    run_root = artifacts_root / "runs" / run_id

    test_records = tests_summary["items"]
    experiment_records = experiments_summary["items"]
    benchmark_records = benchmarks_summary["items"]

    evidence_items = evidence_index["items"]
    evidence_by_record_id = {item["record_id"]: item for item in evidence_items}

    def build_test_entry(item: dict) -> dict:
        record_id = item["record_id"]
        ev = evidence_by_record_id[record_id]
        evidence_json = f"artifacts/runs/{run_id}/evidence/{record_id}/evidence.json"
        evidence_pdf = f"artifacts/runs/{run_id}/evidence/{record_id}/evidence.pdf"
        bundle = load_json(project_root / evidence_json)

        return {
            "record_id": record_id,
            "verification_status": ev["verification_status"],
            "evidence_json": evidence_json,
            "evidence_pdf": evidence_pdf,
            "timestamp_utc": bundle["timestamp_utc"],
            "details": {
                "name": item["name"],
                "file": item["file"],
                "duration_ms": item["duration_ms"],
                "parsed_checks": item.get("parsed_checks", []),
            },
        }

    def build_experiment_entry(item: dict) -> dict:
        record_id = item["record_id"]
        ev = evidence_by_record_id[record_id]
        evidence_json = f"artifacts/runs/{run_id}/evidence/{record_id}/evidence.json"
        evidence_pdf = f"artifacts/runs/{run_id}/evidence/{record_id}/evidence.pdf"
        bundle = load_json(project_root / evidence_json)
        raw = bundle.get("details", {})

        return {
            "record_id": record_id,
            "verification_status": ev["verification_status"],
            "evidence_json": evidence_json,
            "evidence_pdf": evidence_pdf,
            "timestamp_utc": bundle["timestamp_utc"],
            "details": {
                "source_script": raw.get("source_script"),
                "experiment_title": raw.get("experiment_title"),
                "authorized": raw.get("authorized"),
                "ticket_jti": raw.get("ticket_jti"),
                "allowed": raw.get("allowed"),
                "error": raw.get("error"),
                "verdict": raw.get("verdict"),
                "authorized_payload": raw.get("authorized_payload"),
                "tampered_payload": raw.get("tampered_payload"),
                "raw_output_path": raw.get("raw_output_path"),
            },
        }

    def build_benchmark_entry(item: dict) -> dict:
        record_id = item["record_id"]
        ev = evidence_by_record_id[record_id]
        evidence_json = f"artifacts/runs/{run_id}/evidence/{record_id}/evidence.json"
        evidence_pdf = f"artifacts/runs/{run_id}/evidence/{record_id}/evidence.pdf"
        bundle = load_json(project_root / evidence_json)
        raw = bundle.get("details", {})

        return {
            "record_id": record_id,
            "verification_status": ev["verification_status"],
            "evidence_json": evidence_json,
            "evidence_pdf": evidence_pdf,
            "timestamp_utc": bundle["timestamp_utc"],
            "details": {
                "name": raw.get("name"),
                "metric": raw.get("metric"),
                "value": raw.get("value"),
                "source_script": raw.get("source_script"),
                "benchmark_report_path": raw.get("benchmark_report_path"),
            },
        }

    categories = {
        "test_validation": [build_test_entry(item) for item in test_records],
        "experiment_validation": [build_experiment_entry(item) for item in experiment_records],
        "benchmark_validation": [build_benchmark_entry(item) for item in benchmark_records],
    }

    total_test_checks = sum(len(item.get("parsed_checks", [])) for item in test_records)
    total_records = len(test_records) + len(experiment_records) + len(benchmark_records)
    total_validated_checks = total_test_checks + len(experiment_records) + len(benchmark_records)

    overall_status = "PASS"
    for category_items in categories.values():
        if any(item["verification_status"] != "PASS" for item in category_items):
            overall_status = "FAIL"
            break

    manifest = {
        "schema_version": "1.0.0",
        "artifact_type": "evidence_manifest",
        "run_id": run_id,
        "timestamp_utc": utc_now_iso(),
        "status": overall_status,
        "counts": {
            "test_records": len(test_records),
            "test_checks": total_test_checks,
            "experiments": len(experiment_records),
            "benchmarks": len(benchmark_records),
            "total_records": total_records,
            "total_validated_checks": total_validated_checks,
        },
        "index_path": f"artifacts/runs/{run_id}/evidence/index.json",
        "latest_index_path": "artifacts/latest/evidence/index.json",
        "categories": categories,
    }

    write_json(run_root / "evidence_manifest.json", manifest)
    write_json(latest_root / "evidence_manifest.json", manifest)

    print(f"Run ID: {run_id}")
    print(f"Status: {overall_status}")
    print(f"Manifest: {run_root / 'evidence_manifest.json'}")
    return 0 if overall_status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
