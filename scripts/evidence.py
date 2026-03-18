from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from reportlab.lib.pagesizes import LETTER
from reportlab.pdfgen import canvas


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def build_test_evidence(run_id: str, item: dict) -> dict:
    return {
        "schema_version": "1.0.0",
        "artifact_type": "evidence_bundle",
        "category": "test_validation",
        "record_id": item["record_id"],
        "run_id": run_id,
        "timestamp_utc": utc_now_iso(),
        "verification_status": item["status"],
        "details": {
            "name": item["name"],
            "file": item["file"],
            "duration_ms": item["duration_ms"],
        },
    }


def build_experiment_evidence(run_id: str, item: dict, experiment_output: dict) -> dict:
    raw = experiment_output.get("raw_output", {})
    return {
        "schema_version": "1.0.0",
        "artifact_type": "evidence_bundle",
        "category": "experiment_validation",
        "record_id": item["record_id"],
        "run_id": run_id,
        "timestamp_utc": utc_now_iso(),
        "verification_status": item["status"],
        "details": {
            "source_script": experiment_output.get("source_script"),
            "experiment_title": raw.get("title"),
            "authorized": raw.get("authorized"),
            "ticket_jti": raw.get("ticket_jti"),
            "verdict": raw.get("verdict"),
            "raw_output_path": item["path"],
        },
    }


def build_benchmark_evidence(run_id: str, item: dict, benchmark_report: dict) -> dict:
    return {
        "schema_version": "1.0.0",
        "artifact_type": "evidence_bundle",
        "category": "benchmark_validation",
        "record_id": item["record_id"],
        "run_id": run_id,
        "timestamp_utc": utc_now_iso(),
        "verification_status": item["status"],
        "details": {
            "name": item["name"],
            "metric": item["metric"],
            "value": item["value"],
            "source_script": benchmark_report.get("source_script"),
            "benchmark_report_path": item["path"],
        },
    }


def render_pdf(bundle: dict, pdf_path: Path) -> None:
    pdf_path.parent.mkdir(parents=True, exist_ok=True)
    c = canvas.Canvas(str(pdf_path), pagesize=LETTER)
    width, height = LETTER
    y = height - 50

    lines = [
        "LICITRA Evidence Report",
        f"Category: {bundle.get('category')}",
        f"Record ID: {bundle.get('record_id')}",
        f"Run ID: {bundle.get('run_id')}",
        f"Timestamp UTC: {bundle.get('timestamp_utc')}",
        f"Verification Status: {bundle.get('verification_status')}",
        "",
        "Details:",
    ]

    details = bundle.get("details", {})
    for key, value in details.items():
        lines.append(f"{key}: {value}")

    for line in lines:
        c.drawString(50, y, str(line)[:110])
        y -= 16
        if y < 50:
            c.showPage()
            y = height - 50

    c.save()
def main() -> int:
    project_root = Path(__file__).resolve().parent.parent
    artifacts_root = project_root / "artifacts"

    tests_summary_path = artifacts_root / "latest" / "tests" / "summary.json"
    experiments_summary_path = artifacts_root / "latest" / "experiments" / "summary.json"
    benchmarks_summary_path = artifacts_root / "latest" / "benchmarks" / "summary.json"

    if not tests_summary_path.exists():
        raise FileNotFoundError("missing latest test summary")
    if not experiments_summary_path.exists():
        raise FileNotFoundError("missing latest experiment summary")
    if not benchmarks_summary_path.exists():
        raise FileNotFoundError("missing latest benchmark summary")

    tests_summary = load_json(tests_summary_path)
    experiments_summary = load_json(experiments_summary_path)
    benchmarks_summary = load_json(benchmarks_summary_path)

    run_id = tests_summary["run_id"]

    if experiments_summary["run_id"] != run_id or benchmarks_summary["run_id"] != run_id:
        raise ValueError("latest test/experiment/benchmark summaries are not aligned to the same run_id")

    evidence_root = artifacts_root / "runs" / run_id / "evidence"
    latest_evidence_root = artifacts_root / "latest" / "evidence"
    evidence_root.mkdir(parents=True, exist_ok=True)
    latest_evidence_root.mkdir(parents=True, exist_ok=True)

    index_items = []

    for item in tests_summary["items"]:
        record_id = item["record_id"]
        bundle = build_test_evidence(run_id, item)
        out_path = evidence_root / record_id / "evidence.json"
        latest_path = latest_evidence_root / record_id / "evidence.json"
        write_json(out_path, bundle)
        write_json(latest_path, bundle)
        render_pdf(bundle, evidence_root / record_id / 'evidence.pdf')
        render_pdf(bundle, latest_evidence_root / record_id / 'evidence.pdf')
        index_items.append({
            "category": "test_validation",
            "record_id": record_id,
            "verification_status": bundle["verification_status"],
            "path": f"artifacts/runs/{run_id}/evidence/{record_id}/evidence.json",
        })

    for item in experiments_summary["items"]:
        record_id = item["record_id"]
        experiment_output_path = project_root / item["path"]
        experiment_output = load_json(experiment_output_path)
        bundle = build_experiment_evidence(run_id, item, experiment_output)
        out_path = evidence_root / record_id / "evidence.json"
        latest_path = latest_evidence_root / record_id / "evidence.json"
        write_json(out_path, bundle)
        write_json(latest_path, bundle)
        render_pdf(bundle, evidence_root / record_id / 'evidence.pdf')
        render_pdf(bundle, latest_evidence_root / record_id / 'evidence.pdf')
        index_items.append({
            "category": "experiment_validation",
            "record_id": record_id,
            "verification_status": bundle["verification_status"],
            "path": f"artifacts/runs/{run_id}/evidence/{record_id}/evidence.json",
        })

    benchmark_report_path = artifacts_root / "runs" / run_id / "benchmarks" / "benchmark_report.json"
    benchmark_report = load_json(benchmark_report_path)

    for item in benchmarks_summary["items"]:
        record_id = item["record_id"]
        bundle = build_benchmark_evidence(run_id, item, benchmark_report)
        out_path = evidence_root / record_id / "evidence.json"
        latest_path = latest_evidence_root / record_id / "evidence.json"
        write_json(out_path, bundle)
        write_json(latest_path, bundle)
        render_pdf(bundle, evidence_root / record_id / 'evidence.pdf')
        render_pdf(bundle, latest_evidence_root / record_id / 'evidence.pdf')
        index_items.append({
            "category": "benchmark_validation",
            "record_id": record_id,
            "verification_status": bundle["verification_status"],
            "path": f"artifacts/runs/{run_id}/evidence/{record_id}/evidence.json",
        })

    category_order = {
        "test_validation": 0,
        "experiment_validation": 1,
        "benchmark_validation": 2,
    }

    index_items = sorted(index_items, key=lambda x: (category_order[x["category"]], x["record_id"]))

    overall_status = "PASS" if all(item["verification_status"] == "PASS" for item in index_items) else "FAIL"

    index_data = {
        "schema_version": "1.0.0",
        "artifact_type": "evidence_index",
        "run_id": run_id,
        "timestamp_utc": utc_now_iso(),
        "status": overall_status,
        "counts": {
            "tests": len(tests_summary["items"]),
            "experiments": len(experiments_summary["items"]),
            "benchmarks": len(benchmarks_summary["items"]),
            "total": len(index_items),
        },
        "items": index_items,
    }

    write_json(evidence_root / "index.json", index_data)
    write_json(latest_evidence_root / "index.json", index_data)

    print(f"Run ID: {run_id}")
    print(f"Overall Status: {overall_status}")
    print(f"Index: {evidence_root / 'index.json'}")

    return 0 if overall_status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())

