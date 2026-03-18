"""
LICITRA-SENTRY - Run All Experiments (mode-aware)

Usage:
    python -m experiments.run_all_experiments
"""

import json
import subprocess
import sys

from experiments._common import PreflightError, get_mmr_health

DEFAULT_SAFE = [
    ("EXP-01", "experiments.run_exp01_happy_path"),
    ("EXP-02", "experiments.run_exp02_contract_rejection"),
    ("EXP-03", "experiments.run_exp03_identity_expiry"),
    ("EXP-04", "experiments.run_exp04_relay_injection"),
    ("EXP-05", "experiments.run_exp05_pii_exfiltration"),
    ("EXP-06", "experiments.run_exp06_unauthorized_delegation"),
    ("EXP-08", "experiments.run_exp08_ticket_replay"),
    ("EXP-09", "experiments.run_exp09_payload_tampering"),
]

EXPERIMENT_MODE_ONLY = [
    ("EXP-07", "experiments.run_exp07_e2e_mmr_proof"),
    ("EXP-10", "experiments.run_exp10_audit_tampering"),
]

ORDERED_EXPERIMENT_IDS = [
    "EXP-01",
    "EXP-02",
    "EXP-03",
    "EXP-04",
    "EXP-05",
    "EXP-06",
    "EXP-07",
    "EXP-08",
    "EXP-09",
    "EXP-10",
]


def run_module(module_name: str) -> int:
    return subprocess.call([sys.executable, "-m", module_name])


def main() -> None:
    print("\n" + "=" * 72)
    print("  LICITRA-SENTRY - Run All Experiments (Mode Aware)")
    print("=" * 72)

    try:
        mmr_health = get_mmr_health()
        print("[PRECHECK] MMR health:")
        print(json.dumps(mmr_health, indent=2))
    except PreflightError as exc:
        print(f"[PRECHECK FAILED] {exc}")
        sys.exit(1)

    block_size = mmr_health["block_size"]
    ledger_mode = mmr_health.get("ledger_mode")
    dev_mode = mmr_health.get("dev_mode")

    print("\n[MODE]")
    print(f"  block_size  : {block_size}")
    print(f"  ledger_mode : {ledger_mode}")
    print(f"  dev_mode    : {dev_mode}")

    results = {}

    print("\n" + "-" * 72)
    print("  DEFAULT-SAFE EXPERIMENTS")
    print("-" * 72)
    for exp_id, module_name in DEFAULT_SAFE:
        print(f"\n  Running {exp_id} ({module_name})...")
        rc = run_module(module_name)
        results[exp_id] = "PASS" if rc == 0 else "FAIL"

    if block_size == 2:
        print("\n" + "-" * 72)
        print("  EXPERIMENT-MODE-ONLY EXPERIMENTS")
        print("-" * 72)
        for exp_id, module_name in EXPERIMENT_MODE_ONLY:
            print(f"\n  Running {exp_id} ({module_name})...")
            rc = run_module(module_name)
            results[exp_id] = "PASS" if rc == 0 else "FAIL"
    else:
        print("\n" + "-" * 72)
        print("  SKIPPED EXPERIMENT-MODE-ONLY EXPERIMENTS")
        print("-" * 72)
        for exp_id, _module_name in EXPERIMENT_MODE_ONLY:
            print(
                f"  {exp_id}: SKIPPED "
                f"(requires BLOCK_SIZE=2, current BLOCK_SIZE={block_size})"
            )
            results[exp_id] = "SKIPPED"

    pass_count = sum(1 for v in results.values() if v == "PASS")
    fail_count = sum(1 for v in results.values() if v == "FAIL")
    skipped_count = sum(1 for v in results.values() if v == "SKIPPED")

    print("\n" + "=" * 72)
    print("  EXPERIMENT RESULTS")
    print("=" * 72)
    for exp_id in ORDERED_EXPERIMENT_IDS:
        print(f"  {exp_id}: {results.get(exp_id, 'NOT_RUN')}")
    print("=" * 72)

    print("\n  SUMMARY")
    print(f"  PASS    : {pass_count}")
    print(f"  FAIL    : {fail_count}")
    print(f"  SKIPPED : {skipped_count}")

    if fail_count > 0:
        failed = [exp_id for exp_id in ORDERED_EXPERIMENT_IDS if results.get(exp_id) == "FAIL"]
        print(f"\n  FAILURES: {', '.join(failed)}")
        sys.exit(1)

    print("\n  Run completed without invalid mode mixing.")
    sys.exit(0)


if __name__ == "__main__":
    main()
