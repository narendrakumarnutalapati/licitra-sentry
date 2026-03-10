"""
LICITRA-SENTRY - Run All 10 Experiments
Requires LICITRA-MMR at http://localhost:8000

Usage:
    cd licitra-sentry
    python experiments/run_all_experiments.py
"""
import subprocess
import sys
import os

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(project_root)
os.environ["PYTHONPATH"] = project_root

experiments = [
    ("EXP-01", "experiments/run_exp01_happy_path.py"),
    ("EXP-02", "experiments/run_exp02_contract_rejection.py"),
    ("EXP-03", "experiments/run_exp03_identity_expiry.py"),
    ("EXP-04", "experiments/run_exp04_relay_injection.py"),
    ("EXP-05", "experiments/run_exp05_pii_exfiltration.py"),
    ("EXP-06", "experiments/run_exp06_unauthorized_delegation.py"),
    ("EXP-07", "experiments/run_exp07_e2e_mmr_proof.py"),
    ("EXP-08", "experiments/run_exp08_ticket_replay.py"),
    ("EXP-09", "experiments/run_exp09_payload_tampering.py"),
    ("EXP-10", "experiments/run_exp10_audit_tampering.py"),
]

print("\n" + "=" * 60)
print("  LICITRA-SENTRY - Run All Experiments")
print("=" * 60)

results = {}
for exp_id, script in experiments:
    print(f"\n  Running {exp_id}...")
    env = os.environ.copy()
    env["PYTHONPATH"] = project_root
    rc = subprocess.call([sys.executable, script], env=env)
    results[exp_id] = "PASS" if rc == 0 else "FAIL"

print("\n" + "=" * 60)
print("  EXPERIMENT RESULTS")
print("=" * 60)
for exp_id, status in results.items():
    print(f"  {exp_id}: {status}")
print("=" * 60)

all_pass = all(v == "PASS" for v in results.values())
print(f"\n  {'ALL 10/10 EXPERIMENTS PASSED' if all_pass else 'SOME EXPERIMENTS FAILED'}")
sys.exit(0 if all_pass else 1)
