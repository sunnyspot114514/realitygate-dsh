import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path("/home/sunny/projects/realitygate-dsh")
ART = ROOT / "artifacts" / "exitcheck"
EV = ROOT / "evidence" / "exitcheck"
shutil.rmtree(ART, ignore_errors=True)
shutil.rmtree(EV, ignore_errors=True)

def run(*args):
    return subprocess.run([sys.executable, "-m", "realitygate.cli", *args],
                          cwd=ROOT, capture_output=True, text=True)

results = {}
r = run("--policy", "policy.json", "--artifacts", str(ART), "run", "scenario.json", "--run-id", "exitcheck")
results["run_kill_exit_5"] = r.returncode == 5
results["run_terminated"] = json.loads(r.stdout)["run"]["status"] == "terminated"

r = run("--policy", "policy.json", "--artifacts", str(ART), "run", "scenario.json", "--run-id", "exitcheck")
results["duplicate_exit_3"] = r.returncode == 3

r = run("--policy", "policy.json", "--artifacts", str(ART), "replay", "nonexistent")
results["missing_replay_exit_3"] = r.returncode == 3

r = run("--policy", "policy.json", "--artifacts", str(ART), "evidence", "export", "exitcheck", "scenario.json", str(EV))
results["export_ok_exit_0"] = r.returncode == 0

r = run("evidence", "verify", str(EV))
results["verify_ok_exit_0"] = r.returncode == 0 and json.loads(r.stdout)["valid"]

ledger = EV / "ledger.jsonl"
backup = ledger.read_text(encoding="utf-8")
ledger.write_text(backup + "tampered\n", encoding="utf-8")
r = run("evidence", "verify", str(EV))
results["tampered_exit_6"] = r.returncode == 6 and not json.loads(r.stdout).get("valid", False)
ledger.write_text(backup, encoding="utf-8")

r = run("--policy", "policy.json", "--artifacts", str(ART), "stop", "exitcheck", "--reason", "final_check")
results["stop_exit_5"] = r.returncode == 5 and json.loads(r.stdout)["status"] == "terminated"

r = run("--policy", "policy.json", "--artifacts", str(ART), "stop", "exitcheck", "--reason", "final_check")
results["stop_idempotent"] = r.returncode == 5 and json.loads(r.stdout).get("already_stopped") is True

print(json.dumps(results, indent=2))
failed = [k for k, v in results.items() if not v]
print("ALL_PASS" if not failed else "FAILED: " + ", ".join(failed))
sys.exit(0 if not failed else 1)
