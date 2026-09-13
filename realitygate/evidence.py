import hashlib, json, shutil
from pathlib import Path
from .engine import RealityGate, validate_run_id
from .policy import canonical_json, policy_hash, validate_scenario

def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()

def export_bundle(gate, run_id, policy_path, scenario_path, destination):
    validate_run_id(run_id); gate._load_existing(run_id)
    ledger = gate._path(run_id)
    out = Path(destination)
    if out.exists() and any(out.iterdir()): raise FileExistsError("evidence destination must be empty")
    out.mkdir(parents=True, exist_ok=True)
    for name, src in (("policy.json", Path(policy_path)), ("scenario.json", Path(scenario_path)), ("ledger.jsonl", ledger)):
        if not src.is_file(): raise FileNotFoundError(str(src))
        shutil.copyfile(src, out / name)
    (out / "attestation.json").write_text(json.dumps(gate.attest(run_id), sort_keys=True, indent=2) + "\n", encoding="utf-8")
    files = {name: digest(out / name) for name in ("policy.json", "scenario.json", "ledger.jsonl", "attestation.json")}
    (out / "manifest.json").write_text(json.dumps({"format":"realitygate-evidence-v1","run_id":run_id,"files":files}, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return out

def verify_bundle(destination):
    root = Path(destination); manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    errors=[]
    if manifest.get("format") != "realitygate-evidence-v1": errors.append("unsupported manifest")
    for name, expected in manifest.get("files", {}).items():
        path=root/name
        if not path.is_file(): errors.append("missing " + name)
        elif digest(path) != expected: errors.append("hash mismatch: " + name)
    if errors: return {"valid":False,"errors":errors}
    policy=json.loads((root/"policy.json").read_text()); scenario=json.loads((root/"scenario.json").read_text()); att=json.loads((root/"attestation.json").read_text())
    errors += validate_scenario(scenario)
    if att.get("policy_hash") != policy_hash(policy): errors.append("policy identity mismatch")
    if att.get("run_id") != manifest.get("run_id"): errors.append("run identity mismatch")
    from .ledger import Ledger
    ledger=Ledger(root/"ledger.jsonl", create=False); check=ledger.verify()
    if not check["valid"]: errors += check["errors"]
    if att.get("ledger_head") != check["head"]: errors.append("ledger head mismatch")
    return {"valid":not errors,"run_id":manifest.get("run_id"),"errors":errors}
