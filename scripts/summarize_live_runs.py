import json
from pathlib import Path

root = Path("/home/sunny/projects/realitygate-dsh/artifacts/live-run")
for path in sorted(root.glob("*.jsonl")):
    print(f"--- {path.name} ---")
    events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    for event in events:
        et = event.get("event_type")
        p = event.get("payload", {})
        if et == "run_started":
            print("run_started", p.get("run_id"))
        elif et == "action_decision":
            print("decision", p.get("tool"), p.get("target"), "->", p.get("decision"), f"({p.get('reason')})")
        elif et == "action_result":
            print("executed", p.get("action_id", "")[:8], "ok=", p.get("ok"))
        elif et == "capability_issued":
            print("capability", p.get("token_id", "")[:8], "audience", p.get("audience"))
        elif et == "run_killed":
            print("KILLED", p.get("reason"))
