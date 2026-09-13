import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from .policy import canonical_json

class Ledger:
    def __init__(self, path: str | Path, create: bool = True):
        self.path = Path(path)
        if create:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self.previous_hash = "GENESIS"
        if self.path.exists():
            events = self.events()
            self.previous_hash = events[-1]["event_hash"] if events else "GENESIS"
            result = self.verify()
    
    def append(self, event_type: str, payload: dict) -> dict:
        if self.path.exists() and not self.verify()["valid"]:
            raise ValueError("refusing to append to corrupted ledger")
        event = {"ts": datetime.now(timezone.utc).isoformat(), "event_type": event_type, "prev_event_hash": self.previous_hash, "payload": payload}
        event["event_hash"] = "sha256:" + hashlib.sha256(canonical_json(event).encode()).hexdigest()
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(canonical_json(event) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        self.previous_hash = event["event_hash"]
        return event

    def events(self) -> list[dict]:
        if not self.path.exists():
            return []
        result = []
        for number, line in enumerate(self.path.read_text(encoding="utf-8").splitlines(), 1):
            if not line:
                continue
            try:
                result.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid ledger line {number}") from exc
        return result

    def verify(self) -> dict:
        try:
            events = self.events()
        except Exception as exc:
            return {"valid": False, "event_count": 0, "head": "GENESIS", "errors": [str(exc)]}
        previous = "GENESIS"
        errors = []
        for number, event in enumerate(events, 1):
            if not isinstance(event, dict):
                errors.append(f"line {number}: event must be object")
                continue
            if event.get("prev_event_hash") != previous:
                errors.append(f"line {number}: previous hash mismatch")
            claimed = event.get("event_hash")
            body = dict(event)
            body.pop("event_hash", None)
            actual = "sha256:" + hashlib.sha256(canonical_json(body).encode()).hexdigest()
            if not isinstance(claimed, str) or actual != claimed:
                errors.append(f"line {number}: event hash mismatch")
            if number == 1 and event.get("event_type") != "run_started":
                errors.append("first event must be run_started")
            previous = claimed if isinstance(claimed, str) else previous
        return {"valid": not errors, "event_count": len(events), "head": previous, "errors": errors}
