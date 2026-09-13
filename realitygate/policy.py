import hashlib
import json
from pathlib import Path
from typing import Any


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def validate_policy(policy: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not isinstance(policy, dict):
        return ["policy must be an object"]
    if not isinstance(policy.get("version"), str) or not policy["version"].strip():
        errors.append("version must be a non-empty string")
    actions = policy.get("actions")
    if not isinstance(actions, dict):
        errors.append("actions must be an object")
    else:
        for key in ("allow_tools", "hold_tools", "kill_tools", "identity_tools"):
            value = actions.get(key, [])
            if not isinstance(value, list) or any(not isinstance(x, str) or not x.strip() for x in value):
                errors.append(f"actions.{key} must be an array of non-empty strings")
        if isinstance(actions.get("allow_tools"), list) and isinstance(actions.get("kill_tools"), list) and set(actions["allow_tools"]) & set(actions["kill_tools"]):
            errors.append("actions allow_tools and kill_tools must not overlap")
    egress = policy.get("egress")
    if not isinstance(egress, dict) or not isinstance(egress.get("allow_targets", []), list):
        errors.append("egress.allow_targets must be an array")
    elif any(not isinstance(x, str) or not x.strip() for x in egress["allow_targets"]):
        errors.append("egress.allow_targets must contain strings")
    if not isinstance(policy.get("credentials"), dict):
        errors.append("credentials must be an object")
    budget = policy.get("budget", {})
    if not isinstance(budget, dict):
        errors.append("budget must be an object")
    else:
        for key in ("max_actions", "max_network_bytes", "max_persistent_writes", "wall_clock_seconds"):
            if key in budget and (not isinstance(budget[key], int) or budget[key] <= 0):
                errors.append(f"budget.{key} must be a positive integer")
        if "heartbeat" in budget:
            hb = budget["heartbeat"]
            if not isinstance(hb, dict):
                errors.append("budget.heartbeat must be an object")
            else:
                for key in ("window_seconds", "min_events"):
                    if key in hb and (not isinstance(hb[key], int) or hb[key] <= 0):
                        errors.append(f"budget.heartbeat.{key} must be a positive integer")
                if "max_interval_variance" in hb and (not isinstance(hb["max_interval_variance"], (int, float)) or hb["max_interval_variance"] < 0):
                    errors.append("budget.heartbeat.max_interval_variance must be a non-negative number")
                if "decision" in hb and str(hb["decision"]).upper() not in {"HOLD", "KILL"}:
                    errors.append("budget.heartbeat.decision must be HOLD or KILL")
    origins = policy.get("credential_origins", [])
    if not isinstance(origins, list) or any(x not in {"user_provided", "service_managed", "ephemeral_runtime", "publicly_discovered", "unknown"} for x in origins):
        errors.append("credential_origins contains an invalid origin")
    return errors


def validate_scenario(scenario: Any) -> list[str]:
    if not isinstance(scenario, dict) or not isinstance(scenario.get("actions"), list) or not scenario["actions"]:
        return ["scenario.actions must be a non-empty array"]
    errors = []
    from .models import Action
    for i, value in enumerate(scenario["actions"]):
        try:
            Action.from_dict(value)
        except Exception as exc:
            errors.append(f"actions[{i}]: {exc}")
    return errors


def load_policy(path: str | Path) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("policy must be a mapping")
    return data


def policy_hash(policy: dict[str, Any]) -> str:
    payload = json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(payload).hexdigest()
