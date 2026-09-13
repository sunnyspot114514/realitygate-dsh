from dataclasses import dataclass, field
from enum import Enum
from typing import Any

class DecisionKind(str, Enum):
    ALLOW = "ALLOW"
    HOLD = "HOLD"
    KILL = "KILL"

@dataclass(frozen=True)
class Action:
    tool: str
    target: str | None = None
    args: dict[str, Any] = field(default_factory=dict)
    credential_scope: str | None = None
    agent_id: str = "agent-1"
    parent_agent_id: str | None = None
    phase: str = "unknown"
    effect: dict[str, Any] = field(default_factory=dict)
    credential_origin: str | None = None
    expected_postcondition: dict[str, Any] | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Action":
        if not isinstance(data, dict) or not isinstance(data.get("tool"), str) or not data["tool"].strip():
            raise ValueError("action.tool must be a non-empty string")
        if not isinstance(data.get("args", {}), dict):
            raise ValueError("action.args must be an object")
        for key in ("target", "credential_scope", "agent_id", "parent_agent_id", "phase"):
            if data.get(key) is not None and not isinstance(data[key], str):
                raise ValueError(f"action.{key} must be a string")
        effect = data.get("effect", {})
        if not isinstance(effect, dict):
            raise ValueError("action.effect must be an object")
        origin = data.get("credential_origin")
        if origin is not None and not isinstance(origin, str):
            raise ValueError("action.credential_origin must be a string")
        post = data.get("expected_postcondition")
        if post is not None and not isinstance(post, dict):
            raise ValueError("action.expected_postcondition must be an object")
        return cls(data["tool"].strip(), data.get("target"), data.get("args", {}), data.get("credential_scope"), data.get("agent_id", "agent-1"), data.get("parent_agent_id"), data.get("phase", "unknown"), effect, origin, post)

@dataclass(frozen=True)
class Decision:
    kind: DecisionKind
    reason: str
    policy_version: str
    action_id: str
    matched_rule: str = ""

    def to_dict(self):
        return {"kind": self.kind.value, "reason": self.reason, "policy_version": self.policy_version, "action_id": self.action_id, "matched_rule": self.matched_rule}

@dataclass
class RunState:
    run_id: str
    policy_hash: str
    status: str = "active"
    actions: int = 0
    allowed: int = 0
    held: int = 0
    killed: int = 0
    kill_reason: str | None = None
    network_bytes: int = 0
    persistent_writes: int = 0
    capabilities_revoked: int = 0
    started_at: float = 0.0
    write_times: list = field(default_factory=list)

    def to_dict(self):
        return {"run_id": self.run_id, "policy_hash": self.policy_hash, "status": self.status, "actions": self.actions, "allowed": self.allowed, "held": self.held, "killed": self.killed, "kill_reason": self.kill_reason, "network_bytes": self.network_bytes, "persistent_writes": self.persistent_writes, "capabilities_revoked": self.capabilities_revoked}
