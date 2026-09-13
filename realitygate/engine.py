import hashlib
import json
import re
import time
import uuid
from pathlib import Path
from typing import Any
from .ledger import Ledger
from .models import Action, Decision, DecisionKind, RunState
from .policy import canonical_json, policy_hash

_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")

def validate_run_id(value: str) -> str:
    if not isinstance(value, str) or not _RUN_ID.fullmatch(value):
        raise ValueError("invalid run_id")
    return value

class RealityGate:
    EGRESS_TOOLS = {"http_get", "http_post", "dns_lookup", "tcp_connect", "web_fetch"}

    def __init__(self, policy: dict[str, Any], artifact_dir: str | Path = "artifacts/runs"):
        self.policy = policy
        self.policy_hash = policy_hash(policy)
        self.artifact_dir = Path(artifact_dir)
        self.runs: dict[str, RunState] = {}
        self.ledgers: dict[str, Ledger] = {}
        self.pending: dict[str, dict[str, Decision]] = {}
        self.capabilities: dict[str, dict[str, Any]] = {}
        self._capability_key = hashlib.sha256((self.policy_hash + "::realitygate-local").encode()).digest()

    def _path(self, run_id: str) -> Path:
        validate_run_id(run_id)
        root = self.artifact_dir.resolve()
        path = (root / (run_id + ".jsonl")).resolve()
        if path.parent != root:
            raise ValueError("run path escapes artifact directory")
        return path

    def start_run(self, run_id: str | None = None) -> RunState:
        run_id = run_id or "run-" + uuid.uuid4().hex[:12]
        path = self._path(run_id)
        if path.exists():
            raise ValueError("run already exists")
        state = RunState(run_id, self.policy_hash)
        state.started_at = time.time()
        self.runs[run_id] = state
        self.ledgers[run_id] = Ledger(path)
        self.pending[run_id] = {}
        self.ledgers[run_id].append("run_started", {"run_id": run_id, "policy_hash": self.policy_hash, "policy_version": self.policy.get("version")})
        return state

    def _load_existing(self, run_id: str) -> Ledger:
        path = self._path(run_id)
        if not path.is_file():
            raise FileNotFoundError(f"run not found: {run_id}")
        ledger = Ledger(path, create=False)
        events = ledger.events()
        if not events or events[0].get("event_type") != "run_started":
            raise ValueError("missing run_started")
        payload = events[0].get("payload", {})
        if payload.get("run_id") != run_id:
            raise ValueError("run identity mismatch")
        if payload.get("policy_hash") != self.policy_hash:
            raise ValueError("policy hash mismatch")
        self.ledgers[run_id] = ledger
        return ledger

    def _decision(self, state: RunState, action: Action, kind: DecisionKind, reason: str, rule: str) -> Decision:
        if kind is DecisionKind.ALLOW: state.allowed += 1
        elif kind is DecisionKind.HOLD: state.held += 1
        else: state.killed += 1
        state.actions += 1
        aid = uuid.uuid4().hex
        decision = Decision(kind, reason, str(self.policy.get("version")), aid, rule)
        payload = {"run_id": state.run_id, "action_id": aid, "tool": action.tool, "target": action.target, "args_sha256": "sha256:" + hashlib.sha256(canonical_json(action.args).encode()).hexdigest(), "credential_scope": action.credential_scope, "agent_id": action.agent_id, "parent_agent_id": action.parent_agent_id, "phase": action.phase, "effect": action.effect, "decision": kind.value, "reason": reason, "matched_rule": rule}
        self.ledgers[state.run_id].append("action_decision", payload)
        if kind is DecisionKind.ALLOW:
            self.pending[state.run_id][aid] = decision
            try:
                from .capability import issue
                effect = action.effect or {"external_effect": action.tool in self.EGRESS_TOOLS, "persistence": False}
                cap = issue(run_id=state.run_id, agent_id=action.agent_id, tool=action.tool, target=action.target, args=action.args, effect=effect, policy_hash=self.policy_hash, audience=action.agent_id, key=self._capability_key)
                self.capabilities.setdefault(state.run_id, {})[aid] = cap
                self.ledgers[state.run_id].append("capability_issued", {"run_id": state.run_id, "action_id": aid, "token_id": cap.token_id, "audience": cap.audience, "expires_at": cap.expires_at, "max_uses": cap.max_uses, "args_sha256": cap.args_sha256, "effect_sha256": cap.effect_sha256})
            except Exception:
                self.pending[state.run_id].pop(aid, None)
                raise
        return decision

    def authorize(self, state: RunState, action: Action | dict[str, Any]) -> Decision:
        if isinstance(action, dict):
            action = Action.from_dict(action)
        if state.status != "active":
            return self._decision(state, action, DecisionKind.KILL, "run_already_terminated", "run_terminal")
        budget = self.policy.get("budget", {})
        if isinstance(budget.get("max_actions"), int) and state.actions >= budget["max_actions"]:
            return self.kill(state, action, "budget_exceeded:max_actions")
        if isinstance(budget.get("wall_clock_seconds"), int) and time.time() - state.started_at > budget["wall_clock_seconds"]:
            return self.kill(state, action, "budget_exceeded:wall_clock")
        requested_bytes = action.args.get("bytes", 0) if isinstance(action.args.get("bytes", 0), int) else 0
        if action.tool in self.EGRESS_TOOLS and isinstance(budget.get("max_network_bytes"), int) and state.network_bytes + requested_bytes > budget["max_network_bytes"]:
            return self.kill(state, action, "budget_exceeded:network_bytes")
        if action.effect.get("persistence") and isinstance(budget.get("max_persistent_writes"), int) and state.persistent_writes >= budget["max_persistent_writes"]:
            return self.kill(state, action, "budget_exceeded:persistent_writes")
        actions = self.policy["actions"]
        if action.tool in set(actions.get("kill_tools", [])):
            return self.kill(state, action, "policy_kill_tool")
        if action.tool in set(self.policy.get("sensitive_tools", [])):
            return self.kill(state, action, "sensitive_action")
        if action.tool in set(actions.get("identity_tools", [])) or action.effect.get("identity_effect"):
            return self.kill(state, action, "identity_creation_denied")
        valid_origins = {"user_provided", "service_managed", "ephemeral_runtime"}
        if action.credential_origin not in (None, *valid_origins):
            return self.kill(state, action, "credential_provenance_denied")
        if action.credential_scope not in (None, "canary", "production"):
            return self.kill(state, action, "unknown_credential_scope")
        if action.credential_scope == "production":
            return self.kill(state, action, "production_credential_denied")
        if action.credential_scope == "canary" and action.target not in self.policy["credentials"].get("canary", {}).get("allowed_targets", []):
            return self.kill(state, action, "credential_scope_violation")
        if action.tool in self.EGRESS_TOOLS and action.target not in self.policy["egress"].get("allow_targets", []):
            mode = str(self.policy["egress"].get("unknown_decision", "HOLD")).upper()
            if mode == "KILL" or action.tool in set(self.policy["egress"].get("kill_tools", [])):
                return self.kill(state, action, "unknown_egress")
            return self._decision(state, action, DecisionKind.HOLD, "unknown_egress", "egress_default")
        if action.tool in {"http_get", "web_fetch"}:
            # Read-safety is decided by policy (read_only_targets), not by the
            # caller-declared effect: a declared effect can only escalate.
            read_safe = set(self.policy["egress"].get("read_only_targets", []))
            if action.effect.get("external_effect") or action.target not in read_safe:
                return self._decision(state, action, DecisionKind.HOLD, "effecting_read_requires_capability", "effect_descriptor")
        if action.tool in set(actions.get("hold_tools", [])):
            return self._decision(state, action, DecisionKind.HOLD, "requires_review", "policy_hold_tool")
        if action.tool in set(actions.get("allow_tools", [])):
            fixture_root = self.policy.get("fixture_root")
            if fixture_root and action.tool == "read_file" and action.target and (action.target.startswith("/") or ".." in Path(action.target).parts):
                return self.kill(state, action, "path_outside_fixture")
            if action.effect.get("persistence"):
                verdict = self._heartbeat_verdict(state, budget)
                if verdict == "KILL":
                    return self.kill(state, action, "heartbeat_suspected")
                if verdict:
                    return self._decision(state, action, DecisionKind.HOLD, "heartbeat_suspected", "heartbeat_detector")
            return self._decision(state, action, DecisionKind.ALLOW, "policy_allow", "policy_allow_tool")
        return self._decision(state, action, DecisionKind.HOLD, "unknown_action_requires_review", "default_hold")

    def _heartbeat_verdict(self, state: RunState, budget: dict[str, Any]) -> str | None:
        """Slow-beat detector: regular low-frequency persistent writes that a
        plain max_actions budget cannot catch (collusion.wiki beacon pattern)."""
        hb = budget.get("heartbeat")
        if not isinstance(hb, dict):
            return None
        min_events = int(hb.get("min_events", 3))
        variance = float(hb.get("max_interval_variance", 5.0))
        times = state.write_times[-min_events:]
        if len(times) < min_events:
            return None
        intervals = [b - a for a, b in zip(times, times[1:])]
        if intervals and (max(intervals) - min(intervals)) <= variance:
            return str(hb.get("decision", "HOLD")).upper()
        return None

    def kill(self, state: RunState, action: Action, reason: str) -> Decision:
        if state.status == "terminated":
            return self._decision(state, action, DecisionKind.KILL, "run_already_terminated", "run_terminal")
        decision = self._decision(state, action, DecisionKind.KILL, reason, "termination")
        state.status = "terminated"
        state.kill_reason = reason
        revoked = len(self.pending.get(state.run_id, {}))
        self.pending.get(state.run_id, {}).clear()
        self.capabilities.get(state.run_id, {}).clear()
        state.capabilities_revoked += revoked
        self.ledgers[state.run_id].append("run_killed", {"run_id": state.run_id, "reason": reason, "action_id": decision.action_id, "revoked_capabilities": revoked, "response": "local-response-sink"})
        return decision

    def stop_run(self, state: RunState, reason: str = "external_stop") -> None:
        if state.status == "terminated":
            return
        action = Action("runtime.stop", target=state.run_id, phase="emergency")
        self.kill(state, action, reason)

    def stop_run_persisted(self, run_id: str, reason: str = "external_stop") -> dict[str, Any]:
        """Externally stop a run from a fresh process by appending a kill event
        to its verified ledger. Refuses to stop an already-terminated run twice."""
        replay = self.replay(run_id)
        if replay["status"] == "terminated":
            return {"run_id": run_id, "status": "terminated", "already_stopped": True}
        if not replay["ledger"]["valid"]:
            raise ValueError("refusing to stop a run with a corrupted ledger")
        pending_before = len(self.pending.get(run_id, {}))
        self.ledgers[run_id].append("run_killed", {"run_id": run_id, "reason": reason, "action_id": None, "revoked_capabilities": pending_before, "source": "external_stop", "response": "local-response-sink"})
        return {"run_id": run_id, "status": "terminated", "already_stopped": False, "revoked_capabilities": pending_before}

    def record_result(self, state: RunState, action_id: str, result: dict[str, Any]) -> None:
        if state.status != "active":
            raise ValueError("cannot record result after run termination")
        if action_id not in self.pending.get(state.run_id, {}):
            raise ValueError("result is not linked to a pending ALLOW action")
        if not isinstance(result, dict) or not isinstance(result.get("ok"), bool):
            raise ValueError("result.ok must be boolean")
        cap = self.capabilities.get(state.run_id, {}).get(action_id)
        if cap is None:
            raise ValueError("no capability issued for this action")
        cap.consume(self._capability_key)
        self.capabilities[state.run_id].pop(action_id)
        self.pending[state.run_id].pop(action_id)
        decision = next((d for d in self.ledgers[state.run_id].events() if d.get("event_type") == "action_decision" and d.get("payload", {}).get("action_id") == action_id), None)
        action_result_bytes = result.get("bytes", 0) if isinstance(result.get("bytes", 0), int) else 0
        if decision:
            payload = decision["payload"]
            if payload.get("tool") in self.EGRESS_TOOLS:
                state.network_bytes += int(action_result_bytes or 0)
            if payload.get("effect", {}).get("persistence"):
                state.persistent_writes += 1
                state.write_times.append(time.time())
        self.ledgers[state.run_id].append("action_result", {"run_id": state.run_id, "action_id": action_id, "ok": result["ok"], "status": result.get("status"), "result_sha256": "sha256:" + hashlib.sha256(canonical_json(result).encode()).hexdigest()})

    def replay(self, run_id: str) -> dict[str, Any]:
        ledger = self._load_existing(run_id)
        verification = ledger.verify()
        events = ledger.events()
        started = events[0]["payload"]
        status, reason, decisions = "active", None, []
        for event in events:
            if event.get("event_type") == "action_decision": decisions.append(event["payload"])
            if event.get("event_type") == "run_killed": status, reason = "terminated", event["payload"].get("reason")
        return {"run_id": run_id, "policy_hash": started.get("policy_hash"), "policy_version": started.get("policy_version"), "ledger": verification, "status": status, "kill_reason": reason, "decisions": decisions}

    def attest(self, state_or_run: RunState | str) -> dict[str, Any]:
        run_id = state_or_run.run_id if isinstance(state_or_run, RunState) else validate_run_id(state_or_run)
        replay = self.replay(run_id)
        ledger = replay["ledger"]
        att = {"format": "realitygate-attestation-v0.1", "run_id": run_id, "policy_hash": replay["policy_hash"], "policy_version": replay["policy_version"], "ledger_head": ledger["head"], "ledger_valid": ledger["valid"], "event_count": ledger["event_count"], "status": replay["status"], "kill_reason": replay["kill_reason"], "not_claimed": ["host/kernel escape resistance", "unobserved side effects outside the adapter"]}
        return att
