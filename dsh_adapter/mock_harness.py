from pathlib import Path
from typing import Any
import json
from realitygate.engine import RealityGate
from realitygate.models import Action, DecisionKind

class MockHarness:
    """DSH-shaped adapter: only ALLOW decisions reach the mock executor."""
    def __init__(self, gate: RealityGate, executor=None):
        self.gate = gate
        self.executor = executor or (lambda action: {"ok": True, "status": 200, "mocked": True})

    def execute(self, state, action: Action | dict[str, Any]) -> dict[str, Any]:
        action = Action.from_dict(action) if isinstance(action, dict) else action
        decision = self.gate.authorize(state, action)
        if decision.kind is not DecisionKind.ALLOW:
            return {"decision": decision.to_dict(), "executed": False}
        result = self.executor(action)
        self.gate.record_result(state, decision.action_id, result)
        return {"decision": decision.to_dict(), "result": result, "executed": True}

    def run(self, scenario, mode="enforced", run_id=None):
        if isinstance(scenario, (str, Path)):
            data = json.loads(Path(scenario).read_text(encoding="utf-8"))
            actions = data["actions"]
        elif isinstance(scenario, dict):
            actions = scenario["actions"]
        else:
            actions = scenario
        state = self.gate.start_run(run_id)
        results = []
        for action in actions:
            result = self.execute(state, action)
            results.append(result)
            if state.status == "terminated":
                break
        return state, results
