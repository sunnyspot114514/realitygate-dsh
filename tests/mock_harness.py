"""Offline scenario harness used by compatibility tests."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any
from realitygate.models import Action
from tests.compat import authorize

@dataclass
class HarnessResult:
    run_id: str
    decisions: list[Any]
    state: Any

class MockHarness:
    """Drive RealityGate with deterministic, local action scenarios."""
    def __init__(self, gate: Any):
        self.gate = gate

    def run(self, scenario: Any, mode: str = "normal", run_id: str | None = None) -> HarnessResult:
        state = self.gate.start_run(run_id=run_id)
        if callable(scenario):
            produced = scenario(self, state)
        elif isinstance(scenario, dict):
            produced = scenario.get("actions", [])
        else:
            produced = scenario
        decisions = []
        for item in produced or []:
            action = item if isinstance(item, Action) else Action(**item)
            decisions.append(authorize(self.gate, state, action))
            if getattr(state, "status", None) == "terminated":
                break
        if mode == "terminate" and getattr(state, "status", None) == "active":
            raise AssertionError("terminate mode did not terminate the run")
        return HarnessResult(state.run_id, decisions, state)
