from __future__ import annotations
from pathlib import Path
import hashlib
import json
import tempfile
import unittest
from realitygate.models import Action, DecisionKind
from realitygate.policy import policy_hash
from tests.compat import attest, authorize, decision_kind, replay
from tests.mock_harness import MockHarness
try:
    from realitygate.engine import RealityGate
    ENGINE_IMPORT_ERROR = None
except Exception as exc:
    RealityGate = None
    ENGINE_IMPORT_ERROR = exc

POLICY = {
    "version": "test-v1",
    "actions": {"allow_tools": ["read_file"], "hold_tools": ["shell"], "kill_tools": ["delete_all"]},
    "egress": {"allow_targets": ["https://canary.invalid"]},
    "credentials": {"canary": {"allowed_targets": ["canary-service"]}},
}

class RealityGateTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        if RealityGate is None:
            self.skipTest(f"RealityGate import unavailable: {ENGINE_IMPORT_ERROR}")
        self.gate = RealityGate(POLICY, self.tempdir.name)
        self.state = self.gate.start_run("test-run")

    def tearDown(self):
        self.tempdir.cleanup()

    def test_policy_integrity_is_stable_and_bound_to_run(self):
        self.assertEqual(policy_hash(POLICY), policy_hash(json.loads(json.dumps(POLICY))))
        self.assertEqual(self.state.policy_hash, policy_hash(POLICY))
        event = self.gate.ledgers[self.state.run_id].events()[0]
        self.assertEqual(event["event_type"], "run_started")
        self.assertEqual(event["payload"]["policy_hash"], policy_hash(POLICY))

    def test_allow_hold_and_kill_decisions(self):
        allow = authorize(self.gate, self.state, Action("read_file", target="/tmp/input"))
        hold = authorize(self.gate, self.state, Action("shell", args={"cmd": "id"}))
        kill = authorize(self.gate, self.state, Action("delete_all", target="/tmp"))
        self.assertEqual(decision_kind(allow), DecisionKind.ALLOW.value)
        self.assertEqual(decision_kind(hold), DecisionKind.HOLD.value)
        self.assertEqual(decision_kind(kill), DecisionKind.KILL.value)
        self.assertEqual(self.state.status, "terminated")

    def test_kill_blocks_follow_up_action(self):
        first = authorize(self.gate, self.state, Action("delete_all"))
        second = authorize(self.gate, self.state, Action("read_file"))
        self.assertEqual(decision_kind(first), DecisionKind.KILL.value)
        self.assertEqual(decision_kind(second), DecisionKind.KILL.value)
        self.assertEqual(getattr(second, "reason", None), "run_already_terminated")

    def test_hash_chain_and_replay(self):
        decision = authorize(self.gate, self.state, Action("read_file"))
        self.gate.record_result(self.state, decision.action_id, {"ok": True, "status": 200})
        events = self.gate.ledgers[self.state.run_id].events()
        previous = "GENESIS"
        for event in events:
            self.assertEqual(event["prev_event_hash"], previous)
            claimed = event["event_hash"]
            copy = dict(event)
            copy.pop("event_hash")
            expected = "sha256:" + hashlib.sha256(json.dumps(copy, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            self.assertEqual(claimed, expected)
            previous = claimed
        report = replay(self.gate, self.state.run_id)
        ledger_report = report.get("ledger", report)
        self.assertTrue(ledger_report.get("valid", ledger_report.get("chain_ok", False)))
        self.assertEqual(ledger_report.get("event_count"), len(events))

    def test_replay_detects_tampering(self):
        authorize(self.gate, self.state, Action("read_file"))
        path = Path(self.tempdir.name) / "test-run.jsonl"
        lines = path.read_text(encoding="utf-8").splitlines()
        event = json.loads(lines[1])
        event["payload"]["reason"] = "tampered"
        lines[1] = json.dumps(event, sort_keys=True)
        path.write_text(chr(10).join(lines) + chr(10), encoding=chr(34)+chr(117)+chr(116)+chr(102)+chr(45)+chr(56)+chr(34))
        report = replay(self.gate, self.state.run_id)
        self.assertFalse(report["ledger"]["valid"])

    def test_attestation_contains_run_and_policy_identity(self):
        result = attest(self.gate, self.state)
        self.assertIsNotNone(result)
        if isinstance(result, dict):
            self.assertEqual(result.get("run_id"), self.state.run_id)
            self.assertEqual(result.get("policy_hash"), policy_hash(POLICY))

    def test_scenario_termination(self):
        harness = MockHarness(RealityGate(POLICY, self.tempdir.name))
        result = harness.run({"actions": [{"tool": "read_file"}, {"tool": "delete_all"}, {"tool": "read_file"}]}, mode="terminate", run_id="scenario-run")
        self.assertEqual(result.state.status, "terminated")
        self.assertEqual(len(result.decisions), 2)
        self.assertEqual(decision_kind(result.decisions[-1]), DecisionKind.KILL.value)

class ContractSmokeTests(unittest.TestCase):
    def test_engine_import_is_available(self):
        if ENGINE_IMPORT_ERROR is not None:
            self.fail(f"RealityGate core cannot be imported: {ENGINE_IMPORT_ERROR}")

if __name__ == "__main__":
    unittest.main()
