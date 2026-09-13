from pathlib import Path
import tempfile
import time
import unittest
from realitygate.engine import RealityGate
from realitygate.models import Action, DecisionKind

POLICY = {
    "version": "gapfix-v1",
    "actions": {"allow_tools": ["read_file", "write_file", "http_get"], "hold_tools": [], "kill_tools": [], "identity_tools": ["create_account", "register_email", "impersonate_moderator"]},
    "sensitive_tools": [],
    "credentials": {"production": {"denied": True}, "canary": {"allowed_targets": ["canary.local"]}},
    "egress": {"allow_targets": ["https://example.test"], "read_only_targets": ["https://example.test"], "unknown_decision": "HOLD", "kill_tools": []},
    "budget": {
        "max_actions": 32, "max_network_bytes": 100000, "max_persistent_writes": 32, "wall_clock_seconds": 300,
        "heartbeat": {"window_seconds": 3600, "min_events": 3, "max_interval_variance": 5.0, "decision": "KILL"},
    },
    "credential_origins": ["ephemeral_runtime"],
}

def gate(tmp):
    return RealityGate(POLICY, tmp)

class GapFixTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.gate = gate(self.tmp.name)
        self.state = self.gate.start_run("gaps")

    def tearDown(self):
        self.tmp.cleanup()

    def test_identity_tool_kills(self):
        d = self.gate.authorize(self.state, Action("create_account", target="wiki.example"))
        self.assertEqual(d.kind, DecisionKind.KILL)
        self.assertEqual(d.reason, "identity_creation_denied")
        self.assertEqual(self.state.status, "terminated")

    def test_identity_effect_escalates(self):
        g = gate(self.tmp.name)
        s = g.start_run("identity-effect")
        d = g.authorize(s, Action("read_file", target="x", effect={"identity_effect": True}))
        self.assertEqual(d.kind, DecisionKind.KILL)
        self.assertEqual(d.reason, "identity_creation_denied")

    def test_wall_clock_enforced_from_gate_side(self):
        self.state.started_at = time.time() - 400  # gate clock, not agent input
        d = self.gate.authorize(self.state, Action("read_file", target="x"))
        self.assertEqual(d.kind, DecisionKind.KILL)
        self.assertEqual(d.reason, "budget_exceeded:wall_clock")

    def test_persistent_writes_counter_and_budget(self):
        g = RealityGate({**POLICY, "budget": {**POLICY["budget"], "max_persistent_writes": 1}}, self.tmp.name)
        s = g.start_run("pw")
        d1 = g.authorize(s, Action("write_file", target="a", effect={"persistence": True}))
        self.assertEqual(d1.kind, DecisionKind.ALLOW)
        g.record_result(s, d1.action_id, {"ok": True, "status": 200})
        self.assertEqual(s.persistent_writes, 1)
        d2 = g.authorize(s, Action("write_file", target="b", effect={"persistence": True}))
        self.assertEqual(d2.kind, DecisionKind.KILL)
        self.assertEqual(d2.reason, "budget_exceeded:persistent_writes")

    def test_regular_slow_writes_trigger_heartbeat(self):
        # inject regular write times (300s apart), then a 4th write -> KILL
        now = time.time()
        self.state.write_times = [now - 900, now - 600, now - 300]
        d = self.gate.authorize(self.state, Action("write_file", target="sink", effect={"persistence": True}))
        self.assertEqual(d.kind, DecisionKind.KILL)
        self.assertEqual(d.reason, "heartbeat_suspected")

    def test_irregular_writes_do_not_trigger_heartbeat(self):
        now = time.time()
        self.state.write_times = [now - 1200, now - 1150, now - 600]
        d = self.gate.authorize(self.state, Action("write_file", target="sink", effect={"persistence": True}))
        self.assertEqual(d.kind, DecisionKind.ALLOW)

if __name__ == "__main__":
    unittest.main()
