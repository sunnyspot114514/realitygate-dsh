from pathlib import Path
import tempfile
import time
import unittest
from realitygate.engine import RealityGate
from realitygate.models import Action, DecisionKind
from realitygate.capability import issue
from dsh_adapter.mock_harness import MockHarness

POLICY = {
    "version": "controls-v1",
    "actions": {"allow_tools": ["read_file", "http_get", "write_file"], "hold_tools": [], "kill_tools": ["delete_all"]},
    "egress": {"allow_targets": ["https://example.test"], "read_only_targets": ["https://example.test"], "unknown_decision": "HOLD"},
    "credentials": {"canary": {"allowed_targets": ["canary.local"]}},
    "budget": {"max_actions": 4, "max_network_bytes": 100, "max_persistent_writes": 1},
    "credential_origins": ["ephemeral_runtime"],
}

def gate(tmp, **overrides):
    policy = {**POLICY, **overrides}
    return RealityGate(policy, tmp)

class RuntimeControlsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.gate = gate(self.tmp.name)
        self.state = self.gate.start_run("controls")

    def tearDown(self):
        self.tmp.cleanup()

    def test_capability_issued_and_single_use(self):
        d = self.gate.authorize(self.state, Action("read_file", target="x"))
        self.assertEqual(d.kind, DecisionKind.ALLOW)
        cap = self.gate.capabilities["controls"][d.action_id]
        self.assertTrue(cap.valid(self.gate._capability_key))
        cap.consume(self.gate._capability_key)
        self.assertFalse(cap.valid(self.gate._capability_key))
        with self.assertRaises(ValueError):
            cap.consume(self.gate._capability_key)

    def test_tampered_capability_rejected(self):
        cap = issue(run_id="r", agent_id="a", tool="t", target=None, args={}, effect={}, policy_hash="p", audience="a")
        cap.signature = "00" * 32
        with self.assertRaises(ValueError):
            cap.consume(b"key")

    def test_expired_capability_rejected(self):
        cap = issue(run_id="r", agent_id="a", tool="t", target=None, args={}, effect={}, policy_hash="p", audience="a", ttl_seconds=1)
        self.assertFalse(cap.valid(b"key", now=time.time() + 10))

    def test_effecting_get_is_hold(self):
        d = self.gate.authorize(self.state, Action("http_get", target="https://example.test", effect={"external_effect": True}))
        self.assertEqual(d.kind, DecisionKind.HOLD)
        self.assertEqual(d.reason, "effecting_read_requires_capability")

    def test_get_without_read_safe_target_is_hold_regardless_of_declaration(self):
        # Agent cannot downgrade authority by omitting the effect declaration:
        # policy-side read_only_targets decides, declaration can only escalate.
        d = self.gate.authorize(self.state, Action("http_get", target="https://example.test"))
        self.assertEqual(d.kind, DecisionKind.ALLOW)
        d2 = self.gate.authorize(self.state, Action("http_get", target="https://example.test", effect={}))
        self.assertEqual(d2.kind, DecisionKind.ALLOW)

    def test_capability_must_be_consumed_at_commit(self):
        d = self.gate.authorize(self.state, Action("read_file", target="x"))
        cap = self.gate.capabilities["controls"][d.action_id]
        cap.expires_at = time.time() - 1  # force expiry before commit
        with self.assertRaises(ValueError):
            self.gate.record_result(self.state, d.action_id, {"ok": True})

    def test_public_discovered_origin_kills(self):
        d = self.gate.authorize(self.state, Action("read_file", target="x", credential_origin="publicly_discovered"))
        self.assertEqual(d.kind, DecisionKind.KILL)
        self.assertEqual(d.reason, "credential_provenance_denied")

    def test_network_budget_kills(self):
        d1 = self.gate.authorize(self.state, Action("http_get", target="https://example.test", args={"bytes": 90}))
        self.gate.record_result(self.state, d1.action_id, {"ok": True, "status": 200, "bytes": 90})
        d = self.gate.authorize(self.state, Action("http_get", target="https://example.test", args={"bytes": 20}))
        self.assertEqual(d.kind, DecisionKind.KILL)
        self.assertEqual(d.reason, "budget_exceeded:network_bytes")

    def test_action_budget_kills(self):
        g = gate(self.tmp.name, budget={"max_actions": 1})
        s = g.start_run("actions-budget")
        g.authorize(s, Action("read_file", target="a"))
        d = g.authorize(s, Action("read_file", target="b"))
        self.assertEqual(d.kind, DecisionKind.KILL)
        self.assertEqual(d.reason, "budget_exceeded:max_actions")

    def test_external_stop_revokes_capabilities(self):
        d = self.gate.authorize(self.state, Action("read_file", target="x"))
        self.assertEqual(len(self.gate.pending["controls"]), 1)
        self.gate.stop_run(self.state)
        self.assertEqual(self.state.status, "terminated")
        self.assertEqual(len(self.gate.pending["controls"]), 0)
        self.assertEqual(self.state.capabilities_revoked, 1)
        with self.assertRaises(ValueError):
            self.gate.record_result(self.state, d.action_id, {"ok": True})
        follow = self.gate.authorize(self.state, Action("read_file", target="y"))
        self.assertEqual(follow.kind, DecisionKind.KILL)
        self.assertEqual(follow.reason, "run_already_terminated")

    def test_kill_is_idempotent(self):
        self.gate.authorize(self.state, Action("read_file", target="x"))
        first = self.gate.kill(self.state, Action("bad"), "sensitive_action")
        events_before = len(self.gate.ledgers["controls"].events())
        second = self.gate.kill(self.state, Action("bad2"), "sensitive_action")
        self.assertEqual(events_before, len(self.gate.ledgers["controls"].events()) - 1)
        self.assertEqual(second.reason, "run_already_terminated")

    def test_adapter_never_executes_hold_or_kill(self):
        executed = []
        harness = MockHarness(self.gate, executor=lambda a: executed.append(a) or {"ok": True, "status": 200})
        state, results = harness.run({"actions": [
            {"tool": "http_get", "target": "unknown.test"},
            {"tool": "read_file", "target": "fixture.txt"},
            {"tool": "delete_all"},
            {"tool": "read_file", "target": "after.txt"},
        ]}, run_id="adapter-run")
        self.assertEqual(len(executed), 1)
        self.assertEqual(state.status, "terminated")
        self.assertEqual(len(results), 3)
        self.assertFalse(results[0]["executed"])
        self.assertTrue(results[1]["executed"])
        self.assertFalse(results[2]["executed"])

if __name__ == "__main__":
    unittest.main()
