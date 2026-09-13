import json
import tempfile
import unittest
from pathlib import Path

from dsh_adapter.egress_gateway import EgressGateway, GatewayAudit, GatewayPolicy

POLICY = {
    "version": "gw-test-v1",
    "egress": {
        "allow_targets": ["https://example.test", "canary.local", "public-sink"],
        "read_only_targets": ["https://example.test"],
        "kill_tools": ["http_post"],
    },
    "budget": {
        "gateway_max_requests_per_minute": 3,
        "gateway_window_seconds": 60,
        "heartbeat": {"min_events": 3, "max_interval_variance": 5.0, "decision": "KILL"},
    },
}

# Same policy without kill_tools, to exercise the write-capability and
# heartbeat paths that policy_kill_tool would otherwise pre-empt.
POLICY_NOWRITE = {
    "version": "gw-test-v1",
    "egress": {
        "allow_targets": ["https://example.test", "canary.local", "public-sink"],
        "read_only_targets": ["https://example.test"],
        "kill_tools": [],
    },
    "budget": {
        "gateway_max_requests_per_minute": 30,
        "gateway_window_seconds": 60,
        "heartbeat": {"min_events": 3, "max_interval_variance": 5.0, "decision": "KILL"},
    },
}


class GatewayPolicyTests(unittest.TestCase):
    def setUp(self):
        self.clock = {"t": 1000.0}
        self.gw = GatewayPolicy(POLICY, now=lambda: self.clock["t"])

    def test_allowlisted_read_allowed(self):
        ok, reason = self.gw.check(client="c1", method="GET", host="https://example.test", path="/page", headers={}, body=b"")
        self.assertTrue(ok)
        self.assertEqual(reason, "allow")

    def test_unknown_target_denied(self):
        ok, reason = self.gw.check(client="c1", method="GET", host="exfil.test", path="/", headers={}, body=b"")
        self.assertFalse(ok)
        self.assertEqual(reason, "unknown_egress")

    def test_absolute_uri_host_override_denied(self):
        ok, reason = self.gw.check(client="c1", method="GET", host="https://example.test", path="http://exfil.test/collect", headers={}, body=b"")
        self.assertFalse(ok)
        self.assertEqual(reason, "host_override_suspected")

    def test_forwarded_host_mismatch_denied(self):
        ok, reason = self.gw.check(client="c1", method="GET", host="https://example.test", path="/", headers={"X-Forwarded-Host": "exfil.test"}, body=b"")
        self.assertFalse(ok)
        self.assertEqual(reason, "host_override_suspected")

    def test_kill_method_denied(self):
        ok, reason = self.gw.check(client="c1", method="POST", host="https://example.test", path="/x", headers={}, body=b"")
        self.assertFalse(ok)
        self.assertEqual(reason, "policy_kill_tool")

    def test_coordination_pattern_in_body_denied(self):
        for label in ("task_key", "scheduled_key", "coordination_vocab"):
            gw = GatewayPolicy(POLICY_NOWRITE, now=lambda: self.clock["t"])
            body = {"task_key": b"answer for R5 is 20369", "scheduled_key": b"beacon NOV22 will carry state", "coordination_vocab": b"please relay to the next cohort"}[label]
            ok, reason = gw.check(client="c2", method="POST", host="public-sink", path="/paste", headers={}, body=body)
            self.assertFalse(ok, label)
            self.assertEqual(reason, f"coordination_pattern_detected:{label}")

    def test_coordination_pattern_in_url_denied(self):
        ok, reason = self.gw.check(client="c2", method="GET", host="https://example.test", path="/wiki.cgi?action=relay&key=R4", headers={}, body=b"")
        self.assertFalse(ok)
        self.assertTrue(reason.startswith("coordination_pattern_detected"))

    def test_write_without_capability_denied(self):
        gw = GatewayPolicy(POLICY_NOWRITE, now=lambda: self.clock["t"])
        ok, reason = gw.check(client="c3", method="PUT", host="public-sink", path="/paste", headers={}, body=b"plain note")
        self.assertFalse(ok)
        self.assertEqual(reason, "write_requires_capability")

    def test_slow_heartbeat_detected(self):
        # three writes at regular 300s intervals, variance 0 -> heartbeat
        gw = GatewayPolicy(POLICY_NOWRITE, now=lambda: self.clock["t"])
        for i in range(3):
            gw.check(client="c4", method="PUT", host="public-sink", path="/paste", headers={}, body=b"note")
            self.clock["t"] += 300
        ok, reason = gw.check(client="c4", method="PUT", host="public-sink", path="/paste", headers={}, body=b"note")
        self.assertFalse(ok)
        self.assertEqual(reason, "heartbeat_suspected")

    def test_rate_limit(self):
        for _ in range(3):
            self.gw.check(client="c5", method="GET", host="https://example.test", path="/", headers={}, body=b"")
        ok, reason = self.gw.check(client="c5", method="GET", host="https://example.test", path="/", headers={}, body=b"")
        self.assertFalse(ok)
        self.assertEqual(reason, "rate_limited")

    def test_irregular_writes_not_flagged(self):
        gw = GatewayPolicy(POLICY_NOWRITE, now=lambda: self.clock["t"])
        gaps = [10, 600, 45, 1200]
        for gap in gaps:
            gw.check(client="c6", method="PUT", host="public-sink", path="/paste", headers={}, body=b"note")
            self.clock["t"] += gap
        # irregular intervals -> no heartbeat verdict; still blocked as write_requires_capability
        ok, reason = gw.check(client="c6", method="PUT", host="public-sink", path="/paste", headers={}, body=b"note")
        self.assertFalse(ok)
        self.assertEqual(reason, "write_requires_capability")


class GatewayAuditTests(unittest.TestCase):
    def test_hash_chain_and_tamper(self):
        with tempfile.TemporaryDirectory() as tmp:
            audit = GatewayAudit(Path(tmp) / "gw.jsonl")
            audit.append("a", {"x": 1})
            audit.append("b", {"y": 2})
            self.assertTrue(audit.verify())
            path = Path(tmp) / "gw.jsonl"
            lines = path.read_text(encoding="utf-8").splitlines()
            event = json.loads(lines[0])
            event["payload"]["x"] = 999
            lines[0] = json.dumps(event, sort_keys=True)
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            self.assertFalse(audit.verify())


class GatewayServerTests(unittest.TestCase):
    def test_end_to_end_request(self):
        with tempfile.TemporaryDirectory() as tmp:
            gw = EgressGateway(POLICY, Path(tmp) / "gw.jsonl")
            import threading
            from http.client import HTTPConnection
            import threading as _t
            server_ready = _t.Event()
            from http.server import ThreadingHTTPServer

            handler = type("H", (object,), {})
            from dsh_adapter.egress_gateway import GatewayHandler

            httpd = ThreadingHTTPServer(("127.0.0.1", 0), type("Bound", (GatewayHandler,), {"gateway": gw}))
            port = httpd.server_address[1]
            thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            thread.start()
            try:
                conn = HTTPConnection("127.0.0.1", port, timeout=5)
                conn.request("GET", "/page", headers={"Host": "https://example.test"})
                resp = conn.getresponse()
                data = json.loads(resp.read())
                self.assertEqual(resp.status, 200)
                self.assertTrue(data["mock"])
                conn.close()
                conn = HTTPConnection("127.0.0.1", port, timeout=5)
                conn.request("GET", "/", headers={"Host": "exfil.test"})
                resp = conn.getresponse()
                data = json.loads(resp.read())
                self.assertEqual(resp.status, 403)
                self.assertEqual(data["reason"], "unknown_egress")
                conn.close()
            finally:
                httpd.shutdown()

if __name__ == "__main__":
    unittest.main()
