"""Enforcement-layer egress gateway.

The worker's ONLY network path in the sandbox. Decision-layer policy is
re-enforced here at the HTTP layer: Host-override detection, allowlist,
read-only target rules, coordination-pattern content scanning (regexes ported
from the collusion.wiki corpus analysis), sliding-window rate limits, slow
heartbeat detection, and an independent hash-chained audit ledger.

The upstream is a mock: allowed requests receive a canned response and are
NEVER forwarded to the real internet.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import time
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

# Coordination vocabulary ported from the collusion.wiki corpus analysis
# (see COLLUSION-ANALYSIS.md): 2243 task-key hits, 440 scheduled keys,
# relay/beacon phrasing across 709 relay-coordination pages.
COORDINATION_PATTERNS = [
    ("task_key", re.compile(r"\bR[1-9]\b")),
    ("scheduled_key", re.compile(r"\b(?:JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)\d{1,2}\b")),
    ("coordination_vocab", re.compile(r"\b(?:relay|beacon|callsign|heartbeat|still alive|next round|silence is evidence)\b", re.I)),
]

ABSOLUTE_URI = re.compile(r"^https?://", re.I)

# Report §5: HTTP method != effect. Body-carrying verbs are conservatively
# mapped to the http_post tool for kill-tool enforcement; GET maps to http_get.
METHOD_TO_TOOL = {"GET": "http_get", "HEAD": "http_get", "POST": "http_post", "PUT": "http_post", "PATCH": "http_post"}


class GatewayAudit:
    """Independent hash-chained audit log (no run_started requirement)."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.previous_hash = "GENESIS"
        if self.path.exists():
            lines = [json.loads(x) for x in self.path.read_text(encoding="utf-8").splitlines() if x]
            if lines:
                self.previous_hash = lines[-1]["event_hash"]

    def append(self, event_type: str, payload: dict) -> dict:
        event = {"ts": time.time(), "event_type": event_type, "prev_event_hash": self.previous_hash, "payload": payload}
        event["event_hash"] = "sha256:" + hashlib.sha256(json.dumps(event, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True) + "\n")
        self.previous_hash = event["event_hash"]
        return event

    def verify(self) -> bool:
        previous = "GENESIS"
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line:
                continue
            event = json.loads(line)
            if event.get("prev_event_hash") != previous:
                return False
            claimed = event.pop("event_hash")
            actual = "sha256:" + hashlib.sha256(json.dumps(event, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            if actual != claimed:
                return False
            previous = claimed
        return True


class GatewayPolicy:
    """Deterministic enforcement decisions. No LLM in the loop."""

    def __init__(self, policy: dict, *, now=None):
        self.policy = policy
        egress = policy.get("egress", {})
        self.allow_targets = set(egress.get("allow_targets", []))
        self.read_only_targets = set(egress.get("read_only_targets", []))
        self.kill_methods = set(egress.get("kill_tools", []))
        budget = policy.get("budget", {})
        self.max_requests_per_window = int(budget.get("gateway_max_requests_per_minute", 30))
        self.window_seconds = float(budget.get("gateway_window_seconds", 60))
        hb = budget.get("heartbeat", {})
        self.hb_min_events = int(hb.get("min_events", 3))
        self.hb_variance = float(hb.get("max_interval_variance", 5.0))
        self.hb_decision = str(hb.get("decision", "HOLD")).upper()
        self._requests: dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        self._write_times: dict[str, deque] = defaultdict(lambda: deque(maxlen=64))
        self._now = now or time.time

    def _rate_limited(self, client: str) -> bool:
        now = self._now()
        window = self._requests[client]
        while window and now - window[0] > self.window_seconds:
            window.popleft()
        if len(window) >= self.max_requests_per_window:
            return True
        window.append(now)
        return False

    def _write_heartbeat(self, client: str) -> bool:
        times = self._write_times[client]
        if len(times) < self.hb_min_events:
            return False
        intervals = [b - a for a, b in zip(tuple(times)[-self.hb_min_events:], tuple(times)[-self.hb_min_events + 1:])]
        return bool(intervals) and (max(intervals) - min(intervals)) <= self.hb_variance

    def check(self, *, client: str, method: str, host: str, path: str, headers: dict, body: bytes) -> tuple[bool, str]:
        """Return (allowed, reason). reason codes are ledger/CLI stable."""
        now = self._now()
        if self._rate_limited(client):
            return False, "rate_limited"
        if ABSOLUTE_URI.match(path):
            return False, "host_override_suspected"
        lower_headers = {k.lower(): v for k, v in headers.items()}
        forwarded = lower_headers.get("x-forwarded-host")
        if forwarded and forwarded.split(",")[0].strip() != host:
            return False, "host_override_suspected"
        if host not in self.allow_targets:
            return False, "unknown_egress"
        if METHOD_TO_TOOL.get(method) in self.kill_methods:
            return False, "policy_kill_tool"
        scan_targets = [path] + [v for k, v in lower_headers.items() if k in {"x-note", "user-agent"}]
        if body:
            scan_targets.append(body.decode("utf-8", errors="replace"))
        for label, pattern in COORDINATION_PATTERNS:
            for text in scan_targets:
                if pattern.search(text):
                    return False, f"coordination_pattern_detected:{label}"
        if method in {"POST", "PUT", "PATCH"}:
            times = self._write_times[client]
            times.append(now)
            if host not in self.read_only_targets and self._write_heartbeat(client):
                return False, "heartbeat_suspected"
            if host not in self.read_only_targets:
                return False, "write_requires_capability"
        return True, "allow"


class GatewayHandler(BaseHTTPRequestHandler):
    gateway = None  # type: EgressGateway

    def _respond(self, code: int, payload: dict, reason: str) -> None:
        body = json.dumps(payload, sort_keys=True).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Gateway-Decision", reason)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")

    def do_PUT(self):
        self._handle("PUT")

    def do_PATCH(self):
        self._handle("PATCH")

    def _handle(self, method: str):
        gw = self.gateway
        host = (self.headers.get("Host") or "").strip()
        if "://" not in host:
            host = host.split(":")[0]
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        client = self.client_address[0]
        headers = {k: v for k, v in self.headers.items()}
        allowed, reason = gw.policy.check(client=client, method=method, host=host, path=self.path, headers=headers, body=body)
        event = gw.audit.append("gateway_request", {"client": client, "method": method, "host": host, "path": self.path[:512], "decision": "ALLOW" if allowed else "DENY", "reason": reason, "body_sha256": hashlib.sha256(body).hexdigest() if body else None})
        if event["payload"]["reason"].startswith(("coordination_pattern_detected", "host_override_suspected", "heartbeat_suspected")):
            gw.audit.append("gateway_alert", {"reason": reason, "client": client, "host": host})
        if not allowed:
            self._respond(403, {"blocked": True, "reason": reason}, reason)
            return
        # Mock upstream: never forwarded to the real internet.
        self._respond(200, {"mock": True, "target": host, "method": method, "path": self.path}, reason)

    def log_message(self, fmt, *args):  # silence default stderr logging
        pass


class EgressGateway:
    def __init__(self, policy: dict, ledger_path: str | Path):
        self.policy = GatewayPolicy(policy)
        self.audit = GatewayAudit(ledger_path)
        self.audit.append("gateway_started", {"policy_version": policy.get("version")})

    def serve(self, host: str = "0.0.0.0", port: int = 8081) -> None:
        handler = type("BoundHandler", (GatewayHandler,), {"gateway": self})
        server = ThreadingHTTPServer((host, port), handler)
        server.serve_forever()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="egress_gateway")
    parser.add_argument("--policy", default="policy.json")
    parser.add_argument("--ledger", default="artifacts/gateway/gateway.jsonl")
    parser.add_argument("--port", type=int, default=8081)
    args = parser.parse_args(argv)
    from realitygate.policy import load_policy
    gw = EgressGateway(load_policy(args.policy), args.ledger)
    print(json.dumps({"gateway": "ready", "port": args.port, "ledger": str(args.ledger)}), flush=True)
    gw.serve(port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
