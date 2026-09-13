"""Short-lived, single-use action capabilities.

The capability is an authorization record, not a secret and not a replacement for
an infrastructure credential broker. Executors must consume it before effects.
"""
from __future__ import annotations
from dataclasses import dataclass
import hashlib
import hmac
import json
import secrets
import time
from typing import Any


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()

@dataclass
class Capability:
    token_id: str
    run_id: str
    agent_id: str
    tool: str
    target: str | None
    args_sha256: str
    effect_sha256: str
    policy_hash: str
    audience: str
    issued_at: float
    expires_at: float
    max_uses: int = 1
    uses: int = 0
    signature: str = ""

    def claims(self) -> dict[str, Any]:
        return {"token_id": self.token_id, "run_id": self.run_id, "agent_id": self.agent_id,
                "tool": self.tool, "target": self.target, "args_sha256": self.args_sha256,
                "effect_sha256": self.effect_sha256, "policy_hash": self.policy_hash,
                "audience": self.audience, "issued_at": self.issued_at,
                "expires_at": self.expires_at, "max_uses": self.max_uses}

    def sign(self, key: bytes) -> "Capability":
        self.signature = hmac.new(key, _canonical(self.claims()), hashlib.sha256).hexdigest()
        return self

    def valid(self, key: bytes, *, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        expected = hmac.new(key, _canonical(self.claims()), hashlib.sha256).hexdigest()
        return bool(self.signature) and hmac.compare_digest(self.signature, expected) and now < self.expires_at and self.uses < self.max_uses

    def consume(self, key: bytes, *, now: float | None = None) -> None:
        if not self.valid(key, now=now):
            raise ValueError("capability is invalid, expired, or already consumed")
        self.uses += 1


def issue(*, run_id: str, agent_id: str, tool: str, target: str | None,
          args: dict[str, Any], effect: dict[str, Any], policy_hash: str,
          audience: str, ttl_seconds: int = 90, key: bytes | None = None) -> Capability:
    if ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be positive")
    now = time.time()
    cap = Capability(secrets.token_hex(16), run_id, agent_id, tool, target,
        "sha256:" + hashlib.sha256(_canonical(args)).hexdigest(),
        "sha256:" + hashlib.sha256(_canonical(effect)).hexdigest(), policy_hash,
        audience, now, now + ttl_seconds)
    return cap.sign(key or secrets.token_bytes(32))
