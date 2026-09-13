"""Compatibility helpers for the evolving RealityGate API."""
from __future__ import annotations
from typing import Any

def authorize(gate: Any, state: Any, action: Any) -> Any:
    """Call either requested authorize(action) or legacy authorize(state, action)."""
    try:
        return gate.authorize(action)
    except TypeError as exc:
        try:
            return gate.authorize(state, action)
        except TypeError:
            raise exc

def attest(gate: Any, state: Any) -> Any:
    method = getattr(gate, "attest", None)
    if method is None:
        raise AttributeError("RealityGate.attest is not implemented")
    try:
        return method(state)
    except (TypeError, KeyError):
        return method(state.run_id)

def replay(gate: Any, run_id: str) -> Any:
    return gate.replay(run_id)

def decision_kind(decision: Any) -> str:
    kind = getattr(decision, "kind", decision)
    return getattr(kind, "value", str(kind))
