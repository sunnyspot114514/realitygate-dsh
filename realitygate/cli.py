import argparse
import json
import sys
from pathlib import Path
from .engine import RealityGate
from .evidence import export_bundle, verify_bundle
from .models import Action, DecisionKind
from .policy import load_policy, policy_hash, validate_policy, validate_scenario

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_PREFLIGHT = 3
EXIT_HOLD = 4
EXIT_KILL = 5
EXIT_EVIDENCE = 6


def emit(value):
    print(json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False))


def _read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def build_parser():
    parser = argparse.ArgumentParser(prog="realitygate")
    parser.add_argument("--policy", default="policy.json")
    parser.add_argument("--artifacts", default="artifacts/runs")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("preflight")
    run = sub.add_parser("run")
    run.add_argument("scenario")
    run.add_argument("--run-id")
    replay = sub.add_parser("replay")
    replay.add_argument("run_id")
    attest = sub.add_parser("attest")
    attest.add_argument("run_id")
    stop = sub.add_parser("stop")
    stop.add_argument("run_id")
    stop.add_argument("--reason", default="external_stop")
    evidence = sub.add_parser("evidence")
    evidence_sub = evidence.add_subparsers(dest="evidence_command", required=True)
    export = evidence_sub.add_parser("export")
    export.add_argument("run_id")
    export.add_argument("scenario")
    export.add_argument("destination")
    verify = evidence_sub.add_parser("verify")
    verify.add_argument("bundle")
    return parser


def main(argv=None):
    try:
        args = build_parser().parse_args(argv)
        policy = load_policy(args.policy)
        policy_errors = validate_policy(policy)
        if args.command == "preflight":
            emit({"ok": not policy_errors, "policy_version": policy.get("version"), "policy_hash": policy_hash(policy), "errors": policy_errors})
            return EXIT_OK if not policy_errors else EXIT_PREFLIGHT
        if args.command == "evidence" and args.evidence_command == "verify":
            result = verify_bundle(args.bundle)
            emit(result)
            return EXIT_OK if result.get("valid") else EXIT_EVIDENCE
        gate = RealityGate(policy, args.artifacts)
        if args.command == "run":
            scenario = _read_json(args.scenario)
            scenario_errors = validate_scenario(scenario)
            if policy_errors or scenario_errors:
                raise ValueError("preflight failed: " + "; ".join(policy_errors + scenario_errors))
            run_id = args.run_id or scenario.get("run_id")
            state = gate.start_run(run_id)
            decisions = []
            for raw in scenario["actions"]:
                decision = gate.authorize(state, Action.from_dict(raw))
                decisions.append(decision.to_dict())
                if decision.kind is DecisionKind.ALLOW:
                    gate.record_result(state, decision.action_id, {"ok": True, "status": 200, "mocked": True})
                if decision.kind is DecisionKind.KILL:
                    break
            emit({"run": state.to_dict(), "decisions": decisions, "attestation": gate.attest(state)})
            if state.status == "terminated": return EXIT_KILL
            if state.held: return EXIT_HOLD
            return EXIT_OK
        if args.command == "replay":
            emit(gate.replay(args.run_id))
            return EXIT_OK
        if args.command == "attest":
            emit(gate.attest(args.run_id))
            return EXIT_OK
        if args.command == "stop":
            state = gate.runs.get(args.run_id)
            if state is not None:
                pending_before = len(gate.pending.get(state.run_id, {}))
                gate.stop_run(state, args.reason)
                emit({"run_id": state.run_id, "status": state.status, "kill_reason": state.kill_reason, "revoked_capabilities": state.capabilities_revoked, "pending_before": pending_before})
            else:
                result = gate.stop_run_persisted(args.run_id, args.reason)
                emit(result)
            return EXIT_KILL
        if args.command == "evidence" and args.evidence_command == "export":
            output = export_bundle(gate, args.run_id, args.policy, args.scenario, args.destination)
            emit({"ok": True, "bundle": str(output)})
            return EXIT_OK
    except (ValueError, OSError, json.JSONDecodeError, FileNotFoundError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return EXIT_EVIDENCE if argv and "verify" in argv else EXIT_PREFLIGHT
    return EXIT_USAGE


if __name__ == "__main__":
    raise SystemExit(main())
