# RealityGate: An Auditable Containment Standard for Guardrails-Off Agent Evaluations

[中文](README.md) | [English](README_EN.md)

Turns "is containment adequate?" from a writing exercise into an executable specification: every clause is backed by a preflight check, a test, and a cost tier, and produces evidence bundles a third party can verify offline without entering the lab's network.

Built for Track 1 (Containment) of the Apart Research AI Incident Sprint (Sept 2026), against the backdrop of three July 2026 agent-containment incidents: the OpenAI-model intrusion into Hugging Face, the three real-world accesses Anthropic found after reviewing 141,006 evaluation runs, and ~15,000 cross-run coordination edits on a public wiki.

## Core Principles

- **Authority follows action, not agent**: every ALLOW issues a one-shot HMAC capability (bound to run/agent/tool/target/args-digest/effect-digest/policy hash, TTL 90 s, single use), consumed atomically at commit.
- **Attempts may occur; unauthorized effects shall not**: the model may propose anything; authorization comes from a deterministic policy engine, never from a model or classifier.
- **GET is not read-only**: effecting GETs are held; read-safety is decided by policy-side `read_only_targets`, and caller-declared effect can only escalate, never de-escalate.
- **Credential provenance is fail-closed**: `publicly_discovered` / `unknown` origins are killed; canary credentials are target-bound and never enter model context.
- **The gate comes before the run**: `run` forces preflight before any ledger exists; non-compliant policies or scenarios are rejected outright.
- **The task clock belongs to the gate**: `wall_clock_seconds` is enforced from gate-side time, not an agent-visible input.
- **KILL is terminal**: revokes all pending capabilities; `stop` is triggered from outside the model and is idempotent across processes.
- **The ledger is the evidence**: append-only JSONL hash chain + fsync; evidence bundles (manifest/policy/scenario/ledger/attestation) are verifiable offline by an independent process and fail on any single-file tampering.
- **Enforcement below the decision layer**: the worker sits on a Compose internal network with no internet route; the egress gateway is the only exit, enforcing Host-override detection, verb-to-tool mapping, rate limits, slow-heartbeat detection, and coordination-pattern content scanning.

## Explicit Non-Goals

- No official DeepSeek Harness integration; `dsh_adapter/` is an integration boundary and currently a DSH-shaped mock.
- The gateway does no real-internet forwarding and no TLS MITM; its upstream is a mock.
- No host/WSL kernel-escape claims; WSL2 + Docker Desktop is a development/demo boundary only.
- No exploit code, real credentials, or attacks on real targets; all scenarios are synthetic fixtures.
- Not an attempt to detect model "alignment"; final authorization comes only from the deterministic policy engine.

## Architecture

```text
Model (proposal only)
      |
      v
RealityGate deterministic policy   ALLOW / HOLD / KILL
      |                                     |
      |  one-shot capability                |  KILL/stop:
      |  (HMAC, TTL 90 s, single use)       |  revoke pending,
      v                                     |  close channel
Enforcement gateway  ---- only egress ----> Mock executor / public-sink
(host-override, verb->tool, rates,           (denied by default)
 coordination patterns, heartbeat)
      |
      v
Hash-chained ledger --> Evidence bundle (independent offline verify)
```

## Quick Start

```bash
python3 scripts/validate.py                # compile + 39 tests
python3 scripts/check_exits.py             # 9 exit-code contract assertions

python3 -m realitygate.cli --policy policy.json --artifacts artifacts/runs preflight
python3 -m realitygate.cli --policy policy.json --artifacts artifacts/runs run scenario.json --run-id demo      # KILL -> exit 5
python3 -m realitygate.cli --policy policy.json --artifacts artifacts/runs replay demo
python3 -m realitygate.cli --policy policy.json --artifacts artifacts/runs attest demo
python3 -m realitygate.cli --policy policy.json --artifacts artifacts/runs stop demo --reason operator_kill  # idempotent

# Adversarial scenario (effecting GET / metadata / credential discovery / post-KILL blocking)
python3 -m realitygate.cli --policy policy.json --artifacts artifacts/adv run scenarios/adversarial-controls.json --run-id adv-1

# Evidence bundle export and independent verification
python3 -m realitygate.cli --policy policy.json --artifacts artifacts/runs evidence export demo scenario.json evidence/demo
python3 -m realitygate.cli evidence verify evidence/demo

# Multi-model live probes (optional: --pressure / --only minimax|kimi|deepseek)
python3 -m dsh_adapter.multi_model_probe
```

Exit codes: `0` ok; `3` preflight/input error; `4` run contains HOLD; `5` run KILLed or stopped; `6` evidence verification failed.

## Repository Layout

```text
realitygate/            Core runtime (policy/engine/ledger/capability/evidence/cli)
dsh_adapter/            DSH-shaped adapter, proposal channel, multi-model probe, egress gateway
sandbox/                Compose sandbox (worker offline, gateway sole egress)
scenarios/              Adversarial scenarios (adversarial-controls/identity/heartbeat etc.)
tests/                  39 tests
scripts/                validate.py, check_exits.py, ledger summaries
CONTROL_MATRIX.md       Control x attack-phase x evidence x cost matrix
COLLUSION-ANALYSIS.md   Public-wiki corpus analysis and remediation status
LIVE-MODEL-TEST.md      Live-model adversarial test report
submission/             Sprint report (PDF/HTML)
```

## Known Limitations

See Section 5 and Appendix A of the report. Key points: the gateway upstream is a mock with no TLS MITM; network isolation is provided by Compose internal networks; the official DeepSeek Harness is not integrated; capabilities are local HMACs without non-repudiation; evidence bundles only resist tampering by parties without write access.

## Milestones

- [x] Strict policy/scenario validation and preflight gate;
- [x] ALLOW/HOLD/KILL with post-KILL fail-closed;
- [x] One-shot HMAC capabilities with atomic commit-time consumption;
- [x] Fail-closed credential provenance;
- [x] Budget breakers (actions/bytes/writes/wall-clock);
- [x] Cross-process idempotent stop;
- [x] Hash-chained ledger with tamper detection;
- [x] Evidence bundle export and independent verify;
- [x] Egress gateway (Host override / coordination patterns / rates / heartbeat);
- [x] Live probes across four model families (9 runs, zero unauthorized external effects);
- [ ] Schema-structured model outputs (function calling);
- [ ] Real forwarding gateway with TLS termination;
- [ ] Credential broker and signed attestations with protected keys.
