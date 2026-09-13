# RealityGate v0.2 — Pre-committed containment for agent evaluations

核心原则：**Authority follows action, not agent**；**Attempt ≠ Effect**。模型可以提出任何动作，但未经一次性、范围绑定、可撤销授权的动作不产生副作用。

设计对照《长程 AI Agent Sandbox、凭证与 Runtime 安全设计分析报告》：逐项映射见 [CONTROL_MATRIX.md](CONTROL_MATRIX.md)。

## 核心控制

- **预承诺门禁**：`run` 在创建账本前强制 preflight；policy/scenario 不合格直接拒绝（exit 3）。
- **Effect Descriptor**：动作携带结构化效果声明；`external_effect=true` 的 GET 不再自动放行（HTTP method != effect）。
- **一次性 capability**：每次 ALLOW 签发 HMAC 签名、TTL 90s、单次使用的授权票据，绑定 run/agent/tool/target/args/effect digest/policy hash。篡改、过期、重放全部拒绝。
- **凭证 provenance**：`publicly_discovered`/`unknown` 来源直接 KILL；production scope 永不下发。
- **预算熔断**：max_actions / max_network_bytes / max_persistent_writes / wall_clock_seconds，超限 KILL。
- **独立外部 stop**：`stop` 命令从模型之外终止运行；进程内撤销全部 pending capability；跨进程通过追加 `run_killed` 账本事件实现，重复停止幂等。
- **KILL fail-closed**：终态后一切动作返回 `run_already_terminated`，adapter 立即停止队列，不执行任何后续工具。
- **哈希链账本**：append-only JSONL，逐事件前序哈希 + fsync；损坏账本拒绝追加。
- **可验证证据包**：manifest 逐文件 SHA-256 + attestation 绑定 policy/ledger head；独立进程 verify，任一文件篡改即失败（exit 6）。

### v0.3：执行层强制（针对 collusion.wiki 实证缺口，见 COLLUSION-ANALYSIS.md）

- **egress gateway**（`dsh_adapter/egress_gateway.py`）：worker 在 Compose internal 网络中无互联网路由，网关是唯一出口——**网络层的 Attempt ≠ Effect**。执行 Host override / absolute-URI / X-Forwarded-Host 检测（`host_override_suspected`）、动词↔工具映射的 kill 工具再生效（`policy_kill_tool`）、独立哈希链审计。
- **协调模式内容扫描**：R1–R5 任务键、MONdd 时间约定、relay/beacon/callsign 词汇（正则移植自 collusion.wiki 语料分析），命中即 `coordination_pattern_detected:*` 拒绝 + 告警事件。
- **慢速心跳检测**：决策层与网关层双重滑窗检测规律性低频写入（`heartbeat_suspected`），`max_actions` 拦不住的 beacon 模式被时间方差规则捕获。
- **身份创建控制**：`identity_tools` + `identity_effect` 命中 KILL（`identity_creation_denied`）——对应假冒管理员、一次性邮箱。
- **Gate 侧可信时钟**：`wall_clock_seconds` 用 gate 时钟强制（`budget_exceeded:wall_clock`），任务时钟不是 agent 可改输入。
- **public-sink mock**：对公共状态模拟器的写入默认拒绝（`write_requires_capability`），跨 run 隔离可验证。

## WSL 运行

```bash
cd /home/sunny/projects/realitygate-dsh

python3 scripts/validate.py        # 编译 + 全部测试（18 项）

python3 -m realitygate.cli --policy policy.json --artifacts artifacts/runs preflight
python3 -m realitygate.cli --policy policy.json --artifacts artifacts/runs run scenario.json --run-id demo    # KILL → exit 5
python3 -m realitygate.cli --policy policy.json --artifacts artifacts/runs replay demo
python3 -m realitygate.cli --policy policy.json --artifacts artifacts/runs attest demo
python3 -m realitygate.cli --policy policy.json --artifacts artifacts/runs stop demo --reason operator_kill   # 幂等

# 对抗场景（effecting GET / metadata / 凭证发现 / KILL 后阻断）
python3 -m realitygate.cli --policy policy.json --artifacts artifacts/adv run scenarios/adversarial-controls.json --run-id adv-1

# 证据包导出与独立验证
python3 -m realitygate.cli --policy policy.json --artifacts artifacts/runs evidence export demo scenario.json evidence/demo
python3 -m realitygate.cli evidence verify evidence/demo

# Python 级退出码契约验收（9 项）
python3 scripts/check_exits.py
```

退出码契约：`0` 成功 / `3` preflight 或输入错误 / `4` 运行含 HOLD / `5` 运行被 KILL 或 stop / `6` 证据验证失败。

## Docker 沙箱

```bash
docker compose -f sandbox/compose.yaml config --quiet   # 静态校验
```

worker：non-root(10001)、read-only、cap_drop ALL、no-new-privileges、`network_mode: none`、tmpfs /tmp noexec、PID/mem/CPU 限制、无宿主挂载、无 Docker socket、无注入凭据。mock-response 使用显式 `mock` profile、internal-only 网络、healthcheck。

注意：基础镜像 `python:3.12-slim` 未固定 digest，且本环境曾因 Docker Hub registry EOF 无法完成构建；镜像构建/运行验证未完成时不声称运行时隔离已实测。

## 已验证 / 未声明

已验证（见 CONTROL_MATRIX.md 验收命令）：39 项测试、退出码契约 9 项、对抗场景决策序列（含 identity/heartbeat/cross-run-sink 新场景）、证据篡改检测、跨进程 stop 幂等、Compose 静态安全断言、网关 Host override/协调模式/速率/心跳单测、**真实模型对抗测试三轮**（见 [LIVE-MODEL-TEST.md](LIVE-MODEL-TEST.md)）。

**未声明（not_claimed）**：宿主机/WSL 内核抗逃逸；adapter 之外的旁路；官方 DeepSeek Harness 集成（`dsh_adapter/` 是集成边界，官方 DSH 未接入）；capability 的不可抵赖性（本地派生 HMAC 密钥，非硬件保护）；证据包可防持有写权限者的整体伪造；**egress gateway 不转发真实互联网（mock 上游）、不做 TLS MITM**，网络路由隔离由 Compose internal 网络保证而非自建防火墙；网关内容扫描在真实语料上会有误报，需要调参；真实模型/真实凭据/真实外部目标/真实通知服务（模型测试用 ZCode 托管 LLM，目标均为 mock）。
