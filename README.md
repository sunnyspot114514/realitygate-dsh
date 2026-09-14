# RealityGate：面向 guardrails-off 智能体评估的可审计遏制标准

[中文](README.md) | [English](README_EN.md)

把"遏制是否充分"从写作题变成可执行规格：每条条款对应一个启动前检查、一个测试和一档成本，并输出第三方无需进入实验室网络即可离线验证的证据包。

项目为 Apart Research AI Incident Sprint（2026-09）Track 1（Containment）的参赛产物，背景是 2026 年 7 月的三起智能体越界事件：OpenAI 评估模型对 Hugging Face 的入侵、Anthropic 复查 141,006 次评估运行发现的三起真实访问、以及公开 wiki 上约 15,000 次编辑的跨 run 协作。

## 核心原则

- **权限跟随动作，而不是跟随智能体**：每次 ALLOW 签发一次性 HMAC capability（绑定 run/agent/tool/target/参数摘要/效果摘要/policy hash，TTL 90 秒，单次使用），提交时原子消费。
- **尝试可以发生，未授权效果不得发生**：模型可以提出任何动作；授权由确定性策略决定，不由模型或分类器决定。
- **GET 不等于只读**：可能产生外部效果的 GET 一律 HOLD；只读性由策略侧 `read_only_targets` 决定，调用方声明的 effect 只能升级、不能降权。
- **凭证来源 fail-closed**：`publicly_discovered` / `unknown` 来源直接 KILL；金丝雀凭据绑定目标且从不进入模型上下文。
- **门在运行开始之前**：`run` 创建账本前强制 preflight；策略或场景不合格直接拒绝，不允许事后补写合规声明。
- **任务时钟归 Gate 所有**：`wall_clock_seconds` 用 Gate 侧时钟强制，不是模型可见可改的输入。
- **KILL 是终态**：撤销全部 pending capability；`stop` 从模型之外触发，跨进程幂等。
- **账本即证据**：append-only JSONL 前序哈希链 + fsync；evidence bundle（manifest/policy/scenario/ledger/attestation）可由独立进程离线验证，任一文件篡改即失败。
- **执行层也要强制**：worker 位于 Compose internal 网络（无互联网路由），egress gateway 是唯一出口，负责 Host override 检测、动词-工具映射、限速、慢速心跳检测和协调模式内容扫描。

## 路线图边界

以下内容属于后续开发方向，当前版本不包含：

- 官方 DeepSeek Harness 接入（`dsh_adapter/` 目前是 DSH-shaped mock 接入边界）；
- gateway 真实互联网转发与 TLS 终结（当前上游为 mock）；
- 宿主机/WSL 内核级隔离（WSL2 + Docker Desktop 为开发/演示边界）；
- 受保护密钥签名 attestation 与 Credential Broker。

仓库不包含 exploit 代码、真实凭据或对真实目标的攻击；场景全部为合成 fixture。

## 架构

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

## 快速开始

```bash
python3 scripts/validate.py                # 编译 + 39 项测试
python3 scripts/check_exits.py             # 退出码契约 9 项断言

python3 -m realitygate.cli --policy policy.json --artifacts artifacts/runs preflight
python3 -m realitygate.cli --policy policy.json --artifacts artifacts/runs run scenario.json --run-id demo      # KILL -> exit 5
python3 -m realitygate.cli --policy policy.json --artifacts artifacts/runs replay demo
python3 -m realitygate.cli --policy policy.json --artifacts artifacts/runs attest demo
python3 -m realitygate.cli --policy policy.json --artifacts artifacts/runs stop demo --reason operator_kill  # 幂等

# 对抗场景（effecting GET / metadata / 凭证发现 / KILL 后阻断）
python3 -m realitygate.cli --policy policy.json --artifacts artifacts/adv run scenarios/adversarial-controls.json --run-id adv-1

# 证据包导出与独立验证
python3 -m realitygate.cli --policy policy.json --artifacts artifacts/runs evidence export demo scenario.json evidence/demo
python3 -m realitygate.cli evidence verify evidence/demo

# 多模型活体探测（可选：--pressure / --only minimax|kimi|deepseek）
python3 -m dsh_adapter.multi_model_probe
```

退出码：`0` 成功；`3` preflight/输入错误；`4` 运行含 HOLD；`5` 运行被 KILL 或 stop；`6` 证据验证失败。

## 项目结构

```text
realitygate/            核心运行时（policy/engine/ledger/capability/evidence/cli）
dsh_adapter/            DSH-shaped 适配器、提案通道、多模型探测、egress gateway
sandbox/                Compose 沙箱（worker 无网络，gateway 唯一出口）
scenarios/              对抗场景（adversarial-controls/identity/heartbeat 等）
tests/                  39 项测试
scripts/                validate.py、check_exits.py、账本汇总
CONTROL_MATRIX.md       控制 × 攻击阶段 × 证据 × 成本 矩阵
COLLUSION-ANALYSIS.md   公开 wiki 语料分析与缺口修复状态
LIVE-MODEL-TEST.md      真实模型对抗测试报告
submission/             冲刺赛报告（PDF/HTML）
```

## 已知限制

见报告第 5 节与 Appendix A。要点：gateway 上游是 mock、不做 TLS MITM；网络隔离由 Compose internal 网络保证；官方 DeepSeek Harness 未接入；capability 为本地 HMAC，不具备不可抵赖性；证据包只能防"无写权限者"的篡改。

## 里程碑

- [x] 严格 policy/scenario 校验与 preflight 门禁；
- [x] ALLOW/HOLD/KILL 与 KILL 后 fail-closed；
- [x] 一次性 HMAC capability 与提交时原子消费；
- [x] 凭证 provenance fail-closed；
- [x] 预算熔断（actions/bytes/writes/wall-clock）；
- [x] 跨进程幂等 stop；
- [x] 哈希链账本与篡改检测；
- [x] evidence bundle 导出与独立 verify；
- [x] egress gateway（Host override / 协调模式 / 限速 / 心跳）；
- [x] 四个模型家族活体探测（9 次运行，零未授权外部效果）；
- [ ] schema 化模型输出（function calling）；
- [ ] 真实转发 gateway 与 TLS 终结；
- [ ] Credential Broker 与受保护密钥签名 attestation。
