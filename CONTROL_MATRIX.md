# RealityGate v0.2 控制矩阵

核心原则：**Authority follows action, not agent**；**Attempt ≠ Effect**（模型可以尝试任何动作，但未经授权的动作不产生副作用）。

| 控制 | 报告原则 | 攻击链环节 | 实现 | 验收证据 | 成本 |
|---|---|---|---|---|---|
| 预承诺启动门禁 | §26 确定性策略 | 评估开始前 | `policy.validate_policy` + `cli run` 强制 preflight | preflight 输出、策略 hash；不合格场景不创建 ledger | 低 |
| Effect Descriptor | §27 效果描述符 | 全阶段 | `Action.effect`（external_effect/persistence/data_egress 等） | `effecting_read_requires_capability` HOLD | 低 |
| GET≠只读 | §5 HTTP method != effect | 外泄/写入 | effecting GET（external_effect=true）不自动放行 | scenarios/adversarial-controls.json 第三动作 HOLD | 低 |
| 一次性 capability | §1 权限跟随动作 | 工具执行 | HMAC 签名、TTL 90s、max_uses=1、绑定 run/agent/tool/target/args/effect | `capability_issued` 事件；篡改/过期/重放 consume 全部失败 | 低 |
| 凭证 provenance | §10 凭证来源 | 凭据发现 | origin 校验：publicly_discovered/unknown 直接 KILL | `credential_provenance_denied` KILL | 低 |
| 最小权限凭据 | §8/§9 凭证隔离 | 凭据访问/提权 | credential scope 校验 + canary 目标绑定 | `credential_scope_violation`/`production_credential_denied` | 低 |
| 默认拒绝未知出口 | §7 网络 Sandbox | 侦察/C2/metadata | egress 白名单外 HOLD/KILL（metadata IP 覆盖） | `unknown_egress` decision | 低 |
| 预算熔断 | §32 权限漂移 | 持续尝试/重试风暴 | max_actions/max_network_bytes/max_persistent_writes/wall_clock | `budget_exceeded:*` KILL | 低 |
| 敏感动作终止 | §18 不允许自我扩权 | K8s/供应链/外泄 | policy kill/sensitive tools | `run_killed`、terminated 状态 | 低 |
| KILL 后 fail-closed | §22 外部急停 | 横向移动/持续执行 | RunState 终态 + pending/capability 全部撤销 + adapter break | 后续动作不执行；`capabilities_revoked` 计数 | 低 |
| 独立外部 stop | §22 急停独立于 Agent | 运行中任意时刻 | `stop_run`（进程内）+ `stop_run_persisted`（跨进程，追加 run_killed 事件） | `realitygate.cli stop` 输出；重复停止幂等；账本链保持有效 | 低 |
| 执行结果绑定 | §24 现实状态验证 | 工具执行 | pending ALLOW action map + capability 消费 | 未授权/重复/终止后 result 被拒绝 | 低 |
| 审计完整性 | §23 账本不可改 | 全阶段 | JSONL 前序哈希链 + 损坏拒写 + fsync | `Ledger.verify`；篡改后 replay 失败 | 低 |
| 证据可验证 | §23/§30 事后审计 | 独立复核 | manifest 逐文件 SHA-256 + attestation 绑定 policy/ledger head | evidence verify 通过；任一文件篡改即失败（exit 6） | 低 |
| 容器隔离 | §4 Compute Sandbox | 执行环境 | Compose worker：non-root/read-only/cap_drop ALL/no-new-privileges/network none/tmpfs/PID/mem/CPU 限制 | compose config + 静态断言全 PASS | 中 |

## 五层边界（对照报告 §3）

| 层 | 控制对象 | 本项目覆盖 | 未覆盖（诚实声明） |
|---|---|---|---|
| Compute | CPU/进程/内核/文件 | Compose worker 资源与能力限制；fixture 路径约束 | 无 microVM/gVisor；WSL2 内核逃逸不在证明范围 |
| Network | DNS/HTTP/TCP/代理 | egress 白名单、metadata 探测阻断、tunnel 场景决策 | 无真实 egress gateway/代理进程；网络控制仅到决策层 |
| Credential | secret 生命周期 | scope/origin fail-closed；capability 非凭证 | 无 Credential Broker 进程；不发放真实 token |
| Tool | 工具拆分与风险分级 | allow/hold/kill/sensitive 工具表 + effect descriptor | 无真实工具执行器；executor 为 mock |
| State | 记忆/外部持久状态 | persistence 计数与预算；postcondition 字段 | 无跨 run 状态隔离服务；memory provenance 未建模 |

## 成本档位

| 档位 | 内容 | 适用 |
|---|---|---|
| Bronze | 本项目全部控制（单机、标准库、Compose） | 二线实验室/课程，约 1–2 天接入 |
| Silver | + 真实 egress gateway、Credential Broker、远程 append-only 账本 | 中型实验室，约 1–2 周 |
| Gold | + microVM/gVisor、签名 attestation、第三方审计 | Frontier lab，需基础设施与外部审计 |

## 责任边界（not_claimed）

本项目证明的是 RealityGate adapter 观察到的动作决策与本地 Compose 配置。**不证明**：宿主机/WSL 内核抗逃逸；adapter 之外没有旁路；真实 DSH 集成（`dsh_adapter/` 是集成边界，官方 DeepSeek Harness 未接入）；HMAC capability 的不可抵赖性（密钥为本地派生，非硬件保护）；证据包可防持有写权限者的整体伪造。真实模型、真实凭据、真实外部目标、真实通知服务均不在范围。

## 对抗验收命令

```bash
cd /home/sunny/projects/realitygate-dsh
python3 -m unittest discover -s tests -t . -v          # 18 项全过
python3 -m realitygate.cli --policy policy.json --artifacts artifacts/adv run scenarios/adversarial-controls.json --run-id adv-1   # 退出码 5
python3 -m realitygate.cli --policy policy.json --artifacts artifacts/adv stop adv-1 --reason operator_kill   # 幂等
docker compose -f sandbox/compose.yaml config --quiet   # PASS
```
