# GKN-Phantom 双场景使用手册

> 适用版本：v5.11.0（v5.8-v5.11 新增四个知识域：**AI/LLM 应用安全**（`ai_llm_security.md`）、**小程序安全**（`miniprogram_security.md`）、**Android 组件审计 + APK 逆向**（`apk_recon.py` + `android_audit.md`/`apk_reversing.md`）、**Windows PE 逆向**（`pe_reversing.md`）；v5.7 新增纪律层 `AGENTS.md`、业务逻辑/越权方法论层 `business_logic.py`、触发信号路由表与中文化；v5.5 起匹配机制为 Trie/Aho-Corasick 预过滤，命令用法不变，扫描大响应更快）
> 适用场景：**护网行动（防守方自查/验证）** 与 **漏洞挖掘（授权 SRC / 众测 / 赏金）**
> 红线：所有使用必须以**书面授权**为前提。护网场景测的是己方资产；漏洞挖掘场景测的是 SRC 公告范围内的资产。越界即违法。

---

## 一、两个场景的本质差异（决定用法差异）

| 维度 | 护网行动（防守自查） | 漏洞挖掘（SRC/众测） |
|------|---------------------|----------------------|
| 授权深度 | 己方资产，可拿到凭据、源码、测试窗口 | 黑盒为主，仅公告范围内资产 |
| 目标 | **清零可利用面**：宁可误报不可漏报 | **高质量报告**：每条都要可复现、危害论证充分 |
| 节奏 | 护网前集中自查 + 护网期间持续回归 | 长期、分批、深挖单点 |
| safe_mode | 内网/预发可关（`--include-l4` 需审批） | **必须开启**，遵守厂商测试规范 |
| 凭据 | 应提供（AUTH_SETUP 全开） | 通常无；部分 SRC 提供测试账号 |
| 输出消费者 | 运维/开发（要修复清单） | SRC 审核员（要 PoC + 影响证明） |

---

## 二、护网行动场景

### 2.1 护网前 2 周：暴露面清查（被动 + 主动侦察）

目标：摸清"自己会挨打的入口"，先于攻击队发现自己。

```bash
# 1. 被动侦察：零接触，先做资产摸底（子域名/DNS/WHOIS/历史URL/GitHub泄露）
python scripts/passive_recon.py --domain example.com --output recon/passive.json

# 2. 技术指纹：确认每个资产跑的是什么（决定后续检测策略）
python scripts/tech_fingerprint.py --targets targets.txt --output recon/tech.json

# 3. 目录/敏感路径清查：116 条精选路径 + 20 种扩展名
python scripts/directory_fuzzer.py --targets targets.txt --output recon/dirs.json
```

**检查清单**（护网前必须清零的项）：

- [ ] `.git` / `.env` / `.DS_Store` / `phpinfo.php` 可外部访问
- [ ] Actuator / Druid / Swagger / UEditor 未授权
- [ ] 备份文件（`.zip/.tar.gz/.bak`）可下载
- [ ] 目录浏览（`Index of /`）
- [ ] SSL 弱协议/弱加密套件（`ssl_analyzer.py`，评级低于 A 的要整改）
- [ ] GitHub 泄露的密钥/内部地址（passive_recon 的 dork 输出人工过一遍）

### 2.2 护网前 1 周：快速对抗演练（Quick Combat）

目标：用攻击队视角快速打一遍，产出"今晚就能修"的清单。

```bash
python scripts/quick_combat.py \
  --targets targets.txt \
  --tech recon/tech.json \
  --output-dir ./combat_pre_hw/ \
  --severity critical,high,medium
```

- `--tech` 传入第 2 步的指纹结果，让 nuclei 模板选择更精准。
- 产出的 `combat_*/index.html` 直接分发给各系统负责人；`pocs/` 目录是可复制的验证命令。

### 2.3 护网前：深度审计（完整状态机）

对核心业务系统（支付、认证、数据中台）走完整管线：

```
SCOPE_CHECK → PRE_FLIGHT → PASSIVE_RECON → ACTIVE_RECON
→ AUTH_SETUP（提供测试账号凭据！）→ ACTIVE_TESTING（low→critical 全层级）
→ VALIDATION（复放验证 + 置信度评分）→ ATTACK_PATH_ANALYSIS → REPORT
```

护网场景特有配置建议：

```json
{
  "config": {
    "safe_mode": false,
    "require_human_approval": true,
    "rate_limit_rps": 10
  },
  "credentials": { "cookies": "...", "note": "预发环境测试账号" }
}
```

- `safe_mode: false` 解锁 SSRF/RCE 等 L4 探测（仅限预发/内网，生产禁用在侧）。
- **务必提供凭据**：护网中真正致命的是认证后的越权（IDOR/priv_esc）和逻辑缺陷，无凭据测试等于漏掉半个攻击面。
- `require_human_approval: true` 保留 L4 人工闸门，防止误伤。

### 2.4 护网期间：修复验证 + 持续回归

- 修复完成后，用对应 finding 的 PoC（`pocs/` 里的 curl/Python）单独复测，确认信号消失。
- 每日跑一遍 quick_combat，用 `manifest.json` 的 `by_severity` 对比昨日基线，发现"修 A 坏 B"或新上线系统带病。
- CI 集成：`report_generator` 产出 SARIF-like JSON，可接入流水线门禁（出现 high+ 即阻断发布）。

### 2.5 护网场景 Do / Don't

| Do | Don't |
|----|-------|
| 对生产只跑 L1-L2（被动侦察 + 非侵入探测） | 在生产窗口外跑 L4 探测 |
| 攻击链分析结果同步给 SOC，作为监控规则输入 | 只看单点漏洞，忽略 attack_paths 里的链式风险 |
| 用 `execution_trace.py` 留痕，应对护网审计 | 跳过 VALIDATION 直接拿扫描器结果交差 |

---

## 三、漏洞挖掘场景（授权 SRC / 众测）

### 3.1 铁律（厂商规范 + 法律边界）

1. 只测 SRC 公告**范围内**的资产；`scope_guard` 会把越界目标直接 ABORT——不要试图绕过它。
2. `safe_mode` 保持开启；不使用破坏性 payload；不碰真实用户数据（IDOR 验证用自己的两个账号做差分）。
3. 每个 finding 必须过 Reproducibility Gate——SRC 审核员只看可复现的东西，`unverified_leads[]` 交上去只会拉低信誉。

### 3.2 标准工作流

```bash
# Step 1: 被动侦察扩面（子域名是 SRC 挖掘的第一战场）
python scripts/passive_recon.py --domain target-src.com --output recon/

# Step 2: 对子域名批量存活探测 + 指纹
python scripts/tech_fingerprint.py --targets subdomains.txt --output recon/tech.json

# Step 3: Quick Combat 批量过筛（广撒网）
python scripts/quick_combat.py \
  --targets live_hosts.txt \
  --tech recon/tech.json \
  --severity critical,high,medium,low \
  --rate-limit 100
```

- 注意 severity 过滤加上 `low`：SRC 场景里 `component_exposure`、`info_leak` 这类低危也是有效提交（且常是深挖入口）。
- nuclei 模板被封顶时（manifest 里有 `Scope-limited` 提示），把目标按技术栈分组分批跑，避免高价值模板被挤掉。

### 3.3 深挖单点（从"发现"到"高危报告"）

Quick Combat 命中后的深挖路径（这是报告价值拉开差距的地方）：

| 命中信号 | 深挖动作 | 用到的模块 |
|----------|---------|-----------|
| `component_exposure` (Actuator) | 拉 `/actuator/heapdump`、`/actuator/env` 提取凭据 → 升级为数据泄露 | 手动 + httpRequest |
| `graphql_introspection` | 拉完整 schema → 找未授权 mutation/敏感字段 | `api_auditor.py` |
| `info_leak` (.git) | 还原源码 → 白盒找硬编码密钥/未授权接口 | git-dumper 类工具（手工） |
| 带参 URL | SQLi 报错/布尔/时间盲注（capped）、SSTI 算术反射 | `advanced_sqli.py` |
| 登录/注册接口 | 弱口令（bounded set）、验证码绕过、短信轰炸 | `vuln_detector.py` MEDIUM 层 |
| 任意业务功能 | 返回包篡改、价格/数量篡改、步骤跳过、重放 | `logic_flaw` 检测 |

每个深挖 finding 都要走完：

```
detected → PoC 生成（poc_generator）→ finding_validator 复放 ≥2 次
→ 控制请求对比 → 影响证明（读到了什么数据/拿到了什么会话）
→ attack_path.py 看能否成链 → 报告
```

### 3.4 提升报告过审率与定级的技巧

1. **影响证明是定级的核心**：同样的 SQLi，"存在注入"是 medium，"`current_user()` 回显 + 读出库名"是 high，"拖出 PII 样本（遵守最小化原则，脱敏展示）"才可能 critical。报告里写清**实际观察到的影响**，不要写理论影响。
2. **善用攻击链**：单点是 medium 的组合（如 组件泄露 → 拿到凭据 → 登录后台）在 `attack_path.py` 里成链后，按链的最终影响叙事，定级显著更高。
3. **`unverified_leads[]` 是你的线索队列**：本次复现不了的（WAF 拦截、需带内交互）记下来，换 `adaptive_engine` 的编码/变形策略隔日再试，或换 OOB 信道验证。
4. **去重**：`memory` 机制会对历史 finding 去重，重复提交前先查自己的历史报告，避免被 SRC 判重复。
5. **PoC 用 curl + raw_http 双格式提交**：审核员复现成本越低，过审越快。

### 3.5 漏洞挖掘场景 Do / Don't

| Do | Don't |
|----|-------|
| 严格遵守厂商 rate limit，把 `--rate-limit` 调到公告允许值以下 | 用默认 150 rps 猛冲（会被封 IP 且可能被取消成绩） |
| 弱口令/文件上传类测试走人工审批流程 | 上传真实 webshell、拖真实用户数据 |
| 把 `confidence_breakdown` 附在报告里增强说服力 | 把 nuclei 原始输出不加验证直接当漏洞提交 |

---

### 3.6 业务逻辑 / 越权 / 竞态（v5.7 新增）

业务逻辑不是"扫"出来的，是**建模 + 证明**出来的。SRC 的严重/高危档位很大比例落在这里，
而这块恰恰不能靠扫描器。工作流：**建板 → 建模五问 → 计划 → 交叉证明 → 判定 →（过门）成稿**。

```bash
# 1) 建板（任何目标的第一步）
python scripts/clueboard.py init --target <目标> --focus "订单/支付链路越权与金额篡改"

# 2) 业务建模五问 → 模型校验（errors 必须为空；gaps 要么补齐、要么记入线索板"未测"）
python scripts/business_logic.py model --file model.json

# 3) 出测试计划；--board-root 会把未决假设与角色矩阵待办直接写进线索板
python scripts/business_logic.py plan --file model.json --out plan.md \
  --board-root hunts --target <目标>

# 4) 越权：生成 A/B 交叉证明请求对（粘进 Burp Repeater 执行并截图）
python scripts/business_logic.py ab --url https://t/api/order/1001 \
  --owner-token "session=A" --attacker-token "session=B"

# 5) 竞态：生成速率受限的并发骨架（-P 已被压到授权速率，别手改大）
python scripts/business_logic.py race --endpoint https://t/api/coupon/claim \
  --replays 20 --authorized-rps 2

# 6) 判定：缺"先证伪/对照"证据会直接返回 inconclusive；退出码 0=pass / 1=fail / 2=inconclusive
python scripts/business_logic.py judge --file evidence.json
```

**两条硬标准（写报告前必须满足）**

- **越权**：**A 的资源必须用 B 的凭证读到**。无凭证请求也 200 → 那是未授权访问不是 IDOR；
  交叉返回 401/403 → 假设证伪，写 `clueboard.py add --section excluded` 且**不要上报**。
- **竞态**：成功次数 > 业务允许的唯一成功数 **＋** 观察到状态差异 **＋** 串行重放未复现，三条齐才算成立。

> **纪律层（v5.7）**：开工前读 `AGENTS.md`。**失败升级至少推进到 Level 4 才能写"无漏洞"结论**；
> L1-L3 失败只能写"该载荷被过滤"，不能写"不存在该漏洞"。并发度不得超过授权通告允许速率，生产禁跑。

---

## 四、能力现状与知识域覆盖

以下能力在 v5.1 中的现状，以及已规划升级（见改造方案）：

| 能力 | 状态 |
|------|------|
| quick 探针内容感知升级 | **已上线（v5.2）**：`escalate_severity()` — 密钥/.git 泄露/phpinfo/备份可达→high，PII 阈值→critical（与完整状态机同口径），升级附 `escalation_reason` |
| quick 模式影响验证 | **已上线（v5.3 C1）**：深挖适配器 — Actuator env 未脱敏凭据/heapdump 可达→critical、GraphQL schema+mutation 暴露→high、Swagger 无认证方案→high，自动记录 `deep_dive.impact` |
| 参数发现 + 注入探测 | **已上线（v5.3 C2）**：入口页自动提取同源带参 URL → 报错型 SQLi（6 引擎签名）+ SSTI 算术反射（基线差分）→ 直接产出 high findings |
| 认证后测试 | 完整状态机支持；护网场景直接可用，SRC 场景视厂商是否提供测试账号 |

v5.3 起 Quick Combat 的深挖层默认开启（`--no-deep` 可关）：命中即深挖、按证据升级。SRC 提交前仍建议人工复核 `escalation_reason` / `deep_dive.impact` 与证据的一致性。

### 知识域覆盖（v5.8-v5.11）

原先在 `references/knowledge_domains_roadmap.md` 中规划四个知识域，**现已全部落地**：

| 域 | 版本 | 手册 | 规则 | 关键口径 |
|----|------|------|------|----------|
| **AI/LLM 应用安全** | v5.8 | `references/ai_llm_security.md` | `rules/ai_llm_security.yaml`（11 条） | 注入按**行为差分**判（≥3 次复现 + 对照差异）；Agent 工具滥用**必须有落地回显**，模型"声称已执行"不算 |
| **小程序安全** | v5.9 | `references/miniprogram_security.md` | `rules/miniprogram_security.yaml`（8 条） | 云数据库测试**只读且限条数**；接口越权走 `business_logic.py ab` 的 A/B 硬标准 |
| **Android 组件 + APK 逆向** | v5.10 | `references/android_audit.md` · `references/apk_reversing.md` | `rules/android_security.yaml`（7 条） | 先 `apk_recon.py` 秒级快筛；组件类须给 **ADB 命令 + 实际效果** |
| **Windows PE 逆向** | v5.11 | `references/pe_reversing.md` | `rules/pe_security.yaml`（4 条） | 动态分析必须在**隔离 VM**；崩溃须证明**执行流可控** |

> 四域都**复用**既有的取证、判定与交付层（`business_logic.py` / `report_docx.py`），
> 不引入新的扫描引擎，所以过门口径与 Web 域**完全一致**。
> 各域"哪些证据才算数"的完整清单见 `SKILL.md` 的 **Domain invariants** 表。

---

## 五、常用命令速查

| 场景 | 命令 |
|------|------|
| 快速过筛 | `python scripts/quick_combat.py --targets t.txt --severity critical,high,medium` |
| 关闭深挖层（纯 v5.1 行为） | 加 `--no-deep` |
| 无 nuclei 环境 | 加 `--no-nuclei`（仅用内置探针） |
| 只看内置探针 | 加 `--no-nuclei --quick-probes-only` 等价行为 |
| 深度审计某层级 | `python scripts/vuln_detector.py --tier high --safe-mode` |
| 解锁 L4（仅护网内网） | `python scripts/vuln_detector.py --tier critical --no-safe-mode --include-l4` |
| SSL 基线检查 | `python scripts/ssl_analyzer.py --target host:443` |
| JS 泄露挖掘 | `python scripts/js_analyzer.py --target https://host/app.js` |
| 云配置检查 | `python scripts/cloud_security.py --target ...` |
| 生成可视化报告 | `python scripts/report_visualizer.py --findings findings.json` |
| 建/读线索板（跨会话续挖） | `python scripts/clueboard.py init --target T --focus "..."` ／ `brief --target T` |
| 业务逻辑测试计划 | `python scripts/business_logic.py plan --file model.json --board-root hunts --target T` |
| 越权 A/B 交叉证明 | `python scripts/business_logic.py ab --url U --owner-token A --attacker-token B` |
| 竞态重放骨架 | `python scripts/business_logic.py race --endpoint U --replays 20 --authorized-rps 2` |
| 证据判定（越权/竞态/逻辑） | `python scripts/business_logic.py judge --file evidence.json` |
| 出提交稿（先过六道硬门） | `python scripts/report_docx.py --findings f.json --unit X --shots shots/` |
| 只跑验证门不出稿 | `python scripts/report_docx.py --findings f.json --gate-only` |

> 完整脚本契约见 `references/script_contracts.md`；安全模型见 `references/safety_policy.md`。
