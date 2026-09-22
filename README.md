# 🦞 GKN-Phantom

> **Production-grade automated penetration testing skill for the OpenClaw AI Agent Framework.**

[![Version](https://img.shields.io/badge/version-5.11.0-blue)](https://github.com/yuanguin37/GKN-Phantom/releases)
[![OpenClaw](https://img.shields.io/badge/OpenClaw-Skill-orange)](https://openclaw.ai)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)]()
[![Modules](https://img.shields.io/badge/modules-39-brightgreen)]()

GKN-Phantom 是一个面向 OpenClaw AI Agent 框架的工业级自动化渗透测试技能包。v5.11 配备 **39 个模块**，覆盖 **38 种漏洞类型**（= `payload_playbook.md` 22 类 + `advanced_payload_playbook.md` 16 类），支持 **25+ 种 WAF 识别**与绕过策略，**20+ 条攻击链模式**，在严格的 **Scope Guard · Risk Gate · Rate Limiter** 三重安全模型下，执行全生命周期安全验证：从零触碰被动侦察、主动资产发现、分层漏洞检测、交互式浏览器认证、证据验证、攻击路径分析到专业可视化报告生成。

**四个新知识域**（v5.8-v5.11，把能力从 Web 扩展到 AI、小程序、移动端与二进制）：**v5.8 AI/LLM 应用安全**（提示词注入 · 间接注入 · System Prompt 泄露 · RAG 投毒 · 记忆污染 · **Agent 工具滥用** · 过度授权 · 沙箱逃逸 · 输出侧 XSS，11 类检测项 + 12 节手册）；**v5.9 小程序安全**（微信/支付宝/抖音/百度 + 微信云开发：取包 → 反编译 → 接口/密钥提取 → 云数据库与云函数越权，接口越权沿用 Web 的 A/B 硬标准）；**v5.10 Android 组件审计 + APK 逆向**（`apk_recon.py` **纯标准库秒级快筛**：自研二进制 AXML 解析器直接出组件矩阵与导出风险，附加固指纹识别、密钥/端点速筛；组件类必须给 ADB 命令 + 实际效果）；**v5.11 Windows PE 逆向**（PE 结构/保护机制/加壳识别 → 隔离环境动态行为 → 内存破坏与 DLL 劫持定位）。

**执行纪律层**（v5.7 新增）：`AGENTS.md` 是 `SKILL.md` 之外的**行为纪律总纲**——十条执行纪律（JS 不吃透不发包、覆盖度自检、失败升级 Level 1-7、跨接口关联五问、暂停思考触发条件…）、**"至少推进到 Level 4 才能下『无漏洞』结论"** 的硬规、可利用性六问、触发信号→模块路由表。能写进代码的纪律已经写进代码（覆盖度落线索板、未决假设上限 5 条、重复线索拒绝）。**它不能放宽任何安全模型约束**：Scope Guard 不可绕过。

**业务逻辑 / 越权方法论层**（v5.7 新增）：`business_logic.py` 把 `logic_flaw`/`race_condition`/`mass_assignment` 从"检测规则"变成"工作流"——业务建模五问 → 测试计划（跳步/回放/覆盖 + 角色矩阵 + 竞态目标）→ **越权 A/B 交叉证明请求对** → 证据判定（`pass`/`fail`/`inconclusive`，退出码 0/1/2）。**它不发包，只出计划与判定**；判定口径与 `report_docx.py` 的类型命门对齐——缺"先证伪"证据时直接拒绝给出 `pass`。

**触发信号路由表 + 中文化**（v5.7 新增）：`SKILL.md` 新增场景→模块、漏洞类型→模块、SRC 高价值优先级与组合场景四张路由表；补中文触发短语（渗透测试/打点/漏洞挖掘/越权/出报告/线索板…）与**结论先行的输出骨架**（结论 → 影响资产 → 可利用性 → 证据 → 根因 → 修复 → 覆盖度）。

**跨会话线索板**（v5.6 新增）：`clueboard.py` 为每个目标维护一份人类可读的 Markdown 台账 `hunts/<目标>/CLUEBOARD.md` —— 未决假设（含"怎么证伪"）、Host 地图、路径/方法、密钥/协议、**已排除（防止下轮重测）**、覆盖度。`state.py` 只管机器态（阶段/检查点），本模块管**判断与线索**：上下文压缩或换会话后先 `brief` 读板再开挖，同一线索重复录入会被拒绝并标注 `[重复]`，未决假设上限 5 条强制收敛。

**提交级交付层**（v5.6 新增）：`report_docx.py` 把 `validated` finding 变成 SRC / CNVD / EDUSRC 平台真正接收的 **DOCX**（固定 Heading 2 骨架 + Step 式 PoC + 内嵌真实截图 + 语义化命名 `资产 存在 漏洞类型 漏洞.docx`）。**未过分层验证门的 finding 一律不写进报告**——硬门 0-5：先证伪 / PoC 可复现（重放 ≥2）/ 危害为链路终局 / 服务端边界确认 / 类型命门 / 链式追问到终局；缺截图会明确告警而非静默跳过；交付前跑去 AI 腔自检；无 python-docx 时降级为纯验证门。

**模式匹配引擎**（v5.5 新增）：`pattern_matcher.py` 以 **Trie + Aho-Corasick 自动机** 重构全部多模式匹配热路径——技术栈指纹、WAF 检测、JS 密钥/危险Sink 扫描、DB 报错指纹、HTML 技术检测。每条响应只做**一次 AC 扫描**，仅执行"必需字面量确实出现"的正则（可靠字面量提取器保证结果与逐条扫描**完全一致**，并有属性测试背书）。**提速幅度取决于模式集规模与响应体长度**：模式越多、响应越大收益越明显；模式集较小或响应体较短时门控开销大于收益，此时自动回落朴素路径（在 8 模式 × 60KB 响应体下实测为 0.73x，即回落路径更快）。

**Quick Combat 一键管线**（v5.1 引入，v5.4 大幅强化）：`quick_combat.py` 单命令完成 检测 → 深挖 → PoC → 利用脚本 的实战闭环——nuclei 快扫 + 内置探针 + **国内组件/OA 未授权指纹库**（泛微/致远/通达/用友/禅道/JeecgBoot/若依等 32 条探针，含 queryFieldBySql 一键 SQL 验证）+ **katana 全站爬取喂参数注入探测** + **JS 深挖链**（密钥泄露 → 隐藏端点 → 主动探测）+ **真实 OOB 带外信道**（interactsh/ceye/dnslog，盲 SSRF 回调确认即 validated）+ **跨运行去重记忆**（`[已提交]/[重复]` 标注防 SRC 重复提交扣分）。

---

## ✨ 核心特性

| 特性 | 说明 |
|------|------|
| 🔒 **三重安全模型** | Scope Guard（范围检查）+ Risk Gate（L1-L4风险分级）+ Rate Limiter（令牌桶限速） |
| 🎯 **38 种漏洞检测** | 覆盖 LOW → MEDIUM → HIGH → CRITICAL 四个严重级别 |
| 🕵️ **零触碰被动侦察** (v4) | crt.sh · DNS自建客户端 · WHOIS · Wayback Machine · GitHub秘密搜索 · 邮箱枚举 |
| 🔬 **深度主动侦察** (v4) | nmap端口扫描 · SSL/TLS安全分析 · 技术栈指纹识别（200+签名） · 智能目录爆破（116路径+20扩展名） |
| 💉 **专业SQL注入引擎** (v4) | 6种数据库指纹 · 5种提取策略（报错/布尔盲注/时间盲注/UNION/OOB） · 二阶注入 · 10类WAF绕过 |
| ⚡ **Nuclei模板集成** (v4) | 自动检测 · 80+技术到标签映射 · 执行时间预估 · SHA-256去重 · 未安装时回退手动指南 |
| 🛡️ **高级WAF绕过** (v4) | 协议级绕过 · 6种编码绕过 · 38种混淆生成器 · 10种WAF专用规则 · HPP · Content-Type切换 |
| 🌐 **交互式浏览器代理** (v5) | Playwright驱动多步骤认证 · 验证码/MFA/2FA处理 · 会话持久化 · JS执行 · 截图取证 |
| 📋 **专业PoC生成** (v5) | curl命令 · Python脚本 · HAR 1.2归档 · Markdown复现步骤 · 安全级别分类 |
| 🧠 **自适应探测引擎** | 失败自动重试（指数退避） · Payload变异绕过WAF（25+种） · 20+备用信号集 |
| 🛡️ **预飞行安全模拟** | dry-run模式 · 目标风险评分（0-100） · 自动收窄扫描范围 |
| 📊 **多因子置信度评分** | 证据强度+复现性+信号清晰度+佐证，≥0.80才升级为validated |
| 🔗 **20+攻击链分析** | SSRF→云元数据 · SQLi→凭证窃取 · SSTI→RCE · 原型污染→提权 · HTTP走私→投毒 |
| 📊 **可视化报告** (v5) | HTML仪表盘（SVG风险仪表+发现卡片+攻击路径图+资产表+修复矩阵+暗色模式） · PDF导出 |
| ⚙️ **规则配置化** (v5) | YAML/JSON规则定义 · 热加载 · 社区可扩展 · 无需修改Python代码即可添加检测规则 |
| ⚔️ **Quick Combat 一键管线** (v5.1-v5.3) | 单命令 detect → deep-dive → PoC → exploit · 影响升级层（响应内容重定级）· 深挖适配器（Actuator/GraphQL/Swagger）· 参数发现+有界SQLi/SSTI探测 |
| 🇨🇳 **国内组件/OA 探针库** (v5.4) | 32 条探针：泛微 e-cology（BeanShell/Ssologin//services/）· 致远 · 通达 · 用友 · 禅道 · JeecgBoot（jmreport queryFieldBySql 一键 SQL 验证）· 若依（druid 变体）· 帆软/亿邮/金蝶/蓝凌/红帆/万户 · POST 验证器 + 软 404 黑名单防误报 |
| 🕸️ **katana 全站爬取** (v5.4) | 有 katana 时全站爬取（深度 3），所有带参 URL 喂参数注入探测——SQLi/SSTi 覆盖从"首页参数"扩展到"全站面"；无 katana 自动回退单页 |
| 🔍 **JS 深挖链** (v5.4) | JS bundle 分析（密钥/危险Sink/调试端点）+ 隐藏端点提取（`extract_endpoint_entries`）回喂注入探测——JS 侦察链入主动探测 |
| 📡 **真实 OOB 带外信道** (v5.4) | interactsh 自托管/ceye.io/dnslog.cn 三通道 · 替换静态占位符 · 盲 SSRF 回调确认即产出 **validated** 级 finding（直接进 PoC/利用生成） |
| 🧠 **跨运行去重记忆** (v5.4) | finding 指纹持久化到 `combat_memory.json` · 重扫自动标注 `[已提交]/[重复]` · 防 SRC 平台重复提交扣分降信誉 |
| 🧠 **跨会话线索板** (v5.6) | `clueboard.py`：每目标一份 `hunts/<目标>/CLUEBOARD.md` —— 未决假设（含"怎么证伪"）· Host 地图 · 路径/方法 · 密钥/协议 · **已排除（防止下轮重测）** · 覆盖度自检；与 `state.py` 机器态职责分离，重复线索拒绝并标注 `[重复]`，未决假设上限 5 条 |
| 📄 **提交级 DOCX 交付** (v5.6) | `report_docx.py`：**分层验证门**（硬门0-5 + 类型命门，未过门不写报告）· SRC 骨架 / 0day 通用型模板双模式 · Step 式 PoC（Burp 原始请求块，不用 curl）· **截图铁律**（缺图告警而非静默跳过）· 语义化命名 · 交付前四项查重 · 去 AI 腔自检 |
| ⚙️ **模式匹配引擎** (v5.5) | `pattern_matcher.py`：Trie + Aho-Corasick 自动机（delta 完全转移表，单遍 O(n+命中)）· 正则必需字面量 DNF 提取器 · `PrefilteredRegexSet` 只跑可能命中的正则 · 技术指纹/WAF检测/JS扫描/DB指纹/HTML检测全线接入 · 结果与朴素扫描逐字节一致（属性测试）· 收益随模式数与响应体规模增长，小模式集/短响应自动朴素回退 |
| 🧠 **执行纪律层** (v5.7) | `AGENTS.md`：十条执行纪律（JS 不吃透不发包 / 覆盖度自检 / 失败升级 / 跨接口关联五问 / 暂停思考）+ **Level 1-7 升级阶梯**（"至少到 L4 才能下『无漏洞』结论"）+ 可利用性六问；**不可放宽** Scope Guard / Risk Gate / Rate Limiter |
| 🧩 **业务逻辑 · 越权 · 竞态方法论** (v5.7) | `business_logic.py`：建模五问校验 · 测试计划（跳步/回放/覆盖 + 角色矩阵 + 竞态目标）· **A/B 交叉证明请求对**（基线/交叉/无凭证对照）· **速率受限**并发重放骨架 · 证据判定 `pass`/`fail`/`inconclusive` · 可写回线索板；与 `report_docx` 类型命门同口径 |
| 🧭 **触发信号路由表** (v5.7) | `SKILL.md`：场景→模块（16 行）· 漏洞类型→模块（10 行）· SRC 高价值优先级 · 组合场景编排；命中触发信号即加载对应模块深挖，替代线性推进 |
| 🇨🇳 **中文本地化** (v5.7) | 中文触发短语（渗透测试/打点/漏洞挖掘/越权/业务逻辑/并发竞态/出报告/提交稿/线索板）· **结论先行输出骨架**（结论→资产→可利用性→证据→根因→修复→覆盖度）· 危害等级仅"建议"，CVSS 不自评 |
| 🤖 **AI/LLM 应用安全域** (v5.8) | `references/ai_llm_security.md` + `rules/ai_llm_security.yaml`（11 条）：五层攻击面（输入/检索/编排/执行/输出）· 12 类检测项（直接与间接注入 · System Prompt 泄露 · 越狱 · 数据泄露 · RAG 投毒 · 记忆污染 · **Agent 工具滥用** · 过度授权 · 沙箱逃逸 · 工具描述投毒 · 输出侧 XSS）· **行为差分判定**（同一 payload ≥3 次一致 + 对照请求输出差异）· 新增 `prompt_injection` / `agent_tool_abuse` 类型命门（**模型"声称已执行"不算证据，必须有落地回显**） |
| 📱 **小程序安全域** (v5.9) | `references/miniprogram_security.md` + `rules/miniprogram_security.yaml`（8 条）：取包 → 反编译 → 接口/密钥提取 → 越权验证四段链路 · 微信云开发三层面（云数据库权限规则 / 云函数调用方校验 / 云存储遍历）· 登录链路（code2session · session_key · 手机号解密）与支付链路（金额服务端重算 · 回调验签）· **接口越权沿用 Web 的 `idor` A/B 硬标准，不因"是小程序"放低** |
| 📦 **Android 组件审计 + APK 逆向** (v5.10) | `scripts/apk_recon.py`（**纯标准库 · 秒级**：自研二进制 AXML 解析器 → 组件矩阵与导出风险判定 · 加固特征 so 识别 · dex 字符串与 assets 的密钥/端点速筛，密钥自动脱敏）· `references/android_audit.md`（9 类组件检测 + ADB 可复现命令 + **无 Frida/无 Root 降级路径**）· `references/apk_reversing.md`（壳识别 → 脱壳 → 全量还原三段流水线）· 组件类须过 `adb_repro_cmd` + `effect_proof` 命门 |
| 🪟 **Windows PE 逆向域** (v5.11) | `references/pe_reversing.md` + `rules/pe_security.yaml`（4 条）：PE 结构必查表（TLS 回调 · 节熵 · 导入表 · `DllCharacteristics`）· 加壳四类信号（节名/EP 位置/节熵/导入表）· 隔离环境动态行为监控与反调试识别 · 内存破坏（栈堆溢出 · 格式化字符串 · UAF · 整数溢出）与 DLL 劫持三兄弟辨析 · **静态可疑点仅为 lead，崩溃必须证明可控、劫持必须证明被加载** |
| 🔄 **状态恢复系统** | checkpoint重试 · 部分状态恢复 · 失败回滚到安全前态 |
| 📊 **SARIF 2.1.0 输出** | CI/CD兼容，partialFingerprints基线去重 |
| 🔌 **工具自动检测** | nuclei · subfinder · httpx · ffuf · amass · katana · naabu 自动检测，缺失时回退纯Python实现 |
| ⏯️ **断点续扫** | 状态机持久化，任意阶段中断后继续 |

---

## 🧩 支持的漏洞类型

| 严重级别 | 漏洞类型 |
|----------|----------|
| **CRITICAL** | RCE, 认证绕过（auth_bypass）, 权限提升（priv_esc）, 数据泄露（data_exposure）, HTTP请求走私（http_smuggling） |
| **HIGH** | SQL注入（sqli）, 存储型XSS, SSRF, IDOR, 文件上传（file_upload）, 逻辑缺陷（logic_flaw）, NoSQL注入（nosql_injection）, LDAP注入（ldap_injection）, GraphQL注入（graphql_injection）, 缓存投毒（cache_poisoning）, 条件竞争（race_condition）, 原型污染（prototype_pollution）, JWT深度分析（jwt_deep_analysis）, OAuth配置缺陷（oauth_misconfig）, 批量赋值（mass_assignment）, 依赖混淆（dependency_confusion） |
| **MEDIUM** | 反射型XSS, 路径遍历（path_traversal）, XXE, SSTI, 命令注入（command_injection）, CSRF, 弱口令（weak_credential）, 验证码绕过（captcha_bypass）, 反序列化（deserialization）, CRLF注入（crlf_injection）, CORS配置缺陷（cors_misconfig）, 子域名接管（subdomain_takeover）, Host头注入（host_header_injection）, WebSocket劫持（websocket_hijacking）, Session固定（session_fixation）, 邮件头注入（email_injection） |
| **LOW** | 信息泄露（info_leak）, 开放重定向（open_redirect）, CSRF（弱令牌）, 安全配置错误（misconfig）, 组件未授权（component_exposure）, GraphQL内省（graphql_introspection）, 目录列表（directory_listing） |

**v5.8-v5.11 新增知识域漏洞类型**（与上面共用同一套验证门，"哪些证据才算数"逐类型定义见 `SKILL.md` 的 Domain invariants）

| 域 | 漏洞类型 |
|----|----------|
| **AI/LLM** (v5.8) | 提示词注入（prompt_injection）· Agent工具滥用（agent_tool_abuse）· 系统提示泄露（system_prompt_leak）· 越狱绕过（jailbreak）· 大模型数据泄露（llm_data_exposure）· RAG投毒（rag_poisoning）· 记忆污染（memory_poisoning）· 过度授权（excessive_agency）· 沙箱逃逸（sandbox_escape）· 工具描述投毒（llm_supply_chain）· 输出渲染XSS（llm_output_xss） |
| **小程序** (v5.9) | 硬编码密钥（hardcoded_secret）· 小程序接口越权（mp_api_idor）· 云数据库越权（cloud_db_exposure）· 云函数滥用（cloud_function_abuse）· 登录逻辑缺陷（mp_login_logic）· 支付逻辑缺陷（mp_payment_logic）· 包信息泄露（mp_package_disclosure）· 小程序渲染注入（mp_render_injection） |
| **Android** (v5.10) | 导出组件未授权（android_component_exposure）· WebView桥缺陷（android_webview_bridge）· ContentProvider暴露（android_provider_exposure）· Intent重定向（android_intent_redirect）· Binder越权（android_binder_privilege）· PendingIntent劫持（android_pendingintent_hijack）· DeepLink劫持（android_deeplink_hijack） |
| **Windows PE** (v5.11) | 内存破坏（memory_corruption）· 格式化字符串（format_string）· DLL劫持（dll_hijacking）· 保护机制缺失（missing_mitigation） |

---

## 🏗️ 架构设计

```
                        ┌─────────────────────────────────────┐
                        │        GKN-Phantom v5.5 Pipeline      │
                        ├──────────┬──────────┬────────────────┤
                        │  INIT    │  SCOPE   │  PRE_FLIGHT    │
                        │          │  CHECK   │  (dry-run)     │
                        ├──────────┼──────────┼────────────────┤
                        │ PASSIVE  │  ACTIVE  │  AUTH_SETUP    │
                        │  RECON   │  RECON   │  (optional)    │
                        ├──────────┼──────────┼────────────────┤
                        │  ACTIVE  │VALIDATION│  ATTACK PATH   │
                        │ TESTING  │          │  ANALYSIS      │
                        ├──────────┴──────────┴────────────────┤
                        │         REPORT GENERATION             │
                        │    (JSON + SARIF + HTML + PDF)        │
                        └──────────────────────────────────────┘
                                      │
                            ┌─────────▼─────────┐
                            │  三重安全模型       │
                            │  Scope Guard      │
                            │  Risk Gate (L1-L4)│
                            │  Rate Limiter     │
                            └───────────────────┘
```

### 11 阶段状态机

| 阶段 | 功能 | 关键脚本 |
|------|------|----------|
| **INIT** | 输入验证、配置加载、状态初始化 | `utils.py`, `state.py` |
| **SCOPE_CHECK** | 所有目标范围校验，任何越界即中止 | `scope_guard.py` |
| **PRE_FLIGHT** | dry-run模拟、目标风险评分、自动收窄范围 | `safety_simulator.py` |
| **PASSIVE_RECON** (v4) | 零触碰情报收集：crt.sh/DNS/WHOIS/Wayback/GitHub/邮箱 | `passive_recon.py` |
| **ACTIVE_RECON** (v4) | 端口扫描+目录爆破+技术指纹+SSL分析 | `directory_fuzzer.py`, `tech_fingerprint.py`, `ssl_analyzer.py` |
| **AUTH_SETUP** | 认证会话建立，支持浏览器交互式登录 | `browser_agent.py` (v5) |
| **ACTIVE_TESTING** | 分层漏洞探测（12个专项模块），自适应引擎处理失败/WAF | `vuln_detector.py`, `adaptive_engine.py`, `advanced_sqli.py`, `nuclei_runner.py`, `waf_evasion.py`, `js_analyzer.py`, `advanced_injection.py`, `api_auditor.py`, `cloud_security.py` |
| **VALIDATION** | 证据复验、TP/FP分类、多因子置信度评分 | `finding_validator.py`, `confidence_scoring.py`, `decision_engine.py` |
| **ATTACK_PATH_ANALYSIS** | 20+攻击链模式分析 | `attack_path.py` |
| **REPORT_GENERATION** | 多格式报告：JSON + SARIF + HTML + PDF | `report_generator.py`, `report_visualizer.py` (v5), `poc_generator.py` (v5) |
| **DONE** | 持久化状态，返回最终结果 | `state.py` |

---

## 📦 目录结构

```
GKN-Phantom/
├── SKILL.md                         # 技能主契约（能做什么、接口是什么，v5.11）
├── AGENTS.md                        # 执行纪律总纲（怎样才算专业地做，v5.7）
├── USAGE_GUIDE.md                   # 双场景使用手册（护网 / SRC）
├── README.md                        # 本文件
├── scripts/                         # 可执行脚本（39 个）
│   ├── utils.py                     # 共享工具：JSON I/O、DNS解析、指纹、去重
│   ├── pattern_matcher.py           # 模式匹配引擎 (v5.5)：Trie + AC自动机 + 正则字面量预过滤
│   ├── state.py                     # 状态序列化器：原子checkpoint、断点恢复
│   ├── state_recovery.py            # 状态恢复：checkpoint重试/部分恢复/失败回滚
│   ├── scope_guard.py               # 范围守卫：域名/IP/CIDR/路径校验
│   ├── rate_limiter.py              # 令牌桶速率限制器
│   ├── safety_simulator.py          # 安全模拟器：dry-run/风险评分/范围收窄
│   ├── vuln_detector.py             # 分层漏洞检测引擎（38种类型）
│   ├── adaptive_engine.py           # 自适应引擎：25+WAF识别/38类型变异/20+备用信号
│   ├── finding_validator.py         # 发现验证器：TP/FP分类
│   ├── confidence_scoring.py        # 置信度评分：多因子加权
│   ├── decision_engine.py           # 启发式决策引擎（可选插件）
│   ├── execution_trace.py           # 执行追踪：固定决策记录/回放验证/diff
│   ├── attack_path.py               # 攻击路径图构建器（20+攻击链模式）
│   ├── report_generator.py          # JSON/SARIF报告生成器
│   │
│   │   # ── v3 专项模块 ──
│   ├── js_analyzer.py               # JS静态分析：密钥泄露/危险Sink/原型污染/弱加密
│   ├── cve_correlator.py            # CVE关联：技术栈CVE匹配/CVSS评分/漏洞利用
│   ├── advanced_injection.py        # 高级注入：NoSQL/LDAP/CRLF/走私/投毒/条件竞争
│   ├── api_auditor.py               # API审计：GraphQL/REST/WebSocket安全检测
│   ├── cloud_security.py            # 云安全：S3/K8s/Docker/元数据/容器镜像检测
│   │
│   │   # ── v4 新增模块 ──
│   ├── passive_recon.py             # 被动侦察：crt.sh/DNS/WHOIS/Wayback/GitHub/邮箱
│   ├── directory_fuzzer.py          # 目录爆破：10词表类别/SimHash 404检测/递归/技术优先
│   ├── advanced_sqli.py             # SQL注入引擎：6引擎/5提取策略/二阶注入/10类WAF绕过
│   ├── ssl_analyzer.py              # SSL分析：证书链/密码套件分级/协议检测/7种漏洞检查
│   ├── tech_fingerprint.py          # 技术指纹：200+签名/19 favicon哈希/OS检测
│   ├── nuclei_runner.py             # Nuclei集成：自动检测/80+技术映射/去重/回退指南
│   ├── waf_evasion.py               # WAF绕过：协议级/6编码/38混淆/10 WAF/HTTP参数污染
│   │
│   │   # ── v5 新增模块 ──
│   ├── report_visualizer.py         # 可视化报告：HTML仪表盘/SVG图表/暗色模式/PDF导出
│   ├── browser_agent.py             # 浏览器代理：Playwright/多步骤认证/验证码/MFA/2FA
│   ├── poc_generator.py             # PoC生成器：curl/Python/HAR/Markdown/安全分类
│   │
│   │   # ── v5.1-v5.3 Quick Combat ──
│   ├── quick_combat.py              # 一键实战管线：检测→深挖→PoC→利用→HTML报告+manifest
│   ├── exploit_generator.py         # 利用脚本生成器：validated findings→自包含Python演示脚本
│   │
│   │   # ── v5.4 Combat 强化 ──
│   ├── cn_probes.py                 # 国内组件/OA未授权探针库：泛微/致远/通达/用友/禅道/JeecgBoot/若依等32条
│   ├── oob_client.py                # 真实OOB带外信道：interactsh自托管/ceye.io/dnslog.cn，盲SSRF回调验证
│   │
│   │   # ── v5.6 记忆层 / 交付层 ──
│   ├── clueboard.py                 # 跨会话线索板：每目标一份 Markdown 台账，跨压缩/换会话续挖
│   ├── report_docx.py               # 提交级 DOCX + 分层验证门：SRC/CNVD 报告成稿收口
│   │
│   │   # ── v5.7 方法论层 ──
│   ├── business_logic.py            # 业务逻辑/越权/竞态方法论引擎：五问建模→计划→A/B 交叉证明→判定
│   │
│   │   # ── v5.10 移动端快筛 ──
│   └── apk_recon.py                 # APK 秒级快筛：自研二进制 AXML 解析（组件矩阵/导出风险）+ 加固指纹 + 密钥/端点速筛
│
├── rules/                           # 规则配置目录 (v5)
│   ├── low.yaml                     # LOW级别规则（8条）
│   ├── medium.yaml                  # MEDIUM级别规则（15条）
│   ├── high.yaml                    # HIGH级别规则（16条）
│   ├── critical.yaml                # CRITICAL级别规则（5条）
│   ├── waf_signatures.yaml          # WAF签名库（27条）
│   ├── mutation_strategies.yaml     # 变异策略配置
│   │   # ── v5.8-v5.11 知识域规则 ──
│   ├── ai_llm_security.yaml         # AI/LLM 应用安全（11条：注入/泄露/投毒/工具滥用/沙箱逃逸/输出XSS）
│   ├── miniprogram_security.yaml    # 小程序安全（8条：云开发/登录/支付/密钥/接口越权）
│   ├── android_security.yaml        # Android 组件安全（7条：组件/WebView/Provider/Binder/DeepLink）
│   └── pe_security.yaml             # Windows PE 安全（4条：内存破坏/格式化字符串/DLL劫持/保护缺失）
│
├── references/                      # 参考文档（14 个）
│   ├── safety_policy.md             # 安全模型完整规范
│   ├── data_schemas.md              # 所有JSON Schema定义
│   ├── payload_playbook.md          # 非破坏性检测Payload手册（22 类）
│   ├── advanced_payload_playbook.md # 高级Payload手册（16 类）
│   ├── script_contracts.md          # 脚本接口契约
│   ├── formal_algorithms.md         # 可解释评分规则文档
│   ├── tool_contracts.json          # 机器可读JSON Schema
│   ├── business_logic_playbook.md   # 业务逻辑/越权/竞态方法论手册（v5.7，含零身份公开面还原附则）
│   ├── knowledge_domains_roadmap.md # 知识域扩展路线图（v5.7，**v5.8-v5.11 已全部落地**）
│   │   # ── v5.8-v5.11 知识域手册 ──
│   ├── ai_llm_security.md           # AI/LLM 应用安全：五层攻击面 + 12 类检测项与判定标准（v5.8）
│   ├── miniprogram_security.md      # 小程序安全：取包→还原→越权链路 + 云开发专项（v5.9）
│   ├── android_audit.md             # Android 组件审计：9 类检测 + ADB 命令 + 无 Root 降级（v5.10）
│   ├── apk_reversing.md             # APK 逆向：壳识别→脱壳→全量还原三段流水线（v5.10）
│   └── pe_reversing.md              # Windows PE 逆向：静态→动态→漏洞定位（v5.11）
│
└── assets/                          # 示例与清单
    ├── manifest.yml                 # 技能部署清单（v5.11）
    ├── report_template.docx         # 提交级报告模板（v5.6，report_docx.py 使用）
    ├── example_input.json           # 示例AgentContext输入
    ├── example_trace.json           # 完整执行追踪
    └── example_report.json          # 期望输出示例
```

运行时产出的目录（已在 `.gitignore` 中排除）：

```
hunts/<目标>/CLUEBOARD.md    # 跨会话线索板（clueboard.py）
hunts/<目标>/raw/            # 原始材料：完整 JS、未打码凭证（不进线索板）
reports/<单位>src/           # 提交级 DOCX 报告（report_docx.py）
reports/_gate_report.json    # 分层验证门判定结果
```

---

## 🚀 快速开始

### ⚡ 30 秒上手 + 自检

```bash
# 1) 取得技能包
git clone https://github.com/yuanguin37/GKN-Phantom.git && cd GKN-Phantom

# 2) 零依赖检查：全部模块只用标准库（Python ≥ 3.10），无需 pip install
python3 -c "import sys; print(sys.version)"
python3 -m compileall -q scripts/ && echo "语法 OK（39 个模块）"

# 3) 自检 1：范围守卫（离线、确定性、不发包）
#    否定用例：越界目标必须被拒绝
#    期望 {"ok": false, "offenders": ["https://evil.example.com: host 'evil.example.com'
#          does not match any scope domain"]} 且退出码 1
python3 scripts/scope_guard.py --context assets/example_input.json --url https://evil.example.com

# 3b) 直连样例目标：样例用的是 .test 保留域 + 10.0.0.0/24 内网段（离线不可解析），
#     因此会报 "could not resolve host" 并拒绝 —— 这是预期行为，不是故障
python3 scripts/scope_guard.py --context assets/example_input.json

# 4) 自检 2：三层新增能力是否就位
python3 scripts/clueboard.py list                                   # 记忆层（首次为空列表 []）
python3 scripts/business_logic.py scene --name payment               # 方法论层（8 条支付攻击点）
python3 scripts/report_docx.py --emit-template \
        --template assets/report_template.docx                       # 交付层（可选依赖）

# 5) 加载为 OpenClaw 技能：把本目录放入技能路径，或按 assets/manifest.yml 注册
#    注册产物含 name / version / tools / safe_mode 默认值 / 状态机 / 安全模型

# 6) 首个动作：任何目标都必须先建线索板，再开挖
python3 scripts/clueboard.py init --target <目标> --focus "<本轮焦点>"
```

**自检通过标准**

| 检查 | 期望 |
|------|------|
| Python 版本 | ≥ 3.10 |
| `compileall scripts/` | 无输出（无语法错误），39 个模块 |
| `scope_guard --context --url <越界URL>` | exit 1，`offenders` 给出 `does not match any scope domain`（守卫确实在工作） |
| `scope_guard --context`（直连样例目标） | exit 1，`could not resolve host`——样例为 `.test` 保留域，离线不可解析，**预期行为** |
| `clueboard.py list` | 能列出已建板目标（首次为空列表 `[]`，正常） |
| `business_logic.py scene --name payment` | 打印 8 条支付链路攻击点 |
| `report_docx.py --emit-template` | 生成 `assets/report_template.docx`；缺 python-docx 时明确提示降级为 `--gate-only` |
| `AGENTS.md` | 存在且可读（纪律层，开工前必读） |
| `apk_recon.py <样本.apk>` | 打印组件矩阵（含导出风险）+ 加固判定 + 密钥/端点速筛；无样本可跳过（仅移动端目标需要） |

> **合规提醒**：以上自检全部在本地完成，不向任何外部主机发包。真正开始测试前必须有**书面授权**；
> `scope_guard.py` 会对越界目标直接中止，**不要试图绕过它**。

### 环境要求

#### 必需依赖

| 依赖 | 版本 | Kali | CentOS/RHEL |
|------|------|------|-------------|
| Python | ≥ 3.10 | 预装 | `dnf install python3` |
| nmap | 任意 | 预装 | `dnf install nmap` |

#### 可选工具（自动检测，缺失时回退纯Python实现）

| 工具 | 用途 | 安装命令 |
|------|------|----------|
| `nuclei` | 模板化CVE扫描 | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| `subfinder` | 主动子域名爆破 | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| `httpx` | 高速存活探测 | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| `ffuf` | 高速目录Fuzz | `go install github.com/ffuf/ffuf/v2@latest` |
| `amass` | 深度DNS枚举 | `go install github.com/owasp-amass/amass/v4/...@master` |
| `katana` | JS爬虫与端点发现 | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| `naabu` | 快速端口扫描 | `go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` |

#### v5 可选依赖

| 工具 | 用途 | 安装命令 |
|------|------|----------|
| `playwright` | 交互式浏览器代理（验证码/MFA/认证） | `pip install playwright && playwright install chromium` |
| `pytesseract` | 验证码OCR识别（实验性） | `pip install pytesseract` |
| `weasyprint` | PDF报告导出 | `pip install weasyprint` |

### Kali 一键安装

```bash
# 基础工具链
sudo apt update && sudo apt install -y nmap golang-go

# ProjectDiscovery 全家桶
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# v5 增强
pip install playwright && playwright install chromium
pip install weasyprint

echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.zshrc && source ~/.zshrc
```

### 在 OpenClaw 中使用

```yaml
skills:
  - name: gkn-phantom
    source: ./gkn-phantom
    manifest: assets/manifest.yml
```

触发调用：

```
user: "对 staging.example.com 进行一次安全审计"
user: "Run a penetration test on dev-internal.test"
```

### 独立脚本测试

```bash
# ── Quick Combat 一键实战管线（推荐入口）──
# 全层开启：nuclei + 内置探针 + 国内组件探针 + katana爬取 + JS深挖 + 跨运行去重
python scripts/quick_combat.py --targets targets.txt --output-dir ./combat_output/

# 配置 OOB 带外信道（盲SSRF回调验证 → validated级finding）
python scripts/quick_combat.py --targets targets.txt --oob-provider ceye \
    --ceye-identifier <id> --ceye-token <token>

# interactsh 自托管 / 本机安装
python scripts/quick_combat.py --targets targets.txt --oob-provider interactsh \
    --interactsh-server https://oast.your-domain.test

# 精简模式：只要内置探针，关闭所有外部依赖
python scripts/quick_combat.py --targets targets.txt --no-nuclei --no-crawl \
    --no-js --no-memory

# OOB 信道自检
python scripts/oob_client.py --provider auto --tag selftest --wait 5

# 国内组件探针单跑（泛微/通达/若依/JeecgBoot/致远/用友/禅道...）
python scripts/cn_probes.py --targets https://oa.example.com

# ── 记忆层：跨会话线索板（续挖前先读板）──
python scripts/clueboard.py init --target https://oa.example.com --focus "还原 /services/ 鉴权"
python scripts/clueboard.py add  --target https://oa.example.com --section assumptions \
    --cells "Ssologin 缺鉴权,假设,用无凭证请求读 /services/,待执行"
python scripts/clueboard.py brief --target https://oa.example.com      # 压缩/换会话后重载
python scripts/clueboard.py cover --target https://oa.example.com --tested "登录验证码" --level L2
python scripts/clueboard.py check --target https://oa.example.com --section excluded --text "旧 H5 路径"
                                                          # exit 1 = 上轮已证伪，别重测

# ── 交付层：分层验证门 + 提交级 DOCX ──
python scripts/report_docx.py --emit-template                 # 生成 assets/report_template.docx
python scripts/report_docx.py --findings findings.json --gate-only        # 只跑验证门，看哪些卡住
python scripts/report_docx.py --findings findings.json --unit example \
    --shots ./shots --outdir ./reports                        # 生成 SRC 提交稿 DOCX
python scripts/report_docx.py --findings findings.json --mode 0day --outdir ./reports

# ── 单模块使用 ──
# 被动侦察（零触碰）
python scripts/passive_recon.py --domain example.com --mode all

# 技术栈指纹
python scripts/tech_fingerprint.py --url https://target.com

# SSL安全分析
python scripts/ssl_analyzer.py --host target.com --port 443

# 目录爆破
python scripts/directory_fuzzer.py --url https://target.com --wordlist all --extensions php,asp --depth 2

# SQL注入探测
python scripts/advanced_sqli.py --url "https://target.com?id=1" --param id --db-type auto

# WAF绕过变异
python scripts/waf_evasion.py --payload "' OR 1=1--" --vuln-type sqli --waf-type cloudflare

# 漏洞检测
python scripts/vuln_detector.py --tier low,medium --safe-mode

# 规则验证
python scripts/rules_loader.py --validate

# PoC生成
python scripts/poc_generator.py --findings findings.json --format curl,python,har

# 可视化报告
python scripts/report_visualizer.py --findings findings.json --assets assets.json --paths paths.json --log log.json --format html

# 浏览器认证代理
python scripts/browser_agent.py --url https://target.com/login --auth-steps steps.json
```

---

## 🛡️ 安全模型

GKN-Phantom 的安全模型是**不可协商的**。每个操作都经过三层防护：

### 1. Scope Guard（范围守卫）
- 每个目标、每个请求、每个工具调用在执行前都须通过 `ctx.scope` 校验
- 支持域名通配符（`*.staging.example.test`）、IP CIDR、路径白名单/黑名单
- 越界目标 → 立即中止，不执行部分扫描

### 2. Risk Gate（风险门控）
- **L1** — 被动侦察（允许）
- **L2** — 安全探测（允许）
- **L3** — 认证测试（需提供凭据）
- **L4** — 破坏性/提权/写操作（需人工审批，Safe Mode 下完全阻断）

### 3. Rate Limiter（速率限制）
- 令牌桶算法，默认 ≤ 3 req/s，突发上限 5
- 超限请求排队而非丢弃，保障扫描稳定性

### 4. Evidence Requirement（证据要求）
- 每个发现必须包含：`request` + `response` + `timestamp` + `tool` + `reproducible`
- 证据不完整 → 在 VALIDATION 阶段被拒绝

---

## 📊 输出示例

### JSON/SARIF 报告

```json
{
  "summary": "在 staging.example.test 发现 9 个安全问题：1 个严重、2 个高危、3 个中危、3 个低危",
  "risk_score": 85,
  "findings": [
    {
      "id": "finding-001",
      "type": "sqli",
      "severity": "high",
      "target": "https://staging.example.test/api/users?id=1",
      "status": "validated",
      "confidence": 0.95,
      "evidence": {
        "request": "GET /api/users?id=1' OR '1'='1 HTTP/1.1 ...",
        "response": "HTTP/1.1 200 OK ... [all user records returned]",
        "timestamp": "2026-08-05T14:05:30Z",
        "tool": "httpRequest"
      },
      "reproducible": true,
      "remediation": "使用参数化查询或预编译语句，对所有用户输入进行严格过滤"
    }
  ],
  "attack_paths": [
    {
      "id": "path-001",
      "name": "SQL注入 → 凭证窃取 → 横向移动",
      "impact": "攻击者可提取全部用户密码哈希并尝试撞库",
      "confidence": 0.9
    }
  ]
}
```

### HTML 可视化报告 (v5)

执行 `report_visualizer.py` 生成包含以下内容的专业HTML报告：
- **执行仪表盘**：SVG风险评分仪表（绿/黄/橙/红）+ 按严重级别统计卡片
- **发现详情卡片**：彩色编码可折叠卡片，含请求/响应证据、修复建议、CVSS 3.1评分矩阵
- **攻击路径图**：纯SVG渲染的攻击链有向图，悬停显示详情
- **资产清单表**：可排序HTML表格，含域名/IP/端口/技术栈/SSL评级
- **技术栈摘要**：WAF检测标记 + 技术卡片网格
- **修复优先矩阵**：2x2 工作量×影响力矩阵
- **交互功能**：严重级别过滤 · 关键词搜索 · 全部展开/折叠 · 暗色模式切换

---

## 🔧 配置选项

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `rate_limit_rps` | int | 3 | 每秒最大请求数 |
| `safe_mode` | bool | true | 是否阻断 L4 级探测 |
| `require_human_approval` | bool | true | L4 操作是否需要人工审批 |
| `environment` | string | — | 环境类型：staging / dev / internal / lab |

---

## 📋 版本历史

| 版本 | 日期 | 主要更新 |
|------|------|----------|
| **v5.11.0** | 2026-09 | **Windows PE 逆向域**：`references/pe_reversing.md`（PE 结构必查表含 **TLS 回调与节熵** · 编译器与加壳四类信号 · 隔离环境动态行为与反调试识别 · 内存破坏与 **DLL 劫持三兄弟辨析**）· `rules/pe_security.yaml`（4 条）· 4 个类型命门——`memory_corruption` 须证明**执行流可控**、`dll_hijacking` 须证明**被加载执行**；`knowledge_domains_roadmap.md` 规划的四域至此**全部落地** |
| **v5.10.0** | 2026-09 | **Android 组件审计 + APK 逆向**：`scripts/apk_recon.py`（**纯标准库 · 秒级**：自研**二进制 AXML 解析器**直接产出组件矩阵与导出风险判定 · 加固特征 `lib*.so` 识别 · dex 字符串与 assets 的密钥/端点速筛且**密钥自动脱敏**）· `references/android_audit.md`（11 类检测 + 可复制 ADB 命令 + **无 Frida/无 Root 降级路径**）· `references/apk_reversing.md`（壳识别 → 脱壳 → 全量还原三段流水线）· `rules/android_security.yaml`（7 条）· 7 个类型命门（组件类须 `adb_repro_cmd` + `effect_proof`） |
| **v5.9.0** | 2026-09 | **小程序安全域**：`references/miniprogram_security.md`（取包 → 反编译 → 接口/密钥提取 → 越权验证四段链路 · **微信云开发三层面**：云数据库权限规则/云函数调用方校验/云存储遍历 · 登录链路 `code2session`/`session_key`/手机号解密 · 支付链路金额重算与回调验签）· `rules/miniprogram_security.yaml`（8 条）· 7 个类型命门 · **接口越权沿用 Web 的 `idor` A/B 硬标准，不因"是小程序"放低** |
| **v5.8.0** | 2026-09 | **AI/LLM 应用安全域**：`references/ai_llm_security.md`（五层攻击面 + 12 类检测项的构造法/判定标准/**不可提交反例**）· `rules/ai_llm_security.yaml`（11 条：直接与间接注入 · System Prompt 泄露 · 越狱 · 数据泄露 · RAG 投毒 · 记忆污染 · **Agent 工具滥用** · 过度授权 · 沙箱逃逸 · 工具描述投毒 · 输出侧 XSS）· 新增类型命门 `prompt_injection`（行为改写 **≥3 次稳定复现** + 对照请求差异）与 `agent_tool_abuse`（**必须落地证据，模型"声称已执行"不算**） |
| **v5.7.0** | 2026-09 | **纪律层**：`AGENTS.md`（十条执行纪律 · 覆盖度自检 · **失败升级 Level 1-7 且"至少到 L4 才能下『无漏洞』结论"** · 跨接口关联五问 · 暂停思考触发 · 可利用性六问 · 触发信号路由表；不可放宽安全模型）· **方法论层**：`business_logic.py`（建模五问校验 → 测试计划 + 角色矩阵 + 竞态目标 → **A/B 交叉证明请求对** → 证据判定 `pass`/`fail`/`inconclusive`；**速率受限**并发骨架；判定口径与类型命门对齐，不发包）+ `references/business_logic_playbook.md`（含零身份公开面还原附则）· **路由表与中文化**：场景/类型/SRC 优先级/组合场景四张表 + 中文触发短语 + 结论先行输出骨架 · `references/knowledge_domains_roadmap.md`（AI/LLM→小程序→Android/APK→PE 四域路线图，**路线图非能力声明**） |
| **v5.6.0** | 2026-09 | **记忆层**：跨会话线索板 `clueboard.py`（`hunts/<目标>/CLUEBOARD.md`，未决假设/Host/路径/密钥/**已排除防重测**/覆盖度，与 `state.py` 机器态职责分离，重复线索拒绝标注，未决假设上限 5）· **交付层**：`report_docx.py`（分层验证门硬门0-5 + 类型命门 · SRC/0day 双模板 · Step 式 PoC · 截图铁律 · 语义化命名 · 四项查重 · 去 AI 腔自检）+ `assets/report_template.docx` |
| **v5.5.0** | 2026-09 | **模式匹配引擎**（`pattern_matcher.py`）：Trie + Aho-Corasick 自动机（delta 完全转移表，单遍 O(n+命中)）· 可靠正则必需字面量提取器（DNF）· `PrefilteredRegexSet` 门控——技术指纹/WAF检测/JS扫描/DB指纹/HTML检测全线接入，结果与逐条扫描一致；收益随模式数与响应体规模增长，小模式集/短响应自动回落朴素路径（8 模式 × 60KB 实测 0.73x） |
| **v5.4.0** | 2026-09 | 国内组件/OA 未授权探针库（32条：泛微/致远/通达/用友/禅道/JeecgBoot/若依/帆软/亿邮/金蝶/蓝凌/红帆/万户，含 POST 一键验证器）· 真实 OOB 带外信道（interactsh 自托管/ceye.io/dnslog.cn，盲 SSRF 回调验证 → validated）· katana 全站爬取喂参数注入探测 · JS 深挖链（js_analyzer + 隐藏端点提取回喂探测）· 跨运行去重记忆（combat_memory.json，`[已提交]/[重复]` 标注） |
| **v5.3.0** | 2026-09 | Deep-Dive 深挖适配器（Actuator/GraphQL/Swagger：拉取实际暴露内容证明影响并升级严重级）· 参数发现 + 有界注入探测（报错型 SQLi 6 引擎签名 + SSTI 算术反射差分） |
| **v5.2.0** | 2026-09 | 影响升级层：quick-probe findings 按响应内容重定级（活跃凭据/.git/heapdump/phpinfo/备份包 → high；PII 数据暴露评分 ≥3 → critical） |
| **v5.1.0** | 2026-08 | Quick Combat Mode：单命令 detect → PoC → exploit 实战管线 · 利用脚本生成器 · 时间戳战斗报告 + HTML 索引 |
| **v5.0.0** | 2026-08 | 交互式浏览器代理（Playwright）· 可视化HTML/PDF报告 · 规则配置化（YAML热加载） · 专业PoC生成器 · 确定性自检（回放 `assets/example_input.json` 并比对 `example_report.json` 结构） |
| **v4.0.0** | 2026-08 | 被动侦察（crt.sh/DNS/WHOIS/Wayback/GitHub）· 目录爆破 · 专业SQL注入引擎 · SSL分析 · 技术指纹（200+签名） · Nuclei集成 · WAF绕过引擎 |
| **v3.0.0** | 2026-07 | 38种漏洞类型（+16种高级）· 5个专项模块（JS/CVE/高级注入/API/云安全）· 20+攻击链 · 25+WAF识别 |
| **v2.2.0** | 2026-07 | 确定性启发式决策引擎 · 执行追踪与回放 · 可解释评分规则 |
| **v2.1.0** | 2026-07 | 状态恢复系统 · 机器可读工具契约 |
| **v2.0.0** | 2026-06 | 预飞行安全模拟 · 自适应探测引擎 · 多因子置信度评分 · 强Schema契约 |
| **v1.0.0** | 2026-06 | 初始版本：22种漏洞类型 · 基础状态机 · Scope Guard · Rate Limiter |

---

## 🤝 贡献指南

欢迎提交 Issue 和 Pull Request。贡献前请确保：

1. 新增漏洞检测规则优先添加到 `rules/*.yaml` 配置文件，实现热加载
2. 所有探测 Payload 必须为非破坏性（仅检测，不利用）
3. 跨平台兼容（Windows / Linux 均需测试）
4. 新增模块需同时更新 `SKILL.md`、`README.md` 和 `manifest.yml`

---

## ⚠️ 免责声明

**GKN-Phantom 仅供授权安全测试使用**：企业内部安全审计、预发布/开发/实验环境验证。**严禁**在未经授权的系统、生产环境或第三方目标上使用。未经授权使用可能构成违法行为，使用者需自行承担全部法律责任。

---

## 📄 许可证

MIT License © 2026

---

<p align="center">
  <sub>Built with 🔥 for the OpenClaw ecosystem</sub>
</p>
