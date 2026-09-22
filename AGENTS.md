# AGENTS.md — GKN-Phantom 执行纪律与技能调度总纲

> 本文件是 `SKILL.md` 的**纪律层**：`SKILL.md` 回答「能做什么、接口是什么」（契约），
> 本文件回答「怎样才算专业地做」（行为纪律）。
> 两者冲突时，**安全模型优先**：`references/safety_policy.md` 与 Scope Guard / Risk Gate /
> Rate Limiter 的约束不可被本文件任何条款覆盖或放宽。

> ⚠️ **合规前提（不可协商）**：本技能仅用于**已获书面授权**的内部安全审计、
> 预发/测试/靶场环境验证、SRC/众测公告范围内的资产。
> 未授权目标、真实生产系统、真实用户数据一律不碰。
> `scope_guard.py` 判定越界即 ABORT —— **不得以任何理由绕过它**。

---

## 0. 定位与输出标准

GKN-Phantom = 可执行扫描引擎 + 分析师纪律 + 跨会话记忆 + 提交级交付。

| 层 | 载体 | 作用 |
|---|---|---|
| 引擎层 | `scripts/*.py`（39 模块） | 真实工具编排、检测、证据固化 |
| 纪律层 | 本文件 | 怎么想、怎么穷举、何时停 |
| 记忆层 | `scripts/clueboard.py` → `hunts/<目标>/CLUEBOARD.md` | 判断与否定证据跨会话存活 |
| 交付层 | `scripts/report_docx.py` → `reports/` | 过验证门 → DOCX 提交稿 |

**输出标准**

1. 始终中文输出；**结论先行**（风险等级与影响 → 复现过程 → 根因 → 修复）。
2. 每个结论都要能回答「证据是什么、怎么复现、影响是谁的」。
3. 可利用性必填六问（见第 5 节），缺项不得定级。
4. 不写"可能存在/理论上可被利用"——那属于 `unverified_leads[]`，不属于结论。

---

## 1. 十条执行纪律

每条纪律标注**执行载体**：能写进代码的已写进代码，其余靠本文件约束。

### 一、JS 不吃透，不发包

先还原前端再动手：`js_analyzer.py` + webpack/source map 还原 →
提取 API 路径 / 参数 / 鉴权头 / 密钥 / 隐藏功能 → 全方法全参数测试。
**主站 JS 里没有 ≠ 接口不存在**（SPA 的 404 不是接口的 404）；
**客户端拿得到 RSA/AES/uuid ≠ 鉴权**。

> 载体：`js_analyzer.py`、`quick_combat.py` 的 JS bundle mining 层。

### 二、覆盖度自检（强制，每轮输出）

每轮测试结束必须输出四分类，并**写入线索板覆盖度区块**：

```
✅ 已测：<端点/参数/方法>
❌ 未测：<为什么没测——无权限/WAF/时间/需带内交互>
🔄 变种：<同一注入点的编码/类型/顺序/大小写双写变体>
💡 关联：<由本轮结论推导出的新待测面>
```

> 载体：`clueboard.py cover --tested/--untested/--variants/--related`。
> **变种思维强制**：编码（URL/Unicode/双重）、类型（数组/对象/JSON 字符串）、
> 注入点（Header/Cookie/Path/JSON key）、顺序（参数序/步骤序）、大小写双写。

### 三、漏洞嗅觉

响应时间、响应体量、措辞、状态码、字段增减异常 → 记录 → 对比 → 分析 → 利用。
任何"和基线不一样"的地方都是线索，先记板再判断，不要凭记忆。

### 四、业务建模（不许跳过）

状态机 + 角色矩阵 + 非法路径 + 一致性校验位置 + 并发。
资金/权益/流程链路**必须**走 `business_logic.py`：
`model`（五问建模）→ `plan`（测试计划）→ `ab`（越权交叉证明）→ `judge`（硬标准判定）。

> 载体：`business_logic.py` + `references/business_logic_playbook.md`。

### 五、失败升级 Level 1-7（禁止 L1 就下否证结论）

| Level | 动作 | 载体 |
|---|---|---|
| L1 | 编码绕过（URL/Unicode/大小写/双重编码） | `waf_evasion.py` |
| L2 | 载荷变形（注释、等价函数、空白符、拼接） | `adaptive_engine.py` 的 mutation |
| L3 | 逻辑绕过（参数污染、类型混淆、嵌套、覆写） | `advanced_injection.py` |
| L4 | 协议绕过（分块、分号、HTTP/2 降级、CL/TE） | `vuln_detector.py` protocol 层 |
| L5 | 换入口（同功能不同端点、旧版 API、管理端、内网口） | `directory_fuzzer.py` + `cn_probes.py` |
| L6 | 组合利用（低危拼接成链） | `attack_path.py` |
| L7 | 时间维度（竞态、TOCTOU、定时任务、缓存过期窗口） | `business_logic.py race` |

> **硬规：至少推进到 Level 4 才能写「无漏洞」结论。**
> L1-L3 失败只能写「该载荷被过滤」，不能写「不存在该漏洞」。
> 未穷举到 L4 的项写入线索板 `未测`，不得计入覆盖度已完成。

### 六、跨接口关联五问

拿到任一低危结论后，必须回答：

1. **信息流**：这个接口返回的字段，还能喂给哪个接口？
2. **凭证**：泄露的 key/token/appsecret 能打开谁的门？
3. **状态**：这次状态变更，谁的下游流程会因此改变？
4. **权限**：换个角色/换个租户，同一请求是否仍成立？
5. **时序**：并发或重放下结论是否翻转？

五个问题有任一命中 → 走 `attack_path.py` 成链，**按链的终局影响定级**，不按单点定级。

### 七、开发者视角优先测项

新功能、内部接口、批量操作、旧 API、错误分支、管理后台、
第三方回调、导出下载、定时任务 —— 优先于首页公开接口。

### 八、信息收集要脏，线索当轮落盘

源：Wayback、GitHub/GitLab、Google Dork、证书透明度、招聘 JD、JS 注释、
robots、source map、APK/IPA、Changelog、错误栈、备份文件。

> **硬规：线索不进板，本轮收集不算完。**
> `clueboard.py add --section hosts|paths|keys|secrets|excluded|todos|assumptions`
> 原始素材（完整 JS、未打码凭证）写 `hunts/<目标>/raw/`，**不进板**（板要能安全共享）。

### 九、对抗意识

防御在哪一层 → 规则是什么 → 边界在哪 → 协议/编码/逻辑差异在哪。
`adaptive_engine.detect_waf` 识别 WAF 后先记指纹，再选绕过策略，不盲打。

### 十、暂停思考（触发即切换专项）

出现以下任一情况，**停止当前推进**，转向对应专项深挖：

- 遇到加密/签名逻辑 → 先还原算法与密钥来源（纪律一）
- 权限边界不明 → 先做角色矩阵（纪律四）
- 连续 3 次探测失败 → 进入失败升级 L1-L7（纪律五）
- 出现新攻击面（内网地址、新域名、新端口、新角色）→ 记板并扩面
- 复杂业务/多低危堆积 → 走跨接口关联五问（纪律六）

---

## 2. 标准工作流

```
1. 读板/建板   clueboard.py init | brief --target <T>
2. 资产梳理    passive_recon → tech_fingerprint → directory_fuzzer → js_analyzer
3. 攻击面建模  入口 × 角色 × 信任边界（写 board: hosts / paths）
4. 三层挖掘    静态审计(输入点→传播链→Sink) → 动态验证(基线差分) → 组合利用
5. 业务链路    business_logic.py model → plan → ab → judge
6. 证据固化    finding_validator 重放 ≥2 + 控制请求对照 → confidence_scoring
7. 覆盖度自检  ✅/❌/🔄/💡 写回 board
8. 交付        report_docx.py（过门才出稿）→ 语义化命名归档
```

**阶段与状态机对齐**：ACTIVE_TESTING 执行第 4-5 步，VALIDATION 执行第 6 步，
REPORT_GENERATION 执行第 8 步。每步结束先写板，再推进状态。

---

## 3. 触发信号 → 模块路由表

> 命中即**加载并按其手册执行**，不停留在通用扫描。
> 完整版见 `SKILL.md` 的 `Trigger → Module Routing` 章节（含漏洞类型映射与组合场景）。

| 触发信号 / 场景 | 模块 | 深度动作 |
|---|---|---|
| 新目标开工 / 换会话续挖 / 要跨轮保留 Host·路径·密钥 | `clueboard.py` | `init`→挖→`add` 回写；续挖先 `brief` |
| 攻击面不清、要找接口/密钥/子域 | `passive_recon.py` → `js_analyzer.py` | 资产测绘 + JS 还原 + 历史资产/OSINT |
| 路径不在主站 JS、无账号、405 或 `data:[]`、前端加密当鉴权 | `directory_fuzzer.py` + 零身份公开面还原（playbook §6） | 响应指纹分流、加密证伪、迁域与兄弟域复查 |
| 参数拼接 / 动态排序 / JSON 查询 / 模板渲染 / 命令执行点 | `advanced_sqli.py` + `advanced_injection.py` | 报错·布尔·时间盲注（capped）、SSTI 算术反射 |
| 登录/注册/找回密码/验证码/OAuth/JWT、IDOR、角色参数可控 | `vuln_detector.py` critical 层 + `business_logic.py ab` | 认证绕过、A/B 交叉证明、多租户隔离 |
| 支付/下单/退款/提现/券/积分/审批/库存、并发重放 | `business_logic.py` | 状态机建模 + 金额篡改 + 竞态重放 |
| 上传/下载/导出/导入/预览 | `vuln_detector.py` file_upload + `exploit_generator.py` | getshell/解析证明、路径穿越、Zip Slip |
| URL 可控的抓取/代理/webhook/回调/图片预览 | `oob_client.py` + `advanced_injection.py` | 真实带外回调 + 内网回显 |
| XML/SOAP/序列化/JSON 深合并 | `advanced_injection.py` | 反序列化、XXE、原型污染 |
| 反射/存储/DOM XSS、postMessage、CORS、CSRF | `vuln_detector.py` xss + `browser_agent.py` | 浏览器内真实执行证明 |
| REST/GraphQL/gRPC/WebSocket/Swagger/调试端点 | `api_auditor.py` | 全方法测试、BOLA、schema 深挖 |
| 云/容器/K8s/中间件/CI-CD/依赖 CVE | `cloud_security.py` + `cve_correlator.py` | 配置错误、未授权中间件、供应链 |
| 有源码/反编译产物 | 手工审计 + `vuln_detector.py` | 输入点→传播链→Sink |
| **AI 客服/Chatbot/Copilot/RAG 问答/Agent 工具调用/代码解释器/多模态解析** | `references/ai_llm_security.md` + `rules/ai_llm_security.yaml` | 行为差分证「模型被改写」→ 复用落地层取证（`oob_client` / 命令回显 / A/B 交叉）；**模型"声称已执行"不算证据** |
| **小程序（微信/支付宝/抖音/百度）、云开发、`.wxapkg`/`.apkg` 反编译** | `references/miniprogram_security.md` + `rules/miniprogram_security.yaml` | 取包→还原→接口/密钥提取→越权验证（复用 `business_logic.py ab`）；云数据库只读且限条数；**接口越权沿用 idor 硬标准，不因"是小程序"放低** |
| **App/APK/导出组件/WebView/Provider/Deep Link/有壳包** | `scripts/apk_recon.py` → `references/android_audit.md` + `references/apk_reversing.md` | 先秒级快筛（组件矩阵 + 密钥 + 端点 + 加固判定）再决定深挖；组件类必须给 ADB 命令 + 实际效果 |
| **exe/dll/sys/样本/加壳二进制/崩溃排查** | `references/pe_reversing.md` | 静态（结构/保护机制/加壳）→ 动态（隔离环境行为监控）→ 漏洞定位；**崩溃必须证明可控，劫持必须证明被加载** |
| payload 被拦、403/WAF | `waf_evasion.py` + `adaptive_engine.py` | 失败升级 L1-L4 |
| 国内 OA/中间件（泛微/致远/通达/用友/禅道/JeecgBoot/若依…） | `cn_probes.py` | 32 条未授权探针 + 指纹分流 |
| 要出提交稿 / 准备交付 | `report_docx.py` | 分层验证门 → DOCX 归档 |

**组合场景（多模块联动）**

- 信息泄露 → 越权：`js_analyzer` 找接口 → `business_logic ab` 打 IDOR
- 组件泄露 → 拿凭据 → 登录后台：`cn_probes`/`cloud_security` → `auth_bypass`
- 上传 → 内网：`file_upload` 拿路径 → `oob_client` 打 SSRF
- 低危组合提级：完成单点后做跨接口关联五问 → `attack_path.py` 成链
- 跨轮续挖：任何目标先 `clueboard.py brief` → 只补板上的空格
- AI 输出/Markdown 渲染无净化 → 存储型 XSS（`references/ai_llm_security.md` §2.12）
- 注入驱动 Agent 调工具 → 落地层取证：`ai_llm_security.md` §2.8 → `oob_client` 回调 / 命令回显 → `report_docx` 硬门4 `agent_tool_abuse`
- 小程序/App 还原产物 → 接口越权：`apk_recon.py` 或反编译拿接口清单 → `business_logic.py ab` 打 IDOR（与 Web 同一硬标准）
- App 内 WebView 承载 H5 → 双域联动：`android_audit.md` §2.7 WebView 桥 + `ai_llm_security.md` §2.12 输出渲染落地
- 密钥速筛命中 → 先验可用性：`apk_recon --secrets` / grep 结果 → `httpRequest` 调后端 → 可用即 `hardcoded_secret` 成稿

---

## 4. 可利用性评估（每个 finding 必填六问）

1. **是否可稳定复现**：YES/NO（重放 ≥2 次结果一致）
2. **前置条件**：登录态？角色？网络位置？特定版本/配置？
3. **影响面**：数据泄露 / 资金风险 / 权限提升 / 横向移动 / 持久化
4. **攻击成本**：低 / 中 / 高
5. **修复优先级**：P0 / P1 / P2
6. **限制与缓解**：WAF、风控、审计、速率限制、需人工审批的 L4 动作

> 定级纪律：**按实际观察到的影响定级，不按理论影响定级。**
> 同一 SQLi，"存在注入" 是中危；"回显库名" 是高危；"拖出他人 PII（脱敏展示）" 才可能严重。
> 危害等级以**上报者建议**形式给出；CVSS 评分不由本技能自评（提交平台评定）。

---

## 5. 交付纪律

1. **正式提交稿必须走 `report_docx.py`**，先过六道硬门（先证伪 / 可复现 / 危害终局 /
   服务端边界 / 类型命门 / 链式追问），未过门者只能作为 lead 上报，不得成稿。
2. **截图铁律**：每个 Step 必须真实截图（浏览器打开原始 URL 或 Burp Repeater），
   禁止伪造、禁止用文字描述代替；缺截图由构建器显式告警，不得静默跳过。
3. **PoC 用原始请求块**（Burp 风格），不用 curl 代替请求原文；同时给最小化复现步骤。
4. **语义化命名**：`资产 存在 漏洞类型 漏洞.docx`；禁用时间戳命名。
5. **查重**：交付前查历史报告与跨运行记忆（`[已提交]/[重复]`），一洞只交一家。
6. **去 AI 腔**：禁破折号拖尾解释、禁形容词渲染、禁截图元描述、禁方法论黑话进报告。
7. **归档即交付**：产物写入 `reports/<unit>src/`，同步在线索板记 `已提交`。

---

## 6. 记忆纪律（跨会话）

- **机器态**归 `state.py`（per run / JSON）：阶段、checkpoint、历史。
- **判断态**归 `clueboard.py`（per target / Markdown）：假设（含"怎么证伪"）、Host 地图、
  路径/方法、密钥协议、**已排除**、凭证脱敏、待办、覆盖度。
- 上下文即将压缩、会话即将结束、目标切换前：**先写板**。
- 任何会话续挖已知目标：**先 `brief` 读板**，禁止从主站 JS 重开一局。
- 探测任何东西前：`check --section excluded --text "..."`，exit 1 表示上轮已证伪，别重测。
- 假设是闭集（`假设`/`已证伪`/`已证实`/`待打`），未决假设上限 5 条，**先收敛再开新的**。

---

## 7. 禁止事项（Policy Violations）

以下行为视为严重违反纪律，必须立即停止并记录：

1. 绕过 `scope_guard.py` 的范围校验，或对未授权目标发包。
2. 关闭 `safe_mode` 对生产系统执行 L4 破坏性动作（DROP/写入/提权验证）。
3. 拖取真实用户数据、上传真实 WebShell、对真实业务做压测式并发。
4. 把 L1-L3 失败的探测结果写成"无漏洞"结论。
5. 把 `scanner`/`llm`/`version` 推断出的东西当作 finding 上报（违反证据门）。
6. 通过本文件任何条款为上述行为寻找依据。

---

## 8. 快速排查清单（30 秒定位方向）

- [ ] 未鉴权敏感接口？路径已知 → `api_auditor.py`；路径未知/兄弟域/加密当鉴权 → `directory_fuzzer.py` + 零身份还原
- [ ] 对象级校验缺失（IDOR）？→ `business_logic.py ab`
- [ ] 拼接查询/命令/模板渲染？→ `advanced_sqli.py` / `advanced_injection.py`
- [ ] 上传/下载/导入/解析？→ `vuln_detector.py` file_upload
- [ ] URL 抓取代理（SSRF）？→ `oob_client.py`
- [ ] token/JWT/角色参数？→ `vuln_detector.py` critical + `business_logic.py ab`
- [ ] 并发/重放影响资金或状态？→ `business_logic.py race`
- [ ] 配置泄露/调试端点/错误栈？→ `cloud_security.py` / `api_auditor.py`
- [ ] 新目标/续挖/要跨轮留线索？→ `clueboard.py`
- [ ] 有源码可审计？→ 输入点→传播链→Sink
- [ ] payload 被拦？→ `waf_evasion.py`（失败升级 L1-L4）
- [ ] 国内 OA/中间件？→ `cn_probes.py`
- [ ] AI 应用 / Chatbot / RAG / Agent 工具？→ `ai_llm_security.md`（行为差分 → 落地取证）
- [ ] 小程序 / 云开发？→ `miniprogram_security.md`（取包 → 还原 → 越权）
- [ ] APK / 导出组件 / WebView / 有壳包？→ `apk_recon.py` 快筛 → `android_audit.md`
- [ ] exe/dll 样本 / 崩溃排查？→ `pe_reversing.md`（隔离环境）
- [ ] 要出报告？→ `report_docx.py`

---

## 9. 高价值入口点速查

- 用户中心：注册 / 登录 / 找回密码 / 绑定手机 / 实名认证
- 支付流程：下单 → 支付 → 回调 → 退款 → 提现
- 文件功能：头像/附件上传、导入导出、报表下载
- 管理后台：`/admin` `/manager` `/console` `/backstage`
- API：`/api/v1` `/graphql` `/swagger` `/actuator`
- 冷门高价值：客服/工单、邮件通知、二维码/短链、日志监控、第三方登录、分享邀请、数据导出
- 国内常见暴露面：泛微/致远/通达/用友/禅道/JeecgBoot/若依 未授权链（`cn_probes.py`）
- AI 应用入口：`/chat` `/v1/chat` `/completions`、**会话分享链接**、上传解析、反馈/纠错接口（常直连 RAG 写入 → 投毒入口）
- 小程序入口：包体下载 URL、`/api/` 接口清单、云环境 ID（`env`）、`code2session` 登录链路、支付回调
- App 入口：导出 Activity/Service/Receiver/Provider、Deep Link scheme、WebView 承载页、硬编码密钥（最快出成果）

---

## 10. 心法

- **攻击者思维**：开发者忽略的边界、异常、旧接口；一切输入不可信；哪里有捷径。
- **对比测试**：正常 vs 异常、有权限 vs 无权限、新版 vs 旧版、单发 vs 并发。
- **板是黑板，技能是知识源，路由是控制**：不落板的线索等于没收集。
- **穷举优于猜测**：宁可写"未测并说明原因"，不可写"应该没有"。

---

结束。本文件与 `SKILL.md`、`references/safety_policy.md` 共同构成 GKN-Phantom 的执行契约。
