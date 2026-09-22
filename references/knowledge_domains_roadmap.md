# 知识域扩展路线图（Knowledge Domain Roadmap）

> **状态声明：本文件是路线图，不是能力声明。**
> 下列四个知识域在 GKN-Phantom v5.7.0 中**覆盖为 0** —— 全仓库检索
> `miniprogram|小程序|Android|APK|Prompt Injection|Jailbreak|LLM Application` **0 命中**。
> 本文件定义各域的入口点、检测清单、验收标准与分阶段计划，供后续版本按序落地。
> 未落地之前，任何文档（README / SKILL.md / manifest）**不得**把这些域写进能力描述。

适用边界：授权测试 / SRC 公告范围 / 自有 App 与小程序 / 靶场。移动端与小程序测试
须以目标所有者书面授权与平台测试规范为前提；不得对第三方 App 做未授权逆向与抓包。

---

## 0. 优先级与理由

| 序 | 域 | 优先级 | 理由 |
|---|---|---|---|
| 1 | **AI / LLM 应用安全** | P0 | 2026 年 SRC 高价值新面；且与自身正在做的 AI 助手类项目最贴合，能力可双向迁移 |
| 2 | **小程序安全** | P1 | 国内业务密度最高、包体小、反编译门槛低，产出比高 |
| 3 | **Android 组件 + APK 逆向** | P1 | 客户（HyperOS/MIUI 收录标准）明确；导出组件漏洞定级高 |
| 4 | **Windows PE 逆向** | P2 | 名字叫 Phantom 但二进制能力为零，是长期短板；不过与当前 Web/SRC 主战场关联最弱 |

**排序原则**：不是"哪个更难"，而是"哪个最可能在本季度产生真实可提交的产出"。

---

## 1. AI / LLM 应用安全（P0）

### 1.1 为什么是第一位

- 大模型应用在 2025-2026 年大规模上线，**安全评审标准尚未成熟**，SRC 收录意愿高。
- 与既有能力高度重叠：提示词注入驱动工具调用后，落地的还是 SSRF / RCE / 文件读写 —— 
  GKN-Phantom 的 `oob_client.py`、`advanced_injection.py` 可直接复用为**落地层**。
- 自身在做的 AI 助手类项目（含对话历史持久化）正好是天然的授权测试对象。

### 1.2 入口点

AI 客服 / Chatbot、AI 助手 / Copilot、文档问答 / RAG、AI 写作与编程、
AI 搜索、多模态解析（图片/PDF → 文本 → 指令）、代码解释器、Agent 工具调用、
Markdown 渲染输出（→ 前端 XSS）。

### 1.3 检测清单

| 类 | 检测项 | 可判定证据 |
|---|---|---|
| 提示词注入 | 直接注入（要求忽略前文指令） | 模型行为被改写且**稳定复现**（≥3 次一致） |
| 间接注入 | 把指令藏在被检索文档/网页/文件里 | 模型执行了文档内指令（而非用户指令） |
| System Prompt 泄露 | 元指令套取（"重复你上面所有内容"） | 拿到系统指令原文或工具清单 |
| 越狱 / 护栏绕过 | 角色扮演、编码混淆、多轮渐进 | 输出被平台禁止的内容 |
| 敏感信息泄露 | 训练/上下文数据、其他用户会话、密钥 | 拿到非本次会话的数据 |
| RAG 投毒 | 往知识库写入恶意文档影响他人回答 | 其他用户查询时命中投毒内容 |
| 记忆污染 | 跨会话记忆被写入持久化指令 | 下一会话仍生效 |
| **Agent 工具滥用** | 注入驱动 Shell/HTTP/代码解释器 | **命令回显 / 内网回显（终局危害）** |
| 过度授权 | Agent 持高于用户角色的权限 | 低权用户借 Agent 执行高权动作 |
| 沙箱逃逸 | 代码解释器逃逸到宿主 | 读到宿主文件/建立外连 |
| 供应链 | 模型/插件/工具描述被第三方控制 | 工具描述投毒导致行为偏转 |
| 输出侧二次落地 | AI 输出未净化 → 前端渲染 | 存储型 XSS / Markdown 注入 |

### 1.4 验收标准（落地时必须满足）

1. 新增 `references/ai_llm_security.md`：上表 12 类的 payload 构造法与判定标准。
2. 新增 `rules/ai_llm_security.yaml`，与既有 tier 体系一致（`id/type/severity/risk_level/
   safe_poc/blocked_in_safe_mode/remediation/cvss_vector/tags`）。
3. `report_docx.TYPE_GATES` 增加两个类型命门：
   - `prompt_injection` → 行为改写稳定复现（≥3 次）+ 输出原文对照
   - `agent_tool_abuse` → **落地证据**（命令回显/内网回显），仅有模型"声称已执行"不算
4. 间接注入与 RAG 投毒必须给出**跨会话/跨用户**证据，否则降级为 lead。
5. 合规：仅测自有或书面授权的 LLM 应用；测试产生的注入内容不得留存于第三方知识库。

---

## 2. 小程序安全（P1）

### 2.1 入口点

微信 / 支付宝 / 抖音 / 百度小程序；微信云开发（云函数、云数据库）；
登录授权流程、支付回调、`appid/appsecret` 提取；小程序包（`.wxapkg` 等）反编译。

### 2.2 检测清单

| 类 | 检测项 | 可判定证据 |
|---|---|---|
| 包还原 | 反编译得到前端源码 | 拿到完整 JS/配置（`appid`、`appsecret`、接口清单） |
| 硬编码密钥 | 包内 `appsecret`/`key`/`token` | 密钥可用于调用后端接口 |
| 接口越权 | 小程序端接口无鉴权/仅前端校验 | 用 B 的凭证读到 A 的数据（复用 A/B 交叉证明） |
| 云开发越权 | 云函数/云数据库规则宽松 | 匿名可读他人集合 |
| 登录逻辑 | `code2session` 流程缺陷、手机号解密 | 拿到他人手机号 / 任意账号登录 |
| 支付逻辑 | 金额/订单号可控、回调未验签 | 以篡改金额完成支付 |
| 渲染 | 富文本/Markdown 渲染未净化 | 小程序内执行注入（需真机验证） |

### 2.3 验收标准

1. 新增 `references/miniprogram_security.md`：包获取 → 反编译 → 接口/密钥提取 → 越权验证链路。
2. 云开发越权必须给出**匿名或跨用户**读取证据；仅"规则看起来宽松"不算。
3. 接口越权统一复用 `business_logic.py ab` 的 A/B 交叉证明口径。

---

## 3. Android 组件安全 + APK 逆向（P1）

### 3.1 拆成三段流水线（快筛 → 脱壳 → 深挖）

| 段 | 目的 | 输入 | 输出 | 参考工作量 |
|---|---|---|---|---|
| **快筛** | 大包不等待全量反编译，秒级定位 | APK（可 >100MB） | 密钥/隐藏接口/组件清单/引用链 | 中 |
| **脱壳** | 加固包还原 dex 与全量产物 | 有壳 APK | JADX/apktool 全量还原 + so/H5/assets | 大 |
| **审计** | 组件安全与密钥追踪成洞 | 还原产物 | 可提交 finding | 大 |

### 3.2 检测清单

| 类 | 检测项 | 可判定证据 |
|---|---|---|
| 导出组件 | `exported=true` 的 Activity/Service/Receiver/Provider 未授权 | ADB 无权限调用成功且产生实际效果 |
| Intent 重定向 | 可被第三方 App 构造 Intent 触发内部功能 | 越权拉起内部页面/带参执行 |
| PendingIntent | 可变 PendingIntent 被劫持 | 第三方拿到并改写 |
| WebView | `addJavascriptInterface`、`setAllowFileAccess` | JS 桥任意文件读/命令执行 |
| ContentProvider | 路径穿越 / SQL 注入 / 未授权读写 | 读到他人数据 |
| Binder / AIDL | 服务未校验调用方包名/权限 | 低权 App 调用高权服务 |
| Deep Link | scheme 劫持 / 参数注入 | 跳转到任意页面并带参 |
| 硬编码密钥 | `appKey/appSecret` 提取后未授权调接口 | 接口返回真实数据（**最高优先级**） |
| 组件面清单 | Manifest 组件与权限全景 | 组件矩阵（进线索板 hosts 区块） |

### 3.3 验收标准

1. 新增 `references/android_audit.md`（组件安全 checklist + ADB 验证命令 + PoC 构建）。
2. 新增 `references/apk_reversing.md`（壳识别 → 脱壳 → 全量还原 → 产物交付）。
3. 组件漏洞必须给出 **ADB 可复现命令 + 实际效果**，"组件导出但无效果"不得作为 finding。
4. 无 Frida / 无 Root 场景必须给出降级验证路径（这是真实交付中最常见的前置条件）。
5. 合规：仅测自有 App 或授权范围内的目标；不得对第三方应用商店 App 做未授权逆向。

---

## 4. Windows PE 逆向（P2）

### 4.1 为何暂列最后

与当前 Web/SRC 主战场关联最弱，且学习曲线最陡 —— 但它是"Phantom"这个名字的本义，
也是长期能力短板，应在上述三项之后启动。

### 4.2 检测清单（初版）

静态：PE 结构（节表、导入导出表、TLS 回调）、编译器指纹、加壳识别（UPX/Themida/VMProtect）、
字符串与资源提取、`.NET` 元数据还原。
动态：行为监控（文件/注册表/网络）、反调试与反虚拟化识别、协议逆向。
漏洞：缓冲区溢出（栈/堆）、格式化字符串、UAF、整数溢出、DLL 劫持与搜索顺序劫持。

### 4.3 验收标准

1. 新增 `references/pe_reversing.md`（静态 → 动态 → 漏洞定位三段）。
2. 分析结果必须落到「可复现的崩溃/任意代码执行证据」才算 finding，仅有静态可疑点进 lead。
3. 合规：仅分析自有软件、授权样本或公开靶场（如 `exploit-db` 提供的测试环境）。

---

## 5. 分阶段落地计划

| 版本 | 内容 | 交付物 | 依赖 |
|---|---|---|---|
| **v5.8** | AI/LLM 安全域 | `references/ai_llm_security.md`、`rules/ai_llm_security.yaml`、`report_docx.TYPE_GATES` 扩展、`AGENTS.md` 路由表补一行 | 无（纯新增） |
| **v5.9** | 小程序安全域 | `references/miniprogram_security.md`、反编译产物解析辅助脚本、复用 `business_logic.py ab` | v5.8 的 A/B 口径 |
| **v5.10** | Android 快筛 + 组件审计 | `references/android_audit.md`、`references/apk_reversing.md`、组件清单提取脚本 | v5.9 的接口越权口径 |
| **v5.11** | PE 逆向 | `references/pe_reversing.md` | — |

**每阶段完成的统一验收**（缺一不算完成）：

1. 参考手册到位（含判定标准与不可提交的反例）。
2. 规则/类型命门与 `report_docx` 对齐（新类型必须有对应的类型命门，否则不予收录）。
3. `AGENTS.md` 第 3 节路由表新增该域触发信号行。
4. `README.md` / `SKILL.md` / `assets/manifest.yml` 版本与能力描述同步。
5. 至少一个端到端样例走通：检测 → `judge` → `report_docx --gate-only` → DOCX。

---

## 6. 一句话总结

四个域的共同点：**它们的漏洞无法用通用扫描器发现，靠的是"知道该看哪里"**。
本路线图的每一段都把这件事拆成「入口点 → 检测清单 → 可判定证据 → 过门口径」，
与既有引擎（`oob_client.py` / `advanced_injection.py` / `business_logic.py` / `report_docx.py`）
在落地层复用，而不是另起一套。
