# 业务逻辑 / 越权 / 竞态 — 方法论手册

> 对应 `scripts/business_logic.py`（v5.7 新增）与 `AGENTS.md` 纪律四、纪律六。
> 适用：授权 SRC / 众测 / 内网自查 / 靶场。**未授权目标不适用**。
> 定位：本文件补的是「不能被自动化」的那一半 —— 业务怎么建模、越权怎么证明、并发怎么打。

---

## 0. 为什么单独成册

GKN-Phantom 的 `rules/` 里早就有 `logic_flaw` / `race_condition` / `mass_assignment` 检测条目，
但它们只是**规则**：能告诉你"这个端点像是有逻辑缺陷"，不能告诉你：

- 这个业务的状态机长什么样、哪条转换不该存在；
- 越权要怎么证明才算"可判定"，而不是"疑似"；
- 并发重放要怎么做、做几次、成功几次算成立；
- 修的时候该加幂等键还是唯一索引。

SRC 的严重/高危档位很大比例落在越权与资金逻辑上，而这两块恰恰**不能靠扫描器**。
本手册把 CkSKILLS 那类"经验型判定规则"固化成可执行的步骤。

---

## 1. 业务建模五问（不过五问，不许开测）

| # | 问题 | 落位产物 | 缺了会怎样 |
|---|---|---|---|
| ① | 完整状态机有哪些状态？ | `states[]` | 不知道该测哪些"终态" |
| ② | 每个转换谁有权执行？ | `transitions[].actor` + `roles[]` | 越权矩阵无从展开 |
| ③ | 哪些转换不应被允许？ | `transitions[].allowed=false` + `why_forbidden` | 没有假设可证伪 |
| ④ | 一致性校验在哪一层？ | `transitions[].guard` | 会漏掉"服务端是否二次校验金额" |
| ⑤ | 并发会不会出问题？ | `concurrency_notes` | 漏掉所有资金/权益竞态 |

用 `business_logic.py model --file m.json` 校验；`errors` 是结构性错误（必须修），
`gaps` 是五问缺项（会导致漏测）。**两道都干净才开测。**

模型最小骨架：

```json
{
  "unit": "订单系统",
  "states": ["cart", "unpaid", "paid", "shipped", "refunded"],
  "roles": ["guest", "user", "admin"],
  "concurrency_notes": "支付回调与退款可并发",
  "transitions": [
    {"from": "cart", "to": "unpaid", "actor": "user",
     "endpoint": "POST /api/order/create", "guard": "服务端重算金额", "allowed": true},
    {"from": "unpaid", "to": "paid", "actor": "user",
     "endpoint": "POST /api/pay/callback", "allowed": false,
     "why_forbidden": "应由支付网关回调签名驱动，不应由前端直接触发"}
  ],
  "resources": [
    {"name": "order", "url": "https://t/api/order/1001",
     "id_param": "orderId", "owner_field": "userId"}
  ]
}
```

---

## 2. 三类场景的攻击点表

完整表在 `business_logic.py` 的 `SCENES`（`scene --name payment|entitlement|flow`）。
摘要：

### 2.1 支付链路（payment）

| 攻击点 | 手法 | 可判定证据 |
|---|---|---|
| 金额篡改 | 改 `amount/price/total` 为 0.01 或负数 | 订单以篡改后金额创建**且支付成功** |
| 数量篡改 | `quantity` 置负 / 超量 / 小数 | 总价被压低或库存超额扣减 |
| 状态跳变 | 直接调确认/发货接口跳过支付 | 订单由 `unpaid` 直达 `paid`/`shipped` |
| 回调伪造 | 无签名/弱签名回调重放 | 服务端按伪造回调置为已支付 |
| 重复支付/退款 | 并发或重放同一请求 | 余额或订单状态多次变更 |
| 优惠券重复核销 | 同券并发核销 | 券被多次核销或超额抵扣 |

### 2.2 权益链路（entitlement）

无限领取、权益越权（参数带 `vipLevel/roleType`）、试用期重置、积分/余额负值、
付费资源直取（改 `resourceId`）、导出限次绕过、邀请奖励自循环、权益归属越权。

### 2.3 流程链路（flow）

步骤跳过、凭证回放（一次性链接/验证码二次生效）、状态覆盖（后提交覆盖前结果）、
审批人可控（请求带 `approverId`）、定时任务手动触发、草稿态越权访问、
分享链接 token 可枚举、同单据并发提交出双记录。

> 生成计划：`business_logic.py plan --file m.json --out plan.md`
> 加 `--board-root hunts --target <T>` 会把「未决假设 + 角色矩阵待办」直接写进线索板。

---

## 3. 越权的可判定硬标准（A/B 交叉证明）

**"疑似越权"不是结论。** 可判定的标准只有一条：

> **A 的资源，必须用 B 的凭证读到。**

流程（`business_logic.py ab` 生成请求对）：

1. **基线**：A（所有者）自己的凭证请求 `GET /api/order/1001` → 期望 200，记录响应体指纹。
2. **交叉**：B（攻击者）的凭证请求**同一 URL** → 若 200 且响应含同一资源标识（同 `orderId` /
   同一 `userId` / 同一响应体哈希）→ 构成越权读取。
3. **无凭证对照**：不带凭证请求同一 URL →
   - 也 200 → 这不是 IDOR，而是**未授权访问/公开接口泄露**，报告类型要改；
   - 401/403 → 说明接口本身有鉴权，问题出在**对象级**校验缺失，坐实 IDOR。
4. **结果处置**：
   - 交叉 401/403 → **假设证伪**，写 `clueboard.py add --section excluded`，停止，不许上报；
   - 交叉 200 → 生成 finding，`submission_type=idor`，走 `judge` 判定。

角色矩阵（垂直越权）同理：`plan` 会输出「每个转换 × 每个非授权角色」的反例对，
只要出现"非授权角色拿到 200 且业务生效"，即为垂直越权。

> ❌ 不要用"把自己的 token 换成别人 ID 能返回数据"当结论 —— 必须存在**另一个真实账号**的凭证。
> ❌ 不要用未登录状态跑出 200 就写 IDOR —— 那是未授权访问，定级与修复方向都不同。

---

## 4. 并发与竞态

### 4.1 判定标准

| 证据 | 成立条件 |
|---|---|
| 成功计数 | 并发下 2xx 次数 **>** 业务允许的唯一成功数（券只应核销 1 次） |
| 状态差异 | 执行前后余额/库存/券数出现**超发或负数** |
| 排除解释 | **串行**重放同样次数无异常 → 排除"业务本就可重复" |

三条缺一条就是 inconclusive，不能出稿（与 `report_docx` 硬门 2/4 对齐）。

### 4.2 方法（`business_logic.py race` 生成骨架）

| 方法 | 适用 | 注意 |
|---|---|---|
| `xargs -P` | 快速验证，够用 | `-P` 的值**已被压到授权速率**，别手改成"越大越好" |
| Python 线程池 + 信号量 | 需要统计与控速 | 瞬时并发用 `Semaphore` 卡死上限 |
| Turbo Intruder / 同连接管线化 | 打**库层**竞态（前一秒窗口） | 属 L4 动作，需人工审批；仅预发/靶场 |

> **红线**：并发度不得超过授权通告允许的速率；生产环境禁跑；不做压测式并发。
> SRC 场景下这既是合规要求，也是避免被封 IP / 取消成绩的现实考虑。

### 4.3 修复方向（写进报告才有价值）

见 `business_logic.py fix --type race_condition`。核心五条：
唯一索引兜底 → 乐观锁/`FOR UPDATE` → 资源维度分布式锁 →
条件更新 `UPDATE ... SET n=n-1 WHERE n>0` → 异步对账自动冲正。

---

## 5. 判定与交付的衔接

`business_logic.py judge --file evidence.json` 的返回：

| 字段 | 含义 |
|---|---|
| `verdict` | `pass` / `fail` / `inconclusive`（退出码 0/1/2，可直接分支） |
| `submission_type` | 对齐 `report_docx.TYPE_LABELS`（`idor` / `race_condition` / `logic_flaw` / `priv_esc` / `mass_assignment`） |
| `gate_hint` | 对应 `report_docx` 的**硬门 4 类型命门**要求，两边口径一致 |
| `suggested_severity` | 建议危害等级（**CVSS 不由本技能自评**，交提交平台评定） |

**关键**：缺「先证伪/对照」证据时，`judge` 直接返回 `inconclusive` —— 这与
`report_docx` 硬门 0 是同一口径。方法论层过了才谈成稿，成稿还要再过六道硬门。

标准衔接链：

```
business_logic.py plan   → 建板 + 产出测试计划
business_logic.py ab     → 生成 A/B 请求对（copy 进 Burp Repeater 执行 + 截图）
business_logic.py judge  → pass 才继续
report_docx.py --gate-only → 六道硬门复核
report_docx.py            → 出 DOCX 提交稿（截图铁律）
clueboard.py cover         → 覆盖度回写
```

---

## 6. 附则：零身份公开面还原（P1-6 沉淀）

场景：**没有账号、路径不在主站 JS 里、前端加密看起来像鉴权**。这类目标是 SRC 的常见起手式。

### 6.1 四条铁律

1. **主站 JS 里没有 ≠ 接口不存在** —— SPA 的 404 是路由的 404，不是接口的 404。
2. **客户端拿得到 RSA/AES/uuid ≠ 鉴权** —— `getRsaKey` 公网可取是常态，加密只是传输层包装。
3. **旧 H5 下线 ≠ 后端方法下线** —— 前端页面撤了，接口往往还在。
4. **不要拿"已登录的 Network 面板"当发现源** —— 那是在测已知接口，不是找未知接口。

### 6.2 方法

- **响应指纹分流**：`405`（方法存在但不对）、`200` + `data:[]`（接口存在、参数不全）、
  短文案「链接不存在」（网关级兜底，与业务 404 不同）—— 三种指纹指向不同的下一步。
- **加密证伪**：把加密参数替换为固定值/错误值，若后端不报验签失败，说明加密没参与鉴权。
- **迁域与兄弟域复查**：主域封了就走同 IP / 兄弟域 / 旧域名，用 `--resolve` 换 Host 重试。
- **历史资产**：Wayback / `crt.sh` / GitHub 泄露 / 招聘 JD / Changelog 里挖旧接口名。

### 6.3 落地到模块

`directory_fuzzer.py`（116 路径 + 20 扩展名 + SimHash 软 404 检测）
→ `js_analyzer.py`（含 source map 还原）
→ `cn_probes.py`（国内组件暴露面）
→ 本手册第 3 节的 A/B 交叉证明收尾。

---

## 7. 一页检查表

开测前：

- [ ] 五问齐全（`model` 无 `errors`、无 `gaps`）
- [ ] `clueboard.py brief --target <T>` 看过上轮结论与**已排除**项
- [ ] 角色矩阵已在板上展开成待办

拿到结论前：

- [ ] 越权有 A/B 交叉证明（含无凭证对照）
- [ ] 竞态有「成功计数 + 状态差异 + 串行对照」三件套
- [ ] 逻辑有「服务端跟随客户端值 + 落库成功 + 终态」
- [ ] 先证伪记录已写（`falsification`）
- [ ] `judge` 返回 `pass`

交付前：

- [ ] `report_docx.py --gate-only` 六道硬门全过
- [ ] 截图真实、命名语义化、查重无命中
- [ ] 覆盖度 ✅/❌/🔄/💡 已回写线索板
