#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""business_logic.py — 业务逻辑 / 越权 / 竞态 方法论引擎 (v5.7 NEW)

把「业务逻辑漏洞」从一条检测规则变成一套可执行工作流：

    model  → 业务建模五问，产出并校验状态机模型（缺口清单）
    plan   → 由模型 + 角色产出测试计划（跳步/回放/覆盖 + 角色矩阵 + 竞态 + 修复映射）
    ab     → 生成越权 A/B 交叉证明的请求对（可判定的硬标准，不是「疑似」）
    race   → 生成速率受限的并发重放计划（只出命令骨架，不发包）
    judge  → 判定证据是否构成可提交结论（与 report_docx 的硬门/类型命门对齐）
    scene  → 打印场景攻击点表（payment / entitlement / flow）
    fix    → 打印某类型的修复方向

设计约束
--------
* 本模块**不发起任何网络请求**：只产出结构化计划、请求对与判定结论。
* 判定结果用 `submission_type` / `gate_hint` 与 `report_docx.py` 的类型命门对齐，
  使「方法论层」与「交付层」口径一致（越权必须 A/B 交叉证明才算过门）。
* 合规：仅用于授权测试 / SRC 公告范围 / 靶场。见 references/safety_policy.md。

用法示例
--------
    python business_logic.py scene --name payment
    python business_logic.py model --file model.json
    python business_logic.py plan  --file model.json --out plan.md
    python business_logic.py plan  --file model.json --board-root hunts
    python business_logic.py ab    --url https://t/api/order/1001 \
        --owner-token "session=A" --attacker-token "session=B"
    python business_logic.py race  --endpoint https://t/api/coupon/claim --replays 20
    python business_logic.py judge --file evidence.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys

try:  # 线索板是可选依赖：缺了也能出计划，只是不落板
    import clueboard
except Exception:  # pragma: no cover - import guard
    clueboard = None


# ---- 业务建模五问 ------------------------------------------------------------
# 五问缺一，模型即不完整。`gaps` 会把缺的列出来，避免「凭感觉测业务逻辑」。
MODEL_QUESTIONS = [
    ("states", "完整状态机有哪些状态？（每一步的落库状态）"),
    ("transitions", "每个状态转换谁有权执行？（角色 × 转换）"),
    ("forbidden", "哪些转换在业务上不应被允许？（跳步/回退/覆盖）"),
    ("consistency", "一致性校验在哪一层？（服务端是否二次校验金额/数量/归属）"),
    ("concurrency", "并发会不会出问题？（同一资源被并行消费）"),
]

# ---- 场景攻击点表 -----------------------------------------------------------
# 三元组语义：(攻击点, 手法, 可判定证据, submission_type)
# submission_type 必须落在 report_docx.TYPE_GATES / TYPE_LABELS 的词表内。
SCENES = {
    "payment": [
        ("金额篡改", "把 amount/price/total 改成 0.01 或负数",
         "订单以篡改后金额创建且支付成功", "logic_flaw"),
        ("数量篡改", "quantity 置负 / 超量 / 小数",
         "总价被压低或库存被超额扣减", "logic_flaw"),
        ("状态跳变", "直接调用确认/发货接口跳过支付",
         "订单由 unpaid 直达 paid/shipped", "logic_flaw"),
        ("回调伪造", "无签名或弱签名回调接口重放/篡改金额",
         "服务端按伪造回调置为已支付", "logic_flaw"),
        ("重复支付/退款", "并发或重放同一支付/退款请求",
         "余额或订单状态出现多次变更", "race_condition"),
        ("退款不回滚库存", "退款后库存/权益未回滚",
         "库存与账面不一致且可继续下单", "logic_flaw"),
        ("优惠券叠加/重复核销", "同一券并发核销或叠加规则绕过",
         "券被多次核销或超额抵扣", "race_condition"),
        ("订单归属越权", "用 B 的凭证读/改 A 的 orderId",
         "B 读到 A 的订单明细", "idor"),
    ],
    "entitlement": [
        ("无限领取", "活动/新人礼/每日签到并发领取",
         "领取次数超出规则上限", "race_condition"),
        ("权益越权", "普通用户参数带 vipLevel/roleType 提权",
         "越级拿到付费权限", "priv_esc"),
        ("试用期重置", "改设备指纹/手机号无限白嫖试用",
         "试用被无限延长", "logic_flaw"),
        ("积分/余额负值", "兑换时置负或先兑后付",
         "余额变负仍可兑换", "logic_flaw"),
        ("付费资源直取", "改 resourceId 直接拉付费内容",
         "未购买即拿到完整内容", "idor"),
        ("导出限次绕过", "批量导出限次被多账号/多参数绕过",
         "超出配额仍可导出", "logic_flaw"),
        ("邀请奖励自循环", "自己邀请自己 / 环状邀请",
         "无真实新增用户却拿到奖励", "logic_flaw"),
        ("权益归属越权", "用 B 的凭证读 A 的会员信息",
         "B 读到 A 的会员/订单", "idor"),
    ],
    "flow": [
        ("步骤跳过", "直接提交最后一步的表单/接口",
         "未完成前置步骤即落库", "logic_flaw"),
        ("凭证回放", "重放已使用的一次性凭证/链接",
         "凭证二次生效", "logic_flaw"),
        ("状态覆盖", "先提交 A 再提交 B 覆盖 A 的结果",
         "审核态/数据被后写入覆盖", "logic_flaw"),
        ("审批人可控", "请求里带 approverId/nextRole",
         "可指定自己为审批人", "priv_esc"),
        ("定时任务手动触发", "直接调用内部任务接口",
         "未授权触发批处理", "logic_flaw"),
        ("草稿态越权访问", "草稿/未发布资源无鉴权可读",
         "读到他人草稿内容", "idor"),
        ("分享链接越权", "分享 token 可枚举/可改",
         "越权访问他人资源", "idor"),
        ("多处提交竞态", "同一单据并发提交",
         "出现两条有效记录", "race_condition"),
    ],
}

# ---- 并发重放方法 -----------------------------------------------------------
# 只给骨架，不代跑。并发度必须落在授权通告允许的速率之内。
RACE_METHODS = [
    ("xargs -P（最省事）",
     "# 并发度 -P 已被压到授权允许速率 {limit}；响应体丢弃只留状态码\n"
     "seq 1 {n} | xargs -P {limit} -I IDX \\\n"
     "  curl -s -o /tmp/r_IDX.txt -w '%{{http_code}}\\n' \\\n"
     "  -X {method} '{url}'{headers}{data}"),
    ("Python 线程池（可控不超速）",
     "# 用信号量把瞬时并发限制在授权上限内；每轮之间留 1s 冷却\n"
     "import threading, requests\n"
     "SEM = threading.Semaphore({limit})\n"
     "for i in range({n}):\n"
     "    threading.Thread(target=fire, args=(SEM,)).start()"),
    ("Turbo Intruder / Burp（同连接管线化）",
     "# 单连接并发才能真正打穿库层的竞态；注意这是 L4 动作，需人工审批\n"
     "# 仅对已授权的预发/靶场使用；生产禁用"),
]

# ---- 修复方向 ---------------------------------------------------------------
REMEDIATION = {
    "logic_flaw": [
        "服务端二次校验金额/数量/归属，忽略客户端提交的价格与折扣",
        "枚举白名单式状态转换表，禁止任意 from→to",
        "关键操作加业务幂等键（订单号+动作指纹），重复请求直接返回首次结果",
        "回调必须验签 + 校验金额 + 校验订单状态前置条件",
        "敏感字段（role/vipLevel/isAdmin）服务端只读，禁止从请求体映射",
    ],
    "race_condition": [
        "数据库唯一索引兜底（券码核销、领取记录各一条）",
        "乐观锁（version 字段）或 SELECT ... FOR UPDATE 串行化临界区",
        "分布式锁按资源维度加锁，锁粒度到「用户+活动」而非「接口」",
        "库存/余额扣减用条件更新：UPDATE ... SET n=n-1 WHERE n>0",
        "异步补偿队列 + 对账任务，发现不一致自动冲正",
    ],
    "idor": [
        "每个对象访问都做「资源→所有者」校验，不在列表层做一次就复用",
        "用当前会话身份拼 SQL 条件（WHERE owner_id = current_user），而非只按 id 查",
        "对外暴露不可枚举的 ID（UUID/雪花），但不以不可枚举代替鉴权",
        "统一鉴权中间件，禁止个别接口漏挂",
    ],
    "priv_esc": [
        "角色从服务端会话/目录服务读取，禁止任何客户端角色声明参与鉴权",
        "管理端接口独立鉴权，与前台接口不共用同一套过滤器",
        "审批人/流程角色由流程引擎决定，不接受请求参数指定",
        "对越权访问记审计日志并告警",
    ],
    "mass_assignment": [
        "用 DTO/白名单绑定请求字段，禁止直接把请求体映射为实体",
        "敏感属性只读，或在绑定层显式排除",
    ],
}

# ---- 判定硬标准 -------------------------------------------------------------
# 与 report_docx 的「硬门4 类型命门」同一口径：过不了这里，就不该写报告。
GATE_HINT = {
    "idor": "ab_proof / cross_account_proof —— A 的资源必须用 B 的凭证读到",
    "priv_esc": "越权访问到高权限功能或数据（不是「参数看起来可改」）",
    "race_condition": "state_change_proof + concurrency_proof —— 多次成功响应或数据差异",
    "logic_flaw": "state_change_proof —— 操作真实生效且影响业务状态",
    "mass_assignment": "敏感字段被实际写入并生效",
}


# ---- 模型校验 ---------------------------------------------------------------
def validate_model(model: dict) -> dict:
    """校验业务模型：结构性错误进 errors，五问缺项进 gaps。纯函数，不抛异常。"""
    errors, gaps = [], []
    if not isinstance(model, dict):
        return {"ok": False, "errors": ["model 不是 JSON 对象"], "gaps": [k for k, _ in MODEL_QUESTIONS]}

    states = model.get("states")
    if not isinstance(states, list) or not states:
        errors.append("states 必须是非空数组（完整状态机）")
        states = []

    transitions = model.get("transitions")
    if not isinstance(transitions, list) or not transitions:
        errors.append("transitions 必须是非空数组（状态转换）")
        transitions = []

    roles = model.get("roles")
    if not isinstance(roles, list) or not roles:
        errors.append("roles 必须是非空数组（角色矩阵的列）")
        roles = []

    for i, tr in enumerate(transitions):
        if not isinstance(tr, dict):
            errors.append("transitions[%d] 不是对象" % i)
            continue
        for key in ("from", "to", "actor", "endpoint"):
            if not tr.get(key):
                errors.append("transitions[%d] 缺字段 %s" % (i, key))
        for key in ("from", "to"):
            val = tr.get(key)
            if val and states and val not in states:
                errors.append("transitions[%d].%s='%s' 不在 states 中" % (i, key, val))
        if tr.get("allowed") is False and not tr.get("why_forbidden"):
            gaps.append("transitions[%d] 标记为 forbidden，但没写 why_forbidden（无法据此设计否定实验）" % i)

    # 五问落位检查
    if not any(tr.get("guard") for tr in transitions if isinstance(tr, dict)):
        gaps.append("五问③一致性校验位置缺失：没有任何转换标注 guard（服务端校验在哪一层）")
    if not model.get("concurrency_notes") and not any(
        str(tr.get("to", "")).lower() in ("paid", "shipped", "refunded", "delivered") for tr in transitions
        if isinstance(tr, dict)
    ):
        gaps.append("五问⑤并发说明缺失：未提供 concurrency_notes，且没有资金/权益终态可推断竞态点")
    if not model.get("unit"):
        gaps.append("缺少 unit（被建模的业务单元名），计划书与报告无法定位资产")

    return {"ok": not errors, "errors": errors, "gaps": gaps}


# ---- 计划生成 ---------------------------------------------------------------
def build_plan(model: dict) -> dict:
    """由模型产出测试计划。纯函数。"""
    unit = model.get("unit") or "未命名业务单元"
    states = list(model.get("states") or [])
    roles = list(model.get("roles") or [])
    transitions = [t for t in (model.get("transitions") or []) if isinstance(t, dict)]
    resources = [r for r in (model.get("resources") or []) if isinstance(r, dict)]

    # 未决假设：每条 forbidden 转换一条「假设」，并给出怎么证伪 + 结果位
    assumptions = []
    for tr in transitions:
        if tr.get("allowed") is False:
            hyp = "系统允许 %s→%s 的非法转换" % (tr.get("from"), tr.get("to"))
            falsify = "以 %s 身份直接请求 %s；若被拒（4xx/状态未变）则本假设证伪" % (
                tr.get("actor", "user"), tr.get("endpoint", "?"))
            assumptions.append([hyp, "假设", falsify, tr.get("why_forbidden", "")])
    # 一致性缺口也转成假设
    for tr in transitions:
        if tr.get("allowed") is not False and not tr.get("guard"):
            assumptions.append([
                "%s→%s 依赖客户端提交值（无服务端二次校验）" % (tr.get("from"), tr.get("to")),
                "假设",
                "先发基线请求记录服务端计算值，再改客户端值重发；服务端跟着变即证伪失败",
                "转待打前先确认校验位置",
            ])
            break  # 只提示一条代表，避免刷爆 5 条上限

    # 跳步 / 回放 / 覆盖：由状态图推导，而非拍脑袋
    skip_tests, replay_tests, overwrite_tests = [], [], []
    reachable = {}
    for tr in transitions:
        reachable.setdefault(tr.get("from"), set()).add(tr.get("to"))
    for tr in transitions:
        frm, to = tr.get("from"), tr.get("to")
        # 跳步：存在 X→Y 且 Y 不是 X 的直接后继，但 Y 可达 → 尝试 X→…→Y 的直达
        if tr.get("allowed") is False:
            skip_tests.append({
                "from": frm, "to": to, "endpoint": tr.get("endpoint"),
                "action": "以合法前驱身份的凭证，直接请求该终态接口，观察是否跳过中间状态",
            })
    for tr in transitions:
        ep = str(tr.get("endpoint") or "")
        if any(k in ep.lower() for k in ("callback", "notify", "confirm", "verify", "sms", "email")):
            replay_tests.append({
                "endpoint": ep,
                "action": "同一凭证/回调重放（含时间戳与签名原样重放），观察是否二次生效",
            })
    for state in states:
        if str(state).lower() in ("draft", "pending", "reviewing", "submitted"):
            overwrite_tests.append({
                "state": state,
                "action": "对该状态的资源二次提交，观察是否覆盖上一条有效记录",
            })

    # 角色矩阵：每个转换的 actor 之外的每个角色都应被拒 → 一行一个反例对
    role_matrix = []
    for tr in transitions:
        for role in roles:
            if role == tr.get("actor"):
                continue
            role_matrix.append({
                "endpoint": tr.get("endpoint"),
                "transition": "%s→%s" % (tr.get("from"), tr.get("to")),
                "caller": role,
                "expect": "403/401 或业务拒绝",
                "if_pass": "垂直越权（%s 执行了 %s 的转换）" % (role, tr.get("actor")),
            })

    # 竞态目标：端点/资源名含资金与权益关键词
    race_targets = []
    keywords = ("pay", "order", "refund", "coupon", "point", "balance", "stock",
                "claim", "redeem", "transfer", "withdraw", "sign", "voucher", "gift")
    for tr in transitions:
        blob = ("%s %s" % (tr.get("endpoint", ""), tr.get("to", ""))).lower()
        if any(k in blob for k in keywords):
            race_targets.append({
                "endpoint": tr.get("endpoint"),
                "reason": "涉及金额/权益/库存，重复执行有实际收益",
                "method": "见 race 子命令生成的骨架",
            })

    # IDOR 交叉证明目标
    ab_targets = []
    for res in resources:
        ab_targets.append({
            "resource": res.get("name"),
            "url_template": res.get("url"),
            "id_param": res.get("id_param"),
            "owner_field": res.get("owner_field"),
            "action": "用 A 的凭证取一个 A 的资源 URL，再用 B 的凭证请求同一 URL",
        })

    return {
        "unit": unit,
        "questions": [{"key": k, "ask": q} for k, q in MODEL_QUESTIONS],
        "validation": validate_model(model),
        "assumptions": assumptions,
        "state_tests": {"skip": skip_tests, "replay": replay_tests, "overwrite": overwrite_tests},
        "role_matrix": role_matrix,
        "ab_targets": ab_targets,
        "race_targets": race_targets,
        "fixes": REMEDIATION,
        "gate_hints": GATE_HINT,
    }


def render_plan_md(plan: dict) -> str:
    """把计划渲染成可读 Markdown（也是写回线索板的素材）。"""
    L = []
    add = L.append
    v = plan["validation"]
    add("# 业务逻辑测试计划 — %s" % plan["unit"])
    add("")
    add("> 由 `business_logic.py plan` 生成。测试前先读线索板，测完把结论写回板。")
    add("> 合规：仅授权范围；并发与破坏性动作限 L4 审批后执行。")
    add("")
    add("## 0. 建模五问落位")
    add("")
    add("| 问 | 内容 |")
    add("| --- | --- |")
    for q in plan["questions"]:
        add("| %s | %s |" % (q["key"], q["ask"]))
    add("")
    if v["errors"]:
        add("**结构性错误（必须先修模型）**")
        add("")
        for e in v["errors"]:
            add("- ❌ %s" % e)
        add("")
    if v["gaps"]:
        add("**模型缺口（会导致漏测）**")
        add("")
        for g in v["gaps"]:
            add("- ⚠️ %s" % g)
        add("")

    add("## 1. 未决假设（最多 5 条，含怎么证伪）")
    add("")
    if plan["assumptions"]:
        add("| 假设 | 状态 | 怎么证伪 | 备注 |")
        add("| --- | --- | --- | --- |")
        for row in plan["assumptions"][:5]:
            add("| %s | %s | %s | %s |" % tuple(row))
    else:
        add("_无（模型未标注 forbidden 转换）_")
    add("")

    st = plan["state_tests"]
    add("## 2. 状态机测试")
    add("")
    for title, key in (("跳步（forbidden 转换直达）", "skip"),
                       ("回放（一次性凭证/回调重放）", "replay"),
                       ("覆盖（草稿/待审二次提交）", "overwrite")):
        rows = st.get(key) or []
        add("### %s" % title)
        add("")
        if not rows:
            add("_无命中_")
        for r in rows:
            add("- `%s` → %s" % (r.get("endpoint") or r.get("state"), r["action"]))
        add("")

    add("## 3. 角色矩阵（越权反例对）")
    add("")
    if plan["role_matrix"]:
        add("| 端点 | 转换 | 调用者 | 期望 | 若通过 |")
        add("| --- | --- | --- | --- | --- |")
        for r in plan["role_matrix"]:
            add("| %s | %s | %s | %s | %s |" % (
                r["endpoint"], r["transition"], r["caller"], r["expect"], r["if_pass"]))
    else:
        add("_无（模型缺 roles 或 transitions）_")
    add("")

    add("## 4. A/B 交叉证明目标（IDOR 硬标准）")
    add("")
    if plan["ab_targets"]:
        for r in plan["ab_targets"]:
            add("- **%s**：`%s`（ID 参数 `%s`，归属字段 `%s`）"
                % (r["resource"], r["url_template"], r["id_param"], r["owner_field"]))
            add("  - %s" % r["action"])
        add("")
        add("生成请求对：`business_logic.py ab --url <URL> --owner-token <A> --attacker-token <B>`")
    else:
        add("_无（模型未声明 resources）_")
    add("")

    add("## 5. 竞态目标（并发重放）")
    add("")
    if plan["race_targets"]:
        add("| 端点 | 为什么值得重放 |")
        add("| --- | --- |")
        for r in plan["race_targets"]:
            add("| %s | %s |" % (r["endpoint"], r["reason"]))
        add("")
        add("生成骨架：`business_logic.py race --endpoint <URL> --replays 20`")
    else:
        add("_无命中_")
    add("")

    add("## 6. 过门口径（写报告前必须满足）")
    add("")
    add("| 类型 | 类型命门 |")
    add("| --- | --- |")
    for k, hint in plan["gate_hints"].items():
        add("| %s | %s |" % (k, hint))
    add("")

    add("## 7. 修复方向")
    add("")
    for k, items in plan["fixes"].items():
        add("### %s" % k)
        add("")
        for it in items:
            add("- %s" % it)
        add("")
    return "\n".join(L) + "\n"


# ---- A/B 交叉证明 -----------------------------------------------------------
def make_ab(url: str, owner_token: str, attacker_token: str,
            method: str = "GET", body: str = "", headers: dict | None = None,
            owner_label: str = "A(资源所有者)", attacker_label: str = "B(攻击者)") -> dict:
    """生成三段证据请求：基线（A 自己）、交叉（B 读 A 的资源）、无凭证对照。"""
    req_headers = dict(headers or {})
    if owner_token:
        req_headers.setdefault("Cookie", owner_token)
    unauth_headers = {k: v for k, v in req_headers.items() if k.lower() != "cookie"}

    def block(label, hdrs):
        lines = ["%s %s HTTP/1.1" % (method.upper(), url)]
        for k, v in hdrs.items():
            lines.append("%s: %s" % (k, v))
        if body:
            lines.append("Content-Length: %d" % len(body.encode("utf-8")))
        lines.append("")
        if body:
            lines.append(body)
        return {"actor": label, "raw_request": "\n".join(lines)}

    return {
        "verdict_of_this_step": "生成证据，不代表结论；须交给 judge 判定",
        "baseline": block(owner_label, req_headers),
        "cross": block(attacker_label, {**req_headers, "Cookie": attacker_token} if attacker_token else req_headers),
        "unauth_control": block("对照(无凭证)", unauth_headers),
        "criteria": [
            "基线 200：说明 A 确实能访问该资源（资源存在且 A 有权）",
            "交叉 200 且响应含同一资源标识（同 id / 同一归属字段）：构成越权读取",
            "无凭证对照若也 200：则不是 IDOR 而是未授权访问，报告类型应改为未授权接口泄露",
            "交叉 401/403：本假设证伪，停止，不得按「疑似越权」上报",
        ],
        "record_to_board": "clueboard.py add --section excluded --text \"<URL> 对 B 返回 403（已证伪）\"",
    }


# ---- 竞态重放计划 -----------------------------------------------------------
def make_race(endpoint: str, replays: int = 20, method: str = "POST",
              body: str = "", headers: dict | None = None,
              authorized_rps: int = 3) -> dict:
    """生成并发重放骨架。并发度受授权速率约束，不做「无限并发」建议。"""
    replays = max(2, int(replays))
    limit = max(1, min(int(authorized_rps), replays))
    hdr = "".join(" -H '%s: %s'" % (k, v) for k, v in (headers or {}).items())
    data = " -d '%s'" % body if body else ""
    plan = []
    for name, tpl in RACE_METHODS:
        if "xargs" in name:
            cmd = tpl.format(n=replays, limit=limit, method=method.upper(),
                             url=endpoint, headers=hdr, data=data)
        else:
            cmd = tpl.format(n=replays, limit=limit)
        plan.append({"method": name, "skeleton": cmd})
    return {
        "endpoint": endpoint,
        "replays": replays,
        "authorized_rps_ceiling": authorized_rps,
        "concurrency_recommended": limit,
        "warning": "并发度不得超过授权通告允许速率；L4 动作需人工审批；生产禁跑。",
        "plan": plan,
        "success_criteria": [
            "统计 2xx 次数：超过业务允许的唯一成功数（如券只应核销 1 次）即为竞态",
            "比对执行前后状态：余额/库存/券数出现超发或负数即为竞态",
            "单一请求串行重放无异常而并发出现异常 → 排除「业务本就可重复」的解释",
        ],
        "judge_example": {
            "kind": "race", "endpoint": endpoint, "replays": replays,
            "expected_max_success": 1, "observed_success": 5,
            "state_after": "券剩余数 -4（超发）",
        },
    }


# ---- 证据判定 ---------------------------------------------------------------
def judge(evidence: dict) -> dict:
    """判定证据是否构成可提交结论。纯函数，永不抛异常。

    判定口径与 report_docx 的硬门 0 / 硬门 4 对齐：
    缺「先证伪」证据的一律 inconclusive。
    """
    ev = evidence if isinstance(evidence, dict) else {}
    kind = str(ev.get("kind") or "").strip().lower()
    reasons, warnings = [], []
    verdict = "inconclusive"

    # 硬门0 对齐：先证伪（否定实验）是前置条件
    has_falsify = bool(ev.get("falsification") or ev.get("negative_control") or ev.get("control"))
    if not has_falsify:
        return {
            "verdict": "inconclusive",
            "submission_type": None,
            "gate_hint": GATE_HINT.get(kind, ""),
            "reasons": ["缺少先证伪证据（否定实验/对照请求）—— 与 report_docx 硬门0 同一口径，先补对照再判定"],
            "warnings": [],
            "suggested_severity": None,
        }

    if kind == "idor":
        base = ev.get("baseline") or {}
        cross = ev.get("cross") or {}
        unauth = ev.get("unauth") or {}
        b_status = int(cross.get("status") or 0)
        a_status = int(base.get("status") or 0)
        if b_status == 0 or a_status == 0:
            reasons.append("baseline/cross 缺少 status，无法判定")
        elif a_status != 200:
            reasons.append("基线非 200（A 自己都访问不到），资源或凭证有误，不构成本类型结论")
        elif b_status in (401, 403):
            verdict = "fail"
            reasons.append("交叉请求被拒（%d）—— 该假设证伪，写入线索板 excluded，勿上报" % b_status)
        elif b_status == 200:
            same = bool(cross.get("same_resource")) or (
                base.get("body_hash") and base.get("body_hash") == cross.get("body_hash"))
            if int(unauth.get("status") or 0) == 200:
                verdict = "pass"
                reasons.append("无凭证对照同样 200 —— 实为未授权访问，submission_type 应为未授权接口泄露而非 IDOR")
                st = "info_leak"
            else:
                st = "idor"
                if same:
                    verdict = "pass"
                    reasons.append("B 用自身凭证读到了 A 的资源（同一资源标识/同一响应体指纹），构成越权")
                else:
                    verdict = "inconclusive"
                    reasons.append("交叉返回 200 但未证明是同一资源（缺 same_resource 或 body_hash 一致）")
            return _result(verdict, st, reasons, warnings)
        else:
            reasons.append("交叉返回 %d，需人工判断该状态码语义" % b_status)

    elif kind == "race":
        exp = ev.get("expected_max_success")
        obs = ev.get("observed_success")
        replays = ev.get("replays")
        if obs is None or exp is None:
            reasons.append("缺少 expected_max_success / observed_success")
        else:
            try:
                obs_i, exp_i = int(obs), int(exp)
            except Exception:
                reasons.append("observed_success / expected_max_success 必须是整数")
            else:
                if replays is not None and int(replays) < 2:
                    reasons.append("replays < 2，不构成并发证据")
                if obs_i > exp_i:
                    verdict = "pass"
                    reasons.append("实际成功 %d 次 > 业务允许 %d 次 —— 存在竞态" % (obs_i, exp_i))
                    if not ev.get("state_after"):
                        warnings.append("建议补 state_after（余额/库存/券数变化），否则类型命门证据不完整")
                else:
                    verdict = "fail"
                    reasons.append("成功次数未超上限，未观察到竞态")
        return _result(verdict, "race_condition", reasons, warnings)

    elif kind in ("logic", "logic_flaw"):
        client_v, server_v, list_v = ev.get("client_value"), ev.get("server_side_total"), ev.get("list_price")
        created = bool(ev.get("order_created"))
        if client_v is None or server_v is None:
            reasons.append("缺少 client_value / server_side_total（无法证明服务端是否跟随客户端值）")
        elif created and server_v == client_v and (list_v is None or list_v != client_v):
            verdict = "pass"
            reasons.append("服务端接受了客户端提交值（%s）并落库成功 —— 一致性校验缺失生效" % client_v)
            if not ev.get("state_after"):
                warnings.append("建议补 state_after（订单/余额终态）以过 report_docx 硬门2")
        elif not created:
            reasons.append("操作未真实生效（order_created=false），不构成结论")
        else:
            verdict = "fail"
            reasons.append("服务端未跟随客户端值，本假设证伪")
        return _result(verdict, "logic_flaw", reasons, warnings)

    elif kind in ("priv_esc", "vertical"):
        ok = bool(ev.get("high_priv_resource_reached"))
        if ok:
            verdict = "pass"
            reasons.append("低权身份实际访问到高权功能/数据")
        else:
            reasons.append("未提供 high_priv_resource_reached 证据")
        return _result(verdict, "priv_esc", reasons, warnings)

    elif kind == "mass_assignment":
        fields = ev.get("over_posted_fields") or []
        if fields and ev.get("persisted"):
            verdict = "pass"
            reasons.append("敏感字段 %s 被写入并生效" % ",".join(map(str, fields)))
        else:
            reasons.append("缺 over_posted_fields 或 persisted 证据")
        return _result(verdict, "mass_assignment", reasons, warnings)

    else:
        reasons.append("未知 kind='%s'（支持 idor / race / logic / priv_esc / mass_assignment）" % kind)

    return _result(verdict, None, reasons, warnings)


def _result(verdict: str, submission_type, reasons: list, warnings: list) -> dict:
    sev = {"idor": "high", "priv_esc": "critical", "race_condition": "high",
           "logic_flaw": "high", "mass_assignment": "high", "info_leak": "high"}.get(submission_type)
    return {
        "verdict": verdict,                      # pass / fail / inconclusive
        "submission_type": submission_type,      # 对齐 report_docx.TYPE_LABELS
        "gate_hint": GATE_HINT.get(submission_type, ""),
        "reasons": reasons,
        "warnings": warnings,
        "suggested_severity": sev,               # 仅建议，CVSS 不由本技能自评
        "note": "verdict=pass 只代表方法论层通过；成稿前仍需过 report_docx 的六道硬门。",
    }


# ---- 线索板联动 -------------------------------------------------------------
def push_to_board(root: str, target: str, plan: dict) -> dict:
    """把计划里的假设与待办写回线索板（可选能力，失败不阻断）。"""
    if clueboard is None:
        return {"ok": False, "reason": "clueboard 模块不可用"}
    try:
        clueboard.load_board(root, target)
    except Exception:
        try:
            clueboard.save_board(root, target, clueboard.blank_board(target, focus=plan["unit"]))
        except Exception as exc:
            return {"ok": False, "reason": "建板失败: %s" % exc}

    added, dups, capped = 0, 0, 0
    for row in plan["assumptions"][:5]:
        try:
            res = clueboard.add_row(root, target, "assumptions", row)
            if res.get("duplicate") or res.get("status") == "duplicate":
                dups += 1
            elif res.get("capped") or res.get("status") == "capped":
                capped += 1
            else:
                added += 1
        except Exception:
            pass
    for r in plan["role_matrix"][:10]:
        try:
            res = clueboard.add_row(root, target, "todos",
                                    ["角色矩阵：%s 以 %s 调用 %s" % (r["caller"], r["transition"], r["endpoint"])])
            if res.get("duplicate") or res.get("status") == "duplicate":
                dups += 1
            else:
                added += 1
        except Exception:
            pass
    return {"ok": True, "added": added, "duplicates": dups, "capped": capped,
            "board": clueboard.board_path(root, target)}


# ---- CLI --------------------------------------------------------------------
def _force_utf8_stdout() -> None:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="business_logic.py",
        description="业务逻辑 / 越权 / 竞态 方法论引擎：建模 → 计划 → 交叉证明 → 判定")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("model", help="校验业务状态机模型")
    sp.add_argument("--file", required=True)
    sp.add_argument("--json", action="store_true")

    sp = sub.add_parser("plan", help="由模型产出测试计划")
    sp.add_argument("--file", required=True)
    sp.add_argument("--out", default=None, help="写入 Markdown 计划书")
    sp.add_argument("--json", action="store_true")
    sp.add_argument("--board-root", default=None, help="把假设/待办写回线索板（如 hunts）")
    sp.add_argument("--target", default=None, help="线索板目标（--board-root 时必填）")

    sp = sub.add_parser("ab", help="生成越权 A/B 交叉证明请求对")
    sp.add_argument("--url", required=True)
    sp.add_argument("--owner-token", required=True, help="A（资源所有者）的凭证，如 session=xxx")
    sp.add_argument("--attacker-token", required=True, help="B（攻击者）的凭证")
    sp.add_argument("--method", default="GET")
    sp.add_argument("--body", default="")
    sp.add_argument("--header", action="append", default=[], help="额外头 Key: Value，可重复")

    sp = sub.add_parser("race", help="生成速率受限的并发重放骨架")
    sp.add_argument("--endpoint", required=True)
    sp.add_argument("--replays", type=int, default=20)
    sp.add_argument("--method", default="POST")
    sp.add_argument("--body", default="")
    sp.add_argument("--header", action="append", default=[])
    sp.add_argument("--authorized-rps", type=int, default=3, help="授权通告允许的每秒请求上限")

    sp = sub.add_parser("judge", help="判定证据是否构成可提交结论")
    sp.add_argument("--file", required=True)

    sp = sub.add_parser("scene", help="打印场景攻击点表")
    sp.add_argument("--name", choices=list(SCENES), default=None)
    sp.add_argument("--json", action="store_true")

    sp = sub.add_parser("fix", help="打印某类型的修复方向")
    sp.add_argument("--type", required=True, choices=list(REMEDIATION))

    return ap


def _pair_headers(items: list) -> dict:
    out = {}
    for it in items:
        if ":" in it:
            k, v = it.split(":", 1)
            out[k.strip()] = v.strip()
    return out


def main(argv: list | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.cmd == "model":
        model = json.load(open(args.file, encoding="utf-8"))
        res = validate_model(model)
        if args.json:
            print(json.dumps(res, ensure_ascii=False, indent=2))
        else:
            print("模型校验：%s" % ("通过" if res["ok"] else "失败"))
            for e in res["errors"]:
                print("  ❌ %s" % e)
            for g in res["gaps"]:
                print("  ⚠️ %s" % g)
        return 0 if res["ok"] else 1

    if args.cmd == "plan":
        model = json.load(open(args.file, encoding="utf-8"))
        plan = build_plan(model)
        if args.board_root:
            if not args.target:
                print("--board-root 需要同时给 --target", file=sys.stderr)
                return 2
            plan["board_push"] = push_to_board(args.board_root, args.target, plan)
        md = render_plan_md(plan)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(md)
            print(json.dumps({"out": args.out, "board_push": plan.get("board_push")},
                             ensure_ascii=False))
        elif args.json:
            print(json.dumps(plan, ensure_ascii=False, indent=2))
        else:
            print(md)
        return 0 if plan["validation"]["ok"] else 1

    if args.cmd == "ab":
        print(json.dumps(make_ab(args.url, args.owner_token, args.attacker_token,
                                 args.method, args.body, _pair_headers(args.header)),
                         ensure_ascii=False, indent=2))
        return 0

    if args.cmd == "race":
        print(json.dumps(make_race(args.endpoint, args.replays, args.method, args.body,
                                   _pair_headers(args.header), args.authorized_rps),
                         ensure_ascii=False, indent=2))
        return 0

    if args.cmd == "judge":
        ev = json.load(open(args.file, encoding="utf-8"))
        res = judge(ev)
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return {"pass": 0, "fail": 1, "inconclusive": 2}[res["verdict"]]

    if args.cmd == "scene":
        names = [args.name] if args.name else list(SCENES)
        if args.json:
            print(json.dumps({n: SCENES[n] for n in names}, ensure_ascii=False, indent=2))
            return 0
        for n in names:
            print("## %s" % n)
            for atk, how, proof, t in SCENES[n]:
                print("- %s | %s | 证据：%s | 类型：%s" % (atk, how, proof, t))
            print("")
        return 0

    if args.cmd == "fix":
        for it in REMEDIATION[args.type]:
            print("- %s" % it)
        return 0

    return 2


if __name__ == "__main__":
    _force_utf8_stdout()
    raise SystemExit(main())
