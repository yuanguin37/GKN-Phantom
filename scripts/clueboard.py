#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cross-session clue board — target-level analyst memory for GKN-Phantom.

Why this module exists
----------------------
`state.py` persists the MACHINE state (phase / history / checkpoint) so a run
can be resumed after Ctrl-C. It does NOT persist what an analyst reasons
about: which assumptions are still open, which hosts/paths were already
probed, which leads were FALSIFIED, which keys were recovered.

When the agent context is compressed or a new session starts, that judgement
is lost — the target gets re-explored from zero and dead ends get re-tested.
This module adds the missing layer: one human-readable Markdown board per
target.

Boundaries (deliberately disjoint)
----------------------------------
  state.py    machine state  | per RUN    | JSON     | written by state machine
  clueboard   analyst memory | per TARGET | Markdown | read+written by the LLM

Raw material (full JS bundles, unmasked credentials) never goes on the board;
it goes to `hunts/<target>/raw/`. The board only holds judgements + provenance.

CLI
---
  init    --target <name> [--focus "..."] [--constraint "..."] [--root hunts] [--force]
  read    --target <name> [--root hunts]
  brief   --target <name>                       compact form for context re-injection
  add     --target <name> --section <key> (--text "..." | --cells a,b,c) [--force]
  cover   --target <name> [--tested a;b] [--untested a;b] [--variants a;b]
                          [--related a;b] [--level L2]
  check   --target <name> --section <key> --text "..."     exit 1 when duplicate
  status  --target <name>                       machine-readable JSON summary
  list    [--root hunts]

Section keys: assumptions | hosts | paths | keys | excluded | secrets | todos | coverage
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import sys

# ---- Section schema ---------------------------------------------------------
# Fixed order + fixed columns keep `read` / `brief` output stable so it can be
# re-injected into a compressed context cheaply. Index = the "## N." heading
# number, mirrors the CkSKILLS clue-board convention.
SECTION_ORDER = [
    "assumptions", "hosts", "paths", "keys",
    "excluded", "secrets", "todos", "coverage",
]

SECTION_META = {
    "assumptions": ("当前假设（最多 5 条）", ["假设", "状态", "怎么证伪", "结果"], "table"),
    "hosts":       ("Host 地图", ["Host", "类", "IP", "指纹", "下一步"], "table"),
    "paths":       ("路径 / 方法", ["方法", "出处", "首次指纹", "鉴权", "状态"], "table"),
    "keys":        ("密钥 / 协议", ["项", "值", "备注"], "table"),
    "excluded":    ("已排除（防止下轮重测）", None, "list"),
    "secrets":     ("凭证与敏感串（脱敏）", ["类型", "值（打码）", "出处", "有效性"], "table"),
    "todos":       ("待办", None, "todo"),
    "coverage":    ("覆盖度", None, "coverage"),
}

# Assumption lifecycle is a closed set — free-form status makes the board
# unqueryable. Mirrors the methodology: 假设 / 已证伪 / 已证实 / 待打.
ASSUMPTION_STATES = ["假设", "已证伪", "已证实", "待打"]

COVERAGE_KEYS = ["已测", "未测", "变种", "关联", "失败升级已到"]

# CLI flags for `cover`: (ascii flag, coverage key). The ascii flag exists so
# the command is typable in any shell / locale without IME switching.
COVERAGE_FLAGS = [
    ("--tested", "已测"),
    ("--untested", "未测"),
    ("--variants", "变种"),
    ("--related", "关联"),
    ("--level", "失败升级已到"),
]

META_KEYS = ["目标", "开工日", "更新日", "约束", "当前焦点"]

FENCE = "```"
LIST_SEP = re.compile(r"[；;、]|,\s*")


# ---- Paths ------------------------------------------------------------------
def slugify(target: str) -> str:
    """Turn a target (URL / host / IP / name) into a safe directory name."""
    t = (target or "").strip()
    t = re.sub(r"^[a-zA-Z]+://", "", t)          # drop scheme
    t = t.split("/")[0].split("?")[0]            # drop path/query
    t = t.split("@")[-1].split(":")[0]           # drop creds + port
    t = re.sub(r"[^0-9A-Za-z._\u4e00-\u9fff-]", "-", t).strip("-.")
    return t.lower() or "unknown-target"


def board_path(root: str, target: str) -> str:
    return os.path.join(root, slugify(target), "CLUEBOARD.md")


def raw_dir(root: str, target: str) -> str:
    return os.path.join(root, slugify(target), "raw")


def _today() -> str:
    return _dt.date.today().isoformat()


def _now() -> str:
    return _dt.datetime.now().strftime("%Y-%m-%d %H:%M")


# ---- Normalisation / duplicate detection -----------------------------------
def norm(text: str) -> str:
    """Fold a cell for comparison: lowercase, strip, collapse whitespace."""
    return re.sub(r"[\s|]+", " ", (text or "").strip().lower())


def _dup_index(rows: list, text: str) -> int | None:
    """Return the index of an equivalent existing row, else None.

    Equality OR mutual substring (len >= 8) counts as duplicate — re-recording
    the same lead with extra words is the common real-world case.
    """
    key = norm(text)
    if not key:
        return None
    for i, row in enumerate(rows):
        existing = norm(row[0] if isinstance(row, list) else row)
        if existing == key:
            return i
        if len(key) >= 8 and (key in existing or existing in key):
            return i
    return None


# ---- Parse / render --------------------------------------------------------
def blank_board(target: str, focus: str = "", constraints: list | None = None) -> dict:
    """Build an empty board model."""
    return {
        "meta": {
            "目标": target,
            "开工日": _today(),
            "更新日": _today(),
            "约束": "；".join(constraints or []) or "（授权范围内，未授权禁止）",
            "当前焦点": focus or "（一句话：下一轮先做这件事）",
        },
        "sections": {k: [] for k in SECTION_ORDER},
        "coverage": {k: [] for k in COVERAGE_KEYS},
    }


def parse_board(text: str) -> dict:
    """Parse CLUEBOARD.md back into a model. Tolerant: unknown lines are kept."""
    model = {"meta": {}, "sections": {k: [] for k in SECTION_ORDER},
             "coverage": {k: [] for k in COVERAGE_KEYS}}
    cur, in_code = None, False
    for line in text.splitlines():
        m = re.match(r"^##\s+(\d)\.", line)
        if m and int(m.group(1)) < len(SECTION_ORDER):
            cur = SECTION_ORDER[int(m.group(1))]
            continue
        if line.strip().startswith(FENCE):
            in_code = not in_code
            continue
        if cur is None:                                   # ---- header block ----
            m2 = re.match(r"^-\s*([^：:]+)[：:]\s*(.*)$", line)
            if m2:
                model["meta"][m2.group(1).strip()] = m2.group(2).strip()
            continue
        kind = SECTION_META[cur][2]
        if kind == "coverage":                            # ---- coverage ----
            if in_code:
                m3 = re.match(r"^([^：:]+)[：:]\s*(.*)$", line)
                if m3 and m3.group(1).strip() in model["coverage"]:
                    raw = m3.group(2).strip()
                    items = [] if raw in ("", "—", "-") else [s.strip() for s in LIST_SEP.split(raw) if s.strip()]
                    model["coverage"][m3.group(1).strip()] = items
            continue
        if kind in ("list", "todo"):                      # ---- list / todo ----
            item = re.sub(r"^-\s*(\[[ xX]\]\s*)?", "", line).strip() if line.startswith("-") else ""
            if item and item not in ("（空）",):
                model["sections"][cur].append(item)
            continue
        if line.startswith("|"):                          # ---- table ----
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if all(set(c) <= set("-: ") for c in cells):  # separator row
                continue
            if cells == SECTION_META[cur][1]:             # header row
                continue
            model["sections"][cur].append(cells)
    return model


def render_board(model: dict) -> str:
    """Render a model to Markdown. Deterministic — same model, same bytes."""
    meta = model["meta"]
    out = [
        f"# 线索板 · {meta.get('目标', '')}",
        "",
        "> 工作记忆，不是日记。只写判断和出处，不贴整份 JS、不写完整 PII。",
        "> 假设状态只用：`假设` / `已证伪` / `已证实` / `待打`。",
        "> 机器态（阶段/检查点）由 state.py 管理；本板只记判断与线索。",
        "> 原始材料（完整 JS / 未打码凭证）放 `raw/`，不进本板。",
        "",
    ]
    out += [f"- {k}：{meta.get(k, '')}" for k in META_KEYS]
    out.append("")

    for idx, key in enumerate(SECTION_ORDER):
        title, cols, kind = SECTION_META[key]
        out += [f"## {idx}. {title}", ""]
        rows = model["sections"].get(key, [])
        if kind == "coverage":
            cov = model["coverage"]
            out.append(FENCE)
            for ck in COVERAGE_KEYS:
                val = cov.get(ck) or []
                joined = "；".join(val) if ck != "失败升级已到" else (val[0] if val else "L?")
                out.append(f"{ck}：{joined}")
            out.append(FENCE)
        elif kind == "table":
            out.append("| " + " | ".join(cols) + " |")
            out.append("|" + "|".join(["---"] * len(cols)) + "|")
            if rows:
                for row in rows:
                    padded = (list(row) + [""] * len(cols))[:len(cols)]
                    out.append("| " + " | ".join(padded) + " |")
            else:
                out.append("| " + " | ".join([""] * len(cols)) + " |")
        elif kind == "todo":
            out += [f"- [ ] {r}" for r in rows] or ["- [ ] （空）"]
        else:
            out += [f"- {r}" for r in rows] or ["- （空）"]
        out.append("")
    return "\n".join(out).rstrip() + "\n"


# ---- Load / save -----------------------------------------------------------
def load_board(root: str, target: str) -> dict:
    path = board_path(root, target)
    if not os.path.exists(path):
        raise FileNotFoundError(f"no clue board for '{target}' at {path}; run `init` first")
    with open(path, "r", encoding="utf-8") as fh:
        return parse_board(fh.read())


def save_board(root: str, target: str, model: dict) -> str:
    """Atomic write (tmp + replace) so a crash never leaves a half board."""
    model["meta"]["更新日"] = _today()
    path = board_path(root, target)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(render_board(model))
    os.replace(tmp, path)
    return path


# ---- Specialised writers ---------------------------------------------------
def add_row(root: str, target: str, section: str, cells: list, force: bool = False) -> dict:
    """Append one row/item. Returns {status, path, duplicate_of, section}."""
    if section not in SECTION_META:
        raise ValueError(f"unknown section '{section}'; valid: {', '.join(SECTION_ORDER)}")
    model = load_board(root, target)
    title, cols, kind = SECTION_META[section]
    text = cells[0] if cells else ""

    if kind == "table":
        expected = len(cols)
        cells = (list(cells) + [""] * expected)[:expected]
        if section == "assumptions":
            state = cells[1] or "假设"
            if state not in ASSUMPTION_STATES:
                raise ValueError(f"assumption status must be one of {ASSUMPTION_STATES}")
            cells[1] = state
    elif kind == "coverage":
        raise ValueError("coverage is written via `cover`, not `add`")

    rows = model["sections"][section]
    dup = _dup_index(rows, text)
    result = {"status": "added", "section": section, "duplicate_of": None}

    if dup is not None:
        result["duplicate_of"] = dup
        if not force:
            # Record the hit but do not grow the board — the whole point is to
            # stop re-testing leads that are already on it.
            result["status"] = "duplicate"
            result["existing"] = rows[dup]
            return result

    if section == "assumptions" and len(rows) >= 5 and not force:
        result["status"] = "capped"
        result["reason"] = "assumptions capped at 5; falsify/close one first (or pass --force)"
        return result

    if dup is not None:
        cells = [f"[重复] {cells[0]}"] + list(cells[1:]) if kind == "table" else [f"[重复] {text}"]

    model["sections"][section].append(cells if kind == "table" else cells[0])
    result["path"] = save_board(root, target, model)
    return result


def set_coverage(root: str, target: str, updates: dict) -> dict:
    """Replace the listed coverage lines (values are ';'-separated lists)."""
    model = load_board(root, target)
    applied = {}
    for k, v in updates.items():
        if v is None:
            continue
        if k not in COVERAGE_KEYS:
            raise ValueError(f"unknown coverage key '{k}'; valid: {', '.join(COVERAGE_KEYS)}")
        items = [s.strip() for s in LIST_SEP.split(v) if s.strip()] if v else []
        model["coverage"][k] = items
        applied[k] = items
    return {"status": "updated", "path": save_board(root, target, model), "coverage": applied}


def brief(model: dict) -> str:
    """Token-cheap digest for re-injection after context compression."""
    meta = model["meta"]
    sec = model["sections"]
    cov = model["coverage"]
    open_asm = [r for r in sec["assumptions"] if len(r) > 1 and r[1] == "假设"]
    lines = [
        f"[线索板] {meta.get('目标', '')} | 焦点：{meta.get('当前焦点', '')}",
        f"假设 {len(open_asm)}/{len(sec['assumptions'])} 未决 | "
        f"Host {len(sec['hosts'])} | 路径 {len(sec['paths'])} | 密钥 {len(sec['keys'])} | "
        f"已排除 {len(sec['excluded'])} | 待办 {len(sec['todos'])}",
    ]
    if open_asm:
        lines.append("未决假设：")
        lines += [f"  - {r[0]} → 证伪: {r[2] or '未写'}" for r in open_asm]
    if sec["excluded"]:
        lines.append("已排除（不要重测）：" + "；".join(sec["excluded"][:8]))
    if sec["todos"]:
        lines.append("待办：")
        lines += [f"  - {t}" for t in sec["todos"]]
    lines.append(
        f"覆盖度：已测 {len(cov['已测'])} / 未测 {len(cov['未测'])} / "
        f"变种 {len(cov['变种'])} / 关联 {len(cov['关联'])} | "
        f"失败升级已到 {(cov['失败升级已到'] or ['L?'])[0]}"
    )
    return "\n".join(lines)


def status(model: dict, root: str, target: str) -> dict:
    sec, cov = model["sections"], model["coverage"]
    path = board_path(root, target)
    return {
        "target": model["meta"].get("目标", target),
        "slug": slugify(target),
        "board": path,
        "exists": os.path.exists(path),
        "focus": model["meta"].get("当前焦点", ""),
        "constraints": model["meta"].get("约束", ""),
        "counts": {k: len(v) for k, v in sec.items()},
        "open_assumptions": len([r for r in sec["assumptions"] if len(r) > 1 and r[1] == "假设"]),
        "coverage": {k: v for k, v in cov.items()},
        "updated_at": model["meta"].get("更新日", ""),
    }


# ---- CLI -------------------------------------------------------------------
def _force_utf8_stdout() -> None:
    """Windows consoles default to GBK; Chinese board output must not crash."""
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="GKN-Phantom cross-session clue board")
    p.add_argument("--root", default="hunts", help="board root directory (default: hunts)")
    sub = p.add_subparsers(dest="cmd", required=True)

    def with_target(sp):
        sp.add_argument("--target", required=True)
        return sp

    sp = with_target(sub.add_parser("init", help="create a board for a target"))
    sp.add_argument("--focus", default="")
    sp.add_argument("--constraint", action="append", default=[])
    sp.add_argument("--force", action="store_true", help="overwrite an existing board")

    with_target(sub.add_parser("read", help="print the full board"))
    with_target(sub.add_parser("brief", help="print the compact digest"))
    with_target(sub.add_parser("status", help="print a JSON summary"))

    sp = with_target(sub.add_parser("add", help="append a row / item"))
    sp.add_argument("--section", required=True, choices=[k for k in SECTION_ORDER if k != "coverage"])
    sp.add_argument("--text", default="")
    sp.add_argument("--cells", default="", help="comma-separated cells for table sections")
    sp.add_argument("--force", action="store_true", help="allow duplicates / exceed the caps")

    sp = with_target(sub.add_parser("cover", help="update the coverage block"))
    # ASCII flag first (typable everywhere), Chinese alias second. `dest` is
    # index-based so the namespace never holds non-ASCII attribute names.
    for flag, key in COVERAGE_FLAGS:
        sp.add_argument(flag, f"--{key}", dest=f"cov_{COVERAGE_KEYS.index(key)}", default=None)

    sp = with_target(sub.add_parser("check", help="exit 1 when the text is already recorded"))
    sp.add_argument("--section", required=True, choices=SECTION_ORDER)
    sp.add_argument("--text", required=True)

    sub.add_parser("list", help="list all boards")
    return p


def main(argv: list | None = None) -> int:
    _force_utf8_stdout()
    args = build_parser().parse_args(argv)
    root = args.root

    try:
        if args.cmd == "init":
            path = board_path(root, args.target)
            if os.path.exists(path) and not args.force:
                print(f"board already exists: {path} (use --force to overwrite)", file=sys.stderr)
                return 1
            os.makedirs(raw_dir(root, args.target), exist_ok=True)
            model = blank_board(args.target, args.focus, args.constraint)
            saved = save_board(root, args.target, model)
            print(json.dumps({"status": "created", "board": saved,
                              "raw": raw_dir(root, args.target)}, ensure_ascii=False))
            return 0

        if args.cmd == "list":
            base = root if os.path.isdir(root) else "."
            found = []
            for name in sorted(os.listdir(base)):
                bp = os.path.join(base, name, "CLUEBOARD.md")
                if os.path.exists(bp):
                    found.append({"slug": name, "board": bp,
                                  "mtime": _dt.datetime.fromtimestamp(os.path.getmtime(bp))
                                           .strftime("%Y-%m-%d %H:%M")})
            print(json.dumps(found, ensure_ascii=False, indent=2))
            return 0

        model = load_board(root, args.target)

        if args.cmd == "read":
            print(render_board(model), end="")
            return 0
        if args.cmd == "brief":
            print(brief(model))
            return 0
        if args.cmd == "status":
            print(json.dumps(status(model, root, args.target), ensure_ascii=False, indent=2))
            return 0
        if args.cmd == "check":
            rows = model["coverage"].get(args.section) if args.section == "coverage" \
                else model["sections"][args.section]
            idx = _dup_index(rows or [], args.text)
            print(json.dumps({"duplicate": idx is not None, "index": idx}, ensure_ascii=False))
            return 1 if idx is not None else 0
        if args.cmd == "add":
            cells = [c.strip() for c in args.cells.split(",")] if args.cells else [args.text]
            res = add_row(root, args.target, args.section, cells, args.force)
            print(json.dumps(res, ensure_ascii=False))
            # Exit 1 on duplicate / cap so a shell-driven agent can branch on it.
            return 0 if res["status"] == "added" else 1
        if args.cmd == "cover":
            updates = {COVERAGE_KEYS[i]: getattr(args, f"cov_{i}") for i in range(len(COVERAGE_KEYS))
                       if getattr(args, f"cov_{i}") is not None}
            if not updates:
                print("nothing to update; pass at least one coverage flag "
                      "(--tested/--untested/--variants/--related/--level)", file=sys.stderr)
                return 2
            print(json.dumps(set_coverage(root, args.target, updates), ensure_ascii=False))
            return 0
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
