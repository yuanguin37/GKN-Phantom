#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""apk_recon.py — 授权安全测试用的 APK 秒级快筛（不依赖 jadx / apktool）。

设计目标：大包（可 >100MB）不等待全量反编译，秒级给出"该看哪里"的清单。

提取内容：
  1) 包元信息：包名、版本、min/target SDK、debuggable / allowBackup /
     usesCleartextTraffic / networkSecurityConfig
  2) 组件矩阵：activity / service / receiver / provider + exported + permission
     → 直接标出「导出但无权限保护」的高风险组件（Android 12 前的默认导出语义
       也一并计入）
  3) 权限清单
  4) 加固粗判：lib/ 下特征 so、assets 内 dex/so、多 dex 异常
  5) 速筛命中：密钥模式（dex 字符串 + assets/res 文本）与敏感端点
     （含内网/localhost 标记）

AndroidManifest.xml 是二进制 AXML，本模块内置精简解析器（zipfile + struct），
纯标准库，无第三方依赖。

用法：
    python3 apk_recon.py app.apk                     # 人类可读摘要
    python3 apk_recon.py app.apk --json out.json     # 机器可读
    python3 apk_recon.py app.apk --secrets           # 附带密钥命中明细
    python3 apk_recon.py app.apk --top 20            # 端点明细上限

合规：仅分析自有或已获书面授权的 APK。反编译产物不得公开或用于非授权目标。
"""

from __future__ import annotations

import argparse
import json
import re
import struct
import sys
import zipfile

# --------------------------------------------------------------------------
# AXML (binary AndroidManifest.xml) — minimal parser
# --------------------------------------------------------------------------
AXML_MAGIC = 0x00080003
CHUNK_STRING_POOL = 0x0001
CHUNK_RESOURCE_MAP = 0x0180
CHUNK_START_TAG = 0x0102
CHUNK_END_TAG = 0x0103

SP_UTF8_FLAG = 1 << 8

TYPE_STRING = 0x03
TYPE_INT_BOOLEAN = 0x12
TYPE_INT_DEC = 0x10
TYPE_REFERENCE = 0x01

# android: 属性资源 ID → 可读属性名（只列快筛关心的）
ATTR_IDS = {
    0x01010001: "label",
    0x01010003: "name",
    0x01010006: "permission",
    0x01010007: "readPermission",
    0x01010008: "writePermission",
    0x0101000F: "debuggable",
    0x01010010: "exported",
    0x01010011: "process",
    0x01010018: "authorities",
    0x0101001B: "grantUriPermissions",
    0x01010270: "targetSdkVersion",
    0x01010271: "minSdkVersion",
    0x01010280: "allowBackup",
    0x010104EC: "usesCleartextTraffic",
    0x01010527: "extractNativeLibs",
    0x0101053F: "networkSecurityConfig",
}

# 安全上值得单独点名的组件标签
COMPONENT_TAGS = {"activity", "activity-alias", "service", "receiver", "provider"}

# 常见加固厂商在 lib/ 下投放的特征库
HARDENING_SO = (
    "libjiagu", "libshell", "libdexhelper", "libmobisec", "libnesec",
    "libprotectclass", "libexec", "libtup", "libbaiduprotect", "libnqshield",
    "libnsafer", "libapktoolplus", "libsecexe", "libsecmain", "libddd",
    "libwwww", "libedog", "libkwscmm", "libkgis", "libtop", "libsgmain",
)


def _var_len(data: bytes, pos: int):
    """AXML 变长长度编码：首字节高位为 1 表示两字节。"""
    b = data[pos]
    if b & 0x80:
        return ((b & 0x7F) << 8) | data[pos + 1], pos + 2
    return b, pos + 1


def _parse_string_pool(data: bytes, off: int):
    """解析 StringPool chunk，返回字符串列表。"""
    _t, hdr, _size = struct.unpack_from("<HHI", data, off)
    count, _style_count, flags, strings_start, _styles_start = struct.unpack_from(
        "<IIIII", data, off + 8
    )
    is_utf8 = bool(flags & SP_UTF8_FLAG)
    offsets = struct.unpack_from("<%dI" % count, data, off + hdr)
    base = off + strings_start
    out = []
    for i in range(count):
        pos = base + offsets[i]
        try:
            if is_utf8:
                _u16, pos = _var_len(data, pos)          # UTF-16 长度（跳过）
                n, pos = _var_len(data, pos)             # UTF-8 字节长度
                out.append(data[pos:pos + n].decode("utf-8", "replace"))
            else:
                n, pos = _var_len(data, pos)
                out.append(data[pos:pos + n * 2].decode("utf-16-le", "replace"))
        except Exception:
            out.append("")
    return out


def _parse_resource_map(data: bytes, off: int):
    """解析 ResourceMap chunk：字符串池索引 → 资源 ID。"""
    _t, hdr, size = struct.unpack_from("<HHI", data, off)
    count = max(0, (size - hdr) // 4)
    if count == 0:
        return []
    return list(struct.unpack_from("<%dI" % count, data, off + hdr))


def _attr_name(idx: int, strings, res_map):
    """把属性索引还原成可读名：优先用 ResourceMap 查 android: 属性表。"""
    if idx == 0xFFFFFFFF or idx >= len(strings):
        return None
    res_id = res_map[idx] if idx < len(res_map) else 0
    if res_id in ATTR_IDS:
        return ATTR_IDS[res_id]
    name = strings[idx]
    # aapt 有时把属性名也放进字符串池，形如 "android:exported"
    if ":" in name:
        name = name.split(":", 1)[1]
    return name or None


def _attr_value(tv_type: int, tv_data: int, strings):
    if tv_type == TYPE_STRING:
        return strings[tv_data] if tv_data < len(strings) else ""
    if tv_type == TYPE_INT_BOOLEAN:
        return bool(tv_data)
    if tv_type == TYPE_REFERENCE:
        return "@ref/0x%08x" % tv_data
    if tv_type == TYPE_INT_DEC:
        return tv_data
    return tv_data


def parse_axml(data: bytes):
    """解析 AXML，返回 [{tag, attrs}] 的扁平元素列表。"""
    magic, size = struct.unpack_from("<II", data, 0)
    if magic != AXML_MAGIC:
        raise ValueError("not an AXML file (magic=0x%08x)" % magic)

    strings, res_map, elements = [], [], []
    off = 8
    while off + 8 <= min(size, len(data)):
        ch_type, _ch_hdr, ch_size = struct.unpack_from("<HHI", data, off)
        if ch_size <= 0:
            break
        if ch_type == CHUNK_STRING_POOL:
            strings = _parse_string_pool(data, off)
        elif ch_type == CHUNK_RESOURCE_MAP:
            res_map = _parse_resource_map(data, off)
        elif ch_type == CHUNK_START_TAG:
            try:
                # ResXMLTree_node(8) + lineNumber(4) + comment(4) + attrExt:
                # ns(4) name(4) attributeStart(2) attributeSize(2)
                # attributeCount(2) idIndex(2) classIndex(2) styleIndex(2)
                (_line, _cmt, _ns, name, a_start, a_size, a_count,
                 _id_idx, _cls_idx, _sty_idx) = struct.unpack_from(
                    "<IIIIHHHHHH", data, off + 8)
                tag = strings[name] if name < len(strings) else "?"
                attrs = {}
                a_off = off + 16 + a_start
                for i in range(a_count):
                    p = a_off + i * a_size
                    (_ns, an_idx, _raw, _tsz, _tr0, tv_type, tv_data) = \
                        struct.unpack_from("<IIIHBBI", data, p)
                    key = _attr_name(an_idx, strings, res_map)
                    if key:
                        attrs[key] = _attr_value(tv_type, tv_data, strings)
                elements.append({"tag": tag, "attrs": attrs})
            except Exception:
                pass
        off += ch_size
    return elements


# --------------------------------------------------------------------------
# Risk classification
# --------------------------------------------------------------------------
def classify_components(elements):
    """从元素列表里抽出组件矩阵并标风险。"""
    components, perms = [], []
    app_attrs = {}
    manifest = {}

    for el in elements:
        tag, attrs = el["tag"], el["attrs"]
        if tag == "manifest":
            manifest = attrs
        elif tag == "uses-permission":
            p = attrs.get("name")
            if p:
                perms.append(p)
        elif tag == "application":
            app_attrs = attrs
        elif tag in COMPONENT_TAGS:
            comp = {
                "kind": tag,
                "name": attrs.get("name", "?"),
                "exported": _norm_bool(attrs.get("exported")),
                "permission": attrs.get("permission") or attrs.get("readPermission")
                or attrs.get("writePermission"),
                "authorities": attrs.get("authorities"),
                "grantUriPermissions": attrs.get("grantUriPermissions"),
                "process": attrs.get("process"),
            }
            # Android 12 之前：有 intent-filter 且未显式 exported 即为导出；
            # 这里拿不到 intent-filter 归属，故按保守口径——显式 true 才算，
            # 但 exported 缺省且组件名以常见前缀出现时记 unknown。
            comp["risk"] = _component_risk(comp)
            components.append(comp)

    return {
        "package": manifest.get("package", "?"),
        "versionName": manifest.get("versionName") or manifest.get("versionCode"),
        "minSdk": manifest.get("minSdkVersion"),
        "targetSdk": manifest.get("targetSdkVersion"),
        "permissions": sorted(set(perms)),
        "application": {
            "debuggable": app_attrs.get("debuggable"),
            "allowBackup": app_attrs.get("allowBackup"),
            "usesCleartextTraffic": app_attrs.get("usesCleartextTraffic"),
            "networkSecurityConfig": app_attrs.get("networkSecurityConfig"),
        },
        "components": components,
    }


def _norm_bool(v):
    """AXML 的布尔通常是真 bool，但个别打包器会写成字符串，统一规范化。"""
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        s = v.strip().lower()
        if s in ("true", "1"):
            return True
        if s in ("false", "0"):
            return False
    return None


def _component_risk(comp):
    """导出且无自定义 permission 保护 → high；导出有保护 → info。"""
    exported = comp.get("exported")
    has_perm = bool(comp.get("permission"))
    if exported is True:
        return "high" if not has_perm else "info"
    if exported is None and not has_perm:
        # 未显式声明：Android 12+ 默认不导出，旧系统有 intent-filter 则导出
        return "unknown"
    return "info"


# --------------------------------------------------------------------------
# Secrets / endpoints fast scan
# --------------------------------------------------------------------------
SECRET_PATTERNS = [
    ("aws_access_key_id", rb"AKIA[0-9A-Z]{16}"),
    ("google_api_key", rb"AIza[0-9A-Za-z_\-]{35}"),
    ("google_oauth_client", rb"[0-9]{6,}-[0-9a-z_]{32}\.apps\.googleusercontent\.com"),
    ("firebase_rtdb", rb"https://[a-z0-9\-]+\.firebaseio\.com"),
    ("alibaba_ak", rb"LTAI[0-9A-Za-z]{12,20}"),
    ("tencent_secret_id", rb"AKID[0-9A-Za-z]{32}"),
    ("slack_token", rb"xox[baprs]-[0-9A-Za-z\-]{10,}"),
    ("github_pat", rb"gh[pousr]_[0-9A-Za-z]{36,}"),
    ("jwt", rb"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),
    ("private_key", rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
    ("amap_key", rb"(?i)(?:amap|gaode)[_a-z]{0,12}key[\"']?\s*[:=]\s*[\"'][0-9a-f]{32}[\"']"),
    ("baidu_ak", rb"(?i)baidu[_a-z]{0,12}ak[\"']?\s*[:=]\s*[\"'][0-9a-zA-Z]{24,32}[\"']"),
    ("generic_secret_assign",
     rb"(?i)(?:api[_\-]?key|apikey|app[_\-]?secret|appsecret|access[_\-]?token|client[_\-]?secret)"
     rb"[\"']?\s*[:=]\s*[\"'][^\"']{8,80}[\"']"),
]

URL_RE = re.compile(rb"https?://[A-Za-z0-9\.\-]+(?::\d{1,5})?(?:/[A-Za-z0-9_\-./?=&%#]*)?")
INTERNAL_RE = re.compile(
    r"(^|//)(?:10\.|127\.|localhost|0\.0\.0\.0|"
    r"172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.)"
)
# 高价值路径（命中即提示重点看）
INTERESTING_PATH_RE = re.compile(
    r"/(?:admin|manage|manager|internal|debug|actuator|swagger|api-docs|"
    r"upload|export|download|user|order|pay|callback|webhook)\b", re.I
)

TEXT_EXT = (".json", ".xml", ".html", ".htm", ".js", ".txt", ".properties",
            ".yaml", ".yml", ".config", ".ini", ".csv", ".sql")


def _scan_bytes(blob: bytes, secrets, urls, limit_str=400):
    """在字节流里跑密钥与端点模式。"""
    for name, pat in SECRET_PATTERNS:
        for m in re.finditer(pat, blob):
            raw = m.group(0)
            secrets.append({
                "kind": name,
                "value": _mask(raw.decode("utf-8", "replace")),
            })
    for m in URL_RE.finditer(blob):
        u = m.group(0).decode("utf-8", "replace")
        urls.add(u)


def _mask(s: str, keep: int = 6) -> str:
    """脱敏：长串只留头尾，避免把真实密钥写进报告。"""
    if len(s) <= keep * 2:
        return s[:keep] + "…"
    return s[:keep] + "…" + s[-4:]


def scan_apk(path: str, top_urls: int = 15):
    """主扫描：返回结构化报告 dict。"""
    report = {
        "file": path,
        "size_bytes": 0,
        "zip_entries": 0,
        "dex_files": [],
        "native_libs": [],
        "hardening_suspects": [],
        "manifest": {},
        "secrets": [],
        "endpoints": {"total": 0, "internal": [], "interesting": [], "sample": []},
        "notes": [],
    }
    secrets, urls = [], set()

    with zipfile.ZipFile(path) as zf:
        infos = zf.infolist()
        report["zip_entries"] = len(infos)
        report["size_bytes"] = sum(i.file_size for i in infos)

        dex, libs, assets_suspicious = [], [], []
        for i in infos:
            n = i.filename
            if re.match(r"^classes\d*\.dex$", n):
                dex.append(n)
            elif n.startswith("lib/") and n.endswith(".so"):
                libs.append(n)
            elif n.startswith("assets/") and (n.endswith(".dex") or n.endswith(".so")):
                assets_suspicious.append(n)
        report["dex_files"] = sorted(dex)
        report["native_libs"] = sorted(libs)

        # 加固指纹
        for l in libs + assets_suspicious:
            base = l.rsplit("/", 1)[-1].lower()
            for sig in HARDENING_SO:
                if sig in base:
                    report["hardening_suspects"].append(l)
                    break
        if len(dex) == 0:
            report["notes"].append("未发现 classes*.dex —— 可能已被加固剥离。")
        elif len(dex) > 3:
            report["notes"].append("存在 %d 个 dex，分包/多 dex 场景。" % len(dex))

        # Manifest
        try:
            raw_manifest = zf.read("AndroidManifest.xml")
            elements = parse_axml(raw_manifest)
            report["manifest"] = classify_components(elements)
        except KeyError:
            report["manifest"] = {"error": "AndroidManifest.xml 缺失"}
        except Exception as exc:
            report["manifest"] = {"error": "AXML 解析失败: %s" % exc}

        # 密钥/端点扫描：dex 字符串 + assets/res 文本
        for n in dex:
            try:
                _scan_bytes(zf.read(n), secrets, urls)
            except Exception:
                continue
        for i in infos:
            n = i.filename
            if n.lower().endswith(TEXT_EXT) and i.file_size < 4 * 1024 * 1024:
                try:
                    _scan_bytes(zf.read(n), secrets, urls)
                except Exception:
                    continue

    # 去重与归类
    uniq = {}
    for s in secrets:
        uniq[(s["kind"], s["value"])] = s
    report["secrets"] = sorted(uniq.values(), key=lambda x: x["kind"])

    internal, interesting = [], []
    for u in sorted(urls):
        m = INTERNAL_RE.search(u)
        if m:
            internal.append(u)
        elif INTERESTING_PATH_RE.search(u):
            interesting.append(u)
    report["endpoints"] = {
        "total": len(urls),
        "internal": internal[:top_urls],
        "internal_count": len(internal),
        "interesting": interesting[:top_urls],
        "interesting_count": len(interesting),
        "sample": sorted(urls)[:top_urls],
    }
    return report


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------
def render(report: dict, show_secrets: bool = False) -> str:
    L = []
    m = report.get("manifest", {})
    L.append("== APK 秒级快筛 ==")
    L.append("文件        : %s" % report["file"])
    L.append("解压体积    : %.2f MB / %d 个条目"
             % (report["size_bytes"] / 1048576.0, report["zip_entries"]))
    L.append("包名        : %s" % m.get("package", "?"))
    L.append("版本        : %s" % m.get("versionName", "?"))
    L.append("SDK         : min=%s target=%s" % (m.get("minSdk"), m.get("targetSdk")))
    app = m.get("application", {}) or {}
    flags = []
    if app.get("debuggable"):
        flags.append("debuggable=true ★")
    if app.get("allowBackup"):
        flags.append("allowBackup=true ★")
    if app.get("usesCleartextTraffic"):
        flags.append("cleartext=true ★")
    L.append("应用标志    : %s" % (", ".join(flags) if flags else "（未标记高项）"))

    L.append("")
    L.append("-- 加固粗判 --")
    if report["hardening_suspects"]:
        L.append("命中特征 so : %s" % ", ".join(report["hardening_suspects"][:8]))
        L.append("→ 见 references/apk_reversing.md 的壳识别与脱壳流程")
    else:
        L.append("未命中常见加固特征（不代表无壳，需结合 dex 缺失/DEX 头异常判断）")
    L.append("dex 数量    : %d  %s" % (len(report["dex_files"]), report["dex_files"][:6]))
    for n in report["notes"]:
        L.append("  注: %s" % n)

    L.append("")
    L.append("-- 高风险导出组件（exported=true 且无 permission）--")
    comps = m.get("components", []) or []
    high = [c for c in comps if c.get("risk") == "high"]
    unknown = [c for c in comps if c.get("risk") == "unknown"]
    if high:
        for c in high:
            extra = ""
            if c.get("authorities"):
                extra = "  authorities=%s" % c["authorities"]
            L.append("  [%s] %s%s" % (c["kind"], c["name"], extra))
    else:
        L.append("  （无显式导出的无保护组件）")
    if unknown:
        L.append("  · 另有 %d 个组件未显式声明 exported（旧系统默认导出语义，需人工确认）"
                 % len(unknown))
    L.append("组件总计    : %d（activity/service/receiver/provider）" % len(comps))

    L.append("")
    L.append("-- 权限 --")
    perms = m.get("permissions", []) or []
    L.append("共 %d 条：%s" % (len(perms), ", ".join(perms[:12]) + (" …" if len(perms) > 12 else "")))

    ep = report["endpoints"]
    L.append("")
    L.append("-- 端点速筛 --")
    L.append("URL 总数    : %d" % ep["total"])
    if ep["internal_count"]:
        L.append("内网/本地  : %d 条" % ep["internal_count"])
        for u in ep["internal"][:8]:
            L.append("   ! %s" % u)
    if ep["interesting_count"]:
        L.append("高价值路径 : %d 条" % ep["interesting_count"])
        for u in ep["interesting"][:8]:
            L.append("   * %s" % u)

    L.append("")
    L.append("-- 密钥速筛 --")
    secrets = report["secrets"]
    if not secrets:
        L.append("  未命中（注意：加固/加密字符串可能未还原）")
    else:
        kinds = {}
        for s in secrets:
            kinds.setdefault(s["kind"], 0)
            kinds[s["kind"]] += 1
        for k, c in sorted(kinds.items()):
            L.append("  %-24s %d 处" % (k, c))
        if show_secrets:
            L.append("  ---- 命中明细（已脱敏）----")
            for s in secrets[:40]:
                L.append("  [%s] %s" % (s["kind"], s["value"]))

    L.append("")
    L.append("下一步：组件验证见 references/android_audit.md（ADB 命令 + 降级路径），")
    L.append("        有壳则走 references/apk_reversing.md（壳识别 → 脱壳 → 全量还原）。")
    L.append("⚠️ 未过类型命门的组件（导出但无实际效果）只能作为 lead，不得直接成稿。")
    return "\n".join(L)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="APK 秒级快筛（纯标准库，授权测试限定）"
    )
    ap.add_argument("apk", help="APK 文件路径")
    ap.add_argument("--json", metavar="PATH", help="输出机器可读 JSON")
    ap.add_argument("--secrets", action="store_true", help="打印密钥命中明细（已脱敏）")
    ap.add_argument("--top", type=int, default=15, help="端点明细条数上限（默认 15）")
    args = ap.parse_args(argv)

    try:
        report = scan_apk(args.apk, top_urls=args.top)
    except FileNotFoundError:
        print("错误：文件不存在 %s" % args.apk, file=sys.stderr)
        return 1
    except zipfile.BadZipFile:
        print("错误：不是有效的 APK/ZIP —— %s" % args.apk, file=sys.stderr)
        return 1

    print(render(report, show_secrets=args.secrets))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, ensure_ascii=False, indent=2)
        print("\nJSON 已写入 %s" % args.json)
    return 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    raise SystemExit(main())
