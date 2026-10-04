#!/usr/bin/env python3
"""Self-test for the GKN-Phantom skill — the gate README's compileall can't be.

`py_compile` passes modules that explode at import (the old cve_correlator
NameError) and says nothing about detection quality. This script checks what
actually matters, in order of pain:

  1. Import smoke — every module in scripts/ imports cleanly.
  2. CLI smoke    — the main entrypoints respond to --help.
  3. scope_guard  — malformed CIDR is a config error; unresolvable hosts are
                    reported as dns_resolution_failed; scope semantics hold.
  4. rules        — rules_loader --validate exits 0 (rule schema only;
                    waf_signatures/mutation_strategies are excluded).
  5. Validator    — forged legacy evidence can NOT reach 'validated'.
  6. Hard gates   — the single-character-'x' finding is rejected by
                    report_docx.verify_finding; a fully-evidenced one passes.
  7. FALSE-POSITIVE GATE (the big one): run the combat pipeline against a
     local catch-all SPA that 200s every path and a hardened server that
     sends all security headers — the pipeline MUST report ZERO findings.
     This single assertion fails for every soft-404 / header-probe /
     bare-fingerprint FP class at once.
  8. TRUE-POSITIVE SANITY: a server actually exposing actuator config with
     unmasked credentials, a real .git/config and a real backup archive
     MUST produce findings, escalated on proven content.

Run:  python scripts/selftest.py            (all checks)
      python scripts/selftest.py --quick    (skip the live-server passes)

All traffic stays on 127.0.0.1 ephemeral ports. Exit 0 = all green.
"""

from __future__ import annotations

import argparse
import http.server
import importlib
import json
import os
import shutil
import socketserver
import subprocess
import sys
import tempfile
import threading
import traceback

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.dirname(SCRIPTS_DIR)
sys.path.insert(0, SCRIPTS_DIR)

RESULTS: list[dict] = []


def record(name: str, ok: bool, detail: str = "") -> bool:
    RESULTS.append({"check": name, "ok": ok, "detail": detail})
    mark = "PASS" if ok else "FAIL"
    print(f"  [{mark}] {name}" + (f" — {detail}" if detail and not ok else ""))
    return ok


def check_imports() -> None:
    print("[1] import smoke over scripts/*.py")
    failed = []
    for fname in sorted(os.listdir(SCRIPTS_DIR)):
        if not fname.endswith(".py") or fname.startswith("_"):
            continue
        mod_name = fname[:-3]
        try:
            importlib.import_module(mod_name)
        except Exception as e:
            failed.append(f"{mod_name}: {type(e).__name__}: {e}")
    record("all modules import", not failed, "; ".join(failed))


def check_cli_smoke() -> None:
    print("[2] CLI smoke (--help) on core entrypoints")
    bad = []
    for mod in ("scope_guard", "quick_combat", "cn_probes", "finding_validator",
                "rules_loader", "report_docx", "report_generator", "confidence_scoring",
                "clueboard", "oob_client", "rate_limiter", "business_logic",
                "vuln_detector", "js_analyzer", "tech_fingerprint", "waf_evasion"):
        try:
            proc = subprocess.run(
                [sys.executable, os.path.join(SCRIPTS_DIR, f"{mod}.py"), "--help"],
                capture_output=True, timeout=30,
                env={**os.environ, "PYTHONIOENCODING": "utf-8"})
            if proc.returncode != 0:
                bad.append(f"{mod}: rc={proc.returncode}")
        except Exception as e:
            bad.append(f"{mod}: {e}")
    record("core CLIs respond to --help", not bad, "; ".join(bad))


def check_scope_guard() -> None:
    print("[3] scope_guard semantics")
    import scope_guard
    bad = []
    if not scope_guard.validate_scope({"domains": ["a.test"], "ip_ranges": ["10.0.0.0/99"]}):
        bad.append("bad CIDR accepted")
    if not scope_guard.validate_scope({"allow_any_ip": True}):
        bad.append("allow_any_ip alone accepted")
    # domains-only scope is LEGAL (private-IP guard runs at check time):
    # an internal address must be rejected as a rebinding pivot.
    if scope_guard.validate_scope({"domains": ["127.0.0.1"]}):
        bad.append("domains-only scope rejected at config time")
    ok, reason = scope_guard.check_target(
        "http://127.0.0.1:1/", {"domains": ["127.0.0.1"]})
    if ok or "private/loopback" not in reason:
        bad.append(f"private-IP guard failed: {ok} {reason!r}")
    ok2, reason2 = scope_guard.check_target(
        "http://unresolvable-gkn.invalid/", {"domains": ["unresolvable-gkn.invalid"],
                                             "allow_any_ip": True})
    if ok2 or "dns_resolution_failed" not in reason2:
        bad.append(f"DNS failure misattributed: {ok2} {reason2!r}")
    record("scope_guard config + attribution", not bad, "; ".join(bad))


def check_rules() -> None:
    print("[4] rules_loader validation gate")
    proc = subprocess.run(
        [sys.executable, os.path.join(SCRIPTS_DIR, "rules_loader.py"), "--validate"],
        capture_output=True, text=True, timeout=60,
        env={**os.environ, "PYTHONIOENCODING": "utf-8"})
    record("rules_loader --validate exits 0", proc.returncode == 0,
           (proc.stdout or "")[-300:] + (proc.stderr or "")[-200:])


def check_validator_hardening() -> None:
    print("[5] finding_validator anti-forgery")
    import finding_validator as fv
    finding = {"id": "X", "type": "sqli", "status": "detected", "confidence": 0.5,
               "safe_poc": True, "evidence": {}}
    forged = fv.validate(finding, {"request": "fake", "response": "fake",
                                   "tool": "curl", "signal_matched": True})
    record("forged evidence cannot reach validated",
           forged["status"] != "validated", forged["status"])


def check_hard_gates() -> None:
    print("[6] report_docx hard gates")
    import report_docx as rd
    minimal = {"id": "F-1", "type": "idor", "severity": "critical",
               "status": "validated", "target": "https://t/api/1",
               "impact": "x", "falsification": "x", "scope_note": "x", "ab_proof": "x",
               "evidence": {"request": "x", "response": "x", "replay_count": 2,
                            "tool": "httpRequest"}}
    g = rd.verify_finding(minimal)
    ok1 = not g["passed"]
    good = {"id": "F-2", "type": "idor", "severity": "critical", "status": "validated",
            "target": "https://t/api/order/1",
            "impact": "读取了A账号的3条订单数据，含姓名与手机号",
            "falsification": {"request": "GET /api/order/1 (无Cookie)", "response": "401",
                              "expected_absent": "未登录拿不到订单，排除公开接口"},
            "scope_note": "同根因接口 /api/order/{id} 已遍历 id 1-100，全测完。",
            "ab_proof": "用B的Cookie读取A订单返回200及手机号",
            "evidence": {"request": "GET /api/order/1", "response": "order json",
                         "replay_count": 2, "tool": "httpRequest",
                         "response_hash": "sha256:ab",
                         "replay_results": [{"response_hash": "sha256:ab"},
                                            {"response_hash": "sha256:cd"}]}}
    g2 = rd.verify_finding(good)
    record("minimal-x finding rejected / evidenced finding passes",
           ok1 and g2["passed"], f"minimal passed={g['passed']}, good passed={g2['passed']}")


# ---- live-server passes (7, 8) ----------------------------------------------

class _QuietHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence the console
        pass


class CatchAllSPA(_QuietHandler):
    """Soft-404 catch-all: every path returns 200 with the SAME body, and no
    security headers at all. A correct pipeline reports ZERO findings here."""

    def do_GET(self):
        body = b"<!DOCTYPE html><html><body>Welcome to the app. Nothing to see.</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Server", "gkntest/1.0")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class Hardened404(_QuietHandler):
    """Correctly hardened: all security headers, real 404s. Also must be ZERO."""

    def do_GET(self):
        self.send_response(404)
        for h in ("Strict-Transport-Security", "Content-Security-Policy",
                  "X-Frame-Options"):
            self.send_header(h, "on")
        body = b"not found"
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class VulnerableApp(_QuietHandler):
    """Actually exposes things (local synthetic evidence)."""

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/actuator/env":
            body = (b'{"activeProfiles":["prod"],"propertySources":[{"name":"x",'
                    b'"properties":{"spring.datasource.password":{"value":"hunter2secret"}}}]}')
        elif path == "/.git/config":
            body = (b"[core]\nrepositoryformatversion = 0\n"
                    b"DB_PASSWORD = SuperSecret9\n")
        elif path == "/backup.zip":
            body = b"PK\x03\x04" + b"\x00" * 400
        else:
            self.send_response(404)
            self.send_header("Content-Length", "4")
            self.end_headers()
            self.wfile.write(b"none")
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _serve(handler, port=0):
    srv = socketserver.TCPServer(("127.0.0.1", port), handler)
    srv.allow_reuse_address = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _run_pipeline(targets, outdir):
    import quick_combat
    return quick_combat.run_combat_pipeline(
        targets=targets, output_dir=outdir, use_nuclei=False,
        use_crawl=False, use_js=False, use_memory=False,
        use_cn_probes=True, deep=True, rate_limit=25,
        scope={"domains": ["127.0.0.1"], "ip_ranges": ["127.0.0.0/8"],
               "allow_private_ips": True})


def check_clean_targets() -> bool:
    print("[7] FALSE-POSITIVE GATE: clean targets must yield 0 findings")
    outdir = tempfile.mkdtemp(prefix="gkn-clean-")
    srvs = []
    try:
        s1, p1 = _serve(CatchAllSPA)
        s2, p2 = _serve(Hardened404)
        srvs = [s1, s2]
        result = _run_pipeline([f"http://127.0.0.1:{p1}", f"http://127.0.0.1:{p2}"],
                               outdir)
        n = result["total_findings"]
        return record("catch-all SPA + hardened server -> 0 findings", n == 0,
                      f"got {n} findings: "
                      + json.dumps([{"type": f.get("type"), "sev": f.get("severity"),
                                     "path": f.get("probe_path")}
                                    for f in json.load(open(
                                        os.path.join(result["output_dir"],
                                                     "findings.json"),
                                        encoding="utf-8"))][:10],
                                   ensure_ascii=False))
    except Exception as e:
        return record("clean-target pipeline run", False, traceback.format_exc()[-400:])
    finally:
        for s in srvs:
            s.shutdown()
            shutil.rmtree(outdir, ignore_errors=True)


def check_true_positives() -> bool:
    print("[8] TRUE-POSITIVE SANITY: real exposures must be found")
    outdir = tempfile.mkdtemp(prefix="gkn-vuln-")
    srvs = []
    try:
        s1, p1 = _serve(VulnerableApp)
        srvs = [s1]
        result = _run_pipeline([f"http://127.0.0.1:{p1}"], outdir)
        findings = json.load(open(os.path.join(result["output_dir"], "findings.json"),
                                  encoding="utf-8"))
        types = {f.get("type") for f in findings}
        has_component = "component_exposure" in types
        has_leak = "info_leak" in types
        escalated = any(f.get("severity") in ("high", "critical") for f in findings)
        return record("actuator/git/backup exposures detected + escalated",
                      has_component and has_leak and escalated,
                      f"types={sorted(types)}, escalated={escalated}")
    except Exception:
        return record("vulnerable-target pipeline run", False,
                      traceback.format_exc()[-400:])
    finally:
        for s in srvs:
            s.shutdown()
        shutil.rmtree(outdir, ignore_errors=True)


def check_pattern_matcher() -> bool:
    print("[9] pattern_matcher test suite")
    proc = subprocess.run(
        [sys.executable, os.path.join(SKILL_DIR, "tests", "test_pattern_matcher.py")],
        capture_output=True, text=True, timeout=60,
        env={**os.environ, "PYTHONIOENCODING": "utf-8"})
    return record("pattern_matcher unittest", proc.returncode == 0,
                  (proc.stderr or "")[-300:])


def main() -> int:
    ap = argparse.ArgumentParser(description="GKN-Phantom self-test")
    ap.add_argument("--quick", action="store_true",
                    help="skip the live-server false-positive/true-positive passes")
    args = ap.parse_args()

    print("=" * 60)
    print("GKN-Phantom self-test")
    print("=" * 60)

    check_imports()
    check_cli_smoke()
    check_scope_guard()
    check_rules()
    check_validator_hardening()
    check_hard_gates()
    if not args.quick:
        check_pattern_matcher()
        clean = check_clean_targets()
        true_pos = check_true_positives()
    else:
        clean = true_pos = True
        print("  [SKIP] live-server passes (--quick)")

    failed = [r for r in RESULTS if not r["ok"]]
    print("=" * 60)
    print(f"TOTAL: {len(RESULTS)} checks, {len(failed)} failed")
    if failed:
        for r in failed:
            print(f"  FAIL: {r['check']} — {r['detail'][:200]}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
