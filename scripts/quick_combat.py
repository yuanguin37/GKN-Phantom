#!/usr/bin/env python3
"""Quick Combat Pipeline — GKN-Phantom v5.1.

One-command pipeline for practical penetration testing:
  1. Quick detection scan (nuclei + built-in probes)
  2. Auto PoC generation (curl / Python / HAR / Markdown / raw HTTP)
  3. Auto exploit generation (functional Python scripts)
  4. Visual index HTML + structured JSON bundle

Design philosophy (from real combat feedback):
  - Detection should be fast, not exhaustive. Scan narrow, verify quick.
  - PoCs must be copy-paste ready for reporting.
  - Exploits must demonstrate real impact, not theoretical risk.
  - Custom detection rules are brittle — lean on nuclei's curated templates.

Usage:
  python quick_combat.py --targets targets.json --output-dir ./combat_output/
  python quick_combat.py --targets targets.json --tech tech_stack.json
  python quick_combat.py --targets targets.json --no-nuclei --quick-probes-only
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Ensure scripts/ is importable
SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPTS_DIR)

from utils import load_json, dump_json, utc_now_iso
import nuclei_runner
import poc_generator
import exploit_generator

# =============================================================================
# Quick built-in probes — lightweight, high-signal checks (stdlib only)
# =============================================================================

QUICK_PROBES = [
    {
        "type": "misconfig",
        "name": "Security headers check",
        "paths": [""],
        "check": "header",
    },
    {
        "type": "info_leak",
        "name": "Source leak paths",
        "paths": [
            "/.git/config", "/.env", "/.DS_Store",
            "/phpinfo.php", "/info.php", "/test.php",
        ],
        "check": "pattern",
        "patterns": [
            "[core]", "DB_PASSWORD", "APP_KEY", "AKIA",
            "BEGIN RSA PRIVATE KEY", "phpinfo()",
        ],
    },
    {
        "type": "component_exposure",
        "name": "Actuator / Swagger / Druid",
        "paths": [
            "/actuator/env", "/actuator/health", "/actuator/mappings",
            "/swagger-ui.html", "/swagger-ui/index.html", "/v3/api-docs",
            "/druid/index.html", "/druid/login.html",
        ],
        "check": "pattern",
        "patterns": [
            '"activeProfiles"', '"swagger"', '"openapi"',
            "Druid Stat Index", "druid-login",
        ],
    },
    {
        "type": "directory_listing",
        "name": "Directory listing",
        "paths": [
            "/uploads/", "/backup/", "/logs/", "/temp/", "/static/",
        ],
        "check": "pattern",
        "patterns": ["Index of /", "Parent Directory"],
    },
    {
        "type": "info_leak",
        "name": "Backup files",
        "paths": [
            "/backup.zip", "/backup.tar.gz", "/www.zip",
            "/config.php.bak", "/config.yml.bak",
            "/wp-config.php.bak", "/.htaccess.bak",
        ],
        "check": "status",
        "status_codes": [200],
    },
    {
        "type": "graphql_introspection",
        "name": "GraphQL introspection",
        "paths": [
            "/graphql", "/gql", "/api/graphql",
        ],
        "check": "pattern",
        "patterns": ['"__schema"', '"queryType"', '"mutationType"'],
    },
    {
        "type": "open_redirect",
        "name": "Open redirect check",
        "paths": [
            "?redirect=https://oob.authorized.test/GKN",
            "?url=https://oob.authorized.test/GKN",
            "?next=https://oob.authorized.test/GKN",
            "?returnUrl=https://oob.authorized.test/GKN",
        ],
        "check": "redirect",  # 3xx with Location header
    },
]


def _run_quick_probe(target: str, probe: dict) -> list[dict]:
    """Run a single quick probe against a target URL. Returns findings."""
    import urllib.request
    import ssl

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # Build redirect-suppressed opener for redirect probes
    class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    no_redirect_opener = urllib.request.build_opener(_NoRedirectHandler)

    findings: list[dict] = []
    base = target.rstrip("/")

    for path in probe.get("paths", []):
        if path.startswith("?"):
            url = (base + path) if "?" not in base else base
            # When base already has query string and path starts with ?, strip path's ?
            if "?" in base:
                url = base + "&" + path.lstrip("?")
            else:
                url = base + path
        else:
            url = f"{base}{path}"

        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "GKN-Phantom/5.1 QuickProbe"},
            )
            check_type = probe.get("check", "pattern")
            if check_type == "redirect":
                try:
                    resp = no_redirect_opener.open(req, timeout=8)
                except urllib.error.HTTPError as e:
                    resp = e
            else:
                try:
                    resp = urllib.request.urlopen(req, timeout=8, context=ctx)
                except urllib.error.HTTPError as e:
                    resp = e
                except Exception:
                    continue

            body = b""
            try:
                body = resp.read()
            except Exception:
                pass
            body_str = body.decode("utf-8", errors="replace")

            headers = {}
            try:
                headers = {k.lower(): str(v) for k, v in resp.headers.items()}
            except Exception:
                pass

            matched = False
            if check_type == "header":
                matched = _check_headers_dict(headers)
            elif check_type == "pattern":
                for pattern in probe.get("patterns", []):
                    if pattern in body_str:
                        matched = True
                        break
            elif check_type == "status":
                if resp.status in probe.get("status_codes", [200]):
                    matched = True
            elif check_type == "redirect":
                if resp.status in (301, 302, 303, 307, 308):
                    loc = headers.get("location", "")
                    if "oob.authorized.test" in loc or "GKN" in loc:
                        matched = True

            if matched:
                findings.append({
                    "type": probe["type"],
                    "severity": "medium" if probe["type"] in ("component_exposure", "info_leak") else "low",
                    "tier": "low",
                    "target": target,
                    "probe_path": path,
                    "probe_name": probe["name"],
                    "status": "detected",
                    "confidence": 0.7,
                    "evidence": {
                        "request": f"GET {path} HTTP/1.1\\nHost: {target}",
                        "response": body_str[:2000],
                        "timestamp": utc_now_iso(),
                        "tool": "quick_probe",
                        "status_code": resp.status if hasattr(resp, 'status') else None,
                        "headers": headers,
                    },
                    "reproducible": True,
                    "safe_poc": True,
                    "detection_signal": probe.get("patterns", ["header check"])[0] if probe.get("patterns") else "status code",
                    "auto_verifiable": True,
                    "verification_method": "http_probe",
                    "requires_credentials": False,
                    "requires_human_approval": False,
                    "blocked_in_safe_mode": False,
                })
        except Exception:
            continue

    return findings


def _check_headers_dict(headers: dict) -> bool:
    """Check for missing security headers or verbose banners from a header dict."""
    missing = any(
        h not in headers
        for h in ("strict-transport-security", "content-security-policy", "x-frame-options")
    )
    verbose = "x-powered-by" in headers or "server" in headers
    return missing or verbose


def run_quick_probes(targets: list[str]) -> list[dict]:
    """Execute quick probes against all targets. Returns finding dicts."""
    all_findings: list[dict] = []
    for target in targets:
        for probe in QUICK_PROBES:
            found = _run_quick_probe(target, probe)
            all_findings.extend(found)
    return all_findings


# =============================================================================
# Main Pipeline
# =============================================================================

def run_combat_pipeline(
    targets: list[str],
    tech_data: dict | None = None,
    output_dir: str = "./combat_output",
    use_nuclei: bool = True,
    quick_probes: bool = True,
    severity_filter: list[str] | None = None,
    rate_limit: int = 150,
    concurrency: int = 25,
    poc_formats: list[str] | None = None,
) -> dict:
    """Run the full detect → PoC → exploit combat pipeline.

    Returns a summary dict with paths to all generated artifacts.
    """
    if poc_formats is None:
        poc_formats = ["curl", "python", "raw_http"]

    ts_dir = datetime.now(timezone.utc).strftime("combat_%Y%m%d_%H%M%SZ")
    output_path = os.path.join(output_dir, ts_dir)
    os.makedirs(output_path, exist_ok=True)

    sev_filter = severity_filter or ["critical", "high", "medium"]
    all_findings: list[dict] = []
    summary_parts: list[str] = []

    # ------------------------------------------------------------------
    # Phase 1: Nuclei scan
    # ------------------------------------------------------------------
    if use_nuclei:
        nuclei_ok, npath, nversion = nuclei_runner.detect_nuclei()
        if nuclei_ok:
            summary_parts.append(f"Nuclei {nversion} available at {npath}")
            tdir = nuclei_runner._get_default_templates_dir()
            templates = nuclei_runner.scan_templates(
                templates_dir=tdir, severity_filter=sev_filter,
            )
            if tech_data:
                templates = nuclei_runner.select_templates_by_tech(
                    templates, tech_data,
                )
            # Scope-limit: cap to DEFAULT_MAX_TEMPLATES
            removed = 0
            if len(templates) > nuclei_runner.DEFAULT_MAX_TEMPLATES:
                removed = len(templates) - nuclei_runner.DEFAULT_MAX_TEMPLATES
                templates = templates[:nuclei_runner.DEFAULT_MAX_TEMPLATES]
                summary_parts.append(
                    f"Scope-limited: {removed} templates removed "
                    f"({nuclei_runner.DEFAULT_MAX_TEMPLATES} kept)"
                )
            plan = nuclei_runner.generate_execution_plan(
                templates=templates,
                targets=targets,
                rate_limit=rate_limit,
                concurrency=concurrency,
                severity_filter=sev_filter,
            )
            summary_parts.append(
                f"Nuclei plan: {plan.template_count} templates × "
                f"{plan.target_count} targets ≈ {_human(plan.estimated_time_seconds)}"
            )
            # Execute nuclei (if available)
            try:
                proc = subprocess.run(
                    plan.commands[0] if plan.commands else "echo 'no commands'",
                    shell=True, capture_output=True, text=True, timeout=plan.estimated_time_seconds + 60,
                )
                nuclei_findings = [
                    f.to_dict() for f in nuclei_runner.parse_nuclei_output(proc.stdout)
                ]
                deduped = nuclei_runner.deduplicate_findings(
                    nuclei_runner.parse_nuclei_output(proc.stdout)
                )
                all_findings.extend([f.to_dict() for f in deduped])
                summary_parts.append(f"Nuclei: {len(deduped)} findings (deduped)")
            except subprocess.TimeoutExpired:
                summary_parts.append("Nuclei: timed out (scope limit applied)")
            except Exception as e:
                summary_parts.append(f"Nuclei: execution error — {e}")
        else:
            summary_parts.append("Nuclei not installed — skip")
            plan = nuclei_runner.generate_execution_plan(
                templates=[], targets=targets,
                rate_limit=rate_limit, concurrency=concurrency,
                severity_filter=sev_filter,
            )
            if plan.warnings:
                summary_parts.extend(plan.warnings[:2])

    # ------------------------------------------------------------------
    # Phase 2: Quick built-in probes
    # ------------------------------------------------------------------
    if quick_probes:
        qp_findings = run_quick_probes(targets)
        if qp_findings:
            all_findings.extend(qp_findings)
            summary_parts.append(f"Quick probes: {len(qp_findings)} findings")

    # ------------------------------------------------------------------
    # Phase 3: Assign IDs, sort, dedup
    # ------------------------------------------------------------------
    for i, f in enumerate(all_findings, 1):
        f["id"] = f.get("id", "") or f"combat-{i:04d}"
        f["severity"] = f.get("severity", "low").lower()

    # Simple dedup by type+target
    seen: set = set()
    deduped_all: list[dict] = []
    for f in all_findings:
        key = f"{f.get('type','')}|{f.get('target','')}|{f.get('probe_path','')}"
        if key not in seen:
            seen.add(key)
            deduped_all.append(f)

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    deduped_all.sort(key=lambda x: sev_order.get(x.get("severity", "low"), 5))
    all_findings = deduped_all

    summary_parts.append(f"Total findings: {len(all_findings)}")

    # Save findings JSON
    findings_path = os.path.join(output_path, "findings.json")
    with open(findings_path, "w", encoding="utf-8") as fh:
        fh.write(dump_json(all_findings))

    # ------------------------------------------------------------------
    # Phase 4: PoC generation
    # ------------------------------------------------------------------
    poc_dir = os.path.join(output_path, "pocs")
    poc_result = poc_generator.generate_poc_batch(all_findings, poc_formats, poc_dir)
    summary_parts.append(
        f"PoCs: {poc_result.get('generated', 0)} generated → {poc_dir}"
    )

    # ------------------------------------------------------------------
    # Phase 5: Exploit generation (high + critical only)
    # ------------------------------------------------------------------
    exp_dir = os.path.join(output_path, "exploits")
    exp_result = exploit_generator.generate_exploit_batch(all_findings, exp_dir)
    summary_parts.append(
        f"Exploits: {exp_result['generated']} generated → {exp_dir}"
    )

    # ------------------------------------------------------------------
    # Phase 6: Combat index
    # ------------------------------------------------------------------
    index_path = _write_combat_index(output_path, all_findings, summary_parts)

    # ------------------------------------------------------------------
    # Phase 7: Manifest
    # ------------------------------------------------------------------
    manifest = {
        "pipeline_version": "5.1.0",
        "timestamp": utc_now_iso(),
        "targets": targets,
        "target_count": len(targets),
        "total_findings": len(all_findings),
        "by_severity": {
            sev: sum(1 for f in all_findings if f.get("severity") == sev)
            for sev in ["critical", "high", "medium", "low"]
        },
        "artifacts": {
            "findings": findings_path,
            "pocs": poc_dir,
            "exploits": exp_dir,
            "index": index_path,
        },
        "summary": summary_parts,
    }
    manifest_path = os.path.join(output_path, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as fh:
        fh.write(dump_json(manifest))

    return {
        "output_dir": os.path.abspath(output_path),
        **manifest,
    }


def _write_combat_index(output_dir: str, findings: list[dict], summary: list[str]) -> str:
    """Generate a simple index HTML with all findings + links."""
    sev_colors = {
        "critical": "#dc2626", "high": "#ea580c",
        "medium": "#ca8a04", "low": "#2563eb",
    }
    by_type: dict[str, list] = {}
    for f in findings:
        t = f.get("type", "unknown")
        by_type.setdefault(t, []).append(f)

    type_rows = ""
    for t, items in sorted(by_type.items()):
        severity = items[0].get("severity", "low")
        color = sev_colors.get(severity, "#6b7280")
        type_rows += f"""
        <tr>
          <td style="color:{color};font-weight:bold">{t}</td>
          <td>{len(items)}</td>
          <td><span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px">{severity}</span></td>
          <td>{items[0].get('target','?')[:60]}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>GKN-Phantom Combat Report</title>
<style>
  body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0f172a;color:#e2e8f0;padding:24px}}
  h1{{color:#38bdf8}} h2{{color:#94a3b8;border-bottom:1px solid #334155;padding-bottom:8px}}
  table{{width:100%;border-collapse:collapse;margin:16px 0}}
  th,td{{padding:10px 14px;text-align:left;border-bottom:1px solid #1e293b}}
  th{{background:#1e293b;color:#94a3b8}}
  .summary{{background:#1e293b;padding:16px;border-radius:8px;margin:16px 0}}
  .summary li{{margin:4px 0;color:#94a3b8}}
  .artifact{{background:#0f172a;border:1px solid #334155;border-radius:8px;padding:12px;margin:8px 0}}
  a{{color:#38bdf8}}
  .tag{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:12px;margin:2px}}
</style></head>
<body>
<h1>⚔ GKN-Phantom Combat Report</h1>
<p style="color:#64748b">{utc_now_iso()}</p>

<h2>Summary</h2>
<div class="summary">
<ul>{"".join(f"<li>{s}</li>" for s in summary)}</ul>
</div>

<h2>Findings by Type ({len(findings)} total)</h2>
<table>
<tr><th>Type</th><th>Count</th><th>Severity</th><th>Sample Target</th></tr>
{type_rows}
</table>

<h2>Artifacts</h2>
<div class="artifact">
  <strong>Findings JSON:</strong>
  <a href="findings.json">findings.json</a>
  — all findings in structured JSON format
</div>
<div class="artifact">
  <strong>PoC Scripts:</strong>
  <a href="pocs/">pocs/</a>
  — curl commands, Python scripts, raw HTTP for each finding
</div>
<div class="artifact">
  <strong>Exploit Scripts:</strong>
  <a href="exploits/">exploits/</a>
  — functional Python exploit scripts (high + critical)
</div>
<div class="artifact">
  <strong>Manifest:</strong>
  <a href="manifest.json">manifest.json</a>
  — full pipeline manifest
</div>

<p style="color:#64748b;font-size:12px;margin-top:32px">
  ⚠ AUTHORIZED SECURITY TESTING ONLY. Generated by GKN-Phantom v5.1.
</p>
</body></html>"""

    path = os.path.join(output_dir, "index.html")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
    return os.path.abspath(path)


def _human(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s"
    return f"{seconds // 3600}h {(seconds % 3600) // 60}m"


def _load_targets(source: str) -> list[str]:
    """Load targets from JSON file, text file (one per line), or comma-separated."""
    if not source:
        return []
    # Try JSON
    try:
        data = load_json(source)
        if isinstance(data, list):
            return [str(t) for t in data if t]
        if isinstance(data, dict):
            for key in ("targets", "urls", "hosts", "domains"):
                if key in data:
                    return [str(t) for t in data[key] if t]
    except Exception:
        pass
    # Try as comma-separated
    if "," in source and not os.path.isfile(source):
        return [t.strip() for t in source.split(",") if t.strip()]
    # Try as file (one per line)
    try:
        with open(source, "r", encoding="utf-8") as fh:
            return [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    except Exception:
        pass
    return [source]


# =============================================================================
# CLI
# =============================================================================

def main() -> int:
    ap = argparse.ArgumentParser(description="GKN-Phantom Quick Combat Pipeline v5.1")
    ap.add_argument("--targets", required=True,
                    help="Targets: JSON file, comma-separated URLs, or text file (one per line)")
    ap.add_argument("--tech", help="Technology fingerprint JSON (from tech_fingerprint.py)")
    ap.add_argument("--output-dir", default="./combat_output",
                    help="Output directory (default: ./combat_output)")
    ap.add_argument("--severity", default="critical,high,medium",
                    help="Severity filter (default: critical,high,medium)")
    ap.add_argument("--no-nuclei", action="store_true",
                    help="Skip nuclei scan (use only quick built-in probes)")
    ap.add_argument("--no-quick-probes", action="store_true",
                    help="Skip built-in quick probes")
    ap.add_argument("--rate-limit", type=int, default=150,
                    help="Nuclei rate limit (default: 150)")
    ap.add_argument("--concurrency", type=int, default=25,
                    help="Nuclei concurrency (default: 25)")
    ap.add_argument("--poc-formats", default="curl,python,raw_http",
                    help="PoC output formats (default: curl,python,raw_http)")
    args = ap.parse_args()

    targets = _load_targets(args.targets)
    if not targets:
        print("[!] No targets loaded", file=sys.stderr)
        return 2

    severity_filter = [
        s.strip().lower() for s in args.severity.split(",") if s.strip()
    ]

    tech_data = None
    if args.tech:
        try:
            tech_data = load_json(args.tech)
        except Exception:
            print(f"[!] Cannot load tech data from {args.tech}", file=sys.stderr)

    poc_formats = [
        f.strip() for f in args.poc_formats.split(",") if f.strip()
    ]

    print(f"\n{'='*60}")
    print(f"GKN-Phantom Quick Combat Pipeline v5.1")
    print(f"Targets: {len(targets)} | Severity: {', '.join(severity_filter)}")
    print(f"Nuclei: {'ON' if not args.no_nuclei else 'OFF'} | Quick probes: {'ON' if not args.no_quick_probes else 'OFF'}")
    print(f"{'='*60}\n")

    t0 = time.monotonic()
    try:
        result = run_combat_pipeline(
            targets=targets,
            tech_data=tech_data,
            output_dir=args.output_dir,
            use_nuclei=not args.no_nuclei,
            quick_probes=not args.no_quick_probes,
            severity_filter=severity_filter,
            rate_limit=args.rate_limit,
            concurrency=args.concurrency,
            poc_formats=poc_formats,
        )
    except Exception as e:
        print(f"\n[!] Pipeline failed: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1

    elapsed = time.monotonic() - t0
    print(f"\n{'='*60}")
    for s in result["summary"]:
        print(f"  {s}")
    print(f"  Duration: {_human(int(elapsed))}")
    print(f"{'='*60}")
    print(f"\n[+] Output: {result['output_dir']}")
    print(f"[+] Index:  {result['artifacts']['index']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
