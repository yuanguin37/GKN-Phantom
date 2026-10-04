#!/usr/bin/env python3
"""Finding Validator for the GKN-Phantom Penetration Testing Skill.

Re-runs a candidate finding's PoC, captures fresh evidence, and classifies it
as `validated` (TP), `unverified` (lead — insufficient replay evidence), or
`false_positive` (FP). Used at the VALIDATION state.

Reproducibility Gate — the five hard rules are ENFORCED HERE, in code:

  1. Replay >= 2x:        a finding is `validated` only when the validator
                          itself replayed the request >= 2 times and the
                          signal matched on EVERY replay. (perform_replay())
  2. Control request:     perform_replay() can send a benign control request;
                          if the CONTROL also matches the signal, the signal
                          is not specific -> downgraded to `unverified`.
  3. Signal derivation:   signal_matched is ALWAYS derived by this module
                          (match_signal). A caller-supplied signal_matched
                          flag is ignored — no self-attested verdicts.
  4. Evidence freshness:  the validator records the time of each actual
                          replay (`evidence.replayed_at`). It never re-stamps
                          old captured evidence with the current time.
  5. Lead isolation:      anything not fully validated stays a lead:
                          status `unverified` (or `false_positive`), never
                          upgraded by confidence arithmetic alone.

Integration: call perform_replay() (or run this script with
--replay-request) to obtain a validator-signed replay bundle, then pass it
to validate(). The bundle carries per-replay status codes, response hashes
and timestamps — report_docx.py's hard gates check those fields.

Usage:
  # full verification: send the actual requests, then classify
  python finding_validator.py --finding finding.json --replay-request req.json
  # req.json: {"url": "...", "method": "GET", "headers": {}, "body": null,
  #            "replays": 2, "timeout": 8, "control_url": "...", "marker": "PTSKILLTEST"}

  # classification only (legacy mode: caller-provided replay evidence —
  # capped at `unverified`, see validate())
  python finding_validator.py --finding finding.json --replay replay.json
  python finding_validator.py --batch findings.json --replays replays.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from utils import load_json, dump_json, utc_now_iso

CONFIDENCE_THRESHOLD = 0.8
VALIDATOR_ID = "finding_validator"
VALIDATOR_VERSION = "5.12"

# Statuses
ST_VALIDATED = "validated"
ST_UNVERIFIED = "unverified"      # signal matched but evidence insufficient -> lead
ST_FALSE_POSITIVE = "false_positive"
ST_SKIPPED = "skipped"


# =============================================================================
# Signal pattern engine
# =============================================================================
#
# Deterministic response-body patterns per vulnerability type. These encode
# the "detection_signal" definitions from vuln_detector.py rules into
# machine-checkable regexes so that verification does not require a human
# (or the agent) to eyeball the response.

SIGNAL_PATTERNS: dict[str, list[re.Pattern]] = {
    "sqli": [
        re.compile(r"SQL syntax.*?MySQL|Warning.*?\Wmysqli?_", re.I | re.S),
        re.compile(r"MySQLSyntaxErrorException|com\.mysql\.jdbc|MariaDB.*?error", re.I),
        re.compile(r"PostgreSQL.*?ERROR|pg_query\(\).*?failed|Npgsql\.PostgresException", re.I),
        re.compile(r"Microsoft.*?ODBC.*?SQL Server|Unclosed quotation mark|SqlException", re.I),
        re.compile(r"ORA-\d{5}|Oracle.*?Driver|SQL command not properly ended", re.I),
        re.compile(r"SQLite/JDBCDriver|SQLite3?\.query|unrecognized token", re.I),
        re.compile(r"You have an error in your SQL syntax", re.I),
        re.compile(r"syntax error at or near|quoted string not properly terminated", re.I),
    ],
    "path_traversal": [
        re.compile(r"root:x:0:0:"),
        re.compile(r"daemon:x:\d+:\d+:"),
        re.compile(r"\[fonts\]|\[extensions\]", re.I),
        re.compile(r"for 16-bit app support", re.I),
    ],
    "info_leak": [
        re.compile(r"\[core\]\s*[\r\n]+\s*repositoryformatversion", re.I),
        re.compile(r"svn:wc:ra_dav:version-url|<svn:", re.I),
        re.compile(r"AKIA[0-9A-Z]{16}"),
        re.compile(r"ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}"),
        re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |)PRIVATE KEY-----"),
        re.compile(r"(?i)\b(DB_PASSWORD|APP_KEY|SECRET_KEY|JWT_SECRET|API_KEY)\s*[=:]\s*\S+"),
        re.compile(r"<title>phpinfo\(\)</title>|PHP Version \d\.\d+\.\d+", re.I),
    ],
    "component_exposure": [
        re.compile(r'"activeProfiles"|"propertySources"|"contexts".*?"beans"', re.S),
        re.compile(r'"swagger"\s*:\s*"2\.0"|"openapi"\s*:\s*"3\.', re.I),
        re.compile(r"Druid Stat Index|druid-login|DataSource-|SQL Stat", re.I),
        re.compile(r"Jolokia.*?Agent|jolokia.*?version", re.I),
        re.compile(r"<title>Swagger UI</title>|springfox|knife4j", re.I),
        re.compile(r"UEditor|ueditor\.config", re.I),
    ],
    "directory_listing": [
        re.compile(r"<title>Index of /", re.I),
        re.compile(r">\s*Parent Directory\s*<", re.I),
        re.compile(r"\[To Parent Directory\]", re.I),
    ],
    "graphql_introspection": [
        re.compile(r'"__schema"\s*:', re.I),
        re.compile(r'"queryType"\s*:.*?"types"\s*:\s*\[', re.S),
        re.compile(r"IntrospectionQuery", re.I),
    ],
    "xxe": [
        re.compile(r"SAXParseException|XMLParseException|SimpleXMLElement", re.I),
        re.compile(r"libxml.*?error|XML parser.*?error|DOCTYPE.*?not allowed", re.I),
        re.compile(r"org\.xml\.sax|javax\.xml\.parsers", re.I),
    ],
    "ssti": [
        re.compile(r"jinja2\.|TemplateSyntaxError|UndefinedError", re.I),
        re.compile(r"Twig.*?Error|freemarker\.template|VelocityException", re.I),
    ],
    "deserialization": [
        re.compile(r"InvalidClassException|ObjectInputStream|readObject\(\)", re.I),
        re.compile(r"unserialize\(\)|php unserialize|pickle\.loads|_pickle\.UnpicklingError", re.I),
        re.compile(r"java\.io\.StreamCorruptedException|BinaryReader\.ReadString", re.I),
    ],
    "ldap_injection": [
        re.compile(r"LDAPException|NamingException|javax\.naming", re.I),
        re.compile(r"ldap_bind\(\)|ldap_search\(\)|LDAP error code", re.I),
        re.compile(r"Bad search filter|Invalid DN string", re.I),
    ],
    "nosql_injection": [
        re.compile(r"MongoError|MongoServerError|MongoParseError", re.I),
        re.compile(r"invalid operator|\$where.*?not allowed|unknown operator", re.I),
        re.compile(r"SyntaxError: Unexpected token.*?JSON", re.I),
    ],
    "weak_credential": [
        re.compile(r'"code"\s*:\s*0\s*,\s*"msg"\s*:\s*"(?:success|ok)"', re.I),
        re.compile(r'"success"\s*:\s*true.*?"token"', re.I | re.S),
    ],
    "auth_bypass": [
        re.compile(r'"token"\s*:\s*"[A-Za-z0-9_\-.]{16,}".*?"(?:role|isAdmin)"', re.I | re.S),
    ],
}

# Header-based signal checks: vuln type -> list of (header_name, regex|value_check)
HEADER_SIGNAL_CHECKS: dict[str, list[tuple[str, re.Pattern]]] = {
    "open_redirect": [
        # Marker/authorized-sink only. The old pattern had a literal "(?!{host})"
        # (never interpolated) as a catch-all "external host" branch — removed.
        ("Location", re.compile(r"oob\.authorized\.test|PTSKILLTEST", re.I)),
    ],
    "crlf_injection": [
        ("Set-Cookie", re.compile(r"PTSKILLTEST=crlf", re.I)),
        ("X-PTSKILLTEST", re.compile(r"injected", re.I)),
    ],
    "cors_misconfig": [
        ("Access-Control-Allow-Origin", re.compile(r"^null$|attacker\.evil\.test|^\*$", re.I)),
    ],
    "host_header_injection": [
        ("Location", re.compile(r"attacker\.evil\.test", re.I)),
    ],
}

# Default markers injected by the detection plan (payload_playbook.md).
DEFAULT_MARKER = "PTSKILLTEST"
SSTI_ARITHMETIC_RESULT = "49"  # {{7*7}}

# XSS proof: the marker must sit in an EXECUTABLE position, not just be
# reflected anywhere (a reflected plain marker used to validate any XSS).
_XSS_EXECUTABLE_RES = [
    re.compile(r"<script[^>]*>[^<]*" + re.escape(DEFAULT_MARKER), re.I),
    re.compile(re.escape(DEFAULT_MARKER) + r"[^<]*</script>", re.I),
    re.compile(r"<\w+[^>]*\bon\w+\s*=\s*['\"][^'\"]*" + re.escape(DEFAULT_MARKER), re.I),
    re.compile(r"<img[^>]*\bsrc\s*=\s*['\"][^'\"]*" + re.escape(DEFAULT_MARKER), re.I),
    re.compile(r"javascript:[^'\"]*" + re.escape(DEFAULT_MARKER), re.I),
]


def _header_lookup(headers: dict | None, name: str) -> str:
    """Case-insensitive header lookup. Returns '' when absent."""
    if not headers:
        return ""
    if isinstance(headers, dict):
        lower = name.lower()
        for k, v in headers.items():
            if str(k).lower() == lower:
                return str(v)
    return ""


def match_signal(
    finding_type: str,
    response_text: str = "",
    headers: dict | None = None,
    status_code: int | None = None,
    marker: str | None = None,
    control_text: str | None = None,
) -> tuple[bool, str]:
    """Deterministically decide whether a fresh response matches the
    detection signal for `finding_type`.

    Returns (matched, reason). `reason` is a short human-readable string
    describing which check fired (or why nothing matched). Used by
    validate() — signal derivation is never taken from the caller.

    `control_text` (optional): response of the BENIGN control request.
    For differential types (ssti) a control that ALSO shows the signal
    proves the signal is not specific -> no match.
    """
    body = response_text or ""
    marker = marker or DEFAULT_MARKER

    # 1. Type-specific body patterns
    for pattern in SIGNAL_PATTERNS.get(finding_type, []):
        if pattern.search(body):
            return True, f"body pattern matched: {pattern.pattern[:60]}"

    # 2. Header-based signals
    for header_name, pattern in HEADER_SIGNAL_CHECKS.get(finding_type, []):
        value = _header_lookup(headers, header_name)
        if value:
            if header_name == "Location" and finding_type == "open_redirect":
                if marker.lower() in value.lower() or "oob.authorized.test" in value.lower():
                    return True, f"Location header points to authorized sink: {value[:80]}"
            elif pattern.search(value):
                return True, f"header {header_name} matched: {value[:80]}"

    # 3. Marker reflection checks (xss / ssti / host-header / crlf body)
    if finding_type == "xss":
        if marker in body:
            if any(rx.search(body) for rx in _XSS_EXECUTABLE_RES):
                return True, "marker reflected in an EXECUTABLE position (script/handler/uri)"
            if "&lt;" in body.lower() or "&#60;" in body.lower():
                return False, "marker present but HTML-escaped (not executable)"
            return False, "marker reflected but not in an executable position"
    elif finding_type == "ssti":
        # Arithmetic evaluation with specificity guards:
        #   - '49' must appear as a word, the payload template must NOT be
        #     echoed (a bare "49" alone matched any page with the number 49),
        #   - the CONTROL response must NOT contain 49 (else not specific).
        payload_echoed = any(p in body for p in ("{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>"))
        result_present = re.search(r"\b49\b", body) is not None
        if result_present and not payload_echoed:
            if control_text and re.search(r"\b49\b", control_text):
                return False, "arithmetic result present but control also shows it (not specific)"
            return True, "arithmetic result '49' reflected (template evaluated)"
    elif finding_type in ("host_header_injection", "crlf_injection", "open_redirect"):
        if marker in body:
            return True, f"marker '{marker}' reflected in body"
    elif finding_type == "misconfig":
        # misconfig requires >= 2 of the 3 baseline security headers missing
        # AND the caller must actually have captured headers (an empty header
        # dict proves nothing and used to make this branch always-true).
        # A verbose banner alone is informational, not a misconfig signal.
        if not headers:
            return False, "no response headers captured — cannot judge misconfig"
        lowered_headers = {str(k).lower() for k in headers}
        missing = [
            h for h in ("strict-transport-security", "content-security-policy",
                        "x-frame-options")
            if h not in lowered_headers
        ]
        if len(missing) >= 2:
            return True, f"security headers missing: {', '.join(missing)}"
    elif finding_type == "data_exposure":
        # Local PII threshold check (no network needed) — delegate lazily to
        # vuln_detector.classify_data_exposure to avoid circular import cost
        # at module load.
        try:
            from vuln_detector import classify_data_exposure

            triggered, _score = classify_data_exposure(body)
            if triggered:
                return True, "PII threshold exceeded in response body"
        except ImportError:
            return False, "vuln_detector unavailable — data_exposure NOT checked"

    return False, "no signal matched"


# =============================================================================
# Real replay (Reproducibility Gate rules 1, 2, 4)
# =============================================================================

def _sha256_hex(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def perform_replay(request_spec: dict, headers_extra: dict | None = None,
                   proxy: str | None = None,
                   rate_limit: float = 3.0) -> dict:
    """Actually send the finding's PoC request >= 2 times + optional control.

    request_spec:
      {
        "url": "https://t/api/x?param=PAYLOAD",   # required
        "method": "GET",                          # default GET
        "headers": {...},                         # optional extra headers
        "body": "..." or null,                    # optional request body
        "replays": 2,                             # default 2, capped at 5
        "timeout": 8,                             # per request
        "control_url": "https://t/api/x?param=benign",  # optional control
        "control_body": "...",                    # optional control body
      }

    Returns a validator-signed bundle:
      {
        "validator": "finding_validator", "validator_version": "5.12",
        "request": <rendered spec>, "replays": [ {timestamp, status_code,
        response_hash, elapsed_ms, response, headers}, ... ],
        "control": {...} | None
      }
    """
    import ssl
    import urllib.error
    import urllib.request

    from rate_limiter import RateLimiter

    url = str(request_spec.get("url", "") or "")
    if not url:
        raise ValueError("request_spec.url is required")
    method = str(request_spec.get("method", "GET")).upper()
    n_replays = max(2, min(int(request_spec.get("replays", 2) or 2), 5))
    timeout = float(request_spec.get("timeout", 8) or 8)

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    rl = RateLimiter(rps=rate_limit, burst=max(3, int(rate_limit)))

    def _send(target_url: str, body) -> dict:
        rl.acquire()
        hdrs = {"User-Agent": f"GKN-Phantom/{VALIDATOR_VERSION} Validator"}
        hdrs.update(headers_extra or {})
        hdrs.update(request_spec.get("headers") or {})
        data = body.encode("utf-8") if isinstance(body, str) else body
        req = urllib.request.Request(target_url, data=data, method=method,
                                     headers=hdrs)
        t0 = time.monotonic()
        try:
            resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        except urllib.error.HTTPError as e:
            resp = e
        except Exception as e:
            return {"timestamp": utc_now_iso(), "status_code": None,
                    "response_hash": None, "elapsed_ms": int((time.monotonic() - t0) * 1000),
                    "response": "", "headers": {}, "error": str(e)}
        raw = resp.read(262144)
        elapsed = int((time.monotonic() - t0) * 1000)
        hd = {}
        try:
            hd = {k.lower(): str(v) for k, v in resp.headers.items()}
        except Exception:
            pass
        return {"timestamp": utc_now_iso(),
                "status_code": getattr(resp, "status", None) or getattr(resp, "code", None),
                "response_hash": _sha256_hex(raw),
                "elapsed_ms": elapsed,
                "response": raw.decode("utf-8", errors="replace")[:65536],
                "headers": hd}

    replays = [_send(url, request_spec.get("body")) for _ in range(n_replays)]
    control = None
    if request_spec.get("control_url"):
        control = _send(str(request_spec["control_url"]),
                        request_spec.get("control_body"))
    return {
        "validator": VALIDATOR_ID,
        "validator_version": VALIDATOR_VERSION,
        "request": {
            "url": url, "method": method,
            "headers": request_spec.get("headers") or {},
            "body": (request_spec.get("body") or "")[:2000] if isinstance(request_spec.get("body"), str) else request_spec.get("body"),
            "control_url": str(request_spec.get("control_url") or "") or None,
        },
        "replays": replays,
        "control": control,
    }


# =============================================================================
# Core validation
# =============================================================================

def _render_request_line(spec: dict) -> str:
    body = spec.get("body")
    line = f"{spec.get('method', 'GET')} {spec.get('url', '')} HTTP/1.1"
    for k, v in (spec.get("headers") or {}).items():
        line += f"\n{k}: {v}"
    if body:
        line += f"\n\n{str(body)[:500]}"
    return line


def validate(finding: dict, replay_result: dict) -> dict:
    """Return a copy of `finding` with updated status/evidence/confidence.

    Two input shapes are accepted:

    A) Validator-signed bundle (from perform_replay / --replay-request):
       {"validator": "finding_validator", "request": {...},
        "replays": [ {status_code, response_hash, response, headers, ...} xN ],
        "control": {...} | None}
       -> the ONLY shape that can reach `validated` (rules 1-5 enforced).

    B) Legacy caller-provided evidence:
       {"request": "...", "response": "...", "tool": "...", ...}
       -> signal is still derived here (caller flags ignored), but the best
          achievable status is `unverified` (a lead): a single pasted
          response cannot satisfy the >=2-replay rule. Feed it through
          perform_replay() for real validation.
    """
    if not isinstance(finding, dict) or not finding.get("type"):
        raise ValueError("finding must be a dict with a 'type' field")
    if not isinstance(replay_result, dict):
        raise ValueError("replay_result must be a dict")

    out = json.loads(json.dumps(finding))  # deep copy
    out.setdefault("evidence", {})
    ftype = out.get("type", "")
    marker = replay_result.get("marker") or DEFAULT_MARKER

    # ---- Shape A: validator-signed bundle --------------------------------
    if replay_result.get("validator") == VALIDATOR_ID:
        replays = [r for r in (replay_result.get("replays") or [])
                   if isinstance(r, dict)]
        control = replay_result.get("control") or None
        spec = replay_result.get("request") or {}

        if not replays or all(r.get("error") for r in replays):
            out["status"] = ST_FALSE_POSITIVE
            out["validation_note"] = "replay failed (request could not be sent)"
            out["replay_count"] = len(replays)
            return out

        matches = []
        for r in replays:
            ctl = control.get("response") if isinstance(control, dict) else None
            matched, reason = match_signal(
                ftype, response_text=r.get("response", ""),
                headers=r.get("headers") or {},
                status_code=r.get("status_code"),
                marker=marker, control_text=ctl)
            matches.append((matched, reason))

        out["evidence"]["request"] = _render_request_line(spec)
        out["evidence"]["response"] = replays[0].get("response", "")[:2000]
        out["evidence"]["tool"] = f"{VALIDATOR_ID}/{VALIDATOR_VERSION}"
        out["evidence"]["status_code"] = replays[0].get("status_code")
        out["evidence"]["headers"] = replays[0].get("headers") or {}
        # Rule 4: freshness = when WE actually replayed, never a re-stamp
        out["evidence"]["replayed_at"] = replays[0].get("timestamp")
        out["evidence"]["replay_count"] = len(replays)
        out["evidence"]["response_hash"] = replays[0].get("response_hash")
        if control is not None:
            out["evidence"]["control"] = {
                "url": (replay_result.get("request") or {}).get("control_url") or "",
                "status_code": control.get("status_code"),
                "response_hash": control.get("response_hash"),
            }
        out["replay_count"] = len(replays)
        out["signal_derivation"] = "validator"

        n_matched = sum(1 for m, _ in matches)
        all_matched = n_matched == len(replays) and n_matched > 0

        if not all_matched and n_matched == 0:
            out["status"] = ST_FALSE_POSITIVE
            out["confidence"] = round(float(out.get("confidence", 0.0)) * 0.3, 2)
            out["signal_match_reason"] = matches[0][1]
            out["validation_note"] = f"signal matched 0/{len(replays)} replays"
            return out

        # Rule 2: control must NOT match the signal (specificity)
        if control is not None:
            ctl_matched, ctl_reason = match_signal(
                ftype, response_text=control.get("response", ""),
                headers=control.get("headers") or {},
                status_code=control.get("status_code"), marker=marker)
            if ctl_matched:
                out["status"] = ST_UNVERIFIED
                out["validation_note"] = (
                    "control request ALSO matched the signal — "
                    "response difference is not attributable to the payload")
                return out

        if all_matched and len(replays) >= 2:
            out["status"] = ST_VALIDATED
            out["reproducible"] = True
            base = float(out.get("confidence", 0.0))
            out["confidence"] = round(max(base, 0.85), 2)
            out["validation_note"] = (
                f"validator replayed {len(replays)}x, signal matched every "
                "replay" + (", control clean" if control else ""))
        else:
            out["status"] = ST_UNVERIFIED
            out["validation_note"] = (
                f"signal matched {n_matched}/{len(replays)} replays — "
                "needs >= 2 consistent matches to validate")
        return out

    # ---- Shape B: legacy caller-provided evidence -------------------------
    request = str(replay_result.get("request", "") or "")
    response = str(replay_result.get("response", "") or "")
    tool = replay_result.get("tool", finding.get("evidence", {}).get("tool", ""))
    headers = replay_result.get("headers") or {}
    status_code = replay_result.get("status_code")
    response_time_ms = replay_result.get("response_time_ms")

    if not all([request, response, tool]):
        out["status"] = ST_FALSE_POSITIVE
        out["confidence"] = 0.0
        out["reproducible"] = False
        out["validation_note"] = "evidence incomplete (request/response/tool); auto-FP"
        return out

    # Rule 3: derivation is ALWAYS ours; a caller-supplied signal_matched
    # is deliberately ignored (self-attested verdicts were trivially forgeable).
    signal_matched, reason = match_signal(
        ftype, response_text=response, headers=headers,
        status_code=status_code, marker=marker)
    out["signal_derivation"] = "validator-derived (legacy evidence)"
    out["signal_match_reason"] = reason

    # Record what the caller actually gave us (evidence provenance stays
    # theirs; we do not pretend it is fresh — no timestamp re-stamping).
    out["evidence"]["request"] = request
    out["evidence"]["response"] = response[:2000]
    out["evidence"]["tool"] = tool
    if headers:
        out["evidence"]["headers"] = headers
    if status_code is not None:
        out["evidence"]["status_code"] = status_code
    if response_time_ms is not None:
        out["evidence"]["response_time_ms"] = response_time_ms

    if not signal_matched:
        out["status"] = ST_FALSE_POSITIVE
        out["confidence"] = round(float(out.get("confidence", 0.0)) * 0.3, 2)
        out["reproducible"] = False
        out["validation_note"] = "signal not matched on provided evidence"
        return out

    # Signal matched — but without validator replays this stays a LEAD
    # (rule 1 + rule 5): never auto-promote to validated.
    out["status"] = ST_UNVERIFIED
    out["validation_note"] = (
        "signal matched on provided evidence, but only validator-signed "
        "replays (perform_replay) can reach 'validated' — treat as lead")
    return out


def validate_batch(findings: list, replay_results: Any) -> dict:
    """Validate a batch of findings against their replay results.

    replay_results may be:
      - a list aligned 1:1 with `findings`, or
      - a dict keyed by finding id (findings without a matching entry are
        returned with status 'skipped' and reason 'no replay result').

    Returns {"validated": [...], "unverified": [...], "false_positive": [...],
             "skipped": [...], "summary": {...}}.
    """
    validated: list[dict] = []
    unverified: list[dict] = []
    false_positive: list[dict] = []
    skipped: list[dict] = []

    if isinstance(replay_results, dict):
        replay_map: dict[str, dict] = replay_results
        pairs = [(f, replay_map.get(f.get("id", ""))) for f in findings]
    elif isinstance(replay_results, list):
        pairs = list(zip(findings, replay_results))
        if len(findings) > len(replay_results):
            pairs.extend((f, None) for f in findings[len(replay_results):])
    else:
        raise ValueError("replay_results must be a list or a dict keyed by finding id")

    for finding, replay in pairs:
        if not isinstance(finding, dict):
            skipped.append({"finding": finding, "reason": "not a dict"})
            continue
        if not replay:
            entry = json.loads(json.dumps(finding))
            entry["status"] = ST_SKIPPED
            entry["validation_note"] = "no replay result provided"
            skipped.append(entry)
            continue
        result = validate(finding, replay)
        if result["status"] == ST_VALIDATED:
            validated.append(result)
        elif result["status"] == ST_UNVERIFIED:
            unverified.append(result)
        elif result["status"] == ST_FALSE_POSITIVE:
            false_positive.append(result)
        else:
            skipped.append(result)

    return {
        "validated": validated,
        "unverified": unverified,
        "false_positive": false_positive,
        "skipped": skipped,
        "unverified_leads": [
            {"id": f.get("id", ""), "type": f.get("type", ""),
             "target": f.get("target", ""), "reason": f.get("validation_note", "")}
            for f in unverified
        ],
        "summary": {
            "total": len(findings),
            "validated": len(validated),
            "unverified": len(unverified),
            "false_positive": len(false_positive),
            "skipped": len(skipped),
        },
    }


def _load(path: str) -> Any:
    return load_json(path)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Finding validator (real replay + Reproducibility Gate)")
    ap.add_argument("--finding", help="Finding JSON path or '-' (single mode)")
    ap.add_argument("--replay-request",
                    help="Request spec JSON (url/method/headers/body/replays/"
                         "control_url) — actually sends the requests, then "
                         "classifies. This is the path to 'validated'.")
    ap.add_argument("--header", "-H", action="append", default=[],
                    metavar="NAME: VALUE",
                    help="Extra header for replay requests (auth/session), repeatable")
    ap.add_argument("--proxy", default=None, help="HTTP(S) proxy for replay traffic")
    ap.add_argument("--rate-limit", type=float, default=3.0,
                    help="Replay requests per second (default 3)")
    ap.add_argument("--replay", help="Legacy: caller-provided replay evidence JSON "
                                     "(capped at 'unverified')")
    ap.add_argument("--batch", help="Findings JSON array path or '-' (batch mode)")
    ap.add_argument("--replays", help="Replay results list/dict path or '-' (batch mode)")
    args = ap.parse_args()

    try:
        if args.batch:
            if not args.replays:
                print("finding_validator: --batch requires --replays", file=sys.stderr)
                return 2
            findings = _load(args.batch)
            replays = _load(args.replays)
            if not isinstance(findings, list):
                print("finding_validator: --batch input must be a JSON array", file=sys.stderr)
                return 2
            result = validate_batch(findings, replays)
            print(dump_json(result))
            return 0 if result["summary"]["validated"] > 0 else 1

        if not args.finding:
            print("finding_validator: provide --finding with --replay-request "
                  "or --replay, or --batch/--replays", file=sys.stderr)
            return 2
        finding = _load(args.finding)

        headers_extra: dict[str, str] = {}
        for h in args.header or []:
            name, _, value = h.partition(":")
            headers_extra[name.strip()] = value.strip()

        if args.replay_request:
            spec = _load(args.replay_request)
            bundle = perform_replay(spec, headers_extra=headers_extra,
                                    proxy=args.proxy, rate_limit=args.rate_limit)
            result = validate(finding, bundle)
        else:
            if not args.replay:
                print("finding_validator: provide --replay-request or --replay",
                      file=sys.stderr)
                return 2
            replay = _load(args.replay)
            result = validate(finding, replay)
    except (OSError, json.JSONDecodeError, ValueError) as e:
        print(f"finding_validator: input error: {e}", file=sys.stderr)
        return 2

    print(dump_json(result))
    return 0 if result["status"] == ST_VALIDATED else 1


if __name__ == "__main__":
    sys.exit(main())
