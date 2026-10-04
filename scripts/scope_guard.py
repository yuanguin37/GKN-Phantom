#!/usr/bin/env python3
"""Scope Guard for the GKN-Phantom Penetration Testing Skill.

Validates every target (and optionally every concrete request URL) against the
AgentContext scope. Used at the SCOPE_CHECK state of the skill state machine.

Rules (see references/safety_policy.md §2):
  - domain match: host equals or is a subdomain of a scope.domains entry.
    Entries starting with "*." allow any subdomain; otherwise exact match.
  - ip range match: every resolved IP must fall inside one of scope.ip_ranges
    (CIDR). A host resolving to several IPs passes only when ALL of them are
    in range (a mixed result would let requests leave the authorized range).
    Set "allow_partial_ip_match": true to relax to "at least one IP in range"
    for CDN-fronted targets. When ip_ranges is absent entirely, the scope file
    must set "allow_any_ip": true explicitly — silent pass-on-missing is a
    misconfiguration, not a decision.
  - private network guard: when authorization is domain-only (allow_any_ip),
    a host that resolves to loopback / RFC1918 / link-local is rejected unless
    "allow_private_ips": true — that pattern is the classic DNS-rebinding ->
    SSRF pivot, not a normal authorization.
  - path allowlist: path starts with one of scope.allowed_paths (empty => all).
  - path blocklist: path matches any scope.blocked_paths entry => reject.

Scope config is validated up front (validate_scope): malformed CIDR entries
are configuration errors (exit 2), never silently skipped.

Exit codes:
  0  all targets in scope
  1  one or more targets out of scope / unresolvable (offenders printed to
     stderr; DNS resolution failure is reported as dns_resolution_failed so it
     is never confused with a scope violation, but it still fails closed)
  2  input error / malformed scope config

Usage:
  python scope_guard.py --context ctx.json
  cat ctx.json | python scope_guard.py --context -
  python scope_guard.py --url https://staging.example.test/api/x --context ctx.json

Library use:
  from scope_guard import check_target, validate_scope
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from urllib.parse import urlparse

# Allow `python scope_guard.py` from anywhere: prepend this script's dir so
# `import utils` works.
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from utils import load_json, resolve_ips


def _match_domain(host: str, pattern: str) -> bool:
    host = host.lower().rstrip(".")
    pattern = pattern.lower().rstrip(".")
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return host == suffix or host.endswith("." + suffix)
    return host == pattern


def _match_path(path: str, allowed: list[str], blocked: list[str]) -> bool:
    if blocked:
        for b in blocked:
            if path == b or path.startswith(b.rstrip("/") + "/"):
                return False
    if not allowed:
        return True
    for a in allowed:
        if path == a or path.startswith(a.rstrip("/") + "/") or a == "/":
            return True
    return False


# _resolve removed — now uses utils.resolve_ips() (with timeout + cache)
_resolve = resolve_ips


def _ip_in_ranges(ip: str, ranges: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for r in ranges:
        try:
            if addr in ipaddress.ip_network(r, strict=False):
                return True
        except ValueError:
            continue
    return False


def _is_private_ip(ip: str) -> bool:
    """Loopback / RFC1918 / link-local / unique-local / unspecified."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_unspecified
        or addr.is_reserved
    )


def validate_scope(scope: dict) -> list[str]:
    """Validate scope config at load time. Returns a list of human-readable
    errors; empty list means the scope is usable.

    Malformed CIDR entries must surface HERE (exit 2), not be skipped mid-check:
    a silently dropped ip_range silently widens the authorization.
    """
    errors: list[str] = []
    domains = scope.get("domains") or []
    ip_ranges = scope.get("ip_ranges") or []
    allow_any_ip = bool(scope.get("allow_any_ip"))

    if not domains and not ip_ranges and not allow_any_ip:
        errors.append("scope must define domains and/or ip_ranges (or allow_any_ip: true)")
    if not domains and allow_any_ip and not ip_ranges:
        errors.append("allow_any_ip without domains would authorize every host on earth; "
                      "it may only relax the IP dimension of a domain-scoped authorization")

    for r in ip_ranges:
        try:
            net = ipaddress.ip_network(r, strict=False)
        except (ValueError, TypeError):
            errors.append(f"ip_ranges entry {r!r} is not a valid CIDR (e.g. '10.0.0.0/24')")
            continue
        # A bare address is legal as /32 or /128 but usually a typo for a range.
        if "/" not in str(r):
            errors.append(f"ip_ranges entry {r!r} is a bare address, not CIDR "
                          f"(did you mean {net.with_prefixlen()}?)")

    for key in ("allowed_paths", "blocked_paths"):
        val = scope.get(key) or []
        if not isinstance(val, list) or any(not isinstance(p, str) for p in val):
            errors.append(f"scope.{key} must be a list of path strings")
    if not isinstance(domains, list) or any(not isinstance(d, str) for d in domains):
        errors.append("scope.domains must be a list of domain strings")

    return errors


def check_target(target: str, scope: dict) -> tuple[bool, str]:
    """Return (in_scope, reason). reason is empty when in_scope=True."""
    parsed = urlparse(target if "://" in target else "http://" + target)
    host = parsed.hostname or ""
    path = parsed.path or "/"

    domains = scope.get("domains", [])
    ip_ranges = scope.get("ip_ranges", [])
    allow_any_ip = bool(scope.get("allow_any_ip"))
    allow_private = bool(scope.get("allow_private_ips"))
    allow_partial = bool(scope.get("allow_partial_ip_match"))
    allowed_paths = scope.get("allowed_paths", [])
    blocked_paths = scope.get("blocked_paths", [])

    # Domain match
    if domains and not any(_match_domain(host, d) for d in domains):
        return False, f"host '{host}' does not match any scope domain"

    # Resolve. Attribution matters: "cannot resolve" is an infrastructure
    # condition, not a scope violation — but both fail closed.
    if not host:
        return False, "target has no hostname"
    ips = _resolve(host)
    if not ips:
        return False, f"dns_resolution_failed: could not resolve host '{host}'"

    if ip_ranges:
        matched = [ip for ip in ips if _ip_in_ranges(ip, ip_ranges)]
        if allow_partial:
            ok = bool(matched)
        else:
            ok = len(matched) == len(ips)
        if not ok:
            return False, (f"host '{host}' resolved to {', '.join(ips)} which is not "
                           f"fully inside scope ip_ranges")
    else:
        # Domain-only authorization: explicit allow_any_ip was validated at
        # load time. Guard the DNS-rebinding -> SSRF pivot: a scoped domain
        # resolving to loopback/private space is not a normal topology.
        if not allow_private and any(_is_private_ip(ip) for ip in ips):
            return False, (f"host '{host}' resolves to private/loopback address "
                           f"({', '.join(ips)}); set allow_private_ips: true if this is intended")

    # Path match
    if not _match_path(path, allowed_paths, blocked_paths):
        return False, f"path '{path}' rejected by allowed/blocked path lists"

    return True, ""


def run(targets: list[str], scope: dict) -> tuple[bool, list[str]]:
    offenders: list[str] = []
    for t in targets:
        ok, reason = check_target(t, scope)
        if not ok:
            offenders.append(f"{t}: {reason}")
    return (len(offenders) == 0), offenders


def _load_context(path: str) -> dict:
    return load_json(path)


def main() -> int:
    ap = argparse.ArgumentParser(description="GKN-Phantom scope guard")
    ap.add_argument("--context", required=True, help="Path to AgentContext JSON, or '-' for stdin")
    ap.add_argument("--url", help="Optional single URL to check instead of ctx.targets")
    args = ap.parse_args()

    try:
        ctx = _load_context(args.context)
    except (OSError, json.JSONDecodeError) as e:
        print(f"scope_guard: input error: {e}", file=sys.stderr)
        return 2

    scope = ctx.get("scope", {})
    errors = validate_scope(scope)
    if errors:
        print(json.dumps({"ok": False, "config_errors": errors}), file=sys.stderr)
        return 2

    targets = [args.url] if args.url else ctx.get("targets", [])
    if not targets:
        print("scope_guard: no targets to check", file=sys.stderr)
        return 2

    ok, offenders = run(targets, scope)
    if ok:
        print(json.dumps({"ok": True, "checked": len(targets)}))
        return 0
    print(json.dumps({"ok": False, "offenders": offenders}), file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
