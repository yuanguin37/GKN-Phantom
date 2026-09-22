---
name: gkn-phantom
version: 5.11.0
description: GKN-Phantom — production-grade automated penetration testing and security validation skill. v5.5 rebuilds the multi-pattern matching hot paths on a Trie/Aho-Corasick engine (pattern_matcher.py): tech fingerprinting, WAF detection, JS secret/sink scanning, DB error fingerprinting, and HTML tech detection now run one AC pass per response and execute only the regexes whose required literals are present — provably identical results; the gate pays off as pattern count and body size grow, while small pattern sets on short bodies fall back to naive evaluation, which is faster there. v5.6 adds the cross-session clue board (clueboard.py: one Markdown board per target holding open assumptions, falsified leads, recovered keys and coverage) and the submission layer (report_docx.py: layered verification gate + SRC/CNVD DOCX with Step-style PoC, mandatory real screenshots and semantic naming), so analyst judgement survives context compression and validated findings become platform-ready reports. v5.3 completes the Quick Combat impact chain: quick detect (nuclei + built-in probes) → content-aware severity escalation (v5.2) → deep-dive adapters proving impact from exposed content (Actuator/GraphQL/Swagger, v5.3 C1) → parameter discovery with bounded error-based SQLi/SSTI probing (v5.3 C2) → auto PoC generation → auto exploit generation → bundled combat report. Retains v5 capabilities including interactive browser agent (Playwright), HTML/PDF visualization reports, YAML rule configuration with hot-reload, covering 38 vulnerability types, 25+ WAF fingerprints, and 20+ attack chain patterns across 39 modules. v5.8-v5.11 extend coverage beyond the web into four knowledge domains, each shipped as a handbook plus a rule file plus its own type gates: AI/LLM application security (prompt injection is judged by a behaviour delta reproduced at least three times against a control request; agent tool abuse requires landed evidence, because a model claiming it executed something is never evidence), mini program security (package recovery through cloud development authorisation bypass, keeping the same A/B cross-proof bar for API IDOR as the web), Android component auditing plus APK reversing (scripts/apk_recon.py — a pure-standard-library binary AXML parser that emits a component matrix with export-risk classification, hardening fingerprints and secret/endpoint triage in seconds — with a no-Frida/no-root degraded path), and Windows PE reversing (a crash must be proven controllable and a hijack proven loaded, all dynamic work in an isolated VM). v5.8-v5.11 add Chinese trigger phrases for these domains: AI应用安全, 提示词注入, 大模型安全, 小程序, 云开发, 越权, APK, 安卓, 导出组件, 逆向, 样本分析, DLL劫持. Trigger phrases include 渗透测试, 打点, 漏洞挖掘, 授权测试, 安全审计, 漏洞扫描, 安全验证, 越权测试, 业务逻辑漏洞, 并发竞态, 出报告, 提交稿, 线索板, and their English equivalents (penetration test, pentest, security audit, vulnerability scan, security validation, IDOR, business logic flaw, race condition, report). v5.7 adds three layers: the discipline layer (AGENTS.md — ten execution disciplines, coverage self-check, the Level 1-7 escalation ladder with "never conclude 'no vulnerability' before Level 4", cross-interface five questions); the business-logic methodology layer (business_logic.py — five-question state-machine modelling, role matrix, A/B cross-proof for IDOR, rate-bounded race-replay planning, evidence adjudication aligned with the report gate); and a trigger→module routing table plus Chinese trigger phrases and a conclusion-first output skeleton.
---

# GKN-Phantom — Penetration Testing Skill

## Overview

Execute automated, authorized penetration testing and security validation in
staging / dev / internal / lab environments. v5.6 adds the two layers that sit
outside the scan pipeline itself: a **cross-session clue board**
(`scripts/clueboard.py`) so analyst judgement survives context compression, and
a **submission layer** (`scripts/report_docx.py`) that gates findings through
six hard verification gates and emits platform-ready DOCX reports. v5.7 adds
the three layers that make the output trustworthy rather than merely complete:
a **discipline layer** (`AGENTS.md` — ten execution disciplines, coverage
self-check, the Level 1-7 escalation ladder, cross-interface five questions),
a **business-logic methodology layer** (`scripts/business_logic.py` — five-question
state-machine modelling, role matrix, A/B cross-proof for IDOR, rate-bounded
race-replay planning, and evidence adjudication whose pass bar matches the
report gate), and a **trigger → module routing table** plus Chinese trigger
phrases and a conclusion-first output skeleton. v5.8–v5.11 extend coverage
beyond the web into **four knowledge domains**, each shipped as a handbook
plus rule file plus type gates: **AI/LLM application security** (v5.8 —
prompt injection, indirect injection, system prompt leak, jailbreak, data
exposure, RAG poisoning, memory poisoning, agent tool abuse, excessive
agency, sandbox escape, tool-description poisoning, output-side XSS; the
verdict for injection is a behaviour delta reproduced ≥3 times with a control
request, and for tool abuse it is LANDED evidence — a model claiming it ran
something is never evidence); **mini program security** (v5.9 — package
recovery, decompilation, key/endpoint extraction, cloud development
authorisation bypass; API IDOR keeps the same A/B bar as the web); **Android
component auditing plus APK reversing** (v5.10 — `scripts/apk_recon.py` is a
pure-standard-library binary-AXML parser that emits a component matrix with
export-risk classification, hardening fingerprints and secret/endpoint triage
in seconds, backed by `references/android_audit.md` and
`references/apk_reversing.md` with a no-Frida/no-root degraded path); and
**Windows PE reversing** (v5.11 — static structure and packer identification,
isolated-VM dynamic behaviour, memory-corruption and DLL-hijacking location;
a crash must be proven controllable before it counts). v5.1 introduces **Quick Combat Mode**
(`scripts/quick_combat.py`): a streamlined pipeline that runs a fast nuclei scan
(with scope limits preventing timeout), 7 built-in quick probes, then auto-
generates PoCs (curl/Python/HAR) and exploit scripts (functional Python) —
bundling everything into a timestamped combat report with HTML index. This
replaces the elaborate tiered detection plan approach with a practical
detect → PoC → exploit workflow, informed by real combat feedback. v5.4 adds
five combat layers on top: a domestic OA/component probe library (泛微/致远/
通达/用友/禅道/JeecgBoot/若依/...), a full-site katana crawl feeding parameter
probes, JS bundle mining with hidden-endpoint chaining, a real out-of-band
channel (interactsh/ceye/dnslog) that validates blind SSRF via callback, and
a cross-run combat memory that marks `[已提交]/[重复]` findings to avoid SRC
duplicate submissions. v5.5 adds a **pattern matching engine**
(`scripts/pattern_matcher.py`): the multi-literal matching hot paths —
technology fingerprinting, WAF detection, JS secret/sink scanning, DB error
fingerprinting, HTML tech detection — are now evaluated through a
Trie/Aho-Corasick gate that reads each response once and runs only the
regexes whose required literals are actually present. Results are provably
identical to the previous per-pattern scans (property-tested against naive
iteration). The gate pays off as the pattern set and body size grow; with few
patterns on short bodies the naive path is faster and is kept automatically
(measured at 0.73x for 8 patterns on a 60KB body).

The skill still supports the full state-machine pipeline for deep audits:
scope check → pre-flight → reconnaissance → auth setup → active testing →
validation → attack path analysis → report generation. 38 vulnerability types
across 4 severity tiers, 25+ WAF fingerprints, and 20+ attack chain patterns.
Every action passes through a Scope Guard, Risk Gate, and Rate Limiter; every
finding carries reproducible evidence. A hard **Reproducibility Gate**
(see below) guarantees that only live-replayed, control-compared findings
reach the report — theoretical or assumed vulnerabilities are quarantined
as `unverified_leads` and never reported as vulnerabilities.

> **Safety Disclaimer**: This skill is restricted to authorized security
> testing, internal security audits, and staging/dev/lab environment
> verification ONLY. It MUST NOT be used against unauthorized systems, real
> internet targets, or for data theft / destruction. See
> `references/safety_policy.md`.

## System Dependencies (Linux / Kali / CentOS)

GKN-Phantom scripts require **Python 3.10+** (standard library only —
no pip packages). The agent's `runShell` tool delegates to OS-level
utilities for recon. Ensure the following are in `PATH` before use:

### Required

| Package | Required by | Kali (apt) | CentOS / RHEL (yum/dnf) |
| ------- | ----------- | ---------- | ----------------------- |
| `python3` (≥3.10) | all scripts | `python3` (pre-installed) | `dnf install python3` |
| `nmap` | ACTIVE_RECON port scanning | `nmap` (pre-installed) | `dnf install nmap` |

### Optional — Automated Detection & Graceful Fallback

GKN-Phantom v4.0 auto-detects these tools and uses them when available,
falling back to pure-Python built-in implementations when absent.
Installing them unlocks deeper scanning capabilities:

| Package | Unlocks | Kali (apt) | Manual Install |
| ------- | ------- | ---------- | -------------- |
| `nuclei` | Template-based CVE scanning (nuclei_runner.py) | `apt install nuclei` | `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| `subfinder` | Active subdomain brute-force | `apt install subfinder` | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| `httpx` | Live host probing + tech stack fingerprinting | `apt install httpx` | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| `ffuf` | High-speed directory fuzzing | `apt install ffuf` | `go install github.com/ffuf/ffuf/v2@latest` |
| `amass` | Deep DNS/subdomain enumeration | `apt install amass` | `go install -v github.com/owasp-amass/amass/v4/...@master` |
| `katana` | JS crawling & endpoint discovery | `apt install katana` | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| `naabu` | Fast port scanning (nmap alternative) | `apt install naabu` | `go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` |

For minimal CentOS / Docker environments, also ensure `ca-certificates`
is installed for TLS validation during HTTP fingerprinting.

**Note:** All optional tools have pure-Python fallbacks in the v4.0
modules. `passive_recon.py` handles subdomain discovery via crt.sh/DNS;
`directory_fuzzer.py` provides rate-limited built-in fuzzing;
`tech_fingerprint.py` does header/body-based detection without httpx;
`nuclei_runner.py` generates a manual scanning guide when nuclei is absent.

## When To Use This Skill

Use this skill when ANY of the following apply:

- A user requests a penetration test, security audit, or vulnerability scan of
  an asset they are explicitly authorized to test.
- A CI/CD pipeline needs security validation with SARIF-like JSON output.
- A security engineer wants reproducible, evidence-backed findings with attack
  path analysis.
- An agent needs to verify that targets are in-scope before any probing.

Also match these Chinese trigger phrases directly (see the bilingual section
below): 渗透测试 / 打点 / 漏洞挖掘 / 授权测试 / 安全审计 / 漏洞扫描 / 安全验证 /
越权 / 业务逻辑漏洞 / 并发竞态 / 出报告 / 提交稿 / 线索板.

Do NOT use this skill when:

- The user cannot confirm written authorization for the target.
- The target is a production system without an explicit testing window.
- The request is for raw socket exploitation or destructive payload execution.

## Skill Contract (Interface)

The skill conforms to the OpenClaw Skill interface:

```ts
interface Skill {
  name: string;                 // "gkn-phantom"
  version: string;              // "5.6.0"
  description: string;
  inputSchema: object;          // see references/data_schemas.md -> InputSchema
  outputSchema: object;         // see references/data_schemas.md -> OutputSchema
  execute(ctx: AgentContext): Promise<SkillResult>;
}
```

`AgentContext` fields consumed by this skill:

| Field        | Purpose                                                      |
| ------------ | ----------------------------------------------------------- |
| `scope`      | `domains`, `ip_ranges`, `allowed_paths`, `blocked_paths`   |
| `targets`    | List of target URLs / IPs / hosts to test                   |
| `credentials`| Optional cookies / tokens for authenticated testing (L3)    |
| `config`     | `rate_limit_rps` (default 3), `safe_mode` (default true), `require_human_approval` (default true) |
| `tools`      | `runShell`, `httpRequest`, `browser`, `logger`              |
| `state`      | Persisted state-machine scratch area                        |
| `memory`     | Cross-run memory for dedup / trending                      |

## Execution State Machine

The skill MUST execute as a deterministic state machine. Transition to the next
state only after the current state's exit criteria are met. Persist
`state.current` and `state.history` in `ctx.state` so runs are resumable and
auditable.

```
INIT
  ↓
SCOPE_CHECK            ── fail ──► ABORT (no target leaves scope)
  ↓
PRE_FLIGHT (v2)        ── dry-run + risk score + scope narrowing
  ↓
PASSIVE_RECON (v4)     ── crt.sh / DNS / WHOIS / OSINT (zero-touch)
  ↓
ACTIVE_RECON (v4)      ── nmap + directory fuzzing + tech fingerprint + SSL analysis
  ↓
AUTH_SETUP (optional)  ── skip if credentials empty ──► ACTIVE_TESTING
  ↓
ACTIVE_TESTING         ── adaptive engine + 12 specialized modules (JS/CVE/API/Cloud/SQLi/WAF/Nuclei/etc.)
  ↓
VALIDATION             ── confidence scoring + CVE correlation
  ↓
ATTACK_PATH_ANALYSIS   ── v3: 20+ attack chain patterns
  ↓
REPORT_GENERATION
  ↓
DONE
```

### State-by-state procedure

1. **INIT** — Validate `inputSchema`, load config defaults, initialize
   `state`, seed `memory` from prior runs for dedup. Log the run id.

2. **SCOPE_CHECK** — Run `scripts/scope_guard.py` against every target in
   `ctx.targets`. A target is in-scope only if it matches a `scope.domains`
   entry AND an `scope.ip_ranges` entry AND its path is in
   `scope.allowed_paths` and NOT in `scope.blocked_paths`. If ANY target is
   out of scope, ABORT the entire run and return an error result listing the
   offending targets. Never proceed with partial scope.

3. **PRE_FLIGHT** (v2 NEW) — Run `scripts/safety_simulator.py` BEFORE any
   active probing. Three sub-steps:
   - **dry-run**: simulate the detection plan without network calls. Emit
     `safety_verdict` (SAFE_TO_PROCEED / REQUIRES_HUMAN_APPROVAL / CAUTION).
     If verdict is REQUIRES_HUMAN_APPROVAL and `config.require_human_approval`
     is true, pause for approval before proceeding.
   - **target risk scoring**: score each target 0–100 based on environment,
     open ports, sensitive paths, and risky technologies. Targets scoring ≥80
     are marked `require_approval`.
   - **automatic scope narrowing**: if any target is critical-risk, augment
     `scope.blocked_paths` with dangerous paths (`/admin/delete`,
     `/actuator/shutdown`, etc.) to reduce blast radius.
   - Output: `pre_flight_report` with verdict, risk scores, narrowed scope.

4. **PASSIVE_RECON** (v4 NEW, L1 — zero-touch) — Run `scripts/passive_recon.py`
   for each target domain. Collect intelligence without sending a single packet
   to the target:
   - **Certificate Transparency (crt.sh)**: enumerate subdomains from TLS certs.
   - **DNS enumeration**: A/AAAA/CNAME/MX/NS/TXT/SOA records via built-in DNS
     client (pure Python, no external deps).
   - **WHOIS lookup**: registrar, dates, name servers via IANA referral chain.
   - **Technology stack detection**: analyze HTTP headers + HTML body for
     server/framework/CMS/CDN/JS library signatures.
   - **Wayback Machine**: discover historical URLs from archive.org.
   - **GitHub dorking**: generate search queries for exposed secrets/configs.
   - **Email pattern enumeration**: discover organizational email formats.
   - Output: `passive_recon_result` with subdomains, dns_records, whois,
     technologies, wayback_urls, github_dorks, emails.
   This phase is entirely passive — no packets sent to the target.

5. **ACTIVE_RECON** (v4 EXPANDED, L1–L2) — Active asset discovery:
   - **Port scanning** (nmap): `nmap -sT --top-ports 100` or equivalent.
     Auto-detects naabu for faster scanning if available.
     Only in-scope IPs; respect rate limit.
   - **SSL/TLS analysis** (v4 NEW): Run `scripts/ssl_analyzer.py` on each
     HTTPS target. Certificate chain analysis, cipher suite grading (A+–F),
     protocol version detection (SSLv2–TLS 1.3), vulnerability checks
     (POODLE/BEAST/CRIME/FREAK/Logjam/DROWN/Heartbleed), HSTS analysis.
   - **Technology fingerprinting** (v4 NEW): Run `scripts/tech_fingerprint.py`
     for deep tech stack detection: 30+ server patterns, 17 language/framework
     patterns, 26 meta generator tags, 19 favicon hashes, 20 error page
     signatures, 25 CDN/WAF header patterns, 12 database error patterns.
     Auto-detects httpx and uses it if available for faster probing.
   - **Directory fuzzing** (v4 NEW): Run `scripts/directory_fuzzer.py` with
     10 curated wordlist categories (116 paths: general/admin/backup/api/
     config/upload/logs/exposed/shell/backend_tech) + 20 extensions.
     Custom 404 page detection, recursive discovery, technology-aware
     prioritization. Auto-detects ffuf and uses it if available.
   - **HTTP fingerprinting** (headers, server, technologies) via `httpRequest`.
   - **Endpoint discovery** (robots.txt, sitemap.xml, common wordlists).
   - Output: expanded `assets` object `{ domains, ips, endpoints, ssl_report,
     tech_stack, discovered_dirs }`.

6. **AUTH_SETUP** (optional, L3) — Only when `ctx.credentials` is non-empty and
   the user explicitly enabled authenticated testing. Supported methods:
   cookie injection, bearer token injection, browser-driven login session,
   session persistence into `ctx.state.session_ref`. After setup, verify the
   session is authenticated by hitting an identity endpoint; record
   `authenticated: true/false`.

7. **ACTIVE_TESTING** (L2–L3, L4 requires human approval) — Run the
   Vulnerability Engine via `scripts/vuln_detector.py`, which generates a
   severity-tiered detection plan from the recon assets. Execute the plan
   tier-by-tier (low → medium → high → critical), routing every probe through
   `scope_guard` + `rate_limiter`. The detection tiers and their types are
   defined in `references/payload_playbook.md` and `references/advanced_payload_playbook.md` (v3 NEW), and baselined in
   `references/data_schemas.md` (type→severity table):

   - **LOW** — `info_leak`, `open_redirect`, `csrf` (weak/missing token),
     `misconfig` (security headers / verbose banners),
     `component_exposure` (Actuator/Druid/Swagger/UEditor 未授权访问检测),
     `graphql_introspection` (v3 NEW: GraphQL schema disclosure),
     `directory_listing` (v3 NEW: directory listing exposure).
     Non-destructive, L1–L2.
   - **MEDIUM** — `xss` (reflected), `path_traversal` (read-only),
     `xxe` (OOB to authorized sink only), `ssti` (arithmetic reflection),
     `deserialization` (innocuous + malformed probe, NO gadget chains),
     `command_injection` (time-based only, capped),
     `weak_credential` (弱口令/默认凭据，bounded set，来源152份真实SRC报告),
     `captcha_bypass` (验证码绕过：空值/删除/万能码/复用/返回包篡改),
     `crlf_injection` (v3 NEW: CRLF / HTTP response splitting),
     `cors_misconfig` (v3 NEW: CORS misconfiguration),
     `subdomain_takeover` (v3 NEW: dangling DNS takeover),
     `host_header_injection` (v3 NEW: host header poisoning),
     `websocket_hijacking` (v3 NEW: CSWSH),
     `session_fixation` (v3 NEW: session fixation),
     `email_injection` (v3 NEW: email header injection). L2–L3.
   - **HIGH** — `xss` (stored, cross-user), `sqli` (error/boolean/capped
     time-based), `ssrf` (L4, blocked in safe_mode), `idor` (L3 differential,
     含批量ID遍历),
     `file_upload` (文件上传检测：扩展名绕过/Content-Type/UEditor/双后缀，无真实webshell),
     `logic_flaw` (逻辑缺陷：返回包篡改/价格篡改/步骤跳过/短信轰炸/重放),
     `nosql_injection` (v3 NEW: MongoDB/NoSQL injection),
     `ldap_injection` (v3 NEW: LDAP injection),
     `graphql_injection` (v3 NEW: GraphQL batching/DOS/injection),
     `cache_poisoning` (v3 NEW: web cache poisoning),
     `race_condition` (v3 NEW: TOCTOU / race condition),
     `prototype_pollution` (v3 NEW: client/server prototype pollution),
     `jwt_deep_analysis` (v3 NEW: extended JWT attacks),
     `oauth_misconfig` (v3 NEW: OAuth flow misconfig),
     `mass_assignment` (v3 NEW: auto-binding / mass assignment),
     `dependency_confusion` (v3 NEW: supply chain dependency confusion).
   - **CRITICAL** — `rce` (L4, second independent probe, no exfil, blocked in
     safe_mode), `auth_bypass` (default-cred / JWT alg:none / reset-token
     predictability), `priv_esc` (vertical, role-claim flip),
     `data_exposure` (PII regex thresholds — UPGRADES an existing validated
     finding to critical), `http_smuggling` (v3 NEW: HTTP request smuggling).

   Methods: tool-based scanning (nuclei-like templates via `runShell`),
   heuristic probing via `httpRequest`, LLM-assisted reasoning (safe mode
   only) for classification and safe payload suggestion. Each candidate
   finding is emitted in the standard Finding schema with its `tier` and
   baseline `severity`; `data_exposure` is applied as a post-validation
   upgrade via `vuln_detector.classify_data_exposure()`.

   **Adaptive Engine (v3 ENHANCED)**: When a probe fails or is WAF-blocked, the
   agent invokes `scripts/adaptive_engine.py` to build an adaptive plan:
   - **retry with backoff**: transient errors (timeout, connection reset) →
     exponential backoff (500ms, 1s, 2s, 4s, 8s capped).
   - **payload mutation**: WAF detected (25+ types: Cloudflare/Akamai/AWS/Imperva/
     F5/FortiWeb/Barracuda/Sucuri/Radware/ModSecurity/NAXSI/Wallarm/Wordfence/
     安全狗/云盾/腾讯云WAF/深信服/长亭雷池/启明星辰/绿盟/山石/天融信/华为云WAF/
     百度云加速/Cloudbric) → generate 5-12 mutated payload variants (encoding/
     case/comment/unicode/separator/operator bypass) for all 38 vulnerability types.
   - **WAF detection fallback**: identify WAF type from response headers/status/
     body → select type-specific bypass strategy.
   - **alternative probe strategy**: primary signal not matched → try secondary
     signals (20+ signal sets for all vuln types including NoSQL/LDAP/CRLF/SSRF/
     SSTI/XXE/GraphQL/CORS/JWT/OAuth/Smuggling/Cache/Race/Prototype/MassAssign).
   The adaptive plan is recorded in `finding.adaptive_metadata`.

   **v3/v4 Specialized Modules**: In addition to the core vulnerability detector,
   twelve specialized modules are available at ACTIVE_TESTING:
   - `scripts/js_analyzer.py` (v3, v5.4 UPGRADED) — JS static analysis: secrets
     leakage, dangerous sinks (eval/Function/innerHTML), postMessage
     misconfiguration, prototype pollution, weak crypto, debug leaks, DOM
     clobbering; plus `extract_endpoint_entries()` (v5.4) which mines hidden
     hardcoded parameterized API endpoints from bundles — fed into
     `quick_combat.probe_injection()` by the combat pipeline.
   - `scripts/cve_correlator.py` (v3) — CVE correlation: matches discovered
     technologies (nginx, Apache, Tomcat, Spring, Django, etc.) with known CVEs,
     providing CVSS severity, exploit availability, and risk scoring.
   - `scripts/advanced_injection.py` (v3) — Advanced injection engine: specialized
     detection plans for NoSQL, LDAP, CRLF, HTTP smuggling, cache poisoning,
     race conditions, extended SSTI, and XPATH injection.
   - `scripts/api_auditor.py` (v3) — API security auditor: GraphQL introspection
     depth/batching/field-suggestion tests, REST method override/content-type
     confusion, WebSocket origin validation/CSWSH detection.
   - `scripts/cloud_security.py` (v3) — Cloud security scanner: S3 bucket
     permissions, cloud metadata service access, K8s API misconfiguration,
     Docker API exposure, CDN origin IP disclosure, container registry checks.
   - `scripts/advanced_sqli.py` (v4 NEW) — Professional SQL injection engine:
     database fingerprinting (6 engines), error/boolean/time/UNION/OOB extraction,
     second-order SQLi detection, 10 WAF bypass technique categories.
   - `scripts/nuclei_runner.py` (v4 NEW) — Nuclei template scanning integration:
     auto-detects nuclei, builds template index, smart selection (80+ tech-tag
     mappings), execution planning, result parsing, SHA-256 dedup, fallback guide.
   - `scripts/waf_evasion.py` (v4 NEW) — Advanced WAF bypass engine: protocol-level
     evasion, 6 encoding bypass techniques, per-vuln obfuscation (10 SQLi + 10 XSS
     + 7 traversal + 8 cmd-injection), 10 WAF-specific rule sets, HPP, content-type
     switching, all bypass variants with technique descriptions.
   - `scripts/directory_fuzzer.py` (v4 NEW) — Smart directory brute-forcing:
     10 curated wordlist categories (116 paths) + 20 extensions, custom 404
     detection via SimHash, recursive depth, tech-aware prioritization (17 stacks).
   - `scripts/passive_recon.py` (v4 NEW) — Zero-touch intelligence gathering:
     crt.sh subdomain enumeration, built-in DNS client, WHOIS via IANA referral,
     tech detection, Wayback Machine, GitHub secret dorking (15 templates),
     Shodan/Censys integration, email enumeration.
   - `scripts/ssl_analyzer.py` (v4 NEW) — SSL/TLS security analysis: certificate
     chain validation, cipher suite grading (A+–F, 59 ciphers), protocol version
     detection (SSLv2–TLS 1.3), 7 known vulnerability checks, HSTS analysis.
   - `scripts/tech_fingerprint.py` (v4 NEW / v5.5 UPGRADED) — Deep technology stack fingerprinting:
     30+ server, 17 framework, 35+ cookie, 26 meta, 30 JS, 19 favicon hash, 20
     error page, 25 CDN/WAF, 12 DB error + OS detection patterns. All
     body-scanned pattern tables run through the Aho-Corasick prefilter
     (`pattern_matcher.PrefilteredRegexSet`): one pass per response, then
     only the regexes whose required literals are present execute.

   **v5 Add-on Modules** (used at their designated states):
   - `scripts/report_visualizer.py` (v5 NEW) — HTML/PDF visualization report:
     SVG risk score gauge, severity cards, collapsible finding cards with
     syntax-highlighted evidence, pure-SVG attack path graph, sortable asset
     table, remediation priority matrix, dark/light mode, severity filter,
     keyword search, PDF export. Used at REPORT_GENERATION.
   - `scripts/browser_agent.py` (v5 NEW) — Interactive browser agent: Playwright
     auto-detection, multi-step auth workflow (JSON step definitions), captcha
     handling (bypass/manual/OCR), MFA/2FA detection, session persistence
     (JSON/cookie-jar/pickle), JS execution, screenshot capture, proxy support.
     Used at AUTH_SETUP.
   - `scripts/poc_generator.py` (v5 NEW) — Professional PoC generator: 5 formats
     (curl/Python/HAR/Markdown/raw HTTP), vuln-specific templates, safety
     classification (SAFE/CAUTION/DANGEROUS), batch generation, PoC index HTML.
     Used at REPORT_GENERATION.
   - `scripts/rules_loader.py` (v5 NEW) — YAML rule configuration engine: loads
     rules from ../rules/*.yaml, validates schema, hot-reload (mtime watch),
     exports RuleRegistry with get_rules_by_tier/type, backward compatible.
     Used at INIT.
   - `scripts/quick_combat.py` (v5.4) — Streamlined combat
     pipeline with a layered impact chain:
     (1) quick nuclei scan (scope-limited) + 7 built-in probes;
     (2) v5.2 **Impact Escalation Layer** (`escalate_severity()`): quick-probe
     findings re-graded from captured response content — live credentials
     (env-style/AWS key/private key), `.git` config disclosure, phpinfo pages,
     reachable backup archives → **high**; PII/sensitive-content score ≥ 3
     (via `vuln_detector.classify_data_exposure()`, same threshold as the
     full state machine) → **critical**. Every escalation records
     `severity_escalated_from` + `escalation_reason`;
     (3) v5.3 **Deep-Dive Adapters** (Phase 2.5, `deep_dive()`): routed by
     finding type/path — Actuator (fetch `/actuator/env` + `/configprops`,
     probe `/heapdump` presence; unmasked credentials or heapdump →
     **critical**), GraphQL (full introspection; schema + mutation surface
     exposed unauthenticated → **high**), Swagger (pull OpenAPI spec; no
     security scheme → **high**). Bounded: ≤ 3 requests/finding, 8s timeout,
     GET/POST-introspection only, zero overhead when no probe hits;
     (4) v5.3 **Parameter Discovery + Injection Probing** (Phase 2.6):
     `discover_params()` extracts same-origin URLs with query parameters
     from the entry page (links + JS strings), `probe_injection()` runs
     bounded non-destructive probes — error-based SQLi (3 generic payloads
     matched against all 6 DB engine error signatures from
     `advanced_sqli.DB_FINGERPRINT`) and SSTI arithmetic reflection
     (4 payload variants with baseline differential) — emitting high-severity
     sqli/ssti findings. Cap: 10 param URLs, 5 probed params per target;
     (5) v5.4 **CN Component Probes** (Phase 2.55, `cn_probes.py`): domestic
     OA/component unauthorized-access library (32 probes) — 泛微 e-cology
     (BeanShell servlet, Ssologin.jsp, /services/), 致远 seeyon
     (getSessionList, htmlofficeservlet, wpsAssistServlet), 通达 OA
     (/ispirit/, /module/), 用友 NC (~ic servlets, uapws), 禅道, JeecgBoot
     (jmreport `queryFieldBySql` one-shot SQLi verifier via POST →
     **critical**), 若依 (druid prod-api/dev-api, /system/), 帆软, 亿邮,
     金蝶, 蓝凌, 红帆, 万户. Probes support severity overrides, POST
     one-shot verifiers and `not_patterns` soft-404 blacklists;
     (6) v5.4 **katana Full-Site Crawl** (C3): when the katana binary is in
     PATH, `crawl_katana()` crawls the whole site (depth 3, JSONL) — every
     parameterized URL found anywhere feeds `probe_injection`, so SQLi/SSTi
     coverage goes from "entry page params" to "the whole site". No katana →
     silent fallback to entry-page-only discovery;
     (7) v5.4 **JS Bundle Mining** (C4, `js_analyzer.py`): crawled + entry-page
     JS bundles are analyzed (leaked secrets, dangerous sinks, debug
     endpoints) AND mined for hidden hardcoded endpoints
     (`extract_endpoint_entries()`) which feed back into parameter
     injection probing — JS recon chains into active probing;
     (8) v5.4 **Real OOB Channel** (C5, `oob_client.py`): replaces the
     static `oob.authorized.test` placeholder with a pollable channel —
     interactsh-client binary (self-hosted or oast.fun), ceye.io API, or
     dnslog.cn. Open-redirect probes inject the live callback domain, and
     `probe_blind_ssrf()` fires OOB-tagged callbacks into `url`-style
     params; a confirmed callback emits a **validated** (not "detected")
     blind-SSRF finding — OOB verification unlocks the validated tier for
     blind vulnerability classes;
     (9) v5.4 **Cross-Run Combat Memory** (C6): every run's finding
     fingerprints are persisted to `combat_memory.json`; a re-scan marks
     known findings `[已提交]` (submitted, user-flagged) / `[重复]` (repeat)
     so SRC duplicate submissions are avoided. All v5.4 layers toggleable:
     `--no-deep/--no-cn-probes/--no-crawl/--no-js/--no-memory/--oob-provider`.
     After detection: auto PoC generation and auto exploit generation,
     bundled into a timestamped combat report with HTML index. Entry point
     for Quick Combat Mode.
   - `scripts/exploit_generator.py` (v5.1 NEW) — Functional exploit script
     generator: converts VALIDATED findings only into self-contained Python
     demonstration scripts, organized by severity and type. Refuses findings
     that are not `validated`. Used after VALIDATION.


8. **VALIDATION** — Run `scripts/finding_validator.py`. For each candidate
   finding, (re)execute the PoC LIVE against the target, capture fresh
   request/response/timestamp, and classify into exactly one of three
   outcomes:
   - `validated` (TP) — the PoC succeeded in ≥2 independent live replays
     AND the detection signal differs from the baseline/control response
     (see Reproducibility Gate below) AND `safe_poc` is true.
   - `false_positive` (FP) — the signal was reproduced by the control
     request (no payload), or replays contradict the original signal.
     Discard.
   - `unverified_lead` — the finding cannot be reproduced live right now
     (target unreachable, WAF blocks every variant, requires out-of-scope
     action, or evidence is theoretical/assumed). Move to
     `unverified_leads[]`. NEVER report it as a finding.
   A candidate that cannot pass live replay is NOT a vulnerability — it is
   a lead. Findings promoted on the basis of code reading, version
   inference, scanner output, or LLM reasoning ALONE are forbidden in the
   final report. LLM may assist classification but cannot override evidence.

   **Confidence Scoring (v2 NEW)**: Run `scripts/confidence_scoring.py` on
   each finding. Computes a multi-factor confidence score (0.0–1.0):
   - `evidence_strength` (weight 0.30): completeness of evidence fields
   - `reproducibility_score` (weight 0.30): fraction of replays that matched
   - `signal_clarity` (weight 0.25): how unambiguous the detection signal is
   - `corroboration` (weight 0.15): multiple signals/tools/WAF-bypass agree
   A finding is promoted to `validated` only when `confidence >= 0.80`.
   The breakdown is stored in `finding.confidence_breakdown`.

   **Heuristic Decision Layer (v2.2 REPLACES probabilistic v2.1)**:
   `scripts/decision_engine.py` provides deterministic, explainable
   decisions at key decision points (OPTIONAL PLUGIN — core pipeline
   works without it):
   - **probe continuation**: 5 heuristic rules (A-E) evaluated in order:
     budget exhausted → STOP, low yield early → STOP, discovery_yield ≥ 5% →
     CONTINUE, early stage with budget → CONTINUE, otherwise → STOP.
     All decisions carry a `rule_path` for full auditability.
   - **severity upgrade**: additive scoring (+3.0 PII, +2.5 cross-user,
     +2.0 corroboration, +1.5 reproducibility); upgrade if score ≥ 2.5.
     Deterministic — same finding always yields the same decision.
   - **scope expansion**: 5 sequential gates (Gate1–Gate5) — production
     blocked, risk too high blocked, low chain potential, no findings,
     propose expansion. No probability thresholds, pure rule gating.
   - **heuristic confidence**: deterministic weighted scoring replacing
     the v2.1 Bayesian posterior. Same four factors, additive sum.
   See `references/formal_algorithms.md §5` for the explainable rule
   definitions.

9. **ATTACK_PATH_ANALYSIS** — Run `scripts/attack_path.py`. Combine multiple
   validated findings into chains (v3: 20+ attack chain patterns). Emit a graph
   `{ nodes, edges }` where nodes are findings/assets and edges represent
   exploit relationships. LLM may infer candidate edges; only edges confirmed
   by evidence are marked `confirmed`. New v3 chains include: SSRF→cloud
   metadata, SQLi→credential dumping, IDOR→mass PII exposure, SSTI→RCE,
   XSS→session hijacking, CORS→CSRF→account takeover, cache poisoning→mass
   XSS, prototype pollution→privilege escalation, HTTP smuggling→cache
   poisoning/auth bypass, NoSQL→auth bypass→data exposure, JWT→IDOR, OAuth→
   account takeover, race condition→financial fraud, CRLF→XSS, mass assignment
   →privilege escalation, subdomain takeover→phishing, LDAP→directory
   enumeration, GraphQL→data exposure, XXE→SSRF, deserialization→RCE, and
   more.

10. **REPORT_GENERATION** — Run `scripts/report_generator.py`. Produce:
   - Executive summary (human readable).
   - Technical findings table.
   - Risk score 0–100 (CVSS-like aggregate; see
     `references/safety_policy.md`).
   - Remediation steps per finding.
   - Reproduction steps per finding.
   - CI-friendly SARIF-like JSON (`results` array).
   - Full execution log from `state.history`.

11. **DONE** — Return `SkillResult` matching `outputSchema`. Persist `state`
   and `memory`. Emit final JSON (see `references/data_schemas.md` ->
   FinalOutput).

### Execution State Recovery (v2.1 NEW)

At ANY state transition, if the transition fails (network error, crash,
timeout), the agent invokes `scripts/state_recovery.py` to recover:

- **checkpoint retry**: re-attempt the failed transition with exponential
  backoff (500ms → 1s → 2s), up to 3 attempts. Uses
  `state_recovery.build_retry_plan()`.
- **partial state resume**: for ACTIVE_TESTING / VALIDATION, resume from
  where the run left off — already-probed endpoints are skipped. Uses
  `state_recovery.build_partial_resume_plan()` which reads
  `checkpoint.partial_results.probed_endpoints`.
- **failure rollback**: on catastrophic failure (retries exhausted), roll
  back to the previous SAFE state (INIT/SCOPE_CHECK/PRE_FLIGHT/RECONNAISSANCE)
  and re-attempt with a degraded strategy (e.g., reduced tier). Uses
  `state_recovery.execute_rollback()`. If no safe previous state exists,
  ABORT the run.
- The agent MUST call `state_recovery.save_partial_progress()` periodically
  DURING ACTIVE_TESTING so a crash doesn't lose probed-endpoint state.
  See `references/formal_algorithms.md §6` for the recovery algorithms.

## Safety Model (Mandatory)

The safety model is NON-NEGOTIABLE. See `references/safety_policy.md` for the
full spec. Summary:

- **Scope Guard** — every target, every request, every tool call is checked
  against `ctx.scope` before execution. Out-of-scope ⇒ immediate ABORT.
- **Risk Gate** — every action is classified L1–L4. L4 (destructive /
  privilege / write) REQUIRES human approval when
  `config.require_human_approval` is true (default). In `safe_mode`, L4 is
  blocked entirely.
- **Rate Limit** — default ≤ 3 req/sec with burst control. Over-limit
  requests are QUEUED, never dropped and never crash. Implemented in
  `scripts/rate_limiter.py`.
- **Evidence Requirement** — every finding MUST contain `evidence.request`,
  `evidence.response`, `evidence.timestamp`, `evidence.tool`, and a
  `reproducible` flag. Findings without complete evidence are rejected at
  VALIDATION.

## Reproducibility Gate (Mandatory)

Every finding in the final report MUST be a **reproduced vulnerability**,
never a theoretical or hypothetical one. "The version has a known CVE",
"the parameter looks injectable", "the scanner flagged it" — none of these
is a finding until the impact is demonstrated live. This gate is applied at
VALIDATION and enforced again at REPORT_GENERATION.

### Hard rules

1. **Live replay ≥ 2** — the PoC is executed against the live target at
   least twice by `finding_validator.py`; both replays must reproduce the
   detection signal. One-shot successes do not count.
2. **Baseline / control comparison** — a control request (same endpoint,
   benign or no payload) MUST be captured. The finding is valid only if the
   payload response differs from the control in the expected way (error,
   timing delta, content delta, status change). If the control already
   produces the "signal", the finding is a false positive.
3. **Demonstrated impact, not inferred impact** — each finding must name
   the concrete impact actually observed (data read, file read, delay
   measured, token/session obtained, action performed). Inferring impact
   the target *could* have is forbidden.
4. **Fresh evidence per report** — the request/response pair in
   `evidence` must come from a replay executed during THIS run, not copied
   from a scanner export or a previous session.
5. **Quarantine of unverified candidates** — anything that cannot pass
   rules 1–4 is moved to `unverified_leads[]` with the blocking reason
   recorded. Leads are shown in the report appendix for follow-up but are
   excluded from `findings[]`, the risk score, and the executive summary.

### Banned sources of "findings"

A finding MUST NOT originate solely from:

- Version / CVE correlation without a working exploit path on THIS target
  (cve_correlator output is recon input, not evidence).
- Scanner (nuclei et al.) matches without a successful live replay.
- Source-code reading or LLM reasoning without a live request/response.
- Generic best-practice gaps (missing headers etc.) reported beyond their
  actual demonstrated effect.

### Verification method library

Choose the strongest technique the vulnerability class allows:

| Technique | Use for | Proof standard |
| --- | --- | --- |
| Echo / reflection | RCE, SSTI, XSS, SQLi (error/UNION), path traversal | Payload-controlled value appears in response (arithmetic result, file content, DB banner) |
| Differential (boolean) | Blind SQLi, IDOR, auth bypass | True/False conditions produce measurably different responses across ≥2 replays each |
| Time-based | Blind SQLi, command injection | Response delay ≈ requested sleep, confirmed twice, and control request is fast |
| Out-of-band | SSRF, XXE, blind RCE | DNS/HTTP callback received at an authorized OOB sink tied to a unique per-finding token |
| State change | Stored XSS, CSRF, logic flaws, file upload | Second request confirms the persisted effect (stored content served back, uploaded file reachable, order/balance changed) |
| Session / token proof | Auth bypass, priv-esc, session fixation | A protected resource is actually returned with the forged/fixated/predicted credential |

### Report-facing consequence

For every `validated` finding, the report MUST include: minimal repro
steps, the exact payload, the control-vs-payload evidence pair, replay
count, and the observed impact. If any element is missing, the finding is
downgraded to `unverified_leads[]` — no exceptions.

## Submission & Memory Layers (v5.6)

Two modules close gaps the scan pipeline itself cannot close: what the analyst
remembers between sessions, and what the reviewer receives at the end.

### Clue board — cross-session analyst memory (`clueboard.py`)

`state.py` persists the machine state (phase, history, checkpoint). It does NOT
persist judgement. Before compressing or ending a session, and at the start of
any session that resumes a target, the agent MUST read the board:

- New target → `clueboard.py init --target <T> --focus "..."` then work.
- Resuming → `clueboard.py brief --target <T>` (cheap digest: focus, open
  assumptions, excluded leads, todos, coverage).
- After every conclusion → `add` the assumption / host / path / key, or `cover`
  the coverage block. **A conclusion that is not on the board does not count.**
- Before probing anything → `check --section excluded --text "..."`; exit 1
  means it was already falsified last session. Do not re-test it.

Board rules: state vocabulary is closed (`假设` / `已证伪` / `已证实` / `待打`);
open assumptions are capped at 5; raw material (full JS, unmasked credentials)
goes to `hunts/<target>/raw/`, never on the board.

### Submission gate — what is allowed into a report (`report_docx.py`)

A finding may become a submission DOCX **only** after passing the layered
verification gate. The hard gates are non-negotiable (缺一不报):

| Gate | Requirement |
| --- | --- |
| 硬门0 先证伪 | A negative-control experiment is recorded (`falsification` / `negative_control`) |
| 硬门1 PoC 可复现 | Raw request + response, observable tool (not `llm`/`scanner`/`version`), replayed ≥ 2× |
| 硬门2 危害为链路终局 | Concrete demonstrated impact; no "理论上/could be" wording; `status == validated` |
| 硬门3 服务端边界确认 | Server-side or permission-boundary evidence, not a browser-JS artifact |
| 硬门4 类型命门 | Type-specific key: IDOR → A/B proof; SQLi → `database()`; SSRF → internal echo; upload → getshell/parse; RCE → command output; data leak → ≥3 PII fields |
| 硬门5 链式追问到终局 | Same-root-cause endpoints enumerated, or why stopping is recorded |

Findings that do not pass stay **leads**: they are reported in the gate output
with the blocking reason and MUST NOT be written into a DOCX or counted as
findings. Quality items (cross-environment replay, WAF note) do not block, but
must be stated in the report.

**Screenshot iron rule**: every Step needs a real screenshot taken from the
browser (opening the original URL) or Burp Repeater. Never synthesise, never
replace with prose. The builder reports each missing screenshot as a warning
instead of skipping it silently. Screenshots may be a text-free evidence block
only when the target content provably cannot render in a browser — and the
report must say why.

De-AI wording scan: template connectives, dash-trailing explanations,
adjective hype, and screenshot meta-descriptions are flagged before delivery.

## Execution Discipline (v5.7)

`SKILL.md` defines the **contract** — what the skill can do and must not do.
`AGENTS.md` (repo root) defines the **discipline** — how it must be done.
**Read `AGENTS.md` before the first probe of any session.** It is not advisory:
everything that can be enforced in code already is (see the carrier column).

| # | Discipline | Enforced / supported by |
| --- | --- | --- |
| 一 | JS 不吃透，不发包（先还原前端再动手） | `js_analyzer.py`, `quick_combat.py` JS bundle mining |
| 二 | 覆盖度自检 `✅已测 / ❌未测 / 🔄变种 / 💡关联` | `clueboard.py cover --tested/--untested/--variants/--related` |
| 三 | 漏洞嗅觉（时间/体量/措辞/状态码/字段异常） | 记录即落板，`clueboard.py add` |
| 四 | 业务建模五问（状态机+角色矩阵+非法路径+校验层+并发） | `business_logic.py model / plan / ab / judge` |
| 五 | 失败升级 Level 1-7，**至少到 L4 才能下「无漏洞」结论** | `waf_evasion.py`, `adaptive_engine.py` |
| 六 | 跨接口关联五问（信息流/凭证/状态/权限/时序） | `attack_path.py` |
| 七 | 开发者视角优先测项（新功能/内部接口/旧 API/导出/回调） | 本 skill 的路由表（下节） |
| 八 | 信息收集要脏，**线索当轮落盘**，原始素材进 `raw/` | `clueboard.py`, `passive_recon.py` |
| 九 | 对抗意识（防御在哪层 → 规则 → 边界 → 差异） | `adaptive_engine.detect_waf` |
| 十 | 暂停思考：遇加密签名/权限不明/3 连失败/新攻击面即切专项 | 本 skill 的路由表（下节） |

Non-negotiable hard rules from the discipline layer:

1. **At most 5 open assumptions per target** — close one before opening another.
2. **A conclusion that is not on the clue board does not count.**
3. **Before probing anything**, run `clueboard.py check --section excluded --text "..."`;
   exit 1 means it was already falsified — do not re-test it.
4. **Failure at L1-L3 may only be written as "this payload was filtered"**, never as
   "the vulnerability does not exist".
5. **Scope Guard is not bypassable** by any clause of `AGENTS.md` or this file.

Also required per finding: the six-question exploitability assessment
(stable repro / preconditions / impact surface / attack cost / fix priority /
limits & mitigations). Findings missing any answer must not be graded.

## Business Logic & Authorization Methodology (v5.7)

`rules/` already carried `logic_flaw` / `race_condition` / `mass_assignment` as
detection entries, but a rule cannot model a business. `scripts/business_logic.py`
turns those rules into a workflow — see `references/business_logic_playbook.md`.

| Subcommand | Purpose |
| --- | --- |
| `model --file m.json` | Validate the five-question state-machine model (`errors` = structural, `gaps` = missing question) |
| `plan --file m.json [--out plan.md] [--board-root hunts --target T]` | Emit the test plan (skip / replay / overwrite tests, role matrix, A/B targets, race targets, remediation) and optionally push assumptions + todos to the clue board |
| `ab --url U --owner-token A --attacker-token B` | Generate the three-request A/B cross-proof set (baseline / cross / unauthenticated control) |
| `race --endpoint U --replays N --authorized-rps R` | Generate a **rate-bounded** concurrent replay skeleton (`xargs -P` / thread pool / Turbo Intruder) |
| `judge --file e.json` | Adjudicate evidence into `pass` / `fail` / `inconclusive` (exit 0/1/2) |
| `scene --name payment\|entitlement\|flow` / `fix --type <t>` | Print the scenario attack table / remediation set |

**The only decidable standard for IDOR** (mirrors 硬门4 类型命门 `idor`):

> A's resource must be readable with **B's** credential.

A 200 from an unauthenticated request is **not** IDOR — it is unauthenticated
access, a different type with a different fix. A 401/403 on the cross request
**falsifies** the assumption: write it to `excluded` and do not report it.

**The only decidable standard for a race condition**: success count > the
business-allowed unique successes, **plus** an observed state delta,
**plus** a serial-replay control that did not reproduce it (all three).

`judge` refuses to return `pass` without a falsification/control record — the
same bar as 硬门0. `submission_type` and `gate_hint` are aligned with
`report_docx.TYPE_GATES`, so a methodological pass still has to clear the six
hard gates before it can become a DOCX.

## Knowledge Domain Layers (v5.8–v5.11)

Coverage extends beyond the web into four domains. Each ships as **handbook +
rule file + type gates**. None introduces a new scan engine: every domain reuses
the same evidence, adjudication (`business_logic.py`) and delivery
(`report_docx.py`) layers, so the pass bar does not move.

| Version | Domain | Handbook | Rules | Type gates added |
| --- | --- | --- | --- | --- |
| v5.8 | AI / LLM application | `references/ai_llm_security.md` | `rules/ai_llm_security.yaml` (11) | `prompt_injection`, `agent_tool_abuse` |
| v5.9 | Mini program | `references/miniprogram_security.md` | `rules/miniprogram_security.yaml` (8) | `hardcoded_secret`, `mp_api_idor`, `cloud_db_exposure`, `cloud_function_abuse`, `mp_login_logic`, `mp_payment_logic`, `mp_render_injection` |
| v5.10 | Android / APK | `references/android_audit.md`, `references/apk_reversing.md` | `rules/android_security.yaml` (7) | `android_component_exposure`, `android_webview_bridge`, `android_provider_exposure`, `android_intent_redirect`, `android_binder_privilege`, `android_pendingintent_hijack`, `android_deeplink_hijack` |
| v5.11 | Windows PE | `references/pe_reversing.md` | `rules/pe_security.yaml` (4) | `memory_corruption`, `format_string`, `dll_hijacking`, `missing_mitigation` |

### Domain invariants (do not relax)

| Domain | The bar |
| --- | --- |
| AI/LLM injection | A **behaviour delta reproduced ≥3 times** plus a control request whose output differs. One apparent compliance is nothing. |
| AI/LLM tool abuse | **Landed evidence only** — command echo, internal echo, real OOB callback, file content. A model *claiming* it executed something is never evidence. |
| Mini program API IDOR | The same three-request A/B cross-proof as web `idor`. The client carries the whole authorisation story, so identity must never be inferred from a request field. |
| Mini program cloud data | Cross-user or anonymous read, with a de-identified sample; tests are read-only and row-limited. |
| Android components | A **copy-pasteable ADB command plus a real effect**. "Exported but nothing happens" is a lead, not a finding. |
| Android degraded path | No-Frida / no-root coverage must be documented as a limitation, never silently skipped. |
| PE memory corruption | A crash must be proven **controllable** (EIP/RIP overwritten by input). A bare crash is a lead. |
| PE DLL hijacking | The test DLL must be **loaded and executed**, and the report must state which of hijack / search-order / phantom applies. |

**Fast triage for mobile targets**: `python3 scripts/apk_recon.py app.apk --secrets`
— pure standard library, seconds, no jadx/apktool. It emits the component matrix
with export-risk classification, hardening `lib*.so` fingerprints, and masked
secret plus endpoint hits (internal addresses and high-value paths surfaced
separately).

**Compliance per domain**: AI/LLM testing is limited to self-owned or
written-authorized applications, and any poisoning payload must be removed
afterwards with the cleanup recorded on the clue board. Mini program cloud tests
are read-only and row-limited. Android analysis is limited to self-owned apps.
PE analysis happens only in an isolated snapshot-recoverable VM, and DLL hijack
verification never replaces a DLL in the system directory.

## Trigger → Module Routing (v5.7)

Route by trigger signal instead of walking the pipeline linearly.

### Scene → module

| Trigger signal | Module | Deep action |
| --- | --- | --- |
| New target / resuming after compression / keep host+path+key across sessions | `clueboard.py` | `init` → work → `add` back; `brief` first when resuming |
| Unclear attack surface; find endpoints / keys / subdomains | `passive_recon.py` → `js_analyzer.py` | Asset mapping, JS/webpack/source-map recovery, historical assets |
| Path absent from main-site JS / no account / 405 or `data:[]` / frontend crypto treated as auth | `directory_fuzzer.py` + playbook §6 | Zero-identity surface recovery, response-fingerprint triage, crypto falsification |
| Parameter concatenation / dynamic sort / JSON query / template render / command sink | `advanced_sqli.py`, `advanced_injection.py` | Error·boolean·time-blind (capped), SSTI arithmetic reflection |
| Login / register / password reset / captcha / OAuth / JWT, IDOR, role param controllable | `vuln_detector.py` critical + `business_logic.py ab` | Auth bypass, A/B cross-proof, multi-tenant isolation |
| Payment / order / refund / withdraw / coupon / points / approval / stock, concurrency | `business_logic.py` | State-machine modelling, amount tampering, race replay |
| Upload / download / export / import / preview | `vuln_detector.py` file_upload + `exploit_generator.py` | getshell/parse proof, path traversal, Zip Slip |
| URL-driven fetch / proxy / webhook / callback / image preview | `oob_client.py` + `advanced_injection.py` | Real OOB callback + internal echo |
| XML / SOAP / serialized objects / deep JSON merge | `advanced_injection.py` | Deserialization, XXE, prototype pollution |
| Reflected/stored/DOM XSS, postMessage, CORS, CSRF | `vuln_detector.py` xss + `browser_agent.py` | In-browser execution proof |
| REST / GraphQL / gRPC / WebSocket / Swagger / debug endpoints | `api_auditor.py` | All-method testing, BOLA, schema mining |
| Cloud / container / K8s / middleware / CI-CD / dependency CVE | `cloud_security.py` + `cve_correlator.py` | Misconfig, unauth middleware, supply chain |
| Source code or decompiled artefacts available | manual audit + `vuln_detector.py` | Input point → propagation → sink |
| Payload blocked / 403 / WAF | `waf_evasion.py` + `adaptive_engine.py` | Failure escalation L1-L4 |
| Domestic OA/middleware (泛微/致远/通达/用友/禅道/JeecgBoot/若依…) | `cn_probes.py` | 32 unauth probes + fingerprint triage |
| AI chat / assistant / copilot / RAG Q&A / agent tool calling / code interpreter / multimodal parsing | `references/ai_llm_security.md` + `rules/ai_llm_security.yaml` | Behaviour diff to prove the model was rewritten → land it with the existing layers (`oob_client.py`, command echo, `business_logic.py ab`). **A model claiming execution is never evidence.** |
| Mini program (WeChat / Alipay / Douyin / Baidu), cloud development, `.wxapkg`/`.apkg` decompilation | `references/miniprogram_security.md` + `rules/miniprogram_security.yaml` | Package recovery → decompile → key/endpoint extraction → authorisation verification (reuse `business_logic.py ab`). Cloud DB tests read-only and row-limited; API IDOR keeps the web `idor` bar. |
| App / APK / exported component / WebView / Provider / Deep Link / packed bundle | `scripts/apk_recon.py` → `references/android_audit.md` + `references/apk_reversing.md` | Triage in seconds (component matrix + secrets + endpoints + hardening) before deciding what to dig into; component findings need an ADB command plus a real effect. |
| exe / dll / sys / sample / packed binary / crash triage | `references/pe_reversing.md` | Static (structure, mitigations, packer) → isolated-VM dynamic behaviour → crash and hijack location. **A crash must be proven controllable; a hijack must be proven loaded.** |
| About to deliver / write a report | `report_docx.py` | Layered gate → DOCX archive |

### Vulnerability type → module

| Type | Module |
| --- | --- |
| `idor` / `priv_esc` / `auth_bypass` / multi-tenant | `vuln_detector.py` critical tier + `business_logic.py ab` |
| `logic_flaw` / `race_condition` / `mass_assignment` | `business_logic.py` (`rules/high.yaml` entries are the detection seed) |
| `sqli` / `nosql_injection` / `ldap_injection` / `ssti` / `command_injection` | `advanced_sqli.py`, `advanced_injection.py` |
| `xss` / `csrf` / `cors_misconfig` / `open_redirect` | `vuln_detector.py` medium tier + `browser_agent.py` |
| `ssrf` / `xxe` / `deserialization` / `prototype_pollution` | `oob_client.py`, `advanced_injection.py` |
| `file_upload` / `path_traversal` / `directory_listing` | `vuln_detector.py` high/low tiers |
| `info_leak` / `misconfig` / `component_exposure` / `graphql_introspection` | `cloud_security.py`, `cn_probes.py`, `api_auditor.py` |
| `jwt_deep_analysis` / `oauth_misconfig` / `session_fixation` | `vuln_detector.py` high/medium tiers |
| `data_exposure` / `http_smuggling` / `rce` | critical tier (`rce` and `http_smuggling` are L4 — human approval) |
| `weak_credential` / `captcha_bypass` / `email_injection` / `crlf_injection` | medium tier + `adaptive_engine.py` |
| `prompt_injection` / `agent_tool_abuse` / `rag_poisoning` / `excessive_agency` / `sandbox_escape` / `system_prompt_leak` | `references/ai_llm_security.md` + `rules/ai_llm_security.yaml` (`agent_tool_abuse`, `sandbox_escape` are L4 — human approval) |
| `mp_api_idor` / `cloud_db_exposure` / `cloud_function_abuse` / `mp_login_logic` / `mp_payment_logic` / `mp_render_injection` / `hardcoded_secret` | `references/miniprogram_security.md` + `rules/miniprogram_security.yaml` |
| `android_component_exposure` / `android_webview_bridge` / `android_provider_exposure` / `android_intent_redirect` / `android_binder_privilege` / `android_pendingintent_hijack` / `android_deeplink_hijack` | `references/android_audit.md` + `rules/android_security.yaml` (`android_webview_bridge` is L4) |
| `memory_corruption` / `format_string` / `dll_hijacking` / `missing_mitigation` | `references/pe_reversing.md` + `rules/pe_security.yaml` (`memory_corruption` is L4) |

### SRC high-value priority (spend effort here first)

| Severity | Types | Route |
| --- | --- | --- |
| 严重 | RCE / command injection; SQLi on core tables; arbitrary file read/write; SSRF into intranet | critical + high tiers, `oob_client.py` |
| 高危 | Vertical privesc; payment logic; bulk PII leak; arbitrary password reset; SMS bombing; Android exported-component with a real effect; Agent tool abuse with landed evidence; mini program cloud DB cross-user read | `business_logic.py`, `unauth` route, `apk_recon.py`, `ai_llm_security.md` |
| 中危 | IDOR (web / mini program); stored XSS; CSRF on critical actions; unauth access; System Prompt leak; RAG poisoning (with cross-account proof); PendingIntent / Deep Link hijack | type table above |

### Combination playbook

- Info leak → IDOR: `js_analyzer` finds endpoints → `business_logic.py ab` proves it
- Component exposure → credentials → admin login: `cn_probes`/`cloud_security` → auth bypass
- Upload → intranet: `file_upload` yields a path → `oob_client` drives SSRF
- Low-severity chaining: finish the single point, run the cross-interface five
  questions, then `attack_path.py` — grade by the chain's terminal impact
- Cross-session resume: always `clueboard.py brief` first, then fill only the
  blanks already on the board

## 中文触发短语与结论口径 (Chinese Triggers & Conclusion-First Output)

中文环境下按下列触发短语直接命中本技能，无需翻译成英文。

**场景触发短语**：渗透测试 · 打点 · 漏洞挖掘 · 授权测试 · 安全审计 · 漏洞扫描 ·
安全验证 · 资产测绘 · 攻击面梳理 · 内网自查 · 护网自查

**专项触发短语**：

| 说法 | 路由 |
| --- | --- |
| 越权 / 水平越权 / IDOR / 能不能看别人的订单 | `business_logic.py ab` + `judge` |
| 垂直越权 / 普通用户变管理员 / 提权 | `vuln_detector.py` critical + `business_logic.py ab` |
| 业务逻辑 / 金额篡改 / 价格篡改 / 状态跳变 / 跳过支付 | `business_logic.py plan` |
| 并发 / 竞态 / 条件竞争 / 重复领取 / 券被薅 | `business_logic.py race` + `judge` |
| 认证绕过 / 任意密码重置 / 验证码绕过 / JWT | `vuln_detector.py` critical |
| 注入 / SQL注入 / 命令执行 / SSTI / 模板注入 | `advanced_sqli.py`, `advanced_injection.py` |
| 上传 / 下载 / 任意文件读取 / 路径穿越 | `vuln_detector.py` file_upload |
| SSRF / 内网探测 / 打内网 / 云元数据 | `oob_client.py` |
| 云配置 / 未授权中间件 / Actuator / Druid / Swagger | `cloud_security.py`, `cn_probes.py` |
| 泛微 / 致远 / 通达 / 用友 / 禅道 / 若依 / JeecgBoot | `cn_probes.py` |
| payload 被拦 / 被 WAF 拦 / 403 绕过 | `waf_evasion.py`（失败升级 L1-L4） |
| 出报告 / 写报告 / 提交稿 / 生成漏洞报告 / 成稿 | `report_docx.py`（先过六道硬门） |
| 线索板 / 记线索 / 跨会话继续挖 / 上次挖到哪 | `clueboard.py`（先 `brief`） |

**结论先行的输出骨架**（对话内快速结论用；正式交付一律以 `report_docx.py` 的 DOCX 为准）：

```
【结论】<漏洞名称> — <建议危害等级：严重/高危/中危/低危>
【影响资产】<URL / 组件 / 业务单元>
【可利用性】可稳定复现：YES/NO ｜ 前置条件：<登录态/角色/网络位置/版本>
【证据】<原始请求块> → <响应差异> → <实际观察到的影响>
【根因】输入点 → 传播链 → 危险点（缺失的校验）
【修复】一句话结论 + 代码级/配置级要点
【覆盖度】✅ 已测 … ｜ ❌ 未测 … ｜ 🔄 变种 … ｜ 💡 关联 …
```

写作纪律：结论在前，推导在后；只写**实际观察到的影响**，不写理论影响；
危害等级以"建议"形式给出；**CVSS 评分不由本技能自评**（交提交平台评定）；
未验证的线索写进线索板与 `unverified_leads`，不写进结论。

## LLM Usage Boundary

The LLM (this agent) is permitted ONLY for:

- Vulnerability reasoning and classification.
- Report generation and natural-language summaries.
- Attack path inference (candidate edges).
- Safe payload SUGGESTION (never execution of destructive payloads).

The LLM is FORBIDDEN from:

- Exploit chaining for real-world abuse.
- Bypassing or weakening scope logic.
- Generating or executing destructive payload plans.
- Overriding evidence-based validation.
- Declaring or describing a vulnerability as confirmed without live
  request/response evidence from the current run (see Reproducibility
  Gate). Phrasing such as "this should be exploitable" belongs in
  `unverified_leads[]`, never in findings or the executive summary.

## Tool Usage Rules

Allowed tools (from `ctx.tools`): `runShell`, `httpRequest`, `browser`,
`logger`.

Prohibited:

- Raw socket exploitation.
- Destructive payload execution by default.
- Scope bypass attempts (treated as a critical policy violation and logged).
- Uncontrolled scanning (must respect rate limit + scope).

## Output Specification

The skill MUST return a FinalOutput object (see
`references/data_schemas.md` -> FinalOutput):

```json
{
  "summary": "",
  "risk_score": 0,
  "assets": {},
  "findings": [],
  "unverified_leads": [],
  "attack_paths": [],
  "recommendations": [],
  "execution_log": []
}
```

`findings[]` contains ONLY reproducibility-gated `validated` findings.
Candidates that could not be reproduced live during this run are returned
in `unverified_leads[]` (with `blocking_reason`) and MUST NOT influence
`risk_score` or `summary`.

## Testability Requirements

The skill MUST be deterministic, reproducible, and idempotent. The
`assets/` directory contains worked examples:

- `assets/example_input.json` — a complete sample `AgentContext`.
- `assets/example_trace.json` — a step-by-step execution trace through every
  state, with intermediate artifacts.
- `assets/example_report.json` — the expected final output for the sample
  input.

When the user asks to "test", "dry-run", or "validate" the skill, replay the
example input and confirm the output structure matches
`assets/example_report.json`.

## Resources

### scripts/

Deterministic, executable helpers. Read them before modifying.

- `scripts/utils.py` — Shared utilities: UTF-8 JSON I/O, DNS resolve with
  timeout + per-run cache, structured log events, finding fingerprint
  (stable hash for dedup), `dedup_against_memory()` helper.
- `scripts/pattern_matcher.py` (v5.5 NEW) — Multi-pattern matching engine:
  `Trie` (prefix tree), `ACAutomaton` (Aho-Corasick multi-literal matcher,
  single O(n+hits) pass with a complete-transition delta table),
  `required_literal_sets()` (sound regex→required-literal DNF extractor),
  and `PrefilteredRegexSet` (AC-gated regex tables that run only the
  regexes whose required literals are present; small texts fall back to
  naive evaluation). Used by tech_fingerprint, adaptive_engine.detect_waf,
  js_analyzer, passive_recon, and quick_combat at their respective states.
- `scripts/state.py` — `StateSerializer` contract: atomic checkpoint of
  the state machine to `runs/<run_id>.json`. Supports pause/resume between
  transitions and validates resumable states.
- `scripts/vuln_detector.py` — Severity-tiered (low/medium/high/critical)
  detection plan generator. Emits candidate findings for every supported
  vulnerability type. CLI: `--tier`, `--safe-mode/--no-safe-mode`,
  `--include-l4` (opt-in for SSRF/RCE/destructive probes). Used at
  ACTIVE_TESTING. Also exposes `classify_data_exposure()` for the
  critical-upgrade post-validation step.
- `scripts/scope_guard.py` — Validate targets against `ctx.scope`. Exit 0 if
  all in-scope, exit 1 with an offender list if any out-of-scope. Uses
  `utils.resolve_ips()` (3s timeout, per-run cache) for DNS rebinding
  defense. Used at SCOPE_CHECK.
- `scripts/rate_limiter.py` — Token-bucket rate limiter (default 3 rps,
  burst configurable). Importable + CLI. Used to gate every tool call.
- `scripts/finding_validator.py` — Re-run a finding's PoC, capture fresh
  evidence, classify TP/FP. Used at VALIDATION.
- `scripts/attack_path.py` — Build the attack-path graph from validated
  findings. `_has_data()` uses structural JSON field whitelist
  (`SENSITIVE_FIELDS`) to avoid substring false positives. Used at
  ATTACK_PATH_ANALYSIS.
- `scripts/report_generator.py` — Assemble the final report (exec summary,
  findings, risk score, remediation, repro, SARIF-like JSON with
  `partialFingerprints` + `properties.tier` for CI baseline dedup,
  execution log). Used at REPORT_GENERATION.
- `scripts/adaptive_engine.py` (v2 NEW / v5.5 UPGRADED) — Adaptive probing
  engine: retry with exponential backoff, payload mutation for WAF bypass,
  WAF type detection (Cloudflare/Akamai/ModSecurity/安全狗/云盾 — body
  signatures matched via a single Aho-Corasick pass on large responses),
  and alternative probe strategy selection. Used at ACTIVE_TESTING when a
  probe fails. See `references/script_contracts.md` for the full interface contract.
- `scripts/safety_simulator.py` (v2 NEW) — Pre-flight safety simulator:
  dry-run mode (simulate plan without network), target risk scoring
  (0–100 based on environment/ports/paths/tech), and automatic scope
  narrowing (block dangerous paths for critical-risk targets). Used at
  PRE_FLIGHT. See `references/script_contracts.md`.
- `scripts/confidence_scoring.py` (v2 NEW) — Multi-factor confidence
  scoring: evidence_strength (0.30) + reproducibility_score (0.30) +
  signal_clarity (0.25) + corroboration (0.15). A finding is promoted
  to validated only when confidence >= 0.80. Used at VALIDATION.
  See `references/script_contracts.md`.
- `scripts/decision_engine.py` (v2.1 / v2.2 REFACTORED) — Heuristic
  decision engine (OPTIONAL PLUGIN): deterministic rule-based probe
  continuation (5 rules A-E), severity upgrade (additive scoring),
  scope expansion (5 gates), and heuristic confidence scoring. Replaces
  the v2.1 sigmoid/Bayesian probabilistic layer with explainable rule
  paths. See `references/formal_algorithms.md §5`.
- `scripts/execution_trace.py` (v2.2 NEW) — Fixed decision trace +
  replayable execution: records every agent decision into an immutable
  trace, supports replay for determinism verification, and diff for
  cross-run comparison. Used for CI auditability.
- `scripts/state_recovery.py` (v2.1 NEW) — Execution state recovery:
  checkpoint retry with backoff, partial state resume (skip probed
  endpoints), and failure rollback to safe previous state. See
  `references/formal_algorithms.md §6`.
- `scripts/js_analyzer.py` (v3 NEW / v5.5 UPGRADED) — JS static analysis for client-side
  vulnerability mining: secrets detection (API keys/tokens/passwords),
  dangerous sinks (eval/Function/innerHTML/document.write), postMessage
  misconfiguration (missing origin check), prototype pollution vectors,
  weak crypto (MD5/SHA1/ECB), debug leaks (console.log/alert), and DOM
  clobbering patterns. All pattern dicts are evaluated through the
  Aho-Corasick gate (one scan per bundle). Used at ACTIVE_TESTING for front-end targets.
- `scripts/cve_correlator.py` (v3 NEW) — CVE correlation engine: matches
  discovered technologies (via CPE) with a built-in CVE knowledge base
  covering common web frameworks (nginx, Apache, Tomcat, Spring, Django,
  Flask, Node.js, PHP, etc.), databases (MySQL, PostgreSQL, MongoDB,
  Redis), and middleware. Provides CVSS score, severity, exploit
  availability, and aggregated risk score. Used at VALIDATION.
- `scripts/advanced_injection.py` (v3 NEW) — Advanced injection engine:
  specialized detection plans for NoSQL (MongoDB operators), LDAP
  (wildcard/OR/AND/NULL-byte), CRLF (header splitting/response splitting),
  HTTP smuggling (CL.TE/TE.CL/TE.TE), cache poisoning (unkeyed headers/
  fat GET), race conditions (TOCTOU/multi-endpoint), extended SSTI
  (Jinja2/Twig/Freemarker/Velocity/Smarty), and XPATH injection. Used at
  ACTIVE_TESTING for advanced injection targets.
- `scripts/api_auditor.py` (v3 NEW) — API security auditor: GraphQL
  (introspection/query depth/batching/alias overload/field suggestion),
  REST (method override/content-type confusion/parameter pollution),
  WebSocket (origin validation/CSWSH/unauth access). Used at
  ACTIVE_TESTING for API endpoints.
- `scripts/cloud_security.py` (v3 NEW) — Cloud security scanner: AWS S3
  bucket permission checks, cloud metadata service access (169.254.169.254),
  Kubernetes API misconfiguration, Docker API exposure, CDN origin IP
  disclosure, and container registry checks. Used at ACTIVE_TESTING for
  cloud-hosted targets.
- `scripts/passive_recon.py` (v4 NEW) — Zero-touch passive reconnaissance:
  crt.sh certificate transparency, built-in DNS client (A/AAAA/CNAME/MX/NS/
  TXT/SOA), WHOIS via IANA referral, technology stack detection from HTTP
  headers/body, Wayback Machine URL discovery, GitHub secret dorking (15
  templates), Shodan/Censys integration points, email enumeration. Used at
  PASSIVE_RECON.
- `scripts/directory_fuzzer.py` (v4 NEW) — Smart directory brute-forcing
  engine: 10 curated wordlist categories (116 paths), 20 file extensions,
  custom 404 page detection via SimHash similarity, recursive discovery with
  depth control, technology-aware path prioritization (17 tech stacks),
  response analysis (size/status/content-type). Auto-detects ffuf for
  high-speed fuzzing. Used at ACTIVE_RECON.
- `scripts/advanced_sqli.py` (v4 NEW) — Professional SQL injection engine:
  6 database engines (MySQL/PostgreSQL/MSSQL/Oracle/SQLite/MariaDB),
  error-based extraction (EXTRACTVALUE/UPDATEXML/CONVERT/CAST), boolean-based
  blind with character-by-character inference, time-based blind (DB-specific),
  UNION-based with column discovery, OOB exfiltration (DNS/HTTP/SMB),
  second-order SQLi detection, 10 WAF bypass technique categories. All
  detection-only payloads. Used at ACTIVE_TESTING.
- `scripts/ssl_analyzer.py` (v4 NEW) — SSL/TLS security analyzer: certificate
  chain analysis (subject/issuer/SANs/expiry/key strength), cipher suite
  enumeration with grading (A+ through F, 59 ciphers), protocol version
  detection (SSLv2 through TLS 1.3), vulnerability checks (POODLE/BEAST/CRIME/
  FREAK/Logjam/DROWN/Heartbleed), HSTS analysis, OCSP stapling check, CT
  verification. Used at ACTIVE_RECON.
- `scripts/tech_fingerprint.py` (v4 NEW) — Technology stack fingerprinting:
  30+ server signatures, 17 language/framework patterns, 35+ session cookie
  patterns, 26 meta generator tags, 30 JS framework patterns, 19 favicon
  hashes (built-in MurmurHash), 20 error page signatures, 25 CDN/WAF header
  patterns, 12 database error patterns, OS detection from TTL/server hints.
  Auto-detects httpx for faster probing. Used at ACTIVE_RECON.
- `scripts/nuclei_runner.py` (v4 NEW) — Nuclei template scanning integration:
  auto-detects nuclei binary, recursive template index builder (lightweight
  YAML subset parser), smart template selection (80+ tech-to-tag mappings
  with multi-factor scoring), execution planning with time estimation and
  bulk target batching, JSON-lines result parser into Finding schema with
  25+ type classifiers, SHA-256 deduplication, template validation, fallback
  manual scanning guide. Used at ACTIVE_TESTING.
- `scripts/waf_evasion.py` (v4 NEW) — Advanced WAF bypass engine: protocol-level
  evasion (method override, HTTP downgrade, chunked transfer, CL.TE/TE.CL
  smuggling primitives), 6 encoding bypass categories (Unicode NFKC/NFKD,
  UTF-7, URL encoding chain, HTML entities, base64, hex), per-vuln-type
  obfuscation generators (10 SQLi + 10 XSS + 7 Path Traversal + 8 Command
  Injection + LDAP/NoSQL), WAF-specific rules for 10 WAF families, HTTP
  parameter pollution, content-type switching. All bypass variants include
  technique descriptions. Used at ACTIVE_TESTING.
- `scripts/clueboard.py` (v5.6 NEW) — **Cross-session clue board**: one
  human-readable Markdown board per TARGET at `hunts/<target>/CLUEBOARD.md`.
  Complements `state.py` (machine state, per run) with the analyst layer
  (judgements, open assumptions, falsified leads, recovered keys). Call it at
  the START of every session that touches an existing target (`read` / `brief`)
  and whenever a conclusion is reached (`add` / `cover`). Subcommands:
  `init` `read` `brief` `add` `cover` `check` `status` `list`. Duplicate leads
  are refused (`[重复]` marker) so already-tested paths are not re-tested, and
  open assumptions are capped at 5. Raw material goes to `hunts/<target>/raw/`.
- `scripts/report_docx.py` (v5.6 NEW) — **Submission-grade DOCX builder +
  layered verification gate**. Turns `validated` findings into the DOCX that
  SRC / CNVD / EDUSRC platforms actually accept (fixed Heading-2 skeleton,
  Step-style PoC with raw request blocks, embedded real screenshots, semantic
  filename `资产 存在 漏洞类型 漏洞.docx`). Refuses to write a report for any
  finding that fails the hard gates (先证伪 / 可复现 / 危害终局 / 服务端边界 /
  类型命门 / 链式追问), runs a pre-write duplicate check, and reports missing
  screenshots instead of silently skipping them. Degrades to `--gate-only`
  when python-docx is absent. CLI: `--emit-template`, `--findings`,
  `--gate-only`, `--mode src|0day|edu`, `--unit`, `--shots`, `--min-severity`.
  Used at REPORT_GENERATION, after `report_generator.py`.
- `scripts/business_logic.py` (v5.7 NEW) — **Business-logic / authorization /
  race methodology engine**. Turns the `logic_flaw` / `race_condition` /
  `mass_assignment` rules into a workflow: `model` validates the five-question
  state-machine model, `plan` emits the test plan (skip / replay / overwrite
  tests, role matrix, A/B targets, race targets, remediation) and can push
  assumptions + todos straight onto the clue board, `ab` generates the
  three-request IDOR cross-proof set (baseline / cross / unauthenticated
  control), `race` generates a **rate-bounded** concurrent replay skeleton,
  `judge` adjudicates evidence into `pass` / `fail` / `inconclusive`
  (exit 0/1/2) and refuses to pass anything without a falsification record.
  `submission_type` / `gate_hint` are aligned with `report_docx.TYPE_GATES`.
  Sends no traffic — it plans and adjudicates only.
- `scripts/apk_recon.py` (v5.10 NEW) — **APK fast triage, pure standard
  library**. Reads an APK as a zip and, in seconds, emits what to look at next
  without a full decompile: a self-contained **binary AXML parser** for
  `AndroidManifest.xml` producing the component matrix with export-risk
  classification (`high` = exported without a custom permission / `info` =
  protected / `unknown` = not declared), packer fingerprints from the hardening
  `lib*.so` list, and masked secret plus endpoint triage (RFC1918 / localhost /
  metadata addresses and high-value paths surfaced separately). Secrets are
  masked by design. CLI: `<apk> [--json PATH] [--secrets] [--top N]`. Exit `0`
  ok / `1` missing file or bad zip. Used at ACTIVE_RECON for mobile targets,
  feeding `references/android_audit.md` and `references/apk_reversing.md`.

**`AGENTS.md` (repo root, v5.7 NEW)** — the discipline layer. Ten execution
disciplines, the coverage self-check template, the Level 1-7 escalation ladder
(with "at least Level 4 before any 'no vulnerability' conclusion"), the
cross-interface five questions, the six-question exploitability assessment,
and the trigger→module routing table. Read it before the first probe of a
session. It cannot widen anything in the safety model.

### references/

Load into context as needed (do NOT load all at once).

- `references/safety_policy.md` — Full safety model: scope guard, risk gate,
  rate limit, evidence requirement, risk scoring rubric, disclaimers.
- `references/data_schemas.md` — All JSON schemas: AgentContext, InputSchema,
  OutputSchema, Finding (full), Asset (full), AttackPath (full), Tool I/O
  (httpRequest/runShell/browser/logger), FinalOutput.
- `references/payload_playbook.md` — Safe, non-destructive detection payloads
  per vulnerability class (22 types). For DETECTION only.
- `references/advanced_payload_playbook.md` (v3 NEW) — Advanced detection
  payloads for 16 new vulnerability types: NoSQL injection, LDAP injection,
  CRLF injection, HTTP smuggling, cache poisoning, race conditions, extended
  SSTI, XXE, prototype pollution, GraphQL injection, CORS misconfiguration,
  JWT deep analysis, OAuth misconfiguration, subdomain takeover, host header
  injection, mass assignment, dependency confusion, session fixation, email
  injection, WebSocket hijacking, and directory listing. All payloads are
  non-destructive (detection only).
- `references/script_contracts.md` (v2 NEW) — Interface contracts for every
  script: function signatures, input/output JSON, error states, and
  integration flow through the state machine.
- `references/formal_algorithms.md` (v2.1 / v2.2 SIMPLIFIED) —
  Documentation-only reference for explainable scoring rules and decision
  logic. Describes risk scoring, scope matching, confidence scoring,
  adaptive engine, heuristic decision rules (v2.2), and state recovery
  in plain language. Not a normative specification.
- `references/tool_contracts.json` (v2.1 / v2.2 UPDATED) — Machine-readable
  JSON Schema contracts for the 13 v2-era core scripts + 4 tools
  (httpRequest/runShell/browser/logger). Modules added after v2 (v3–v5.7) are
  documented in `references/script_contracts.md` instead — read that file for
  the authoritative contract of any newer module.
- `references/business_logic_playbook.md` (v5.7 NEW) — Methodology manual for
  `business_logic.py`: the five modelling questions, the three scenario attack
  tables (payment / entitlement / flow), the decidable A/B standard for IDOR,
  the three-part race-condition evidence standard, remediation sets, and the
  P1-6 appendix on zero-identity surface recovery (four iron rules + response
  fingerprint triage + crypto falsification).
- `references/knowledge_domains_roadmap.md` (v5.7) — Domain expansion roadmap.
  **All four planned domains have since landed (v5.8 → v5.11)** and every
  deliverable this file named now exists in the repository; it remains as the
  record of how each domain was scoped. The implemented behaviour lives in the
  four handbooks below.
- `references/ai_llm_security.md` (v5.8 NEW) — AI/LLM application security: the
  five-layer attack surface (input / retrieval / orchestration / execution /
  output), twelve detection classes each with construction, decision standard and
  non-submittable counter-examples, the behaviour-diff methodology, reuse of the
  existing landing layers (`oob_client.py`, command echo, `business_logic.py ab`),
  the two new type gates, and the cleanup duty for poisoning tests.
- `references/miniprogram_security.md` (v5.9 NEW) — Mini program security: the
  four-stage chain (package recovery → decompilation → key/endpoint extraction →
  authorisation verification), cloud development in three layers (database rules,
  cloud functions, storage), login-chain (`code2session` / `session_key` /
  phone-number decryption) and payment-chain weaknesses, and the rule that mini
  program API IDOR keeps the same A/B bar as the web.
- `references/android_audit.md` (v5.10 NEW) — Android component audit: the
  exported × permission decision table, eleven detection classes with
  copy-pasteable ADB commands, the no-Frida/no-root degraded verification path
  (mandatory to document, never silently skipped), and the requirement that a
  component finding carries both a reproducible command and a real effect.
- `references/apk_reversing.md` (v5.10 NEW) — APK reversing: the
  triage → packer identification → unpacking → full restore pipeline, the
  hardening `lib*.so` fingerprint table, root and no-root unpacking strategies,
  and artefact-handling rules (decompiled output is never committed or shared).
- `references/pe_reversing.md` (v5.11 NEW) — Windows PE reversing: the PE
  structure checklist (including TLS callbacks and section entropy), compiler and
  packer fingerprints, isolated-VM dynamic analysis with anti-debug
  identification, memory-corruption and DLL-hijacking location, and the rule that
  a crash must be proven controllable before it counts as a finding.

### assets/

- `assets/example_input.json` — Sample authorized `AgentContext` for a
  staging target.
- `assets/example_trace.json` — Full state-machine execution trace.
- `assets/example_report.json` — Expected `FinalOutput` for the sample input.
- `assets/report_template.docx` (v5.6 NEW) — Submission-report template for
  `report_docx.py`: Normal 微软雅黑 11pt, Heading 2 13pt bold, Heading 3 11pt
  bold, all text forced to black (Word's theme blue removed). Regenerate with
  `report_docx.py --emit-template`.

## Manifest

See `assets/manifest.yml` for the deployable Skill Manifest (name, version,
category, runtime, required tools, safe-mode default). This is the artifact
registered with the OpenClaw Gateway.

## Disclaimer

This skill is for AUTHORIZED security testing ONLY: enterprise internal
audits, staging/dev/lab verification. Unauthorized use against production or
third-party systems is prohibited and may be illegal.
