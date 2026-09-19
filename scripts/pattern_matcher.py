#!/usr/bin/env python3
"""Pattern Matching Engine for GKN-Phantom (v5.5).

Multi-pattern matching algorithms used to replace naive "one regex (or one
substring check) per pattern, scanned over the whole text" loops that appear
in the fingerprinting / WAF-detection / JS-analysis hot paths.

Components
----------
Trie
    Prefix tree. The goto structure of the Aho-Corasick automaton; also
    usable standalone for exact-membership and longest-prefix queries.

ACAutomaton
    Aho-Corasick multi-pattern literal matcher. One pass over the text,
    O(len(text) + number_of_hits) regardless of how many patterns are
    registered. Supports case-insensitive matching (ASCII + caseless
    scripts such as CJK) and reports both pattern presence and match spans.

required_literal_sets()
    Conservative extractor: given a regex *source string*, returns the set
    of literal substrings that EVERY match of that regex must contain
    (per top-level alternation branch). Returns None when the regex uses
    constructs the extractor cannot prove (lookarounds, backreferences,
    scoped inline flags, ...). Soundness property: if a literal is listed
    for a branch, no string can match that branch without containing the
    literal. This is what makes the prefilter below safe.

PrefilteredRegexSet
    A table of regexes evaluated through an Aho-Corasick gate: the AC scan
    (one pass) determines which regexes *can* match; only those are then
    executed. Results are identical to naive iteration over the table
    (property-tested in tests/test_pattern_matcher.py). Regexes whose
    required literals cannot be proven are "unguarded" and always
    evaluated — correctness never depends on the extractor.

Performance notes (honest engineering)
--------------------------------------
A pure-Python AC scan costs ~50-100 ns/char, while ``regex.search`` /
``str in`` run at C speed. For SMALL texts the naive loop over a handful of
patterns can therefore be faster than one Python-level AC pass; for LARGE
texts (HTML bodies, JS bundles) with many patterns the single AC pass plus a
handful of candidate regexes wins by orders of magnitude. PrefilteredRegexSet
auto-switches to naive evaluation below ``min_prefilter_len`` characters so
small-response workloads never regress.

All stdlib-only (no pip dependencies), consistent with the rest of the skill.
"""

from __future__ import annotations

import re
import unicodedata
from collections import deque
from typing import Any, Iterable, Iterator

__all__ = [
    "Trie",
    "ACAutomaton",
    "PrefilteredRegexSet",
    "required_literal_sets",
    "DEFAULT_MIN_PREFILTER_LEN",
]

# Below this text length the naive C-speed evaluation of every regex in a
# PrefilteredRegexSet is typically faster than one Python-level AC pass.
# Measured on the tech_fingerprint tables (~40 patterns per table); see
# tests/test_pattern_matcher.py benchmark.
DEFAULT_MIN_PREFILTER_LEN = 2048


# =============================================================================
# Trie
# =============================================================================

class Trie:
    """Prefix tree over ``str`` keys (also the goto structure of the AC).

    Node 0 is the root. Children are dicts char -> node index; values are
    attached per node. All operations are O(len(key)).
    """

    __slots__ = ("_children", "_values", "_terminal", "_size")

    def __init__(self) -> None:
        self._children: list[dict[str, int]] = [{}]
        self._values: list[list[Any]] = [[]]
        self._terminal: list[bool] = [False]
        self._size = 0

    def insert(self, key: str, value: Any = None) -> None:
        """Insert ``key``; ``value`` (if given) is attached to the terminal node."""
        if not key:
            raise ValueError("Trie keys must be non-empty")
        node = 0
        children = self._children
        for ch in key:
            nxt = children[node].get(ch)
            if nxt is None:
                nxt = len(children)
                children[node][ch] = nxt
                children.append({})
                self._values.append([])
                self._terminal.append(False)
            node = nxt
        if value is not None:
            self._values[node].append(value)
        self._terminal[node] = True
        self._size += 1

    def _walk(self, key: str) -> int | None:
        node = 0
        children = self._children
        for ch in key:
            node = children[node].get(ch, -1)
            if node < 0:
                return None
        return node

    def contains(self, key: str) -> bool:
        """True when ``key`` was explicitly inserted (not just a prefix path)."""
        node = self._walk(key)
        return node is not None and self._terminal[node]

    def get(self, key: str) -> list[Any]:
        """Values attached to ``key`` (empty list when the key is absent)."""
        node = self._walk(key)
        return self._values[node] if node is not None and self._terminal[node] \
            else []

    def longest_prefix(self, text: str) -> tuple[str | None, list[Any]]:
        """Longest registered key that is a prefix of ``text``.

        Returns (key, values) or (None, []).
        """
        best: str | None = None
        best_vals: list[Any] = []
        node = 0
        children = self._children
        for i, ch in enumerate(text):
            node = children[node].get(ch, -1)
            if node < 0:
                break
            if self._terminal[node]:
                best = text[: i + 1]
                best_vals = self._values[node]
        return best, best_vals

    def __len__(self) -> int:
        return self._size

    def iter_keys(self) -> Iterator[str]:
        """Yield every registered key in depth-first (insertion-alphabet) order."""
        stack: list[tuple[int, str]] = [(0, "")]
        children = self._children
        terminal = self._terminal
        while stack:
            node, prefix = stack.pop()
            if node and terminal[node]:
                yield prefix
            for ch, nxt in children[node].items():
                stack.append((nxt, prefix + ch))


# =============================================================================
# Aho-Corasick automaton
# =============================================================================

class ACAutomaton:
    """Aho-Corasick multi-pattern literal matcher.

    Build once (``add`` for each pattern, then the automaton lazily builds
    on first query), query many times:

        ac = ACAutomaton(case_insensitive=True)
        ac.add("Cloudflare", "cloudflare")
        ac.add("安全狗", "safedog")
        ac.which(body_text)          # -> {"cloudflare"}  (one pass)
        ac.find_all(body_text)       # -> {"cloudflare": [(start, end), ...]}

    Complexity: preprocessing O(total pattern length); each scan
    O(len(text) + hits) — independent of the number of patterns.
    """

    def __init__(self, case_insensitive: bool = False) -> None:
        self._ci = case_insensitive
        self._children: list[dict[str, int]] = [{}]
        self._out: list[set[Any]] = [set()]
        self._fail: list[int] = [0]
        self._pat_len: dict[Any, int] = {}
        self._delta: list[dict[str, int]] = []
        self._built = False

    # -- construction ---------------------------------------------------------

    def add(self, pattern: str, pid: Any = None) -> None:
        """Register a literal pattern. ``pid`` defaults to the pattern as
        given (not case-folded, even when the automaton is case-insensitive)."""
        if not pattern:
            raise ValueError("ACAutomaton patterns must be non-empty")
        if pid is None:
            pid = pattern
        if self._ci:
            pattern = pattern.lower()
        self._pat_len[pid] = len(pattern)
        node = 0
        children = self._children
        for ch in pattern:
            nxt = children[node].get(ch)
            if nxt is None:
                nxt = len(children)
                children[node][ch] = nxt
                children.append({})
                self._out.append(set())
                self._fail.append(0)
            node = nxt
        self._out[node].add(pid)
        self._built = False

    def _build(self) -> None:
        """BFS construction of failure links; merge suffix outputs."""
        children, fail, out = self._children, self._fail, self._out
        queue: deque[int] = deque()
        # Complete transition table (delta): computed in BFS order (fail[s]
        # is always shallower than s, hence already finalized), merging gives
        # every state a total transition function. The scan then costs ONE
        # dict lookup per character.
        delta: list[dict[str, int] | None] = [dict(children[0])] \
            + [None] * (len(children) - 1)
        for nxt in children[0].values():
            fail[nxt] = 0
            queue.append(nxt)
        while queue:
            s = queue.popleft()
            merged = dict(delta[fail[s]])
            merged.update(children[s])
            delta[s] = merged
            for ch, nxt in children[s].items():
                f = fail[s]
                while f and ch not in children[f]:
                    f = fail[f]
                fs = children[f].get(ch, 0)
                fail[nxt] = 0 if fs == nxt else fs
                out[nxt] |= out[fail[nxt]]
                queue.append(nxt)
        if any(d is None for d in delta):  # unreachable state — build bug
            raise RuntimeError("ACAutomaton: incomplete delta table")
        self._delta = [d for d in delta]
        self._built = True

    # -- queries ---------------------------------------------------------------

    def _ensure_built(self) -> None:
        if not self._built:
            self._build()

    def _scan_text(self, text: str) -> str:
        if not isinstance(text, str):
            raise TypeError("ACAutomaton scans require str text")
        return text.lower() if self._ci else text

    def which(self, text: str) -> set[Any]:
        """Set of pids with at least one occurrence in ``text`` (single pass).

        Hot loop kept minimal: one dict lookup + one list index per char.
        Output states are collected as ints and unioned once at the end —
        unioning pid-sets per position (which high-frequency short literals
        like ``'='`` would trigger tens of thousands of times) is the
        dominant cost otherwise.
        """
        self._ensure_built()
        text = self._scan_text(text)
        delta, out = self._delta, self._out
        seen: set[int] = set()
        add = seen.add
        s = 0
        for ch in text:
            s = delta[s].get(ch, 0)
            if out[s] and s not in seen:
                add(s)
        hits: set[Any] = set()
        for s in seen:
            hits |= out[s]
        return hits

    def find_all(self, text: str) -> dict[Any, list[tuple[int, int]]]:
        """All match spans per pid: {pid: [(start, end), ...]} (single pass).

        Slower than ``which`` (records per-position ends); intended for
        tests, evidence extraction, and debugging.
        """
        self._ensure_built()
        text = self._scan_text(text)
        delta, out = self._delta, self._out
        pat_len = self._pat_len
        ends: dict[Any, list[int]] = {}
        s = 0
        for j, ch in enumerate(text, 1):
            s = delta[s].get(ch, 0)
            o = out[s]
            if o:
                for pid in o:
                    ends.setdefault(pid, []).append(j)
        return {pid: [(e - pat_len[pid], e) for e in spans]
                for pid, spans in ends.items()}


# =============================================================================
# Regex required-literal extraction (sound, conservative)
# =============================================================================

class _Unsupported(Exception):
    """Regex construct the extractor cannot prove requirements for."""


# node = (kind, payload, min_repeats)
#   kind "char"  payload=str(ch)     literal character
#   kind "wide"  payload=None        any single char (class, \d, .) — breaks
#                                    literal contiguity, adds no literal
#   kind "zero"  payload=None        zero-width assertion (^ $ \b \A \Z)
#   kind "group" payload=list[alt]   alternation of node lists
# min_repeats == 0 => the node is optional (breaks contiguity, adds nothing)

_ESC_CLASS = set("dDsSwW")
_ESC_ZERO = set("bBAZ")
_FLAG_CHARS = set("aiLmsux")
_MAX_DEPTH = 50
_MAX_DNF_TERMS = 64


def _parse_class(src: str, i: int) -> int:
    """Parse a [...] class starting at ``src[i] == '['``; return index past ']'."""
    n = len(src)
    i += 1
    if i < n and src[i] == "^":
        i += 1
    if i < n and src[i] == "]":  # literal ']' as first class member
        i += 1
    while i < n and src[i] != "]":
        if src[i] == "\\":
            if i + 1 >= n:
                raise _Unsupported("trailing backslash in class")
            i += 2
        elif src[i] == "[" and src[i + 1 : i + 2] == ":":
            j = src.find(":]", i + 2)
            if j < 0:
                raise _Unsupported("unclosed posix class")
            i = j + 2
        else:
            i += 1
    if i >= n:
        raise _Unsupported("unclosed character class")
    return i + 1


def _parse_escape(src: str, i: int) -> tuple[tuple[str, Any, int], int]:
    """Parse an escape at ``src[i] == '\\'``. Returns (node, next_index)."""
    n = len(src)
    if i + 1 >= n:
        raise _Unsupported("trailing backslash")
    c = src[i + 1]
    if c in _ESC_CLASS:
        return ("wide", None, 1), i + 2
    if c in _ESC_ZERO:
        return ("zero", None, 1), i + 2
    if c == "x":
        return ("char", chr(int(src[i + 2 : i + 4], 16)), 1), i + 4
    if c == "u":
        return ("char", chr(int(src[i + 2 : i + 6], 16)), 1), i + 6
    if c == "U":
        return ("char", chr(int(src[i + 2 : i + 10], 16)), 1), i + 10
    if c == "N":
        j = src.find("}", i + 2)
        if j < 0:
            raise _Unsupported("unclosed \\N{...}")
        return ("char", unicodedata.lookup(src[i + 2 : j]), 1), j + 1
    if c == "0":
        return ("char", "\0", 1), i + 2
    if c in "fnrtva":
        return ("char", {"f": "\f", "n": "\n", "r": "\r", "t": "\t",
                         "v": "\v", "a": "\a"}[c], 1), i + 2
    if c.isdigit():
        raise _Unsupported("backreference / octal escape")
    if c.isalnum():
        raise _Unsupported(f"unsupported escape \\{c}")
    return ("char", c, 1), i + 2  # escaped punctuation, e.g. \. \\ \[


def _parse_quant(src: str, i: int, node: tuple[str, Any, int]
                 ) -> tuple[tuple[str, Any, int], int]:
    """Apply an optional quantifier at ``src[i]`` to ``node``.

    An invalid ``{...}`` is NOT a quantifier — it is left for the caller to
    treat as a literal character (matching Python re semantics).
    """
    n = len(src)
    if i >= n:
        return node, i
    c = src[i]
    min_rep = 1
    if c == "*":
        min_rep, i = 0, i + 1
    elif c == "+":
        min_rep, i = 1, i + 1
    elif c == "?":
        min_rep, i = 0, i + 1
    elif c == "{":
        j = src.find("}", i)
        if j > i:
            body = src[i + 1 : j]
            parts = body.split(",")
            try:
                if len(parts) == 1:
                    lo = int(parts[0])
                    min_rep = 1 if lo >= 1 else 0
                elif len(parts) == 2:
                    if parts[0] == "":
                        min_rep = 0  # {,n} == {0,n}
                    else:
                        lo = int(parts[0])
                        min_rep = 1 if lo >= 1 else 0
                else:
                    return node, i  # "{a,b,c}" — treat braces as literals
            except ValueError:
                return node, i  # "{foo}" — literal braces
            i = j + 1
        else:
            return node, i  # no closing brace — literal
    else:
        return node, i
    # lazy / possessive modifiers
    if i < n and src[i] == "?":
        i += 1
    if i < n and src[i] == "+":  # possessive (Python 3.11+)
        i += 1
    return (node[0], node[1], min_rep), i


def _parse_branches(src: str, i: int, stop: set[str], depth: int
                    ) -> tuple[list[list], int]:
    """Parse node sequences split on ``|`` until a stop char (or end).

    Returns (alternatives, index_at_stop_char_or_len). The alternative in
    progress when the stop char / end is reached counts as the last one;
    the stop char itself is left for the caller to consume.
    """
    if depth > _MAX_DEPTH:
        raise _Unsupported("nesting too deep")
    n = len(src)
    branches: list[list] = []
    cur: list = []
    while i < n:
        c = src[i]
        if c in stop:
            break
        if c == "|":
            branches.append(cur)
            cur = []
            i += 1
            continue
        if c == "(":
            i += 1
            if i < n and src[i] == "?":
                i += 1
                if i >= n:
                    raise _Unsupported("truncated (?...")
                ch = src[i]
                if ch == "#":  # (?#comment)
                    j = src.find(")", i)
                    if j < 0:
                        raise _Unsupported("unclosed (?#...)")
                    i = j + 1
                    continue
                if ch in "=!>((" or src[i : i + 3] in ("<=", "<!") \
                        or src[i : i + 2] in ("P=", "P>"):
                    raise _Unsupported(f"group construct (?{src[i:i+3]}")
                if ch == "P" and src[i + 1 : i + 2] == "<":
                    j = src.find(">", i)  # (?P<name>...) — parse as plain group
                    if j < 0:
                        raise _Unsupported("unclosed (?P<...>")
                    i = j + 1
                elif ch == ":":
                    i += 1  # consume the ':' — group body starts after it
                else:
                    # (?im-sx) flags: ')' => global directive (zero-width),
                    # ':' => scoped flags (case semantics change) => unsupported
                    j = i
                    while j < n and (src[j] in _FLAG_CHARS or src[j] == "-"):
                        j += 1
                    if j < n and src[j] == ")" and j > i:
                        i = j + 1
                        continue
                    raise _Unsupported("scoped inline flags / unknown (?...)")
            subs, i = _parse_branches(src, i, {")"}, depth + 1)
            if i >= n or src[i] != ")":
                raise _Unsupported("unclosed group")
            i += 1
            node = ("group", subs, 1)
            node, i = _parse_quant(src, i, node)
            cur.append(node)
        elif c == "[":
            j = _parse_class(src, i)
            node, i = _parse_quant(src, j, ("wide", None, 1))
            cur.append(node)
        elif c == "\\":
            node, i = _parse_escape(src, i)
            node, i = _parse_quant(src, i, node)
            cur.append(node)
        elif c == ".":
            node, i = _parse_quant(src, i + 1, ("wide", None, 1))
            cur.append(node)
        elif c in "^$":
            node, i = _parse_quant(src, i + 1, ("zero", None, 1))
            cur.append(node)
        elif c in "*+?":
            raise _Unsupported("quantifier without a preceding element")
        elif c == "{":
            # literal '{' (Python treats an invalid {..} as literal)
            node, i = _parse_quant(src, i + 1, ("char", "{", 1))
            cur.append(node)
        else:
            node, i = _parse_quant(src, i + 1, ("char", c, 1))
            cur.append(node)
    branches.append(cur)
    return branches, i


def _dnf(nodes: list) -> list[frozenset[str]] | None:
    """Requirement of one node sequence as a DNF: OR of AND-terms.

    Returns a list of frozensets — the sequence can only match when at least
    one term's literals are ALL present in the text (as substrings). Returns
    None when the term product exceeds _MAX_DNF_TERMS (give up, stay sound).

    Construction:
      - a run of contiguous required chars merges into one literal (selective)
      - char node           -> term {ch}
      - zero-width node     -> no requirement (does not break contiguity)
      - wide node / min=0   -> no literal, but breaks the contiguous run
      - group node          -> OR over alternatives (concatenation of each
                               alternative's DNF)
      - sequence            -> AND (cartesian product of terms)
    """
    terms: list[frozenset[str]] = [frozenset()]  # product so far (TRUE)
    cur: list[str] = []

    def flush() -> bool:
        nonlocal terms
        if not cur:
            return True
        run = frozenset({"".join(cur)})
        cur.clear()
        if len(terms) > _MAX_DNF_TERMS:
            return False
        terms = [t | run for t in terms]
        return True

    for kind, payload, min_rep in nodes:
        if min_rep == 0:
            if not flush():
                return None
            continue  # optional node: no requirement, breaks contiguity
        if kind == "char":
            cur.append(payload)
        elif kind == "zero":
            pass  # zero-width: does not break contiguity
        elif kind == "wide":
            if not flush():
                return None
        elif kind == "group":
            if not flush():
                return None
            alt_terms: list[frozenset[str]] = []
            for alt in payload:
                sub = _dnf(alt)
                if sub is None:
                    return None
                alt_terms.extend(sub)
                if len(alt_terms) > _MAX_DNF_TERMS:
                    return None
            terms = [t1 | t2 for t1 in terms for t2 in alt_terms]
            if len(terms) > _MAX_DNF_TERMS:
                return None
    if not flush():
        return None
    return terms


def _case_safe(literal: str) -> bool:
    """True when lowercasing the literal is exact under re.IGNORECASE.

    ASCII letters lower exactly; caseless scripts (CJK etc.) are identity;
    other cased non-ASCII chars (ß, İ, Kelvin sign, fullwidth forms) are
    rejected to keep the prefilter provably sound.
    """
    for ch in literal:
        if ch.isascii():
            continue
        if ch.lower() != ch or ch.upper() != ch:
            return False
    return True


def required_literal_sets(pattern: str) -> list[list[frozenset[str]]] | None:
    """Required-literal DNF per top-level branch for a regex source string.

    Returns [branch_dnf, ...] where branch_dnf is a list of frozensets
    (OR of AND-terms): a regex match on branch ``b`` implies at least one
    AND-term of ``b`` has ALL its literals present in the text as
    substrings. Returns None when the extractor cannot prove requirements
    (empty/zero-width branch, term blowup, unsupported construct, cased
    non-ASCII literal) — the caller must then always evaluate the regex.
    Both paths are safe; None only loses speed.
    """
    try:
        branches, i = _parse_branches(pattern, 0, set(), 0)
        if i != len(pattern):
            raise _Unsupported("unconsumed input")
        result: list[list[frozenset[str]]] = []
        for alt in branches:
            dnf = _dnf(alt)
            if dnf is None or not dnf or frozenset() in dnf:
                # term blowup, or a branch satisfiable with no literal
                return None
            lits = [lit for term in dnf for lit in term]
            if all(_case_safe(lit) for lit in lits):
                result.append(dnf)
        return result or None
    except (_Unsupported, RecursionError, ValueError, KeyError, IndexError):
        return None


# =============================================================================
# Prefiltered regex set
# =============================================================================

class PrefilteredRegexSet:
    """Evaluate a table of regexes through an Aho-Corasick literal gate.

    Built from ``(key, regex)`` pairs where regex is a source string or an
    already-compiled ``re.Pattern`` (``flags`` applies to string entries).

        pset = PrefilteredRegexSet([("wp", re.compile(r"wp-content", re.I)), ...])
        for key, m in pset.search_all(body):   # first match per key, in order
            ...

    Semantics: for every key whose regex matches ``text``, ``search_all``
    yields (key, first match) in registration order, exactly like iterating
    the table with ``regex.search``. ``iter_matches`` yields every match of
    every matching regex in registration order (like a nested
    ``for entry: for m in finditer`` loop). Unguarded regexes (extractor
    returned None) are always evaluated, so results never depend on the
    extractor's coverage — only the speed does.

    Texts shorter than ``min_prefilter_len`` skip the AC gate entirely and
    evaluate every regex directly (C-speed naive loops win on small inputs).
    """

    def __init__(self, entries: Iterable[tuple[Any, Any]],
                 flags: int = 0,
                 min_prefilter_len: int = DEFAULT_MIN_PREFILTER_LEN) -> None:
        self._entries: list[tuple[Any, re.Pattern]] = []
        self._unguarded: set[Any] = set()
        self._branches: dict[Any, list[list[frozenset[str]]]] = {}
        self._ac_ci = ACAutomaton(case_insensitive=True)
        self._ac_cs = ACAutomaton()
        self._has_ci = self._has_cs = False
        self._min_len = min_prefilter_len

        for key, regex in entries:
            if isinstance(regex, str):
                compiled = re.compile(regex, flags)
            else:
                compiled = regex
            self._entries.append((key, compiled))
            branches = required_literal_sets(compiled.pattern)
            if branches is None:
                self._unguarded.add(key)
                continue
            ci = bool(compiled.flags & re.IGNORECASE)
            # Branch literals must be stored in the same case mode the AC
            # scans in, otherwise the candidate check can never succeed.
            if ci:
                branches = [
                    [frozenset(lit.lower() for lit in term) for term in dnf]
                    for dnf in branches
                ]
            # Duplicate keys accumulate: a candidate hit on ANY entry's DNF
            # marks the key; search_all then evaluates each regex itself.
            self._branches.setdefault(key, []).extend(branches)
            self._has_ci = self._has_ci or ci
            self._has_cs = self._has_cs or not ci
            ac = self._ac_ci if ci else self._ac_cs
            for dnf in branches:
                for term in dnf:
                    for lit in term:
                        ac.add(lit, pid=(key, lit))

    @staticmethod
    def _branch_possible(dnf: list[frozenset[str]],
                         present: frozenset[str]) -> bool:
        """DNF candidate predicate: at least one AND-term fully present."""
        return any(term <= present for term in dnf)

    # -- candidate computation --------------------------------------------------

    def candidates(self, text: str) -> set[Any]:
        """Keys whose regex may match ``text`` (superset of actual matches)."""
        if not self._entries:
            return set()
        if len(text) < self._min_len or not (self._has_ci or self._has_cs):
            return {key for key, _ in self._entries}
        present: dict[Any, set[str]] = {}
        if self._has_ci:
            for key, lit in self._ac_ci.which(text.lower()):
                present.setdefault(key, set()).add(lit)
        if self._has_cs:
            for key, lit in self._ac_cs.which(text):
                present.setdefault(key, set()).add(lit)
        result = set(self._unguarded)
        for key, lits in present.items():
            for branch in self._branches[key]:
                if self._branch_possible(branch, frozenset(lits)):
                    result.add(key)
                    break
        return result

    # -- evaluation ---------------------------------------------------------------

    def search_all(self, text: str) -> list[tuple[Any, re.Match]]:
        """First match per matching key, in registration order."""
        cand = self.candidates(text)
        out: list[tuple[Any, re.Match]] = []
        for key, regex in self._entries:
            if key not in cand:
                continue
            m = regex.search(text)
            if m is not None:
                out.append((key, m))
        return out

    def iter_matches(self, text: str) -> Iterator[tuple[Any, re.Match]]:
        """Every match of every matching key, in registration order."""
        cand = self.candidates(text)
        for key, regex in self._entries:
            if key not in cand:
                continue
            yield from ((key, m) for m in regex.finditer(text))

    def __len__(self) -> int:
        return len(self._entries)


# =============================================================================
# Self-test (python pattern_matcher.py)
# =============================================================================

if __name__ == "__main__":
    ac = ACAutomaton(case_insensitive=True)
    for w in ("Cloudflare", "安全狗", "云盾", "cf-chl-bypass"):
        ac.add(w)
    sample = "Blocked by SafeDog WAF — 安全狗已拦截 (cf-chl-bypass token)"
    print("which:", sorted(ac.which(sample), key=str))
    print("spans:", ac.find_all(sample))

    t = Trie()
    for k in ("wp-admin", "wp-content", "wp"):
        t.insert(k)
    print("longest prefix of 'wp-content/themes':",
          t.longest_prefix("wp-content/themes")[0])

    demos = [
        r'<meta[^>]*\bname\s*=\s*["\']?generator["\']?[^>]*\bcontent\s*=\s*["\']?WordPress\s*([\d.]*)',
        r"SQL syntax.*MySQL",
        r"AKIA[0-9A-Z]{16}",
        r"(?i)(?:api[_-]?key|apikey|secret|token|password|passwd)\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
        r"(?=lookahead)nunsupported",
    ]
    for d in demos:
        print(f"{d[:50]!r:55} -> {required_literal_sets(d)}")
