#!/usr/bin/env python3
"""Tests for pattern_matcher.PrefilteredRegexSet — stdlib only, no pytest.

Run:  python tests/test_pattern_matcher.py

Two guarantees are checked:

1. EQUIVALENCE (property test): for a corpus of texts x pattern tables,
   ``PrefilteredRegexSet.search_all`` / ``iter_matches`` return exactly what
   naive iteration (``regex.search`` / ``regex.finditer`` per entry, in
   registration order) returns. The prefilter may only skip regexes that
   cannot match — never one that does.

2. SOUNDNESS regressions (both were real, measured false negatives):
   FN-A: a top-level branch with a case-unsafe literal made the whole regex
         register a partial (unsound) DNF — 'password|pässword' claimed
         'password' was required and skipped texts containing only 'pässword'.
   FN-B: the CI channel scanned text.lower(), but re.IGNORECASE folds more
         than str.lower() (ſ→s, ı→i, K→k): (?i)s matched 'ſ' while the
         lowered scan saw no 's'.
"""

from __future__ import annotations

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "scripts"))

from pattern_matcher import (  # noqa: E402
    PrefilteredRegexSet,
    required_literal_sets,
    DEFAULT_MIN_PREFILTER_LEN,
)


def naive_search_all(entries, text):
    out = []
    for key, regex in entries:
        m = regex.search(text)
        if m is not None:
            out.append((key, m))
    return out


def naive_iter_matches(entries, text):
    out = []
    for key, regex in entries:
        for m in regex.finditer(text):
            out.append((key, m))
    return out


TABLE = [
    ("wp", re.compile(r"wp-content", re.I)),
    ("wp2", re.compile(r"wp-admin")),
    ("meta", re.compile(
        r'<meta[^>]*\bname\s*=\s*["\']?generator["\']?[^>]*\bcontent\s*=\s*'
        r'["\']?WordPress\s*([\d.]*)', re.I)),
    ("sqli", re.compile(r"SQL syntax.*MySQL", re.I)),
    ("aws", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("apikey", re.compile(
        r"(?i)(?:api[_-]?key|apikey|secret|token|password|passwd)"
        r"\s*[:=]\s*['\"]([^'\"]{8,})['\"]")),
    ("cards", re.compile(r"\b(?:\d[ -]*?){13,16}\b")),
    ("cn", re.compile(r"安全狗|云盾")),
    ("unsupported", re.compile(r"(?=lookahead)nunsupported")),
    ("branchy", re.compile(r"foo|bar|baz", re.I)),
    ("mixed_case_branch", re.compile(r"password|pässword", re.I)),
]

TEXTS = [
    "",
    "plain text with nothing",
    "<meta name=\"generator\" content=\"WordPress 6.4\">",
    "wp-admin and wp-content both present; SQL syntax error near 'x' in MySQL",
    "AKIAIOSFODNN7EXAMPLE key with api_key = 'supersecretvalue'",
    "card 4111 1111 1111 1111 end",
    "安全狗已拦截 (cf-chl-bypass token)",
    "x" * (DEFAULT_MIN_PREFILTER_LEN + 64) + "pässword trailing",
    "x" * (DEFAULT_MIN_PREFILTER_LEN + 64) + "\u017f long-s trailing",
    "x" * (DEFAULT_MIN_PREFILTER_LEN + 64) + "\u0131 dotless-i trailing",
    "x" * (DEFAULT_MIN_PREFILTER_LEN + 64) + "\u212a kelvin trailing",
    "x" * (DEFAULT_MIN_PREFILTER_LEN + 64) + "foo middle",
    "short mixed_case: pässword",
    "lowercase short: password",
]


class TestEquivalence(unittest.TestCase):
    """PrefilteredRegexSet must equal naive iteration on every (table, text)."""

    def test_search_all_equivalence(self):
        for text in TEXTS:
            with self.subTest(text_head=text[:40]):
                entries = list(TABLE)
                pset = PrefilteredRegexSet(entries, min_prefilter_len=0)
                got = [(k, m.group(0)) for k, m in pset.search_all(text)]
                want = [(k, m.group(0)) for k, m in naive_search_all(entries, text)]
                self.assertEqual(got, want)

    def test_iter_matches_equivalence(self):
        for text in TEXTS:
            with self.subTest(text_head=text[:40]):
                entries = list(TABLE)
                pset = PrefilteredRegexSet(entries, min_prefilter_len=0)
                got = [(k, m.group(0)) for k, m in pset.iter_matches(text)]
                want = [(k, m.group(0)) for k, m in naive_iter_matches(entries, text)]
                self.assertEqual(got, want)

    def test_default_min_len_skips_gate(self):
        """Below min_prefilter_len every regex is evaluated (all candidates)."""
        text = "short body wp-content"
        pset = PrefilteredRegexSet(list(TABLE))  # default threshold
        got = [(k, m.group(0)) for k, m in pset.search_all(text)]
        want = [(k, m.group(0)) for k, m in naive_search_all(list(TABLE), text)]
        self.assertEqual(got, want)


class TestSoundnessRegressions(unittest.TestCase):
    """The two measured false negatives must stay fixed."""

    def test_fn_a_mixed_branch_is_unguarded(self):
        # The extractor must NOT claim 'password' is required: the äsbranch
        # matches without it. Whole pattern -> None (unguarded).
        self.assertIsNone(required_literal_sets("password|pässword"))
        long_text = "x" * (DEFAULT_MIN_PREFILTER_LEN + 64) + "pässword"
        entries = [("k", re.compile("password|pässword", re.I))]
        pset = PrefilteredRegexSet(entries, min_prefilter_len=0)
        self.assertEqual(len(pset.search_all(long_text)),
                         len(naive_search_all(entries, long_text)))
        self.assertTrue(pset.search_all(long_text))  # must actually match

    def test_fn_b_ci_fold_chars(self):
        # (?i)s matches 'ſ', (?i)i matches 'ı', (?i)k matches 'K' — the
        # prefilter must never hide those matches.
        for lit, weird in (("s", "\u017f"), ("i", "\u0131"), ("k", "\u212a")):
            with self.subTest(lit=lit):
                long_text = "x" * (DEFAULT_MIN_PREFILTER_LEN + 64) + weird
                entries = [("k", re.compile(lit, re.I))]
                pset = PrefilteredRegexSet(entries, min_prefilter_len=0)
                self.assertTrue(pset.search_all(long_text),
                                f"(?i){lit} must match {weird!r} in long text")

    def test_ci_unsafe_literals_go_unguarded(self):
        # A CI literal containing a fold-quirk char must demote the entry to
        # unguarded, and the set must still behave naively.
        entries = [("pw", re.compile(r"password", re.I)),   # contains s -> unguarded
                   ("clean", re.compile(r"wp-content", re.I))]  # stays guarded
        pset = PrefilteredRegexSet(entries, min_prefilter_len=0)
        self.assertIn("pw", pset._unguarded)
        self.assertNotIn("clean", pset._unguarded)
        text = "x" * (DEFAULT_MIN_PREFILTER_LEN + 64) + "password here"
        self.assertEqual(
            [(k, m.group(0)) for k, m in pset.search_all(text)],
            [(k, m.group(0)) for k, m in naive_search_all(entries, text)])


class TestHappyPath(unittest.TestCase):
    def test_guarded_entry_still_matches(self):
        pset = PrefilteredRegexSet(
            [("aws", re.compile(r"AKIA[0-9A-Z]{16}"))], min_prefilter_len=0)
        m = pset.search_all("key AKIAIOSFODNN7EXAMPLE ok")
        self.assertEqual(len(m), 1)
        self.assertEqual(m[0][0], "aws")

    def test_no_false_candidates_on_clean_text(self):
        pset = PrefilteredRegexSet(list(TABLE), min_prefilter_len=0)
        self.assertEqual(pset.search_all("nothing to see here"), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
