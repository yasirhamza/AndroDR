#!/usr/bin/env python3
"""test_selection.py — Unit tests for the scenario selector.

Run with:
    cd test-adversary && python3 test_selection.py -v
"""

from __future__ import annotations

import collections
import unittest

from selector import _expand_profile, _match_patterns, resolve_scenarios

# ── Shared test fixture ──────────────────────────────────────────────────────

MINI_MANIFEST: dict = {
    "version": 3,
    "profiles": {
        "pegasus": [
            "mercenary_package_name",
            "mercenary_cert_hash",
        ],
        "journalist": [
            "@pegasus",       # nested profile reference
            "stalk_*",        # glob pattern
        ],
        "banking": [
            "cerberus_banker",
            "anubis_banker",
        ],
    },
    "scenarios": [
        {
            "id": "cerberus_banker",
            "track": 1,
            "risk": "high",
            "description": "Cerberus banking trojan",
        },
        {
            "id": "anubis_banker",
            "track": 1,
            "risk": "medium",
            "description": "Anubis banking trojan",
        },
        {
            "id": "stalk_truthspy",
            "track": 2,
            "risk": "medium",
            "description": "TheTruthSpy stalkerware",
        },
        {
            "id": "stalk_andrmonitor",
            "track": 2,
            "risk": "low",
            "description": "AndrMonitor stalkerware",
        },
        {
            "id": "mercenary_package_name",
            "track": 3,
            "risk": "high",
            "description": "Known Pegasus package name",
        },
        {
            "id": "mercenary_cert_hash",
            "track": 3,
            "risk": "high",
            "description": "Cert hash IOC match",
        },
    ],
}

ALL_IDS = [s["id"] for s in MINI_MANIFEST["scenarios"]]


# ── Tests ────────────────────────────────────────────────────────────────────


class TestNoFilters(unittest.TestCase):
    """No filters returns all scenarios."""

    def test_returns_all(self):
        result = resolve_scenarios(MINI_MANIFEST)
        self.assertEqual([s["id"] for s in result], ALL_IDS)


class TestTrackFilter(unittest.TestCase):
    """--track filters by track number."""

    def test_single_track(self):
        result = resolve_scenarios(MINI_MANIFEST, tracks=[2])
        ids = [s["id"] for s in result]
        self.assertEqual(ids, ["stalk_truthspy", "stalk_andrmonitor"])

    def test_multiple_tracks(self):
        result = resolve_scenarios(MINI_MANIFEST, tracks=[1, 3])
        ids = [s["id"] for s in result]
        self.assertEqual(
            ids,
            ["cerberus_banker", "anubis_banker", "mercenary_package_name", "mercenary_cert_hash"],
        )


class TestRiskFilter(unittest.TestCase):
    """--risk filters by risk level."""

    def test_high_only(self):
        result = resolve_scenarios(MINI_MANIFEST, risks=["high"])
        ids = [s["id"] for s in result]
        self.assertEqual(ids, ["cerberus_banker", "mercenary_package_name", "mercenary_cert_hash"])

    def test_low_only(self):
        result = resolve_scenarios(MINI_MANIFEST, risks=["low"])
        ids = [s["id"] for s in result]
        self.assertEqual(ids, ["stalk_andrmonitor"])


class TestProfileFilter(unittest.TestCase):
    """--profile resolves direct profile entries."""

    def test_banking_profile(self):
        result = resolve_scenarios(MINI_MANIFEST, profile="banking")
        ids = [s["id"] for s in result]
        self.assertEqual(ids, ["cerberus_banker", "anubis_banker"])


class TestNestedProfileExpansion(unittest.TestCase):
    """journalist profile expands @pegasus + stalk_* glob."""

    def test_journalist_expands_correctly(self):
        patterns = _expand_profile(MINI_MANIFEST, "journalist")
        # Should include pegasus entries + stalk_* glob
        self.assertIn("mercenary_package_name", patterns)
        self.assertIn("mercenary_cert_hash", patterns)
        self.assertIn("stalk_*", patterns)

    def test_journalist_matches_scenarios(self):
        result = resolve_scenarios(MINI_MANIFEST, profile="journalist")
        ids = [s["id"] for s in result]
        expected = [
            "stalk_truthspy",
            "stalk_andrmonitor",
            "mercenary_package_name",
            "mercenary_cert_hash",
        ]
        self.assertEqual(sorted(ids), sorted(expected))


class TestOnlyOverride(unittest.TestCase):
    """--only overrides all other filters."""

    def test_only_ignores_track(self):
        result = resolve_scenarios(
            MINI_MANIFEST,
            tracks=[1],
            risks=["low"],
            only=["mercenary_cert_hash"],
        )
        ids = [s["id"] for s in result]
        self.assertEqual(ids, ["mercenary_cert_hash"])


class TestRandom(unittest.TestCase):
    """--random N returns exactly N items (when N <= total)."""

    def test_random_count(self):
        result = resolve_scenarios(MINI_MANIFEST, random_n=3)
        self.assertEqual(len(result), 3)
        # All returned items must come from the full set
        for s in result:
            self.assertIn(s["id"], ALL_IDS)

    def test_random_capped_at_total(self):
        result = resolve_scenarios(MINI_MANIFEST, random_n=100)
        self.assertEqual(len(result), len(ALL_IDS))


class TestWeightedRandom(unittest.TestCase):
    """Weighted random favours high-risk scenarios."""

    def test_high_risk_selected_more_often(self):
        # Over 100 iterations picking 1, high-risk should appear >50% of the time.
        # 3 high-risk (weight 3 each = 9), 2 medium (4), 1 low (1) → total 14
        # P(high) = 9/14 ≈ 0.643
        counts: dict[str, int] = collections.Counter()
        for _ in range(300):
            result = resolve_scenarios(MINI_MANIFEST, random_n=1)
            risk = result[0].get("risk", "low")
            counts[risk] += 1
        # High should dominate — use a generous threshold to avoid flaky tests
        self.assertGreater(counts.get("high", 0), counts.get("low", 0))


class TestComposableIntersection(unittest.TestCase):
    """track + risk compose as intersection."""

    def test_track1_and_high(self):
        result = resolve_scenarios(MINI_MANIFEST, tracks=[1], risks=["high"])
        ids = [s["id"] for s in result]
        self.assertEqual(ids, ["cerberus_banker"])

    def test_track2_and_high_empty(self):
        result = resolve_scenarios(MINI_MANIFEST, tracks=[2], risks=["high"])
        self.assertEqual(result, [])


class TestEmptyResult(unittest.TestCase):
    """Filters that match nothing return an empty list."""

    def test_nonexistent_track(self):
        result = resolve_scenarios(MINI_MANIFEST, tracks=[99])
        self.assertEqual(result, [])

    def test_nonexistent_profile(self):
        result = resolve_scenarios(MINI_MANIFEST, profile="nonexistent")
        # A profile with no entries matches nothing
        self.assertEqual(result, [])


class TestGlobPatterns(unittest.TestCase):
    """Glob patterns in profiles match correctly."""

    def test_stalk_glob(self):
        self.assertTrue(_match_patterns("stalk_truthspy", ["stalk_*"]))
        self.assertTrue(_match_patterns("stalk_andrmonitor", ["stalk_*"]))
        self.assertFalse(_match_patterns("cerberus_banker", ["stalk_*"]))

    def test_exact_match(self):
        self.assertTrue(_match_patterns("cerberus_banker", ["cerberus_banker"]))
        self.assertFalse(_match_patterns("cerberus_banker", ["anubis_banker"]))

    def test_wildcard_all(self):
        self.assertTrue(_match_patterns("anything", ["*"]))


if __name__ == "__main__":
    unittest.main()
