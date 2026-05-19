"""Tests for audit_oem_prefixes.py — UAD-vs-YAML coverage diff."""
from __future__ import annotations

import json
from pathlib import Path

import yaml

import audit_oem_prefixes

FIXTURES = Path(__file__).parent / "fixtures"


def test_generate_report_matches_golden():
    uad = json.loads((FIXTURES / "audit_uad_sample.json").read_text())
    yaml_doc = yaml.safe_load((FIXTURES / "audit_yaml_sample.yml").read_text())
    expected = (FIXTURES / "audit_expected_report.md").read_text()

    actual = audit_oem_prefixes.generate_report(uad=uad, yaml_doc=yaml_doc)

    # rstrip on both sides — tolerates whether the fixture file (manually
    # authored from the plan's code block) ends in a trailing newline or
    # not, while still asserting all interior whitespace/blank-line structure.
    assert actual.rstrip("\n") == expected.rstrip("\n"), (
        f"Report mismatch.\nExpected:\n{expected}\n---Actual:\n{actual}"
    )


def test_derive_prefix_second_segment():
    assert audit_oem_prefixes.derive_prefix("com.hihonor.appmarket") == "com.hihonor."
    assert audit_oem_prefixes.derive_prefix("com.samsung.android.bixby.agent") == "com.samsung."
    assert audit_oem_prefixes.derive_prefix("org.lineageos.updater") == "org.lineageos."


def test_derive_prefix_handles_short_names():
    # Edge case: a package with only one segment — return as-is with trailing dot.
    assert audit_oem_prefixes.derive_prefix("android") == "android."
