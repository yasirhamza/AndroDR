"""Golden-fixture tests for discover_extract.py (AndroDR #119).

Each test invokes discover_extract.py with a fixture RSS and asserts
the script's JSON stdout matches the committed expected JSON canonically.
"""
import json
import pathlib
import subprocess
import sys

import pytest

FIXTURES = pathlib.Path(__file__).resolve().parent.parent / "fixtures" / "discover"
SCRIPT = pathlib.Path(__file__).resolve().parent / "discover_extract.py"


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, indent=2)


def _run(fixture_xml, source_id, rule_index=None):
    args = [
        sys.executable, str(SCRIPT),
        "--source-id", source_id,
        "--rss-file", str(fixture_xml),
        "--denylist", str(FIXTURES / "denylist.yml"),
        "--known-families", str(FIXTURES / "known-families.yml"),
    ]
    if rule_index:
        args += ["--rule-index", ",".join(rule_index)]
    result = subprocess.run(args, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise AssertionError(f"discover_extract.py failed:\n{result.stderr}")
    return json.loads(result.stdout)


@pytest.mark.parametrize("source_id", ["securelist", "welivesecurity", "google-tag"])
def test_golden_extraction(source_id):
    fixture = FIXTURES / f"{source_id}.xml"
    expected_path = FIXTURES / f"{source_id}-expected.json"
    expected = json.loads(expected_path.read_text())
    actual = _run(fixture, source_id)
    assert _canonical(actual) == _canonical(expected), (
        f"\nActual:\n{_canonical(actual)}\n\nExpected:\n{_canonical(expected)}"
    )


def test_rule_index_drops_already_tracked():
    fixture = FIXTURES / "securelist.xml"
    actual = _run(fixture, "securelist", rule_index=["SparkKitty", "Bitter"])
    names = [c["threat_name"] for c in actual["candidates"]]
    assert "SparkKitty" not in names
    assert "Bitter" not in names
    assert "SparkCat" in names
    assert "Silver Fox" in names
    assert "CVE-2026-0049" in names
