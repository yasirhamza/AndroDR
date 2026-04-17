"""Lint tests for the known-families list (AndroDR #119)."""
import pathlib
import re

import pytest
import yaml

PATH = pathlib.Path(__file__).resolve().parent.parent / "fixtures" / "discover" / "known-families.yml"


@pytest.fixture(scope="module")
def families():
    data = yaml.safe_load(PATH.read_text())
    assert data["version"] == 1
    return data["families"]


def test_no_duplicates(families):
    duplicates = [t for t in families if families.count(t) > 1]
    assert not duplicates, f"duplicate known-family entries: {sorted(set(duplicates))}"


def test_each_entry_well_formed(families):
    # CamelCase, single capitalized word, or two-word phrase
    valid = re.compile(r"^[A-Z][a-zA-Z0-9]{2,}$|^[A-Z][a-z]+ [A-Z][a-z]+$")
    for entry in families:
        assert valid.match(entry), f"malformed known-family entry {entry!r}"


def test_minimum_size(families):
    assert len(families) >= 30, f"known-families list should have ≥30 entries; got {len(families)}"
