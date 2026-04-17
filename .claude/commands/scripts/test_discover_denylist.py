"""Lint tests for the discover denylist (AndroDR #119)."""
import pathlib
import re

import pytest
import yaml

DENYLIST_PATH = pathlib.Path(__file__).resolve().parent.parent / "fixtures" / "discover" / "denylist.yml"

# Real malware family / APT names. If any of these appear in the denylist,
# the test fails — adding them would mute detection of the real threat.
# Tokens that look like plain English nouns (Silver, Fox, Bitter, Predator)
# carry extra risk of well-meaning denylist additions.
KNOWN_REAL_THREAT_TOKENS = {
    "SparkKitty", "SparkCat", "Anatsa", "TrickMo", "ClayRat",
    "BlackRock", "Joker", "FluBot", "Brata", "Hook", "Anubis",
    "GriftHorse", "Pegasus", "Predator", "Graphite", "Hermit",
    "Bitter", "Silver", "Fox", "Cozy", "Lazarus", "Sandworm",
    "Bear", "Mandrake", "Vultur", "SharkBot", "Cerberus",
}


@pytest.fixture(scope="module")
def denylist():
    data = yaml.safe_load(DENYLIST_PATH.read_text())
    assert data["version"] == 1
    return data["denylist"]


def test_no_duplicates(denylist):
    duplicates = [t for t in denylist if denylist.count(t) > 1]
    assert not duplicates, f"duplicate denylist entries: {sorted(set(duplicates))}"


def test_each_entry_well_formed(denylist):
    camelcase = re.compile(r"^[A-Z][a-zA-Z0-9]{2,}$")
    two_word = re.compile(r"^[A-Z][a-z]+ [A-Z][a-z]+$")
    for entry in denylist:
        assert camelcase.match(entry) or two_word.match(entry), (
            f"denylist entry {entry!r} is neither a valid CamelCase token "
            f"nor a two-word phrase"
        )


def test_no_real_threat_names(denylist):
    overlap = set(denylist) & KNOWN_REAL_THREAT_TOKENS
    assert not overlap, (
        f"denylist contains real malware/APT tokens: {sorted(overlap)}. "
        f"Adding these would mute detection of the real threat. If "
        f"intentional, update KNOWN_REAL_THREAT_TOKENS in this test AND "
        f"document why in the commit message."
    )
