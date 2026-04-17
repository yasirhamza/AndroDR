"""Lint tests for the discover denylist (AndroDR #119).

The denylist is consulted by `--validate-tokens` mode to drop known-garbage
candidates before emission. This test guards the denylist itself against
two failure modes:

1. Structural: entries must be valid CamelCase tokens or two-word phrases.
2. Semantic: a well-meaning contributor must not add a real malware / APT
   name to the denylist — doing so would mute detection of that threat.

The guard-token list is inlined (hand-curated) since the prior
`known-families.yml` reference list was removed when extraction moved
fully to the LLM. Names in the guard list are the ones most likely to be
confused for plain English (Silver, Fox, Bitter, Predator) or for
well-meaning-but-wrong denylist entries.
"""
import pathlib
import re

import pytest
import yaml

DENYLIST_PATH = pathlib.Path(__file__).resolve().parent.parent / "fixtures" / "discover" / "denylist.yml"

# Real malware family / APT / CVE-adjacent tokens that must never appear in
# the denylist. A mix of single-word threats that collide with English,
# commonly-confused two-word names, and notable single-hump names.
KNOWN_REAL_THREAT_TOKENS = {
    # Android banker / stealer / trojan families
    "Anatsa", "BlackRock", "Brata", "Cerberus", "ClayRat", "FluBot",
    "GriftHorse", "Hook", "Joker", "Mandrake", "SharkBot", "TianySpy",
    "TrickMo", "Vultur", "XLoader",
    # Spyware / commercial surveillance
    "FinSpy", "Graphite", "Hermit", "NoviSpy", "Pegasus", "Predator",
    "ResidentBat", "SparkCat", "SparkKitty", "DCHSpy", "Massistant",
    "EagleMsgSpy",
    # APT group names (single-word variants that risk English-collision)
    "Anubis", "Lazarus", "Sandworm", "Bitter", "Turla", "Akira",
    "MuddyWater", "Tetrade",
    # Two-word APT / campaign names
    "Silver Fox", "Cozy Bear", "Fancy Bear", "Scattered Spider",
    "Operation Triangulation",
    # Cross-platform with Android payloads
    "Cellebrite",
    # Sub-words of two-word names that must also be safe from individual
    # denylisting (e.g., "Silver" alone would look English-y)
    "Silver", "Fox", "Cozy", "Fancy", "Bear",
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
