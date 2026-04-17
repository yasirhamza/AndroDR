"""Lint tests for the discover denylist (AndroDR #119)."""
import pathlib
import re

import pytest
import yaml

DENYLIST_PATH = pathlib.Path(__file__).resolve().parent.parent / "fixtures" / "discover" / "denylist.yml"

# Real malware family / APT names. Derived at test time from
# known-families.yml (the authoritative list) UNIONED with a small set of
# extra real tokens that might not be in the families list but could still
# drift into the denylist by mistake. If any of these appear in the
# denylist, the test fails — adding them would mute detection of the real
# threat. Tokens like Silver, Fox, Bitter, Predator look like plain English
# nouns and carry extra risk of well-meaning denylist additions.
FAMILIES_PATH = pathlib.Path(__file__).resolve().parent.parent / "fixtures" / "discover" / "known-families.yml"
_families_data = yaml.safe_load(FAMILIES_PATH.read_text())
# Split two-word entries into individual tokens so "Silver Fox" also guards
# "Silver" and "Fox" from being denylisted individually.
_family_tokens = set()
for entry in _families_data["families"]:
    _family_tokens.add(entry)
    for word in entry.split():
        if len(word) >= 3:  # skip trivial like "of"
            _family_tokens.add(word)

# Extra tokens that might not survive as a family entry but still must never
# appear in the denylist (catch-all for commonly-confused plain-English names).
_extra_guard_tokens = {
    "Silver", "Fox", "Bear", "Cozy", "Fancy",
}

KNOWN_REAL_THREAT_TOKENS = _family_tokens | _extra_guard_tokens


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
