"""--validate-tokens must drop already-tracked threat names however the rule index is written.

2026-11-02: the dispatcher passed a comma-space list ("Albiriox, AndroRAT, ..."). The helper split
on "," without trimming, so only the first name matched and tracked threats (RatHat, PromptSpy,
NGate) went on to research. Slash aliases (BTMOB/BtmobRAT) and spelling variants (RATHat,
SuperCard X) also passed.
"""
import json
import pathlib
import subprocess
import sys

FIXTURES = pathlib.Path(__file__).resolve().parent.parent / "fixtures" / "discover"
SCRIPT = pathlib.Path(__file__).resolve().parent / "discover_extract.py"


def _filter(names, rule_index):
    r = subprocess.run(
        [sys.executable, str(SCRIPT), "--validate-tokens", "--denylist", str(FIXTURES / "denylist.yml"),
         "--rule-index", rule_index],
        input=json.dumps(names), capture_output=True, text=True, check=False, timeout=30)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def test_comma_space_index_matches_every_entry():
    index = "Albiriox, AndroRAT, RatHat, PromptSpy, NGate"
    assert _filter(["Albiriox", "RatHat", "PromptSpy", "NGate", "NewThreat"], index) == ["NewThreat"]


def test_slash_aliases_case_and_spacing_variants_match():
    index = "BTMOB/BtmobRAT, SuperCardX, RatHat, Graphite (Paragon)"
    got = _filter(["BtmobRAT", "btmob", "SuperCard X", "RATHat", "Super-Card-X", "Graphite (Paragon)", "KGB RAT"], index)
    assert got == ["KGB RAT"]


def test_empty_pieces_never_match():
    assert _filter(["Albiriox"], ", ,Albiriox,,") == []
    assert _filter(["NewThreat"], ",,  ,") == ["NewThreat"]
