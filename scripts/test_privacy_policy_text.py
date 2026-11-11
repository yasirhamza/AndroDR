"""The public privacy policy must describe what a privacy scan keeps, and for how long.

A privacy scan's results (the trackers found, the matching code packages, the tracker domains each
app looked up) are kept until the next privacy scan replaces them or the person chooses "Delete
privacy results": they are not covered by the 30-day automatic deletion. The policy promised 30-day
deletion in several places; each of those statements must now carry the privacy-scan exception on
the same line, and the policy must say plainly how privacy scan results are kept. This check runs
in CI's python-pipeline job on any change to the policy (spec 2026-11-10, sections 8 and 9).
"""
import pathlib
import re

POLICY = pathlib.Path(__file__).resolve().parent.parent / "docs" / "PRIVACY_POLICY.md"

# Lines that mention 30 days about something other than DNS, usage or Timeline retention.
UNRELATED_30_DAY_MARKERS = (
    "| Forensic timeline events",  # Part B moves this row under the rule.
    "from the import",  # Intrusion-log imports: a different limit.
)


def _policy() -> str:
    return POLICY.read_text(encoding="utf-8")


def _section(text: str, heading: str) -> str:
    match = re.search(rf"^## {re.escape(heading)}\n(.*?)(?=^## |\Z)", text, re.MULTILINE | re.DOTALL)
    assert match, f"no section '## {heading}'"
    return match.group(1)


def bare_thirty_day_lines(text: str) -> list[str]:
    """Lines that state the 30-day deletion without naming the privacy-scan exception."""
    return [
        line for line in text.splitlines()
        if "30 days" in line
        and "privacy scan" not in line.lower()
        and not any(marker in line for marker in UNRELATED_30_DAY_MARKERS)
    ]


def test_the_policy_says_how_long_privacy_scan_results_are_kept():
    body = _section(_policy(), "Privacy Scan").lower()
    for phrase in ("until the next privacy scan replaces", "delete privacy results", "30 days",
                   "exported report", "never leave"):
        assert phrase in body, phrase


def test_every_30_day_statement_names_the_privacy_scan_exception():
    assert bare_thirty_day_lines(_policy()) == []


def test_a_bare_30_day_line_is_noticed():
    assert len(bare_thirty_day_lines("- DNS logs are deleted after 30 days\n")) == 1
    assert bare_thirty_day_lines(
        "- DNS logs are deleted after 30 days (a privacy scan's results are kept separately)\n") == []


def test_the_play_summary_states_the_exception_twice():
    play = _section(_policy(), "Google Play Data Safety Alignment")
    for label in ("**Data collected:**", "**Data deletion:**"):
        line = next(line for line in play.splitlines() if label in line)
        assert "privacy scan" in line.lower(), label


def test_the_policy_still_says_androdr_collects_no_data():
    assert "AndroDR collects no data" in _policy()
