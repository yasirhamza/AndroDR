"""Lint test: source-ID to URL binding (AndroDR #119).

Will pass once the skill markdown (Phase 3) lands. Stays failing in
Phase 2's PR — intentional, signals Phase 3 is the completion step.
"""
import pathlib
import re

SKILL_PATH = pathlib.Path(__file__).resolve().parent.parent / "update-rules-discover.md"

EXPECTED_HOSTNAME_SUBSTRING = {
    "securelist":     "securelist.com",
    "welivesecurity": "welivesecurity.com",
    "zimperium":      "zimperium.com",
    "lookout":        "lookout.com",
    "google-tag":     "blog.google",
}


def test_skill_file_exists():
    assert SKILL_PATH.exists(), f"expected skill at {SKILL_PATH} (ships in Phase 3)"


def test_each_source_url_matches_hostname():
    content = SKILL_PATH.read_text()
    failures = []
    for source_id, expected_host in EXPECTED_HOSTNAME_SUBSTRING.items():
        m = re.search(rf"\b{re.escape(source_id)}\b", content)
        if m is None:
            failures.append(f"source_id {source_id!r} not mentioned in skill")
            continue
        window = content[m.start(): m.start() + 400]
        if expected_host not in window:
            failures.append(
                f"source_id {source_id!r} mentioned but hostname substring "
                f"{expected_host!r} not found within 400 chars"
            )
    assert not failures, "\n".join(failures)
