"""Lint test: exact source-ID → URL binding (AndroDR #119, exact-URL lock).

Asserts the discover skill's source URLs match EXPECTED_SOURCE_URLS
EXACTLY — same-host path changes fail, which the old hostname-substring
lock could not see. This test must always pass; edit EXPECTED_SOURCE_URLS
in the same commit as any URL change.
"""
import pathlib
import re

SKILL_PATH = pathlib.Path(__file__).resolve().parent.parent / "update-rules-discover.md"

EXPECTED_SOURCE_URLS = {
    "securelist":     "https://securelist.com/feed/",
    "welivesecurity": "https://www.welivesecurity.com/en/rss/feed/",
    "zimperium":      "https://zimperium.com/blog",
    "google-tag":     "https://blog.google/security/rss/",
    "threatfabric":   "https://www.threatfabric.com/blogs",
    "cleafy":         "https://www.cleafy.com/labs",
    "group-ib":       "https://www.group-ib.com/blog/",
}


def test_skill_file_exists():
    assert SKILL_PATH.exists(), f"expected skill at {SKILL_PATH} (ships in Phase 3)"


def test_each_source_url_has_exact_expected_url():
    content = SKILL_PATH.read_text()
    failures = []
    for source_id, expected_url in EXPECTED_SOURCE_URLS.items():
        m = re.search(rf"\b{re.escape(source_id)}\b", content)
        if m is None:
            failures.append(f"source_id {source_id!r} not mentioned in skill")
            continue
        window = content[m.start(): m.start() + 400]
        if expected_url not in window:
            failures.append(
                f"source_id {source_id!r} mentioned but exact URL "
                f"{expected_url!r} not found within 400 chars — same-host "
                f"URL moves are the silent-rot class this lock exists for"
            )
    assert not failures, "\n".join(failures)
