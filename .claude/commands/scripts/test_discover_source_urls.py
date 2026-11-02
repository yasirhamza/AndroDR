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
    "lookout":        "security.lookout.com",
    "google-tag":     "blog.google",
    "threatfabric":   "threatfabric.com",
    "cleafy":         "cleafy.com",
    "group-ib":       "group-ib.com",
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


def _table_row(content, source_id):
    m = re.search(rf"^\| `{re.escape(source_id)}` \| `([^`]+)` \|$", content, re.M)
    assert m, f"no source-table row for {source_id!r}"
    return m


def test_threatfabric_is_read_from_its_rss_feed():
    # 2026-11-02: the /blogs index page has no publication dates, so the web path emitted 0 posts
    # and the cursor never advanced. Its RSS feed carries pubDate.
    content = SKILL_PATH.read_text()
    m = _table_row(content, "threatfabric")
    assert m.group(1) == "https://www.threatfabric.com/blogs/rss.xml"
    rss_end = content.index("### Web path")
    assert m.start() < rss_end, "threatfabric must be in the RSS table, not the web table"


def test_lookout_avoids_the_host_that_403s_the_pipeline():
    # 2026-11-02: www.lookout.com answers 403 for every path; security.lookout.com serves the posts.
    assert _table_row(SKILL_PATH.read_text(), "lookout").group(1) == "https://security.lookout.com/threat-intelligence"
