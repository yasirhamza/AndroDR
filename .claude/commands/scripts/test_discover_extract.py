"""Tests for discover_extract.py post-parser + cursor semantics (AndroDR #119).

The extractor no longer does regex pattern matching — that's the LLM's job
(see `update-rules-discover.md`). The helper's remaining responsibilities:

- Parse RSS into a canonical post list.
- Apply the cursor filter (timestamp-only, bootstrap on empty cursor).
- Emit a cursor-advance block for whatever post was newest on this run.
- Flag CMS-migration suspicion (diagnostic; doesn't change filter behavior).

XPIA / token-shape / denylist / rule-index coverage lives in
`test_discover_xpia.py` — those tests exercise `--validate-tokens` mode.
"""
import json
import pathlib
import subprocess
import sys
import tempfile

FIXTURES = pathlib.Path(__file__).resolve().parent.parent / "fixtures" / "discover"
SCRIPT = pathlib.Path(__file__).resolve().parent / "discover_extract.py"


def _run(rss_path, source_id, cursor_ts="", cursor_url=""):
    args = [
        sys.executable, str(SCRIPT),
        "--source-id", source_id,
        "--rss-file", str(rss_path),
        "--denylist", str(FIXTURES / "denylist.yml"),
    ]
    if cursor_ts:
        args += ["--cursor-last-seen-timestamp", cursor_ts]
    if cursor_url:
        args += ["--cursor-last-url", cursor_url]
    result = subprocess.run(args, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise AssertionError(
            f"discover_extract.py failed (rc={result.returncode}):\n"
            f"STDOUT: {result.stdout!r}\n"
            f"STDERR: {result.stderr!r}\n"
            f"ARGS: {args}"
        )
    return json.loads(result.stdout)


def _write_rss(tmp_path, items):
    """Build a minimal RSS 2.0 file from a list of (title, url, pubdate, desc) tuples."""
    lines = [
        '<?xml version="1.0"?>',
        '<rss version="2.0"><channel>',
        '<title>test</title><link>https://example.test</link><description>t</description>',
    ]
    for t, u, p, d in items:
        lines.append(
            f"<item><title>{t}</title><link>{u}</link>"
            f"<pubDate>{p}</pubDate><description>{d}</description></item>"
        )
    lines.append('</channel></rss>')
    rss = tmp_path / "feed.xml"
    rss.write_text("\n".join(lines) + "\n")
    return rss


def test_parse_returns_posts_with_required_fields(tmp_path):
    rss = _write_rss(tmp_path, [
        ("Post A", "https://example.test/a", "Mon, 06 Apr 2026 10:00:00 +0000", "desc-a"),
        ("Post B", "https://example.test/b", "Tue, 07 Apr 2026 10:00:00 +0000", "desc-b"),
    ])
    out = _run(rss, "testsrc")
    assert out["source_id"] == "testsrc"
    assert out["error"] is None
    assert len(out["posts"]) == 2
    for p in out["posts"]:
        assert set(p) == {"url", "pub_date", "title", "description", "body"}
    # Sorted ascending by pub_date
    assert out["posts"][0]["pub_date"] < out["posts"][1]["pub_date"]


def test_parse_emits_cursor_update_to_newest_post(tmp_path):
    rss = _write_rss(tmp_path, [
        ("A", "https://example.test/a", "Mon, 06 Apr 2026 10:00:00 +0000", "d"),
        ("B", "https://example.test/b", "Tue, 07 Apr 2026 10:00:00 +0000", "d"),
    ])
    out = _run(rss, "testsrc")
    assert out["cursor_update"]["last_seen_timestamp"] == "2026-04-07T10:00:00Z"
    assert out["cursor_update"]["last_post_url"] == "https://example.test/b"


def test_cursor_filter_skips_already_seen_posts(tmp_path):
    rss = _write_rss(tmp_path, [
        ("old", "https://example.test/old", "Mon, 06 Apr 2026 10:00:00 +0000", "d"),
        ("new", "https://example.test/new", "Tue, 07 Apr 2026 10:00:00 +0000", "d"),
    ])
    out = _run(rss, "testsrc", cursor_ts="2026-04-06T10:00:00Z",
               cursor_url="https://example.test/old")
    titles = [p["title"] for p in out["posts"]]
    assert titles == ["new"], f"cursor should have excluded 'old': got {titles}"
    # Cursor advances to the new post
    assert out["cursor_update"]["last_post_url"] == "https://example.test/new"


def test_cursor_on_empty_feed_omits_cursor_update(tmp_path):
    """If every post is filtered out (all older than cursor), no cursor_update
    is emitted — nothing new happened on this source, leave cursor unchanged."""
    rss = _write_rss(tmp_path, [
        ("only", "https://example.test/only", "Mon, 06 Apr 2026 10:00:00 +0000", "d"),
    ])
    out = _run(rss, "testsrc", cursor_ts="2026-04-10T00:00:00Z",
               cursor_url="https://example.test/only")
    assert out["posts"] == []
    assert "cursor_update" not in out


def test_malformed_pubdate_is_silently_dropped(tmp_path):
    """A single bad pubDate should not fail the whole feed — skip and continue."""
    rss = _write_rss(tmp_path, [
        ("good", "https://example.test/good", "Mon, 06 Apr 2026 10:00:00 +0000", "d"),
        ("bad",  "https://example.test/bad",  "not-a-date",                      "d"),
    ])
    out = _run(rss, "testsrc")
    titles = [p["title"] for p in out["posts"]]
    assert titles == ["good"]


def test_cms_migration_flag_fires_when_old_cursor_url_absent(tmp_path):
    """Cursor >90 days old AND cursor's last_post_url not in current feed →
    flag (diagnostic only; does not change the filter result)."""
    rss = _write_rss(tmp_path, [
        ("current", "https://example.test/current", "Tue, 07 Apr 2026 10:00:00 +0000", "d"),
    ])
    # 100 days ago relative to the feed content — but datetime.now() in the
    # helper uses wall-clock. Pass an obviously-ancient cursor.
    out = _run(rss, "testsrc",
               cursor_ts="2020-01-01T00:00:00Z",
               cursor_url="https://old-cms.example.test/very-old-post")
    assert out["cms_migration_detected"] is True


def test_cms_migration_flag_stays_false_when_cursor_url_still_present(tmp_path):
    rss = _write_rss(tmp_path, [
        ("kept", "https://example.test/kept", "Tue, 07 Apr 2026 10:00:00 +0000", "d"),
    ])
    out = _run(rss, "testsrc",
               cursor_ts="2020-01-01T00:00:00Z",
               cursor_url="https://example.test/kept")
    assert out["cms_migration_detected"] is False


def test_missing_rss_file_returns_fetch_error():
    result = subprocess.run(
        [sys.executable, str(SCRIPT),
         "--source-id", "testsrc",
         "--rss-file", "/nonexistent/path.xml",
         "--denylist", str(FIXTURES / "denylist.yml")],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 2
    out = json.loads(result.stdout)
    assert out["error"]["kind"] == "fetch_error"
    assert out["posts"] == []


def test_malformed_xml_returns_parse_error(tmp_path):
    bad = tmp_path / "bad.xml"
    bad.write_text("<rss>not-closed")
    result = subprocess.run(
        [sys.executable, str(SCRIPT),
         "--source-id", "testsrc",
         "--rss-file", str(bad),
         "--denylist", str(FIXTURES / "denylist.yml")],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 2
    out = json.loads(result.stdout)
    assert out["error"]["kind"] == "parse_error"


def test_real_rss_fixtures_parse_cleanly():
    """Smoke test against the checked-in vendor RSS fixtures. The helper
    must parse all three without raising — content-level extraction is
    the LLM's job, so no assertions on specific post counts."""
    for source_id in ("securelist", "welivesecurity", "google-tag"):
        rss = FIXTURES / f"{source_id}.xml"
        out = _run(rss, source_id)
        assert out["error"] is None
        assert isinstance(out["posts"], list)
        # The checked-in fixtures all contain at least one well-formed item
        assert len(out["posts"]) >= 1, f"{source_id} fixture parsed to zero posts"
