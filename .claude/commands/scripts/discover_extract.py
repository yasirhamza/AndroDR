#!/usr/bin/env python3
"""Post-parser + structural validator for /update-rules discover (AndroDR #119).

The prior revision of this script carried six regex patterns that tried to
extract threat names directly from post text. Dogfooding showed the regex
stack produced mostly grammatical noise ("Interestingly", "Additionally",
"Leveraging", ...) while missing single-hump names like "Massistant" — and
the top-N ranking was dominated by false positives. The fix is architectural:
the LLM is the only extractor. This script is a supporting helper, not an
extractor itself.

Responsibilities retained
-------------------------
1. **Parse mode** (default): read an RSS file, emit the post list
   (url / pub_date / title / description / body) for the skill orchestrator
   to loop over with per-post LLM prompts. Applies the cursor filter and
   emits cursor-advance metadata.
2. **Validate-tokens mode** (`--validate-tokens`): accept a JSON list of
   candidate strings from stdin and apply the structural post-filter —
   denylist, rule-index, token shape. This is the XPIA defense line; every
   LLM-extracted name passes through it before emission.
3. **Robots-check mode** (`--check-robots`): fetch `<origin>/robots.txt`
   and report whether the given URL is allowed.

Responsibilities removed
------------------------
- Regex patterns 1-6 and their keyword/stopword sets.
- `--known-families` argument and the reverse-match loop it fed.
- `Candidate` emission from default mode. Default mode now emits `posts`
  only; candidate naming is the skill's job.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as _ET  # for ParseError class reference

try:
    import defusedxml.ElementTree as ET
except ImportError:
    sys.exit("defusedxml required: pip install defusedxml")
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("pyyaml required: pip install pyyaml")


# Token-shape validator — the structural XPIA defense.
# Applies to every LLM-extracted candidate before emission, regardless of
# how plausible the LLM's prose response was.
RE_VALID_TOKEN = re.compile(r"^[A-Z][a-zA-Z0-9\- ]{2,40}$")

RSS_PUBDATE_FORMATS = [
    "%a, %d %b %Y %H:%M:%S %z",
    "%a, %d %b %Y %H:%M:%S %Z",
]


@dataclass
class Post:
    title: str
    url: str
    pub_date: datetime
    description: str
    body: str


# ---- RSS parsing ------------------------------------------------------------

def parse_pubdate(raw: str) -> datetime:
    raw = raw.strip()
    for fmt in RSS_PUBDATE_FORMATS:
        try:
            dt = datetime.strptime(raw, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            continue
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        raise ValueError(f"unrecognized RSS pubDate format: {raw!r}")


def parse_rss(xml_bytes: bytes) -> list[Post]:
    ns = {"content": "http://purl.org/rss/1.0/modules/content/"}
    root = ET.fromstring(xml_bytes)
    channel = root.find("channel")
    if channel is None:
        return []
    posts: list[Post] = []
    for item in channel.findall("item"):
        title = (item.findtext("title") or "").strip()
        url = (item.findtext("link") or "").strip()
        raw_pub = item.findtext("pubDate") or ""
        description = (item.findtext("description") or "").strip()
        body_el = item.find("content:encoded", ns)
        body = (body_el.text or "").strip() if body_el is not None else ""
        if not title or not url or not raw_pub:
            continue
        try:
            pub_date = parse_pubdate(raw_pub)
        except ValueError:
            continue
        posts.append(Post(title=title, url=url, pub_date=pub_date,
                          description=description, body=body))
    posts.sort(key=lambda p: p.pub_date)
    return posts


# ---- Token-shape validator (post-filter, applies to ALL LLM output) --------

def is_valid_token_shape(token: str) -> bool:
    """Reject shell metacharacters, URLs, over-length strings."""
    if not RE_VALID_TOKEN.match(token):
        return False
    # Defense-in-depth: reject known metacharacters even if regex somehow allowed
    for c in "$|;`&><":
        if c in token:
            return False
    return True


# ---- Cursor handling (CMS-migration fallback) -------------------------------

def _should_skip_via_cursor(post: Post, last_seen: datetime | None) -> bool:
    """Skip posts already seen on a prior run. Bootstrap (no cursor) passes all."""
    if last_seen is None:
        return False
    return post.pub_date <= last_seen


def _detect_cms_migration(last_seen: datetime | None, last_url: str | None,
                          all_urls: set[str]) -> bool:
    """Diagnostic: a cursor URL that disappeared from a >90-day-old feed
    suggests a CMS migration to a new URL scheme. Log-only; the cursor
    filter decision itself is unchanged (timestamp-only).
    """
    if last_seen is None or last_url is None:
        return False
    if last_url in all_urls:
        return False
    age_days = (datetime.now(timezone.utc) - last_seen).days
    return age_days > 90


# ---- Main modes -------------------------------------------------------------

def run_parse_posts(args) -> int:
    """Default mode: parse RSS, emit posts for LLM extraction downstream.

    Output shape (stdout, pretty-printed JSON):
        {
          "source_id": "...",
          "path": "rss",
          "posts": [
            {"url": ..., "pub_date": ..., "title": ..., "description": ..., "body": ...},
            ...
          ],
          "cursor_update": {"last_seen_timestamp": ..., "last_post_url": ...} | absent,
          "cms_migration_detected": bool,
          "error": null | {"kind": "fetch_error" | "parse_error", "message": "..."}
        }

    `posts` is ordered newest-last (ascending pub_date) — the skill picks
    which to feed to its LLM prompt based on rank/slice rules.
    """
    try:
        xml_bytes = Path(args.rss_file).read_bytes()
    except OSError as e:
        print(json.dumps({
            "source_id": args.source_id, "path": "rss",
            "posts": [],
            "error": {"kind": "fetch_error", "message": str(e)},
        }))
        return 2
    try:
        posts = parse_rss(xml_bytes)
    except ET.ParseError as e:
        print(json.dumps({
            "source_id": args.source_id, "path": "rss",
            "posts": [],
            "error": {"kind": "parse_error", "message": str(e)},
        }))
        return 2

    cursor_last_seen: datetime | None = None
    if args.cursor_last_seen_timestamp:
        cursor_last_seen = datetime.fromisoformat(
            args.cursor_last_seen_timestamp.replace("Z", "+00:00")
        ).astimezone(timezone.utc)
    cursor_last_url: str | None = args.cursor_last_url or None

    emitted: list[dict] = []
    new_cursor_last_seen: datetime | None = None
    new_cursor_last_url: str | None = None
    all_urls = {p.url for p in posts}

    for post in posts:
        if _should_skip_via_cursor(post, cursor_last_seen):
            continue
        new_cursor_last_seen = post.pub_date
        new_cursor_last_url = post.url
        emitted.append({
            "url": post.url,
            "pub_date": post.pub_date.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "title": post.title,
            "description": post.description,
            "body": post.body,
        })

    cms_migration = _detect_cms_migration(cursor_last_seen, cursor_last_url, all_urls)

    output: dict = {
        "source_id": args.source_id,
        "path": "rss",
        "posts": emitted,
        "cms_migration_detected": cms_migration,
        "error": None,
    }
    if new_cursor_last_seen is not None:
        output["cursor_update"] = {
            "last_seen_timestamp": new_cursor_last_seen.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "last_post_url": new_cursor_last_url,
        }
    print(json.dumps(output, sort_keys=True, indent=2, ensure_ascii=False))
    return 0


def run_validate_tokens(args) -> int:
    """Filter a JSON list of candidate names from stdin via token-shape +
    denylist + rule-index. The structural XPIA defense line — see
    test_discover_xpia.py.
    """
    raw = sys.stdin.read()
    try:
        candidates = json.loads(raw)
        if not isinstance(candidates, list) or not all(isinstance(c, str) for c in candidates):
            raise ValueError("expected JSON list of strings")
    except (json.JSONDecodeError, ValueError) as e:
        print(json.dumps({"error": f"invalid input: {e}"}))
        return 2

    denylist = set(yaml.safe_load(Path(args.denylist).read_text())["denylist"])
    rule_index = set(args.rule_index.split(",")) if args.rule_index else set()

    filtered: list[str] = []
    for name in candidates[:20]:  # Cap at 20 — guards against flood-attack LLM output
        if name in denylist:
            continue
        if name in rule_index:
            continue
        if not is_valid_token_shape(name):
            continue
        filtered.append(name)

    print(json.dumps(filtered))
    return 0


def run_check_robots(args) -> int:
    """Fetch <origin>/robots.txt and emit {allowed: bool} for the given path.
    Minimal robots.txt parser: checks User-Agent: * Disallow: rules.
    """
    import urllib.parse
    import urllib.request
    parsed = urllib.parse.urlparse(args.check_robots)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    robots_url = f"{origin}/robots.txt"
    path = parsed.path or "/"
    try:
        req = urllib.request.Request(robots_url, headers={
            "User-Agent": "AndroDR-AI-Rule-Pipeline/1.0 (+https://github.com/yasirhamza/AndroDR)"
        })
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except Exception:
        # Per spec: robots.txt fetch failure → allow (err on the side of trying)
        print(json.dumps({"allowed": True, "reason": "robots_fetch_failed"}))
        return 0

    current_agent: str | None = None
    disallows: list[str] = []
    for line in body.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, val = [p.strip() for p in line.split(":", 1)]
        key_lower = key.lower()
        if key_lower == "user-agent":
            current_agent = val
        elif key_lower == "disallow" and current_agent == "*":
            if val:
                disallows.append(val)
    allowed = not any(path.startswith(d) for d in disallows)
    print(json.dumps({"allowed": allowed, "disallow_rules": disallows}))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--source-id")
    ap.add_argument("--rss-file")
    ap.add_argument("--denylist", required=True)
    ap.add_argument("--rule-index", default="")
    ap.add_argument("--cursor-last-seen-timestamp", default="")
    ap.add_argument("--cursor-last-url", default="")
    ap.add_argument("--validate-tokens", action="store_true",
                    help="Read JSON list of names from stdin, emit filtered list")
    ap.add_argument("--check-robots",
                    help="URL to check against <origin>/robots.txt — emits {allowed: bool}")
    args = ap.parse_args()

    if args.validate_tokens:
        sys.exit(run_validate_tokens(args))
    if args.check_robots:
        sys.exit(run_check_robots(args))
    if not args.rss_file or not args.source_id:
        ap.error("default (parse) mode requires --source-id and --rss-file")
    sys.exit(run_parse_posts(args))


if __name__ == "__main__":
    main()
