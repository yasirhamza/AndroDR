#!/usr/bin/env python3
"""Regex-enhanced extraction for /update-rules discover (AndroDR #119).

Implements patterns 1-6 + post-filters + token-shape validator.
LLM fallback is NOT invoked by this helper — the skill orchestrates
LLM calls and pipes results back through --validate-tokens mode.

Modes:
  (default)         — read RSS file, emit candidates JSON
  --validate-tokens — read JSON list of names from stdin, filter via
                      denylist + rule-index + token-shape, emit filtered JSON
  --check-robots    — fetch <origin>/robots.txt, emit {allowed: bool} for path

Output (default mode, stdout):
    {
      "source_id": "...",
      "path": "rss",
      "candidates": [{threat_name, source_url, pub_date, confidence, pattern}, ...],
      "posts_processed": [{url, pub_date, candidate_count}, ...],
      "cursor_update": {"last_seen_timestamp": "...", "last_post_url": "..."},
      "error": null | {"kind": "fetch_error" | "parse_error", "message": "..."}
    }

`posts_processed` lets the skill identify zero-regex-hit posts (for LLM
fallback) without re-parsing the RSS itself.

`error.kind` distinguishes fetch vs parse failure per spec §cursor semantics
(partial-failure: both skip cursor advance, but operator diagnosis differs).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("pyyaml required: pip install pyyaml")


# ---- Regex patterns ---------------------------------------------------------

RE_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b")
RE_CATEGORY_SUFFIX = re.compile(
    r"\b[A-Z][a-zA-Z0-9]{2,}"
    r"(?:Kit|RAT|Stealer|Trojan|Spy|Bot|Banker|Loader|Dropper|Miner|Ransomware|Worm)\b"
)
RE_CAMELCASE = re.compile(r"\b(?:[A-Z][a-z]+){2,}\b")
RE_TWO_WORD = re.compile(r"\b([A-Z][a-z]+) ([A-Z][a-z]+)\b")
# Pattern 6: single-word capitalized with strict 3-word context gate.
# Requires 3+ lowercase letters, so minimum token length is 4 chars:
# "Good"/"This"/"Bitter" match; "The"/"New" don't. A trailing lookahead
# rejects hyphen-compounds ("China-aligned" would otherwise let "China"
# leak through as a threat candidate).
RE_SINGLE_WORD = re.compile(r"\b([A-Z][a-z]{3,})\b(?!-[a-z])")

# General malware context keywords (patterns 3, 4)
MALWARE_CONTEXT_KEYWORDS = {
    "trojan", "spyware", "malware", "banker", "stealer", "campaign",
    "spy", "backdoor", "surveillance", "apt", "botnet", "ransomware",
    "loader", "dropper", "rootkit", "rat", "cryptojacker", "infostealer",
    "mercenary", "hack-for-hire",
    "preys", "targets", "attacks", "exfiltrates", "hijacks",
}

# Strong-signal context keywords (pattern 6 — single-word requires these)
STRONG_SIGNAL_KEYWORDS = {
    "apt", "group", "actor", "trojan", "spyware", "malware", "campaign",
    "threat", "hack-for-hire", "mercenary", "ransomware", "banker",
    "stealer", "backdoor", "surveillance", "rat", "botnet",
}

# Grammatical-opener words that Pattern 4 must reject as word1 in a
# two-word match. "How Silver preys..." would otherwise emit "How Silver"
# as a threat name. These are sentence-initial capitalization artifacts,
# not parts of threat names.
TWO_WORD_STOPWORDS = {
    "The", "How", "New", "This", "That", "These", "Those",
    "A", "An", "In", "Of", "For", "With", "From", "Is", "Are",
    "Our", "Their", "Its", "Your", "My", "Some", "Any",
    "What", "Which", "When", "Where", "Why", "Who",
    "All", "Both", "Each", "Every", "Many", "Most",
    "But", "Or", "And", "So", "Yet", "If", "Because",
    "While", "Although", "Though", "After", "Before", "During",
}

# Token-shape validator (post-filter; applies to ALL extraction paths
# including LLM fallback — defends against shell metacharacters, URLs,
# pathologically long strings regardless of source).
RE_VALID_TOKEN = re.compile(r"^[A-Z][a-zA-Z0-9\- ]{2,40}$")

RSS_PUBDATE_FORMATS = [
    "%a, %d %b %Y %H:%M:%S %z",
    "%a, %d %b %Y %H:%M:%S %Z",
]


@dataclass
class Candidate:
    threat_name: str
    source_url: str
    pub_date: str
    confidence: str
    pattern: str

    def as_dict(self):
        return {
            "threat_name": self.threat_name,
            "source_url": self.source_url,
            "pub_date": self.pub_date,
            "confidence": self.confidence,
            "pattern": self.pattern,
        }


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


# ---- Context helpers --------------------------------------------------------

def _has_keyword_near(text: str, match_span: tuple[int, int], keywords: set[str], window_words: int) -> bool:
    start, end = match_span
    left_tokens = re.findall(r"[\w-]+", text[:start])[-window_words:]
    right_tokens = re.findall(r"[\w-]+", text[end:])[:window_words]
    context = [t.lower() for t in left_tokens + right_tokens]
    return any(kw in context for kw in keywords)


# ---- Extraction -------------------------------------------------------------

def extract_from_text(text: str, known_families: set[str]) -> list[tuple[str, str, bool]]:
    """Return list of (token, pattern_label, has_context) candidates.

    Dedup strategy:
    - `emitted_tokens` tracks exact-string tokens already emitted (all patterns)
    - `emitted_subwords` tracks constituent words of multi-word emissions
      (Pattern 5 "Silver Fox" → adds "Silver", "Fox"; Pattern 4 emission
      similarly). Prevents Pattern 6 from re-emitting a subword already
      covered by a more-specific match.

    Order is deliberate: Pattern 5 (known-families) first so known tokens
    claim the "known_family" label before Pattern 3 (camelcase) could
    reclassify them. Multi-word patterns (4, 5) run before single-word
    (6) so subwords are registered.

    Does not apply denylist or rule-index filter — caller's job.
    """
    out: list[tuple[str, str, bool]] = []
    emitted_tokens: set[str] = set()
    emitted_subwords: set[str] = set()

    def _register(token: str) -> None:
        emitted_tokens.add(token)
        # Split on whitespace to record constituent words
        for w in token.split():
            emitted_subwords.add(w)

    # Pattern 5: known-families reverse match (case-insensitive whole-word).
    # Longest matches first so "Silver Fox" wins over "Silver" if both exist
    # in the known-families list.
    text_lower = text.lower()
    for family in sorted(known_families, key=len, reverse=True):
        family_lower = family.lower()
        pat = re.compile(r"\b" + re.escape(family_lower) + r"\b")
        if pat.search(text_lower) and family not in emitted_tokens:
            # Check not already covered by a longer known-family match
            if not any(family_lower in t.lower() and t != family for t in emitted_tokens):
                out.append((family, "known_family", True))
                _register(family)

    # Pattern 1: CVE (distinct shape, no subword concerns)
    for m in RE_CVE.finditer(text):
        token = m.group(0)
        if token in emitted_tokens:
            continue
        out.append((token, "cve", True))
        _register(token)

    # Pattern 2: category-suffix
    for m in RE_CATEGORY_SUFFIX.finditer(text):
        token = m.group(0)
        if token in emitted_tokens:
            continue
        out.append((token, "category_suffix", True))
        _register(token)

    # Pattern 3: camelcase-novel
    for m in RE_CAMELCASE.finditer(text):
        token = m.group(0)
        if token in emitted_tokens:
            continue
        ctx = _has_keyword_near(text, m.span(), MALWARE_CONTEXT_KEYWORDS, window_words=5)
        label = "camelcase_with_context" if ctx else "camelcase_no_context"
        out.append((token, label, ctx))
        _register(token)

    # Pattern 4: two-word with context (context required).
    # Reject if word1 is a grammatical opener (stopword) OR if either
    # word is already a subword of a prior multi-word emission.
    for m in RE_TWO_WORD.finditer(text):
        word1, word2 = m.group(1), m.group(2)
        token = m.group(0)
        if token in emitted_tokens:
            continue
        if word1 in TWO_WORD_STOPWORDS:
            continue
        if word1 in emitted_subwords or word2 in emitted_subwords:
            continue  # already covered by a longer multi-word match
        if _has_keyword_near(text, m.span(), MALWARE_CONTEXT_KEYWORDS, window_words=5):
            out.append((token, "two_word_with_context", True))
            _register(token)

    # Pattern 6: single-word with STRONG context (strict 3-word gate).
    # Skip if the token is already a subword of an earlier emission
    # (e.g., "Silver" after "Silver Fox" was emitted).
    for m in RE_SINGLE_WORD.finditer(text):
        token = m.group(0)
        if token in emitted_tokens or token in emitted_subwords:
            continue
        if _has_keyword_near(text, m.span(), STRONG_SIGNAL_KEYWORDS, window_words=3):
            out.append((token, "single_word_with_context", True))
            _register(token)

    return out


# ---- Token-shape validator (post-filter, applies to LLM output too) --------

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

def _should_skip_via_cursor(post: Post, last_seen: datetime | None,
                            last_url: str | None, all_urls: set[str]) -> bool:
    """Apply cursor filter.

    Logic:
    - No cursor (bootstrap): pass everything.
    - Have cursor: skip posts with pub_date <= last_seen.
      The last_url field is a diagnostic belt-and-suspenders — if it's
      present but NOT in the current feed AND the cursor is >90 days
      old, we log `cms_migration_detected` in the caller (for operator
      visibility) but the filter decision is the same: timestamp-only.

    CMS-migration detection is diagnostic, not a different filter — the
    spec's intent is for operators to KNOW when a CMS migration may have
    happened (via log), but the cursor-advance behavior is identical to
    the normal case. Consolidated here so no dead branches.
    """
    if last_seen is None:
        return False
    return post.pub_date <= last_seen


def _detect_cms_migration(last_seen: datetime | None, last_url: str | None,
                          all_urls: set[str]) -> bool:
    """Diagnostic: has the source's CMS likely migrated to a new URL
    scheme? Used for log-only notification; does not change filter.
    """
    if last_seen is None or last_url is None:
        return False
    if last_url in all_urls:
        return False
    age_days = (datetime.now(timezone.utc) - last_seen).days
    return age_days > 90


# ---- Main -------------------------------------------------------------------

def run_extract(args) -> int:
    """Default mode: parse RSS, extract, emit candidates."""
    try:
        xml_bytes = Path(args.rss_file).read_bytes()
    except OSError as e:
        print(json.dumps({
            "source_id": args.source_id, "path": "rss",
            "candidates": [], "posts_processed": [],
            "error": {"kind": "fetch_error", "message": str(e)},
        }))
        return 2
    try:
        posts = parse_rss(xml_bytes)
    except ET.ParseError as e:
        print(json.dumps({
            "source_id": args.source_id, "path": "rss",
            "candidates": [], "posts_processed": [],
            "error": {"kind": "parse_error", "message": str(e)},
        }))
        return 2

    denylist = set(yaml.safe_load(Path(args.denylist).read_text())["denylist"])
    known_families = set(yaml.safe_load(Path(args.known_families).read_text())["families"])
    rule_index = set(args.rule_index.split(",")) if args.rule_index else set()

    # Parse optional cursor inputs (spec §cursor CMS-migration fallback)
    cursor_last_seen: datetime | None = None
    if args.cursor_last_seen_timestamp:
        cursor_last_seen = datetime.fromisoformat(
            args.cursor_last_seen_timestamp.replace("Z", "+00:00")
        ).astimezone(timezone.utc)
    cursor_last_url: str | None = args.cursor_last_url or None

    candidates: list[Candidate] = []
    posts_processed: list[dict] = []
    new_cursor_last_seen: datetime | None = None
    new_cursor_last_url: str | None = None
    seen_dedup: set[tuple[str, str]] = set()
    all_urls = {p.url for p in posts}

    for post in posts:
        if _should_skip_via_cursor(post, cursor_last_seen, cursor_last_url, all_urls):
            continue

        text = " \n ".join([post.title, post.description, post.body])
        raw_hits = extract_from_text(text, known_families)

        # Cursor advances to newest SURVIVING post (post-cursor-filter)
        new_cursor_last_seen = post.pub_date
        new_cursor_last_url = post.url

        post_candidate_count = 0
        for token, pattern_label, has_ctx in raw_hits:
            if token in denylist:
                continue
            if token in rule_index:
                continue
            if not is_valid_token_shape(token):
                continue
            key = (token, post.url)
            if key in seen_dedup:
                continue
            seen_dedup.add(key)
            confidence = "high" if has_ctx or pattern_label in {"cve", "category_suffix", "known_family"} else "low"
            candidates.append(Candidate(
                threat_name=token,
                source_url=post.url,
                pub_date=post.pub_date.strftime("%Y-%m-%dT%H:%M:%SZ"),
                confidence=confidence,
                pattern=pattern_label,
            ))
            post_candidate_count += 1

        posts_processed.append({
            "url": post.url,
            "pub_date": post.pub_date.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "candidate_count": post_candidate_count,
        })

    cms_migration = _detect_cms_migration(cursor_last_seen, cursor_last_url, all_urls)

    output = {
        "source_id": args.source_id,
        "path": "rss",
        "candidates": [c.as_dict() for c in candidates],
        "posts_processed": posts_processed,
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
    """Filter a JSON list of candidate names via token-shape + denylist +
    rule-index. Intended as the post-filter for LLM-fallback output.
    Also the structural XPIA defense line — see test_discover_xpia.py.
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

    # Parse: look for User-Agent: * block, collect Disallow: prefixes
    current_agent: str | None = None
    disallows: list[str] = []
    for line in body.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        if ":" not in line:
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
    ap.add_argument("--known-families")
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
    if not args.rss_file or not args.source_id or not args.known_families:
        ap.error("default mode requires --source-id, --rss-file, --known-families")
    sys.exit(run_extract(args))


if __name__ == "__main__":
    main()
