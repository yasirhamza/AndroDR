"""Render docs/PRIVACY_POLICY.md into the privacy section of a target HTML file.

Usage:
    python3 render_privacy.py <markdown-path> <target-html-path>

Targets: cloudflare-worker.js (in this repo) and index.html (in androdr-site).
Both files have <!-- ANDRODR:PRIVACY:START --> ... <!-- ANDRODR:PRIVACY:END -->
fence markers; this script replaces the region between them.

The script:
  1. Parses the markdown into an HTML fragment with the 'tables' extension.
  2. Wraps it in <section class="privacy" id="privacy">...</section>
     so existing CSS in both target files applies unchanged.
  3. Asserts structural invariants (expected <h2> and <table> counts); exits
     non-zero if they don't match. Update EXPECTED_H2 / EXPECTED_TABLES in the
     same commit that deliberately changes the privacy structure.
  4. Replaces the fenced region in the target file.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import markdown

# Locked on 2026-04-24 against docs/PRIVACY_POLICY.md. Update in the same
# commit that deliberately adds/removes a top-level section or table.
EXPECTED_H2 = 18
EXPECTED_TABLES = 3

FENCE_START = "<!-- ANDRODR:PRIVACY:START -->"
FENCE_END = "<!-- ANDRODR:PRIVACY:END -->"

LAST_UPDATED_RE = re.compile(r"^_Last updated:\s*(\d{4}-\d{2}-\d{2})_\s*$", re.MULTILINE)


def extract_last_updated(md_text: str) -> str | None:
    """Pull the YYYY-MM-DD from a line like `_Last updated: 2026-04-24_`."""
    m = LAST_UPDATED_RE.search(md_text)
    return m.group(1) if m else None


def render(md_text: str) -> str:
    """Convert markdown to an HTML fragment wrapped in <section class="privacy">.

    The rendered fragment mirrors the structure the current target files use,
    so the existing .privacy CSS selectors apply without change. The top
    `# AndroDR Privacy Policy` H1 in the markdown is dropped (the H2 "Privacy
    Policy" title lives in the HTML template), and the `_Last updated: ..._`
    line is rendered as `<p><em>Last updated: YYYY-MM-DD</em></p>` at the top
    of the fragment so the date stays visible.
    """
    last_updated = extract_last_updated(md_text)
    # Strip the H1 and the last-updated line; we'll re-inject the date below.
    body = re.sub(r"^#\s+.*\n", "", md_text, count=1)
    body = LAST_UPDATED_RE.sub("", body, count=1).lstrip()
    inner = markdown.markdown(body, extensions=["tables"])
    if last_updated:
        inner = f'<p><em>Last updated: {last_updated}</em></p>\n{inner}'
    return f'<section class="privacy" id="privacy">\n<h2>Privacy Policy</h2>\n{inner}\n</section>'


def assert_structural_invariants(html: str, expected_h2: int = EXPECTED_H2,
                                 expected_tables: int = EXPECTED_TABLES) -> None:
    """Raise AssertionError if rendered HTML deviates from expected structure."""
    h2_count = len(re.findall(r"<h2[^>]*>", html))
    # First <h2> is the "Privacy Policy" title we inject; source markdown
    # contributes the rest.
    source_h2 = h2_count - 1
    assert source_h2 == expected_h2, (
        f"expected {expected_h2} h2 headings from source, got {source_h2}. "
        f"If this change is deliberate, update EXPECTED_H2 in render_privacy.py."
    )
    table_count = html.count("<table>")
    assert table_count == expected_tables, (
        f"expected {expected_tables} table blocks, got {table_count}. "
        f"If this change is deliberate, update EXPECTED_TABLES in render_privacy.py."
    )


def replace_fenced_region(template: str, new_section: str) -> str:
    """Replace everything between FENCE_START and FENCE_END with new_section.

    Preserves the fence comments themselves. Raises if either fence is missing.
    """
    if FENCE_START not in template or FENCE_END not in template:
        raise ValueError(
            f"fence markers not found in template; expected both "
            f"{FENCE_START!r} and {FENCE_END!r}"
        )
    pattern = re.compile(
        re.escape(FENCE_START) + r".*?" + re.escape(FENCE_END),
        re.DOTALL,
    )
    replacement = f"{FENCE_START}\n{new_section}\n{FENCE_END}"
    return pattern.sub(replacement, template, count=1)


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(f"usage: {argv[0]} <markdown-path> <target-html-path>", file=sys.stderr)
        return 2
    md_path = Path(argv[1])
    target_path = Path(argv[2])
    md_text = md_path.read_text(encoding="utf-8")
    rendered = render(md_text)
    assert_structural_invariants(rendered)
    template = target_path.read_text(encoding="utf-8")
    updated = replace_fenced_region(template, rendered)
    if updated == template:
        print("no change")
        return 0
    target_path.write_text(updated, encoding="utf-8")
    print(f"updated {target_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
