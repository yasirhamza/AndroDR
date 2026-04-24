"""Tests for render_privacy.py — the markdown-to-HTML fragment renderer."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

import render_privacy

FIXTURE = Path(__file__).parent / "fixtures" / "sample_privacy.md"


def test_render_wraps_in_privacy_section():
    html = render_privacy.render(FIXTURE.read_text())
    assert html.startswith('<section class="privacy" id="privacy">')
    assert html.rstrip().endswith("</section>")


def test_render_produces_h2_for_top_sections():
    html = render_privacy.render(FIXTURE.read_text())
    h2_count = len(re.findall(r"<h2[^>]*>", html))
    # Injected "Privacy Policy" h2 + 3 source h2s.
    assert h2_count == 4


def test_render_produces_table_block():
    html = render_privacy.render(FIXTURE.read_text())
    assert "<table>" in html
    assert "<th>Data</th>" in html


def test_render_extracts_last_updated():
    last_updated = render_privacy.extract_last_updated(FIXTURE.read_text())
    assert last_updated == "2026-04-01"


def test_render_injects_last_updated_into_fragment():
    html = render_privacy.render(FIXTURE.read_text())
    assert "Last updated: 2026-04-01" in html


def test_assert_structural_invariants_pass_matching_fixture():
    html = render_privacy.render(FIXTURE.read_text())
    render_privacy.assert_structural_invariants(html, expected_h2=3, expected_tables=1)


def test_assert_structural_invariants_raises_on_h2_mismatch():
    html = render_privacy.render(FIXTURE.read_text())
    with pytest.raises(AssertionError, match="h2"):
        render_privacy.assert_structural_invariants(html, expected_h2=99, expected_tables=1)


def test_assert_structural_invariants_raises_on_table_mismatch():
    html = render_privacy.render(FIXTURE.read_text())
    with pytest.raises(AssertionError, match="table"):
        render_privacy.assert_structural_invariants(html, expected_h2=3, expected_tables=99)


def test_replace_fenced_region():
    template = """<body>
<!-- ANDRODR:PRIVACY:START -->
<section class="privacy" id="privacy">OLD</section>
<!-- ANDRODR:PRIVACY:END -->
</body>"""
    new_section = '<section class="privacy" id="privacy">NEW</section>'
    result = render_privacy.replace_fenced_region(template, new_section)
    assert "OLD" not in result
    assert "NEW" in result
    assert "<!-- ANDRODR:PRIVACY:START -->" in result
    assert "<!-- ANDRODR:PRIVACY:END -->" in result


def test_replace_fenced_region_preserves_fences_exactly_once():
    template = "<!-- ANDRODR:PRIVACY:START -->\nOLD\n<!-- ANDRODR:PRIVACY:END -->"
    result = render_privacy.replace_fenced_region(template, "NEW")
    assert result.count("<!-- ANDRODR:PRIVACY:START -->") == 1
    assert result.count("<!-- ANDRODR:PRIVACY:END -->") == 1


def test_replace_fenced_region_raises_when_fence_missing():
    template = "<body>no fences</body>"
    with pytest.raises(ValueError, match="fence"):
        render_privacy.replace_fenced_region(template, "x")
