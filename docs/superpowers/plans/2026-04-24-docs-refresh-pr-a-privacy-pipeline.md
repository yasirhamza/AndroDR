# Docs Refresh PR A — Privacy Publishing Pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish `docs/PRIVACY_POLICY.md` in the AndroDR repo as the single source of truth for the privacy policy, auto-render it into the `androdr-site` public site at build time, archive the dead `androdr-privacy` mirror repo, and fix the hallucinated contact email everywhere.

**Architecture:** Cross-repo pipeline. AndroDR is the authoritative edit surface; a workflow fires `repository_dispatch` on privacy markdown change; the `androdr-site` repo's render workflow fetches the markdown (authenticated GH API, required because of the account shadowban), converts it to HTML via a small Python script with structural assertions, replaces a fenced region in `index.html`, and pushes — existing GitHub Pages workflow handles the rest. Cloudflare Worker mirror picks up the change via its normal pull.

**Tech Stack:** Python 3 + `markdown` PyPI package (with `tables` extension), GitHub Actions, `gh` CLI.

**Spec:** `docs/superpowers/specs/2026-04-24-docs-refresh-design.md` §5.

---

## File structure

**Repo: `yasirhamza/androdr-site` (separate repo, local checkout at /tmp for plan execution)**
- Create: `scripts/render_privacy.py` — markdown-to-HTML-fragment renderer with structural assertions
- Create: `scripts/requirements.txt` — pinned dependency for renderer
- Create: `scripts/test_render_privacy.py` — tests for the renderer
- Create: `scripts/fixtures/sample_privacy.md` — minimal test fixture
- Create: `.github/workflows/render-privacy.yml` — triggers rendering (push, dispatch, cron, manual)
- Modify: `index.html` — add `<!-- ANDRODR:PRIVACY:START -->` / `<!-- ANDRODR:PRIVACY:END -->` fences around existing `<section class="privacy">`
- Delete: `.github/workflows/static.yml` — duplicate of `pages.yml`

**Repo: `yasirhamza/AndroDR`**
- Modify: `docs/PRIVACY_POLICY.md` — content update (email fix, active feeds, timeline, bugreport retention language, Data Safety alignment expansion, last-updated date)
- Modify: `docs/play-store/store-listing.md` — email fix (`privacy@androdr.dev` → `yhamad.dev@gmail.com`)
- Create: `.github/workflows/notify-privacy-sync.yml` — fires `repository_dispatch` to `androdr-site` on privacy markdown change

**Repo: `yasirhamza/androdr-privacy`**
- Replace: `index.md` with single-line forwarding pointer
- Archive via `gh repo archive`

---

## Cutover sequence

Because this is cross-repo and has visible public effects, land changes in this order:

1. Tasks 1–6 land in a single PR against `yasirhamza/androdr-site`. First merge of this PR triggers the render workflow; the workflow will regenerate the privacy HTML from AndroDR's *current* `docs/PRIVACY_POLICY.md` (old content). That is safe — it normalizes the already-live content into the fenced region, no regression.
2. Tasks 7–9 land in a single PR against `yasirhamza/AndroDR`. Merge fires the `repository_dispatch`; the site re-renders with the updated content; Cloudflare mirror catches up on next pull.
3. Task 10 (archive mirror repo) runs after both PRs are merged and verified.

---

## Task 1: Fence the privacy section in `androdr-site/index.html`

**Repo:** `yasirhamza/androdr-site`
**Files:**
- Modify: `index.html` around the `<section class="privacy" id="privacy">` block

- [ ] **Step 1: Clone `androdr-site` if not already local**

Run:
```bash
cd /tmp && [ -d androdr-site-work ] || gh repo clone yasirhamza/androdr-site androdr-site-work
cd /tmp/androdr-site-work
git checkout -b docs/privacy-pipeline
```

- [ ] **Step 2: Locate the privacy section**

Run: `grep -n 'section class="privacy"' index.html`
Expected: one match on a line around 219 (`<section class="privacy" id="privacy">`).

- [ ] **Step 3: Wrap with fence comments**

Edit `index.html`. Replace:
```html
  <section class="privacy" id="privacy">
```
with:
```html
  <!-- ANDRODR:PRIVACY:START -->
  <section class="privacy" id="privacy">
```

And replace the matching closing `</section>` (the one on the line immediately before the `<!-- Footer -->` comment or the `<footer>` tag) with:
```html
  </section>
  <!-- ANDRODR:PRIVACY:END -->
```

Verify with: `grep -c 'ANDRODR:PRIVACY' index.html`
Expected: `2`

- [ ] **Step 4: Confirm the fence brackets exactly one privacy section**

Run: `python3 -c "import re,sys; html=open('index.html').read(); m=re.search(r'<!-- ANDRODR:PRIVACY:START -->(.*?)<!-- ANDRODR:PRIVACY:END -->', html, re.DOTALL); print('lines:', m.group(1).count(chr(10)) if m else 'NO MATCH')"`
Expected: `lines: <some number > 150>` (the fenced region is the bulk of the privacy content).

- [ ] **Step 5: Commit**

```bash
git add index.html
git commit -m "site: fence privacy section for render-privacy workflow"
```

---

## Task 2: Create `scripts/requirements.txt` in `androdr-site`

**Repo:** `yasirhamza/androdr-site`
**Files:**
- Create: `scripts/requirements.txt`

- [ ] **Step 1: Create the requirements file**

```bash
mkdir -p scripts
cat > scripts/requirements.txt <<'EOF'
markdown==3.6
EOF
```

- [ ] **Step 2: Commit**

```bash
git add scripts/requirements.txt
git commit -m "site: pin markdown dependency for render-privacy script"
```

---

## Task 3: Write tests for `render_privacy.py` (fail first)

**Repo:** `yasirhamza/androdr-site`
**Files:**
- Create: `scripts/fixtures/sample_privacy.md`
- Create: `scripts/test_render_privacy.py`

- [ ] **Step 1: Create test fixture**

Create `scripts/fixtures/sample_privacy.md`:
```markdown
# AndroDR Privacy Policy

_Last updated: 2026-04-01_

## Our Philosophy

AndroDR is an open-source security tool.

## What AndroDR Does

It scans.

| Data | Purpose |
|------|---------|
| App list | Threat detection |
| DNS queries | Blocklist check |

## Contact

- Email: yhamad.dev@gmail.com
```

- [ ] **Step 2: Write test file**

Create `scripts/test_render_privacy.py`:
```python
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
    assert h2_count == 3  # Our Philosophy, What AndroDR Does, Contact


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
    # Should not raise
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


def test_replace_fenced_region_preserves_fences():
    template = "<!-- ANDRODR:PRIVACY:START -->\nOLD\n<!-- ANDRODR:PRIVACY:END -->"
    result = render_privacy.replace_fenced_region(template, "NEW")
    assert result.count("<!-- ANDRODR:PRIVACY:START -->") == 1
    assert result.count("<!-- ANDRODR:PRIVACY:END -->") == 1


def test_replace_fenced_region_raises_when_fence_missing():
    template = "<body>no fences</body>"
    with pytest.raises(ValueError, match="fence"):
        render_privacy.replace_fenced_region(template, "x")
```

- [ ] **Step 3: Run tests and confirm they fail with import error**

Run:
```bash
cd /tmp/androdr-site-work/scripts
python3 -m pip install markdown==3.6 pytest -q
python3 -m pytest test_render_privacy.py -v
```
Expected: all 11 tests fail because `render_privacy` module doesn't exist yet (`ModuleNotFoundError` or `ImportError`).

- [ ] **Step 4: Commit failing tests**

```bash
cd /tmp/androdr-site-work
git add scripts/fixtures/sample_privacy.md scripts/test_render_privacy.py
git commit -m "site: tests for privacy render script (red)"
```

---

## Task 4: Implement `render_privacy.py`

**Repo:** `yasirhamza/androdr-site`
**Files:**
- Create: `scripts/render_privacy.py`

- [ ] **Step 1: Write the implementation**

Create `scripts/render_privacy.py`:
```python
"""Render docs/PRIVACY_POLICY.md (from the AndroDR repo) into an HTML fragment
for injection into index.html in the androdr-site repo.

Usage:
    python3 render_privacy.py <markdown-path> <index-html-path>

The script:
  1. Parses the markdown into an HTML fragment with the 'tables' extension.
  2. Wraps it in <section class="privacy" id="privacy">...</section>
     so existing CSS in index.html applies unchanged.
  3. Asserts structural invariants (expected <h2> and <table> counts); exits
     non-zero if they don't match. Update EXPECTED_H2 / EXPECTED_TABLES in the
     same commit that deliberately changes the privacy structure.
  4. Replaces the fenced region (<!-- ANDRODR:PRIVACY:START --> ... END -->)
     in index.html with the new section.
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

    The rendered fragment mirrors the structure the current index.html already
    uses, so the existing .privacy CSS selectors apply without change. The top
    `# AndroDR Privacy Policy` H1 in the markdown is dropped (the H2 "Privacy
    Policy" title lives in the HTML template), and the `_Last updated: ..._`
    line is rendered as a `<p><em>Last updated: YYYY-MM-DD</em></p>` at the
    top of the fragment so the date stays visible.
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
    # First <h2> is the "Privacy Policy" title we injected; source markdown
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
        print(f"usage: {argv[0]} <markdown-path> <index-html-path>", file=sys.stderr)
        return 2
    md_path = Path(argv[1])
    html_path = Path(argv[2])
    md_text = md_path.read_text(encoding="utf-8")
    rendered = render(md_text)
    assert_structural_invariants(rendered)
    template = html_path.read_text(encoding="utf-8")
    updated = replace_fenced_region(template, rendered)
    if updated == template:
        print("no change")
        return 0
    html_path.write_text(updated, encoding="utf-8")
    print(f"updated {html_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
```

- [ ] **Step 2: Run tests — should now pass**

Run:
```bash
cd /tmp/androdr-site-work/scripts
python3 -m pytest test_render_privacy.py -v
```
Expected: all 11 tests PASS.

- [ ] **Step 3: Dry-run against real privacy markdown**

Run:
```bash
cd /tmp/androdr-site-work
cp /home/yasir/AndroDR/docs/PRIVACY_POLICY.md /tmp/live-privacy.md
python3 scripts/render_privacy.py /tmp/live-privacy.md index.html
```
Expected: script prints `updated index.html` and exits 0.

- [ ] **Step 4: Verify the rendered HTML looks reasonable**

Run:
```bash
grep -c '<h3' index.html
grep -c '<table>' index.html
grep -c 'yhamad.dev@gmail.com\|privacy@androdr.dev' index.html
```
Expected: some `<h3>` count, 3 `<table>` blocks, and `yhamad.dev@gmail.com` present. (Current markdown still has `privacy@androdr.dev` — that gets fixed in Task 7.)

- [ ] **Step 5: Revert the dry-run edit to index.html**

The render in Step 3 modified index.html for preview only. We want the committed state to still have the unmodified fenced region (from Task 1), not pre-applied content. Revert:
```bash
git checkout -- index.html
```

- [ ] **Step 6: Commit the script**

```bash
git add scripts/render_privacy.py
git commit -m "site: add render_privacy.py (tests now green)"
```

---

## Task 5: Create the `render-privacy.yml` workflow in `androdr-site`

**Repo:** `yasirhamza/androdr-site`
**Files:**
- Create: `.github/workflows/render-privacy.yml`

- [ ] **Step 1: Write the workflow**

Create `.github/workflows/render-privacy.yml`:
```yaml
name: Render privacy from AndroDR

on:
  push:
    branches: [main]
    paths:
      - 'scripts/render_privacy.py'
      - 'scripts/requirements.txt'
      - '.github/workflows/render-privacy.yml'
  repository_dispatch:
    types: [privacy-updated]
  schedule:
    # Daily safety net in case a repository_dispatch was missed.
    - cron: '17 5 * * *'
  workflow_dispatch:

permissions:
  contents: write

concurrency:
  group: render-privacy
  cancel-in-progress: false

jobs:
  render:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout androdr-site
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install renderer dependencies
        run: python -m pip install -r scripts/requirements.txt

      - name: Fetch PRIVACY_POLICY.md from AndroDR
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          gh api repos/yasirhamza/AndroDR/contents/docs/PRIVACY_POLICY.md \
            --jq '.content' | base64 -d > /tmp/PRIVACY_POLICY.md
          test -s /tmp/PRIVACY_POLICY.md

      - name: Capture source SHA
        id: src
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          SHA=$(gh api repos/yasirhamza/AndroDR/commits/main --jq '.sha' | cut -c1-7)
          echo "sha=$SHA" >> "$GITHUB_OUTPUT"

      - name: Render privacy into index.html
        run: python3 scripts/render_privacy.py /tmp/PRIVACY_POLICY.md index.html

      - name: Commit if changed
        run: |
          if git diff --quiet -- index.html; then
            echo "no change — privacy content already in sync"
            exit 0
          fi
          git config user.name 'androdr-site-bot'
          git config user.email 'yhamad.dev@gmail.com'
          git add index.html
          git commit -m "docs(privacy): sync from AndroDR@${{ steps.src.outputs.sha }}"
          git push
```

- [ ] **Step 2: Lint the YAML**

Run: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/render-privacy.yml'))"`
Expected: no output, exit 0.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/render-privacy.yml
git commit -m "site: render-privacy workflow (push/dispatch/cron/manual triggers)"
```

---

## Task 6: Delete duplicate `static.yml` workflow, open the site PR

**Repo:** `yasirhamza/androdr-site`
**Files:**
- Delete: `.github/workflows/static.yml`

- [ ] **Step 1: Verify `pages.yml` is sufficient for deploy**

Run:
```bash
cat .github/workflows/pages.yml
cat .github/workflows/static.yml
diff <(grep -v '^#\|^$\|name:' .github/workflows/pages.yml) <(grep -v '^#\|^$\|name:' .github/workflows/static.yml)
```
Expected: the two files are near-identical pages-deploy jobs. If there is a unique step in `static.yml`, stop and ask the user before deleting.

- [ ] **Step 2: Delete `static.yml`**

```bash
git rm .github/workflows/static.yml
git commit -m "site: remove duplicate static.yml deploy workflow"
```

- [ ] **Step 3: Push and open PR**

```bash
git push -u origin docs/privacy-pipeline
gh pr create --repo yasirhamza/androdr-site \
  --title "privacy: render from AndroDR markdown via repository_dispatch" \
  --body "$(cat <<'EOF'
Establishes single-source-of-truth pipeline for the privacy policy.

- Fences the existing privacy section with ANDRODR:PRIVACY markers
- Adds scripts/render_privacy.py (with tests) to convert markdown → HTML fragment
- Adds render-privacy.yml workflow (push / repository_dispatch / daily cron / manual)
- Removes duplicate static.yml in favor of pages.yml

First merge will trigger a render of the current AndroDR PRIVACY_POLICY.md
(unchanged content; just normalizes the already-live copy into the fenced
region). A subsequent AndroDR PR updates the markdown content and fires the
dispatch.

Spec: https://github.com/yasirhamza/AndroDR/blob/main/docs/superpowers/specs/2026-04-24-docs-refresh-design.md §5
EOF
)"
```

- [ ] **Step 4: Watch the workflow after merge**

After the PR merges, confirm `render-privacy.yml` runs successfully on the push-to-main trigger and produces a `docs(privacy): sync from AndroDR@<sha>` commit (or "no change — privacy content already in sync" if no diff).

```bash
gh run list --repo yasirhamza/androdr-site --workflow render-privacy.yml --limit 3
```

Expected: at least one successful run. If it failed, inspect logs with `gh run view --repo yasirhamza/androdr-site <run-id> --log`.

---

## Task 7: Update `docs/PRIVACY_POLICY.md` content

**Repo:** `yasirhamza/AndroDR`
**Files:**
- Modify: `docs/PRIVACY_POLICY.md`

- [ ] **Step 1: Create branch in AndroDR repo**

```bash
cd /home/yasir/AndroDR
git checkout main
git pull --ff-only
git checkout -b docs/privacy-content-update
```

- [ ] **Step 2: Update the `_Last updated:_` line**

Use Edit to change `_Last updated: 2026-03-26_` → `_Last updated: 2026-04-24_`.

- [ ] **Step 3: Replace all `privacy@androdr.dev` with `yhamad.dev@gmail.com`**

Run: `grep -n "privacy@androdr.dev" docs/PRIVACY_POLICY.md`
Expected: one match on line 197.

Use Edit (replace_all=true) to change `privacy@androdr.dev` → `yhamad.dev@gmail.com`.

- [ ] **Step 4: Update "What AndroDR Does" to mention SIGMA engine + STIX2**

Edit the "What AndroDR Does" section so its last bullet cluster includes:
- "Uses auditable YAML [SIGMA](https://github.com/SigmaHQ/sigma)-style detection rules — detection logic is not hidden in compiled code"
- "Imports and exports STIX2-compatible indicators for interoperability with other forensic tools"

- [ ] **Step 5: Extend "Data That Stays On Your Device" table**

Append two rows to the table:
```
| Forensic timeline events (e.g., device admin grants) | Displayed in the timeline screen and exportable as part of reports | On-device Room database |
| Bug report analysis findings | Displayed with scan results; raw bug report file is not retained | On-device Room database |
```

- [ ] **Step 6: Update "Network Requests" table**

Remove the "Cert hash IOCs (planned)" stub row. Add or update these rows to reflect the current ingesters:

```
| MalwareBazaar APK hashes + cert hashes | abuse.ch MalwareBazaar public API | Hashes of known malicious APKs and the cert hashes that signed them | 1 API request per refresh |
| ThreatFox indicators | abuse.ch ThreatFox public API | Command-and-control domain and IP indicators | 1 API request per refresh |
| Stalkerware cert-hash indicators | AssoEchap/stalkerware-indicators (GitHub) | Cert hashes of known stalkerware signers | 1 HTTP GET |
```

Keep the existing rows for stalkerware package names, mvt-indicators (but note the dispatcher/cross-dedup wording), and the UAD / Plexus known-app databases.

Append this paragraph below the table:
> IOC ingesters run in a dispatcher that deduplicates indicators across feeds before writing to the on-device database. Each feed is independently auditable in `app/src/main/java/com/androdr/ioc/feeds/`.

- [ ] **Step 7: Tighten "Bug Report Analysis" section**

Ensure the section explicitly says:
> AndroDR retains only the analysis *findings* — flagged app names, indicator matches, detected patterns — in the scan result. The original bug report ZIP is not stored on-device after analysis completes.

- [ ] **Step 8: Expand "Google Play Data Safety Alignment"**

Update the bullet list to mirror the declarations in `docs/play-store/18-data-safety-form.md` (read that file first and align the language). At minimum:
- Data collected — installed apps (on-device), device info (bugreport analysis findings, user-initiated reports only), diagnostic info (app logcat in user-initiated reports only)
- Data shared — none (explicit user-initiated sharing only)
- Data encrypted in transit — N/A (no user data transmitted)
- Data deletion — clear app data / uninstall
- Optional data collection — none

- [ ] **Step 9: Sanity-check the result**

Run:
```bash
grep -c "^## " docs/PRIVACY_POLICY.md
grep -c "^|" docs/PRIVACY_POLICY.md
grep -c "privacy@androdr.dev" docs/PRIVACY_POLICY.md
grep -c "yhamad.dev@gmail.com" docs/PRIVACY_POLICY.md
```
Expected: heading count still `18` (no structural break); table row count `≥ 22`; zero matches for `privacy@androdr.dev`; at least one match for `yhamad.dev@gmail.com`.

If the heading count changed, update `EXPECTED_H2` in `androdr-site/scripts/render_privacy.py` within the same cross-repo coordination before merging (raise to user).

- [ ] **Step 10: Commit**

```bash
git add docs/PRIVACY_POLICY.md
git commit -m "docs(privacy): refresh content — active feeds, timeline, bugreport retention, correct contact"
```

---

## Task 8: Sweep contact email in `docs/play-store/store-listing.md`

**Repo:** `yasirhamza/AndroDR`
**Files:**
- Modify: `docs/play-store/store-listing.md`

- [ ] **Step 1: Locate the bad email**

Run: `grep -n "privacy@androdr.dev" docs/play-store/store-listing.md`
Expected: one match on line 58.

- [ ] **Step 2: Replace**

Use Edit to change `privacy@androdr.dev` → `yhamad.dev@gmail.com`.

- [ ] **Step 3: Verify no more occurrences anywhere in repo**

Run: `grep -rn "privacy@androdr.dev" . --exclude-dir=.git --exclude-dir=.claude`
Expected: zero output.

- [ ] **Step 4: Commit**

```bash
git add docs/play-store/store-listing.md
git commit -m "docs(play-store): correct contact email in store listing"
```

---

## Task 9: Add `notify-privacy-sync.yml` workflow in AndroDR

**Repo:** `yasirhamza/AndroDR`
**Files:**
- Create: `.github/workflows/notify-privacy-sync.yml`

- [ ] **Step 1: Write the workflow**

Create `.github/workflows/notify-privacy-sync.yml`:
```yaml
name: Notify androdr-site of privacy changes

on:
  push:
    branches: [main]
    paths:
      - 'docs/PRIVACY_POLICY.md'

permissions:
  contents: read

jobs:
  dispatch:
    runs-on: ubuntu-latest
    steps:
      - name: Fire repository_dispatch to androdr-site
        env:
          GH_TOKEN: ${{ secrets.PRIVACY_SYNC_TOKEN }}
        run: |
          gh api repos/yasirhamza/androdr-site/dispatches \
            --method POST \
            -f event_type=privacy-updated \
            -f 'client_payload[source_sha]=${{ github.sha }}'
```

- [ ] **Step 2: Flag the token requirement to the user**

The default `GITHUB_TOKEN` **cannot** dispatch to another repo. This workflow needs a Personal Access Token (classic, with `repo` scope) or a fine-grained token scoped to `yasirhamza/androdr-site` with `Contents: read` + `Metadata: read` + `Actions: write`. Store it as `PRIVACY_SYNC_TOKEN` in AndroDR repo secrets.

Print this instruction so the user (or a follow-up task) handles it:

Run: `echo "MANUAL STEP: create PAT with dispatch scope on androdr-site, add as PRIVACY_SYNC_TOKEN secret in AndroDR repo"`

- [ ] **Step 3: Lint the YAML**

Run: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/notify-privacy-sync.yml'))"`
Expected: no output, exit 0.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/notify-privacy-sync.yml
git commit -m "ci: dispatch privacy-updated event to androdr-site on PRIVACY_POLICY change"
```

- [ ] **Step 5: Push branch and open AndroDR PR**

```bash
git push -u origin docs/privacy-content-update
gh pr create \
  --title "docs(privacy): refresh policy + wire up site auto-render" \
  --body "$(cat <<'EOF'
## Summary
- Refreshes \`docs/PRIVACY_POLICY.md\` content (active feeds including MalwareBazaar APK/cert hashes and ThreatFox, timeline events, bugreport retention language, Data Safety alignment expansion)
- Fixes hallucinated \`privacy@androdr.dev\` contact (replaced with \`yhamad.dev@gmail.com\`) in the privacy policy and in docs/play-store/store-listing.md
- Adds notify-privacy-sync.yml workflow that fires \`repository_dispatch\` to androdr-site when the privacy markdown changes, so the public site auto-renders

Depends on androdr-site PR (https://github.com/yasirhamza/androdr-site/pulls) landing first; once that is in, merging this PR will propagate content to the public site within minutes.

Closes no issues directly; implements spec §5 (PR A) of docs/superpowers/specs/2026-04-24-docs-refresh-design.md

## Test plan
- [ ] PRIVACY_SYNC_TOKEN secret created in AndroDR repo (PAT with dispatch scope on androdr-site)
- [ ] CI build check green
- [ ] After merge, notify-privacy-sync workflow runs successfully
- [ ] After merge, androdr-site render-privacy workflow fires and produces a \`docs(privacy): sync from AndroDR@<sha>\` commit
- [ ] Live site (GitHub Pages + Cloudflare mirror) reflects the new content within 5–10 minutes

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Task 10: Archive the `androdr-privacy` repo

**Repo:** `yasirhamza/androdr-privacy`

Run after Tasks 1–9 are merged and the pipeline is verified end-to-end.

- [ ] **Step 1: Replace `index.md` with a forwarding pointer**

```bash
cd /tmp
rm -rf androdr-privacy-archive
gh repo clone yasirhamza/androdr-privacy androdr-privacy-archive
cd androdr-privacy-archive
cat > index.md <<'EOF'
# AndroDR Privacy Policy — Moved

The canonical AndroDR privacy policy now lives at
https://github.com/yasirhamza/AndroDR/blob/main/docs/PRIVACY_POLICY.md
and is rendered publicly at https://yasirhamza.github.io/androdr-site/#privacy
(mirrored at https://androdr.yasirhamza.workers.dev ).

This repository is archived and no longer accepts changes.
EOF
git add index.md
git commit -m "chore: archive — point to canonical privacy policy in AndroDR repo"
git push
```

- [ ] **Step 2: Archive the repo**

Run:
```bash
gh repo archive yasirhamza/androdr-privacy --yes
```
Expected: confirmation that the repo is now archived.

- [ ] **Step 3: Verify**

Run: `gh api repos/yasirhamza/androdr-privacy --jq '{archived, updated_at}'`
Expected: `"archived": true`.

---

## End-to-end verification

Run after both PRs are merged and Task 10 completes.

- [ ] **Step 1: Live site reflects content update**

Open https://androdr.yasirhamza.workers.dev in a browser. Confirm the `#privacy` section shows `Last updated: 2026-04-24` and the correct contact email `yhamad.dev@gmail.com`. Also confirm the MalwareBazaar row no longer says `(planned)`.

- [ ] **Step 2: Cross-repo grep is clean**

Run: `grep -rn "privacy@androdr\.dev" /home/yasir/AndroDR --exclude-dir=.git --exclude-dir=.claude`
Expected: zero output.

- [ ] **Step 3: Archive is visible**

Open https://github.com/yasirhamza/androdr-privacy. Confirm the repo shows the "Archived" banner and the `index.md` pointer is visible.

- [ ] **Step 4: Trigger a trivial propagation test**

Make a whitespace-only commit to `docs/PRIVACY_POLICY.md` on a throwaway branch in AndroDR, merge it, and confirm the site re-renders within ~5 minutes.

If all four verification steps pass, PR A is complete. Proceed to PR B plan.
