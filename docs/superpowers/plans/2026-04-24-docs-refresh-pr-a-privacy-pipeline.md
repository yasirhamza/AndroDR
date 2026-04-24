# Docs Refresh PR A — Privacy Publishing Pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish `docs/PRIVACY_POLICY.md` in the AndroDR repo as the single source of truth for the privacy policy, auto-render it into two derived artifacts (`cloudflare-worker.js` in AndroDR and `index.html` in `androdr-site`), archive the dead `androdr-privacy` mirror repo, and fix the hallucinated contact email everywhere.

**Architecture:** Cross-repo pipeline with **one canonical renderer** in AndroDR (`scripts/render_privacy.py`) used by two workflows:

- `.github/workflows/render-privacy-worker.yml` in AndroDR renders `cloudflare-worker.js` on push when privacy content changes. Commit message reminds the maintainer to `wrangler deploy`.
- `.github/workflows/render-privacy.yml` in `androdr-site` fetches the markdown AND the renderer from AndroDR at run time (authenticated — the account shadowban blocks anonymous `raw.githubusercontent.com`) and renders `index.html`. It fires on `repository_dispatch` from AndroDR, with a daily cron as safety net.

**Tech Stack:** Python 3 + `markdown` PyPI package (with `tables` extension), GitHub Actions, `gh` CLI. Worker deployment is manual (`wrangler deploy`).

**Spec:** `docs/superpowers/specs/2026-04-24-docs-refresh-design.md` §5.

---

## Cutover sequence (critical — read before starting)

Two PRs, merged in this order:

1. **Site PR first** (tasks 1–3): small PR in `yasirhamza/androdr-site`. On merge, the new render workflow fires once and **fails as expected** because the renderer doesn't exist on AndroDR main yet. This is a known, acceptable first-run failure — see Task 3 Step 4.
2. **AndroDR PR second** (tasks 4–12): larger PR in `yasirhamza/AndroDR`. On merge: the worker-render workflow produces an updated `cloudflare-worker.js`; the notify workflow dispatches to the site; the site render workflow now succeeds.
3. **Manual `wrangler deploy`** (task 13) to push the updated Worker live.
4. **Archive `androdr-privacy`** (task 14).

---

## File structure

### `yasirhamza/androdr-site` (site PR)
- Modify: `index.html` — fence the privacy section with `<!-- ANDRODR:PRIVACY:START -->` / `<!-- ANDRODR:PRIVACY:END -->`
- Create: `.github/workflows/render-privacy.yml` — fetches renderer + markdown from AndroDR, renders `index.html`
- Delete: `.github/workflows/static.yml` — duplicate of `pages.yml`

### `yasirhamza/AndroDR` (AndroDR PR)
- Modify: `cloudflare-worker.js` — fence privacy section, content update
- Modify: `docs/PRIVACY_POLICY.md` — content refresh, email fix, date bump
- Modify: `docs/play-store/store-listing.md` — email fix
- Create: `scripts/requirements.txt` — pinned `markdown` dependency
- Create: `scripts/render_privacy.py` — canonical renderer (CLI takes markdown path + target html path)
- Create: `scripts/test_render_privacy.py` — renderer tests
- Create: `scripts/fixtures/sample_privacy.md` — minimal fixture for tests
- Create: `.github/workflows/render-privacy-worker.yml` — renders `cloudflare-worker.js` on push
- Create: `.github/workflows/notify-privacy-sync.yml` — fires `repository_dispatch` to site

### `yasirhamza/androdr-privacy` (admin action)
- Modify: `index.md` → forwarding pointer
- Archive via `gh repo archive`

---

# Part 1: Site PR

## Task 1: Fence the privacy section in `androdr-site/index.html`

**Repo:** `yasirhamza/androdr-site`
**Files:**
- Modify: `index.html` (fence markers around existing `<section class="privacy">`)

- [ ] **Step 1: Clone the site repo and create a branch**

```bash
cd /tmp && rm -rf androdr-site-work
gh repo clone yasirhamza/androdr-site androdr-site-work
cd /tmp/androdr-site-work
git checkout -b docs/privacy-pipeline
```

- [ ] **Step 2: Locate the privacy section**

Run: `grep -n 'section class="privacy"' index.html`
Expected: one line showing `<section class="privacy" id="privacy">`.

- [ ] **Step 3: Insert `<!-- ANDRODR:PRIVACY:START -->` before the section and `<!-- ANDRODR:PRIVACY:END -->` after its matching `</section>`**

Use Edit on `index.html`. Replace:
```html
  <section class="privacy" id="privacy">
```
with:
```html
  <!-- ANDRODR:PRIVACY:START -->
  <section class="privacy" id="privacy">
```

Then find the closing `</section>` that matches (the one right before the `<footer>` block) and replace:
```html
  </section>

  <hr>

  <!-- Footer -->
```
with:
```html
  </section>
  <!-- ANDRODR:PRIVACY:END -->

  <hr>

  <!-- Footer -->
```

(If the exact surrounding context differs, adjust the Edit match; the invariant is exactly one `START` and exactly one `END`, with the `<section>...</section>` block between them and nothing else.)

- [ ] **Step 4: Verify fence markers bracket exactly one privacy section**

Run:
```bash
grep -c 'ANDRODR:PRIVACY:START' index.html
grep -c 'ANDRODR:PRIVACY:END' index.html
python3 -c "
import re
html = open('index.html').read()
m = re.search(r'<!-- ANDRODR:PRIVACY:START -->(.*?)<!-- ANDRODR:PRIVACY:END -->', html, re.DOTALL)
assert m, 'fence region not found'
inner = m.group(1)
assert inner.count('<section class=\"privacy\"') == 1, f'expected 1 section, got {inner.count(\"<section class=\\\"privacy\\\"\")}'
print('OK: fence region contains exactly one privacy section')
"
```
Expected: each grep prints `1`, Python prints `OK: fence region contains exactly one privacy section`.

- [ ] **Step 5: Commit**

```bash
git add index.html
git commit -m "site: fence privacy section for render-privacy workflow"
```

---

## Task 2: Create `render-privacy.yml` workflow in `androdr-site`

**Repo:** `yasirhamza/androdr-site`
**Files:**
- Create: `.github/workflows/render-privacy.yml`

- [ ] **Step 1: Write the workflow**

Create `.github/workflows/render-privacy.yml` with this content:

```yaml
name: Render privacy from AndroDR

on:
  push:
    branches: [main]
    paths:
      - '.github/workflows/render-privacy.yml'
      - 'index.html'
  repository_dispatch:
    types: [privacy-updated]
  schedule:
    # Daily safety net at 05:17 UTC in case a dispatch was missed.
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

      - name: Fetch renderer + markdown from AndroDR
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          mkdir -p /tmp/androdr
          for path in docs/PRIVACY_POLICY.md scripts/render_privacy.py scripts/requirements.txt; do
            out="/tmp/androdr/$(basename "$path")"
            gh api "repos/yasirhamza/AndroDR/contents/$path" --jq '.content' | base64 -d > "$out"
            test -s "$out" || { echo "fetch failed: $path"; exit 1; }
          done

      - name: Capture source SHA for commit message
        id: src
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          SHA=$(gh api repos/yasirhamza/AndroDR/commits/main --jq '.sha' | cut -c1-7)
          echo "sha=$SHA" >> "$GITHUB_OUTPUT"

      - name: Install renderer dependencies
        run: python -m pip install -r /tmp/androdr/requirements.txt

      - name: Render privacy into index.html
        run: python3 /tmp/androdr/render_privacy.py /tmp/androdr/PRIVACY_POLICY.md index.html

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
git commit -m "site: render-privacy workflow (fetches renderer + markdown from AndroDR)"
```

---

## Task 3: Delete duplicate `static.yml`, push, and open the site PR

**Repo:** `yasirhamza/androdr-site`

- [ ] **Step 1: Compare `static.yml` against `pages.yml`**

Run:
```bash
cat .github/workflows/pages.yml .github/workflows/static.yml
```

Both are GitHub Pages deploy workflows. Confirm `static.yml` has no unique step that `pages.yml` lacks. If it does, stop and ask the user before deleting.

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
Part 1 of the privacy publishing pipeline (the other half lands in yasirhamza/AndroDR).

- Fences the existing privacy section with ANDRODR:PRIVACY markers.
- Adds render-privacy.yml that fetches the renderer + markdown from AndroDR main at run time and renders into index.html. Authenticated GH API fetch is required because the account shadowban blocks anonymous raw.githubusercontent.com.
- Removes duplicate static.yml in favor of pages.yml.

### Expected first-run failure
On merge, the push event fires render-privacy.yml. The renderer script does not exist on AndroDR main yet (it lands in the AndroDR-side PR that merges next). The first run will fail with "fetch failed: scripts/render_privacy.py" and that is expected. Normal operation begins once the AndroDR PR merges and the subsequent repository_dispatch triggers a successful render.

Spec: AndroDR/docs/superpowers/specs/2026-04-24-docs-refresh-design.md §5.
EOF
)"
```

- [ ] **Step 4: Merge and confirm expected first-run failure**

After merge, inspect the first workflow run:
```bash
gh run list --repo yasirhamza/androdr-site --workflow render-privacy.yml --limit 3
```

Expected: one failed run with the "fetch failed: scripts/render_privacy.py" message. This is the expected first-run failure — do not treat it as a blocker.

---

# Part 2: AndroDR PR

All remaining tasks happen in the AndroDR repo worktree at `.claude/worktrees/docs-privacy` on branch `docs/privacy-content-update` (already created during plan execution setup).

## Task 4: Fence the privacy section in `cloudflare-worker.js`

**Repo:** `yasirhamza/AndroDR` (worktree `.claude/worktrees/docs-privacy`)
**Files:**
- Modify: `cloudflare-worker.js`

- [ ] **Step 1: Change to the worktree**

```bash
cd /home/yasir/AndroDR/.claude/worktrees/docs-privacy
git status  # should report clean tree on docs/privacy-content-update
```

- [ ] **Step 2: Locate the privacy section**

Run: `grep -n '<section class="privacy"' cloudflare-worker.js`
Expected: one match.

- [ ] **Step 3: Wrap with fence markers**

Use Edit to wrap the `<section class="privacy" id="privacy">...</section>` block with the same `<!-- ANDRODR:PRIVACY:START -->` and `<!-- ANDRODR:PRIVACY:END -->` comments. Note: the HTML is inside a JavaScript template literal, so the comments become literal characters in the response HTML — that's fine; browsers ignore HTML comments.

The final structure inside the template literal must be:
```
  <!-- ANDRODR:PRIVACY:START -->
  <section class="privacy" id="privacy">
    ...existing content...
  </section>
  <!-- ANDRODR:PRIVACY:END -->
```

- [ ] **Step 4: Verify the fence brackets exactly one privacy section**

Run:
```bash
grep -c 'ANDRODR:PRIVACY:START' cloudflare-worker.js
grep -c 'ANDRODR:PRIVACY:END' cloudflare-worker.js
python3 -c "
import re
txt = open('cloudflare-worker.js').read()
m = re.search(r'<!-- ANDRODR:PRIVACY:START -->(.*?)<!-- ANDRODR:PRIVACY:END -->', txt, re.DOTALL)
assert m, 'fence region not found'
assert m.group(1).count('<section class=\"privacy\"') == 1
print('OK')
"
```
Expected: two `1`s and `OK`.

- [ ] **Step 5: Commit**

```bash
git add cloudflare-worker.js
git commit -m "worker: fence privacy section for render pipeline"
```

---

## Task 5: Add `scripts/requirements.txt`

**Repo:** `yasirhamza/AndroDR`
**Files:**
- Create: `scripts/requirements.txt`

- [ ] **Step 1: Create the file**

Use Write to create `scripts/requirements.txt` with content:
```
markdown==3.6
```

- [ ] **Step 2: Commit**

```bash
git add scripts/requirements.txt
git commit -m "scripts: pin markdown dependency for privacy renderer"
```

---

## Task 6: Write failing tests for `render_privacy.py`

**Repo:** `yasirhamza/AndroDR`
**Files:**
- Create: `scripts/fixtures/sample_privacy.md`
- Create: `scripts/test_render_privacy.py`

- [ ] **Step 1: Create the fixture**

Use Write to create `scripts/fixtures/sample_privacy.md`:
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

- [ ] **Step 2: Create the tests**

Use Write to create `scripts/test_render_privacy.py`:
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
```

- [ ] **Step 3: Install deps and confirm tests fail with ImportError**

```bash
cd /home/yasir/AndroDR/.claude/worktrees/docs-privacy/scripts
python3 -m pip install --quiet markdown==3.6 pytest
python3 -m pytest test_render_privacy.py -v 2>&1 | tail -20
```
Expected: all tests fail with `ModuleNotFoundError: No module named 'render_privacy'` (module doesn't exist yet).

- [ ] **Step 4: Commit failing tests**

```bash
cd /home/yasir/AndroDR/.claude/worktrees/docs-privacy
git add scripts/fixtures/sample_privacy.md scripts/test_render_privacy.py
git commit -m "scripts: tests for privacy renderer (red)"
```

---

## Task 7: Implement `render_privacy.py`

**Repo:** `yasirhamza/AndroDR`
**Files:**
- Create: `scripts/render_privacy.py`

- [ ] **Step 1: Write the implementation**

Use Write to create `scripts/render_privacy.py`:
```python
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
```

- [ ] **Step 2: Run tests — should pass**

```bash
cd /home/yasir/AndroDR/.claude/worktrees/docs-privacy/scripts
python3 -m pytest test_render_privacy.py -v 2>&1 | tail -20
```
Expected: all 11 tests PASS.

- [ ] **Step 3: Dry-run against `cloudflare-worker.js` to verify end-to-end**

```bash
cd /home/yasir/AndroDR/.claude/worktrees/docs-privacy
cp cloudflare-worker.js /tmp/worker-before.js
python3 scripts/render_privacy.py docs/PRIVACY_POLICY.md cloudflare-worker.js
echo "--- diff summary ---"
diff <(head -100 /tmp/worker-before.js) <(head -100 cloudflare-worker.js) | head -40
```
Expected: either `updated cloudflare-worker.js` (current markdown and worker content are different, which is likely because the worker has the old 2026-03-26 date hard-coded) or `no change` (if they happen to match). No assertion failure — the counts should match between markdown and worker.

**If the script reports an AssertionError about h2/table counts:** the markdown or target has drifted structurally from when the counts were locked. Stop and investigate before continuing.

- [ ] **Step 4: Revert the preview edit — the AndroDR PR's privacy content update will happen in Task 10, not here**

```bash
git checkout -- cloudflare-worker.js
```

- [ ] **Step 5: Commit the script**

```bash
git add scripts/render_privacy.py
git commit -m "scripts: render_privacy.py canonical markdown-to-HTML renderer (green)"
```

---

## Task 8: Add `render-privacy-worker.yml` workflow

**Repo:** `yasirhamza/AndroDR`
**Files:**
- Create: `.github/workflows/render-privacy-worker.yml`

- [ ] **Step 1: Write the workflow**

Use Write to create `.github/workflows/render-privacy-worker.yml`:
```yaml
name: Render privacy into cloudflare-worker.js

on:
  push:
    branches: [main]
    paths:
      - 'docs/PRIVACY_POLICY.md'
      - 'scripts/render_privacy.py'
      - 'cloudflare-worker.js'
      - '.github/workflows/render-privacy-worker.yml'
  workflow_dispatch:

permissions:
  contents: write

concurrency:
  group: render-privacy-worker
  cancel-in-progress: false

jobs:
  render:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install renderer dependencies
        run: python -m pip install -r scripts/requirements.txt

      - name: Render privacy into cloudflare-worker.js
        run: python3 scripts/render_privacy.py docs/PRIVACY_POLICY.md cloudflare-worker.js

      - name: Commit if changed
        run: |
          if git diff --quiet -- cloudflare-worker.js; then
            echo "no change — worker already in sync"
            exit 0
          fi
          git config user.name 'androdr-bot'
          git config user.email 'yhamad.dev@gmail.com'
          git add cloudflare-worker.js
          git commit -m "docs(privacy): render into cloudflare-worker.js

          Reminder: run 'wrangler deploy' locally to push this change to the
          Cloudflare Worker. The render workflow only updates the file in the
          repo; the live Worker deploys from a local checkout."
          git push
```

- [ ] **Step 2: Lint YAML**

```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/render-privacy-worker.yml'))"
```
Expected: no output.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/render-privacy-worker.yml
git commit -m "ci: render-privacy-worker workflow (updates cloudflare-worker.js on push)"
```

---

## Task 9: Add `notify-privacy-sync.yml` workflow

**Repo:** `yasirhamza/AndroDR`
**Files:**
- Create: `.github/workflows/notify-privacy-sync.yml`

- [ ] **Step 1: Write the workflow**

Use Write to create `.github/workflows/notify-privacy-sync.yml`:
```yaml
name: Notify androdr-site of privacy changes

on:
  push:
    branches: [main]
    paths:
      - 'docs/PRIVACY_POLICY.md'
      - 'scripts/render_privacy.py'
      - 'scripts/requirements.txt'

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
          if [ -z "$GH_TOKEN" ]; then
            echo "::error::PRIVACY_SYNC_TOKEN secret is not configured. See CONTRIBUTING or the plan for setup steps."
            exit 1
          fi
          gh api repos/yasirhamza/androdr-site/dispatches \
            --method POST \
            -f event_type=privacy-updated \
            -f "client_payload[source_sha]=${{ github.sha }}"
```

- [ ] **Step 2: Flag token setup to the user**

The default `GITHUB_TOKEN` cannot dispatch to another repo. The PR must be accompanied by a manual secret setup:

1. Create a **fine-grained PAT** scoped to `yasirhamza/androdr-site` with `Contents: read`, `Metadata: read`, `Actions: write` (only these three).
2. Add it as `PRIVACY_SYNC_TOKEN` in `yasirhamza/AndroDR` repo secrets (Settings → Secrets and variables → Actions → New repository secret).

Print this note so the user sees it:

```bash
echo "============================================================"
echo "MANUAL STEP before merging this PR:"
echo "  Create a fine-grained PAT scoped to yasirhamza/androdr-site"
echo "  with Contents: read, Metadata: read, Actions: write."
echo "  Add it as secret PRIVACY_SYNC_TOKEN in yasirhamza/AndroDR."
echo "============================================================"
```

- [ ] **Step 3: Lint YAML**

```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/notify-privacy-sync.yml'))"
```
Expected: no output.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/notify-privacy-sync.yml
git commit -m "ci: notify androdr-site when privacy content or renderer changes"
```

---

## Task 10: Update `docs/PRIVACY_POLICY.md` content

**Repo:** `yasirhamza/AndroDR`
**Files:**
- Modify: `docs/PRIVACY_POLICY.md`

- [ ] **Step 1: Read current file (so Write has prior Read on this path)**

```bash
wc -l docs/PRIVACY_POLICY.md
grep -n "Last updated\|privacy@androdr" docs/PRIVACY_POLICY.md
```

- [ ] **Step 2: Update `_Last updated:_` to `2026-04-24`**

Use Edit: `_Last updated: 2026-03-26_` → `_Last updated: 2026-04-24_`.

- [ ] **Step 3: Replace all occurrences of `privacy@androdr.dev` with `yhamad.dev@gmail.com`**

Use Edit with `replace_all=true` on `privacy@androdr.dev` → `yhamad.dev@gmail.com`.

Verify: `grep -c "privacy@androdr.dev" docs/PRIVACY_POLICY.md` returns `0`.

- [ ] **Step 4: Update "What AndroDR Does" section**

Add these bullets at the end of the existing list (immediately before the `---` divider):

```
- Evaluates detection rules expressed as auditable YAML — detection logic is not hidden inside compiled code
- Imports and exports STIX2-compatible indicators for interoperability with other forensic tools
```

And ensure the DNS monitor bullet reads "**optional** DNS monitor".

- [ ] **Step 5: Extend "Data That Stays On Your Device" table**

Append two rows to the table (before the closing `---`):
```
| Forensic timeline events (e.g., device admin grants) | Displayed in the timeline screen; included in exported reports | On-device Room database |
| Bug report analysis findings | Displayed with scan results; the original bug report ZIP is not retained after analysis | On-device Room database |
```

- [ ] **Step 6: Update "Network Requests AndroDR Makes" table**

Remove the "Cert hash IOCs (planned)" row. Add or update these rows to reflect the currently-live ingesters:

```
| MalwareBazaar APK + cert hashes | abuse.ch MalwareBazaar public API | Hashes of known malicious APKs and the cert hashes that signed them | 1 API request per refresh |
| ThreatFox indicators | abuse.ch ThreatFox public API | Command-and-control domain / IP indicators | 1 API request per refresh |
| Stalkerware cert-hash indicators | AssoEchap/stalkerware-indicators (GitHub) | Cert hashes of known stalkerware signers | 1 HTTP GET |
```

Keep existing rows for stalkerware package names, MVT, UAD, and Plexus.

Append this paragraph below the table:
> All ingesters run inside a dispatcher that deduplicates indicators across feeds before writing to the on-device database. Each feed is independently auditable in `app/src/main/java/com/androdr/ioc/feeds/`.

- [ ] **Step 7: Tighten "Bug Report Analysis" section**

Make sure the section contains this language (add it if missing):
> AndroDR retains only the analysis findings — flagged app names, indicator matches, detected patterns — in the scan result. The original bug report ZIP is not stored on-device after analysis completes.

- [ ] **Step 8: Expand "Google Play Data Safety Alignment"**

Read `docs/play-store/18-data-safety-form.md` (via Read tool) and align the bullet list in this section so the two files say the same thing. At minimum the bullets should cover:

- Data collected: on-device only — installed app list, device info (in user-initiated reports), diagnostic info (app logcat in user-initiated reports)
- Data shared: none (only user-initiated sharing)
- Data encrypted in transit: N/A — no user data is transmitted
- Data deletion: clear app data or uninstall
- Optional data collection: none

- [ ] **Step 9: Sanity-check counts**

```bash
grep -c "^## " docs/PRIVACY_POLICY.md
grep -c "privacy@androdr.dev" docs/PRIVACY_POLICY.md
grep -c "yhamad.dev@gmail.com" docs/PRIVACY_POLICY.md
grep -c "^_Last updated: 2026-04-24_$" docs/PRIVACY_POLICY.md
```

Expected:
- `## ` heading count must be exactly `18` (the renderer's EXPECTED_H2). If it differs, update `scripts/render_privacy.py`'s `EXPECTED_H2` in the same commit.
- `privacy@androdr.dev` → `0`
- `yhamad.dev@gmail.com` → at least `1`
- `_Last updated: 2026-04-24_` → `1`

- [ ] **Step 10: Dry-run the renderer against the updated markdown**

```bash
python3 scripts/render_privacy.py docs/PRIVACY_POLICY.md cloudflare-worker.js
```

Expected: either `updated cloudflare-worker.js` or `no change`. If AssertionError fires, the heading or table count is off — fix the markdown (or the EXPECTED_* constants with explicit justification) before continuing.

Revert the preview: `git checkout -- cloudflare-worker.js`

- [ ] **Step 11: Commit**

```bash
git add docs/PRIVACY_POLICY.md
git commit -m "docs(privacy): refresh — active feeds, timeline, bugreport retention, fix contact"
```

---

## Task 11: Fix contact email in `docs/play-store/store-listing.md`

**Repo:** `yasirhamza/AndroDR`
**Files:**
- Modify: `docs/play-store/store-listing.md`

- [ ] **Step 1: Confirm the bad email is present**

```bash
grep -n "privacy@androdr.dev" docs/play-store/store-listing.md
```
Expected: one match around line 58.

- [ ] **Step 2: Replace**

Use Edit: `privacy@androdr.dev` → `yhamad.dev@gmail.com`.

- [ ] **Step 3: Confirm zero matches remain anywhere in the repo**

```bash
cd /home/yasir/AndroDR/.claude/worktrees/docs-privacy
grep -rn "privacy@androdr.dev" . --exclude-dir=.git --exclude-dir=.claude
```
Expected: no output. (The `.claude` exclusion prevents matching the plan file which legitimately refers to the old string.)

- [ ] **Step 4: Commit**

```bash
git add docs/play-store/store-listing.md
git commit -m "docs(play-store): correct contact email in store listing"
```

---

## Task 12: Push branch and open the AndroDR PR

**Repo:** `yasirhamza/AndroDR`

- [ ] **Step 1: Push**

```bash
cd /home/yasir/AndroDR/.claude/worktrees/docs-privacy
git push -u origin docs/privacy-content-update
```

- [ ] **Step 2: Open PR**

```bash
gh pr create \
  --title "docs(privacy): single-source-of-truth pipeline + content refresh" \
  --body "$(cat <<'EOF'
Part 2 of the privacy publishing pipeline. Depends on the androdr-site PR (merged first).

## Summary
- Fences the privacy section in cloudflare-worker.js so the renderer can replace it.
- Adds scripts/render_privacy.py (the canonical renderer) with tests, fixture, and pinned requirements.
- Adds .github/workflows/render-privacy-worker.yml — on push when privacy content or renderer changes, re-renders cloudflare-worker.js. Commit message reminds the maintainer to run wrangler deploy.
- Adds .github/workflows/notify-privacy-sync.yml — fires repository_dispatch to androdr-site so its render workflow runs immediately.
- Refreshes docs/PRIVACY_POLICY.md content:
  - Replaces hallucinated contact privacy@androdr.dev with yhamad.dev@gmail.com (same fix in docs/play-store/store-listing.md)
  - Removes "Cert hash IOCs (planned)" stub; documents active MalwareBazaar APK+cert feed, ThreatFox, and stalkerware cert-hash ingestion
  - Adds timeline events and bugreport findings to the on-device data table
  - Adds IOC dispatcher / cross-dedup note
  - Aligns Google Play Data Safety section with docs/play-store/18-data-safety-form.md
  - Updates last-updated date to 2026-04-24

## Manual setup required before merge
Create a fine-grained PAT scoped to yasirhamza/androdr-site (Contents: read, Metadata: read, Actions: write) and add it as PRIVACY_SYNC_TOKEN in this repo's Actions secrets. Without it, the notify-privacy-sync workflow will fail.

## Post-merge manual action
Run \`wrangler deploy\` from a local checkout to push the updated cloudflare-worker.js to the live Worker at androdr.yasirhamza.workers.dev.

Spec: docs/superpowers/specs/2026-04-24-docs-refresh-design.md §5

## Test plan
- [ ] PRIVACY_SYNC_TOKEN secret exists in repo settings
- [ ] CI build + lint pass
- [ ] After merge: render-privacy-worker workflow succeeds and produces a "docs(privacy): render into cloudflare-worker.js" commit
- [ ] After merge: notify-privacy-sync workflow succeeds and fires dispatch
- [ ] After merge: androdr-site render-privacy workflow succeeds and updates index.html
- [ ] After wrangler deploy: live Cloudflare Worker shows Last updated 2026-04-24 and correct contact email

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Task 13: Manual `wrangler deploy`

**Maintainer:** Yasir
**Environment:** local machine with `wrangler` installed and Cloudflare authenticated

- [ ] **Step 1: After the AndroDR PR merges and the worker-render commit lands on main**

```bash
cd /home/yasir/AndroDR
git checkout main && git pull --ff-only
grep "Last updated" cloudflare-worker.js | head -2
```
Expected: the `Last updated: 2026-04-24` string appears inside the inline HTML.

- [ ] **Step 2: Deploy**

```bash
wrangler deploy cloudflare-worker.js
```

If the Worker is deployed under a different name or script path, use the maintainer's standard `wrangler deploy` invocation.

- [ ] **Step 3: Verify live response**

```bash
curl -s https://androdr.yasirhamza.workers.dev/ | grep "Last updated\|yhamad.dev\|privacy@androdr" | head -5
```
Expected: at least one line containing `Last updated: 2026-04-24`, at least one containing `yhamad.dev@gmail.com`, zero containing `privacy@androdr.dev`.

---

## Task 14: Archive `androdr-privacy`

**Repo:** `yasirhamza/androdr-privacy`

Run only after Tasks 1–13 succeed and the pipeline is verified end-to-end. Archiving is semi-destructive — confirm with user before running if in doubt.

- [ ] **Step 1: Replace `index.md` with a forwarding pointer**

```bash
cd /tmp && rm -rf androdr-privacy-archive
gh repo clone yasirhamza/androdr-privacy androdr-privacy-archive
cd androdr-privacy-archive
cat > index.md <<'EOF'
# AndroDR Privacy Policy — Moved

The canonical AndroDR privacy policy now lives at
https://github.com/yasirhamza/AndroDR/blob/main/docs/PRIVACY_POLICY.md

It is rendered publicly at:
- https://yasirhamza.github.io/androdr-site/#privacy (GitHub Pages)
- https://androdr.yasirhamza.workers.dev/#privacy (Cloudflare Worker mirror)

This repository is archived and no longer accepts changes.
EOF
git add index.md
git commit -m "chore: archive — point to canonical privacy policy in AndroDR repo"
git push
```

- [ ] **Step 2: Archive the repo**

```bash
gh repo archive yasirhamza/androdr-privacy --yes
```

- [ ] **Step 3: Verify**

```bash
gh api repos/yasirhamza/androdr-privacy --jq '{archived, updated_at}'
```
Expected: `"archived": true`.

---

## End-to-end verification

Run after Tasks 1–14 complete. This is the gate between PR A and PR B.

- [ ] **Step 1: Live site shows fresh content**

Open `https://androdr.yasirhamza.workers.dev/#privacy` in a browser. Confirm:
- `Last updated: 2026-04-24`
- Contact is `yhamad.dev@gmail.com`
- MalwareBazaar cert hash row no longer says `(planned)`

Also open `https://yasirhamza.github.io/androdr-site/#privacy` (may 404 anonymously due to shadowban; use an authenticated GitHub session or check from the workflow logs instead).

- [ ] **Step 2: No stale email anywhere**

```bash
cd /home/yasir/AndroDR && git checkout main && git pull --ff-only
grep -rn "privacy@androdr\.dev" . --exclude-dir=.git --exclude-dir=.claude
```
Expected: no output.

- [ ] **Step 3: Archive visible**

Open `https://github.com/yasirhamza/androdr-privacy`. Confirm the archived banner and the forwarding `index.md`.

- [ ] **Step 4: Propagation test**

Make a whitespace-only commit to `docs/PRIVACY_POLICY.md` on a throwaway branch, merge it, and confirm within ~5 minutes:
- `render-privacy-worker.yml` run succeeded and pushed a "docs(privacy): render into cloudflare-worker.js" commit
- `notify-privacy-sync.yml` run succeeded
- `androdr-site/render-privacy.yml` run succeeded and pushed a "docs(privacy): sync from AndroDR@<sha>" commit
- `wrangler deploy` (manual) and re-check the live Worker

If all four steps pass, PR A is complete. Proceed to PR B.
