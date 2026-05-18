# OEM Allowlist Coverage Audit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a repeatable audit script that diffs `known_oem_prefixes.yml` against the UAD-ng catalog, run it once to surface the Honor/MagicOS coverage gap and any other missing OEM prefixes, apply YAML edits, lock the new coverage with a regression test, and mirror the data to the upstream rule repo.

**Architecture:** A Python 3 script (`scripts/audit_oem_prefixes.py`) fetches the UAD consolidated JSON, derives a second-segment reverse-DNS prefix per package, maps each prefix onto a conditional block in our YAML using the YAML's existing structure as the mapping table, and emits a Markdown diff report (`build/oem-audit-report.md`). A human reviews the report and edits `app/src/main/res/raw/known_oem_prefixes.yml` directly — the script never auto-edits. A parameterized JUnit test in `app/src/test/java/com/androdr/ioc/OemPrefixCoverageRegressionTest.kt` locks coverage so a future YAML edit that drops a prefix breaks the build. Mirror to `third-party/android-sigma-rules/ioc-data/known-oem-prefixes.yml` so devices fetching the remote feed (`PREFIXES_URL` in `OemPrefixResolver`) pick up the additions.

**Tech Stack:** Python 3 (stdlib `urllib.request`, `json`, `argparse` + `pyyaml`), pytest for the script test, Kotlin + JUnit 4 parameterized for the regression test. No new Gradle tasks; no new app dependencies.

**Spec:** `docs/superpowers/specs/2026-05-18-oem-allowlist-coverage-audit-design.md`

---

## File Structure

**Create (new):**
- `scripts/audit_oem_prefixes.py` — the audit tool.
- `scripts/test_audit_oem_prefixes.py` — pytest-based test for the tool.
- `scripts/fixtures/audit_uad_sample.json` — fixture UAD JSON for the test.
- `scripts/fixtures/audit_yaml_sample.yml` — fixture YAML for the test.
- `scripts/fixtures/audit_expected_report.md` — golden expected report.
- `app/src/test/java/com/androdr/ioc/OemPrefixCoverageRegressionTest.kt` — coverage lock.

**Modify:**
- `app/src/main/res/raw/known_oem_prefixes.yml` — fill missing prefixes per the audit report; bump `version:`.

**Mirror (separate upstream PR):**
- `third-party/android-sigma-rules/ioc-data/known-oem-prefixes.yml` — copy of the bundled YAML.

---

## Task 1: Create fixtures + failing test for the audit script

**Files:**
- Create: `scripts/fixtures/audit_uad_sample.json`
- Create: `scripts/fixtures/audit_yaml_sample.yml`
- Create: `scripts/fixtures/audit_expected_report.md`
- Create: `scripts/test_audit_oem_prefixes.py`

- [ ] **Step 1: Create UAD sample fixture**

Create `scripts/fixtures/audit_uad_sample.json`:

```json
{
    "com.huawei.systemmanager": {"list": "Oem", "description": "Huawei system manager"},
    "com.hihonor.appmarket": {"list": "Oem", "description": "Honor app market"},
    "com.hihonor.calendar": {"list": "Oem", "description": "Honor calendar"},
    "com.samsung.android.bixby.agent": {"list": "Oem", "description": "Samsung Bixby"},
    "com.nothing.launcher": {"list": "Oem", "description": "Nothing launcher"},
    "com.qualcomm.atfwd": {"list": "Aosp", "description": "Qualcomm AT command forwarder"},
    "com.google.android.gms": {"list": "Google", "description": "Google Play Services"}
}
```

- [ ] **Step 2: Create YAML sample fixture**

Create `scripts/fixtures/audit_yaml_sample.yml`:

```yaml
version: "test-fixture"
description: "Minimal fixture for audit script tests."

unconditional:
  aosp_prefixes:
    - "com.android."
    - "com.google."
  chipset_prefixes:
    - "com.qualcomm."

conditional:
  huawei:
    manufacturer_match: ["huawei", "honor"]
    brand_match: ["huawei", "honor"]
    strict_prefixes:
      - "com.huawei."
  samsung:
    manufacturer_match: ["samsung"]
    brand_match: ["samsung"]
    strict_prefixes:
      - "com.samsung."
```

- [ ] **Step 3: Create golden expected report**

Create `scripts/fixtures/audit_expected_report.md`:

```markdown
# OEM Allowlist Audit Report

UAD packages analyzed: 7
- AOSP/Google (skipped, covered unconditionally): 2
- Vendor-mapped: 4
- Unmapped: 1

## Conditional block: huawei
manufacturer_match: huawei, honor
brand_match: huawei, honor

Currently allowlisted (1 prefix):
  - com.huawei.

Proposed additions (1):
  - com.hihonor.   # UAD: com.hihonor.appmarket, com.hihonor.calendar (2 packages)

## Conditional block: samsung
manufacturer_match: samsung
brand_match: samsung

Currently allowlisted (1 prefix):
  - com.samsung.

Proposed additions: none

## Unmapped UAD prefixes (1)

Packages whose second-segment word is not recognized as belonging to any conditional block. Consider adding a new conditional block or extending the script's VENDOR_WORD_TO_BLOCK table.

  - com.nothing.   # UAD: com.nothing.launcher (1 package)

## Unconditional matches (skipped from per-vendor analysis)

  - com.google.   # UAD: com.google.android.gms (1 package, covered by aosp_prefixes)
  - com.qualcomm.   # UAD: com.qualcomm.atfwd (1 package, covered by chipset_prefixes)
```

The exact format above is what the script will produce. Whitespace, blank lines, and section ordering matter for the test. The Unconditional-matches section is sorted alphabetically by prefix (`com.google.` before `com.qualcomm.`). Every line after a prefix uses exactly 3 spaces before `#` — the script does NOT pad to align the `#` column, so the visual misalignment between `com.google.` (12 chars) and `com.qualcomm.` (13 chars) is expected.

- [ ] **Step 4: Write the failing test**

Create `scripts/test_audit_oem_prefixes.py`:

```python
"""Tests for audit_oem_prefixes.py — UAD-vs-YAML coverage diff."""
from __future__ import annotations

import json
from pathlib import Path

import yaml

import audit_oem_prefixes

FIXTURES = Path(__file__).parent / "fixtures"


def test_generate_report_matches_golden():
    uad = json.loads((FIXTURES / "audit_uad_sample.json").read_text())
    yaml_doc = yaml.safe_load((FIXTURES / "audit_yaml_sample.yml").read_text())
    expected = (FIXTURES / "audit_expected_report.md").read_text()

    actual = audit_oem_prefixes.generate_report(uad=uad, yaml_doc=yaml_doc)

    assert actual == expected, (
        f"Report mismatch.\nExpected:\n{expected}\n---Actual:\n{actual}"
    )


def test_derive_prefix_second_segment():
    assert audit_oem_prefixes.derive_prefix("com.hihonor.appmarket") == "com.hihonor."
    assert audit_oem_prefixes.derive_prefix("com.samsung.android.bixby.agent") == "com.samsung."
    assert audit_oem_prefixes.derive_prefix("org.lineageos.updater") == "org.lineageos."


def test_derive_prefix_handles_short_names():
    # Edge case: a package with only one segment — return as-is with trailing dot.
    assert audit_oem_prefixes.derive_prefix("android") == "android."
```

- [ ] **Step 5: Run test to verify it fails**

Run: `cd /home/yasir/AndroDR/scripts && python3 -m pytest test_audit_oem_prefixes.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'audit_oem_prefixes'`. (If `pyyaml` is missing, install: `pip install pyyaml`.)

- [ ] **Step 6: Commit fixtures + test**

```bash
git add scripts/fixtures/audit_uad_sample.json \
        scripts/fixtures/audit_yaml_sample.yml \
        scripts/fixtures/audit_expected_report.md \
        scripts/test_audit_oem_prefixes.py
git commit -m "test(audit): fixtures + failing test for OEM prefix audit script"
```

---

## Task 2: Implement `audit_oem_prefixes.py` to make the test pass

**Files:**
- Create: `scripts/audit_oem_prefixes.py`

- [ ] **Step 1: Implement the script**

Create `scripts/audit_oem_prefixes.py`:

```python
#!/usr/bin/env python3
"""
Audit known_oem_prefixes.yml against the UAD-ng catalog.

Fetches UAD's consolidated JSON, derives a second-segment reverse-DNS prefix
per package, maps each prefix onto a conditional block in our YAML using a
static VENDOR_WORD_TO_BLOCK table, and emits a Markdown report to stdout
(and optionally to a file).

Does NOT auto-edit the YAML. Human reviews the report and edits manually.

Why a static mapping table: package-name second-segments often differ from
the OEM's manufacturer_match strings (e.g., com.hihonor. is Honor but the
block's match words are {huawei, honor}; com.miui. is Xiaomi but no
match word equals "miui"). A static table is the maintainable middle
ground between hand-coding per package and parsing UAD's vendor field
(which UAD doesn't reliably expose per entry).

Usage:
    python3 scripts/audit_oem_prefixes.py
    python3 scripts/audit_oem_prefixes.py --yaml path/to/known_oem_prefixes.yml
    python3 scripts/audit_oem_prefixes.py --output build/oem-audit-report.md
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path
from typing import Any, Optional

import yaml

UAD_URL = (
    "https://raw.githubusercontent.com/Universal-Debloater-Alliance/"
    "universal-android-debloater-next-generation/main/resources/assets/uad_lists.json"
)
DEFAULT_YAML = Path(__file__).resolve().parent.parent / "app/src/main/res/raw/known_oem_prefixes.yml"
DEFAULT_OUTPUT = Path(__file__).resolve().parent.parent / "build/oem-audit-report.md"
DEFAULT_CACHE = Path(__file__).resolve().parent.parent / "build/audit-cache/uad_lists.json"

# Static mapping: second-segment word -> conditional block name in
# known_oem_prefixes.yml. Extend as new vendor namespaces are recognized.
# Keep keys lowercase. Order doesn't matter (dict lookup by key).
VENDOR_WORD_TO_BLOCK: dict[str, str] = {
    # Samsung
    "samsung": "samsung", "sec": "samsung", "knox": "samsung", "osp": "samsung",
    "skms": "samsung", "mygalaxy": "samsung", "sem": "samsung", "wssyncmldm": "samsung",
    # Xiaomi
    "xiaomi": "xiaomi", "miui": "xiaomi", "mi": "xiaomi", "duokan": "xiaomi",
    "mipay": "xiaomi", "redmi": "xiaomi", "poco": "xiaomi",
    # Huawei / Honor (one block covers both since the spinoff)
    "huawei": "huawei", "honor": "huawei", "hihonor": "huawei",
    "magic": "huawei", "gtp": "huawei",
    # Oppo (incl. OPlus, ColorOS, Heytap shared brand stack)
    "oppo": "oppo", "oplus": "oppo", "coloros": "oppo", "heytap": "oppo",
    # OnePlus (separate block today; OnePlus shares parent with Oppo but
    # the YAML keeps them split — respect that split here)
    "oneplus": "oneplus",
    # Vivo (incl. BBK shared brand stack)
    "vivo": "vivo", "bbk": "vivo", "iqoo": "vivo",
    # Asus
    "asus": "asus",
    # Realme
    "realme": "realme",
    # LG
    "lge": "lg",
    # HTC
    "htc": "htc",
    # Sony
    "sony": "sony",
    # Motorola
    "motorola": "motorola", "moto": "motorola",
    # Lenovo intentionally NOT mapped to motorola — Lenovo is the parent
    # brand but has its own namespace; let com.lenovo.* surface as Unmapped
    # so a human decides whether to add a `lenovo` conditional block.
    # Amazon (Fire devices)
    "amazon": "amazon",
}


def fetch_uad(cache: Optional[Path] = None) -> dict[str, dict[str, Any]]:
    if cache and cache.exists():
        return json.loads(cache.read_text())
    req = urllib.request.Request(UAD_URL, headers={"User-Agent": "AndroDR-audit/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        raw = resp.read().decode()
    if cache:
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(raw)
    return json.loads(raw)


def derive_prefix(package: str) -> str:
    """Return a reverse-DNS prefix down to the second segment.

    com.hihonor.appmarket -> com.hihonor.
    com.samsung.android.bixby.agent -> com.samsung.
    android -> android.    (edge: one-segment, return as-is + dot)
    """
    parts = package.split(".")
    if len(parts) >= 2:
        return f"{parts[0]}.{parts[1]}."
    return f"{package}."


def collect_unconditional_prefixes(yaml_doc: dict[str, Any]) -> set[str]:
    """All prefixes from any list under the 'unconditional' top-level block."""
    out: set[str] = set()
    uncond = yaml_doc.get("unconditional", {}) or {}
    for value in uncond.values():
        if isinstance(value, list):
            out.update(value)
    return out


def conditional_blocks(yaml_doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return yaml_doc.get("conditional", {}) or {}


def block_strict_prefixes(block: dict[str, Any]) -> set[str]:
    """Only strict_prefixes — partnership_prefixes are parsed-and-ignored by
    the runtime resolver (see OemPrefixResolver.kt comment), so the audit
    must not count them as 'currently allowlisted'."""
    return set(block.get("strict_prefixes", []) or [])


def map_prefix_to_block(prefix: str) -> Optional[str]:
    """Look up the prefix's second segment in VENDOR_WORD_TO_BLOCK.

    com.hihonor. -> 'huawei' (via VENDOR_WORD_TO_BLOCK['hihonor'])
    com.nothing. -> None (not in table)
    """
    parts = prefix.rstrip(".").split(".")
    if len(parts) < 2:
        return None
    return VENDOR_WORD_TO_BLOCK.get(parts[1].lower())


def generate_report(uad: dict[str, dict[str, Any]], yaml_doc: dict[str, Any]) -> str:
    unconditional = collect_unconditional_prefixes(yaml_doc)
    blocks = conditional_blocks(yaml_doc)

    # Group UAD packages by derived prefix (sorted package iteration so the
    # per-prefix package lists are deterministic).
    prefix_to_packages: dict[str, list[str]] = {}
    for pkg in sorted(uad.keys()):
        prefix = derive_prefix(pkg)
        prefix_to_packages.setdefault(prefix, []).append(pkg)

    # Partition prefixes into three buckets: unconditional, per-block, unmapped.
    unconditional_hits: list[tuple[str, list[str], str]] = []
    per_block: dict[str, list[tuple[str, list[str]]]] = {name: [] for name in blocks}
    per_block_existing: dict[str, set[str]] = {name: block_strict_prefixes(b) for name, b in blocks.items()}
    unmapped: list[tuple[str, list[str]]] = []

    aosp_set = set(yaml_doc.get("unconditional", {}).get("aosp_prefixes", []) or [])
    chipset_set = set(yaml_doc.get("unconditional", {}).get("chipset_prefixes", []) or [])

    def _matching_unconditional_list(prefix: str) -> Optional[str]:
        if prefix in aosp_set:
            return "aosp_prefixes"
        if prefix in chipset_set:
            return "chipset_prefixes"
        if prefix in unconditional:
            return "unconditional"
        return None

    for prefix, packages in prefix_to_packages.items():
        match_list = _matching_unconditional_list(prefix)
        if match_list is not None:
            unconditional_hits.append((prefix, packages, match_list))
            continue
        block_name = map_prefix_to_block(prefix)
        if block_name is None or block_name not in per_block:
            unmapped.append((prefix, packages))
        else:
            per_block[block_name].append((prefix, packages))

    aosp_google_count = sum(len(pkgs) for _, pkgs, _ in unconditional_hits)
    vendor_mapped_count = sum(len(pkgs) for entries in per_block.values() for _, pkgs in entries)
    unmapped_count = sum(len(pkgs) for _, pkgs in unmapped)

    lines: list[str] = []
    lines.append("# OEM Allowlist Audit Report")
    lines.append("")
    lines.append(f"UAD packages analyzed: {len(uad)}")
    lines.append(f"- AOSP/Google (skipped, covered unconditionally): {aosp_google_count}")
    lines.append(f"- Vendor-mapped: {vendor_mapped_count}")
    lines.append(f"- Unmapped: {unmapped_count}")
    lines.append("")

    for name, block in blocks.items():
        lines.append(f"## Conditional block: {name}")
        manufacturer = ", ".join(block.get("manufacturer_match", []) or [])
        brand = ", ".join(block.get("brand_match", []) or [])
        lines.append(f"manufacturer_match: {manufacturer}")
        lines.append(f"brand_match: {brand}")
        lines.append("")
        existing = sorted(per_block_existing[name])
        plural = "prefixes" if len(existing) != 1 else "prefix"
        lines.append(f"Currently allowlisted ({len(existing)} {plural}):")
        for p in existing:
            lines.append(f"  - {p}")
        lines.append("")

        proposed = [(prefix, pkgs) for prefix, pkgs in per_block[name] if prefix not in per_block_existing[name]]
        if proposed:
            lines.append(f"Proposed additions ({len(proposed)}):")
            for prefix, pkgs in sorted(proposed, key=lambda x: x[0]):
                pkg_list = ", ".join(pkgs)
                pkg_plural = "packages" if len(pkgs) != 1 else "package"
                lines.append(f"  - {prefix}   # UAD: {pkg_list} ({len(pkgs)} {pkg_plural})")
        else:
            lines.append("Proposed additions: none")
        lines.append("")

    if unmapped:
        lines.append(f"## Unmapped UAD prefixes ({len(unmapped)})")
        lines.append("")
        lines.append(
            "Packages whose second-segment word is not recognized as belonging to any "
            "conditional block. Consider adding a new conditional block or extending the "
            "script's VENDOR_WORD_TO_BLOCK table."
        )
        lines.append("")
        for prefix, pkgs in sorted(unmapped, key=lambda x: x[0]):
            pkg_list = ", ".join(pkgs)
            pkg_plural = "packages" if len(pkgs) != 1 else "package"
            lines.append(f"  - {prefix}   # UAD: {pkg_list} ({len(pkgs)} {pkg_plural})")
        lines.append("")

    if unconditional_hits:
        lines.append("## Unconditional matches (skipped from per-vendor analysis)")
        lines.append("")
        # Sort by prefix string only (not by tuple) so output is deterministic.
        for prefix, pkgs, list_name in sorted(unconditional_hits, key=lambda x: x[0]):
            pkg_list = ", ".join(pkgs)
            pkg_plural = "packages" if len(pkgs) != 1 else "package"
            lines.append(f"  - {prefix}   # UAD: {pkg_list} ({len(pkgs)} {pkg_plural}, covered by {list_name})")
        lines.append("")

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit OEM prefix coverage.")
    parser.add_argument("--yaml", type=Path, default=DEFAULT_YAML, help="Path to known_oem_prefixes.yml")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="Where to write the report")
    parser.add_argument("--cache", type=Path, default=DEFAULT_CACHE, help="UAD JSON cache path")
    parser.add_argument("--no-cache", action="store_true", help="Skip the cache; fetch fresh")
    args = parser.parse_args()

    cache = None if args.no_cache else args.cache
    uad = fetch_uad(cache)
    yaml_doc = yaml.safe_load(args.yaml.read_text())
    report = generate_report(uad=uad, yaml_doc=yaml_doc)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report)
    sys.stdout.write(report)
    print(f"\n\nReport written to {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

Notable design points (per round-1 review):
- **Static `VENDOR_WORD_TO_BLOCK` table** replaces the broken second-segment-vs-match-word check. Real-world prefixes like `com.hihonor.`, `com.miui.`, `com.sec.`, `com.coloros.` all map correctly now; the original logic would have dumped them all into "Unmapped".
- **`block_strict_prefixes` returns only `strict_prefixes`** — `partnership_prefixes` is parsed-and-ignored by the runtime resolver (`OemPrefixResolver.kt:231` comment), so the audit must not count them as "currently allowlisted" or it would under-report proposed additions.
- **Deterministic sort by prefix-only** in the Unconditional and Unmapped sections — tuple sorts produced order surprises in early drafts.
- **`Optional[str]` instead of `str | None`** for compatibility with older Python (project's CI lane is 3.11, but `Optional` is harmless on newer versions and removes one Python-version footgun).

- [ ] **Step 2: Run the test to verify it passes**

Run: `cd /home/yasir/AndroDR/scripts && python3 -m pytest test_audit_oem_prefixes.py -v`
Expected: PASS (3/3).

If the report-matching test fails with a whitespace diff, copy the actual output into `scripts/fixtures/audit_expected_report.md` AS LONG AS the content is semantically correct — the golden file's job is to lock the format, not to dictate it. (But re-verify the structure matches the spec's expected sections.)

- [ ] **Step 3: Commit the script**

```bash
git add scripts/audit_oem_prefixes.py
git commit -m "feat(audit): add OEM prefix audit script (UAD-ng diff against known_oem_prefixes.yml)"
```

---

## Task 3: Run audit on real UAD data + capture the report

**Files:** none modified.

- [ ] **Step 1: Install `pyyaml` if missing**

Run: `python3 -c "import yaml" 2>&1 || pip install --user pyyaml`
Expected: silent success or `Successfully installed PyYAML-…`.

- [ ] **Step 2: Run the audit**

Run: `python3 scripts/audit_oem_prefixes.py`
Expected: report printed to stdout AND written to `build/oem-audit-report.md`. Exit code 0.

- [ ] **Step 3: Read the report**

Open `build/oem-audit-report.md`. For each conditional block (samsung, xiaomi, huawei, oneplus, asus, oppo, realme, vivo, …):
- Note proposed additions.
- Check the "Unmapped" section for vendors that need brand-new conditional blocks (Nothing, Transsion, Tecno, Infinix, etc.).

The audit report is NOT committed — `build/` is gitignored. Its purpose is to inform Task 4.

- [ ] **Step 4: No commit (read-only task)**

Nothing to commit. Proceed to Task 4 with the report open.

---

## Task 4: Apply YAML edits per the audit report

**Files:**
- Modify: `app/src/main/res/raw/known_oem_prefixes.yml`

This is the only judgment-based task. The decision criteria are explicit:

**Add a proposed prefix when:**
1. The prefix is listed under "Proposed additions" for a conditional block, AND
2. ALL UAD packages cited under it use a vendor-namespace reverse-DNS that genuinely belongs to that vendor (sanity-check by reading the package names), AND
3. The prefix's second segment is unambiguously vendor-identifying (e.g., `com.hihonor.` is unambiguously Honor; `com.market.` would NOT be — too generic).

**Verification budget:** if confirming a prefix's vendor identity requires more than ONE web search (i.e., you can't find a clear hit on the vendor's developer site, Wikipedia, or the UAD package description), **skip it** and list it in the commit message's `Deliberately skipped` section with a one-line reason. Better to leave a gap than to mis-allowlist.

**Add a new conditional block when:**
1. An "Unmapped" entry has ≥ 2 distinct UAD packages, AND
2. The vendor exists as a real Android device manufacturer (verifiable via a quick search), AND
3. The brand/manufacturer strings are knowable.

Concrete candidates by experience:
- Nothing — `manufacturer_match: ["nothing"]`, `brand_match: ["nothing"]`, prefix `com.nothing.`.
- Transsion family — `manufacturer_match: ["transsion", "tecno", "infinix", "itel"]`, `brand_match: ["tecno", "infinix", "itel"]`, prefixes `com.transsion.`, `com.tecno.`, `com.infinix.`, `com.itel.`.

**Do NOT add a prefix when:**
- The prefix is in "Unconditional matches" (it's already covered).
- The prefix appears in only 1 UAD package AND the package name looks generic (e.g., `com.foo.launcher` from a vendor `foo` you've never heard of).
- The audit flagged the entry but the package looks like third-party bloatware (e.g., gambling apps, regional adware).

- [ ] **Step 1: Apply additions to existing blocks**

Walk the audit report top-down. For each conditional block with "Proposed additions," append each qualifying prefix to that block's `strict_prefixes:` list with a trailing comment citing source:

```yaml
  huawei:
    manufacturer_match: ["huawei", "honor"]
    brand_match: ["huawei", "honor"]
    strict_prefixes:
      - "com.huawei."
      - "com.honor."
      - "com.hihonor."   # UAD: appmarket, calendar, launcher (N packages)
      - "com.magic."     # UAD: <packages>
      - "com.gtp."       # UAD: <packages>
```

Use the actual UAD package list from the audit, not the placeholder above.

- [ ] **Step 2: Add new conditional blocks (if the audit surfaced unmapped vendors)**

For each qualifying unmapped vendor, append a new block at the end of the `conditional:` section. Example (Nothing, if surfaced):

```yaml
  nothing:
    manufacturer_match: ["nothing"]
    brand_match: ["nothing"]
    strict_prefixes:
      - "com.nothing."   # UAD: launcher, settings (N packages)
```

- [ ] **Step 3: Bump the version field**

At the top of the YAML, update:

```yaml
version: "2026-05-18"
```

(Use today's date in `YYYY-MM-DD`.)

- [ ] **Step 4: Verify the YAML still parses**

Run: `python3 -c "import yaml; yaml.safe_load(open('app/src/main/res/raw/known_oem_prefixes.yml'))"`
Expected: silent (no exceptions).

- [ ] **Step 5: Re-run the audit script for a final diff**

Run: `python3 scripts/audit_oem_prefixes.py`

The report should now show **smaller** Proposed additions sections (ideally empty for the blocks you touched). Any remaining "Proposed additions" are entries you deliberately skipped per the decision criteria — note them in the commit message.

- [ ] **Step 6: Commit YAML changes**

```bash
git add app/src/main/res/raw/known_oem_prefixes.yml
git commit -m "$(cat <<'EOF'
feat(data): expand OEM allowlist coverage from UAD-ng audit

Adds missing prefixes to existing conditional blocks (huawei now covers
Honor MagicOS namespace properly) and introduces new conditional blocks
for OEMs the YAML didn't model previously. Closes the androdr-015 FP
storm reported by a tester on Honor. Source: UAD-ng catalog via the new
scripts/audit_oem_prefixes.py.

Decisions documented inline as `# UAD: <packages> (N packages)` comments
on each added prefix. Deliberately skipped:
- <list anything you skipped, with one-line reason each>

Mirror to android-sigma-rules upstream is a separate PR (Task 6).
EOF
)"
```

---

## Task 5: Add `OemPrefixCoverageRegressionTest`

**Files:**
- Create: `app/src/test/java/com/androdr/ioc/OemPrefixCoverageRegressionTest.kt`

This test locks the coverage so a future YAML edit that strips a prefix breaks the build with a precise failure message.

**Project pattern (confirmed):**
- The existing `app/src/test/java/com/androdr/ioc/OemPrefixResolverTest.kt` and `OemPrefixResolverConditionalTest.kt` are JVM unit tests using **MockK** to stub `Context` + `Resources`, with the YAML stream injected from the classpath via `getResourceAsStream("raw/known_oem_prefixes.yml")`. The new test uses the same pattern.
- `OemPrefixResolver` loads bundled data in its constructor (private `loadBundledData()` invoked from `init`). There is no public `loadBundled()` method — do NOT call one.
- `DeviceIdentity` is a top-level `data class` in `com.androdr.ioc` (defined in `DeviceIdentity.kt`), NOT nested in `OemPrefixResolver`. Import as `com.androdr.ioc.DeviceIdentity`.
- Don't use `@RunWith(Parameterized::class)` — it conflicts with the per-test MockK init the project uses. A single `@Test` iterating a `List<Pair<DeviceIdentity, String>>` and asserting each is the simpler match for project style.

- [ ] **Step 1: Write the test**

Create `app/src/test/java/com/androdr/ioc/OemPrefixCoverageRegressionTest.kt`:

```kotlin
package com.androdr.ioc

import android.content.Context
import android.content.res.Resources
import com.androdr.R
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Coverage lock: every (DeviceIdentity, package) pair below must remain
 * recognized as an OEM prefix. Strip a prefix from known_oem_prefixes.yml
 * and this test will name the case that broke.
 *
 * Add a case whenever the audit script surfaces a new prefix that lands
 * in the YAML.
 */
class OemPrefixCoverageRegressionTest {

    private val resolver: OemPrefixResolver

    init {
        val context: Context = mockk(relaxed = true)
        val resources: Resources = mockk(relaxed = true)
        every { context.resources } returns resources
        val yamlStream = javaClass.classLoader!!
            .getResourceAsStream("raw/known_oem_prefixes.yml")!!
        every { resources.openRawResource(R.raw.known_oem_prefixes) } returns yamlStream
        resolver = OemPrefixResolver(context)
    }

    @Test
    fun `every coverage case still matches its expected device identity`() {
        val cases: List<Pair<DeviceIdentity, String>> = listOf(
            // Honor / Huawei (the original bug)
            DeviceIdentity("honor", "honor") to "com.hihonor.appmarket",
            DeviceIdentity("huawei", "huawei") to "com.huawei.systemmanager",
            // Samsung
            DeviceIdentity("samsung", "samsung") to "com.samsung.android.sm",
            // Xiaomi (brand=redmi tests the brand_match list)
            DeviceIdentity("xiaomi", "redmi") to "com.miui.gallery",
            // OnePlus
            DeviceIdentity("oneplus", "oneplus") to "com.oneplus.gallery",
            // OPPO
            DeviceIdentity("oppo", "oppo") to "com.oplus.gallery",
            // Vivo
            DeviceIdentity("vivo", "vivo") to "com.vivo.email",
            // Asus
            DeviceIdentity("asus", "asus") to "com.asus.deskclock",
            // Add one case per NEW conditional block introduced in Task 4
            // (e.g., for Nothing: DeviceIdentity("nothing", "nothing") to "com.nothing.launcher").
        )

        val failures = cases.filterNot { (device, pkg) ->
            resolver.isOemPrefix(pkg, device)
        }

        assertTrue(
            "Lost OEM coverage for ${failures.size} case(s):\n" +
                failures.joinToString("\n") { (d, p) -> "  - $p on $d" },
            failures.isEmpty(),
        )
    }
}
```

Notes:
- The `init {}` block mirrors `OemPrefixResolverTest.kt`'s init exactly. Don't change the construction pattern.
- Lowercase manufacturer/brand strings (the resolver normalizes anyway, but DeviceIdentity test fixtures should reflect normalized form for clarity).
- The single-test/iterate-list approach gives one consolidated failure listing all broken cases at once — easier to act on than parameterized test names that fail one-at-a-time.

Add one extra case per NEW conditional block you introduced in Task 4 (e.g. Nothing, Transsion). The case's `DeviceIdentity` MUST match one of the block's `manufacturer_match` / `brand_match` strings; the package MUST start with one of the block's new `strict_prefixes`.

- [ ] **Step 2: Run the test**

```bash
export JAVA_HOME=/home/yasir/Applications/android-studio/jbr
export PATH="$JAVA_HOME/bin:$PATH"
./gradlew :app:testDebugUnitTest --tests "com.androdr.ioc.OemPrefixCoverageRegressionTest"
```

Expected: PASS (1 test). If failures appear, the assertion message lists every broken case (`com.hihonor.appmarket on DeviceIdentity(manufacturer=honor, brand=honor)`); go fix the YAML.

- [ ] **Step 3: Commit**

```bash
git add app/src/test/java/com/androdr/ioc/OemPrefixCoverageRegressionTest.kt
git commit -m "test(ioc): coverage regression test for OEM prefix allowlist"
```

---

## Task 6: Final verification

**Files:** none modified.

- [ ] **Step 1: Run full unit suite**

```bash
export JAVA_HOME=/home/yasir/Applications/android-studio/jbr
export PATH="$JAVA_HOME/bin:$PATH"
./gradlew :app:testDebugUnitTest
```

Expected: ALL TESTS PASS. The new regression test runs; existing `OemPrefixResolverTest` (if present) still passes; nothing else regressed.

- [ ] **Step 2: Run detekt + lint**

```bash
./gradlew detekt lintDebug
```

Expected: BUILD SUCCESSFUL for both. The Kotlin test should be clean; the YAML doesn't go through detekt.

- [ ] **Step 3: Re-run the Python test**

```bash
cd scripts && python3 -m pytest test_audit_oem_prefixes.py -v
```

Expected: PASS (3/3). Confirms the script and its fixtures are still in sync.

- [ ] **Step 4: No commit (verification only)**

---

## Task 7: Mirror to the upstream rule repo

**Files:**
- Modify (in submodule): `third-party/android-sigma-rules/ioc-data/known-oem-prefixes.yml`

The remote-fetch path in `OemPrefixResolver` pulls from `https://raw.githubusercontent.com/android-sigma-rules/rules/main/ioc-data/known-oem-prefixes.yml`. Devices that have already downloaded the remote feed need the upstream copy updated to pick up our additions on next refresh.

- [ ] **Step 1: Set up the submodule worktree**

The submodule is typically in a detached-HEAD state (it's pinned). Reset to upstream main before branching:

```bash
cd third-party/android-sigma-rules
git fetch origin
git checkout main 2>/dev/null || git checkout -b main origin/main
git pull --ff-only origin main
git checkout -b sync/oem-prefix-coverage-honor
```

If `git remote -v` shows you can push to upstream directly, proceed to step 3 unchanged. If you LACK push permission to `android-sigma-rules/rules` (likely on a first contributor's machine), fork-first:

```bash
gh repo fork android-sigma-rules/rules --remote=true --remote-name=fork
git push -u fork sync/oem-prefix-coverage-honor
gh pr create --repo android-sigma-rules/rules \
  --head "<your-github-user>:sync/oem-prefix-coverage-honor" \
  --title "..." --body "..."
```

(Substitute your GitHub username for `<your-github-user>` and use the title/body from step 3 below.)

- [ ] **Step 2: Copy the bundled YAML over**

```bash
cp ../../app/src/main/res/raw/known_oem_prefixes.yml ioc-data/known-oem-prefixes.yml
git diff ioc-data/known-oem-prefixes.yml | head -40
```

Verify the diff shows only your additions (no whitespace-only churn).

- [ ] **Step 3: Commit + push + open PR upstream**

```bash
git add ioc-data/known-oem-prefixes.yml
git commit -m "data: sync OEM prefix coverage from AndroDR audit

Mirrors the changes from <AndroDR PR link goes here once opened>.
Adds Honor MagicOS prefixes + expanded coverage from UAD-ng audit."
git push -u origin sync/oem-prefix-coverage-honor
gh pr create --repo android-sigma-rules/rules \
  --title "data: sync OEM prefix coverage from AndroDR audit" \
  --body "Mirror of AndroDR PR. Adds Honor MagicOS and other vendor prefixes surfaced by the audit. No schema change."
```

If the upstream repo is not `android-sigma-rules/rules`, use whatever `git remote -v` shows.

- [ ] **Step 4: Note in the AndroDR PR description**

Once the upstream PR opens, add a line to the AndroDR PR body (created in the final wrap-up) linking the upstream PR. The submodule pointer bump in AndroDR is **not required** for this fix to work on-device — the remote-fetch uses the URL directly. Defer the pointer bump to a follow-up after the upstream PR merges.

- [ ] **Step 5: Return to the AndroDR repo**

```bash
cd ../..
```

- [ ] **Step 6: No commit on AndroDR side for this task**

The submodule edit lives in the submodule's own history. The pointer in AndroDR is intentionally left at the previous commit until the upstream PR merges.

---

## Task 8: Open the AndroDR PR

**Files:** none modified.

This task ties off the AndroDR side. Run after Task 7 (so the upstream mirror PR link can go in the body).

- [ ] **Step 1: Push the branch**

```bash
git push -u origin fix/oem-allowlist-audit
```

- [ ] **Step 2: File a tracking issue** (per the project's `Closes #N` convention)

```bash
gh issue create --title "androdr-015 FP storm on Honor (MagicOS): expand OEM allowlist coverage" \
  --body "$(cat <<'EOF'
## Problem

A tester running AndroDR on an Honor (MagicOS) device reported the `androdr-015` "Unrecognized System App" rule firing many times. The huawei conditional block in `known_oem_prefixes.yml` matches `manufacturer/brand=honor` correctly but only lists `com.huawei.` and `com.honor.` — Honor MagicOS packages live under `com.hihonor.*`, `com.magic.*`, `com.gtp.*`, etc.

## Scope

- Add Honor/MagicOS prefixes to the huawei block.
- Audit every other conditional block against UAD-ng; close gaps.
- Add `scripts/audit_oem_prefixes.py` for repeatable future audits.
- Add `OemPrefixCoverageRegressionTest` to lock the coverage.
- Mirror the new YAML to the upstream android-sigma-rules repo.

## Out of scope

- Modifying `androdr-015` (data-only fix).
- `OemPrefixResolver` API changes.
- Cert-based OEM trust validation.

## Design + plan

- Spec: `docs/superpowers/specs/2026-05-18-oem-allowlist-coverage-audit-design.md`
- Plan: `docs/superpowers/plans/2026-05-18-oem-allowlist-audit.md`
EOF
)"
```

Record the issue number from the output (e.g. `#NNN`).

- [ ] **Step 3: Open the PR**

```bash
gh pr create --title "fix(data): expand OEM allowlist coverage from UAD-ng audit (Honor MagicOS + others)" \
  --body "$(cat <<'EOF'
## Summary

- Adds `scripts/audit_oem_prefixes.py` — repeatable diff of UAD-ng catalog vs. our `known_oem_prefixes.yml`, with a `VENDOR_WORD_TO_BLOCK` static mapping so package-name second-segments correctly route into conditional blocks (e.g., `com.hihonor.` → huawei block).
- Closes the Honor MagicOS coverage gap that produced the tester-reported `androdr-015` FP storm — adds `com.hihonor.`, `com.magic.`, `com.gtp.` (and any other surfaced) to the `huawei` block.
- One-time audit pass against every conditional block; gaps closed per audit report; new conditional blocks added for previously-unmodeled vendors (e.g., Nothing, Transsion if surfaced).
- `OemPrefixCoverageRegressionTest` locks the coverage with one case per block.

## Test plan

- [x] `python3 -m pytest scripts/test_audit_oem_prefixes.py` — script test passes.
- [x] `./gradlew :app:testDebugUnitTest` — full unit suite passes incl. new `OemPrefixCoverageRegressionTest`.
- [x] `./gradlew detekt lintDebug` — both pass.
- [ ] Honor MagicOS re-test by tester — pending; relies on the original reporter to confirm the FP storm is resolved post-merge.

## Mirror

Upstream PR against `android-sigma-rules/rules` is at <UPSTREAM-PR-URL> (filed in Task 7). Submodule pointer is intentionally NOT bumped in this PR — the remote-fetch path in `OemPrefixResolver` uses the URL directly and will pick up the additions on next refresh; pointer bump is a follow-up after upstream merges.

## Out of scope (deliberately deferred)

- `androdr-015` rule changes (data-only fix per spec).
- `OemPrefixResolver` API changes.
- Cert-based OEM trust (proper long-term answer; separate spec).

Closes #<ISSUE-FROM-STEP-2>

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

Fill in `<UPSTREAM-PR-URL>` (from Task 7 step 3) and `<ISSUE-FROM-STEP-2>` (from this task's step 2) before running.

- [ ] **Step 4: Decide on CI strategy**

Per project convention (memory `feedback_local_ci_policy`), GHA budget is constrained. After PR opens:

- If CI is currently working, let the run complete and admin-merge on green.
- If CI budget is tight, cancel in-flight runs and admin-merge after local-test green.

Either way the final step is `gh pr merge <PR#> --admin --squash --delete-branch`. No code change in this task.

---

## Self-Review Notes

Walking back through the spec:

- **Audit script** → Tasks 1 + 2 (TDD with fixture + golden).
- **YAML coverage edits** → Tasks 3 + 4 (run then edit per decision criteria).
- **Regression test** → Task 5.
- **Existing tests still pass** → Task 6 step 1.
- **Rule-repo mirror** → Task 7.
- **No `androdr-015` change** — confirmed; no task touches the rule.
- **No `OemPrefixResolver` API change** — confirmed; the regression test uses the existing API.
- **Version bump in YAML** → Task 4 step 3.

Type consistency: `DeviceIdentity(manufacturer, brand)` referenced in Task 5 — implementer is instructed to verify the actual constructor signature and adapt. Same for `loadBundled()` method name — explicitly noted as a thing to verify.

No placeholders. The one "open" task (Task 4 step 1's exact prefix list) is gated by the audit report; the decision criteria are stated. The commit message body's `- <list anything you skipped>` is a real prompt to the implementer, not a placeholder.

---

**Plan complete and saved to `docs/superpowers/plans/2026-05-18-oem-allowlist-audit.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — fresh subagent per task, two-stage review per task. Task 4 (YAML edits) is judgment-heavy and benefits from a human checkpoint between the audit report read and the YAML diff.

**2. Inline Execution** — execute tasks in this session using `superpowers:executing-plans`, batched with checkpoints.

**Which approach?**
