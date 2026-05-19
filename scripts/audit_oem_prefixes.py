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
    "magic": "huawei",
    # gtp intentionally NOT mapped: com.gtp.* is the Go Dev Team (3P launcher
    # publisher), not an Honor/Huawei namespace, even though Honor MagicOS
    # preloads GO Launcher. Let it surface in Unmapped for human review.
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
