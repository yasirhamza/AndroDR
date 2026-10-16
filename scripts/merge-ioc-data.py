#!/usr/bin/env python3
"""
Generate AndroDR's bundled IOC lists from the android-sigma-rules `ioc-data`.

The bundled files under app/src/main/res/raw are GENERATED, never hand-edited
and never appended to: every run rewrites them from ioc-data, so an entry
removed upstream disappears from the bundle.

Usage:
    python3 scripts/merge-ioc-data.py [--repo-dir DIR] [--raw-dir DIR] [--check]

--repo-dir defaults to the pinned submodule third-party/android-sigma-rules
(no cloning). With --check nothing is written; the script exits 1 and names
the files that differ from what ioc-data would generate.
"""

import argparse
import json
import os
import sys
import yaml


ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
DEFAULT_REPO_DIR = os.path.join(ROOT, "third-party", "android-sigma-rules")
DEFAULT_RAW_DIR = os.path.join(ROOT, "app", "src", "main", "res", "raw")

ALLOWED_SOURCES_PATH = os.path.join(
    DEFAULT_REPO_DIR, "validation", "allowed-sources.json"
)

FILES = {
    # known_campaigns.json is rendered separately: [{"key", "label", "aliases"}] from campaigns.yml
    "known_bad_domains.json":    ("c2-domains.yml",     "domain"),
    "known_bad_packages.json":   ("package-names.yml",  "packageName"),
    "known_bad_certs.json":      ("cert-hashes.yml",    "certHash"),
    "known_bad_apk_hashes.json": ("malware-hashes.yml", "apkHash"),
}


def load_yaml(path):
    with open(path) as f:
        data = yaml.safe_load(f)
    return data.get("entries", []) if data else []


def load_allowed_sources():
    """Load allowed source IDs from the submodule registry."""
    if not os.path.exists(ALLOWED_SOURCES_PATH):
        print(f"WARNING: allowed-sources.json not found at {ALLOWED_SOURCES_PATH}", file=sys.stderr)
        print("  Skipping source validation (submodule may not be initialized)", file=sys.stderr)
        return None
    with open(ALLOWED_SOURCES_PATH) as f:
        entries = json.load(f)
    return {entry["id"] for entry in entries}


def validate_sources(entries, allowed_sources):
    """Validate source field on all entries. Return list of errors."""
    if allowed_sources is None:
        return []
    errors = []
    for i, entry in enumerate(entries):
        source = entry.get("source")
        if not source:
            errors.append(f"Entry {i}: missing 'source' field (indicator: {entry.get('indicator', '?')})")
        elif source not in allowed_sources:
            errors.append(f"Entry {i}: unknown source '{source}' (indicator: {entry.get('indicator', '?')})")
    return errors


def _row(key, e):
    family_key = "name" if key == "packageName" else "familyName"
    value = str(e["indicator"])
    if key != "packageName":
        value = value.lower()
    row = {key: value, family_key: e.get("family", ""), "category": e.get("category", ""),
           "campaign": e.get("campaign", ""), "severity": e.get("severity", "HIGH"),
           "description": e.get("description", ""), "source": e.get("source", ""),
           "reference": e.get("reference", "")}
    if key == "domain":
        row["blockByDefault"] = bool(e.get("block_by_default", False))
    return row


def render(repo_dir):
    """filename -> JSON text the bundle must contain."""
    out = {}
    for fname, (src, key) in FILES.items():
        entries = [e for e in load_yaml(os.path.join(repo_dir, "ioc-data", src)) if "indicator" in e]
        rows = sorted((_row(key, e) for e in entries), key=lambda r: r[key])
        out[fname] = json.dumps(rows, indent=2, ensure_ascii=True) + "\n"
    with open(os.path.join(repo_dir, "ioc-data", "campaigns.yml")) as f:
        camps = (yaml.safe_load(f) or {}).get("campaigns", [])
    out["known_campaigns.json"] = json.dumps(
        sorted(({"key": c["key"], "label": c["label"], "aliases": sorted(c.get("aliases", []))} for c in camps),
               key=lambda c: c["key"]),
        indent=2, ensure_ascii=True) + "\n"
    return out


def generate(repo_dir, raw_dir):
    for fname, text in render(repo_dir).items():
        with open(os.path.join(raw_dir, fname), "w") as f:
            f.write(text)


def check(repo_dir, raw_dir):
    """Names of bundled files that differ from what ioc-data generates."""
    bad = []
    for fname, text in render(repo_dir).items():
        path = os.path.join(raw_dir, fname)
        if not os.path.exists(path) or open(path).read() != text:
            bad.append(fname)
    return bad


def main():
    parser = argparse.ArgumentParser(description=__doc__.strip().split("\n")[0])
    parser.add_argument("--repo-dir", default=DEFAULT_REPO_DIR,
                        help="android-sigma-rules checkout (default: the pinned submodule)")
    parser.add_argument("--raw-dir", default=DEFAULT_RAW_DIR, help="bundled res/raw directory")
    parser.add_argument("--check", action="store_true",
                        help="write nothing; exit 1 if the bundle differs from ioc-data")
    args = parser.parse_args()

    allowed_sources = load_allowed_sources()
    all_errors = []
    for label, src, _ in [(k, v[0], v[1]) for k, v in FILES.items()]:
        ioc_file = os.path.join(args.repo_dir, "ioc-data", src)
        if os.path.exists(ioc_file):
            all_errors.extend(f"[{label}] {e}" for e in validate_sources(load_yaml(ioc_file), allowed_sources))
    if all_errors:
        print(f"ERROR: Source validation failed ({len(all_errors)} error(s)):", file=sys.stderr)
        for err in all_errors:
            print(f"  - {err}", file=sys.stderr)
        sys.exit(1)

    if args.check:
        bad = check(args.repo_dir, args.raw_dir)
        if bad:
            print(f"Bundled files differ from ioc-data: {', '.join(bad)}. "
                  "Run: python3 scripts/merge-ioc-data.py", file=sys.stderr)
            sys.exit(1)
        print("Bundled IOC lists match ioc-data.")
        return

    generate(args.repo_dir, args.raw_dir)
    print("Bundled IOC lists regenerated from ioc-data.")


if __name__ == "__main__":
    main()
