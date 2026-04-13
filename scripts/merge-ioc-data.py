#!/usr/bin/env python3
"""
Merge IOC data from the public android-sigma-rules repo into AndroDR's
bundled JSON/txt files for offline baseline.

Usage:
    python3 scripts/merge-ioc-data.py [--repo-dir /path/to/rules/clone]

If --repo-dir is not specified, clones the public repo to /tmp/androdr-rules-merge.
"""

import argparse
import json
import os
import subprocess
import sys
import yaml


REPO_URL = "https://github.com/android-sigma-rules/rules.git"

ALLOWED_SOURCES_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..",
    "third-party", "android-sigma-rules", "validation", "allowed-sources.json"
)
DEFAULT_CLONE_DIR = "/tmp/androdr-rules-merge"

BUNDLED_PACKAGES = "app/src/main/res/raw/known_bad_packages.json"
BUNDLED_CERTS = "app/src/main/res/raw/known_bad_certs.json"
BUNDLED_DOMAINS = "app/src/main/res/raw/domain_blocklist.txt"


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


def merge_packages(entries, bundled_path):
    with open(bundled_path) as f:
        existing = json.load(f)

    existing_names = {e["packageName"] for e in existing}

    added = 0
    for entry in entries:
        indicator = entry.get("indicator", "")
        if indicator and indicator not in existing_names:
            existing.append({
                "packageName": indicator,
                "name": entry.get("family", indicator),
                "category": entry.get("category", "MALWARE"),
                "severity": entry.get("severity", "CRITICAL"),
                "description": entry.get("description", "")
            })
            existing_names.add(indicator)
            added += 1

    with open(bundled_path, "w") as f:
        json.dump(existing, f, indent=2)

    print(f"  Packages: {added} new entries added (total: {len(existing)})")


def merge_certs(entries, bundled_path):
    with open(bundled_path) as f:
        existing = json.load(f)

    existing_hashes = {e["certHash"] for e in existing}

    added = 0
    for entry in entries:
        indicator = entry.get("indicator", "").lower()
        if indicator and indicator not in existing_hashes:
            existing.append({
                "certHash": indicator,
                "familyName": entry.get("family", ""),
                "category": entry.get("category", "MALWARE"),
                "severity": entry.get("severity", "CRITICAL"),
                "description": entry.get("description", "")
            })
            existing_hashes.add(indicator)
            added += 1

    with open(bundled_path, "w") as f:
        json.dump(existing, f, indent=2)

    print(f"  Cert hashes: {added} new entries added (total: {len(existing)})")


def merge_domains(entries, bundled_path):
    with open(bundled_path) as f:
        existing_lines = f.read().strip().split("\n")

    existing_domains = {
        line.strip().lower()
        for line in existing_lines
        if line.strip() and not line.startswith("#")
    }

    added = 0
    new_lines = []
    for entry in entries:
        domain = entry.get("indicator", "").lower().strip()
        if domain and domain not in existing_domains:
            new_lines.append(domain)
            existing_domains.add(domain)
            added += 1

    if new_lines:
        with open(bundled_path, "a") as f:
            f.write(f"\n# Public repo IOC data (auto-merged)\n")
            for domain in sorted(new_lines):
                f.write(f"{domain}\n")

    print(f"  Domains: {added} new entries added (total: {len(existing_domains)})")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-dir", default=None)
    args = parser.parse_args()

    repo_dir = args.repo_dir
    if not repo_dir:
        repo_dir = DEFAULT_CLONE_DIR
        if os.path.exists(repo_dir):
            subprocess.run(["git", "-C", repo_dir, "pull", "--quiet"], check=True)
        else:
            subprocess.run(
                ["git", "clone", "--quiet", REPO_URL, repo_dir], check=True
            )

    print("Merging IOC data from public repo into bundled files...")

    pkg_path = os.path.join(repo_dir, "ioc-data", "package-names.yml")
    cert_path = os.path.join(repo_dir, "ioc-data", "cert-hashes.yml")
    domain_path = os.path.join(repo_dir, "ioc-data", "c2-domains.yml")

    allowed_sources = load_allowed_sources()

    # Validate all source entries before merging
    all_errors = []
    for label, ioc_file in [("packages", pkg_path), ("certs", cert_path), ("domains", domain_path)]:
        if os.path.exists(ioc_file):
            entries = load_yaml(ioc_file)
            errs = validate_sources(entries, allowed_sources)
            if errs:
                all_errors.extend([f"[{label}] {e}" for e in errs])

    if all_errors:
        print(f"ERROR: Source validation failed ({len(all_errors)} error(s)):", file=sys.stderr)
        for err in all_errors:
            print(f"  - {err}", file=sys.stderr)
        sys.exit(1)

    if os.path.exists(pkg_path):
        merge_packages(load_yaml(pkg_path), BUNDLED_PACKAGES)

    if os.path.exists(cert_path):
        merge_certs(load_yaml(cert_path), BUNDLED_CERTS)

    if os.path.exists(domain_path):
        merge_domains(load_yaml(domain_path), BUNDLED_DOMAINS)

    print("Done.")


if __name__ == "__main__":
    main()
