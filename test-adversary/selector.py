#!/usr/bin/env python3
"""selector.py — Manifest parser and scenario selector for AndroDR test-adversary.

Loads a YAML manifest (v3 format with `profiles` and `scenarios` blocks) and
resolves composable selection filters.

CLI usage:
    python3 selector.py manifest.yml [--profile X] [--track N,M] \\
        [--risk high,medium] [--only a,b] [--random N]

Prints selected scenario IDs to stdout, one per line.
Exits 1 with error message if no scenarios match.
"""

from __future__ import annotations

import argparse
import random
import sys
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    sys.exit("ERROR: PyYAML required. Install: pip3 install pyyaml")


# ── Risk weights for weighted random sampling ────────────────────────────────

RISK_WEIGHTS: dict[str, int] = {
    "high": 3,
    "medium": 2,
    "low": 1,
}


# ── Core functions ───────────────────────────────────────────────────────────


def load_manifest(path: str | Path) -> dict[str, Any]:
    """Read and return a parsed YAML manifest."""
    with open(path) as fh:
        return yaml.safe_load(fh)


def _expand_profile(
    manifest: dict[str, Any],
    profile_name: str,
    visited: set[str] | None = None,
) -> list[str]:
    """Recursively expand a profile into a flat list of scenario-ID patterns.

    Supports two profile formats:

    **Flat list** (used by unit tests / legacy)::

        profiles:
          pegasus: [mercenary_package_name, mercenary_cert_hash]

    **Dict with keys** (v3 manifest)::

        profiles:
          pegasus:
            description: "..."
            scenarios: [mercenary_package_name, ...]
          journalist:
            profiles: [pegasus, predator]   # nested profile references
            scenarios: [stalk_*]

    In the flat-list format, entries starting with ``@`` are recursive
    profile references (e.g. ``"@pegasus"``).

    Circular references are detected via *visited*.
    """
    if visited is None:
        visited = set()

    if profile_name in visited:
        return []
    visited.add(profile_name)

    profiles = manifest.get("profiles", {})
    entry = profiles.get(profile_name)
    if entry is None:
        return []

    patterns: list[str] = []

    # Dict-style profile (v3 manifest): has 'scenarios' and/or 'profiles' keys
    if isinstance(entry, dict):
        # Recursively include nested profiles
        for nested in entry.get("profiles", []):
            patterns.extend(_expand_profile(manifest, str(nested), visited))
        # Include scenario ID patterns
        for s in entry.get("scenarios", []):
            patterns.append(str(s))
    else:
        # Flat list style (unit tests / legacy)
        for item in entry:
            if isinstance(item, str) and item.startswith("@"):
                # Recursive profile reference
                nested = item[1:]
                patterns.extend(_expand_profile(manifest, nested, visited))
            else:
                patterns.append(str(item))

    return patterns


def _match_patterns(scenario_id: str, patterns: list[str]) -> bool:
    """Return True if *scenario_id* matches any fnmatch glob *patterns*."""
    return any(fnmatch(scenario_id, p) for p in patterns)


def resolve_scenarios(
    manifest: dict[str, Any],
    *,
    profile: str | None = None,
    tracks: list[int] | None = None,
    risks: list[str] | None = None,
    only: list[str] | None = None,
    random_n: int | None = None,
) -> list[dict[str, Any]]:
    """Select scenarios from *manifest* using composable filters.

    Filter composition:
    - ``only`` overrides every other filter.
    - All other active filters compose as **intersection** — a scenario must
      satisfy *all* of them.
    - ``random_n`` performs weighted sampling on the filtered set.

    Returns a list of scenario dicts.
    """
    scenarios: list[dict[str, Any]] = manifest.get("scenarios", [])

    # --only overrides everything
    if only:
        candidates = [s for s in scenarios if s["id"] in only]
        return candidates

    candidates = list(scenarios)

    # --profile filter
    if profile is not None:
        patterns = _expand_profile(manifest, profile)
        if patterns:
            candidates = [s for s in candidates if _match_patterns(s["id"], patterns)]
        else:
            # Profile not found or empty — nothing can match
            candidates = []

    # --track filter
    if tracks:
        candidates = [s for s in candidates if s.get("track") in tracks]

    # --risk filter
    if risks:
        normalised = [r.lower() for r in risks]
        candidates = [s for s in candidates if s.get("risk", "").lower() in normalised]

    # --random weighted sampling
    if random_n is not None and candidates:
        weights = [RISK_WEIGHTS.get(s.get("risk", "low").lower(), 1) for s in candidates]
        count = min(random_n, len(candidates))
        chosen_indices: set[int] = set()
        pool_indices = list(range(len(candidates)))
        pool_weights = list(weights)
        result: list[dict[str, Any]] = []
        # Weighted sampling without replacement
        while len(result) < count and pool_indices:
            picks = random.choices(pool_indices, weights=pool_weights, k=1)
            idx = picks[0]
            if idx not in chosen_indices:
                chosen_indices.add(idx)
                result.append(candidates[idx])
                # Remove from pool
                pos = pool_indices.index(idx)
                pool_indices.pop(pos)
                pool_weights.pop(pos)
        return result

    return candidates


# ── CLI entry point ──────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Select scenarios from an AndroDR adversary manifest."
    )
    parser.add_argument("manifest", help="Path to the YAML manifest file")
    parser.add_argument("--profile", default=None, help="Profile name to select")
    parser.add_argument(
        "--track",
        default=None,
        help="Comma-separated track numbers (e.g. 1,3)",
    )
    parser.add_argument(
        "--risk",
        default=None,
        help="Comma-separated risk levels (e.g. high,medium)",
    )
    parser.add_argument(
        "--only",
        default=None,
        help="Comma-separated scenario IDs — overrides all other filters",
    )
    parser.add_argument(
        "--random",
        type=int,
        default=None,
        metavar="N",
        help="Randomly select N scenarios (weighted by risk)",
    )

    args = parser.parse_args(argv)

    manifest = load_manifest(args.manifest)

    tracks = [int(t) for t in args.track.split(",")] if args.track else None
    risks = [r.strip() for r in args.risk.split(",")] if args.risk else None
    only = [o.strip() for o in args.only.split(",")] if args.only else None

    selected = resolve_scenarios(
        manifest,
        profile=args.profile,
        tracks=tracks,
        risks=risks,
        only=only,
        random_n=args.random,
    )

    if not selected:
        print("ERROR: no scenarios matched the given filters", file=sys.stderr)
        sys.exit(1)

    for s in selected:
        print(s["id"])


if __name__ == "__main__":
    main()
