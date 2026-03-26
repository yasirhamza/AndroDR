#!/usr/bin/env python3
"""
Generate res/raw/known_good_apps.json from UAD-ng + Plexus community sources.

Usage:
    python3 scripts/generate_known_good_apps.py

Output: app/src/main/res/raw/known_good_apps.json

Run this script and commit the updated JSON whenever you want to refresh the
bundled snapshot (e.g. before a release).
"""
import json
import urllib.request
from pathlib import Path

UAD_URL = (
    "https://raw.githubusercontent.com/Universal-Debloater-Alliance/"
    "universal-android-debloater-next-generation/main/resources/assets/uad_lists.json"
)
PLEXUS_BASE = "https://plexus.techlore.tech/api/v1/apps?limit=500"
OUT_PATH = Path(__file__).parent.parent / "app/src/main/res/raw/known_good_apps.json"

LIST_TO_CATEGORY = {
    "Oem":     "OEM",
    "Carrier": "OEM",
    "Misc":    "OEM",
    "Aosp":    "AOSP",
    "Google":  "GOOGLE",
}


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "AndroDR-script/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode()


def fetch_uad() -> list[dict]:
    print("Fetching UAD-ng …")
    entries = []
    try:
        data = json.loads(fetch(UAD_URL))
        for pkg, info in data.items():
            list_val = info.get("list", "")
            category = LIST_TO_CATEGORY.get(list_val)
            if category is None:
                continue
            entries.append({
                "packageName": pkg,
                "displayName": info.get("description") or pkg,
                "category": category,
                "sourceId": "bundled",
                "fetchedAt": 0,
            })
    except Exception as e:
        print(f"  UAD-ng: error fetching/parsing — {e}. Continuing with {len(entries)} entries.")
    print(f"  UAD-ng: {len(entries)} entries")
    return entries


def fetch_plexus() -> list[dict]:
    print("Fetching Plexus …")
    entries = []
    page = 1
    while True:
        try:
            data = json.loads(fetch(f"{PLEXUS_BASE}&page={page}"))
            apps = data.get("data", [])
            meta = data.get("meta", {})
            for app in apps:
                pkg = app.get("package", "").strip()
                if not pkg:
                    continue
                entries.append({
                    "packageName": pkg,
                    "displayName": app.get("name") or pkg,
                    "category": "USER_APP",
                    "sourceId": "bundled",
                    "fetchedAt": 0,
                })
            current = meta.get("page_number", meta.get("current_page", 1))
            total   = meta.get("total_pages", 1)
            print(f"  Plexus page {current}/{total} …")
            if current >= total:
                break
            page += 1
        except Exception as e:
            print(f"  Plexus: error on page {page} — {e}. Stopping pagination.")
            break
    print(f"  Plexus: {len(entries)} entries")
    return entries


def main():
    uad     = fetch_uad()
    plexus  = fetch_plexus()

    # UAD-ng takes precedence over Plexus for the same package name
    merged: dict[str, dict] = {}
    for e in plexus:
        merged[e["packageName"]] = e
    for e in uad:
        merged[e["packageName"]] = e  # overwrite Plexus if same pkg

    result = sorted(merged.values(), key=lambda x: x["packageName"])
    OUT_PATH.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    print(f"\nWrote {len(result)} entries to {OUT_PATH}")


if __name__ == "__main__":
    main()
