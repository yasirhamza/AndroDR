"""Pins run.sh's cert-hash seeding to the debug app code it depends on.

History. run.sh used to write the fixture's signing cert into the app's `indicators` table with
`sqlite3` on the device. Schema 19 renamed that table's columns and the INSERT silently stopped
working; later the emulator image and the test phone turned out to have no `sqlite3` at all, so
`mercenary_cert_hash` could not be set up and was left out of the 2026-11-12 release battery (#424).

Now the debug build seeds the row itself: run.sh sends a broadcast with the hash, and the debug
receiver inserts an `Indicator` through the app's own DAO and reloads the indicator cache. The row is
type-checked by the compiler (AdversarySeedTest covers it), so nothing here parses SQL any more. These
tests keep the two sides of that broadcast, and the log line run.sh waits for, from drifting apart.

CI: the `python-pipeline` job runs this file; test_ci_path_filter_covers_every_input pins its inputs.
"""

import re
from pathlib import Path

HERE = Path(__file__).parent
REPO = HERE.parent
RUN_SH = HERE / "run.sh"
DEBUG = REPO / "app" / "src" / "debug"
SEED_KT = DEBUG / "java" / "com" / "androdr" / "debug" / "AdversarySeed.kt"
RECEIVER_KT = DEBUG / "java" / "com" / "androdr" / "debug" / "ScanBroadcastReceiver.kt"
DEBUG_MANIFEST = DEBUG / "AndroidManifest.xml"
RESOLVER = REPO / "app" / "src" / "main" / "java" / "com" / "androdr" / "ioc" / "IndicatorResolver.kt"
CI_YML = REPO / ".github" / "workflows" / "ci.yml"


def kotlin_const(name):
    m = re.search(rf'const val {name} = "([^"]+)"', SEED_KT.read_text())
    assert m, f"{name} not found in {SEED_KT.name}"
    return m.group(1)


def seed_body():
    body = RUN_SH.read_text().split("seed_cert_hash()", 1)[1].split("\n}\n", 1)[0]
    return "\n".join(ln for ln in body.splitlines() if not ln.lstrip().startswith("#"))


def shell_var(name):
    m = re.search(rf'^{name}="([^"]*)"', RUN_SH.read_text(), re.MULTILINE)
    assert m, f"{name} not set in run.sh"
    return m.group(1)


def test_seeding_needs_no_sqlite3_on_the_device():
    code = "\n".join(ln for ln in RUN_SH.read_text().splitlines() if not ln.lstrip().startswith("#"))
    assert "sqlite3" not in code
    assert "INSERT" not in code


def test_run_sh_sends_the_broadcast_the_debug_receiver_handles():
    action, extra = kotlin_const("ACTION_SEED_CERT"), kotlin_const("EXTRA_CERT_HASH")
    body = seed_body()
    assert f"-a {action}" in body
    assert f'--es {extra} "$cert_hash"' in body
    assert "com.androdr.debug/com.androdr.debug.ScanBroadcastReceiver" in body
    assert f'android:name="{action}"' in DEBUG_MANIFEST.read_text()
    receiver = RECEIVER_KT.read_text()
    assert "AdversarySeed.ACTION_SEED_CERT" in receiver
    assert "refreshCache()" in receiver, "the seeded row must reach the in-memory indicator cache"


def test_cache_refresh_wait_matches_indicator_resolver():
    """run.sh waits for refreshCache()'s own log line, under IndicatorResolver's tag.

    The receiver's own "complete" lines are not proof the cache was reloaded.
    """
    src = RESOLVER.read_text()
    tag = re.search(r'TAG\s*=\s*"([^"]+)"', src).group(1)
    assert shell_var("CACHE_REFRESH_TAG") == tag
    line = shell_var("CACHE_REFRESH_LINE")
    refresh = src[src.index("suspend fun refreshCache"):]
    refresh = refresh[: refresh.index("\n    }\n")]
    assert f'"{line}' in refresh, f"{line!r} is not logged by refreshCache()"
    assert "Update complete" not in seed_body()
    assert "ACTION_UPDATE" not in seed_body(), "a feed update can skip the refresh when another update holds the lock"


def test_ci_path_filter_covers_every_input():
    """The seed gate must run when any file it reads changes, not only run.sh."""
    import yaml
    jobs = yaml.safe_load(CI_YML.read_text())["jobs"]
    filters = yaml.safe_load(jobs["changes"]["steps"][1]["with"]["filters"])
    python = filters["python"]
    assert "python" in jobs["python-pipeline"]["if"]
    for path in ("test-adversary/**", str(RESOLVER.relative_to(REPO)), "app/src/debug/**"):
        assert path in python, f"{path} missing from the python path filter"
