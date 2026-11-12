"""Pins run.sh's cert-hash seeding to the debug app code it depends on.

History. run.sh used to write the fixture's signing cert into the app's `indicators` table with
`sqlite3` on the device. Schema 19 renamed that table's columns and the INSERT silently stopped
working; later the emulator image and the test phone turned out to have no `sqlite3` at all, so
`mercenary_cert_hash` could not be set up and was left out of the 2026-11-12 release battery (#424).

Now the debug build seeds the row itself: run.sh sends a broadcast with the hash, and the debug
receiver inserts an `Indicator` through the app's own DAO and reloads the indicator cache. The row is
type-checked by the compiler (AdversarySeedTest covers it), so nothing here parses SQL any more. These
tests keep the two sides of that broadcast, and the log lines run.sh waits for, from drifting apart.

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
    assert "AdversarySeed.ACTION_SEED_CERT" in RECEIVER_KT.read_text()


def seed_cert_kotlin():
    """The body of the receiver's seedCert function."""
    src = RECEIVER_KT.read_text()
    body = src[src.index("private suspend fun seedCert("):]
    return body[: body.index("\n    }\n")]


def test_seeded_is_logged_only_after_the_row_is_stored_and_the_cache_reloaded():
    """run.sh starts the scan on the receiver's "Seeded" line. Cert lookups are answered from
    IndicatorResolver's in-memory cache, so the line must come after the insert AND the reload; another
    update's cache-refresh line would not do (it may have read the table before the seed)."""
    body = seed_cert_kotlin()
    stored, reloaded = body.index("indicatorDao.upsertAll("), body.index("indicatorResolver.refreshCache()")
    logged = body.index("AdversarySeed.LOG_SEEDED")
    assert stored < reloaded < logged


def test_run_sh_waits_for_the_receivers_own_lines():
    assert shell_var("SEED_DONE_LINE") == kotlin_const("LOG_SEEDED")
    assert kotlin_const("LOG_REFUSED").startswith(shell_var("SEED_REFUSED_LINE"))
    tag = re.search(r'TAG\s*=\s*"([^"]+)"', RECEIVER_KT.read_text()).group(1)
    assert shell_var("SEED_TAG") == tag
    body = seed_body()
    assert '"$SEED_DONE_LINE"' in body and '"$SEED_REFUSED_LINE"' in body
    assert "ACTION_UPDATE" not in body and "Indicator cache" not in body
    # The "before" counts are taken before the broadcast, so only this seed's lines are counted.
    assert body.index("done_before=") < body.index("am broadcast") < body.index("while ")


def test_ci_path_filter_covers_every_input():
    """The seed gate must run when any file it reads changes, not only run.sh."""
    import yaml
    jobs = yaml.safe_load(CI_YML.read_text())["jobs"]
    filters = yaml.safe_load(jobs["changes"]["steps"][1]["with"]["filters"])
    python = filters["python"]
    assert "python" in jobs["python-pipeline"]["if"]
    for path in ("test-adversary/**", "app/src/debug/**"):
        assert path in python, f"{path} missing from the python path filter"


def test_only_the_adb_shell_can_reach_the_debug_receiver():
    """The receiver is exported so `adb shell am broadcast` can reach it. Without a permission any
    app on a test device could plant an indicator (a false "known threat developer") or start scans.
    DUMP is held by the shell and cannot be granted to an ordinary app."""
    manifest = DEBUG_MANIFEST.read_text()
    receiver = manifest[manifest.index("<receiver"):manifest.index("</receiver>")]
    assert 'android:permission="android.permission.DUMP"' in receiver
