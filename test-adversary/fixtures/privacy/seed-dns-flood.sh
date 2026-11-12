#!/usr/bin/env bash
# Seeds the debug app's DNS log as if two fixture apps had made lookups, so the privacy scan's network
# step can be checked on a device without sending tens of thousands of real queries to a third party:
#
#   com.androdr.fixture.privacy.flood     25,000 junk subdomains of doubleclick.net (a flood)
#   com.androdr.fixture.privacy.positive  3 lookups of two Firebase Analytics domains (real evidence)
#
# The flood must cost only the flooding app: the scan finishes, says network evidence is incomplete,
# and the positive fixture still shows its three lookups. See README.md for the expected results.
#
# Retail-style images have no sqlite3, so the database is pulled, edited here and pushed back
# (the app is stopped first; its -wal and -shm files are folded in and removed).
#
#   ./seed-dns-flood.sh <adb serial>      (AndroDR debug installed and opened once; needs sqlite3 here)
set -euo pipefail
SERIAL="${1:?usage: seed-dns-flood.sh <adb serial>}"
ADB="${ANDROID_HOME:?set ANDROID_HOME}/platform-tools/adb"
PKG=com.androdr.debug
DB=databases/androdr.db
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

"$ADB" -s "$SERIAL" shell am force-stop "$PKG"
for part in "" -wal -shm; do
    "$ADB" -s "$SERIAL" exec-out run-as "$PKG" sh -c "cat $DB$part 2>/dev/null" > "$WORK/androdr.db$part"
    [ -s "$WORK/androdr.db$part" ] || rm -f "$WORK/androdr.db$part"
done
[ -s "$WORK/androdr.db" ] || { echo "no database on the device: open AndroDR debug once first" >&2; exit 1; }
NOW_MS="$("$ADB" -s "$SERIAL" shell date +%s | tr -d '\r')000"

sqlite3 "$WORK/androdr.db" <<SQL
PRAGMA wal_checkpoint(TRUNCATE);
PRAGMA journal_mode = DELETE;
DELETE FROM DnsEvent WHERE appName LIKE 'com.androdr.fixture.privacy.%';
WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 25000)
INSERT INTO DnsEvent (timestamp, domain, appUid, appName, isBlocked, reason)
SELECT $NOW_MS - i * 1000, 'j' || i || '.doubleclick.net', 10999, 'com.androdr.fixture.privacy.flood', 0, NULL FROM n;
INSERT INTO DnsEvent (timestamp, domain, appUid, appName, isBlocked, reason) VALUES
($NOW_MS - 7200000, 'App-Measurement.firebase.com', 10998, 'com.androdr.fixture.privacy.positive', 0, NULL),
($NOW_MS - 3600000, 'App-Measurement.firebase.com', 10998, 'com.androdr.fixture.privacy.positive', 0, NULL),
($NOW_MS - 60000, 'firebaselogging-pa.googleapis.com', 10998, 'com.androdr.fixture.privacy.positive', 0, NULL);
SELECT 'seeded: ' || appName || ' ' || COUNT(*) FROM DnsEvent WHERE appName LIKE 'com.androdr.fixture.privacy.%' GROUP BY appName;
SQL

"$ADB" -s "$SERIAL" exec-in run-as "$PKG" sh -c "cat > $DB" < "$WORK/androdr.db"
"$ADB" -s "$SERIAL" shell "run-as $PKG rm -f $DB-wal $DB-shm"
echo "pushed back: $("$ADB" -s "$SERIAL" shell "run-as $PKG ls -l $DB" | tr -d '\r')"
