# Privacy-scan adversary fixtures

These are small signed APKs for checking the privacy scan (ARCHITECTURE.md chapter 12) on a device, including APKs built to break the dex reader. `test-adversary/run.sh` drives security scans only, so these fixtures are installed and checked by hand as part of the release battery.

```bash
JAVA_HOME=<jdk21> ANDROID_HOME=~/Android/Sdk test-adversary/fixtures/privacy/build-hostile-apk.sh
for f in test-adversary/fixtures/privacy/out/*.apk; do adb -s emulator-5554 install -r --no-incremental "$f"; done
# open AndroDR once, then seed the DNS log (needs sqlite3 on this machine, not on the device):
ANDROID_HOME=~/Android/Sdk test-adversary/fixtures/privacy/seed-dns-flood.sh emulator-5554
# AndroDR → Dashboard → Privacy scan → Run privacy scan, with the default threshold
```

Use `--no-incremental`: an incremental install loads files lazily, which isn't how a store install behaves.

| APK | Contents | Must show |
|---|---|---|
| `privacy-positive` ("Privacy Fixture Trackers") | `com.facebook.ads…` (Facebook Ads, Advertisement) and `com.google.firebase.analytics…` (Firebase Analytics) in `classes.dex` | **Cross your threshold**: "2 trackers from the registry", Advertisement and Analytics |
| `privacy-negative` ("Privacy Fixture Clean") | only `com.androdr.fixture.clean…` | **Other apps**: "None of the N trackers in the registry were found in its code" |
| `privacy-corrupt-dex` ("Privacy Fixture Corrupt Dex") | a valid `classes.dex` with Facebook Ads, plus a `classes2.dex` made of a dex magic followed by random bytes | **Cross your threshold**: "Partly inspected: malformed classes2.dex", "Advertisement (partly inspected)". A broken dex costs only that dex. |
| `privacy-dex-bomb` ("Privacy Fixture Dex Bomb") | a valid `classes.dex` with Facebook Ads, plus a 40 MiB `classes2.dex` of zeros that compresses to about 40 KiB | **Cross your threshold**: "Partly inspected: skipped classes2.dex", "Advertisement (partly inspected)". The scan finishes, with no out-of-memory error or crash. |
| `privacy-hostile-label` (label: "Bank" + a right-to-left override + "evil" + a line break + "Spyware detected") | Facebook Ads in `classes.dex` | Listed everywhere as **Bankevil Spyware detected** (no override, one line): the privacy screen, the tracker details, and its Timeline entry "Bankevil Spyware detected: 1 tracker found in code". It never looks like a finding: no severity, tag `privacy_scan`. |
| `privacy-flood` ("Privacy Fixture Flood") + `seed-dns-flood.sh` | no tracker in code; the script gives it 25,000 junk `j<N>.doubleclick.net` lookups and gives `privacy-positive` 3 lookups of two Firebase Analytics domains | The scan finishes and the header says **Network evidence is incomplete: the DNS log was too large to read in full.** `privacy-positive` → Google Firebase Analytics → details still lists `App-Measurement.firebase.com` (2 lookups, spelled as recorded) and `firebaselogging-pa.googleapis.com` (1), with "This list of domains may be incomplete." The flood app has **no** Timeline entry (network evidence only). |

**Timeline (Part B):** one entry per fixture with a tracker in code (positive, corrupt, bomb, hostile label) plus the "Privacy scan: N apps inspected …" entry; none for `privacy-negative` or `privacy-flood`. An entry's sheet → **Open in privacy results** opens that app's sheet. Filters → Source → **Privacy scan** shows only these. Export CSV with only these shown writes no file.

Must not happen: a crash or ANR in logcat, a fixture missing from the list, or a partly inspected fixture missing from **Cross your threshold** (cutting an app's own inspection short must never take it off the list).

Clean up: `adb uninstall com.androdr.fixture.privacy.{positive,negative,corrupt,bomb,label,flood}`; the seeded rows go with the debug app's data (`pm clear` or uninstall), or with a re-run of the seed script (it deletes its own rows first).

First run: 2026-11-07, API 36.1 emulator, main `eabd102b`. All four matched.

Second run: 2026-11-12, main `2066d094`, API 36.1 emulator and SM-F916B (clean install): all six matched, with the Timeline and details checks above.
