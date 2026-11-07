# Privacy-scan adversary fixtures

These are small signed APKs for checking the privacy scan (ARCHITECTURE.md chapter 12) on a device, including APKs built to break the dex reader. `test-adversary/run.sh` drives security scans only, so these fixtures are installed and checked by hand as part of the release battery.

```bash
JAVA_HOME=<jdk21> ANDROID_HOME=~/Android/Sdk test-adversary/fixtures/privacy/build-hostile-apk.sh
for f in test-adversary/fixtures/privacy/out/*.apk; do adb -s emulator-5554 install -r --no-incremental "$f"; done
# AndroDR → Dashboard → Privacy scan → Run privacy scan, with the default threshold
```

Use `--no-incremental`: an incremental install loads files lazily, which isn't how a store install behaves.

| APK | Contents | Must show |
|---|---|---|
| `privacy-positive` ("Privacy Fixture Trackers") | `com.facebook.ads…` (Facebook Ads, Advertisement) and `com.google.firebase.analytics…` (Firebase Analytics) in `classes.dex` | **Cross your threshold**: "2 trackers from the registry", Advertisement and Analytics |
| `privacy-negative` ("Privacy Fixture Clean") | only `com.androdr.fixture.clean…` | **Other apps**: "None of the N trackers in the registry were found in its code" |
| `privacy-corrupt-dex` ("Privacy Fixture Corrupt Dex") | a valid `classes.dex` with Facebook Ads, plus a `classes2.dex` made of a dex magic followed by random bytes | **Cross your threshold**: "Partly inspected: malformed classes2.dex", "Advertisement (partly inspected)". A broken dex costs only that dex. |
| `privacy-dex-bomb` ("Privacy Fixture Dex Bomb") | a valid `classes.dex` with Facebook Ads, plus a 40 MiB `classes2.dex` of zeros that compresses to about 40 KiB | **Cross your threshold**: "Partly inspected: skipped classes2.dex", "Advertisement (partly inspected)". The scan finishes, with no out-of-memory error or crash. |

Must not happen: a crash or ANR in logcat, a fixture missing from the list, or a partly inspected fixture missing from **Cross your threshold** (cutting an app's own inspection short must never take it off the list).

Clean up: `adb uninstall com.androdr.fixture.privacy.{positive,negative,corrupt,bomb}`.

First run: 2026-11-07, API 36.1 emulator, main `eabd102b`. All four matched.
