# Adversary Simulation Test Suite

Manual developer UAT harness for validating AndroDR's detection against
real malware and synthetic adversary artifacts.

## Prerequisites

- **Linux host** (iptables required for network isolation)
- **ANDROID_HOME** set, `adb` on PATH
- **Emulator** running (`Medium_Phone_API_36.1` recommended)
- **AndroDR debug build** installed: `./gradlew installDebug`
- **python3 with PyYAML** for manifest parsing (`pip3 install pyyaml`)
- **MalwareBazaar API key** (optional — only for Track 1 & 2):
  set `MALWAREBAZAAR_API_KEY` env var (free at https://bazaar.abuse.ch)

## Quick Start

```bash
# 1. Build fixture APKs (one-time)
cd test-adversary/fixtures/mercenary
./build-fixtures.sh
cd ../../..

# 2. Update manifest.yml with fixture SHA256 hashes
#    (printed by build-fixtures.sh)

# 3. Run the harness
./test-adversary/run.sh <emulator-serial>
```

## Test Tracks

| Track | Source | Samples |
|-------|--------|---------|
| 1 | MalwareBazaar | Commodity RATs (Cerberus, SpyNote) |
| 2 | MalwareBazaar | Stalkerware (FlexiSpy) |
| 3 | Synthetic fixtures | Mercenary spyware simulation |

Track 3 runs without MalwareBazaar credentials.

## Expected Failures

Scenarios tagged with `roadmap_issue` test detectors that don't exist yet.
These print `EXPECTED FAIL (roadmap #N)` — not real failures.

| Scenario | Roadmap Issue | Missing Detector |
|----------|---------------|-----------------|
| mercenary_cert_hash | #7 | APK cert hash IOC matching |
| mercenary_accessibility | #10 | Accessibility service abuse |
| mercenary_device_admin | #10 | Device admin abuse |
| mercenary_file_artifacts | #8 | File system artifact scanning |
| mercenary_ip_c2 | #6 | IP address IOC detection |

## Adding New Scenarios

1. Add entry to `manifest.yml` with unique `id`, `source`, `sha256`, and `expected_patterns`
2. Create `fixtures/expected/<id>.patterns` with one grep pattern per line
3. If `source: fixture`, build the APK and add to `fixtures/mercenary/`
