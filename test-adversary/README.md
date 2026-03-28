# Adversary Simulation Test Suite

Manual developer UAT harness for validating AndroDR's detection against
real malware and synthetic adversary artifacts.

## Prerequisites

- **Linux host**
- **ANDROID_HOME** set, `adb` on PATH
- **Emulator** running (`Medium_Phone_API_36.1` recommended)
- **AndroDR debug build** installed: `./gradlew installDebug`
- **python3 with PyYAML**: `pip3 install pyyaml`
- **MalwareBazaar API key** (optional — only for Track 1 & 2):
  set `MALWAREBAZAAR_API_KEY` env var (free at https://bazaar.abuse.ch)
- **7z** for MalwareBazaar ZIPs: `sudo apt install p7zip-full`

## Modes

### Regression (default)
Sequential per-scenario install→scan→diff→cleanup:
```bash
./test-adversary/run.sh emulator-5554              # interactive (pauses per scenario)
./test-adversary/run.sh --no-pause emulator-5554   # unattended
```

### Load (interactive exploration)
Install all selected samples, scan once, explore manually:
```bash
./test-adversary/run.sh --load emulator-5554
./test-adversary/run.sh --load --profile pegasus emulator-5554
./test-adversary/run.sh --load --track 1,3 --risk high emulator-5554
./test-adversary/run.sh --load --random 5 emulator-5554
```
Press ENTER when done to clean up.

### Guided (hybrid walkthrough)
Install, scan, then guided category-by-category review with assertions:
```bash
./test-adversary/run.sh --guided emulator-5554
./test-adversary/run.sh --guided --profile journalist emulator-5554
```

## Selection Filters

All modes accept the same filters:

| Flag | Example | Effect |
|------|---------|--------|
| `--profile` | `--profile pegasus` | Select scenarios from a named profile |
| `--track` | `--track 1,3` | Filter by track number |
| `--risk` | `--risk high,medium` | Filter by risk level |
| `--only` | `--only cerberus_banker` | Select specific scenarios (overrides all) |
| `--random` | `--random 5` | Weighted random sample (high-risk favored) |

Filters compose as intersection. `--only` overrides all other filters.

## Profiles

| Profile | Description | Tracks |
|---------|-------------|--------|
| `pegasus` | NSO Group Pegasus mercenary spyware | 3, 4 |
| `predator` | Intellexa Predator | 3, 4 |
| `graphite` | Paragon Graphite | 3, 4 |
| `journalist` | Journalist/activist threat model | 2, 3, 4 |
| `banking` | Banking trojan landscape | 1 |
| `stalkerware` | Commercial stalkerware | 2 |
| `full` | All scenarios | all |

## Test Tracks

| Track | Source | Scenarios |
|-------|--------|-----------|
| 1 | MalwareBazaar | Commodity RATs and banking trojans |
| 2 | MalwareBazaar | Stalkerware |
| 3 | Synthetic fixtures | Mercenary spyware simulation |
| 4 | Device state | CVE vulnerability detection |

Track 3 and 4 run without MalwareBazaar credentials.

## Cleanup

If `--load` or `--guided` is interrupted before you press ENTER:
```bash
./test-adversary/cleanup.sh emulator-5554
```

## Expected Failures

Scenarios tagged with `roadmap_issue` test detectors not yet implemented.
These print `EXPECTED FAIL (roadmap #N)`.

## Building Fixture APKs

```bash
cd test-adversary/fixtures/mercenary
./build-fixtures.sh
```

Update `manifest.yml` SHA256 hashes with the printed values.

## Adding New Scenarios

1. Add entry to `manifest.yml` with `id`, `source`, `risk`, `technique`, `tactic`, and `expected_patterns`
2. Create `fixtures/expected/<id>.patterns` with one grep pattern per line
3. If `source: fixture`, build the APK and add to `fixtures/mercenary/`
4. Add to relevant profiles in the `profiles` block
