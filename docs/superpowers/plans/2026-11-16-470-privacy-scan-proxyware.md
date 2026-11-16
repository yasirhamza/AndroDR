# Proxyware in the Privacy Scan Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The privacy scan names apps that contain Bright SDK code, under a new "Proxyware" category refused by default.

**Architecture:** AndroDR's own entries live in `validation/tracker-supplement.yml` in the rules repo; `mirror-exodus-trackers.py` appends them to `ioc-data/trackers.yml` on every run, so the app keeps reading one file. The app gains one enum value, two texts and a rule for thresholds saved before the category existed.

**Tech Stack:** Python + pytest + YAML (rules repo); Kotlin + JUnit (AndroDR).

**Spec:** `docs/superpowers/specs/2026-11-16-privacy-scan-proxyware-design.md`

## Global Constraints

- Category label is exactly `Proxyware`; enum value `PROXYWARE`.
- Supplement ids start at `900001`. The one entry: id `900001`, name `Bright SDK (residential proxy)`, website `https://bright-sdk.com`, categories `[Proxyware]`, code prefixes `io.lum.sdk`, `io.topvpn.vpn_api`, `org.hola.peer`, `brdat.sdk`, `com.android.eapx`.
- Domain suffixes: the fourteen Bright hosts of #466 (`brdtnet.com`, `bright-sdk.com`, `luminatinet.com`, `luminati-china.io`, `brdtest.com`, `l-err.biz`, `cdn-cloud.b-cdn.net`, `perr.l-agent.me`, `p.l-conn.net`, `zagent108/110/111/112/113.l-cdn.com`), minus any the guards refuse.
- `ioc-data/trackers.yml` is only ever the whole output of the mirror script; never hand-edited.
- A supplement fault is exit code 3 with one `ERROR:` line and nothing written. A supplement entry is never dropped quietly.
- Not a security finding: no rule, no alert, no Timeline detection.
- No household or LAN detail in any committed file; references are public URLs.
- Safe ordering: rules branch → AndroDR PR pinned to it → `build-and-test` green → merge rules → re-point submodule.

## Review Focus

- An Exodus entry that arrives with an id of 900001 or above must not collide with or displace ours (Task 1: it is dropped and reported).
- A supplement prefix that equals or parents an ordinary package (for example `com.android`) must stop the run, not ship (Task 1).
- A regeneration from an Exodus dump must still contain entry 900001 (Task 1).
- A person who saved a threshold before the update must have Proxyware refused; one who then switches it off must not get it back (Task 2).
- An older app version reading the new file must still load it: unknown top-level keys and an unknown category must be harmless (Task 2: parse test with the current parser shape; `fromLabel("Proxyware")` on old code is `OTHER` by construction).

---

### Task 1: Rules repo: supplement, merge, category, regenerated list

**Files** (under `third-party/android-sigma-rules/`, branch `feat/tracker-supplement-proxyware`):
- Create: `validation/tracker-supplement.yml`
- Modify: `validation/tracker_guards.py` (`SUPPLEMENT_ID_MIN = 900_001`)
- Modify: `validation/mirror-exodus-trackers.py`
- Modify: `validation/validate-ioc-data.py` (`TRACKER_CATEGORIES` gains `Proxyware`)
- Modify: `validation/test_mirror_exodus_trackers.py`, `validation/test_validate_ioc_data.py`
- Regenerate: `ioc-data/trackers.yml` (from the list in use plus the supplement), `ioc-data.sha256`
- Modify: `README.md` (the tracker paragraph names the supplement)

**Interfaces (produces):**
- `mirror.load_supplement(path=SUPPLEMENT_FILE, first_party=None, common=None) -> list[dict]`: entries in output shape (`id, name, website, categories, code_prefixes, code_segments, domain_suffixes, domain_labels, domain_patterns=[], excluded_domains=[]`), sorted by id. Raises `ValueError` naming the entry id and the problem when: the file is not a map with a `trackers` list; an id is not a whole number ≥ `SUPPLEMENT_ID_MIN` and ≤ `ID_MAX`; an id repeats; the name fails `tg.name_problem`; the website fails the website check; categories are not a non-empty list of text; a signature fails its field check, is over `SIGNATURE_MAX`, matches a common package or a first-party host; an entry has no signature; an entry has a key outside the known set plus `references`; `references` is not a list of `https://` text.
- `render(api, previous, first_party=None, common=None, supplement=None)`: `supplement=None` means none (tests of Exodus behaviour are unchanged); `main()` always passes the loaded supplement. An Exodus entry with id ≥ `SUPPLEMENT_ID_MIN` is dropped with `tracker dropped: <id>: its id is in the range reserved for AndroDR's own entries`. The document gains `supplement: "Entries with id 900001 and above are AndroDR's own, not Exodus Privacy's"`.
- `main()`: loads the supplement with the other local files; a failure is exit 3.

- [ ] **Step 1:** Write failing tests in `test_mirror_exodus_trackers.py`: supplement entries are appended after Exodus ones in id order; the snapshot fixture rendered with the real supplement contains 900001 with category `Proxyware` and the five prefixes; an Exodus entry with id 900001 is dropped and reported; `load_supplement` raises for each fault listed above (parametrised, including prefix `com.google.gson` and suffix taken from `first_party_hosts.txt`); `main` exits 3 and writes nothing when the supplement is missing or broken; the real supplement file loads; whatever the mirror keeps, the validator accepts (extend the existing test to pass the supplement). In `test_validate_ioc_data.py`: `Proxyware` is an accepted category.
- [ ] **Step 2:** Run them; expect failures.
- [ ] **Step 3:** Implement per Interfaces; write the supplement file with `references` to the Include Security post, the webOS teardown and the Bright SDK documentation repository.
- [ ] **Step 4:** Regenerate `ioc-data/trackers.yml` from the snapshot of the list in use: the Exodus part must be byte-identical to today's, so regenerate with `--from-json` only if that reproduces today's file; otherwise build the candidate by rendering and confirm with `summarize-tracker-changes.py` that the only change is one added tracker. Regenerate `ioc-data.sha256`.
- [ ] **Step 5:** `python3 -m pytest -q validation` and `python3 validation/validate-ioc-data.py ioc-data/trackers.yml` and `sha256sum -c ioc-data.sha256 --strict --quiet`; expect all green.
- [ ] **Step 6:** Commit, push, open the rules PR (do not merge).

### Task 2: AndroDR: category, threshold, bundled list, fixture

**Files** (branch `feat/privacy-scan-proxyware`):
- Modify: `app/src/main/java/com/androdr/privacy/model/TrackerCategory.kt` (`PROXYWARE("Proxyware")`, first in the enum so it leads the threshold sheet)
- Modify: `app/src/main/java/com/androdr/ui/privacy/PrivacyThresholdSheet.kt`, `app/src/main/res/values/strings.xml` (`privacy_cat_proxyware`, `privacy_cat_proxyware_info`)
- Modify: `app/src/main/java/com/androdr/data/repo/SettingsRepository.kt`
- Modify: `app/src/main/res/raw/trackers.yml` (via `scripts/merge-ioc-data.py`), submodule pointer
- Create: `app/src/test/java/com/androdr/privacy/ProxywareTrackerTest.kt`
- Modify: `app/src/test/java/com/androdr/data/repo/SettingsRepositoryPrivacyTest.kt`
- Modify: `test-adversary/fixtures/privacy/build-hostile-apk.sh`, `README.md` (fixture `privacy-proxyware`, package `com.androdr.fixture.privacy.proxyware`, classes `io.lum.sdk.Agent` and `com.androdr.fixture.proxyware.Main`)
- Modify: `docs/ARCHITECTURE.md` (tracker registry paragraph names the supplement and the category)

**Interfaces:**
- `SettingsRepository.refusedTrackerCategories`: when a stored set exists and the new stored flag `privacy_proxyware_decided` is absent, the result is the stored set plus `PROXYWARE`. `setRefusedTrackerCategories` writes the flag with the set.

- [ ] **Step 1:** Write failing tests. `ProxywareTrackerTest`: the pinned submodule's `trackers.yml` parses with `TrackerRegistry.parse` and holds tracker 900001 named `Bright SDK (residential proxy)` with `categories == setOf(PROXYWARE)`; `matchPackages` of `io.lum.sdk.Agent`'s package and of `brdat.sdk.x` names it, and `io.lum.sdkx` does not; `TrackerCategory.fromLabel("Proxyware") == PROXYWARE`; `PROXYWARE in SettingsRepository.DEFAULT_REFUSED_CATEGORIES`. `SettingsRepositoryPrivacyTest`: a stored `{LOCATION}` without the flag reads as `{LOCATION, PROXYWARE}`; after `setRefusedTrackerCategories({LOCATION})` it reads as `{LOCATION}`.
- [ ] **Step 2:** Bump the submodule to the Task 1 commit; run the two classes; expect failures.
- [ ] **Step 3:** Implement; run `python3 scripts/merge-ioc-data.py` to refresh the bundled list; add the fixture and README row; update `ARCHITECTURE.md`.
- [ ] **Step 4:** `./gradlew testDebugUnitTest detekt lintDebug` (delete `app/build/test-results` first) and `python3 -m pytest -q scripts`; expect green.
- [ ] **Step 5:** Commit, push, open the AndroDR PR with `Closes #470`.

### Task 3: Review, battery, land in safe order

- [ ] **Step 1:** Review ceremony on both diffs; fix findings with a regression test each.
- [ ] **Step 2:** Battery: smoke on `Medium_Phone_API_36.1` and `Pixel_9a`; SM-F916B clean install of the debug build; privacy fixtures installed and a privacy scan run: `privacy-proxyware` under "Cross your threshold" with Proxyware, `privacy-positive` unchanged, no `androdr-113` finding for the fixture; adversary `--load`.
- [ ] **Step 3:** AndroDR `build-and-test` green; rules `validate` green; merge the rules PR; re-point the submodule; `ci-success`; merge the AndroDR PR.
