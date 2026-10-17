# Per-campaign check state (#394) Implementation Plan

> **Plan gate:** skipped for this plan by owner decision (2026-10-17); the per-task reviews and the final whole-branch review are the defect net. **Execution:** subagent-driven (owner, 2026-10-17).

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. **Execution model:** per owner, chosen at plan handoff — do not assume one.

**Goal:** Each MERCENARY SPYWARE CHECK row says whether its campaign was fully checked and, if not, why and what to do — `[OK]` only when every infection check for that campaign ran in full.

**Architecture:** `campaigns.yml` declares per campaign the rule services that can make it DETECTED (`detected_by`), derived and enforced by a rules-repo CI test. The app renders each no-hit row at render time from that list plus the scan's already-stored `scannerErrors`, through one pure function (`campaignCoverage`). No new DB column, no migration, no scan-time campaign logic; the only orchestrator change records a failed DNS snapshot read instead of swallowing it.

**Tech Stack:** Kotlin (Android, JUnit4, mockk, snakeyaml-engine, kotlinx.serialization), Python 3 + pytest + PyYAML (rules repo, `scripts/`), bash (`test-adversary/`).

**Spec:** `docs/superpowers/specs/2026-10-17-campaign-check-state-design.md` (this branch, approved 2026-10-17). Executors read both.

## Global Constraints

- Report output is strictly ASCII (`ReportFormatter` KDoc): no Unicode in any new row text.
- Row prefixes stay `  [OK]  `, `  [--]  `, `  [!!]  ` (two spaces, marker, two spaces). Fix lines are indented 8 spaces.
- `[OK]  <Label>: not detected` is printed only when every service in the campaign's `detected_by` is CHECKED, or when `detected_by` is absent (legacy fallback).
- `detected_by` values are logsource service names from `validation/logsource-taxonomy.yml`; the app keeps only values matching `^[a-z_]{1,32}$`.
- Only rules listed in `rules.txt` count as detectors (`staging/` never ships).
- Imports (`source != LIVE_SCAN`) keep today's rows exactly.
- Safe ordering: rules branch → AndroDR PR pinned to it → `build-and-test` green → merge rules → re-point submodule at rules main → merge AndroDR. `submodule-check` / `ci-success` are red by design while pinned to the branch.
- Every editing of `ioc-data/*.yml` regenerates `ioc-data.sha256` (rules repo root): `for f in $(ls ioc-data/*.yml | sort); do printf '%s  %s\n' "$(sha256sum "$f" | cut -d' ' -f1)" "$f"; done > ioc-data.sha256`
- Gradle env (one line; the worktree hook refuses `export … &&`): `JAVA_HOME=/home/yasir/.gradle/jdks/eclipse_adoptium-21-amd64-linux.2 ANDROID_HOME=/home/yasir/Android/Sdk ./gradlew <task>`. Never the Android Studio JBR (JDK 25).
- Before reading JUnit XML: `rm -rf app/build/test-results` (a failed sibling task leaves stale XML that reads green).
- Run everything in the task's worktree path, never in `/home/yasir/AndroDR` (stale checkout with owner WIP).
- Commit trailers: `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>` and `Claude-Session: https://claude.ai/code/session_01B8H9x5KmTtY8Ejyi2eUdjH`.

### Deviations from the spec found while grounding it in code (owner ACCEPTED all five, 2026-10-17; spec updated to match)

1. **DNS-off wording.** Spec §6 clause "DNS lookups not checked (DNS monitoring was off)" is untrue: with the tunnel off the scan still evaluates the newest 500 *recorded* lookups (`ScanOrchestrator.kt:384-387`; `NotEvaluatedReason.DNS_MONITOR_OFF.heading` says "the most recent recorded lookups were checked"). This plan uses `DNS lookups not monitored (DNS monitoring was off; only lookups recorded earlier were checked)`. Status stays BLIND (row `[--]`).
2. **Where `detected_by` shape is validated.** Spec §1 says `validate-ioc-data.py`; `campaigns.yml` is actually validated by `validation/test_campaign_vocabulary.py` (validate-ioc-data.py only runs the manual-record pass on it). The shape checks go in the new `test_campaign_detected_by.py`, run by both CI jobs.
3. **BLIND reasons are typed.** Spec §3 `ServiceStatus.reason: String?`; this plan uses `reason: BlindReason?` (`DNS_OFF`, `CHECK_FAILED`, `UNKNOWN_SERVICE`) so rendering never compares strings.
4. **MVT derivation** adds the service of the `ioc_match` rule using `domain_ioc_db` (today `dns_monitor`), not a hard-coded `dns_monitor` — same result today, stays true if androdr-003 changes.
5. **Scope note condition.** Spec: "printed only when some row has `coverage == null`". Plan: live scan AND some NOT_DETECTED row has `coverage == null` (the note explains "not detected"; a DETECTED row without coverage needs no note).
6. **Owner addition: `missingSources`.** A missing MVT list marks only `dns_monitor` built-in-only (Task A2 Steps 0a/0b).

## Review Focus

1. **A crashed scanner plus feeds-not-loaded on the same service** → the row must say the check failed (BLIND), not "built-in list only". Pinned in Task A2 (`crash beats feeds not loaded`).
2. **A campaign rule's unreadable-paths entry belonging to another campaign** (androdr-108 is predator's; pegasus must stay CHECKED for files) → no cross-campaign leak. Pinned in Task A2 (`unreadable paths of another campaign's rule do not count`).
3. **A newer `campaigns.yml` naming a service this app build does not know** (e.g. a future `usage_stats`) → fails closed as BLIND "update the app", never `[OK]`. Pinned in Task A2 (`unknown service is blind`) and Task A4 (row text).
4. **A History scan saved before this change** (no `dnsSnapshot` entries, same sentinels) → renders reasons from its stored entries with no crash; an old cached `campaigns.yml` without the field → today's rows plus the global note. Pinned in Task A4 (`legacy campaign without detected_by keeps today's row and the note`).
5. **Two services that need the same fix** (e.g. both BUILT_IN_LISTS_ONLY) → the fix line prints once. Pinned in Task A4 (`a shared fix is printed once`).

## File Structure

Rules repo (`third-party/android-sigma-rules`, own branch):
- `ioc-data/campaigns.yml` — add `detected_by` to the 7 campaigns.
- `ioc-data.sha256` — regenerated.
- `validation/test_campaign_detected_by.py` (new) — `derive(root)`, `mismatches(root)`, shape checks, fixture failure cases.
- `.github/workflows/validate.yml` — add the new test to the ioc-data job's explicit pytest list.

AndroDR:
- `app/src/main/java/com/androdr/ioc/CampaignRegistry.kt` — `Campaign.detectedBy`, parsing.
- `scripts/merge-ioc-data.py`, `scripts/test_merge_ioc_data.py` — emit `detected_by`.
- `app/src/main/res/raw/known_campaigns.json` — regenerated.
- `app/src/main/java/com/androdr/reporting/CampaignCoverage.kt` (new) — `ServiceCoverage`, `BlindReason`, `ServiceStatus`, `SCANNER_FOR_SERVICE`, `IMPORT_ONLY_SERVICES`, `campaignCoverage()`.
- `app/src/main/java/com/androdr/scanner/ScanOrchestrator.kt` — record `dnsSnapshot` failure.
- `app/src/main/java/com/androdr/reporting/ReportInputs.kt` — `ruleCampaigns()`.
- `app/src/main/java/com/androdr/reporting/CampaignVerdict.kt` — `coverage`, row text, scope-note condition.
- `app/src/main/java/com/androdr/reporting/ReportFormatter.kt`, `ReportExporter.kt`, `ui/history/HistoryViewModel.kt` — pass `ruleCampaigns`.
- Tests: `ioc/CampaignRegistryTest.kt`, `reporting/CampaignCoverageTest.kt` (new), `reporting/ServiceScannerMapCrossCheckTest.kt` (new), `scanner/ScanOrchestratorErrorHandlingTest.kt`, `reporting/ReportInputsTest.kt`, `reporting/MercenaryCheckReportTest.kt`, plus the mechanical `ruleCampaigns = emptyMap()` insertion in the other report tests.
- `test-adversary/fixtures/expected/clean_device.patterns`, `test-adversary/fixtures/expected/campaign_rows_dns_off.patterns` (new), `test-adversary/manifest.yml`, `test-adversary/test_check_patterns.py`.

---

### Task R1: `detected_by` in campaigns.yml, enforced by derivation (rules repo)

**Files:**
- Modify: `ioc-data/campaigns.yml`, `ioc-data.sha256`, `.github/workflows/validate.yml:35-37`
- Create: `validation/test_campaign_detected_by.py`

**Interfaces:**
- Consumes: `rules.txt`, rule YAML (`tags`, `logsource.service`, top-level `category`, `display.evidence_type`, `detection.*.<field>|ioc_lookup`), `ioc-data/{c2-domains,package-names,cert-hashes,malware-hashes}.yml` `entries[].campaign`, `validation/mvt-campaign-map.json` (`[{name,url,key}]`), `validation/logsource-taxonomy.yml` `services`.
- Produces: `campaigns[].detected_by: [service, ...]` (sorted, unique) consumed by AndroDR Task A1.

- [ ] **Step 1: Worktree**

```bash
cd /home/yasir/android-sigma-rules && git fetch -q origin && git worktree add -b feat/394-detected-by /home/yasir/android-sigma-rules-wt-394 origin/main && cd /home/yasir/android-sigma-rules-wt-394
```

- [ ] **Step 2: Write the failing test** — `validation/test_campaign_detected_by.py`:

```python
"""campaigns.yml `detected_by`: the rule services that can make each campaign DETECTED (AndroDR #394).

The app renders "fully checked / not checked, and why" per campaign from this list plus what the
scan stored, so the list must be exactly what the shipped rules and ioc-data can detect: derived
here from rules.txt rules, ioc-data campaign values and the MVT map, and compared both ways.
"""
import json
import pathlib
import textwrap

import yaml

ROOT = pathlib.Path(__file__).parent.parent
# ioc-data file -> the ioc_lookup that reads it on the device
LOOKUP_FOR_FILE = {
    "c2-domains.yml": "domain_ioc_db",
    "package-names.yml": "package_ioc_db",
    "cert-hashes.yml": "cert_hash_ioc_db",
    "malware-hashes.yml": "apk_hash_ioc_db",
}


def _load(path):
    return yaml.safe_load(path.read_text()) or {}


def _selections(detection):
    for name, sel in (detection or {}).items():
        if name == "condition":
            continue
        for item in (sel if isinstance(sel, list) else [sel]):
            if isinstance(item, dict):
                yield item


def _ioc_lookups(rule):
    out = set()
    for sel in _selections(rule.get("detection")):
        for field, value in sel.items():
            if str(field).endswith("|ioc_lookup"):
                out.update(value if isinstance(value, list) else [value])
    return out


def derive(root):
    """{campaign key: sorted services} the shipped rules and ioc-data can detect it with."""
    camps = _load(root / "ioc-data" / "campaigns.yml").get("campaigns", [])
    key_by_name = {c["key"]: c["key"] for c in camps}
    for c in camps:
        for alias in c.get("aliases") or []:
            key_by_name.setdefault(str(alias).lower(), c["key"])
    out = {c["key"]: set() for c in camps}
    lookup_services = {}
    for rel in (root / "rules.txt").read_text().split():
        if not rel.endswith(".yml"):
            continue
        rule = _load(root / rel)
        service = (rule.get("logsource") or {}).get("service")
        if rule.get("category") != "device_posture":   # patch level is EXPOSED, never DETECTED
            for tag in rule.get("tags") or []:
                tag = str(tag)
                if tag.startswith("campaign.") and tag[len("campaign."):].lower() in key_by_name:
                    out[key_by_name[tag[len("campaign."):].lower()]].add(service)
        if (rule.get("display") or {}).get("evidence_type") == "ioc_match":   # only these carry a campaign
            for name in _ioc_lookups(rule):
                lookup_services.setdefault(name, set()).add(service)
    for fname, lookup in LOOKUP_FOR_FILE.items():
        path = root / "ioc-data" / fname
        if not path.is_file():
            continue
        for entry in _load(path).get("entries") or []:
            if entry.get("campaign") in out:
                out[entry["campaign"]].update(lookup_services.get(lookup, set()))
    mvt = root / "validation" / "mvt-campaign-map.json"
    if mvt.is_file():   # MVT campaign attribution is domain-only
        for m in json.loads(mvt.read_text()):
            if m.get("key") in out:
                out[m["key"]].update(lookup_services.get("domain_ioc_db", set()))
    return {k: sorted(v) for k, v in out.items()}


def mismatches(root):
    declared = {c["key"]: c.get("detected_by")
                for c in _load(root / "ioc-data" / "campaigns.yml").get("campaigns", [])}
    derived = derive(root)
    return [f"{k}: declared {declared[k]} but the rules and ioc-data give {derived[k]}"
            for k in sorted(derived) if declared[k] != derived[k]]


def test_detected_by_matches_what_the_rules_can_detect():
    assert not mismatches(ROOT), "\n".join(mismatches(ROOT))


def test_detected_by_is_a_sorted_unique_list_of_taxonomy_services():
    services = set(_load(ROOT / "validation" / "logsource-taxonomy.yml")["services"])
    for c in _load(ROOT / "ioc-data" / "campaigns.yml")["campaigns"]:
        value = c.get("detected_by")
        assert isinstance(value, list), f"{c['key']}: detected_by must be a list ([] = patch level only)"
        assert value == sorted(set(value)), f"{c['key']}: detected_by must be sorted and unique: {value}"
        assert set(value) <= services, f"{c['key']}: not taxonomy services: {set(value) - services}"


# -- fixture repos: the gate fails on the mistakes it exists for ----------------------------------

IOC_RULE = """\
    title: t
    id: {id}
    tags: [attack.t1437]
    logsource: {{product: androdr, service: {service}}}
    detection:
        selection:
            {field}|ioc_lookup: {lookup}
        condition: selection
    category: incident
    display: {{evidence_type: {evidence}}}
"""


def mini(tmp_path, detected_by, rules=(), entries=None, mvt=()):
    (tmp_path / "ioc-data").mkdir()
    (tmp_path / "validation").mkdir()
    (tmp_path / "ioc-data" / "campaigns.yml").write_text(yaml.safe_dump({"campaigns": [
        {"key": "pegasus", "label": "Pegasus", "aliases": ["nso"], "detected_by": detected_by}]}))
    names = []
    for i, text in enumerate(rules):
        (tmp_path / f"r{i}.yml").write_text(textwrap.dedent(text))
        names.append(f"r{i}.yml")
    (tmp_path / "rules.txt").write_text("\n".join(names) + "\n")
    for fname, items in (entries or {}).items():
        (tmp_path / "ioc-data" / fname).write_text(yaml.safe_dump({"entries": items}))
    (tmp_path / "validation" / "mvt-campaign-map.json").write_text(json.dumps(list(mvt)))
    return tmp_path


def tagged_rule(service, category="incident", tag="campaign.pegasus"):
    return f"""\
    title: t
    id: androdr-900
    tags: [{tag}]
    logsource: {{product: androdr, service: {service}}}
    detection: {{selection: {{x: y}}, condition: selection}}
    category: {category}
"""


def test_a_new_tagged_rule_on_a_new_service_fails_until_declared(tmp_path):
    root = mini(tmp_path, [], rules=[tagged_rule("file_scanner")])
    assert mismatches(root) == ["pegasus: declared [] but the rules and ioc-data give ['file_scanner']"]


def test_an_overclaimed_service_fails(tmp_path):
    root = mini(tmp_path, ["dns_monitor"])
    assert mismatches(root) == ["pegasus: declared ['dns_monitor'] but the rules and ioc-data give []"]


def test_an_alias_tag_counts_and_a_patch_level_tag_does_not(tmp_path):
    root = mini(tmp_path, ["app_scanner"], rules=[
        tagged_rule("app_scanner", tag="campaign.nso"),
        tagged_rule("device_auditor", category="device_posture"),
    ])
    assert mismatches(root) == []


def test_campaign_iocs_count_only_through_an_ioc_match_rule(tmp_path):
    rules = [
        IOC_RULE.format(id="androdr-003", service="dns_monitor", field="domain",
                        lookup="domain_ioc_db", evidence="ioc_match"),
        IOC_RULE.format(id="androdr-004", service="app_scanner", field="apk_hash",
                        lookup="apk_hash_ioc_db", evidence="none"),
    ]
    entries = {"c2-domains.yml": [{"indicator": "a.example", "campaign": "pegasus"}],
               "malware-hashes.yml": [{"indicator": "a" * 64, "campaign": "pegasus"}]}
    assert derive(mini(tmp_path, ["dns_monitor"], rules=rules, entries=entries)) == {"pegasus": ["dns_monitor"]}


def test_mvt_campaigns_count_through_the_domain_lookup_rule(tmp_path):
    rules = [IOC_RULE.format(id="androdr-003", service="dns_monitor", field="domain",
                             lookup="domain_ioc_db", evidence="ioc_match")]
    root = mini(tmp_path, ["dns_monitor"], rules=rules, mvt=[{"name": "n", "url": "u", "key": "pegasus"}])
    assert mismatches(root) == []
```

- [ ] **Step 3: Run it to verify it fails**

Run: `python3 -m pytest -q validation/test_campaign_detected_by.py`
Expected: the 5 fixture tests PASS; `test_detected_by_matches_what_the_rules_can_detect` FAILS with 7 lines like `pegasus: declared None but the rules and ioc-data give ['dns_monitor']`; `test_detected_by_is_a_sorted_unique_list_of_taxonomy_services` FAILS (`detected_by must be a list`).

- [ ] **Step 4: Add `detected_by`** to each campaign in `ioc-data/campaigns.yml`, directly under its `label:` line (keep comments and `references` untouched):

| key | line to add |
|---|---|
| pegasus | `    detected_by: [dns_monitor]` |
| predator | `    detected_by: [dns_monitor, file_scanner]` |
| graphite | `    detected_by: [dns_monitor]` |
| cellebrite | `    detected_by: [app_scanner]` |
| landfall | `    detected_by: []          # patch level only: no infection check exists` |
| massistant | `    detected_by: [app_scanner]` |
| midnight-mimosa | `    detected_by: [app_scanner, dns_monitor]` |

Also extend the file's `description:` with one sentence: `detected_by lists the rule services that can make the campaign DETECTED; validation/test_campaign_detected_by.py derives it from the rules and ioc-data.`

- [ ] **Step 5: Run the tests to verify they pass**

Run: `python3 -m pytest -q validation/test_campaign_detected_by.py validation/test_campaign_vocabulary.py`
Expected: all PASS. If the derivation disagrees with the table, the failure line names the campaign: trust the derivation only after reading the rule/ioc-data it cites, and report the difference instead of editing the expected table silently.

- [ ] **Step 6: Wire it into the ioc-data CI job** — `.github/workflows/validate.yml`, in the "IOC data gates and the reference checker" step's pytest list, add `validation/test_campaign_detected_by.py` after `validation/test_campaign_vocabulary.py`.

- [ ] **Step 7: Regenerate the manifest and run the whole validation suite**

```bash
for f in $(ls ioc-data/*.yml | sort); do printf '%s  %s\n' "$(sha256sum "$f" | cut -d' ' -f1)" "$f"; done > ioc-data.sha256
python3 -m pytest -q validation/
for f in ioc-data/*.yml; do python3 validation/validate-ioc-data.py "$f" >/dev/null || echo "FAIL $f"; done
```
Expected: pytest all pass; no `FAIL` lines; `git diff --stat` shows `ioc-data.sha256` with exactly one changed line (campaigns.yml).

- [ ] **Step 8: Commit and push the branch** (push is needed so AndroDR can pin it; no PR yet)

```bash
git add ioc-data/campaigns.yml ioc-data.sha256 validation/test_campaign_detected_by.py .github/workflows/validate.yml
git commit -m "feat(campaigns): detected_by per campaign, derived and enforced by CI (AndroDR #394)" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01B8H9x5KmTtY8Ejyi2eUdjH"
git push -u origin feat/394-detected-by
```

---

### Task A1: App reads `detected_by`; bundle carries it

**Files:**
- Modify: `app/src/main/java/com/androdr/ioc/CampaignRegistry.kt`, `scripts/merge-ioc-data.py:93-98`, `scripts/test_merge_ioc_data.py`, `app/src/main/res/raw/known_campaigns.json` (regenerated), `app/src/test/java/com/androdr/ioc/CampaignRegistryTest.kt`
- Submodule: `third-party/android-sigma-rules` → R1 branch commit

**Interfaces:**
- Consumes: R1's `detected_by`.
- Produces: `data class Campaign(val key: String, val label: String, val aliases: List<String> = emptyList(), val detectedBy: List<String>? = null)` — `null` = field absent, `[]` = patch level only. Used by A4.

- [ ] **Step 1: Worktree, pinned to R1**

```bash
cd /home/yasir/AndroDR && git fetch -q origin && git worktree add -b feat/394-campaign-check-state /home/yasir/AndroDR-wt-394impl origin/main
cd /home/yasir/AndroDR-wt-394impl && git submodule update --init -q
cp /home/yasir/AndroDR/local.properties .
cd third-party/android-sigma-rules && git fetch -q origin feat/394-detected-by && git checkout -q FETCH_HEAD && cd ../..
git -C third-party/android-sigma-rules log --oneline -1   # expect R1's commit
```

- [ ] **Step 2: Failing tests** — append to `CampaignRegistryTest`:

```kotlin
    @Test
    fun `detected_by is read from yaml - present, empty, absent, junk`() {
        val yaml = """
            campaigns:
              - key: a
                label: A
                detected_by: [dns_monitor, app_scanner, dns_monitor]
              - key: b
                label: B
                detected_by: []
              - key: c
                label: C
              - key: d
                label: D
                detected_by: dns_monitor
              - key: e
                label: E
                detected_by: [file_scanner, "Bad Value", "x;y"]
        """.trimIndent()
        val byKey = CampaignRegistry.parseYaml(yaml).associate { it.key to it.detectedBy }
        assertEquals(listOf("app_scanner", "dns_monitor"), byKey["a"])
        assertEquals(emptyList<String>(), byKey["b"])
        assertNull(byKey["c"])
        assertNull(byKey["d"]) // not a list: treated as absent
        assertEquals(listOf("file_scanner"), byKey["e"])
    }

    @Test
    fun `detected_by is read from the bundled json`() {
        val json = """[{"key":"a","label":"A","aliases":[],"detected_by":["dns_monitor"]},
            {"key":"b","label":"B","aliases":[]},{"key":"c","label":"C","aliases":[],"detected_by":"x"}]"""
        val byKey = CampaignRegistry.parseBundled(json).associate { it.key to it.detectedBy }
        assertEquals(listOf("dns_monitor"), byKey["a"])
        assertNull(byKey["b"])
        assertNull(byKey["c"])
    }

    @Test
    fun `the bundle declares detected_by for every campaign`() {
        val byKey = CampaignRegistry.parseBundled(bundledJson).associate { it.key to it.detectedBy }
        assertEquals(
            mapOf(
                "cellebrite" to listOf("app_scanner"), "graphite" to listOf("dns_monitor"),
                "landfall" to emptyList(), "massistant" to listOf("app_scanner"),
                "midnight-mimosa" to listOf("app_scanner", "dns_monitor"), "pegasus" to listOf("dns_monitor"),
                "predator" to listOf("dns_monitor", "file_scanner"),
            ),
            byKey,
        )
    }
```

And in `scripts/test_merge_ioc_data.py` append:

```python
def test_campaign_vocabulary_carries_detected_by(tmp_path):
    root = repo(tmp_path)
    (root / "ioc-data" / "campaigns.yml").write_text(
        "campaigns:\n- key: graphite\n  label: Graphite (Paragon)\n  aliases: [paragon]\n"
        "  detected_by: [dns_monitor]\n  references: []\n")
    out = tmp_path / "raw"; out.mkdir()
    m.generate(root, out)
    assert json.loads((out / "known_campaigns.json").read_text()) == [
        {"key": "graphite", "label": "Graphite (Paragon)", "aliases": ["paragon"], "detected_by": ["dns_monitor"]}]
```

- [ ] **Step 3: Run them to verify they fail**

Run: `JAVA_HOME=/home/yasir/.gradle/jdks/eclipse_adoptium-21-amd64-linux.2 ANDROID_HOME=/home/yasir/Android/Sdk ./gradlew testDebugUnitTest --tests 'com.androdr.ioc.CampaignRegistryTest' -q` and `python3 -m pytest -q scripts/test_merge_ioc_data.py`
Expected: Kotlin compile error `Unresolved reference: detectedBy`; pytest `test_campaign_vocabulary_carries_detected_by` FAILS (no `detected_by` key).

- [ ] **Step 4: Implement parsing** in `CampaignRegistry.kt`:

Replace the data class:

```kotlin
/**
 * One mercenary-check row: a `campaigns.yml` key, its display label, the aliases that fold into it,
 * and the rule services that can make it DETECTED (#394). [detectedBy] null = the source predates
 * the field (render today's row); empty = patch level only, no infection check exists.
 */
data class Campaign(
    val key: String,
    val label: String,
    val aliases: List<String> = emptyList(),
    val detectedBy: List<String>? = null,
)
```

In the companion, add `private val SERVICE = Regex("^[a-z_]{1,32}$")` next to `KEY`, and a private holder:

```kotlin
        private data class RawCampaign(
            val key: String?, val label: String?, val aliases: List<String>, val detectedBy: List<String>?,
        )
```

`parseBundled` builds `RawCampaign(key, label, aliases, detectedBy = (o["detected_by"] as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.content })` in place of the `Triple`; `parseYaml` builds `RawCampaign(..., detectedBy = (m["detected_by"] as? List<*>)?.mapNotNull { it?.toString() })`. `validated` takes `List<RawCampaign>`:

```kotlin
        private fun validated(raw: List<RawCampaign>): List<Campaign> =
            raw.mapNotNull { r ->
                val key = r.key
                if (key == null || !KEY.matches(key)) return@mapNotNull null
                val clean = IocSanitizer.clean(r.label.orEmpty()).takeCodePoints(MAX_LABEL).trim()
                Campaign(
                    key = key,
                    label = clean.ifEmpty { key.replaceFirstChar { it.uppercase() } },
                    aliases = r.aliases.filter { KEY.matches(it) && it != key }.distinct().sorted(),
                    detectedBy = r.detectedBy?.filter { SERVICE.matches(it) }?.distinct()?.sorted(),
                )
            }.distinctBy { it.key }.sortedBy { it.key } // same row order whichever source loaded
```

Update the two KDoc lines that describe the formats to `[{key, label, aliases, detected_by}]`.

- [ ] **Step 5: Emit it from the merge script** — `scripts/merge-ioc-data.py`, replace the `known_campaigns.json` dict comprehension body and the comment at line 33:

```python
    # known_campaigns.json is rendered separately: [{"key", "label", "aliases", "detected_by"?}] from campaigns.yml
```

```python
    def _campaign(c):
        row = {"key": c["key"], "label": c["label"], "aliases": sorted(c.get("aliases", []))}
        if "detected_by" in c:   # absent stays absent: the app renders today's row for it
            row["detected_by"] = sorted(c["detected_by"])
        return row
    out["known_campaigns.json"] = json.dumps(
        sorted((_campaign(c) for c in camps), key=lambda c: c["key"]), indent=2, ensure_ascii=True) + "\n"
```

- [ ] **Step 6: Regenerate the bundle**

Run: `python3 scripts/merge-ioc-data.py && python3 scripts/merge-ioc-data.py --check && git diff --stat app/src/main/res/raw/`
Expected: only `known_campaigns.json` changed; `--check` exits 0.

- [ ] **Step 7: Run the tests to verify they pass**

Run: `python3 -m pytest -q scripts/test_merge_ioc_data.py` and `rm -rf app/build/test-results && JAVA_HOME=/home/yasir/.gradle/jdks/eclipse_adoptium-21-amd64-linux.2 ANDROID_HOME=/home/yasir/Android/Sdk ./gradlew testDebugUnitTest --tests 'com.androdr.ioc.*' --tests 'com.androdr.reporting.*' -q`
Expected: all pass, including the existing `the pinned campaigns yml parses to the same vocabulary as the bundle` (both sides now carry `detectedBy`). `MercenaryCheckReportTest` still passes: rendering does not read the field yet.

- [ ] **Step 8: Commit**

```bash
git add third-party/android-sigma-rules app/src/main/java/com/androdr/ioc/CampaignRegistry.kt scripts/merge-ioc-data.py scripts/test_merge_ioc_data.py app/src/main/res/raw/known_campaigns.json app/src/test/java/com/androdr/ioc/CampaignRegistryTest.kt
git commit -m "feat(campaigns): read detected_by from campaigns.yml and the bundle (#394)" -m "Submodule pinned to the rules feat/394-detected-by branch (safe ordering).

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01B8H9x5KmTtY8Ejyi2eUdjH"
```

---

### Task A2: `campaignCoverage` — one status per declared service

**Files:**
- Create: `app/src/main/java/com/androdr/reporting/CampaignCoverage.kt`
- Modify: `app/src/main/java/com/androdr/data/model/ScanResult.kt` (`ScannerFailure.missingSources`), `app/src/main/java/com/androdr/scanner/ScanVisibilityGaps.kt`
- Test: `app/src/test/java/com/androdr/reporting/CampaignCoverageTest.kt`, `app/src/test/java/com/androdr/reporting/ServiceScannerMapCrossCheckTest.kt`, `app/src/test/java/com/androdr/scanner/ScanVisibilityGapsTest.kt`

**Interfaces:**
- Consumes: `ScannerFailure`, `NotEvaluatedReason` (`data/model/ScanResult.kt`).
- Produces (used by A4):
  - `enum class ServiceCoverage { CHECKED, BUILT_IN_LISTS_ONLY, PARTLY_UNREADABLE, BLIND, NEEDS_IMPORT }`
  - `enum class BlindReason { DNS_OFF, CHECK_FAILED, UNKNOWN_SERVICE }`
  - `data class ServiceStatus(val service: String, val coverage: ServiceCoverage, val reason: BlindReason? = null)`
  - `internal val SCANNER_FOR_SERVICE: Map<String, String>`, `internal val IMPORT_ONLY_SERVICES: Set<String>`, `internal const val DNS_SNAPSHOT_SCANNER = "dnsSnapshot"`
  - `internal fun campaignCoverage(detectedBy: List<String>, campaignKey: String, scannerErrors: List<ScannerFailure>, ruleCampaigns: Map<String, Set<String>>): List<ServiceStatus>`
  - `ScannerFailure.missingSources: List<String> = emptyList()` — for `CAMPAIGN_SOURCES_NOT_LOADED` only: `"rules_repo"` and/or `"mvt"` (`MISSING_SOURCE_RULES_REPO`, `MISSING_SOURCE_MVT` constants in `ScanVisibilityGaps.kt`).

**Owner addition (2026-10-17): a missing MVT list affects DNS rows only.** MVT carries domain indicators only, so a `CAMPAIGN_SOURCES_NOT_LOADED` entry naming only `mvt` must not mark `app_scanner` built-in-only. The source is stored structurally in a new `ScannerFailure.missingSources` field: **not** `missingEvidence`, which `appendNotChecked` renders as "needs X, none recorded in this scan" and which belongs to `NO_EVENTS_TO_CHECK`. The field is JSON with a default, so it needs no migration, and old rows decode as empty. An entry with empty `missingSources` (a scan saved before this change) keeps the cautious reading: both list services are built-in-only.

- [ ] **Step 0a: Failing test** — append to `ScanVisibilityGapsTest.kt`:

```kotlin
    @Test
    fun `campaign-sources entry records which sources were missing`() {
        fun sources(rulesRepo: Boolean, mvt: Boolean) = scanVisibilityGaps(
            FeedCoverage(rows = 10, rulesRepoLoaded = rulesRepo, mvtLoaded = mvt), dnsMonitorRunning = true,
        ).single().missingSources
        assertEquals(listOf(MISSING_SOURCE_MVT), sources(rulesRepo = true, mvt = false))
        assertEquals(listOf(MISSING_SOURCE_RULES_REPO), sources(rulesRepo = false, mvt = true))
        assertEquals(listOf(MISSING_SOURCE_RULES_REPO, MISSING_SOURCE_MVT), sources(rulesRepo = false, mvt = false))
    }
```
(Add `import org.junit.Assert.assertEquals` if the file lacks it.) Run `JAVA_HOME=/home/yasir/.gradle/jdks/eclipse_adoptium-21-amd64-linux.2 ANDROID_HOME=/home/yasir/Android/Sdk ./gradlew testDebugUnitTest --tests 'com.androdr.scanner.ScanVisibilityGapsTest' -q` → FAIL (unresolved `missingSources` / constants).

- [ ] **Step 0b: Implement.** In `ScanResult.kt`, add to `ScannerFailure` after `missingEvidence`:

```kotlin
    /**
     * For [NotEvaluatedReason.CAMPAIGN_SOURCES_NOT_LOADED]: which sources did not load
     * ("rules_repo", "mvt"), so the mercenary check can tell a missing MVT list (domains only)
     * from a missing rules-repo list (domains and packages) without parsing [message] (#394).
     * Empty on rows saved before this field existed: readers must then assume both.
     */
    val missingSources: List<String> = emptyList(),
```
In `ScanVisibilityGaps.kt`, add top-level `internal const val MISSING_SOURCE_RULES_REPO = "rules_repo"` and `internal const val MISSING_SOURCE_MVT = "mvt"`, and pass `missingSources = listOfNotNull(if (coverage.rulesRepoLoaded) null else MISSING_SOURCE_RULES_REPO, if (coverage.mvtLoaded) null else MISSING_SOURCE_MVT)` to the `CAMPAIGN_SOURCES_NOT_LOADED` `ScannerFailure`. Rerun Step 0a's command → PASS.


- [ ] **Step 1: Failing tests** — `CampaignCoverageTest.kt`:

```kotlin
package com.androdr.reporting

import com.androdr.data.model.NotEvaluatedReason
import com.androdr.data.model.ScannerFailure
import org.junit.Assert.assertEquals
import org.junit.Test

class CampaignCoverageTest {

    private fun sentinel(reason: NotEvaluatedReason, scanner: String = "x", ruleId: String? = null) =
        ScannerFailure(scanner = scanner, exception = reason.sentinel, message = "m", ruleId = ruleId)
    private fun crash(scanner: String) = ScannerFailure(scanner = scanner, exception = "IllegalStateException", message = "boom")
    private fun one(service: String, errors: List<ScannerFailure>, key: String = "predator",
                    ruleCampaigns: Map<String, Set<String>> = emptyMap()) =
        campaignCoverage(listOf(service), key, errors, ruleCampaigns).single()

    @Test
    fun `nothing recorded means every service was checked`() {
        assertEquals(
            listOf(ServiceStatus("dns_monitor", ServiceCoverage.CHECKED), ServiceStatus("file_scanner", ServiceCoverage.CHECKED)),
            campaignCoverage(listOf("dns_monitor", "file_scanner"), "predator", emptyList(), emptyMap()),
        )
    }

    @Test
    fun `dns monitor off is blind with the dns reason`() {
        assertEquals(ServiceStatus("dns_monitor", ServiceCoverage.BLIND, BlindReason.DNS_OFF),
            one("dns_monitor", listOf(sentinel(NotEvaluatedReason.DNS_MONITOR_OFF, "dns_monitor"))))
    }

    @Test
    fun `a failed dns snapshot read is blind with the failure reason`() {
        assertEquals(ServiceStatus("dns_monitor", ServiceCoverage.BLIND, BlindReason.CHECK_FAILED),
            one("dns_monitor", listOf(crash(DNS_SNAPSHOT_SCANNER))))
    }

    @Test
    fun `a crashed scanner makes its service blind`() {
        assertEquals(ServiceStatus("app_scanner", ServiceCoverage.BLIND, BlindReason.CHECK_FAILED),
            one("app_scanner", listOf(crash("appScanner"))))
    }

    @Test
    fun `crash beats feeds not loaded`() {
        assertEquals(ServiceCoverage.BLIND,
            one("app_scanner", listOf(crash("appScanner"), sentinel(NotEvaluatedReason.FEEDS_NOT_LOADED))).coverage)
    }

    @Test
    fun `missing MVT only marks DNS built-in-only, not installed apps`() {
        val mvtOnly = ScannerFailure("threat_intel", NotEvaluatedReason.CAMPAIGN_SOURCES_NOT_LOADED.sentinel, "m",
            missingSources = listOf(MISSING_SOURCE_MVT))
        assertEquals(ServiceCoverage.BUILT_IN_LISTS_ONLY, one("dns_monitor", listOf(mvtOnly)).coverage)
        assertEquals(ServiceCoverage.CHECKED, one("app_scanner", listOf(mvtOnly)).coverage)
        val repo = mvtOnly.copy(missingSources = listOf(MISSING_SOURCE_RULES_REPO))
        assertEquals(ServiceCoverage.BUILT_IN_LISTS_ONLY, one("app_scanner", listOf(repo)).coverage)
    }

    @Test
    fun `feeds or campaign sources not loaded leave the list services on the built-in lists`() {
        listOf(NotEvaluatedReason.FEEDS_NOT_LOADED, NotEvaluatedReason.CAMPAIGN_SOURCES_NOT_LOADED).forEach { r ->
            assertEquals(r.name, ServiceCoverage.BUILT_IN_LISTS_ONLY, one("dns_monitor", listOf(sentinel(r))).coverage)
            assertEquals(r.name, ServiceCoverage.BUILT_IN_LISTS_ONLY, one("app_scanner", listOf(sentinel(r))).coverage)
            assertEquals(r.name, ServiceCoverage.CHECKED, one("file_scanner", listOf(sentinel(r))).coverage)
        }
    }

    @Test
    fun `unreadable paths of this campaign's rule leave files partly checked`() {
        val e = sentinel(NotEvaluatedReason.UNREADABLE_PATHS, "file_scanner", ruleId = "androdr-108")
        assertEquals(ServiceCoverage.PARTLY_UNREADABLE,
            one("file_scanner", listOf(e), ruleCampaigns = mapOf("androdr-108" to setOf("predator"))).coverage)
    }

    @Test
    fun `unreadable paths of another campaign's rule do not count`() {
        val e = sentinel(NotEvaluatedReason.UNREADABLE_PATHS, "file_scanner", ruleId = "androdr-108")
        assertEquals(ServiceCoverage.CHECKED,
            one("file_scanner", listOf(e), key = "pegasus", ruleCampaigns = mapOf("androdr-108" to setOf("predator"))).coverage)
        assertEquals(ServiceCoverage.CHECKED, one("file_scanner", listOf(e), ruleCampaigns = emptyMap()).coverage)
    }

    @Test
    fun `an import-only service needs an import`() {
        assertEquals(ServiceStatus("security_log", ServiceCoverage.NEEDS_IMPORT), one("security_log", emptyList()))
    }

    @Test
    fun `unknown service is blind`() {
        assertEquals(ServiceStatus("usage_stats", ServiceCoverage.BLIND, BlindReason.UNKNOWN_SERVICE),
            one("usage_stats", emptyList()))
    }

    @Test
    fun `patch level only campaign has no services`() {
        assertEquals(emptyList<ServiceStatus>(), campaignCoverage(emptyList(), "landfall", emptyList(), emptyMap()))
    }
}
```

`ServiceScannerMapCrossCheckTest.kt`:

```kotlin
package com.androdr.reporting

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.snakeyaml.engine.v2.api.Load
import org.snakeyaml.engine.v2.api.LoadSettings
import java.io.File

/**
 * Every logsource service is either run by a live scan (SCANNER_FOR_SERVICE, keyed to the name the
 * orchestrator records when that scanner crashes) or only by an import (IMPORT_ONLY_SERVICES).
 * A new service or a renamed scanner would otherwise count as "always checked" (#394).
 */
class ServiceScannerMapCrossCheckTest {

    private fun file(vararg candidates: String) = candidates.map(::File).first { it.isFile }

    @Suppress("UNCHECKED_CAST")
    private fun taxonomyServices(): Set<String> {
        val f = file("../third-party/android-sigma-rules/validation/logsource-taxonomy.yml",
            "third-party/android-sigma-rules/validation/logsource-taxonomy.yml")
        val root = Load(LoadSettings.builder().build()).loadFromString(f.readText()) as Map<String, Any?>
        return (root["services"] as Map<String, Any?>).keys
    }

    @Test
    fun `every taxonomy service is classified exactly once`() {
        val services = taxonomyServices()
        assertEquals(services, SCANNER_FOR_SERVICE.keys + IMPORT_ONLY_SERVICES)
        assertTrue((SCANNER_FOR_SERVICE.keys intersect IMPORT_ONLY_SERVICES).isEmpty())
    }

    @Test
    fun `every mapped scanner name is one the orchestrator records`() {
        val source = file("src/main/java/com/androdr/scanner/ScanOrchestrator.kt",
            "app/src/main/java/com/androdr/scanner/ScanOrchestrator.kt").readText()
        val recorded = Regex("""trackedAsync\(\s*"(\w+)"""").findAll(source).map { it.groupValues[1] }.toSet() +
            (if ("scanner = DNS_SNAPSHOT_SCANNER" in source) setOf(DNS_SNAPSHOT_SCANNER) else emptySet())
        assertTrue("not recorded by ScanOrchestrator: ${SCANNER_FOR_SERVICE.values.toSet() - recorded}",
            recorded.containsAll(SCANNER_FOR_SERVICE.values))
    }
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `JAVA_HOME=/home/yasir/.gradle/jdks/eclipse_adoptium-21-amd64-linux.2 ANDROID_HOME=/home/yasir/Android/Sdk ./gradlew testDebugUnitTest --tests 'com.androdr.reporting.CampaignCoverageTest' --tests 'com.androdr.reporting.ServiceScannerMapCrossCheckTest' -q`
Expected: compile error `Unresolved reference: campaignCoverage`.

- [ ] **Step 3: Implement** `CampaignCoverage.kt`:

```kotlin
package com.androdr.reporting

import com.androdr.data.model.NotEvaluatedReason
import com.androdr.data.model.ScannerFailure

/** How fully a scan covered one service a campaign is detected by (#394). */
enum class ServiceCoverage { CHECKED, BUILT_IN_LISTS_ONLY, PARTLY_UNREADABLE, BLIND, NEEDS_IMPORT }

/** Why a [ServiceCoverage.BLIND] service did not run; each has its own row text and fix. */
enum class BlindReason { DNS_OFF, CHECK_FAILED, UNKNOWN_SERVICE }

data class ServiceStatus(val service: String, val coverage: ServiceCoverage, val reason: BlindReason? = null)

/** The scanner name the orchestrator records when the DNS snapshot read fails. */
internal const val DNS_SNAPSHOT_SCANNER = "dnsSnapshot"

/**
 * Live-scan service -> the scanner name a crash of it is recorded under. Pinned against the
 * taxonomy and ScanOrchestrator by ServiceScannerMapCrossCheckTest.
 */
internal val SCANNER_FOR_SERVICE: Map<String, String> = mapOf(
    "app_scanner" to "appScanner",
    "device_auditor" to "deviceAuditor",
    "process_monitor" to "processScanner",
    "file_scanner" to "fileArtifactScanner",
    "accessibility_audit" to "accessibilityAuditScanner",
    "receiver_audit" to "receiverAuditScanner",
    "appops_audit" to "appOpsScanner",
    "dns_monitor" to DNS_SNAPSHOT_SCANNER,
)

/** Services only an imported bug report or intrusion log is evaluated against. */
internal val IMPORT_ONLY_SERVICES: Set<String> = setOf(
    "network_monitor", "security_log", "tombstone_parser", "wakelock_parser", "battery_daily",
    "package_install_history", "platform_compat", "db_info", "timeline",
)

/** Services whose matches come from threat lists that may still be loading. */
private val LIST_SERVICES = setOf("dns_monitor", "app_scanner")
private const val FILE_SERVICE = "file_scanner"
private const val DNS_SERVICE = "dns_monitor"

/**
 * One status per service in [detectedBy], from what the scan stored: the first that applies of
 * import-only, blind (DNS off, a crash of its scanner, or a service this build doesn't know),
 * files partly unreadable for this campaign's own rule, built-in lists only, else checked.
 */
internal fun campaignCoverage(
    detectedBy: List<String>,
    campaignKey: String,
    scannerErrors: List<ScannerFailure>,
    ruleCampaigns: Map<String, Set<String>>,
): List<ServiceStatus> {
    val reasons = scannerErrors.mapNotNull { e -> NotEvaluatedReason.fromSentinel(e.exception)?.let { it to e } }
    val crashed = scannerErrors.filter { NotEvaluatedReason.fromSentinel(it.exception) == null }.map { it.scanner }.toSet()
    fun has(r: NotEvaluatedReason) = reasons.any { it.first == r }
    // Which list services ran on the built-in lists only. FEEDS_NOT_LOADED: both. CAMPAIGN_SOURCES_NOT_LOADED:
    // a missing MVT list touches domains only; a missing rules-repo list, or a row saved before
    // missingSources existed (empty), touches both (owner addition, #394).
    val builtInOnly: Set<String> = buildSet {
        if (has(NotEvaluatedReason.FEEDS_NOT_LOADED)) addAll(LIST_SERVICES)
        reasons.filter { it.first == NotEvaluatedReason.CAMPAIGN_SOURCES_NOT_LOADED }.forEach { (_, e) ->
            val src = e.missingSources
            if (src.isEmpty() || MISSING_SOURCE_RULES_REPO in src) addAll(LIST_SERVICES)
            if (MISSING_SOURCE_MVT in src) add(DNS_SERVICE)
        }
    }
    val ownPathsUnreadable = reasons.any { (r, e) ->
        r == NotEvaluatedReason.UNREADABLE_PATHS && campaignKey in e.ruleId?.let { ruleCampaigns[it] }.orEmpty()
    }
    return detectedBy.map { service ->
        when {
            service in IMPORT_ONLY_SERVICES -> ServiceStatus(service, ServiceCoverage.NEEDS_IMPORT)
            service == DNS_SERVICE && has(NotEvaluatedReason.DNS_MONITOR_OFF) ->
                ServiceStatus(service, ServiceCoverage.BLIND, BlindReason.DNS_OFF)
            service !in SCANNER_FOR_SERVICE -> ServiceStatus(service, ServiceCoverage.BLIND, BlindReason.UNKNOWN_SERVICE)
            SCANNER_FOR_SERVICE.getValue(service) in crashed ->
                ServiceStatus(service, ServiceCoverage.BLIND, BlindReason.CHECK_FAILED)
            service == FILE_SERVICE && ownPathsUnreadable -> ServiceStatus(service, ServiceCoverage.PARTLY_UNREADABLE)
            service in builtInOnly -> ServiceStatus(service, ServiceCoverage.BUILT_IN_LISTS_ONLY)
            else -> ServiceStatus(service, ServiceCoverage.CHECKED)
        }
    }
}
```

- [ ] **Step 4: Run them to verify** — same command as Step 2.
Expected: `CampaignCoverageTest` all PASS; `ServiceScannerMapCrossCheckTest.every taxonomy service is classified exactly once` PASSES; `every mapped scanner name is one the orchestrator records` FAILS naming `dnsSnapshot` (Task A3 adds it). This one red test is expected until A3; note it in the task report.

- [ ] **Step 5: Detekt** — `JAVA_HOME=/home/yasir/.gradle/jdks/eclipse_adoptium-21-amd64-linux.2 ANDROID_HOME=/home/yasir/Android/Sdk ./gradlew detekt -q`. Expected: clean (add `@Suppress("CyclomaticComplexMethod")` on `campaignCoverage` only if detekt flags it).

- [ ] **Step 6: Commit**

```bash
git add app/src/main/java/com/androdr/reporting/CampaignCoverage.kt app/src/test/java/com/androdr/reporting/CampaignCoverageTest.kt app/src/test/java/com/androdr/reporting/ServiceScannerMapCrossCheckTest.kt app/src/main/java/com/androdr/data/model/ScanResult.kt app/src/main/java/com/androdr/scanner/ScanVisibilityGaps.kt app/src/test/java/com/androdr/scanner/ScanVisibilityGapsTest.kt
git commit -m "feat(report): campaignCoverage, one status per detected_by service (#394)" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01B8H9x5KmTtY8Ejyi2eUdjH"
```

---

### Task A3: A failed DNS snapshot read is recorded, not swallowed

**Files:**
- Modify: `app/src/main/java/com/androdr/scanner/ScanOrchestrator.kt:384-386`
- Test: `app/src/test/java/com/androdr/scanner/ScanOrchestratorErrorHandlingTest.kt`

**Interfaces:**
- Consumes: `DNS_SNAPSHOT_SCANNER` (A2, `com.androdr.reporting`).
- Produces: `ScannerFailure(scanner = "dnsSnapshot", exception = <class simple name>, message = <e.message>)` on the scan; it is a real failure (counts in `realFailureCount`, marks the scan partial — DNS rules did not run).

- [ ] **Step 1: Failing test** — add to `ScanOrchestratorErrorHandlingTest`:

```kotlin
    @Test
    fun `a failed DNS snapshot read is recorded as dnsSnapshot and the scan completes`() = runTest {
        coEvery { dnsEventDao.getRecentSnapshot() } throws IllegalStateException("database is locked")

        val result: ScanResult = orchestrator.runFullScan()

        val failure = result.scannerErrors.single { it.scanner == "dnsSnapshot" }
        assertEquals("IllegalStateException", failure.exception)
        assertEquals("database is locked", failure.message)
        assertTrue("DNS rules did not run: the scan is partial", result.isPartialScan)
    }

    @Test
    fun `cancellation during the DNS snapshot read propagates`() = runTest {
        coEvery { dnsEventDao.getRecentSnapshot() } throws CancellationException("user cancelled")
        var caught: Throwable? = null
        try { orchestrator.runFullScan() } catch (e: CancellationException) { caught = e }
        assertNotNull(caught)
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `JAVA_HOME=/home/yasir/.gradle/jdks/eclipse_adoptium-21-amd64-linux.2 ANDROID_HOME=/home/yasir/Android/Sdk ./gradlew testDebugUnitTest --tests 'com.androdr.scanner.ScanOrchestratorErrorHandlingTest' -q`
Expected: the first test FAILS (`NoSuchElementException`: no `dnsSnapshot` entry); the cancellation test FAILS (`runCatching` swallows it).

- [ ] **Step 3: Implement** — replace

```kotlin
        val recentDnsEvents = runCatching {
            dnsEventDao.getRecentSnapshot()
        }.getOrDefault(emptyList())
```

with

```kotlin
        // A failed read means the DNS rules did not run: record it (#394) so the report says so
        // per campaign, instead of reading as "no DNS hits".
        @Suppress("TooGenericExceptionCaught")
        val recentDnsEvents = try {
            dnsEventDao.getRecentSnapshot()
        } catch (c: CancellationException) {
            throw c
        } catch (e: Exception) {
            Log.w(TAG, "DNS snapshot read failed; DNS rules not evaluated", e)
            synchronized(scannerErrors) {
                scannerErrors.add(
                    ScannerFailure(scanner = DNS_SNAPSHOT_SCANNER, exception = e.javaClass.simpleName, message = e.message)
                )
            }
            emptyList()
        }
```

and add `import com.androdr.reporting.DNS_SNAPSHOT_SCANNER`.

- [ ] **Step 4: Run to verify** — the orchestrator test class plus the cross-check:

Run: `rm -rf app/build/test-results && JAVA_HOME=/home/yasir/.gradle/jdks/eclipse_adoptium-21-amd64-linux.2 ANDROID_HOME=/home/yasir/Android/Sdk ./gradlew testDebugUnitTest --tests 'com.androdr.scanner.*' --tests 'com.androdr.reporting.ServiceScannerMapCrossCheckTest' -q`
Expected: all PASS (the A2 cross-check now finds `scanner = DNS_SNAPSHOT_SCANNER` in the source).

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/androdr/scanner/ScanOrchestrator.kt app/src/test/java/com/androdr/scanner/ScanOrchestratorErrorHandlingTest.kt
git commit -m "fix(scan): record a failed DNS snapshot read instead of swallowing it (#394)" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01B8H9x5KmTtY8Ejyi2eUdjH"
```

---

### Task A4: Rows say why — inputs, verdicts, rendering

**Files:**
- Modify: `app/src/main/java/com/androdr/reporting/ReportInputs.kt`, `CampaignVerdict.kt`, `ReportFormatter.kt:47-85`, `ReportExporter.kt:89-91`, `ui/history/HistoryViewModel.kt:96-107`
- Test: `ReportInputsTest.kt`, `MercenaryCheckReportTest.kt`, and the mechanical call-site update in `ReportFormatterTest.kt`, `DnsAttributionReportTest.kt`, `IntrusionLogReportSectionTest.kt`, `ScanVisibilityGapsTest.kt`, `IocEvidenceRegistrationTest.kt`, `ReportRendersEveryFindingCategoryTest.kt`, `OverallRiskConsistencyTest.kt`, `NotEvaluatedReportSectionTest.kt`, `ImportDnsSectionTest.kt`, `ActivityChainsReportSectionTest.kt`

**Interfaces:**
- Consumes: `Campaign.detectedBy` (A1), `campaignCoverage`, `ServiceStatus`, `ServiceCoverage`, `BlindReason` (A2).
- Produces: `ReportInputs.ruleCampaigns(): Map<String, Set<String>>`; `CampaignVerdict.coverage: List<ServiceStatus>?`; `campaignVerdicts(scan, campaigns, referenceTime, ruleCategoryById, ruleCampaigns)`; `ReportFormatter.formatScanReport(..., ruleCampaigns: Map<String, Set<String>>, ...)` — required, no default (a default would hide a missing production wiring).

- [ ] **Step 1: Failing test — inputs.** Append to `ReportInputsTest` (and give its `rule()` helper a `tags: List<String> = emptyList()` parameter passed through to `SigmaRule`):

```kotlin
    @Test
    fun `ruleCampaigns resolves campaign tags through aliases and drops unknown ones`() {
        val engine = mockk<SigmaRuleEngine> {
            every { getRules() } returns listOf(
                rule("androdr-108", RuleCategory.INCIDENT, tags = listOf("attack.t1", "campaign.cytrox")),
                rule("androdr-200", RuleCategory.INCIDENT, tags = listOf("campaign.nobody")),
                rule("androdr-001", RuleCategory.INCIDENT),
            )
        }
        val registry = mockk<CampaignRegistry> {
            every { campaigns() } returns listOf(Campaign("predator", "Predator", aliases = listOf("cytrox")))
        }
        assertEquals(mapOf("androdr-108" to setOf("predator")), ReportInputs(registry, engine).ruleCampaigns())
    }
```

- [ ] **Step 2: Failing tests — rows.** In `MercenaryCheckReportTest`:
  - give `formatReportWith` a `ruleCampaigns: Map<String, Set<String>> = emptyMap()` parameter and pass `ruleCampaigns = ruleCampaigns` to `formatScanReport`; `formatImportReportWith` passes `ruleCampaigns = emptyMap()`.
  - replace the body of `not detected carries the scope note` so it exercises the legacy fallback (a campaign without the field), renamed:

```kotlin
    @Test
    fun `legacy campaign without detected_by keeps today's row and the note`() {
        val legacy = Campaign("pegasus", "Pegasus")
        val report = formatReportWith(campaigns = listOf(legacy),
            scannerErrors = listOf(ScannerFailure(scanner = "threat_intel",
                exception = NotEvaluatedReason.FEEDS_NOT_LOADED.sentinel, message = "threat-intel feeds not loaded yet")))
        assertTrue(report.contains("[OK]  Pegasus: not detected"))
        assertTrue(report.contains("\"not detected\" means none of the checks that ran in this scan matched."))
        assertTrue(report.contains("1 check(s) could not run -- see ${ReportFormatter.NOT_CHECKED_SECTION} below."))
    }
```

  - replace `clean live device lists every registry campaign as not detected` with:

```kotlin
    @Test
    fun `clean live device - fully checked campaigns are OK, LANDFALL has no infection check`() {
        val report = formatReportWith(campaigns = REGISTRY)
        REGISTRY.filter { it.key != "landfall" }
            .forEach { assertTrue(it.key, report.contains("  [OK]  ${it.label}: not detected")) }
        assertTrue(report.contains("  [--]  LANDFALL: no infection check exists for a live scan; patch level only"))
        assertFalse("every row carries its own reason", report.contains("\"not detected\" means"))
        assertTrue(report.contains("Campaign detections: none"))
    }
```

  - add:

```kotlin
    private val dnsOff = ScannerFailure(scanner = "dns_monitor",
        exception = NotEvaluatedReason.DNS_MONITOR_OFF.sentinel, message = "DNS monitoring was off")
    private val dnsOffClause =
        "DNS lookups not monitored (DNS monitoring was off; only lookups recorded earlier were checked)"
    private val dnsOffFix = "        Turn on DNS monitoring, use the phone as usual, then scan again."

    @Test
    fun `dns off - a dns-only campaign is not fully checked and says how to fix it`() {
        val lines = formatReportWith(campaigns = listOf(campaign("pegasus")), scannerErrors = listOf(dnsOff)).lines()
        val at = lines.indexOf("  [--]  Pegasus: $dnsOffClause")
        assertTrue(lines.joinToString("\n"), at >= 0)
        assertEquals(dnsOffFix, lines[at + 1])
    }

    @Test
    fun `dns off - a two-service campaign names what was checked and what was not`() {
        val report = formatReportWith(campaigns = listOf(campaign("midnight-mimosa")), scannerErrors = listOf(dnsOff))
        assertTrue(report, report.contains("  [--]  Midnight Mimosa: no hit in installed apps; $dnsOffClause"))
    }

    @Test
    fun `a crashed scanner says the check failed`() {
        val report = formatReportWith(campaigns = listOf(campaign("massistant")),
            scannerErrors = listOf(ScannerFailure("appScanner", "IllegalStateException", "boom")))
        assertTrue(report, report.contains(
            "  [--]  Massistant: installed apps not checked (that check failed on this scan)"))
        assertTrue(report, report.contains("        Scan again; if it keeps failing, export the report and send it to us."))
    }

    @Test
    fun `this campaign's unreadable file paths leave it partly checked`() {
        val report = formatReportWith(campaigns = listOf(campaign("predator")),
            ruleCampaigns = mapOf("androdr-108" to setOf("predator")),
            scannerErrors = listOf(ScannerFailure("file_scanner", NotEvaluatedReason.UNREADABLE_PATHS.sentinel,
                "Predator (androdr-108): 3 of 5 path(s) could not be read", ruleId = "androdr-108")))
        assertTrue(report, report.contains(
            "  [--]  Predator: no hit in DNS lookups; files only partly checked (some paths could not be read)"))
    }

    @Test
    fun `a shared fix is printed once`() {
        val report = formatReportWith(campaigns = listOf(campaign("midnight-mimosa")),
            scannerErrors = listOf(ScannerFailure("threat_intel", NotEvaluatedReason.FEEDS_NOT_LOADED.sentinel, "x")))
        assertTrue(report, report.contains("  [--]  Midnight Mimosa: installed apps checked against the built-in list " +
            "only (threat lists had not finished loading); DNS lookups checked against the built-in list only " +
            "(threat lists had not finished loading)"))
        assertEquals(1, Regex("Scan again in a few minutes\\.").findAll(report).count())
    }

    @Test
    fun `unknown service fails closed`() {
        val future = Campaign("pegasus", "Pegasus", detectedBy = listOf("usage_stats"))
        val report = formatReportWith(campaigns = listOf(future))
        assertTrue(report, report.contains("  [--]  Pegasus: usage_stats not checked (this app version does not know that check)"))
        assertTrue(report, report.contains("        Update the app."))
    }

    @Test
    fun `exposed carries the infection-check summary`() {
        val cve = cveCampaignFinding(tags = listOf("campaign.pegasus"), triggered = true, ruleCategory = "DEVICE_POSTURE")
        val report = formatReportWith(deviceFlags = listOf(cve), campaigns = listOf(campaign("pegasus")),
            scannerErrors = listOf(dnsOff))
        assertTrue(report, report.contains("  [!!]  Pegasus: EXPOSED -- Unpatched exploited CVE (unpatched; not " +
            "evidence of infection); infection check: $dnsOffClause"))
        val clean = formatReportWith(deviceFlags = listOf(cve), campaigns = listOf(campaign("pegasus")))
        assertTrue(clean, clean.contains("(unpatched; not evidence of infection); infection check: not detected"))
    }

    @Test
    fun `import rows are unchanged even with detected_by`() {
        val report = formatImportReportWith(appRisks = emptyList(), campaigns = listOf(campaign("pegasus")))
        assertTrue(report, report.contains("  [--]  Pegasus: no hit in the imported log (device checks not run)"))
        assertFalse(report, report.contains("infection check"))
    }
```

- [ ] **Step 3: Mechanical call-site update** (every direct `formatScanReport` call names `ruleCategoryById`; the two test helpers get the parameter in Step 2):

```bash
perl -0pi -e 's/ruleCategoryById = /ruleCampaigns = emptyMap(), ruleCategoryById = /g' $(grep -rl "ruleCategoryById = " app/src/test)
```

Then fix the two helpers that must forward their own parameter, not `emptyMap()`: in `MercenaryCheckReportTest.formatReportWith` the call reads `ruleCampaigns = ruleCampaigns, ruleCategoryById = ruleCategoryById`; in `ReportFormatterTest.formatReportWith` add the parameter `ruleCampaigns: Map<String, Set<String>> = emptyMap()` and forward it the same way. Check: `grep -rn "ruleCampaigns = emptyMap(), ruleCampaigns" app/src/test` prints nothing.

- [ ] **Step 4: Run to verify they fail**

Run: `JAVA_HOME=/home/yasir/.gradle/jdks/eclipse_adoptium-21-amd64-linux.2 ANDROID_HOME=/home/yasir/Android/Sdk ./gradlew testDebugUnitTest --tests 'com.androdr.reporting.*' -q`
Expected: compile errors `No parameter with name 'ruleCampaigns'` / `Unresolved reference: ruleCampaigns`.

- [ ] **Step 5: Implement inputs** — `ReportInputs.kt`, add:

```kotlin
    /**
     * Each loaded rule's campaign keys (its `campaign.*` tags, aliases folded, unknown names dropped):
     * which campaign an unreadable-paths entry belongs to (#394). Reads a small file: off the main thread.
     */
    fun ruleCampaigns(): Map<String, Set<String>> {
        val campaigns = campaignRegistry.campaigns()
        val keyByName = HashMap<String, String>()
        campaigns.forEach { keyByName[it.key] = it.key }
        campaigns.forEach { c -> c.aliases.forEach { keyByName.putIfAbsent(it, c.key) } }
        return sigmaRuleEngine.getRules().associate { rule ->
            rule.id to rule.tags.filter { it.startsWith(CAMPAIGN_TAG) }
                .mapNotNull { keyByName[it.removePrefix(CAMPAIGN_TAG).lowercase()] }.toSet()
        }.filterValues { it.isNotEmpty() }
    }

    private companion object {
        const val CAMPAIGN_TAG = "campaign."
    }
```

- [ ] **Step 6: Implement verdicts and rows** — `CampaignVerdict.kt`:

  - `CampaignVerdict` gains `val coverage: List<ServiceStatus>? = null` (KDoc: "null = no `detected_by` for this campaign, or an import: render today's row; empty = patch level only").
  - `campaignVerdicts` gains a last parameter `ruleCampaigns: Map<String, Set<String>>`, and inside, after `val known = …`:

```kotlin
    val detectedByKey = campaigns.associate { it.key to it.detectedBy }
    fun coverageOf(key: String): List<ServiceStatus>? = if (!live) null
        else detectedByKey[key]?.let { campaignCoverage(it, key, scan.scannerErrors, ruleCampaigns) }
```

    and each `CampaignVerdict(...)` constructed in the `when` passes `coverage = coverageOf(key)` (compute once per row: `val coverage = coverageOf(key)` before the `when`).

  - Add the row text helpers (file-private):

```kotlin
private val SERVICE_WORDS = mapOf(
    "dns_monitor" to "DNS lookups", "app_scanner" to "installed apps", "file_scanner" to "files",
    "device_auditor" to "device settings", "process_monitor" to "running processes",
    "accessibility_audit" to "accessibility services", "receiver_audit" to "app receivers",
    "appops_audit" to "app permissions in use",
)
private fun words(service: String) = SERVICE_WORDS[service] ?: service

private const val FIX_DNS = "Turn on DNS monitoring, use the phone as usual, then scan again."
private const val FIX_FAILED = "Scan again; if it keeps failing, export the report and send it to us."
private const val FIX_LISTS = "Scan again in a few minutes."
private const val FIX_IMPORT = "Import one to check this."
private const val FIX_UPDATE = "Update the app."
private const val NO_INFECTION_CHECK = "no infection check exists for a live scan; patch level only"

/** One clause and its fix (or null) for a service that was not fully checked. */
private fun clause(s: ServiceStatus): Pair<String, String?> = when (s.coverage) {
    ServiceCoverage.BLIND -> when (s.reason) {
        BlindReason.DNS_OFF ->
            "${words(s.service)} not monitored (DNS monitoring was off; only lookups recorded earlier were checked)" to FIX_DNS
        BlindReason.UNKNOWN_SERVICE -> "${words(s.service)} not checked (this app version does not know that check)" to FIX_UPDATE
        BlindReason.CHECK_FAILED, null -> "${words(s.service)} not checked (that check failed on this scan)" to FIX_FAILED
    }
    ServiceCoverage.PARTLY_UNREADABLE -> "${words(s.service)} only partly checked (some paths could not be read)" to null
    ServiceCoverage.BUILT_IN_LISTS_ONLY ->
        "${words(s.service)} checked against the built-in list only (threat lists had not finished loading)" to FIX_LISTS
    ServiceCoverage.NEEDS_IMPORT -> "${words(s.service)} need a bug report or intrusion log" to FIX_IMPORT
    ServiceCoverage.CHECKED -> "" to null
}

/** The row's state text and its distinct fixes, in clause order. */
internal fun coverageSummary(coverage: List<ServiceStatus>): Pair<String, List<String>> {
    if (coverage.isEmpty()) return NO_INFECTION_CHECK to emptyList()
    val checked = coverage.filter { it.coverage == ServiceCoverage.CHECKED }
    if (checked.size == coverage.size) return "not detected" to emptyList()
    val missing = coverage.filter { it.coverage != ServiceCoverage.CHECKED }.map(::clause)
    val parts = buildList {
        if (checked.isNotEmpty()) add("no hit in ${checked.joinToString(" and ") { words(it.service) }}")
        addAll(missing.map { it.first })
    }
    return parts.joinToString("; ") to missing.mapNotNull { it.second }.distinct()
}

private fun StringBuilder.appendFixes(fixes: List<String>) {
    if (fixes.isNotEmpty()) appendLine("        ${fixes.joinToString(" ")}")
}
```

  - In `appendCampaignRows`, replace the EXPOSED and NOT_DETECTED branches:

```kotlin
            CampaignVerdict.State.EXPOSED -> {
                val summary = v.coverage?.let(::coverageSummary)
                val suffix = summary?.let { "; infection check: ${it.first}" }.orEmpty()
                appendLine("  [!!]  ${v.label}: EXPOSED -- ${v.detail} (unpatched; not evidence of infection)$suffix")
                v.earlierHit?.let { appendLine("       also an earlier hit -- $it (over 30 days before this scan)") }
                summary?.let { appendFixes(it.second) }
            }
            CampaignVerdict.State.NOT_DETECTED -> {
                val summary = v.coverage?.let(::coverageSummary)
                if (summary == null || summary.first == "not detected") {
                    appendLine("  [OK]  ${v.label}: not detected")
                } else {
                    appendLine("  [--]  ${v.label}: ${summary.first}")
                    appendFixes(summary.second)
                }
            }
```

  - Replace the scope-note line with:

```kotlin
    // Rows with their own coverage say what "not detected" covered; only legacy rows (no detected_by) need the note.
    if (live && verdicts.any { it.state == CampaignVerdict.State.NOT_DETECTED && it.coverage == null }) {
        appendLine("  \"not detected\" means none of the checks that ran in this scan matched.")
    }
```

- [ ] **Step 7: Wire the parameter through.**
  - `ReportFormatter.formatScanReport`: add `ruleCampaigns: Map<String, Set<String>>,` after `ruleCategoryById`, and pass it as the 5th argument of `campaignVerdicts(...)`.
  - `ReportExporter`: add `ruleCampaigns = reportInputs.ruleCampaigns(),` next to `ruleCategoryById = …`.
  - `HistoryViewModel.openSheet`: read it off the main thread next to `campaigns` — `val ruleCampaigns = withContext(Dispatchers.IO) { reportInputs.ruleCampaigns() }` — and pass `ruleCampaigns = ruleCampaigns`.

- [ ] **Step 8: Run the tests to verify they pass**

Run: `rm -rf app/build/test-results && JAVA_HOME=/home/yasir/.gradle/jdks/eclipse_adoptium-21-amd64-linux.2 ANDROID_HOME=/home/yasir/Android/Sdk ./gradlew testDebugUnitTest detekt lintDebug -q`
Expected: BUILD SUCCESSFUL; every unit test passes (count the XML: `python3 -c "import glob,xml.etree.ElementTree as E;t=f=0
for p in glob.glob('app/build/test-results/testDebugUnitTest/*.xml'):r=E.parse(p).getroot();t+=int(r.get('tests'));f+=int(r.get('failures'))+int(r.get('errors'))
print(t,f)"` → `f` = 0, and `CampaignCoverageTest`, `ServiceScannerMapCrossCheckTest`, `ReportInputsTest`, `MercenaryCheckReportTest` XML files present).

- [ ] **Step 9: Commit**

```bash
git add app/src/main/java/com/androdr/reporting app/src/main/java/com/androdr/ui/history/HistoryViewModel.kt app/src/test
git commit -m "feat(report): each campaign row says what was checked and how to fix gaps (#394)" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01B8H9x5KmTtY8Ejyi2eUdjH"
```

---

### Task A5: Adversary harness — baseline update and a DNS-off scenario

**Files:**
- Modify: `test-adversary/fixtures/expected/clean_device.patterns`, `test-adversary/test_check_patterns.py:115-133`, `test-adversary/manifest.yml` (after `detect_only_dns_wording`)
- Create: `test-adversary/fixtures/expected/campaign_rows_dns_off.patterns`

**Interfaces:**
- Consumes: the row strings from A4 (verbatim).
- Produces: nothing downstream.

- [ ] **Step 1: Failing test** — in `test_check_patterns.py`, change `CLEAN_DEVICE_REPORT`'s rows to the new rendering and add a DNS-off case:

```python
  [OK]  Cellebrite: not detected
  [OK]  Graphite (Paragon): not detected
  [--]  LANDFALL: no infection check exists for a live scan; patch level only
  [OK]  Massistant: not detected
  [OK]  Midnight Mimosa: not detected
  [OK]  Pegasus: not detected
  [OK]  Predator: not detected
"""
```

(the `"not detected" means …` line is removed), and append:

```python
DNS_OFF_REPORT = """  MERCENARY SPYWARE CHECK
  [--]  LANDFALL: no infection check exists for a live scan; patch level only
  [--]  Pegasus: DNS lookups not monitored (DNS monitoring was off; only lookups recorded earlier were checked)
        Turn on DNS monitoring, use the phone as usual, then scan again.
    Campaign detections: none
"""

DNS_OFF = Path(__file__).parent / "fixtures" / "expected" / "campaign_rows_dns_off.patterns"


def test_dns_off_scenario_accepts_the_dns_off_rows(tmp_path):
    report = tmp_path / "report.txt"
    report.write_text(DNS_OFF_REPORT)
    result = subprocess.run(["bash", str(SCRIPT), str(report), str(DNS_OFF)], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout


def test_dns_off_scenario_rejects_an_ok_pegasus_row(tmp_path):
    report = tmp_path / "report.txt"
    report.write_text(DNS_OFF_REPORT.replace(
        "  [--]  Pegasus: DNS lookups not monitored (DNS monitoring was off; only lookups recorded earlier were checked)",
        "  [OK]  Pegasus: not detected"))
    result = subprocess.run(["bash", str(SCRIPT), str(report), str(DNS_OFF)], capture_output=True, text=True)
    assert result.returncode == 1
```

- [ ] **Step 2: Run to verify it fails**

Run: `python3 -m pytest -q test-adversary/test_check_patterns.py`
Expected: `test_clean_device_baseline_accepts_a_clean_report` FAILS (baseline still requires the scope-note line); both DNS-off tests FAIL (`No patterns file`).

- [ ] **Step 3: Update the baseline** — in `clean_device.patterns` replace the line `"not detected" means none of the checks that ran in this scan matched.` with:

```
# Every row carries its own coverage (#394); LANDFALL has no live infection check.
[--]  LANDFALL: no infection check exists for a live scan; patch level only
```

- [ ] **Step 4: Add the scenario** — `campaign_rows_dns_off.patterns`:

```
# DNS monitoring OFF (#394): a DNS-only campaign must not read [OK]; the row says why and how to fix it.
# Precondition: stop the debug app's VPN before the scan.
MERCENARY SPYWARE CHECK
[--]  Pegasus: DNS lookups not monitored (DNS monitoring was off; only lookups recorded earlier were checked)
Turn on DNS monitoring, use the phone as usual, then scan again.
[--]  LANDFALL: no infection check exists for a live scan; patch level only
![OK]  Pegasus: not detected
!: DETECTED --
```

and in `manifest.yml`, after `detect_only_dns_wording`:

```yaml
  # ── 2026-10-17: per-campaign check state (#394) ─────────────────────────
  - id: campaign_rows_dns_off
    track: 5
    risk: none
    # Needs the VPN OFF (the opposite of the DNS scenarios): run it with --only after
    # stopping the debug VPN. Pegasus is DNS-only, so it cannot read [OK] with DNS off.
    description: "DNS monitoring off: DNS-only campaign rows say not monitored, with the fix"
    source: baseline
    tags: [android, baseline, report-wording]
    expected_patterns:
      - "[--]  Pegasus: DNS lookups not monitored (DNS monitoring was off; only lookups recorded earlier were checked)"
      - "Turn on DNS monitoring, use the phone as usual, then scan again."
      - "![OK]  Pegasus: not detected"
```

- [ ] **Step 5: Run to verify** — `python3 -m pytest -q test-adversary/`
Expected: all pass (selection tests included: the new id matches no profile glob except `full`).

- [ ] **Step 6: Commit**

```bash
git add test-adversary
git commit -m "test(harness): campaign rows carry coverage; DNS-off scenario (#394)" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01B8H9x5KmTtY8Ejyi2eUdjH"
```

---

### Task D: Delivery (safe ordering) and release note

**Files:** none new.

- [ ] **Step 1: Rules PR** — open a PR for `feat/394-detected-by` (body: what `detected_by` is, the derivation, the 7 values, "Do not merge before AndroDR #<n> build-and-test is green (safe ordering)"). Wait for its `validate` check to be green.
- [ ] **Step 2: AndroDR PR** — push `feat/394-campaign-check-state`, open a PR to `main` with `Closes #394`, the spec link, the five spec deviations above, and the row examples. Expect `submodule-check` and `ci-success` red (pinned to a branch); `build-and-test`, `lint-and-detekt`, `bundle-provenance` must be green.
- [ ] **Step 3:** After the owner approves both: merge the rules PR (update its branch first if rules main moved: `gh pr update-branch`), then in the AndroDR worktree `cd third-party/android-sigma-rules && git fetch -q origin main && git checkout -q origin/main && cd ../.. && git add third-party/android-sigma-rules && git commit -m "build: re-point android-sigma-rules at rules main"`, push, wait for full green including `ci-success`, merge.
- [ ] **Step 4: Release.** No app release is triggered by this. Before the next Play AAB the standing full battery runs (unit/detekt/lint, smoke on Pixel_9a + Medium_Phone_API_36.1 + Play_API_26, F916B clean install with VPN on AND off, adversary `--load` including `--only campaign_rows_dns_off` with the debug VPN stopped).

---

## Self-review (done while writing)

- **Spec coverage:** §1 → R1; §2 → A1; §3 → A2; §4 → A3; §5 → A4 Steps 1, 5, 7; §6 → A4 Steps 2, 6; residuals → unchanged behaviour, no task; tests list → R1, A1–A5; delivery → D. Spec "Tests" item "the validator rejects a missing/unsorted/duplicated/unknown-service detected_by" → R1 `test_detected_by_is_a_sorted_unique_list_of_taxonomy_services` (deviation 2).
- **Placeholders:** none; every code step carries code, every run step a command and expected result.
- **Type consistency:** `Campaign.detectedBy: List<String>?` (A1) → `detectedByKey` (A4); `campaignCoverage(detectedBy, campaignKey, scannerErrors, ruleCampaigns)` (A2) → A4 call; `DNS_SNAPSHOT_SCANNER` (A2) → A3; `ruleCampaigns: Map<String, Set<String>>` in ReportInputs, campaignVerdicts, formatScanReport, both callers and both test helpers.
- **Review Focus:** each of the 5 lines has its pinning test in A2 or A4.
- **Known residuals carried from the spec:** BUILT_IN_LISTS_ONLY is per service (closed for new scans by `missingSources`, owner addition in A2; scans saved before it keep the cautious reading); DNS switched on just before a scan counts as checked; History uses the current registry and rules.
