# WebAPK Brand-Impersonation Detection (#299) — Design

**Date:** 2026-08-20
**Issue:** #299 (WebAPK display-name/brand impersonation coverage gap)
**Approved approach:** scope-anchored WebAPK rule + companion general-sideload rule
(user-selected over feed-only name matching and over a layered stopgap).

## 1. Problem

After #313 removed the androdr-010 WebAPK exemption, every non-Play WebAPK
surfaces as a medium "Sideloaded Application" (REVIEW). That restores baseline
visibility but stays undifferentiated: a phishing PWA labelled "Chase Bank"
produces the same finding as a benign recipe PWA. The impersonation rules
cannot sharpen it — androdr-014 and androdr-077 are package-name-keyed and can
never match a randomized `org.chromium.webapk.<hash>` package; androdr-016
matches only system-sounding names. Google's WebAPK minting service is
unauthenticated (documented in-the-wild abuse: PKO Bank Polski credential
phishing shipped as a minted WebAPK), so "Google-signed WebAPK" says nothing
about intent.

The detection anchor with real adversarial cost is the pairing of the app's
**display name** with its **web scope**: the minting pipeline derives the scope
from the origin serving the web manifest, so an attacker cannot mint a WebAPK
scoped to `chase.com` without controlling content on `chase.com`. A brand name
over a non-brand scope is therefore a high-confidence phishing signal.

## 2. Detection rules

### androdr-092 — WebAPK impersonating a protected brand (the #299 rule)

```yaml
detection:
    selection:
        package_name|startswith: 'org.chromium.webapk.'
        app_name|ioc_lookup: brand_name_db
    scope_legit:
        webapk_scope|ioc_lookup: brand_domain_db
    condition: selection and not scope_legit
level: high          # guidance: UNINSTALL; category: incident / app_risk
status: experimental
```

Deliberate properties:

- **No installer/trust conjunct.** A phishing WebAPK delivered through the
  Play install path must still fire. Cert/installer trust gates only the
  "installed from untrusted source" claim (the #296 lesson), never behavior.
- **Null scope fires.** Every genuinely minted WebAPK carries the scope
  meta-data; a brand-named `org.chromium.webapk.*` package with the key
  stripped is itself suspicious, and the evaluator's null semantics
  (`SigmaRuleEvaluator` IOC_LOOKUP branch: `fieldValue?.let { lookup(it) }
  ?: false`) make the `scope_legit` filter evaluate false on null — verified
  against main, no evaluator change needed.
- **No `implies_flags: sideloaded`.** Firing is orthogonal to install path;
  a Play-installed WebAPK triggering this must not imply a sideload.
- **Evidence via template vars.** `buildFinding` already exposes scalar
  record fields to title/remediation templates, so the remediation line
  interpolates `{webapk_scope}` ("…points at {webapk_scope}, which is not
  the brand's official site"). `evidence_type: none`; no UI machinery
  changes. The record fields also land in `matchContext` automatically.
  (Null scope renders as an empty string in the template — rare and
  acceptable; wording must read sensibly with it blank.)

### androdr-093 — Sideloaded app impersonating a protected brand (companion)

```yaml
detection:
    selection:
        is_system_app: false
        is_known_oem_app: false
        from_trusted_store: false
        app_name|ioc_lookup: brand_name_db
    filter_known_good:
        package_name|ioc_lookup: known_good_app_db
    filter_webapk:
        package_name|startswith: 'org.chromium.webapk.'
    condition: selection and not filter_known_good and not filter_webapk
level: high          # guidance: UNINSTALL; category: incident / app_risk
status: experimental
implies_flags: [sideloaded]
```

Catches native fake-brand APKs (banker droppers) — the larger real-world
threat class. `filter_webapk` keeps WebAPKs exclusively androdr-092's domain:
without it, a *genuine* brand PWA browser-installed on API 36+ (installer ≠
vending → `from_trusted_store: false`) would fire 093 at high severity — the
exact FP class 092's scope check exists to prevent. Genuine brand apps
sideloaded from mirrors are exempted per-package via `known_good_app_db`, so
each seeded brand's official package(s) must be present in
`popular-apps.yml` (see §4).

Uses main's current `from_trusted_store` vocabulary. The parked #136 Phase-2
branch migrates that idiom to `installer|ioc_lookup: trusted_installer_db`
fleet-wide; when Phase 2 lands it must sweep 093 too (rebase note for the
parked branch).

## 3. Emitter and schema

**AppScanner (AndroDR):** in `buildTelemetryForPackage`, for packages with
prefix `org.chromium.webapk.` only, perform a targeted
`pm.getApplicationInfo(packageName, GET_META_DATA)` and read application-level
meta-data keys `org.chromium.webapk.shell_apk.scope` and
`org.chromium.webapk.shell_apk.startUrl` (both verified present on a real
minted WebAPK via aapt2). Targeted read, not a `GET_META_DATA` flag on the
bulk `getInstalledPackages` call — the bulk query already contends with Binder
size limits, and only the prefixed packages can satisfy 092's selection.
Read failure → nulls (rule then fires on brand-named WebAPKs, per §2 null
semantics — fail-suspicious is intended for this prefix). New `AppTelemetry`
fields `webapkScope`, `webapkStartUrl` (nullable strings), mapped in
`TelemetryFieldMaps.toFieldMap()` as `webapk_scope` / `webapk_start_url`.

**Rules repo:** `validation/logsource-taxonomy.yml` gains both fields under
`app_scanner` as nullable raw_facts (taxonomy edits follow the safe-ordering,
per CLAUDE.md). `validation/rule-schema.json` untouched unless it enumerates
fields (cross-check tests will say). Existing gates enforce agreement:
`LogsourceTaxonomyCrossCheckTest`, `DetectionFieldCrossCheckTest`,
`BundledRulesSchemaCrossCheckTest`.

**New lookup DBs** in `validation/ioc-lookup-definitions.yml`, registered in
`ScanOrchestrator.initRuleEngine()` (gated by
`IocLookupDefinitionsCrossCheckTest`):

- `brand_name_db` — type `BRAND_NAME`, files `[ioc-data/brand-names.yml]`.
  Matcher: **word-boundary, case-insensitive** containment — a variant
  matches when it occurs in the label with a non-alphanumeric character or
  string edge on both sides of the occurrence (so "Chase Bank" matches
  "Chase Bank Login", while a variant can never match inside a word —
  "Purchase Tracker" matches nothing). Curation, not the matcher, bans
  ambiguous single tokens like "chase". New matcher code in the IOC lookup
  layer.
- `brand_domain_db` — type `BRAND_DOMAIN`, files
  `[ioc-data/brand-domains.yml]`. Matcher: parse the host from the scope
  URL; match if host equals a listed domain or ends with `"." + domain`
  (same suffix semantics as DNS C2 matching). Non-parseable scope → no
  match (fires — consistent with null handling).

Independent membership (names and domains in two flat lists, no pairing) is
sound because scope is origin-bound at minting: the unreachable exempt path
would require name = brand A while scope = brand B's real domain, i.e. the
attacker controls a listed brand's origin — game over regardless.

`ioc-entry-schema.json` and `validate-ioc-data.py` likely need the two new
file shapes/categories admitted; the complementarity validator must not choke
on them (implementation checkpoint — memory notes it silently skips
`parser_limited` feeds).

## 4. Seed data (per-candidate HitL before any commit)

~15–25 **financial/payment** brands (the documented phishing-WebAPK class),
global majors plus the documented-abuse geography (PKO Bank Polski). Each
brand contributes: name variants to `brand-names.yml` (distinctive only —
multi-token or unambiguous single tokens; ambiguous English words banned),
official domains to `brand-domains.yml` (the ecosystem's app-serving
domains), and its official Android package(s) to `popular-apps.yml` for 093's
known-good exemption. Curation policy recorded in each file's header.
Expansion (social, crypto, mail providers) is follow-up work via the
pipeline, not this change.

## 5. Fleet compatibility and delivery

Whole public fleet ≥ vc610 (R1 fail-closed evaluator). Both rules reference
unregistered-lookup names on every fielded binary, so `unevaluableRules`
skips them whole — **shipping the rules to the feed immediately is safe**;
they activate per-device as the next release (617+) rolls out. No coverage
hole meanwhile: androdr-010 keeps flagging non-Play WebAPKs as reviewable
sideloads. No R1 capability-gap violation (nothing negates a
boolean that old binaries emit differently; old binaries simply skip).

Standard safe-ordering: rules-repo branch (taxonomy + lookup defs + ioc-data
+ 2 rules + `rules.sha256` regen) → AndroDR PR (submodule bump + Kotlin:
emitter fields, matchers, lookup registration, bundled rules + parity) →
AndroDR CI green → merge rules branch to main → re-point submodule → merge
AndroDR PR.

## 6. Testing

- **Matcher units:** BRAND_NAME word-boundary behavior (case-insensitivity;
  multi-token variant inside longer label; substring near-miss "Purchase
  Tracker" vs "chase"-like token; unicode-case label), BRAND_DOMAIN
  host-suffix (exact host, subdomain, unrelated suffix like
  `notchase.com` NOT matching `chase.com`, non-URL scope, null).
- **Rule tests (anti-vacuity discipline — every gate field pinned both
  ways):** 092: fake-brand WebAPK with evil scope fires; genuine brand PWA
  (scope = official domain) does not; Play-installed fake **still** fires
  (pin `from_trusted_store` true and false to prove independence);
  null-scope brand-named WebAPK fires; non-brand WebAPK clean. 093:
  sideloaded fake-brand native app fires; genuine package exempt via
  known_good; store-installed clean; WebAPK excluded (no double-fire with
  092).
- **Cross-check gates:** the existing schema/taxonomy/lookup drift tests
  plus `RuleManifestIntegrityTest` cover the wiring; rules-repo `validate`
  must be green.
- **On-device (Fold 2):** verify the excalidraw/squoosh WebAPKs emit their
  scope and produce no 092/093 findings. No live positive case is built
  (a phishing-shaped test PWA will not be created); positives are covered
  by unit tests.

## 7. Non-goals

- Homoglyph/confusable-name detection (rabbit hole; revisit with evidence).
- Non-financial brand categories in the seed (pipeline follow-up).
- Any new evidence_type/UI machinery.
- Emitting all signer certs / CA-anchored WebAPK trust (dead end — a real
  malicious WebAPK carries the real Google cert; see
  project_webapk_no_exemption memory and #311).
