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
**display name** with its **web scope**: for a **genuine** mint the pipeline
derives the scope from the origin serving the web manifest, so an attacker
cannot mint a WebAPK scoped to `chase.com` without controlling content on
`chase.com`. A brand name over a non-brand scope is therefore a high-confidence
phishing signal. **This is an invariant of the minting service, not of the
rule** — see §7: a self-built APK can adopt the `org.chromium.webapk.` prefix
and self-declare a scope, forging both signals; that residual is caught only by
androdr-010 (medium REVIEW) and is a documented non-goal.

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
        app_name|ioc_lookup: brand_name_db
    store_installed:
        installer|ioc_lookup: trusted_installer_db
    filter_known_good:
        package_name|ioc_lookup: known_good_app_db
        installer|ioc_lookup: trusted_installer_db
    filter_webapk:
        package_name|startswith: "org.chromium.webapk."
    condition: selection and not store_installed and not filter_known_good and not filter_webapk
level: high          # guidance: UNINSTALL; category: incident / app_risk
status: experimental
```

Catches native fake-brand APKs (banker droppers) — the larger real-world
threat class. Design notes, corrected against repo policy during planning:

- **No judgment fields.** `from_trusted_store`, `is_sideloaded`, and
  `is_known_oem_app` are `kind: judgment`; the judgment-field allowlist is
  remove-only (#136 strangler-fig: "the emitter contract forbids new
  uses"). 093 therefore uses the Phase-2 idiom the validator itself
  recommends: `not (installer|ioc_lookup: trusted_installer_db)` — already
  registered on main. The OEM exemption folds into `filter_known_good`,
  whose Kotlin lambda already covers OEM prefixes.
- **No `implies_flags`.** Main's structural sideload-guarantee gate does
  not yet recognize the negated-lookup form (that recognition lives on the
  parked Phase-2 branch). Nothing is lost: any 093 hit co-fires
  androdr-010, which supplies the `sideloaded` flag.
- **Evasion-resistant exemption (the androdr-089 pattern).** The
  `filter_known_good` block conjoins the trusted-installer lookup, making
  the exemption deliberately unreachable for sideloads — an impersonation
  backstop, not a noise filter. Without it, a fake could adopt a known-good
  *package name* (free-form for sideloads, no signature binding in
  known_good_app_db per ADR #51) and be silently exempted. Consequence: a
  genuinely brand-published APK sideloaded from a mirror also fires — an
  accepted, documented FP (falsepositives wording follows
  authoring-lessons lesson 5). No `popular-apps.yml` additions are needed.
- `filter_webapk` (`package_name|startswith "org.chromium.webapk."`)
  excludes **all** WebAPK-prefixed packages, delegating them to androdr-092.
  092 already covers them comprehensively — it fires on a foreign/absent
  scope and exempts a genuine brand scope — so re-evaluating a WebAPK here
  adds no detection, only a redundant 092/093 double-fire (and a false
  positive on a genuine regional PWA whose domain is not yet in the
  registry). A scope conjunct was considered and rejected for exactly that
  reason: it buys nothing 092 doesn't already do and reintroduces the
  double-fire. The forge-both residual (prefix + genuine brand scope) is
  092's documented boundary, caught only at androdr-010 (§7).
- When the parked #136 Phase-2 branch lands it needs no sweep of 093 (093
  is already in the target idiom), only a rebase over the added files.

## 3. Emitter and schema

**AppScanner (AndroDR):** in `buildTelemetryForPackage`, for packages with
prefix `org.chromium.webapk.` only, perform a targeted
`pm.getApplicationInfo(packageName, GET_META_DATA)` (helper `extractWebApkScope`)
and read the application-level meta-data key
`org.chromium.webapk.shell_apk.scope` (verified present on a real minted WebAPK
via aapt2). Targeted read, not a `GET_META_DATA` flag on the bulk
`getInstalledPackages` call — the bulk query already contends with Binder size
limits, and only the prefixed packages can satisfy 092's selection. Read
failure → null (rule then fires on brand-named WebAPKs, per §2 null semantics —
fail-suspicious is intended for this prefix). The value is
**attacker-controlled** (any app may adopt the prefix and self-declare it), so
before it leaves the emitter it is stripped of control characters and capped at
2048 chars — it flows into findings, `matchContext`, and the line-oriented
report export, where an un-capped/newline value would forge report lines or
exhaust memory. One new `AppTelemetry` field `webapkScope` (nullable string),
mapped as `webapk_scope` in `AppTelemetry.toFieldMap()` — the member function
is the app_scanner field map (`TelemetryFieldMaps.kt` holds only the plan-6
bugreport services; `LogsourceTaxonomyCrossCheckTest` compares the taxonomy
against a live `AppTelemetry` instance's map keys). (`webapk_start_url` was
considered but dropped: no rule consumes it, and an unused attacker-controlled
field is only surface.)

**Rules repo:** `validation/logsource-taxonomy.yml` gains `webapk_scope` under
`app_scanner` as a nullable raw_fact (taxonomy edits follow the safe-ordering,
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

**Feed-file shape (resolved during planning): structural, no `entries:`
key** — the `known-oem-prefixes.yml` pattern (`version`/`description`/
`sources` + a `brands:` map). This takes the documented early-return path in
`validate-ioc-data.py` and `IocDataSchemaCrossCheckTest`, so
`ioc-entry-schema.json` needs no extension and `allowed-sources.json` no new
source id. The one mandatory tooling change: both filenames must be added to
`IOC_TYPE_BY_FILENAME` in `validate-ioc-complementarity.py`, whose `--all`
sweep otherwise hard-fails (exit 2) on every push.

**On-device delivery/storage: a self-contained `BrandImpersonationResolver`
on the `OemPrefixResolver` model** — bundled res/raw byte-copies
(`brand_names.yml`, `brand_domains.yml`) for cold start, direct remote
refresh of the two ioc-data URLs on the 12h cycle, in-memory
`AtomicReference` state. No Room migration, no `PublicRepoIocFeed` changes.
Mirror parity is gated by extending `OemPrefixMirrorParityTest`.

**Suppression-channel hardening.** `brand_domain_db` is the fleet's first
remote input that *suppresses* a finding (092's `not scope_legit`), and
ioc-data is not covered by `rules.sha256`. So the resolver follows
OemPrefixResolver's *validation* model, not just its delivery model:
`buildMatcher` **rejects the whole fetch** (keeping previous state) if any
name variant is < 2 chars, any domain lacks a dot or is a bare public suffix
(a `PUBLIC_SUFFIX_DENYLIST`), or either list exceeds its cap — never a silent
truncate. The same bounds are enforced at CI by a structural validator added
to `validate-ioc-data.py` for `brand-names.yml`/`brand-domains.yml` (they
previously took the entries-less pass-through), with the denylist kept in
lockstep with the Kotlin one. `BrandRegistrySeedTest` additionally proves the
*shipped* seeds parse to a non-empty matcher and that the two files' brand
keys agree — closing the silent-content-loss (#203) class the byte-parity
gate can't see.

**Name matching robustness.** Labels and variants are NFKC-normalised with
default-ignorable format characters (zero-width space/joiner, soft hyphen,
RTL/LTR overrides) stripped before matching, and case folding uses `(?iu)`
(Unicode-aware; `RegexOption.IGNORE_CASE` alone is ASCII-only on the JVM).
This closes the pixel-identical zero-width interior-insertion evasion
("Pay​Pal") without entering the homoglyph/confusables rabbit hole (§7).

## 4. Seed data (per-candidate HitL before any commit)

23 **financial/payment** brands (HitL-approved), global majors plus the
documented-abuse geography (PKO Bank Polski, mBank) and the current tester
geography (Portugal: MB WAY, Millennium BCP, Caixadirecta). Each brand
contributes: name variants to `brand-names.yml` (distinctive only —
multi-token or unambiguous single tokens; ambiguous dictionary words banned,
accepting the coverage loss on brands whose real label IS an ambiguous word)
and its **complete** official domain list across every region the name
variants cover to `brand-domains.yml` — an incomplete list is a guaranteed
092 FP on the genuine regional app. No `popular-apps.yml` additions (see §2 —
the 093 exemption is deliberately unreachable for sideloads). Curation policy
recorded in each file's header. Expansion (social, crypto, mail providers)
is follow-up work via the pipeline, not this change.

## 5. Fleet compatibility and delivery

Whole public fleet ≥ vc610 (R1 fail-closed evaluator). Both rules reference
unregistered-lookup names on every fielded binary, so `unevaluableRules`
skips them whole — **shipping the rules to the feed immediately is safe**;
they activate per-device as the next release (617+) rolls out. No coverage
hole meanwhile: androdr-010 keeps flagging non-Play WebAPKs as reviewable
sideloads. No R1 capability-gap violation (nothing negates a
boolean that old binaries emit differently; old binaries simply skip).

**Pre-R1 straggler safety (legacy closed-track testers may still run 606,
which resolves unknown lookups to matcher-false instead of skipping):** both
rules are still safe there, because each rule's *positively required*
selection contains a new-lookup conjunct (`app_name|ioc_lookup:
brand_name_db`) that resolves false — the negated lookups can never
over-fire through an AND with false. This analysis goes in the rules-PR body
to discharge the CAPABILITY CONSTRAINT header in
`ioc-lookup-definitions.yml`.

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
  sideloaded fake-brand native app fires; store-installed clean; system app
  clean; WebAPK excluded (no double-fire with 092); genuine brand package
  sideloaded **still fires** (asserting the backstop is unreachable — the
  deliberate design choice, not a bug).
- **Cross-check gates:** the existing schema/taxonomy/lookup drift tests
  plus `RuleManifestIntegrityTest` cover the wiring; rules-repo `validate`
  must be green.
- **On-device (Fold 2):** verify the excalidraw/squoosh WebAPKs emit their
  scope and produce no 092/093 findings. No live positive case is built
  (a phishing-shaped test PWA will not be created); positives are covered
  by unit tests.

## 7. Non-goals

- **Closing the forge-both WebAPK residual.** A self-built APK that adopts
  the `org.chromium.webapk.` prefix *and* self-declares a scope on the
  brand's genuine domain evades both 092 and 093. This is the irreducible
  WebAPK-identity gap (per-app leaf certs, unmeasurable/forgeable installer —
  the #311/#296 wall). It is **not a regression** (androdr-010 still surfaces
  it as a medium REVIEW sideload) and is recorded as a deliberate boundary in
  both rules' text and pinned by a test, not treated as impossible. The
  scope-conjoined `filter_webapk` (§2) collapses the two evasion levers to
  this single one and catches the lazy prefix-adopter.
- Homoglyph/confusable-name detection, and Unicode confusables generally
  (rabbit hole; the zero-width/default-ignorable class IS handled, §3).
- Per-brand name↔domain pairing (a subdomain takeover on one listed brand's
  domain currently exempts *any* brand name; the flat-set design is sound for
  the apex per §2 but overstated for `*.brand.com`). Deferred — it needs the
  evaluator's `(fieldValue) -> Boolean` lookup signature widened to carry the
  full record. Tracked as a follow-up.
- Non-financial brand categories in the seed (pipeline follow-up).
- Any new evidence_type/UI machinery.
- Emitting all signer certs / CA-anchored WebAPK trust (dead end — a real
  malicious WebAPK carries the real Google cert; see
  project_webapk_no_exemption memory and #311).
