# Pure-Emitter Contract & Safe Capability Delivery — Design (#136 end state)

**Goal:** Make the telemetry emitter raw-facts-only — delete the emitted judgment
booleans (`from_trusted_store` first; `is_sideloaded` / `is_known_oem_app` in later
phases) — and make that end state *reachable safely* by fixing the evaluator's
failure mode for capability-dependent rules, then enforcing the contract with
static checks so it cannot regress.

**Why now / background:** The #136 Phase-2 rule migration (rules off
`from_trusted_store` onto `installer|ioc_lookup: trusted_installer_db`) was built
and ceremony-reviewed in Aug 2026, then **deliberately pulled back**: the shared
rules feed (`android-sigma-rules` main, 12h fetch, rule-ID replacement) serves
every installed app version, and a binary that lacks a lookup registration
resolves the matcher to `false` (`SigmaRuleEvaluator.kt:283`,
`iocLookups[lookupName] ?: return false`). Under a negated selection
(`... and not store_installed`) that **inverts the sideload gate → the rule
fires on every app**, including androdr-017 CRITICAL "Stalkerware Pattern" on
genuine Play installs. The migration content survives on the local
`worktree-phase2-from-trusted-store` branch (AndroDR commits `3efdeb7..86146db`,
submodule commit `b28914e`) and is resurrected in Step 2 below.

**Fleet assumption (decision input):** the install base is a closed testing
audience; the user accepts a **short window of rule inconsistency** during
rollout — provided the inconsistency is benign under-detection, never
false-positive over-firing.

**Non-goals:**
- Redesigning the `filter_known_good` / trusted-store filter family (#249 + #270
  interplay) — separate design.
- Designing the replacement lookups for `is_sideloaded` / `is_known_oem_app`
  (their phases are sequenced here but specced later).
- Capability negotiation / per-binary feed versioning — unnecessary for a closed
  fleet; the fail-closed evaluator makes it redundant at this scale.
- Migrating to a different static-analysis framework.

---

## Workstream A — Fail-closed evaluator (ships in R1)

**Semantics.** Before evaluating a rule against a record, collect every
`ioc_lookup` matcher in the rule's detection (selections and filters alike). If
any such matcher's name is absent from the injected `iocLookups` map — **or the
matcher names no lookup at all** (`installer|ioc_lookup:` with a missing/blank
value, which the parser yields as an empty value list) — **skip the entire
rule**: no matchers evaluated, no finding emitted, positive or negative. A
binary that lacks a rule's vocabulary must not guess — today's matcher-level
`false` silently mis-evaluates (inverts under negation; defeats exemptions when
the unresolved matcher sits in a filter). Skipping only the matcher is therefore
not acceptable; the unit of skip is the rule.

**Placement.** A per-rule pre-scan in `SigmaRuleEvaluator.evaluate()` (no cache:
the lookup registry can change between scans and the pre-scan cost is trivial).
No parser, schema, or rule-format change. Rules referencing no lookups are
untouched; registered lookups behave byte-identically to today. The engine
exposes a no-arg `SigmaRuleEngine.unevaluableRules()` reading the same internal
lookup registry `evaluate()` uses — reporting and skipping share one input by
construction.

**Observability & consumer correctness.** A skip is *accepted under-detection*,
not a scanner failure, and must read that way everywhere:
- Each skipped rule surfaces once per scan as a `ScannerFailure` with a
  dedicated kind (`exception = UNREGISTERED_IOC_LOOKUP`), message
  `rule <id> not evaluated on this build: unregistered ioc_lookup '<name>'`.
- These entries are **excluded from `isPartialScan`** (no red partial-scan
  alarm for an accepted condition) and rendered by `ReportFormatter` as their
  own "rules not evaluated on this build" section — which is what makes the
  gap diagnosable from the report.
- Skipped rule ids are **excluded from `resolvedFindings`** (a skipped CRITICAL
  must never render as "resolved" — affirmative false reassurance) and from
  `computeAtomBindings` (the atom-binding path evaluates only the category
  matcher and would otherwise bypass the pre-scan).
- Both Finding-producing entry points are wired: the full scan and
  `analyzeBugReport`.

## Workstream B — Guardrails (ship in R1; rules-repo lints ship alongside)

**B1. `Finding(...)` construction allowlist (#136 check 1).** A source-scanning
unit test (repo's existing cross-check-test convention; no custom detekt module)
fails the build when `Finding(` is constructed — or its `level` mutated via
`.copy(level = …)` — outside `SigmaRuleEvaluator.kt` (the single production
construction site; `SigmaRuleEngine` only delegates and `SigmaCorrelationEngine`
emits `ForensicTimelineEvent`, so neither earns an allowlist entry) or test
sources. Explicit path allowlist.

**B2. Telemetry emitters declare no severity (#136 check 2).** A source-scan
test over the full emitter surface — every type declaring `toFieldMap()`
(`com.androdr.data.model` types incl. `DnsEvent`, plus the extension emitters in
`sigma/TelemetryFieldMaps.kt`) — asserts none declares a `severity`/`level`/
`priority` property **or emits such a key from `toFieldMap()`**. The emitter
file set is equality-asserted so a new emitter fails loudly and gets classified.

**B3. Per-category severity caps, one source (#136 check 3).** New
`validation/severity-caps.yml` in `android-sigma-rules` codifies the established
policy (`device_posture: medium`; categories absent from the file are uncapped).
Consumed by (a) `validate-rule.py` at rules-repo PR time and (b) an AndroDR
build-time test against the pinned submodule — the same dual-gate pattern as the
taxonomy (#268). Taxonomy-file changes follow CLAUDE.md safe-ordering.

**B4. Raw-facts field contract.** **Every** field in `logsource-taxonomy.yml`
declares `kind: raw_fact | judgment` — completeness is enforced (an unlabeled
field is a CI failure in both repos; "absent = raw_fact" defaults are forbidden,
else a new judgment field passes by staying unlabeled). *Raw fact* = read
directly from OS APIs without policy interpretation (e.g. `installer`,
`is_system_app` from FLAG_SYSTEM); *judgment* = computed by applying a
trust/allowlist policy. The frozen judgment set is **data, not test code**: the
top-level keys of `judgment-field-allowlist.yml` (expected:
`from_trusted_store`, `is_sideloaded`, `is_known_oem_app`); both validators
assert taxonomy-marked == allowlist keys, so Phase 3 shrinks the set with a
rules-repo-only edit.

**B5. Rule-side deprecation lint + #275 port — dual-gated.** `validate-rule.py`
fails any rule whose detection references a judgment-kind field unless its id is
allowlisted, with **separate `delivered` and `staging` id lists** (staging twins
share ids with delivered rules and must never shield them). On the AndroDR side,
`DetectionFieldCrossCheckTest` — which already walks res/raw and every
`rules.txt` rule in the pinned submodule — gains the same check against the
`delivered` list, so neither guard can silently become the only one (#268
doctrine). Phase 2 empties `from_trusted_store.delivered`; the lint then
permanently blocks reintroduction. The same pass ports the `ioc_lookup`-name
registry cross-check (#275): every `|ioc_lookup:` value in any rule must be a
non-blank registered name in `ioc-lookup-definitions.yml` (a missing/blank name
is rejected too — it is unresolvable by construction).

## Workstream C — Delivery sequence (three independently-safe gated steps)

1. **R1 safety release (app):** Workstreams A + B in one AndroDR release to the
   closed-testing fleet. No rule content changes. From R1 onward, any capability
   gap on any future rule = skip + logged, never over-fire.
2. **Phase 2 go-live (rules):** resurrect the reviewed migration from the local
   branch (re-validate against R1: full gate + the Phase-2 equivalence tests),
   then standard safe-ordering gated go-live (rules branch → CI-green AndroDR PR
   with branch-pinned submodule → user-gated merge to rules main → re-point).
   Stragglers still pre-R1 under-detect the migrated sideload rules until they
   update — the accepted window. Go-live remains user-gated.
3. **Phase 3 (emitter deletion):** with no delivered rule referencing
   `from_trusted_store`: delete the field from `AppTelemetry.toFieldMap()` and
   its computation in `AppScanner`; mark/remove it in the taxonomy; migrate the
   two staging rules; empty its B5 allowlist entries. Later phases repeat the
   same recipe for `is_sideloaded` then `is_known_oem_app`, each with its own
   lookup design and its own spec.

Each step is its own PR and gate; no step's safety depends on a later step.

## Error-handling posture (single table)

| Condition | Behavior | Surface |
|---|---|---|
| Rule references unregistered `ioc_lookup` (on-device) | Skip whole rule | capability-skip entries: report section; excluded from `isPartialScan`, `resolvedFindings`, atom bindings |
| `ioc_lookup` matcher with missing/blank name (on-device) | Skip whole rule (fail-closed, never matcher-false) | same as above |
| New rule uses judgment-kind field (PR time) | CI failure | `validate-rule.py` + AndroDR `DetectionFieldCrossCheckTest` |
| New judgment-kind field added to taxonomy / unlabeled field | CI failure | both repos (B4) |
| Rule severity exceeds category cap | CI failure | both repos (B3, `severityOrder` rank-clamp mirrored) |
| `Finding(...)` constructed or `.copy(level=)` outside evaluator | Build failure | AndroDR test (B1) |
| Telemetry emitter declares/emits severity | Build failure | AndroDR test (B2) |

No path resolves a capability or contract gap into a silently wrong detection
verdict — nor into false reassurance (a skip never renders as "resolved").

**Recorded residuals (Phase-2 preconditions, not R1 scope):**

- **(a) R1→Phase-2 window — expressed as versionCode floors.** No delivered
  rule may reference any `ioc_lookup` name until the fleet is uniformly at or
  above the floor: pre-R1 binaries resolve an unknown name to matcher-false and
  therefore OVER-FIRE under negation. Two capabilities are needed and, as
  built, they collapse into one floor:
  - the `trusted_installer_db` registration (`a3d2e15`, #286) — verified
    2026-08-14 to be in **no release tag** (`git tag --contains a3d2e15` is
    empty; `v0.9.0.605` is `4c2c3cc`/#281, which predates the registration, and
    606/607 are #282/#283). So there is no shipped floor for the registration
    alone.
  - fail-closed evaluation (this R1 branch), which is strictly newer.
  ⇒ **The binding floor is R1's own release versionCode** (`versionName =
  0.9.0.$versionCode`), to be pinned here at release. Until then Phase-2
  go-live has no numeric precondition to check against.
- **(b) `OemPrefixResolver` empty-data door — the ONE hard Phase-2 blocker R1
  does NOT mitigate.** Every other residual here is either a timing window or
  pre-existing; this one is a live over-fire path *through* the fail-closed
  design: the lookup IS registered, so `unevaluableRules()` sees nothing wrong,
  yet with an empty parsed OEM feed `trusted_installer_db` returns false for
  every installer — post-migration, `condition: … and not store_installed`
  fires on every app on the device.
  Corrected remedy (the original "don't register a lookup whose backing set is
  empty" wording cannot express the timing — registration happens once per
  process at `initRuleEngine()`, while the feed refreshes on the 12h
  `IocUpdateWorker` cycle, so a set that is non-empty at registration can be
  empty later and vice versa): either
  (i) give each lookup an **availability predicate** consulted by
  `unevaluableRules()` at evaluation time, so an empty backing set makes the
  rule *skip* on that scan exactly as an unregistered name would, or
  (ii) move registration to **per-scan** (re-register at the top of each scan
  from the then-current feed state), which reduces the window to one scan but
  does not close it.
  (i) is the fail-closed-consistent option; (ii) is a stopgap.
- **(c) Feed fragility (pre-existing, separate issue):** one unparseable remote
  rule aborts the whole fetch loop, silently dropping all later rules in
  `rules.txt` order.
- **(d) Skip-set purity — DONE (implemented in the R1 final-review wave,
  2026-08-14; supersedes the earlier "ship R1 as-is" ruling).**
  `ScannerFailure` now carries a structured `ruleId`, `recordRuleCapabilitySkips`
  populates it, and `computeDiff(newer, older)` derives its skip set from
  `newer`'s own persisted capability-skip entries — no live-engine read, no
  Room migration (the column is kotlinx-serialized JSON TEXT; old rows decode
  with `ruleId = null`). The function is now pure in its two arguments, so a
  cold-start History diff is identical to a mid-session one. Residual compat
  limit: capability-skip rows written by a pre-wave binary carry no `ruleId` and
  contribute nothing to the skip set.

## Testing

- **Evaluator (A):** unregistered lookup in a negated selection → rule skipped,
  zero findings — a permanent regression test using the migrated androdr-010
  detection shape (verbatim from the parked Phase-2 branch; the bundled file is
  not yet migrated) with empty `iocLookups`; nameless `installer|ioc_lookup:`
  matcher → skipped even with all names registered; unregistered lookup in a
  filter → rule skipped (exemption never silently defeated); registered lookup →
  identical behavior to today (existing suite stays green except tests that
  asserted the old matcher-false behavior); no-lookup rules unaffected; one
  capability-skip entry per skipped rule per scan, excluded from
  `isPartialScan`, rendered by `ReportFormatter`, excluded from
  `resolvedFindings` and atom bindings.
- **Guardrails (B):** every lint/test lands with a red-case fixture (rules repo:
  fixture files under `validation/`; AndroDR: synthetic-doc unit tests in the
  `BundledRulesSchemaCrossCheckTest` style). B3/B4 dual-consumer tests verify
  both repos reject the same bad input.
- **On-device UAT (C):** after Phase-2 go-live on an R1 device, re-run the #284
  installer A/B test (same surveillance fixture; `samsungapps` → exempt,
  `scloud` → androdr-010/011/068 fire) proving migrated rules behave identically
  under the lookup; if a pre-R1 build remains installed anywhere, verify the
  capability gap manifests as skip + `scannerErrors`, not findings.

## Related

- #136 (this closes it at Phase 3 of the boolean family), #275 (closed by B5),
  #84 (parent architecture), #268 (taxonomy trust-root pattern), #249/#270
  (filter-family redesign — interacts with B5's allowlist but designed
  separately).
