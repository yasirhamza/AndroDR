# Spec: Tier 1 cellular telemetry — `cellular_monitor` (personal-first v1)

**Status: DESIGN APPROVED IN BRAINSTORM (2026-08-22) — AWAITING SPEC REVIEW.**
No implementation is authorized by this document. It has not been through the
four-agent review ceremony and no issue has been filed. The next step after
maintainer review of this spec is an implementation plan (writing-plans), then
the review ceremony scaled to the change size. Per
`docs/AI-PIPELINE-CONVENTIONS.md` ("No speculative edits"), nothing here may be
built until that sequence completes.

**Supersedes the "Proposal" framing of**
[`2026-08-22-tier1-cellular-telemetry-product-note.md`](2026-08-22-tier1-cellular-telemetry-product-note.md),
which remains the record of the original unapproved idea capture and the
empirical evidence behind it. This document resolves three of that note's open
questions by decision (audience, v1 rule scope, emitter architecture) and
carries the rest forward.

**Decisions taken in brainstorm** (maintainer, 2026-08-22):

| Question | Decision |
|---|---|
| Audience / delivery | **Dogfood / personal-first.** Not a fleet feature in v1. |
| v1 rule scope | **Zero/tiny-reference core**: H1, H2, H4, H6, H7. H3 + H5 deferred. |
| Emitter architecture | **Event-driven (`TelephonyCallback`), hybrid-ready.** |
| Advanced Protection angle | **Out of scope for v1**, recorded below as future work. |
| Code location | **Isolated git worktree on a branch never intended for merge to `main`** (revised 2026-08-22; supersedes an earlier `src/debug/` source-set proposal — see §3). |
| CI coverage | **All stages must run**, via a permanent draft PR used as a CI vehicle (§9a). `workflow_dispatch` alone is insufficient — it never reaches the instrumented tests. |

---

## 1. Goal and non-goals

**Goal.** Give AndroDR a radio-layer observation plane it does not have today,
sufficient to flag candidate IMSI-catcher / fake-base-station / cellular-downgrade
conditions using **only public Android telephony APIs** — no root, no custom
firmware, no Qualcomm DIAG. Validate it against ground truth during field travel
before any fleet conversation begins.

**Non-goals.**

- **Not a fleet feature.** v1 ships disabled-by-construction for every user but
  the maintainer (see §3).
- **No root / DIAG / custom firmware.** That is the separate travel-honeypot
  project's Tier 2. If a heuristic turns out to require privileged baseband
  access, it is out of scope — not a reason to expand scope.
- **No H3 (EARFCN band-plan) or H5 (OpenCelliD unknown-cell-tuple).** Both need
  reference datasets whose size, licensing, and update cadence are unresolved.
- **No Play Data Safety change, and no `ACCESS_FINE_LOCATION` on `main`.**
  Guaranteed by branch isolation (§3), not by a runtime flag that could regress.
- **Not merged to `main`.** The branch is research tooling with one user; it is
  deliberately never PR'd.
- **Does not relitigate IP filtering**, which is parked indefinitely.
- **Does not depend on Android Intrusion Logging**, which cannot supply radio
  data (§11, empirically confirmed).

## 2. Background and evidence

AndroDR's telemetry today is entirely app-, filesystem-, and DNS-derived. Radio
telemetry covers an attack class — passive interception, downgrade-then-intercept
— that no existing AndroDR signal can observe at all.

**Verified greenfield (2026-08-22, against the working tree).** The only
cellular-adjacent match anywhere in `app/src` is a code *comment* ("Qualcomm-aligned
baseband/IMS") in `OemPrefixCoverageRegressionTest.kt:85`. There is no
`TelephonyManager`, `CellInfo`, or `CellIdentity` usage, and **no location
permission of any kind in `app/src/main/AndroidManifest.xml`**. There is no
existing emitter to extend and no existing permission posture to preserve.

**Radio-field evidence** (from the product note; gathered on Samsung SM-F916B,
`kona` / Snapdragon 865, Android 13, **unrooted shell, SELinux enforcing** —
already verified, do not re-run):

| Observation | Value |
|---|---|
| `CellIdentity` records from `dumpsys telephony.registry` | 21 (serving + neighbours) |
| Fields populated on a sampled `CellIdentityLte` | **all 11** |
| Fields set to `Integer.MAX_VALUE` (Android's "unavailable" sentinel) | **zero** |

The load-bearing result is the absence of `Integer.MAX_VALUE`: the platform is
not silently blanking the fields the heuristics depend on.

**Caveat carried forward — this evidence is necessary but not sufficient.**
`dumpsys` runs as the `shell` user and observes the *unredacted framework view*.
It does not prove that an **unprivileged app** holding `ACCESS_FINE_LOCATION`
sees all 11 fields. Closing that gap is the entire purpose of the spike in §10,
which is step 0 of implementation.

## 3. Delivery model — isolated worktree, never merged to `main`

**Decision (2026-08-22): all cellular work lives on a long-lived branch in a
dedicated git worktree that is never intended to merge to `main`.** Code goes in
the ordinary `src/main/` source set *on that branch*.

This supersedes an earlier proposal to use the `src/debug/` source set on `main`.
That approach was rejected after investigation revealed it needs **three separate
pieces of source-set gymnastics**, each a latent failure:

1. `SigmaRuleEngine.loadBundledRules()` iterates an explicit
   `BUNDLED_RULE_IDS = listOf(R.raw.…)` manifest — deliberately reflection-free
   and R8-safe. `R.raw` identifiers are compile-time constants, so a debug-only
   rule resource cannot be named from a `main` source-set list. The list would
   have to become per-source-set overridable or accept an injected supplement.
2. The manifest would have to be split so `ACCESS_FINE_LOCATION` appears only in
   the debug variant.
3. **The decisive one.** `LogsourceTaxonomyCrossCheckTest` builds its
   service→fields map from a **hardcoded `mapOf(...)` in `src/test/`** that
   constructs real model instances. `src/test/` compiles against *both* variants,
   so registering `cellular_monitor` there would make the test reference a
   `src/debug/`-only `CellularSnapshot` — and `testReleaseUnitTest` would fail to
   compile. The test would need duplicating into `src/testDebug/`.

The worktree eliminates all three at once: with everything in `src/main/` on an
unmerged branch, the rule list is edited in place, the manifest is edited in
place, and the cross-check test is edited in place.

**Isolation is strictly stronger than `src/debug/`.** The code never enters
`main` at all, so no future refactor can drift it into a release build, and
`ACCESS_FINE_LOCATION` can never reach the shipped manifest. **The fleet's Play
Data Safety declaration cannot change**, because the branch that produces Play
builds never contains the permission.

**Layout.**

| Item | Location |
|---|---|
| Worktree | `.claude/worktrees/cellular-tier1/` (precedent: `.claude/worktrees/phase2-from-trusted-store`) |
| Branch | e.g. `research/cellular-tier1` — **never PR'd to `main`** |
| Code | `src/main/` on that branch (`CellularMonitor`, `CellularSnapshot`, `evaluateCellular()`) |
| Rules | `src/main/res/raw/` + appended to `BUNDLED_RULE_IDS` in place |
| Permissions | `src/main/AndroidManifest.xml` on that branch |
| Install target | `debug` build type → `com.androdr.debug`, installs alongside the Play build |

The `debug` **build type** is still used (for `applicationIdSuffix = ".debug"`, so
the research build coexists with the production app). What is abandoned is the
`debug` **source set** as an isolation mechanism — branch isolation replaces it.

**CI does not lapse.** An unmerged branch gets no CI *by default*, but this spec
requires full CI coverage on every stage regardless. The mechanism — a permanent
draft PR used purely as a CI vehicle, plus `workflow_dispatch` and local runs —
is specified in full in **§9a**, including the one job that cannot be reached any
other way and the reason the PR is mechanically unmergeable.

**Cost, accepted: drift.** A long-lived branch diverges from `main` as
`SigmaRuleEngine` and the telemetry models evolve. Periodic rebase is required.
Acceptable for a tool scoped to a research trip; if this outlives that, the
divergence becomes a reason to revisit, not to paper over.

**Consequence for promotion.** If v1 ever justifies fleet delivery, it is
re-specced and rebuilt against `main` with the field data in hand — not
fast-forwarded from this branch. That is the intended outcome, not a regression.

## 4. Architecture

```
DnsVpnService  (existing foreground service, foregroundServiceType="specialUse")
  └─ CellularMonitor            [debug-only; no-ops unless both permissions granted]
       ├─ TelephonyCallback.CellInfoListener      → List<CellInfo>   (FINE_LOCATION)
       ├─ TelephonyCallback.ServiceStateListener  → ServiceState/RAT (READ_PHONE_STATE)
       └─ RadioStateStore  (in-memory: last snapshot + 5-minute rolling window)
            └─ on each change event → CellularSnapshot (raw facts + derived measurements)
                 └─ SigmaRuleEngine.evaluateCellular(...) → Finding → Room → report UI
```

**Why event-driven.** `TelephonyCallback` delivers cell/RAT changes as they
happen, so the two stateful heuristics (H1 TAC churn, H6 RAT downgrade) observe
transitions directly instead of inferring them from samples. This avoids both the
battery cost of polling and Android 10+/12+ background poll throttling — *provided
it runs in a foreground-service context*, which `DnsVpnService` already supplies.

**Hybrid-ready.** If the §10 spike shows callbacks arrive too sparsely to be
useful, a slow (multi-minute) `requestCellInfoUpdate()` heartbeat is added as a
backstop. `RadioStateStore` must therefore accept snapshots from an arbitrary
producer, so adding the backstop touches one call site and no heuristic logic.

**Coupling to `DnsVpnService` is a v1 simplification**, justified because the VPN
runs during travel anyway. Extracting a dedicated foreground service is future
work, not v1 scope.

## 5. Emitter contract — the measurement/judgment line

The standing rule is that **emitters emit all facts verbatim; curation belongs in
rules** (the `androdr-294` dead-rule lesson). H1 and H6 are stateful, which appears
to conflict with that rule. It does not, once the line is drawn correctly:

> The emitter may compute **objective measurements** over its own history —
> "the value changed", "it changed N times in T minutes", "the device moved M
> metres". It may **never** decide what is *suspicious*. Every threshold,
> comparison, and correlation lives in the rule.

So the emitter emits `tac_changes_last_5m: 4` (a measurement); the rule decides
that `>= 3` with no movement is churn (a judgment). Thresholds stay tunable
without recompiling, which matters because §10 will tune them from field data.

**Emitted fields — `cellular_monitor`.** The emitter emits *all* of these on every
snapshot, including any no current rule consumes.

*Raw instantaneous facts:*

| Field | Type | Notes |
|---|---|---|
| `mcc` | string | Mobile country code |
| `mnc` | string | Mobile network code |
| `tac` | int | Tracking area code |
| `ci` | long | Cell identity |
| `pci` | int | Physical cell ID |
| `earfcn` | int | Frequency channel (emitted for future H3; unused in v1) |
| `bands` | list | Reported band numbers |
| `bandwidth_khz` | int | Channel bandwidth |
| `rat` | string | Radio access technology (`LTE`, `NR`, `UMTS`, `GSM`, …) |
| `operator_alpha_long` | string, nullable | Network-reported operator name |
| `operator_alpha_short` | string, nullable | Network-reported short name |
| `additional_plmns` | list | Additional PLMN identifiers |
| `neighbor_count` | int | Neighbour cells in the same report |
| `serving_rsrp` | int, nullable | Serving-cell signal strength (dBm) |
| `is_registered` | boolean | Device is registered on this cell |
| `captured_at` | long | Epoch ms |
| `source` | string | `TelemetrySource` enum name |

*Objective derived measurements (state in emitter, judgment in rules):*

| Field | Type | Notes |
|---|---|---|
| `previous_tac` | int, nullable | Null on first observation |
| `previous_rat` | string, nullable | Null on first observation |
| `tac_changed` | boolean | |
| `rat_changed` | boolean | |
| `tac_changes_last_5m` | int | Count over the rolling window |
| `serving_minus_max_neighbor_rsrp_db` | int, nullable | Null when no neighbours reported |
| `location_moved_m_last_5m` | int, nullable | Coarse displacement; null if unavailable |

**`location_moved_m_last_5m` must degrade gracefully.** It uses cheap
network-provider displacement, not GPS. When null, H1 must still evaluate (see
§6) — a heuristic that silently stops working when location is unavailable is a
worse failure than a false positive.

## 6. The five v1 rules

All expressed as SIGMA YAML — **never hardcoded Kotlin**
(`docs/AI-PIPELINE-CONVENTIONS.md`). Thresholds below are **starting points to be
tuned by §10 field data**, not settled values.

| # | Rule | Logic (sketch) | Severity | Kind |
|---|---|---|---|---|
| H2 | Narrow bandwidth | `bandwidth_khz <= 3000` AND `is_registered: true` | low | snapshot |
| H4 | Isolated cell | `neighbor_count: 0` AND `is_registered: true` | low | snapshot |
| H6 | RAT downgrade | `previous_rat` in {`LTE`,`NR`} AND `rat` in {`GSM`,`UMTS`} | medium | stateful |
| H1 | TAC churn | `tac_changes_last_5m >= 3` AND (`location_moved_m_last_5m < 100` OR field absent) | medium | windowed |
| H7 | Operator mismatch | per-operator: e.g. `mcc: 427` AND `mnc: 01` AND `operator_alpha_long` != `Ooredoo` | low | snapshot |

**H1 is the strongest candidate.** A fake cell changes tracking area to force a
Tracking Area Update, and that TAU is the mechanism by which the IMSI/TMSI is
harvested. Its `OR field absent` clause is deliberate: absent location must not
disable the rule.

**H7 needs no reference asset.** Rather than bundling an MCC/MNC→operator table,
v1 authors a small number of per-operator rules covering only the networks
actually travelled through. This keeps all judgment in rules and adds zero
reference data. If the operator list ever grows past a handful, revisit as
reference data (§9).

**Implementation order:** H2 → H4 (trivial, snapshot-only, validate the pipeline
end-to-end) → H6 → H1 (stateful, depend on the spike) → H7.

## 7. Wiring — avoiding the `network_monitor` dead end

`network_monitor` is `status: unwired` in the taxonomy with the comment
*"toFieldMap() exists but NO evaluate method in SigmaRuleEngine — rules cannot
fire"*. **Verified 2026-08-22:** `NetworkTelemetry` exists at
`app/src/main/java/com/androdr/data/model/NetworkTelemetry.kt` with a complete
`toFieldMap()`, and `grep` for `evaluateNetwork` across `app/src/main/java`
returns nothing. Every other service has an explicit
`evaluateXxx()` that calls
`SigmaRuleEvaluator.evaluate(effectiveRules(), records, "<service>", …)`.

**Therefore, three things are jointly required for `cellular_monitor` to fire, and
all three are mandatory:**

1. `CellularSnapshot.toFieldMap()` producing exactly the §5 field names;
2. `SigmaRuleEngine.evaluateCellular(...)` passing the service string
   `"cellular_monitor"`;
3. **A live caller** — `CellularMonitor` actually invoking (2) on each snapshot.

Declaring the taxonomy service and `toFieldMap()` without (2) and (3) reproduces
the `network_monitor` failure exactly. The implementation plan must include an
instrumented or unit test that asserts a synthetic snapshot produces a `Finding`,
so "wired" is proven rather than assumed.

## 8. Permissions, lifecycle, severity, UX

**Permissions.** `ACCESS_FINE_LOCATION` (runtime) and `READ_PHONE_STATE`
(install-time), declared **only in the manifest on the research branch** — never
on `main`, and therefore never in a Play build (§3). `CellularMonitor` registers
its callback only when both are granted and no-ops otherwise — no location, fully
inert. An opt-in control in the research build starts and stops monitoring.

**Severity.** All v1 findings are capped at **medium** and framed
*"investigate"*, never *"alert"*. Rationale: the maintainer is the analyst,
false-positive tolerance is high, and no user-facing alarm is warranted by a
heuristic that has not yet been validated. This is a **distinct severity class
from `device_posture`** — it is not inheriting that cap — but adopts the same
conservative ceiling for v1. **The real severity policy is a fleet-time decision
and is explicitly deferred**, exactly as the product note left it.

**Persistence.** Every finding stores its full triggering snapshot, because §10
depends on being able to adjudicate each flag after the fact.

## 9. Taxonomy, CI gates, and rule-repo mirroring

### The bidirectional constraint that drives this section

**Verified 2026-08-22 by reading `LogsourceTaxonomyCrossCheckTest`.** The test is
**strictly bidirectional**, in two independent ways:

- `val untested = taxonomy.keys - actual.keys` (`:212`) — any taxonomy service
  with no Kotlin `toFieldMap()` counterpart is collected as a failure.
- `assertEquals("…", actual.size, taxonomy.size)` (`:237`) — the service counts
  must match **exactly**.

**Therefore: adding `cellular_monitor` to the rules-repo taxonomy on `main` would
immediately break AndroDR `main`'s CI**, because `main`'s Kotlin has no
`CellularSnapshot`. Both assertions would fail. The normal safe-ordering
sequence, which ends by merging the taxonomy change to rules `main`, **cannot be
followed for this work.**

### Consequence: an unmerged pair

The taxonomy change stays on an **unmerged `android-sigma-rules` branch**, and the
AndroDR worktree branch pins its submodule pointer at that branch commit. Neither
side ever merges.

| Repo | Branch state | Result |
|---|---|---|
| AndroDR `main` | untouched | Taxonomy has no `cellular_monitor`; cross-check passes; fleet unaffected |
| AndroDR worktree branch | `CellularSnapshot` + taxonomy entry + test entry | Cross-check passes on that branch |
| `android-sigma-rules` `main` | untouched | Fleet's 12h `rules.txt` fetch never sees any of it |
| `android-sigma-rules` branch | taxonomy + mirrored rules | Pinned by the worktree submodule pointer only |

This is symmetric and self-consistent: both mains stay green, and the production
fleet is untouched by construction rather than by policy.

**`status:` for the new service.** Declared `active` on the branch, since it is
genuinely wired there (§7). It is never declared on rules `main` at all, so the
`unwired` status — used by `network_monitor` to mean "declared but cannot fire" —
is not the right tool here and must not be used as a workaround to land the
taxonomy entry on `main` early.

### Unit-test gates

| Gate | What it proves |
|---|---|
| `LogsourceTaxonomyCrossCheckTest` | Taxonomy service + fields match `CellularSnapshot.toFieldMap()`, and service counts agree |
| `DetectionFieldCrossCheckTest` | Every field referenced by the five rules exists in the taxonomy |
| `RuleManifestIntegrityTest` | Pinned submodule's `rules.sha256` has not drifted |

A service or field that fails either cross-check is dead on-device — the exact
failure mode #268/#269 exist to prevent. **All three must be kept green after
every rebase from `main`**, since a rebase can pull in taxonomy or model changes
that shift the expected service count.

## 9a. CI coverage plan — every stage, on an unmerged branch

**Requirement (maintainer, 2026-08-22): CI tests must run at all expected
stages.** Verified against the actual workflow definitions on 2026-08-22.

### What each trigger actually reaches

`ci.yml` defines twelve jobs. Two are gated on the event type:

- **`instrumented`** — `if: github.event_name == 'pull_request'`. Emulator /
  on-device tests. **Unreachable via `workflow_dispatch`.**
- **`dependency-review`** — `if: github.event_name == 'pull_request'`.
  Also unreachable via dispatch.

`check-privacy-sync.yml` is likewise `pull_request`-only (and path-gated to
privacy documents, so normally not triggered by this work). `codeql.yml` and the
rules repo's `validate.yml` both declare `workflow_dispatch` and are fully
reachable on an arbitrary ref.

| Stage | `workflow_dispatch` on branch | Draft PR (`pull_request`) |
|---|---|---|
| `changes`, `build-and-test`, `lint-and-detekt`, `apk-analyze` | ✅ | ✅ |
| `secret-scan`, `tracked-path-denylist`, `python-pipeline` | ✅ | ✅ |
| `submodule-check` | ✅ (fails — by design, see below) | ✅ (fails — by design) |
| `dependency-submission` | only if `deps` changed | only if `deps` changed |
| `dependency-review` | ❌ **never** | ✅ |
| **`instrumented`** (on-device) | ❌ **never** | ✅ |
| `ci-success` (aggregate) | ✅ (red — see below) | ✅ (red — see below) |
| CodeQL (`codeql.yml`) | ✅ | ✅ |
| Rules `validate.yml` | ✅ | ✅ |

**Conclusion: `workflow_dispatch` alone is not sufficient.** It silently skips
the instrumented tests — which for a `TelephonyCallback`-based emitter are the
most relevant tests in the suite, being the only ones that exercise real platform
telephony behaviour rather than mocks. Relying on dispatch alone would mean the
emitter's actual runtime behaviour is never exercised by CI at all.

### Mechanism: a permanent draft PR as a CI vehicle

The research branch gets a **draft pull request targeting `main`, titled
`DO NOT MERGE — research branch, CI vehicle only`**, kept open for the life of
the branch and never marked ready for review.

This is a deliberate, narrow use of a PR as a *CI trigger*, not as a merge
request. It contradicts nothing in §3: the branch is still never merged, and the
PR exists so that every push re-runs the complete CI surface automatically.

**It is mechanically unmergeable, and the reason is structural rather than
procedural.** `submodule-check` asserts the submodule HEAD is an ancestor of the
rules-repo upstream `main`:

```
git merge-base --is-ancestor "$HEAD_SHA" FETCH_HEAD
```

The research branch pins the submodule at an **unmerged** rules-repo branch
commit (§9), so that assertion **can never pass**. `submodule-check` is listed in
`ci-success.needs`, so `ci-success` is permanently red — and branch protection on
`main` was confirmed on 2026-08-22 as:

```
required_checks: ["ci-success"],  strict: true,  enforce_admins: true
```

`ci-success` is the **only** required check, `strict` is on, and admins are **not**
exempt. **Therefore the PR cannot be merged by anyone, including the maintainer,
for as long as the submodule points off-main.** The same fact that prevents CI
from ever being fully green is what guarantees this branch cannot reach
production. Draft status and the title are secondary belt-and-braces.

### Defining "green" for this branch

`ci-success` red is **expected and permanent**, so it cannot serve as the signal.
The branch is healthy when:

| Job | Required state |
|---|---|
| `build-and-test` | **green** — the real gate (unit tests + all three §9 cross-checks) |
| `lint-and-detekt` | **green** |
| `apk-analyze`, `secret-scan`, `tracked-path-denylist` | **green** |
| CodeQL | **green** |
| `instrumented` | **green** — note it is `continue-on-error` and exempt from `ci-success`, so it will *not* fail the run; it must be read directly and never assumed passing |
| `submodule-check` | **red — expected**, documented here |
| `ci-success` | **red — expected**, follows from `submodule-check` |

This matches the established project convention that `submodule-check` goes red
during safe-ordering while `build-and-test` is the real gate. The difference is
that here the condition is **permanent, not transient**, so it must be stated in
the PR body to stop a future reader treating the red as a regression.

**`instrumented` deserves particular care.** Because it is advisory and
`continue-on-error`, a failure there produces a green-looking run. For this work
it is one of the most important signals, so the implementation plan must require
reading its result explicitly rather than inferring it from the overall run
status.

### Rules-repo branch

`validate.yml` has **no** PR-only jobs, so `workflow_dispatch` reaches the full
validation:

```
gh workflow run validate.yml --ref <rules-branch> --repo <rules-repo>
```

No PR is needed on that side. Run it after every taxonomy or rule edit.

### Local runs

Before each field deployment, and after every rebase:

```
./gradlew testDebugUnitTest lintDebug
```

**Run from inside the worktree path.** Running from the main checkout silently
verifies the wrong tree and reports success for code that was never built.

### Summary of obligations

1. Open the draft `DO NOT MERGE` PR when the branch is created — not later.
2. State in the PR body that `submodule-check` and `ci-success` are
   expected-red, and why.
3. Read `instrumented` results explicitly; never infer them from run status.
4. `gh workflow run validate.yml --ref <rules-branch>` after every rules edit.
5. Local `testDebugUnitTest lintDebug` in the worktree before deployment and
   after every rebase.

### Mirroring and `rules.txt` — corrected 2026-08-22

**An earlier draft of this spec said the cellular rules would be deliberately
kept out of `rules.txt`. That was wrong and would fail CI.** Correction made
during implementation planning, after reading `BundledMirrorParityTest`.

That test enforces two invariants on **every** bundled rule in `res/raw/`
(correlation rules, `sigma_androdr_corr_*`, are the only exemption):

1. A **byte-equal** mirror counterpart must exist in the submodule, in the
   directory named for its logsource service (`sigma_` prefix stripped).
2. It must be **listed in `rules.txt`**, or the test fails with
   `"<name>: missing from rules.txt (OTA-unreachable)"`.

A third test additionally requires mirror rule basenames to be unique across
service directories.

**Resolution — list them in `rules.txt` on the unmerged rules-repo branch.**
This satisfies the gate while keeping fleet exposure at exactly zero, because
the two facts are independent:

- The **app** fetches `rules.txt` from `android-sigma-rules` **main**, on a 12h
  cycle. The research branch is never merged, so main contains neither the
  cellular rules nor any `rules.txt` entry for them. **The fleet cannot fetch
  what main does not have.**
- The **test** reads `rules.txt` from the **pinned submodule commit**, which is
  the research branch. There it lists the cellular rules, so parity passes.

Fleet isolation was never provided by the `rules.txt` omission — it is provided
by the branch never merging (§3). The omission bought nothing and broke a gate.

**Consequences for the rules-repo branch:**

- Create `cellular_monitor/` and place the five rules there, byte-identical to
  the bundled copies.
- Append their paths to `rules.txt`.
- **Regenerate `rules.sha256`**, since `rules.txt`-listed files changed. This is
  now required (the earlier draft wrongly stated it did not apply):

  ```bash
  cd third-party/android-sigma-rules
  while read -r f; do printf '%s  %s\n' "$(sha256sum "$f" | cut -d' ' -f1)" "$f"; done \
      < rules.txt > rules.sha256
  ```

- `RuleManifestIntegrityTest` then passes against the pinned commit.

**If that branch is ever proposed for merge to rules `main`, this becomes a
genuine fleet-delivery change** and must be re-approved on those terms — merging
it would put the cellular rules on the 12h fetch path for every user within 12
hours.

## 10. Spike (implementation step 0) and validation methodology

**The spike gates H1 and H6 and must run before any production code is written.**

A **throwaway** build from the research worktree registers a `TelephonyCallback`
under the existing
foreground service with `ACCESS_FINE_LOCATION` granted, and logs, while moving
between cells on the SM-F916B:

1. **Field richness** — does an *unprivileged app* see all 11 `CellIdentityLte`
   fields, or does it see `Integer.MAX_VALUE` sentinels where `dumpsys` did not?
   This is the §2 caveat and the single biggest feasibility risk.
2. **Event frequency** — how often do cell/RAT change callbacks actually arrive?
3. **Neighbour visibility** — is `neighbor_count` populated in the app's view?
   (H4 depends entirely on this.)

**Decisions the spike outputs:** the H1 window and threshold defaults; whether
the §4 hybrid backstop is required; and, if field richness fails, whether H2/H4
survive at all. Anything built during the spike is labelled throwaway and is not
carried into the implementation.

**Validation methodology — the dual payoff.** During field runs the honeypot
project's Tier 2 rooted `/dev/diag` capture (QCSuper / SCAT) records layer-3
signalling over the same window. Each Tier 1 finding is adjudicated
true-positive or false-positive against that ground truth. The output is a
labelled dataset that tunes the §6 thresholds *before* any fleet conversation
begins. This is methodology, recorded as text — it is not code and not v1 scope.

## 11. Related findings recorded, not scoped

Recorded so they are not lost. **None is authorized by this document.**

### Android Intrusion Logging cannot feed this detector — but is valuable elsewhere

Investigated at the maintainer's prompting (2026-08-22) and settled by evidence,
including **real logs downloaded from the maintainer's own device**:

- **Wrong data plane.** Intrusion Logging captures security events (unlocks, ADB,
  file transfers, installs, process launches), DNS events, and connection events.
  It captures **no cellular, radio, baseband, IMSI, cell-tower, TAC or EARFCN
  data whatsoever** — confirmed both by Amnesty Security Lab's analysis and by
  direct inspection of a 21-event real sample containing only `dns_event` and
  `connect_event` records.
- **No app-read API.** Logs are end-to-end encrypted and reachable only via a
  user-initiated Settings download or AndroidQF, then parsed offline by MVT's
  `check-advanced-logs`. There is no public API for an app to read or subscribe.
- **Android 16 minimum**, which the SM-F916B field device (Android 13) does not
  meet.

**But `connect_event` maps almost exactly onto the stranded `network_monitor`
model** — `ip_address`→`destination_ip`, `port`→`destination_port`,
`package_name`→`app_name`, `event_time`→`timestamp`; `app_uid` is resolvable via
PackageManager and `protocol` is absent. AndroDR already has the precise
architecture to consume it: `TelemetrySource.BUGREPORT_IMPORT` and the
`scanner/bugreport/` module directory, into which an `IntrusionLogModule` would
slot directly.

**This is explicitly not the parked IP-filtering question.** That decision
rejected *live VPN-based IP inspection* on battery cost. This is *offline import
of logs the platform has already written*, at zero battery cost. It is a
different proposal that happens to touch the same data plane, and it would need
its own approval on its own merits.

A further observation from the sample: the device performs DNS-over-TLS (port
853, to `8.8.8.8` and a local `192.168.168.1` resolver). **AndroDR's VPN-based
DNS monitor cannot observe encrypted DNS, yet `dns_event` records the resolved
hostname regardless** — so Intrusion Logging would close a real, current
visibility gap.

### `AdvancedProtectionManager` posture check (fleet-facing, cheap)

`AdvancedProtectionManager.isAdvancedProtectionEnabled()` (Android 16+,
permission `QUERY_ADVANCED_PROTECTION_MODE`) is a cheap `device_auditor` check
needing **no location permission and no Data Safety change**. Advanced Protection
**disables 2G**, which is the platform *mitigation* for the same downgrade vector
H6 merely *detects* — giving AndroDR a coherent detect-and-prevent story.

It does **not** make this spec redundant: Advanced Protection removes the 2G
vector, but modern IMSI catchers operate on LTE/NR by forcing a Tracking Area
Update with no 2G downgrade at all — precisely what H1, H2 and H4 target.
Complementary, not substitutes. Deferred by maintainer decision ("cellular only
for now") to its own issue.

### `tombstone_parser` field enrichment (independent, smaller)

Carried forward unchanged from the product note. `tombstone_parser` is
`status: active` but thin (`process_name`, `package_name`, `signal_number`,
`abort_message`, `crash_timestamp`, `source`, `captured_at` — verified
2026-08-22). For detecting **failed** exploitation it would benefit from
`fault_address`, `signal_code` (`SEGV_MAPERR` vs `SEGV_ACCERR` — "dereferenced
something unmapped" vs "touched something it was not allowed to"), and the
faulting library plus offset. Crashes are the primary forensic residue of failed
memory-corruption exploits: a successful exploit leaves little, a failed one
leaves a tombstone. Independent of this spec; a field addition to an active
service, following the same safe ordering.

## 12. Open questions carried forward

- **Field richness for an unprivileged app** — §10 spike, item 1. The largest
  single risk to the whole spec.
- **Callback frequency vs. background throttling.** If callbacks are sparse *and*
  polling is throttled below a useful rate, H1 degrades to "3 changes whenever
  the modem chose to report". Still useful for a dogfood build adjudicated
  against ground truth, but the degradation must be documented rather than
  hidden.
- **False-positive rate in dense, multi-operator, roaming environments** is
  unmeasured. Qatar (Ooredoo, Vodafone Qatar) is the immediate test environment.
  §10 is how it gets measured.
- **Battery cost of an always-registered `TelephonyCallback`** is expected to be
  low (event-driven, no polling) but is **unmeasured**. The IP-filtering decision
  was driven substantially by battery cost; the same scrutiny applies before any
  fleet conversation.
- **Rebase cadence and drift budget** (§3). A long-lived unmerged branch diverges
  from `main`; every rebase can shift the taxonomy service count and must be
  followed by a local re-run of the three gates in §9. How often to rebase, and
  at what point divergence makes the branch not worth maintaining, is unsettled.
- **Whether `instrumented` can meaningfully exercise the emitter in CI.** The
  job runs on an emulator, which has a simulated modem: it will not reproduce
  real `CellIdentityLte` neighbour lists, TAC transitions, or RAT downgrades.
  It can cover wiring, `toFieldMap()` shape, and rule evaluation against
  synthetic snapshots — but **it cannot validate the heuristics themselves**.
  That remains the job of the §10 field methodology, and the CI plan in §9a must
  not be read as a substitute for it.
- **Fleet severity policy** — deferred, unchanged from the product note.
- **Reference-data delivery** — if H3, H5, or a grown H7 operator table is ever
  taken up, whether band plans and MCC/MNC tables ride the existing rule/IOC feed
  path or need their own remains unexamined.
