# Product note: Tier 1 cellular / radio telemetry — IMSI-catcher detection

**Status: UNAPPROVED IDEA CAPTURE — not a plan, not a spec, not authorized
work.** Nothing here has been through the four-agent review ceremony, no
issue has been filed, and no code, rule YAML, or taxonomy change is
sanctioned by this document. It exists so a finding does not get lost. A
human must review and explicitly approve before any implementation,
brainstorm, or spec cycle begins. Severity policy, permission model, and
scope are all open. Per `docs/AI-PIPELINE-CONVENTIONS.md` ("No speculative
edits"), treat every heuristic below as a proposal awaiting confirmation,
not a direction already agreed.

**Provenance:** the observation fell out of a separate travel-honeypot-phone
research project and is parked here so it does not derail that project —
the honeypot work itself is out of scope for this note.

---

## Proposal

AndroDR gains a **Tier 1 cellular / radio telemetry source** that detects
IMSI-catcher, fake-base-station, and cellular-downgrade conditions using
**only public Android telephony APIs** — no root, no custom firmware, no
Qualcomm DIAG port, working on ordinary retail hardware.

This is the SnoopSnitch / EFF-Rayhunter detection family, reduced to the
subset reachable without privileged baseband access. Those tools need root
or dedicated hardware precisely because they read the DIAG interface; the
claim here is that a useful — not equivalent, but useful — slice of the
same detection surface is reachable from an unprivileged app.

Why it is interesting for AndroDR specifically: the app's current telemetry
is entirely app-, filesystem-, and DNS-derived. Radio-layer telemetry is a
different observation plane covering an attack class (passive interception,
downgrade-then-intercept) that no existing AndroDR signal can see at all.

## Empirical evidence

Gathered on a Samsung SM-F916B (`kona` / Snapdragon 865, Android 13),
**unrooted shell, SELinux enforcing**. This is already verified — do not
re-run it against the device to confirm.

| Observation | Value |
|---|---|
| `CellIdentity` records exposed by `dumpsys telephony.registry` | 21 (serving + neighbours) |
| `CellIdentityLte` references | 35 |
| `CellSignalStrengthLte` references | 3 |
| Fields populated on a sampled `CellIdentityLte` record | **all 11** |
| Fields set to `Integer.MAX_VALUE` (2147483647, Android's "unavailable" sentinel) | **zero** |

Fields available on that record: `mCi` (cell identity), `mPci` (physical
cell ID), `mTac` (tracking area code), `mEarfcn` (frequency channel),
`mBands`, `mBandwidth`, `mMcc`, `mMnc`, `mAlphaLong`, `mAlphaShort`,
`mAdditionalPlmns`.

**Conclusion:** the no-root telemetry surface is materially richer than
expected — a full neighbour list with no redaction sentinels — and is
sufficient for meaningful detection. The absence of `Integer.MAX_VALUE`
across all 11 fields is the load-bearing result: it means the platform is
not silently blanking the fields the heuristics below depend on.

## Candidate detection heuristics

Each of these would be expressed as **rule-driven SIGMA YAML, never
hardcoded Kotlin** — a standing project constraint
(`docs/AI-PIPELINE-CONVENTIONS.md`, "Detection logic is rule-driven YAML").
The emitter's job is to emit the radio facts verbatim; all curation,
thresholding, and correlation belongs in the rules.

| # | Heuristic | Signal | Notes |
|---|---|---|---|
| 1 | **TAC churn** | Repeated `mTac` changes without corresponding geographic movement | Fake cells change tracking area to force a Tracking Area Update — that TAU is the mechanism by which IMSI/TMSI is harvested. The strongest candidate. |
| 2 | **Implausibly narrow bandwidth** | `mBandwidth` at 1.4/3 MHz | Software-defined fake cells commonly transmit narrow; real macro cells run 10/15/20 MHz. |
| 3 | **EARFCN off-plan** | `mEarfcn` outside the operator's licensed allocation for that country/region | Needs a per-country/per-operator band-plan reference dataset. |
| 4 | **Isolated cell** | Serving cell presenting no neighbour list, and/or implausibly strong signal relative to neighbours | Uses the neighbour records the evidence above confirms are available. |
| 5 | **Unknown cell tuple** | `(MCC, MNC, TAC, CI)` never previously observed *and* absent from a reference database | OpenCelliD is the main candidate. Mozilla Location Service is discontinued — do not design against it. |
| 6 | **RAT downgrade** | LTE/NR → GSM/UMTS transition | The classic IMSI-catcher move: 2G lacks mutual authentication. |
| 7 | **Operator name mismatch** | `mAlphaLong` / `mAlphaShort` inconsistent with the operator the MCC/MNC pair actually identifies | Cheap to evaluate; needs an MCC/MNC → operator-name reference table. |

Heuristics 1 and 6 are stateful (they compare against prior observations);
2, 3, 4 and 7 are evaluable from a single snapshot. That split matters for
how the emitter is shaped and is one reason this note does not attempt an
implementation design.

## Integration path and gating requirements

Stated as **constraints**, not as a design. The implementation is
deliberately not specified here.

**Starting point: AndroDR currently has zero cellular / radio telemetry.**
Verified: no `TelephonyManager`, `CellInfo`, `baseband`, or `IMSI`
references anywhere in `app/src`. This is greenfield — there is no existing
emitter to extend.

**A new logsource service is required** (working name `cellular_monitor`).
The authoritative taxonomy is
`third-party/android-sigma-rules/validation/logsource-taxonomy.yml`; the
schema is `third-party/android-sigma-rules/validation/rule-schema.json`.

**Any such taxonomy or rule change must follow the safe ordering in
`CLAUDE.md`**, so AndroDR CI gates *before* the change reaches production —
the app pulls rules from `android-sigma-rules` main on a 12h cycle, not from
the submodule, so a broken manifest on main is live for up to 12h regardless
of the submodule pointer:

1. Edit the rule YAML on an `android-sigma-rules` branch and regenerate
   `rules.sha256`. (The manifest regen applies only when `rules.txt`-listed
   files change — taxonomy-only edits skip it.)
2. Bump the AndroDR submodule pointer to that branch commit in an AndroDR PR.
3. Confirm `RuleManifestIntegrityTest` is green in AndroDR CI.
4. Only then merge the `android-sigma-rules` branch to main.
5. Re-point the submodule at the resulting main commit.

The AndroDR-side gates for taxonomy changes are
`LogsourceTaxonomyCrossCheckTest` and `DetectionFieldCrossCheckTest`. A new
service or field that does not satisfy both is dead on-device — the failure
mode #268/#269 exist to prevent.

Two further standing constraints apply:

- **Rule-repo mirroring.** Every bundled rule must also land in the
  submodule under the matching `<logsource_service>/` directory, byte
  identical (`docs/AI-PIPELINE-CONVENTIONS.md`, "mirror every bundled
  rule"). A `cellular_monitor` service means a `cellular_monitor/`
  directory in the rule repo from day one.
- **Emitters emit all facts verbatim.** Curation belongs in rules, not in
  the emitter. Whatever the radio emitter reads, it emits — including
  fields no current rule consumes.

## Related gaps worth recording

### `network_monitor` is declared but unwired

`logsource-taxonomy.yml` declares `network_monitor` with `status: unwired`
and the comment: *"toFieldMap() exists but NO evaluate method in
SigmaRuleEngine — rules cannot fire"*. Any network-derived detection work
would need this wired first. Worth knowing before anyone assumes a
network-adjacent service is available to build on — and worth checking
whether a radio emitter would hit the same missing-`evaluate` wall.

### `tombstone_parser` field enrichment (separate, smaller idea)

The `tombstone_parser` service is `status: active` but thin. Current
fields: `process_name`, `package_name`, `signal_number`, `abort_message`,
`crash_timestamp`, `source`, `captured_at`.

For detecting **failed** exploitation attempts it would benefit from:

- `fault_address` — the faulting address.
- `signal_code` — distinguishing `SEGV_MAPERR` from `SEGV_ACCERR`, which is
  the difference between "dereferenced something unmapped" and "touched
  something it was not allowed to".
- The faulting library and offset.

Rationale: crashes are the primary forensic residue of failed
memory-corruption exploits. A successful exploit leaves little; a failed one
leaves a tombstone. This is independent of the cellular proposal and could
be pursued on its own — it is a field addition to an already-active service,
not a new one, though it follows the same safe ordering.

## Open questions

Recorded honestly as unresolved. None of these should be asserted as settled
in any downstream issue or spec.

- **Permission and throttling model.** Android 10+ gates `getAllCellInfo()`
  behind `ACCESS_FINE_LOCATION` and throttles background polling; Android
  12+ tightened this further. **The exact current limits need verification.**
  Do not assert specifics until checked against current platform docs and
  behaviour on target API levels. This is the single biggest feasibility
  risk: a heuristic like TAC churn needs a sample rate that background
  throttling may not permit.
- **A location permission is a product decision, not just a technical one.**
  Requesting `ACCESS_FINE_LOCATION` changes AndroDR's permission posture and
  its Play Data Safety declaration. Not evaluated here.
- **Polling cadence versus battery drain** is unresolved. Related precedent:
  the IP-filtering decision was driven substantially by battery cost, and
  the same scrutiny should apply here.
- **OpenCelliD** offline database size, licensing terms, and update cadence
  are all unresolved. Relevant to heuristic 5 and to APK size.
- **False-positive risk is high** in dense urban and multi-operator
  environments and during roaming/handover. Qatar (Ooredoo, Vodafone Qatar)
  is the immediate test environment.
- **Severity policy.** `device_posture` rules are hard-capped at medium
  severity by prior decision. Do cellular findings belong under that cap, or
  do they warrant their own severity policy? Raised as a question — **not
  decided here.** A confirmed IMSI catcher and a stale device patch level
  are not obviously the same severity class, but neither is a
  high-false-positive radio heuristic obviously worth a high-severity alert.
- **Reference-data delivery.** Band plans (heuristic 3), MCC/MNC → operator
  names (heuristic 7), and any OpenCelliD subset are reference data, not
  IOCs. Whether they ride the existing rule/IOC feed path or need their own
  is unexamined.

## Non-goals

- **This note is not approved work.** It authorizes nothing.
- **It is not a spec and not a plan.** No API surface, no emitter design, no
  data model, no rule YAML, no schema or taxonomy diff. Contrast with
  `docs/plans/2026-08-05-268-269-dead-rule-gates.md`, which is a gated,
  approved, executed plan — this document is at an earlier stage entirely.
- **It does not cover the travel-honeypot research project**, which is
  mentioned once above purely as provenance.
- **It does not propose DIAG-port, root, or custom-firmware access.** The
  entire premise is what is reachable without them. If a heuristic turns out
  to need privileged baseband access, it is out of scope, not a reason to
  expand scope.
- **It does not relitigate IP filtering**, which is parked indefinitely.

## Suggested next step

If a human approves the direction: verify the Android 10/12+ permission and
throttling limits first, because that single question determines whether
heuristics 1 and 6 are viable at all. Everything else is downstream of the
answer. Then file an issue (GitHub issues are the canonical roadmap) and run
a proper brainstorm/spec cycle — a new Tier 1 telemetry source is not a
quick implementation.
