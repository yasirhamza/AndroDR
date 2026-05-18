# AI Pipeline Conventions

Policies and decisions that govern how AI-assisted work flows through this
codebase. These were accumulated across many sessions and lifted out of
individual contributors' agent memory so the rules stand on their own and
new contributors (human or otherwise) see them as part of the repo.

Sections:
- [Review & approval workflow](#review--approval-workflow)
- [Architectural decisions](#architectural-decisions)
- [Roadmap & contact](#roadmap--contact)

---

## Review & approval workflow

### Two independent reviewers after every implementation

Every implementation goes through **two independent review agents** dispatched
in parallel, not a single combined review. Combined reviews tend to be too
agreeable and miss issues; enforced separation produces better coverage.

**Spec compliance reviewer.** Personality: strict, literal,
requirement-focused. Its only job is to verify the implementation matches what
was requested. It does not comment on code quality, style, or architecture.
Reports `✅` or `❌` per requirement. Reads the actual code rather than trusting
the implementer's claims.

**Code quality reviewer.** Personality: harsh, detail-oriented, skeptical. It
does not check spec compliance. It looks for bugs, dead code, race conditions,
memory leaks, naming inconsistencies, test coverage gaps, security risks, and
poor practices. No participation trophies.

Rules:

- Dispatch both in parallel (Claude Code Agent tool with `run_in_background:
  true`).
- Both must complete before moving to the next task.
- Issues found must be fixed before proceeding.
- Templates: Superpowers `spec-reviewer-prompt.md` and
  `code-quality-reviewer-prompt.md` (or the `code-refactoring:code-reviewer`
  agent type for an even harsher personality).

The hardcoded "0 DNS count" bug from an earlier release was caught only by the
harsh code-quality reviewer, not by combined reviews. That is the precedent
that locked this policy in.

### Reviews are non-negotiable

There are no "this fix is trivial, skip the review" exceptions. Multiple
commits historically went unreviewed and accumulated issues that the
two-reviewer cycle would have caught — thread safety, spec drift, and dead
code among them. After every batch of related commits, dispatch both
reviewers before starting the next task. Block on their results.

### HitL gate before commits — scope approval ≠ content approval

For pipelines that include an explicit human-in-the-loop step (e.g.,
`/update-rules` dispatcher Step 7 "Present Results" + Step 8 "Process User
Decisions"), the per-candidate **Approve / Modify / Reject** gate is
mandatory **before** writing files or committing — even if scope was approved
upstream.

Why: scope approval ("which threats", "full or partial scope") is not content
approval. Until the maintainer sees the generated YAML, exact IOC text, rule
selectors, commit messages, and PR copy, no commit step is authorized.
Shipping straight to a PR conflates "you approved the scope" with "you
approved the artifacts" — they are not the same. PRs are reviewable on
GitHub, but the spec's intent is review-before-ship, not review-after-ship
via PR diff.

How to apply:

- After the Rule Author / IOC generator produces candidates, **stop**.
  Present the per-candidate format (or a compact table if the volume is
  large), then ask Approve / Modify / Reject per item (or per logical group
  if dozens).
- Do not run "validate then commit" as a single autonomous block. Validate
  locally first, present the validated artifacts, **then** commit on
  approval.
- This overrides any "run the full cycle without interruption" instruction
  in pipelines that have a built-in approval gate — the gate is part of the
  cycle, not an interruption of it.

### No speculative edits

Do not edit files before the user confirms the change they want. When an
issue is reported, explain the proposed fix and ask before editing. Touch
files only after the direction is confirmed.

The cost of asking once is much less than the cost of an edit-revert cycle
that leaves a dirty working tree and risks accidentally committing reverted
changes.

---

## Architectural decisions

### Detection logic is rule-driven YAML, never hardcoded Kotlin

Detection patterns (system name impersonation, permission clusters,
accessibility abuse, etc.) must not be hardcoded in Kotlin. Patterns are
fluid and change with the threat landscape; detection logic is an ongoing
process informed by threat intelligence. Rules must be updatable
independently of the app binary, in the same spirit that SIGMA rules are
SIEM-agnostic.

How to apply:

- Existing hardcoded heuristics in `AppScanner` and friends are first-class
  candidates for conversion to rules; the rule engine treats them as
  built-in rules.
- New detection patterns are added as YAML files, fetchable as feeds. No
  new hardcoded detection logic — everything goes through the rule engine.

### Rule engine is a Tier 1 strategic initiative

The YAML detection rule engine ([#22](https://github.com/yasirhamza/AndroDR/issues/22))
is Tier 1, not Tier 2/3. It needs:

- Its own public GitHub repo (separate from this app repo) so the community
  can contribute rules.
- Careful design — this defines the first open mobile detection rule
  standard.
- A separate brainstorm/spec/plan cycle — not a quick implementation.

The companion repo is `android-sigma-rules/rules`. AndroDR consumes it as
the `third-party/android-sigma-rules` submodule. The model mirrors
SigmaHQ/sigma: community contributions, peer review, version-controlled
rules fetchable as a feed.

### The rule repo is a standalone strategic initiative — mirror every bundled rule

The `third-party/android-sigma-rules` submodule is **not** a schema workspace
or scratch space for the AI pipeline. It is the public-facing catalog of
AndroDR's detection coverage, intended to stand on its own as a reference
and community resource.

Rules:

- Every new SIGMA rule added to `app/src/main/res/raw/sigma_androdr_*.yml`
  **must** also be added to the submodule under the matching
  `<logsource_service>/` directory (filename strips the `sigma_` prefix).
- Bundled and submodule copies of a rule must be byte-identical. Drift is a
  bug to reconcile, not expected behaviour.
- The CLAUDE.md note about "submodule pointer pinned, AI pipeline writes
  upstream first" describes the AI pipeline's flow only. Rules authored
  manually in AndroDR do not get a free pass — they must be mirrored by
  hand in the same session.
- When opening a rule PR in AndroDR, plan from the start to land a paired
  submodule PR.
- Treat the rule repo's README, catalog completeness, and discoverability
  as first-class concerns — they are how outsiders judge the initiative.

### IP filtering is parked indefinitely, not deferred

AndroDR's `VpnService` tun stays DNS-only. Promoting it to full
`0.0.0.0/0` traffic filtering is parked indefinitely. Reasoning:

- NetGuard's FAQ explicitly flags IP filtering as the opt-in battery-drain
  feature (ships with a user-facing warning). DNS-only stays cheap;
  full-traffic does not.
- NetGuard had to rewrite its entire packet path in C/JNI to make IP
  filtering viable. JVM allocation/GC plus Kotlin parsing cannot sustain
  full-traffic packet rates without melting battery. A JNI port would be a
  prerequisite, not an optimisation.
- Full-traffic mode inherits TCP state tracking, per-flow
  `VpnService.protect()` (a documented NetGuard battery + crash
  anti-pattern), connection pooling, zero-copy buffers, and
  Doze-compatible always-on foreground service work.
- Detection uplift over DNS-only is marginal for AndroDR's threat model.
  Stalkerware C2 is overwhelmingly DNS-resolved — that's why DNS66 and
  DNSNet exist as separate projects from NetGuard.

How to apply:

- Don't relitigate this without a material change in the threat model.
- If a future need arises for flow-level signal ("which app is talking to
  which IP"), prefer **passive** sampling via `ConnectivityManager` /
  `NetworkStatsManager` / `/proc/net/{tcp,udp}` polling over building a
  real firewall — roughly 70% of the value at 5% of the cost.
- Any roadmap or issue text for "IP filtering" should be framed as
  parked-indefinitely with this rationale, not "deferred / next sprint".

### Test harness: use load or guided mode, not regression

The on-device adversary harness (`test-adversary/run.sh`) defaults to
regression mode, but **use `--load` or `--guided`** for real validation
runs.

Why: regression mode runs each scenario in isolation
(install → scan → check → cleanup), which produces timing issues — scans
may not complete in the per-scenario window, and per-app permission
detection is less reliable with only one app installed. Load mode installs
all selected samples first, then triggers one scan, producing results that
match real-world device state.

Quote load-mode results when reporting harness outcomes.

---

## Roadmap & contact

### GitHub issues are the canonical roadmap

GitHub issues are the single source of truth for open work. The main
roadmap reference is **[issue #11](https://github.com/yasirhamza/AndroDR/issues/11)**.
Its title reads as a feature name, but the body is repurposed as the AndroDR
Strategic Roadmap with checkbox sections for completed / next / future
work. The issue is closed but kept as the roadmap tracker.

`docs/ROADMAP.md` is a readable snapshot refreshed at milestones — not
maintained on every issue state change.

Memory and notes should **not** mirror roadmap state either: no "current
sprint", "next priorities", "epic N status", or "module X pending"
snapshots. Those drift the moment a PR merges.

How to apply:

- When creating or closing issues, update the parent epic's checkbox list.
  Regenerate `ROADMAP.md` only at natural milestones.
- Before saving a project-state note anywhere, ask: "would this be an
  issue if I filed it?" If yes → file the issue, don't write a note.
  Decisions *not* to do something, conventions, or pointers to external
  systems are fair game; in-progress snapshots are not.
- When asked "what's next," query `gh issue list` — don't recall sprint
  snapshots.

### Official contact email is `yhamad.dev@gmail.com`

The official contact email for AndroDR (privacy contact, Play Store
developer contact, support) is **`yhamad.dev@gmail.com`** — the
maintainer's Google Developer account email.

There is **no `@androdr.dev` address**. AndroDR does not own a custom
domain. A historical AI-assisted edit hallucinated `privacy@androdr.dev`;
do not propagate it.

Any privacy policy, support contact, Data Safety form, README, or
public-facing doc that needs a contact email uses `yhamad.dev@gmail.com`.
