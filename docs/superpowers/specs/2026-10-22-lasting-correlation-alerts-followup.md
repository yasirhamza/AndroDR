# Lasting Correlation Alerts — Follow-up Spec (recorded, not scoped)

**Date:** 2026-10-22
**Status:** Recorded follow-up. Split out of `2026-10-22-telemetry-store-design.md` by maintainer decision at plan-gate round 7.
**Depends on:** the telemetry store design shipping first (`telemetry_record` / `scan_record`, `signal_member`, `alert`, `scan_finding`, `AtomRef`).

## 1. What this is

In the telemetry store design, findings on **event records** (DNS IOC hits, connections, security events, …) become lasting alerts. They stay open until a person closes them (the SOC pattern).

**Correlation findings** stay as they are today: state findings of the scan that produced them. This spec records how they could become lasting alerts too, and why that was not done in the first design.

## 2. Why it was split

Plan-gate rounds 3–7 tried to give correlation chains a lasting alert identity. Each round fixed the previous round's defects and exposed new edges. By round 7, roughly two-thirds of every round's findings came from this one feature, while the record-level alert lifecycle had been stable since round 3.

The maintainer chose to land the store, the uncapped Timeline and the record-alert lifecycle first, and design this separately.

## 3. Design explored (rounds 3–7) and what each step broke

| Mechanism | Problem found |
|---|---|
| Alert key `ruleId:` + sorted member refs | A lookback window that grows mints a new key each scan, so duplicate alerts appear. |
| Join an existing alert when members overlap | Joining a CLOSED alert silenced new activity. Fixed by joining OPEN alerts only, plus a subset rule for CLOSED alerts. |
| `alert_member` capped at the newest 1,000, with a `truncatedBelow` cutoff | The cutoff compared two id spaces (row vs fact), which counted non-members as members and suppressed new chains. |
| Membership written only on create | Members added later were neither recorded nor pinned, so evidence was lost after 30 days or on scan deletion. |
| A `persistent` flag on alert-referenced rows | The flag drifted. It also grew without bound with uncapped membership. |
| Every member pinned | A chatty app's events escaped retention forever. |
| Pinning only evidence members (opening 50 + newest 50) | No ordering column, so "opening/newest" fell back to id order. A decisive mid-chain stage could fall out of the evidence set. |
| Re-homing rows of deleted scans to `scanResultId = -1` | Cleanup leaked once the reference was lost (import rows are never pruned). Deleted-import evidence showed up as live events. |
| Correlating before the finishing transaction | The current scan's rows had no ids to use as atom refs. Fixed by correlating inside the transaction, which this design keeps. |
| Legacy signals | Existing `member_event_ids` were never migrated into the member tables. The `signal_member` backfill in this design fixes this for signals. |

## 4. Requirements a future design must meet

These come from the findings above.

- **R1. Identity stable under a sliding lookback window.** The same incident maps to one alert across scans, without depending on the exact member set.
- **R2. Closing an alert never silences new activity.** New members after a close open, or visibly reopen, an alert.
- **R3. Bounded evidence that keeps what is decisive.** For example: the first and last K members per correlation step, ordered by event time (an explicit `seq` / `eventTime` column), plus the members that are themselves record alerts.
- **R4. Membership is not pinning.** Exact matching must not require keeping every fact forever.
- **R5. Evidence survives scan deletion and retention without re-homing or overloading `scanResultId`.** A candidate approach is a dedicated `alert_evidence` table holding decoded copies of the bounded evidence set.
- **R6. Bounded cost inside `finish`.** Overlap and subset tests use indexed joins (a TEMP table against a `(kind, refId)` index). The correlator keeps its per-(rule, group) budget.
- **R7. Migration of existing correlation findings** into the new identity.
- **R8. Deterministic tests** for growing chains, closed-then-new chains, members split across closed alerts, adversarial density, scan deletion and retention.

## 5. What the first design already provides

- Correlation runs inside the finishing transaction, over `AtomRef`s (`Row` / `Fact`). The `AtomRef` kind values (0 = Row, 1 = Fact) stored in `signal_member.kind` are stable.
- `signal_member` is the single, indexed member store for signals, with a one-time backfill.
- The correlator has per-(rule, group) budgets and `CORRELATION_INCOMPLETE`.
- Record alerts, `alert.evidenceJson`, credential-protected close, and audited deletion are in place.

## 6. References

- Plan-gate findings: `docs/superpowers/plans/2026-10-22-telemetry-store-plan-gate-round{3..7}-findings.md`.
