# Telemetry store — plan gate round 7 findings (2026-10-22)

Reviewers were fresh Opus instances, read-only, on a narrow re-gate against 9f6a756. All four lenses failed: correctness 2 SEV-2, architect 2, code quality 4, security 1. That is 9 raw SEV-2s, de-duplicating to six roots. Every lens confirmed the round-6 roots resolved.

**Maintainer decision, 2026-10-22:** lasting correlation alerts split to a follow-up spec (`docs/superpowers/specs/2026-10-22-lasting-correlation-alerts-followup.md`). From round 3 to round 7, roughly two-thirds of every round's findings came from that one feature. Correlation findings stay per-scan state findings, as today. Record (event) alerts keep the lasting lifecycle.

| # | Root | Found by | Resolution |
|---|---|---|---|
| Y1 | "Clear all" wrote its audit row last, so a force-stop erased it | arch, sec, corr | The first transaction writes one capped audit row and sets every scan to `DELETING`. Kill test added to L2 for both `deleteScan` and "Clear all". |
| Y2 | The evidence-only pin rule was not applied on every delete path | corr, arch, sec | Moot: `alert_member` and evidence pinning are removed with the split. |
| Y3 | Re-homed rows were never cleaned up, and re-homing landed after the D2 tests needed it | corr, qual, arch, sec | Moot: re-homing is removed. A deleted scan's rows go, and other signals show the members that remain, as today. |
| Y4 | "Opening" and "newest" evidence had no ordering | qual, arch, sec | Moot (moved into the follow-up's requirements, R3). |
| Y5 | Existing users' `member_event_ids` were never migrated | qual | `SignalMemberBackfill`, a one-time Phase C job, fills `signal_member` (still the single member store for signals). Test added. |
| Y6 | Timeline clusters had no way to load fact members | qual | `ClusterMembers.load(signalRowId): List<TimelineMember>` (rows and decoded facts), loaded on expand. Behavioural test added. |

SEV-3s folded in:
- **Correlation budget.** Per (rule, group), with an injected clock and a deadline check that returns normally. Partial signals are kept. `CORRELATION_INCOMPLETE` is excluded from `realFailureCount`.
- **Correlation inputs.** Groups are filtered to the rule's steps, and the largest groups run last.
- **Re-check suppression.** Based on whether the alert's record key exists, so it survives scan deletion.
- **Dirty flag.** Defined as a DataStore boolean.
- **`correlationId`.** A canonical sorted-member hash. `member_count` goes in `matchContext`.
- **Tests and exporters.** C2 test files listed. `TimelineExporter` gains a `member_refs` column.
- **Wording and battery.** The stale "short transaction" wording was replaced. The `finish` ≤ 2 s target was added to the D battery.

Re-gate scope: all four lenses re-run in round 8, narrowly, against this file.
