# Tier 1 Cellular Telemetry — Decision: Park — 2026-09-23

**Decision: park the Tier 1 cellular / radio telemetry work.** It is not
merged to `main`, not shipped, and not scheduled. The branch
`research/cellular-tier1` stays on the remote as the record.

This reverses nothing that was promised — the work was always research, opened
under a product note that explicitly authorised no implementation. What it does
is close the question, so the idea is not re-proposed from scratch in six
months without the measurements that decided it.

**Provenance:** `docs/plans/2026-08-22-tier1-cellular-telemetry-product-note.md`
(idea capture), plus the spec and plan of the same date. Roughly 45 commits,
field-verified on a Samsung SM-F916B (Snapdragon 865, Android 13), unrooted,
SELinux enforcing.

---

## The headline, stated plainly

**API access was not the problem.** That was the expected failure mode and it
did not happen. The no-root telemetry surface is rich, and it is reachable from
a background service. What kills the feature is the *rate* at which the
platform hands that telemetry over, the permission it charges for it, and the
fact that the one detection worth having is better solved by prevention that we
cannot read.

Anyone revisiting this should not re-litigate "can we see the radio". We can.

---

## What was proven to work

Measured from the production code path — a location-typed foreground service
with no visible activity — not from a test harness:

```
snapshot rat=LTE tac=1437 ci=192816407 pci=167 earfcn=1600 bw=null
         mcc=427 mnc=01 op=Ooredoo neighbours=13 rsrp=-84
```

- **The background path works.** `foregroundServiceType="specialUse|location"`
  plus `FOREGROUND_SERVICE_LOCATION` was both necessary and sufficient. Without
  it the identical code returns an empty list and *no error* — a background
  caller cannot distinguish "no cells nearby" from "not allowed to look".
- **Neighbours are visible:** 13 of them, with real tracking area, cell
  identity, physical cell ID, frequency channel and operator.
- **Serving-cell TAC is populated** (neighbours' are not), which is all the
  churn heuristic needs.
- **EARFCN is populated** in 14/14 records, so a future band-plan heuristic has
  a real field to work with.

One field turned out dead and the rule that depended on it was deleted rather
than shipped: `bandwidth` is unavailable in 14/14 app-visible records and
105/106 at the framework layer, so **androdr-101 was removed**. Shipping it
would have manufactured a false sense of coverage — the failure mode #268/#269
exist to prevent.

---

## Why it is parked anyway

### 1. Event rate, not access — the load-bearing reason

`androdr-104` (tracking-area churn) is the strongest Tier 1 signal on the
branch: a fake cell changes tracking area to force a Tracking Area Update, and
that update is the exchange in which the IMSI or TMSI is disclosed. The rule
requires `tac_changes_last_5m >= 3`.

A forced airplane-mode cycle — full radio de-registration and re-registration,
the loudest stimulus available on a stationary device — produced **one delivery
in about sixty seconds**.

Nothing measured has ever shown three deliveries in five minutes is reachable.
Movement between cells is the one unmeasured input, so this is not proof the
rate is inadequate; it is the absence of any evidence that the flagship rule's
trigger condition can be met at the cadence the platform actually delivers. The
feature's best detection is unproven against the platform's own clock.

A related defect: `RadioStateStore` is per-monitor, so toggling the VPN resets
the churn window. `androdr-104` cannot fire across a restart.

### 2. The permission price is out of proportion

This needs `ACCESS_FINE_LOCATION` and `FOREGROUND_SERVICE_LOCATION`, and a Play
Data Safety declaration change. For a tool whose users include journalists and
domestic-violence survivors, fine location is the most expensive permission in
the catalogue in trust terms. The return is six rules, every one of them
`status: experimental`.

### 3. The false-positive direction is wrong for this product

The worst live defect is a clean device reporting a false HIGH. This family
pushes the same way:

- `androdr-102` fires whenever a serving cell reports no neighbours — indoors,
  basements, rural coverage.
- `androdr-105` already fired on a genuine Vodafone Qatar and needed a fix
  (commit `44237ab`).

Adding noise while that trust problem is open makes it worse.

### 4. The operator-name rules do not scale

`androdr-105`, `106` and `107` are hardcoded to Vodafone Qatar and Ooredoo.
Worldwide coverage means either one rule per carrier or a network-code →
operator-name reference dataset with its own delivery path, size budget and
update cadence. Neither is designed, and reference data is not IOC data — it
would not ride the existing feed without work.

### 5. Prevention would beat detection — but we cannot read it

`androdr-103`'s own remediation text says it: turning off 2G *"removes this
attack surface entirely rather than merely detecting it"*, and Advanced
Protection on Android 16+ does it automatically.

So the obvious better feature is a posture check — "2G is still enabled" — with
no location permission, no foreground service, no battery cost and no false
positives. **That check cannot be built.** See the next section; it is the
newest finding here and the reason this decision is being written now rather
than in August.

### 6. Findings land in the wrong model

Cellular detection is continuous and event-driven; the Timeline's notion of a
finding is scan-bound. Cellular findings therefore land in `forensic_timeline`,
which has no severity column. Filtering the Timeline to LOW — the level
`androdr-102` declares — returns "No timeline events yet". A cellular finding
cannot be found by filtering for its own severity. Tracked as **#350**;
reconciling it touches every telemetry source.

---

## The 2G-toggle readability check

Verified 2026-09-23 against platform sources for API 36.1 and a booted
`Medium_Phone_API_36.1` emulator (API 36). **Three independent routes, all
closed.**

### Route 1 — the public API is gated to privileged callers

`TelephonyManager.java`, API 36.1:

```java
@RequiresPermission(android.Manifest.permission.READ_PRIVILEGED_PHONE_STATE)
public @NetworkTypeBitMask long getAllowedNetworkTypesForReason(
        @AllowedNetworkTypesReason int reason)
```

What that permission costs, from `pm list permissions -f` on API 36:

```
permission:android.permission.READ_PRIVILEGED_PHONE_STATE
  protectionLevel: signature|privileged|role
```

Signature-or-privileged. Unobtainable by a Play-distributed app, with no
runtime-prompt path to it. (`getAllowedNetworkTypesBitmask` is worse: same
permission, plus `@hide` and `@SystemApi`.)

### Route 2 — the reason code for the toggle is a system API

The "Allow 2G" switch maps to exactly one reason code, and it is not public:

```java
/** To indicate allowed network type change is requested by the user via the 2G toggle.
 *  @hide */
@SystemApi
public static final int ALLOWED_NETWORK_TYPES_REASON_ENABLE_2G = 3;
```

Even holding the privileged permission, the constant needed to ask the
question is hidden.

### Route 3 — the legacy fallbacks are dead

- The telephony provider column backing the toggle,
  `allowed_network_types_for_reasons` on `Telephony.SimInfo`, is `@hide` on a
  class that is itself `@hide`.
- `Settings.Global.PREFERRED_NETWORK_MODE` carries
  `@UnsupportedAppUsage(maxTargetSdk = Build.VERSION_CODES.R)` — blocked for
  apps targeting Android 12+. AndroDR targets 36.

**Conclusion: an ordinary app cannot read whether 2G is permitted.** It can
observe that it is *currently on* 2G (`getDataNetworkType()`, needs
`READ_PHONE_STATE`), which is a different and weaker fact — it says the
downgrade already happened rather than that the door is open.

---

## What survives: read Advanced Protection state

The check above turned up a better signal than the one it killed.
`AdvancedProtectionManager.isAdvancedProtectionEnabled()` is genuine public
API, and it is cheap:

```
permission:android.permission.QUERY_ADVANCED_PROTECTION_MODE
  protectionLevel: normal
```

`normal` means install-time granted — no runtime prompt, no user approval, no
Data Safety consequence. Confirmed present in the public SDK jar AndroDR
already compiles against (`compileSdk = 36`), with a change callback as well as
a getter:

```
public final class android.security.advancedprotection.AdvancedProtectionManager {
  public boolean isAdvancedProtectionEnabled();
  public void registerAdvancedProtectionCallback(Executor, Callback);
  public void unregisterAdvancedProtectionCallback(Callback);
}
```

This is strictly better than the 2G check would have been. Advanced Protection
disables 2G automatically, so it covers `androdr-103`'s attack surface, and it
also brings memory tagging, intrusion logging, sideload restriction and USB
hardening. One boolean, no meaningful permission cost, no false positives, and
a callback so the app notices if it is switched off.

Two honest limits, recorded rather than glossed:

- **Android 16+ only.** `minSdk = 26`, so this is a version-gated check
  reaching a thin slice of the fleet today. It grows.
- **It is a proxy.** It says the bundle is on, not that 2G specifically is off.

It is also a natural companion to the intrusion-log import (#342), which
already consumes Advanced Protection *logs* while nothing reads the *state*.

**Filed separately — it is independent of cellular and should not inherit this
decision's park.**

---

## What would change the verdict

Stated so a future revisit has a bar to clear rather than an argument to
re-run:

1. **Measured evidence that `androdr-104`'s trigger is reachable** — three
   tracking-area changes inside five minutes, observed while moving, from the
   foreground-service path. This is the one experiment that was never run and
   the single most valuable thing anyone could contribute.
2. **A route to the telemetry without `ACCESS_FINE_LOCATION`**, or a product
   decision that the permission is acceptable, taken deliberately and not as a
   side effect of shipping a detection.
3. **A scalable operator-name source**, replacing the per-carrier rules.
4. **#350 resolved**, so continuous findings are first-class in the Timeline.

Absent (1), the rest is moot.

## Non-goals

- This does not delete `research/cellular-tier1`. The branch is the evidence.
- It does not revisit DIAG-port, root or custom-firmware access — out of scope
  then, out of scope now.
- It does not relitigate IP filtering, which is parked indefinitely.
- It does not park the Advanced Protection state check, which is a separate
  item with separate economics.
