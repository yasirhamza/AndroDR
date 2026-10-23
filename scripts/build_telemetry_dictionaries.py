#!/usr/bin/env python3
"""Builds candidate Deflate preset dictionaries for the telemetry store, one per service family.

The dictionaries are IMMUTABLE once shipped: a stored body is only readable with the exact
bytes it was compressed against.  This script never edits res/raw; it writes candidates to
--out (default app/build/telemetry-dict-candidates).  TelemetryDictionariesTest runs it and
fails when a candidate differs from the pinned bytes of its version: to change a dictionary,
add a NEW version (new file telemetry_dict_<family>_v<N>.txt with a globally new N, a new
PINNED_SHA256 entry, and point the family at it), never rewrite an old one.

Family table (must match TelemetryDictionaries.FAMILY_OF_SERVICE):
  network   (v1)  network_monitor
  dns       (v2)  dns_monitor
  activity  (v3)  package_install_history, usage_stats, appops_audit, wakelock_parser,
                  tombstone_parser, battery_daily
  security  (v4)  security_log

Content is canonical-JSON skeletons in sorted-key order (what the codec emits) with sample
values; each dictionary is <= 4 KiB.  Pure standard library, deterministic.
"""
import argparse
import json
import os
import sys

MAX_BYTES = 4096
T = 1729612345678

PKGS = ["com.android.chrome", "com.google.android.gms", "com.whatsapp", "com.instagram.android",
        "com.google.android.youtube", "com.android.vending", "com.android.systemui"]
DOMAINS = ["www.google.com", "play.googleapis.com", "graph.facebook.com", "mtalk.google.com",
           "connectivitycheck.gstatic.com", "app-measurement.com"]
IPS = ["142.250.185.78", "157.240.201.35", "172.217.169.46", "216.58.213.174", "10.0.2.15"]


def net(app, uid, ip, port, proto, ts):
    return {"app_name": app, "app_uid": uid, "destination_ip": ip, "destination_port": port,
            "protocol": proto, "timestamp": ts}


NETWORK = [net(None, 1000, IPS[4], 80, None, T + 4),
           net(PKGS[1], 10187, IPS[0], 443, "UDP", T + 3),
           net(PKGS[2], 10145, IPS[1], 5222, "TCP", T + 2),
           net(PKGS[0], 10123, IPS[2], 443, "TCP", T + 1),
           net(PKGS[0], 10123, IPS[3], 443, "TCP", T)]

DNS = [{"app_uid": 10187, "domain": DOMAINS[1], "is_blocked": True, "reason": "blocklist",
        "source_package": PKGS[1], "timestamp": T},
       {"app_uid": 10123, "domain": DOMAINS[3], "is_blocked": False, "reason": None,
        "resolved_ips": [IPS[0], IPS[1]], "source_package": PKGS[0], "timestamp": T},
       {"app_uid": 10145, "domain": DOMAINS[2], "is_blocked": False, "reason": None,
        "resolved_ips": [IPS[2]], "source_package": PKGS[2], "timestamp": T},
       {"app_uid": 10123, "domain": DOMAINS[0], "is_blocked": False, "reason": None,
        "resolved_ips": [IPS[3]], "source_package": PKGS[0], "timestamp": T + 1}]

ACTIVITY = [
    {"event_type": "INSTALL", "package_name": PKGS[0], "timestamp": T, "version_code": 1234567890},
    {"event_type": "UPDATE", "package_name": PKGS[1], "timestamp": T, "version_code": 244735035},
    {"event_type": "UNINSTALL", "package_name": PKGS[2], "timestamp": T, "version_code": 2},
    {"app_name": PKGS[3], "event_type": "app_foreground", "package_name": PKGS[3], "timestamp": T},
    {"app_name": PKGS[3], "event_type": "app_background", "package_name": PKGS[3], "timestamp": T},
    {"access_count": 12, "event_time_ms": T, "is_system_app": False, "last_access_time": T,
     "last_reject_time": 0, "operation": "android:camera", "package_name": PKGS[3]},
    {"access_count": 3, "event_time_ms": T, "is_system_app": True, "last_access_time": T,
     "last_reject_time": 0, "operation": "android:record_audio", "package_name": PKGS[5]},
    {"acquired_at": T, "duration_millis": 1500, "package_name": PKGS[1], "wakelock_tag": "*alarm*"},
    {"abort_message": "", "crash_timestamp": T, "package_name": PKGS[4], "process_name": PKGS[4],
     "signal_number": 11},
    {"day_index": 3, "description": "top=10123:\"" + PKGS[5] + "\"", "event_type": "top",
     "package_name": PKGS[5], "timestamp": T, "timestamp_precision": "day", "version": 1},
]

SECURITY = [
    {"security_data": "", "tag": 210002, "tag_name": "adb_shell_cmd", "timestamp": T},
    {"security_data": "", "tag": 210003, "tag_name": "keyguard_dismissed", "timestamp": T},
    {"security_data": "", "tag": 210005, "tag_name": "app_process_start", "timestamp": T},
    {"security_data": "", "tag": 210007, "tag_name": "unknown_210099", "timestamp": T},
]

# family -> (globally unique version, skeleton records)
FAMILIES = {
    "network": (1, NETWORK),
    "dns": (2, DNS),
    "activity": (3, ACTIVITY),
    "security": (4, SECURITY),
}


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def build(records):
    return ("\n".join(canonical(r) for r in records) + "\n").encode("utf-8")


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="app/build/telemetry-dict-candidates")
    args = ap.parse_args(argv)
    os.makedirs(args.out, exist_ok=True)
    for family, (version, records) in sorted(FAMILIES.items(), key=lambda kv: kv[1][0]):
        data = build(records)
        if len(data) > MAX_BYTES:
            print("family %s dictionary is %d bytes (> %d)" % (family, len(data), MAX_BYTES),
                  file=sys.stderr)
            return 1
        name = "telemetry_dict_%s_v%d.txt" % (family, version)
        with open(os.path.join(args.out, name), "wb") as f:
            f.write(data)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
