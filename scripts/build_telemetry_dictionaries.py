#!/usr/bin/env python3
"""Builds candidate Deflate preset dictionaries for the telemetry store.

The dictionaries are IMMUTABLE once shipped: a stored body is only readable with the exact
bytes it was compressed against.  This script never edits res/raw; it writes candidates to
--out (default app/build/telemetry-dict-candidates).  TelemetryDictionariesTest runs it and
fails when a candidate differs from the pinned bytes of its version: to change a dictionary,
add a NEW version (new file telemetry_dict_events_v<N+1>.txt, new PINNED_SHA256 entry,
service->version mapping), never rewrite an old one.

Content is canonical-JSON skeletons in sorted-key order (what the codec emits) for each
event service; the most common service (network_monitor) goes last, nearest the data.
Pure standard library, deterministic.
"""
import argparse
import json
import os
import sys

VERSION = 1
NAME = "telemetry_dict_events_v%d.txt" % VERSION

PACKAGES = [
    "com.android.chrome", "com.google.android.gms", "com.whatsapp", "com.instagram.android",
    "com.facebook.katana", "com.google.android.youtube", "com.android.vending",
    "com.samsung.android.messaging", "org.telegram.messenger", "com.zhiliaoapp.musically",
    "com.google.android.apps.maps", "com.microsoft.office.outlook", "com.spotify.music",
    "com.android.systemui", "com.android.providers.media", "com.google.android.gm",
]
DOMAINS = [
    "www.google.com", "play.googleapis.com", "graph.facebook.com", "api.whatsapp.net",
    "mtalk.google.com", "connectivitycheck.gstatic.com", "clients4.google.com", "i.instagram.com",
    "firebaseinstallations.googleapis.com", "app-measurement.com", "cdn.example.com",
]
IPS = [
    "142.250.185.78", "172.217.169.46", "157.240.201.35", "31.13.72.36", "216.58.213.174",
    "34.107.221.82", "104.18.32.47", "2a00:1450:4009:81f::200e", "10.0.2.15", "192.168.1.1",
]

SKELETONS = [
    ("package_install_history", {"event_type": "INSTALL", "package_name": PACKAGES[0],
                                 "timestamp": 1729612345678, "version_code": 1234567890}),
    ("package_install_history", {"event_type": "UPDATE", "package_name": PACKAGES[1],
                                 "timestamp": 1729612345678, "version_code": 244735035}),
    ("platform_compat", {"change_id": 168419799, "enabled": True, "package_name": PACKAGES[2]}),
    ("wakelock_parser", {"acquired_at": 1729612345678, "duration_millis": 1500,
                         "package_name": PACKAGES[3], "wakelock_tag": "*alarm*"}),
    ("tombstone_parser", {"abort_message": "", "crash_timestamp": 1729612345678,
                          "package_name": PACKAGES[4], "process_name": PACKAGES[4],
                          "signal_number": 11}),
    ("battery_daily", {"day_index": 3, "description": "top=10123:\"" + PACKAGES[5] + "\"",
                       "event_type": "top", "package_name": PACKAGES[5],
                       "timestamp": 1729612345678, "timestamp_precision": "day", "version": 1}),
    ("dns_monitor", {"app_uid": 10123, "domain": DOMAINS[0], "is_blocked": False,
                     "reason": None, "resolved_ips": [IPS[0], IPS[1]],
                     "source_package": PACKAGES[0], "timestamp": 1729612345678}),
    ("dns_monitor", {"app_uid": 10187, "domain": DOMAINS[1], "is_blocked": True,
                     "reason": "blocklist", "source_package": PACKAGES[1],
                     "timestamp": 1729612345678}),
    ("appops_audit", {"event_time_ms": 1729612345678, "mode": "allow", "op": "CAMERA",
                      "package_name": PACKAGES[3]}),
    ("network_monitor", {"app_name": PACKAGES[2], "app_uid": 10145, "destination_ip": IPS[2],
                         "destination_port": 5222, "protocol": "TCP", "timestamp": 1729612345678}),
    ("network_monitor", {"app_name": PACKAGES[1], "app_uid": 10187, "destination_ip": IPS[0],
                         "destination_port": 443, "protocol": "UDP", "timestamp": 1729612399123}),
    ("network_monitor", {"app_name": PACKAGES[0], "app_uid": 10123, "destination_ip": IPS[3],
                         "destination_port": 443, "protocol": "TCP", "timestamp": 1729612401456}),
    ("network_monitor", {"app_name": None, "app_uid": 1000, "destination_ip": IPS[4],
                         "destination_port": 80, "protocol": None, "timestamp": 1729612402789}),
]


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def build():
    parts = ['"%s"' % name for name in PACKAGES + DOMAINS + IPS]
    parts.append("")
    for _service, rec in SKELETONS:
        parts.append(canonical(rec))
    return ("\n".join(parts) + "\n").encode("utf-8")


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="app/build/telemetry-dict-candidates")
    args = ap.parse_args(argv)
    data = build()
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, NAME), "wb") as f:
        f.write(data)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
