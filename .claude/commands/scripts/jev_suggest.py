#!/usr/bin/env python3
"""Jev ATT&CK Mobile tag suggester — pipeline Step 6.6 (advisory, fail-open).

Registered materials (Jev trial, Study B ADOPT): battery
criteria/B1_nouls.json and ranking semantics from jev-androdr-eval @
d89e1b3 (trial preregistration frozen at 339e907); model jev-1.13.0 via
https://api.typesafe.ai.

The API key arrives on stdin (piped from:
    secret-tool lookup service jev-androdr account typesafe
) — never argv, env, or files.

Input:  --candidates FILE — JSONL of {id, title, description, detection, service}
        --battery PATH   — default $JEV_EVAL_REPO/criteria/B1_nouls.json
Output: stdout JSONL {id, model, top3: [{technique, p}...]} in input order;
        a candidate that errors emits {id, model, error: {type, status,
        request_id}} instead — type/status/request_id only, never the
        server text (trial rule).
Exit:   0 = emitted (possibly with per-candidate errors);
        3 = no key, or missing/corrupt battery;
        4 = every candidate errored, OR the key is dead (an auth error on
            the first request aborts immediately — one doomed request
            proves it; mirrors the trial harness's STOP, folded into 4).
The dispatcher treats 3/4/all-errors identically: WARN, author tags stand.
"""
import argparse
import json
import os
import sys

MODEL = "jev-1.13.0"
BASE_URL = "https://api.typesafe.ai"
DEFAULT_EVAL_REPO = "/home/yasir/projects/jev-androdr-eval"
TOP_N = 3


def build_state(candidate):
    """The B-item state shape the battery was registered against
    (jev-androdr-eval src/items.py b_state: title/description/detection/service)."""
    return {
        "title": candidate["title"],
        "description": candidate["description"],
        "detection": candidate["detection"],
        "service": candidate["service"],
    }


def rank_top3(nouls):
    """Registered ranking (jev-androdr-eval src/score.py jev_b1_ranking):
    descending yes-score, ties broken by technique ID."""
    ranked = sorted(nouls.items(), key=lambda kv: (-kv[1], kv[0]))
    return [{"technique": t, "p": p} for t, p in ranked[:TOP_N]]


def exit_code(n_candidates, n_ok):
    """Fail-open contract: all-errored is 4 (loud), everything else is 0.
    Pinned by test so an API outage can never masquerade as 'the model
    returned no suggestions'."""
    return 4 if n_candidates and n_ok == 0 else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--candidates", required=True)
    ap.add_argument("--battery", default=None)
    args = ap.parse_args()

    eval_repo = os.environ.get("JEV_EVAL_REPO", DEFAULT_EVAL_REPO)
    battery_path = args.battery or os.path.join(eval_repo, "criteria", "B1_nouls.json")
    try:
        with open(battery_path) as f:
            battery = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"jev: battery missing/unreadable/corrupt: {battery_path}: {e}", file=sys.stderr)
        return 3

    key = sys.stdin.readline().strip()
    if not key:
        print("jev: no key on stdin", file=sys.stderr)
        return 3

    # The trial's SDK + HTTP client are installed in the eval repo's venv —
    # the same interpreter scripts/jev pins. This script must be run with
    # that venv's python (the dispatcher command does); no sys.path games.
    import httpx2  # noqa: E402
    import typesafe_sdk as ts  # noqa: E402

    candidates = []
    with open(args.candidates) as f:
        for line in f:
            if not line.strip():
                continue
            try:
                candidates.append(json.loads(line))
            except json.JSONDecodeError:
                print("jev: skipping unparseable candidate line", file=sys.stderr)

    client = ts.TypeSafeClient(
        api_key=key, model=MODEL, base_url=BASE_URL,
        http_client=httpx2.Client(trust_env=False, timeout=60))
    del key

    # Dead-key fast fail: one doomed request proves the key is dead —
    # stop instead of burning one call per candidate (the trial
    # harness's STOP pair, folded into this script's exit 4).
    STOP = (ts.TypeSafeAuthenticationError, ts.TypeSafePermissionDeniedError)

    n_ok = n_err = 0
    for cand in candidates:
        rec = {"id": cand["id"], "model": MODEL}
        try:
            resp = client.system_one(build_state(cand), battery)
            rec["top3"] = rank_top3({qid: a.noul for qid, a in resp.nouls.items()})
            n_ok += 1
        except STOP as e:
            print(f"jev: stopping: {type(e).__name__} status={getattr(e, 'status', None)} "
                  f"request_id={getattr(e, 'request_id', None)}", file=sys.stderr)
            return 4
        except ts.TypeSafeError as e:
            rec["error"] = {"type": type(e).__name__,
                            "status": getattr(e, "status", None),
                            "request_id": getattr(e, "request_id", None)}
            n_err += 1
        print(json.dumps(rec, sort_keys=True))
        sys.stdout.flush()

    if candidates and n_ok == 0:
        print(f"jev: every candidate errored ({n_err})", file=sys.stderr)
    return exit_code(len(candidates), n_ok)


if __name__ == "__main__":
    sys.exit(main())
