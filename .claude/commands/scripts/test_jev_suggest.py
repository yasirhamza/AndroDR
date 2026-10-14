"""Unit tests for jev_suggest.py — pure functions + fail-open paths.

The live API path mirrors the frozen trial harness (jev-androdr-eval @
d89e1b3) and is exercised only in a real sweep; these tests pin what can
silently break between runs: the registered B-item state shape, the
registered ranking semantics (score.jev_b1_ranking: descending score,
tie-break by technique ID), and the fail-open exit codes the dispatcher
depends on (3 = no key / missing-or-corrupt battery, 4 = all candidates
errored).
"""
import importlib.util
import json
import pathlib
import subprocess
import sys

SCRIPT = pathlib.Path(__file__).resolve().parent / "jev_suggest.py"


def load_module():
    spec = importlib.util.spec_from_file_location("jev_suggest", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_build_state_matches_registered_b_item_shape():
    mod = load_module()
    state = mod.build_state({
        "id": "x", "title": "T", "description": "D",
        "detection": "condition: selection", "service": "app_scanner",
    })
    assert state == {
        "title": "T", "description": "D",
        "detection": "condition: selection", "service": "app_scanner",
    }


def test_rank_top3_descending_then_id_tiebreak():
    mod = load_module()
    nouls = {"T1429": 0.9, "T1430": 0.9, "T1404": 0.8, "T1417": 0.7}
    top3 = mod.rank_top3(nouls)
    assert [t["technique"] for t in top3] == ["T1429", "T1430", "T1404"]
    assert top3[0]["p"] == 0.9


def test_rank_top3_fewer_than_three():
    mod = load_module()
    assert [t["technique"] for t in mod.rank_top3({"T1404": 0.5})] == ["T1404"]


def test_no_key_exits_3(tmp_path):
    cpath = tmp_path / "c.jsonl"
    cpath.write_text(json.dumps({"id": "x", "title": "t", "description": "d",
                                 "detection": "c", "service": "s"}) + "\n")
    bpath = tmp_path / "battery.json"
    bpath.write_text("{}")
    r = subprocess.run(
        [sys.executable, str(SCRIPT), "--candidates", str(cpath), "--battery", str(bpath)],
        input="\n", capture_output=True, text=True)
    assert r.returncode == 3
    assert "no key" in r.stderr


def test_missing_battery_exits_3_even_with_key(tmp_path):
    cpath = tmp_path / "c.jsonl"
    cpath.write_text("{}\n")
    r = subprocess.run(
        [sys.executable, str(SCRIPT), "--candidates", str(cpath),
         "--battery", str(tmp_path / "nonexistent.json")],
        input="fake-key\n", capture_output=True, text=True)
    assert r.returncode == 3
    assert "battery" in r.stderr


def test_corrupt_battery_exits_3(tmp_path):
    cpath = tmp_path / "c.jsonl"
    cpath.write_text("{}\n")
    bpath = tmp_path / "battery.json"
    bpath.write_text("{not json")
    r = subprocess.run(
        [sys.executable, str(SCRIPT), "--candidates", str(cpath), "--battery", str(bpath)],
        input="fake-key\n", capture_output=True, text=True)
    assert r.returncode == 3
    assert "battery" in r.stderr


def test_exit_code_all_errors_is_4():
    mod = load_module()
    assert mod.exit_code(3, 0) == 4   # every candidate errored
    assert mod.exit_code(3, 1) == 0   # partial success still emits + exit 0
    assert mod.exit_code(0, 0) == 0   # empty input is vacuous success