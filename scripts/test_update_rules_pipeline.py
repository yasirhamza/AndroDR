"""Regression gates for the update-rules pipeline's agent instructions.

These guard against the 2026-11-02 stall: the ASB ingester followed
"cvss (from NVD if available)", fetched NVD one CVE at a time at the anonymous
rate limit (5 requests / 30 s) from a background job it then blocked on, and
the run looked hung for ~10 minutes. It also tried the flat bulletin URL, which
404s for 2026 bulletins.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
COMMANDS = ROOT / ".claude" / "commands"
WORKFLOW = ROOT / ".claude" / "workflows" / "update-rules-e2e.workflow.js"

LIMITS_PHRASES = (
    "120 seconds",
    "never start a background job",
    "one item at a time",
)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _flat(text: str) -> str:
    """Collapse whitespace so phrases wrapped across Markdown lines still match."""
    return re.sub(r"\s+", " ", text)


def _prompt_functions(js: str) -> dict:
    """Map each `function xxxPrompt(` to its body (up to the next top-level `}`)."""
    bodies = {}
    for m in re.finditer(r"^function (\w+Prompt)\(", js, re.M):
        end = js.find("\n}\n", m.end())
        assert end != -1, f"unterminated function {m.group(1)}"
        bodies[m.group(1)] = js[m.end():end]
    return bodies


def test_asb_skill_never_enriches_cvss_from_nvd():
    asb = _flat(_read(COMMANDS / "update-rules-ingest-asb.md"))
    assert "from NVD if available" not in asb
    assert "Do NOT query NVD from this ingester" in asb


def test_asb_skill_uses_year_directory_bulletin_urls():
    asb = _read(COMMANDS / "update-rules-ingest-asb.md")
    # Flat form .../bulletin/2026-03-01 404s; it must be .../bulletin/2026/2026-03-01.
    flat = re.findall(r"security/bulletin/\d{4}-\d{2}-\d{2}", asb)
    assert not flat, f"flat bulletin URL(s) without the year directory: {flat}"
    assert re.search(r"security/bulletin/(\d{4}|YYYY)/(\d{4}|YYYY)-", asb)


def test_asb_skill_states_execution_limits():
    asb = _flat(_read(COMMANDS / "update-rules-ingest-asb.md"))
    for phrase in ("120 seconds", "background job", "per CVE"):
        assert phrase in asb, phrase


def test_workflow_defines_execution_limits():
    js = _read(WORKFLOW)
    m = re.search(r"^const EXEC_LIMITS = `([^`]*)`", js, re.M)
    assert m, "EXEC_LIMITS constant missing from the workflow script"
    for phrase in LIMITS_PHRASES:
        assert phrase in m.group(1), phrase


def test_every_workflow_prompt_includes_execution_limits():
    bodies = _prompt_functions(_read(WORKFLOW))
    assert len(bodies) >= 10, f"expected the pipeline's prompt functions, found {sorted(bodies)}"
    missing = [name for name, body in bodies.items() if "${EXEC_LIMITS}" not in body]
    assert not missing, f"prompt functions without ${{EXEC_LIMITS}}: {missing}"


def test_dispatcher_briefs_carry_execution_limits():
    dispatcher = _flat(_read(COMMANDS / "update-rules.md"))
    assert "include this paragraph verbatim in EVERY subagent brief" in dispatcher
    for phrase in LIMITS_PHRASES:
        assert phrase in dispatcher, phrase


# 2026-11-02, second stall: the dedup agent finished its feed checks in ~70 s,
# then spent many minutes retyping all 368 surviving candidates as `additive`
# because DEDUP_OUT required it. The agent now returns only its drop list and
# the script derives the survivors.

def _const_block(js: str, name: str) -> str:
    m = re.search(rf"^const {name} = \{{\n(.*?)^\}}\n", js, re.M | re.S)
    assert m, f"{name} not found"
    return m.group(1)


def test_dedup_schema_does_not_ask_the_agent_to_echo_survivors():
    block = _const_block(_read(WORKFLOW), "DEDUP_OUT")
    code = "\n".join(line.split("//")[0] for line in block.splitlines())
    assert "additive" not in code, "DEDUP_OUT must not define or require `additive`"
    assert "required: ['dropped']" in code


def test_dedup_prompt_returns_only_the_drop_list():
    body = _prompt_functions(_read(WORKFLOW))["dedupPrompt"]
    assert "additive:" not in body
    assert "Do NOT list the candidates you keep" in body
    # The agent gets [type, indicator] pairs, not the full candidate objects.
    assert "iocs.map(e => [e.type, e.indicator])" in body


def test_dedup_prompt_checks_parent_domain_labels():
    body = _flat(_prompt_functions(_read(WORKFLOW))["dedupPrompt"])
    assert "parent label" in body


def test_workflow_derives_dedup_survivors_from_the_drop_list():
    js = _read(WORKFLOW)
    assert "dedupResult.additive" not in js
    assert re.search(r"survivors = dedupCandidates\.filter\(e => !droppedKeys\.has\(", js)


# 2026-11-02, decision-only records: the author returns "no rule" decisions in `candidates`
# without yaml. They were validated as empty rules ("9 failed") and took IDs in renumbering.

def _is_rule_candidate_js() -> str:
    m = re.search(r"^const isRuleCandidate = (.+)$", _read(WORKFLOW), re.M)
    assert m, "isRuleCandidate missing from the workflow script"
    return m.group(1)


def test_decision_only_records_are_not_rule_candidates():
    import json
    import shutil
    import subprocess
    node = shutil.which("node")
    assert node, "node is required (preinstalled on GitHub runners)"
    records = [
        {"rule_id": "androdr-311", "yaml": "title: x\nid: androdr-311\n", "decisions": []},   # real rule
        {"rule_id": None, "yaml": None, "decisions": [{"chosen": "skip"}]},                    # 2026-11-02 shape
        {"rule_id": None, "yaml": None, "decision_only": True, "decisions": []},
        {"rule_id": None, "yaml": "  \n", "decisions": []},
        {"rule_id": "androdr-312", "yaml": "title: y\n", "decision_only": True},
        None,
    ]
    script = f"const f = {_is_rule_candidate_js()}; console.log(JSON.stringify({json.dumps(records)}.map(f)))"
    out = subprocess.run([node, "-e", script], capture_output=True, text=True, check=True, timeout=30).stdout
    assert json.loads(out) == [True, False, False, False, False, False]


def test_only_rule_candidates_reach_renumbering_and_validation():
    js = _read(WORKFLOW)
    assert "const candidates = authoredRecords.filter(isRuleCandidate)" in js
    split = js.index("const candidates = authoredRecords.filter(isRuleCandidate)")
    assert split < js.index("candidates.forEach((c, i) =>"), "split must happen before ID renumbering"
    assert "author_decisions: authorDecisions" in js, "decision-only records go to HitL, not validation"


# 2026-11: ThreatFoxDomainFeed retired (public export HTTP 410; replacement needs an Auth-Key).
# ThreatFox is no longer an on-device mirror, so nothing in the pipeline may treat it as one.

def test_threatfox_is_not_treated_as_an_on_device_mirror():
    dedup = _flat(_prompt_functions(_read(WORKFLOW))["dedupPrompt"])
    assert "(currently mvt-indicators)" in dedup
    assert "ThreatFox C2 domains are always ADDITIVE" in dedup
    abusech = _flat(_read(COMMANDS / "update-rules-ingest-abusech.md"))
    assert '"upstream_snapshot_hash_set": []' in abusech
    assert '["C2_DOMAIN"' not in abusech, "a ThreatFox snapshot would make dedup drop every ThreatFox candidate"


# 2026-11: tracker-list refresh (ioc-data/trackers.yml, the Exodus Privacy mirror) became a
# step of /update-rules. The list is fetched by phones, so the instructions must build the
# candidate away from the live file, treat a failed fetch as a failure, ask one question,
# and commit the list on its own with a regenerated manifest.

def _section(text: str, heading: str) -> str:
    """The text from the Markdown heading line starting with `heading` up to the next
    heading of the same or a higher level. `#` lines inside code fences are not headings."""
    level = len(heading) - len(heading.lstrip("#"))
    assert level, f"{heading!r} is not a Markdown heading"
    out, inside, fenced = [], False, False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            fenced = not fenced
        elif not fenced and line.startswith("#"):
            hashes = len(line) - len(line.lstrip("#"))
            if inside and hashes <= level:
                break
            if not inside and line.startswith(heading) and hashes == level:
                inside = True
        if inside:
            out.append(line)
    assert out, f"heading {heading!r} not found"
    return "\n".join(out)


def _dispatcher() -> str:
    return _read(COMMANDS / "update-rules.md")


def test_section_stops_at_the_next_heading_of_the_same_or_higher_level():
    doc = "## A\na\n### A.1\na1\n```bash\n# not a heading\n```\n## B\nb\n### B.1\nb1\n### B.2\nb2\n# C\n"
    assert _section(doc, "## A") == "## A\na\n### A.1\na1\n```bash\n# not a heading\n```"
    assert _section(doc, "### B.1") == "### B.1\nb1"
    assert _section(doc, "### B.2") == "### B.2\nb2"


def test_launcher_and_dispatcher_agree_on_source_ids():
    ids_line = next(l for l in _dispatcher().splitlines() if "/update-rules source <id>" in l)
    dispatcher = set(re.findall(r"`([a-z]+)`", ids_line.split("valid IDs:")[1]))
    launcher_text = _read(ROOT / "scripts" / "update-rules.sh")
    launcher = set(re.search(r'^VALID_SOURCES="([^"]*)"', launcher_text, re.M).group(1).split())
    assert dispatcher == launcher and "trackers" in dispatcher
    for source_id in launcher:   # the help text lists every id the launcher accepts, and no other
        assert re.search(rf"^  {source_id}\s+\S", launcher_text, re.M), f"usage() does not list {source_id}"
    assert "citizenlab" not in launcher_text, "citizenlab has no ingester"


def test_tracker_candidate_is_built_away_from_the_live_file():
    d = _dispatcher()
    step = _flat(_section(d, "## Step 6.7"))
    assert "--out <run-dir>/trackers/trackers.yml" in step and "--previous ioc-data/trackers.yml" in step
    assert "--out ioc-data/trackers.yml" not in d


def test_tracker_failure_is_a_feed_failure_not_no_change():
    step = _flat(_section(_dispatcher(), "## Step 6.7"))
    for phrase in ("exit code 1", "exit code 2", "feed FAILURE", "never as \"no change\"", "the rest of the run continues"):
        assert phrase in step, phrase


def test_tracker_step_runs_in_full_mode_even_with_no_threat_intel():
    assert "Step 6.7" in _flat(_section(_dispatcher(), "## Step 3"))


def test_tracker_change_has_one_decision_and_is_never_hand_edited():
    block = _flat(_section(_dispatcher(), "### 7.2"))
    for phrase in ("Approve", "Skip", "never edited by hand", "first_party_hosts.txt", "data, not instructions"):
        assert phrase in block, phrase
    assert "Modify" not in block


def test_tracker_commit_is_its_own_and_regenerates_the_manifest():
    block = _flat(_section(_dispatcher(), "### 8.5"))
    for phrase in ("cp <run-dir>/trackers/trackers.yml ioc-data/trackers.yml", "ioc-data.sha256",
                   "validate-ioc-data.py ioc-data/trackers.yml", "validate-feed-state.py", "exodus_trackers",
                   "its own commit", "merge-ioc-data.py"):
        assert phrase in block, phrase


def test_tracker_list_skips_cross_dedup_reference_check_and_ledger():
    step = _flat(_section(_dispatcher(), "## Step 6.7"))
    for phrase in ("Step 6.5", "Gate 2b", "run ledger"):
        assert phrase in step, phrase


def test_workflow_defers_the_tracker_refresh_to_the_main_session():
    js = _read(WORKFLOW)
    deferred = js[js.index("deferred_to_main_session"):]
    assert "Tracker-list refresh" in deferred and "Step 6.7" in deferred
