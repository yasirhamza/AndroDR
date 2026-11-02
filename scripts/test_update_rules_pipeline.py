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
