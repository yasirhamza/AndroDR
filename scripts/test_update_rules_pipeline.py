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
