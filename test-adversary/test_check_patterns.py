"""Tests for check-patterns.sh — the adversary harness's report assertion step.

The harness could only ever assert that a pattern IS present, so every one of its
37 scenarios was an attack and "did the report over-escalate?" was unaskable. That
is how #332 shipped: a clean device reporting OVERALL RISK: HIGH is invisible to a
suite whose every fixture expects HIGH to be correct.

A line prefixed with `!` asserts the pattern is ABSENT, which makes a benign
baseline scenario expressible.
"""

import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parent / "check-patterns.sh"


def run_check(tmp_path, report_text, patterns_text):
    report = tmp_path / "report.txt"
    report.write_text(report_text)
    patterns = tmp_path / "scenario.patterns"
    patterns.write_text(patterns_text)
    return subprocess.run(
        ["bash", str(SCRIPT), str(report), str(patterns)],
        capture_output=True,
        text=True,
    )


CLEAN_REPORT = """  AndroDR Security Report
  OVERALL RISK: MEDIUM

FINDINGS SECTION
  Sideloaded Application
"""


def test_passes_when_every_required_pattern_is_present(tmp_path):
    result = run_check(tmp_path, CLEAN_REPORT, "Sideloaded Application\nOVERALL RISK: MEDIUM\n")
    assert result.returncode == 0, result.stdout


def test_fails_when_a_required_pattern_is_missing(tmp_path):
    result = run_check(tmp_path, CLEAN_REPORT, "Known Malicious Package\n")
    assert result.returncode == 1
    assert "MISS" in result.stdout
    assert "Known Malicious Package" in result.stdout


def test_fails_when_a_forbidden_pattern_is_present(tmp_path):
    """The #332 shape: a benign scan must not escalate."""
    escalated = CLEAN_REPORT.replace("OVERALL RISK: MEDIUM", "OVERALL RISK: HIGH")
    result = run_check(tmp_path, escalated, "!OVERALL RISK: HIGH\n")
    assert result.returncode == 1
    assert "UNEXPECTED" in result.stdout
    assert "OVERALL RISK: HIGH" in result.stdout


def test_passes_when_a_forbidden_pattern_is_absent(tmp_path):
    result = run_check(tmp_path, CLEAN_REPORT, "!OVERALL RISK: HIGH\n!OVERALL RISK: CRITICAL\n")
    assert result.returncode == 0, result.stdout


def test_mixed_required_and_forbidden_patterns(tmp_path):
    result = run_check(
        tmp_path,
        CLEAN_REPORT,
        "OVERALL RISK: MEDIUM\n!OVERALL RISK: HIGH\n",
    )
    assert result.returncode == 0, result.stdout


def test_ignores_comments_and_blank_lines(tmp_path):
    patterns = "# the clean-device baseline\n\n!OVERALL RISK: HIGH\n\n"
    result = run_check(tmp_path, CLEAN_REPORT, patterns)
    assert result.returncode == 0, result.stdout


def test_patterns_are_literal_not_regex(tmp_path):
    """Report text is matched with grep -F; a pattern with regex metacharacters
    must match literally or scenario authors get silent false passes."""
    report = "  Spyware artifact: /data/local/tmp/.raptor\n"
    result = run_check(tmp_path, report, "/data/local/tmp/.raptor\n")
    assert result.returncode == 0, result.stdout
    result = run_check(tmp_path, report, "/data/local/tmp/Xraptor\n")
    assert result.returncode == 1


def test_fails_when_the_report_is_missing(tmp_path):
    patterns = tmp_path / "scenario.patterns"
    patterns.write_text("anything\n")
    result = subprocess.run(
        ["bash", str(SCRIPT), str(tmp_path / "absent.txt"), str(patterns)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "report" in result.stdout.lower()


def test_fails_when_the_patterns_file_is_missing(tmp_path):
    report = tmp_path / "report.txt"
    report.write_text(CLEAN_REPORT)
    result = subprocess.run(
        ["bash", str(SCRIPT), str(report), str(tmp_path / "absent.patterns")],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "patterns" in result.stdout.lower()


@pytest.mark.parametrize("risk", ["HIGH", "CRITICAL"])
def test_clean_device_baseline_rejects_escalation(tmp_path, risk):
    """Exactly what test-adversary/fixtures/expected/clean_device.patterns asserts."""
    baseline = Path(__file__).parent / "fixtures" / "expected" / "clean_device.patterns"
    report = tmp_path / "report.txt"
    report.write_text(CLEAN_REPORT.replace("OVERALL RISK: MEDIUM", f"OVERALL RISK: {risk}"))
    result = subprocess.run(
        ["bash", str(SCRIPT), str(report), str(baseline)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1, f"a clean device reporting {risk} must fail the baseline"
