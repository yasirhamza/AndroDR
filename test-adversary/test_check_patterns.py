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


# The shape ReportFormatter prints for a clean live device (summary + MERCENARY
# SPYWARE CHECK, as rendered in MercenaryCheckReportTest's clean-device case).
CLEAN_DEVICE_REPORT = """  OVERALL RISK: LOW

  No threats detected. Your phone appears secure.

  SUMMARY:
    Apps scanned: 212 -- Flagged: 0
    Campaign detections: none
    DNS IOC matches: 0

------------------------------------------------------------
  MERCENARY SPYWARE CHECK
------------------------------------------------------------
  [OK]  Cellebrite: not detected
  [OK]  Graphite (Paragon): not detected
  [--]  LANDFALL: no infection check exists for a live scan; patch level only
  [OK]  Massistant: not detected
  [OK]  Midnight Mimosa: not detected
  [OK]  Pegasus: not detected
  [OK]  Predator: not detected
"""

DNS_OFF_REPORT = """  MERCENARY SPYWARE CHECK
  [--]  LANDFALL: no infection check exists for a live scan; patch level only
  [--]  Pegasus: DNS lookups not monitored (DNS monitoring was off; only lookups recorded earlier were checked)
        Turn on DNS monitoring, use the phone as usual, then scan again.
    Campaign detections: none
"""

DNS_OFF = Path(__file__).parent / "fixtures" / "expected" / "campaign_rows_dns_off.patterns"


def test_dns_off_scenario_accepts_the_dns_off_rows(tmp_path):
    report = tmp_path / "report.txt"
    report.write_text(DNS_OFF_REPORT)
    result = subprocess.run(["bash", str(SCRIPT), str(report), str(DNS_OFF)], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout


def test_dns_off_scenario_rejects_an_ok_pegasus_row(tmp_path):
    report = tmp_path / "report.txt"
    report.write_text(DNS_OFF_REPORT.replace(
        "  [--]  Pegasus: DNS lookups not monitored (DNS monitoring was off; only lookups recorded earlier were checked)",
        "  [OK]  Pegasus: not detected"))
    result = subprocess.run(["bash", str(SCRIPT), str(report), str(DNS_OFF)], capture_output=True, text=True)
    assert result.returncode == 1

BASELINE = Path(__file__).parent / "fixtures" / "expected" / "clean_device.patterns"


def run_baseline(tmp_path, report_text):
    report = tmp_path / "report.txt"
    report.write_text(report_text)
    return subprocess.run(
        ["bash", str(SCRIPT), str(report), str(BASELINE)],
        capture_output=True,
        text=True,
    )


def test_clean_device_baseline_accepts_a_clean_report(tmp_path):
    """Without this, the rejection tests below would pass on any report at all."""
    result = run_baseline(tmp_path, CLEAN_DEVICE_REPORT)
    assert result.returncode == 0, result.stdout


@pytest.mark.parametrize("risk", ["HIGH", "CRITICAL"])
def test_clean_device_baseline_rejects_escalation(tmp_path, risk):
    """Exactly what test-adversary/fixtures/expected/clean_device.patterns asserts."""
    report = CLEAN_DEVICE_REPORT.replace("OVERALL RISK: LOW", f"OVERALL RISK: {risk}")
    result = run_baseline(tmp_path, report)
    assert result.returncode == 1, f"a clean device reporting {risk} must fail the baseline"
    assert f"forbidden pattern present: 'OVERALL RISK: {risk}'" in result.stdout


def test_clean_device_baseline_rejects_a_detected_campaign(tmp_path):
    report = CLEAN_DEVICE_REPORT.replace(
        "  [OK]  Pegasus: not detected",
        "  [!!]  Pegasus: DETECTED -- domain p.example (Pegasus), 2025-10-15",
    )
    result = run_baseline(tmp_path, report)
    assert result.returncode == 1
    assert "forbidden pattern present: ': DETECTED --'" in result.stdout


def test_clean_device_baseline_allows_patch_level_exposure(tmp_path):
    # An old emulator patch level leaves campaign CVEs unpatched: EXPOSED is not an escalation.
    report = CLEAN_DEVICE_REPORT.replace(
        "  [OK]  Pegasus: not detected",
        "  [!!]  Pegasus: EXPOSED -- 2 CVEs linked to Pegasus (unpatched; not evidence of infection)",
    )
    result = run_baseline(tmp_path, report)
    assert result.returncode == 0, result.stdout


DNS_REPORT = """DNS ACTIVITY
  [MATCHED]  12:00:01  forti.external-muki.com                             <- shell
           reason: blocklist
  [ALLOWED]  12:00:02  paragon-graphite.net                                <- shell
"""


def test_regex_requires_a_matching_line(tmp_path):
    result = run_check(tmp_path, DNS_REPORT, "~\\[MATCHED\\].*forti\\.external-muki\\.com\n")
    assert result.returncode == 0, result.stdout


def test_regex_miss_fails(tmp_path):
    result = run_check(tmp_path, DNS_REPORT, "~\\[MATCHED\\].*paragon-graphite\\.net\n")
    assert result.returncode == 1
    assert "MISS: regex not matched" in result.stdout


def test_negated_regex_fails_when_a_line_matches(tmp_path):
    result = run_check(tmp_path, DNS_REPORT, "!~\\[MATCHED\\].*forti\\.external-muki\\.com\n")
    assert result.returncode == 1
    assert "UNEXPECTED: forbidden regex matched" in result.stdout


def test_negated_regex_ties_both_facts_to_one_line(tmp_path):
    # Literal checks would pass "[MATCHED]" and "paragon-graphite.net" separately;
    # the regex only fails if the same line carries both.
    result = run_check(tmp_path, DNS_REPORT, "!~\\[MATCHED\\].*paragon-graphite\\.net\n")
    assert result.returncode == 0, result.stdout


# Since Phase B the report's DNS rows are the scan's stored dns_monitor records, printed one
# field per line by the generic per-service renderer (ReportFormatter). The scenario files'
# DNS checks target that format; this pins them against it.
STORED_DNS_REPORT = """------------------------------------------------------------
  STORED TELEMETRY: dns_monitor (2 record(s))
------------------------------------------------------------
  [0] captured 2026-10-23 12:00:01
     app_uid: 2000
     domain: forti.external-muki.com
     is_blocked: false
     reason: IOC_detect: forti.external-muki.com
     source_package: com.android.shell
     timestamp: 1792746001000
  [1] captured 2026-10-23 12:00:02
     app_uid: 2000
     domain: paragon-graphite.net
     is_blocked: false
     reason: null
     source_package: com.android.shell
     timestamp: 1792746002000
"""

GRAPHITE = Path(__file__).parent / "fixtures" / "expected" / "graphite_dns_attribution.patterns"


def graphite_dns_lines():
    return "".join(line for line in GRAPHITE.read_text().splitlines(keepends=True)
                   if "reason:" in line and not line.startswith("#"))


def test_graphite_dns_checks_accept_the_stored_record_format(tmp_path):
    lines = graphite_dns_lines()
    assert lines.count("\n") == 2, lines
    result = run_check(tmp_path, STORED_DNS_REPORT, lines)
    assert result.returncode == 0, result.stdout


@pytest.mark.parametrize("reason", ["IOC: paragon-graphite.net", "IOC_detect: graphite.net", "blocklist",
                                    "blocklist_detect"])
def test_graphite_dns_checks_reject_any_reason_on_the_placeholder(tmp_path, reason):
    # The old "[MATCHED]" negative caught every non-null reason, not only an IOC that quotes the host.
    report = STORED_DNS_REPORT.replace("     reason: null", "     reason: " + reason)
    result = run_check(tmp_path, report, graphite_dns_lines())
    assert result.returncode == 1, result.stdout
    assert "a record matching '^     domain: paragon-graphite" in result.stdout


def test_graphite_dns_checks_reject_an_unmatched_graphite_domain(tmp_path):
    report = STORED_DNS_REPORT.replace("     reason: IOC_detect: forti.external-muki.com", "     reason: null")
    result = run_check(tmp_path, report, graphite_dns_lines())
    assert result.returncode == 1
    assert "MISS: regex not matched" in result.stdout


# Record-scoped assertions ("@<anchor> => <regex>", "!@<anchor> => <regex>"): the regexes are
# evaluated within one stored record's block, so a file's path is tied to its own file_exists.
FILE_REPORT = """------------------------------------------------------------
  STORED TELEMETRY: file_scanner (3 record(s))
------------------------------------------------------------
  [0] captured 2026-10-23 12:00:01
     accessible: true
     file_exists: true
     file_path: /data/local/tmp/wd
  [1] captured 2026-10-23 12:00:01
     accessible: true
     file_exists: false
     file_path: /data/local/tmp/wd/fs.db
  [2] captured 2026-10-23 12:00:01
     accessible: true
     file_exists: true
     file_path: /data/local/tmp/dropbox
------------------------------------------------------------
  APPLICATION LOG  (1 lines, captured at export)
------------------------------------------------------------
     file_exists: true
"""

FOUND = " => ^     file_exists: true$\n"


def test_record_scoped_accepts_a_found_record(tmp_path):
    result = run_check(tmp_path, FILE_REPORT, "@^     file_path: /data/local/tmp/wd$" + FOUND)
    assert result.returncode == 0, result.stdout


def test_record_scoped_rejects_a_stored_but_not_found_path(tmp_path):
    # Its neighbours say file_exists: true; only its own block counts.
    result = run_check(tmp_path, FILE_REPORT, "@^     file_path: /data/local/tmp/wd/fs\\.db$" + FOUND)
    assert result.returncode == 1
    assert "has no line matching" in result.stdout


def test_record_scoped_rejects_a_missing_record(tmp_path):
    result = run_check(tmp_path, FILE_REPORT, "@^     file_path: /data/local/tmp/\\.raptor$" + FOUND)
    assert result.returncode == 1
    assert "MISS: no record matches" in result.stdout


def test_record_scoped_block_ends_at_the_first_non_field_line(tmp_path):
    # The log's indented "file_exists: true" after the section rule is not part of record [2].
    report = FILE_REPORT.replace("     file_exists: true\n     file_path: /data/local/tmp/dropbox",
                                 "     file_exists: false\n     file_path: /data/local/tmp/dropbox")
    result = run_check(tmp_path, report, "@^     file_path: /data/local/tmp/dropbox$" + FOUND)
    assert result.returncode == 1, result.stdout


def test_negated_record_scoped_fails_only_on_its_own_record(tmp_path):
    ok = run_check(tmp_path, FILE_REPORT, "!@^     file_path: /data/local/tmp/wd$ => ^     file_exists: false$\n")
    assert ok.returncode == 0, ok.stdout
    bad = run_check(tmp_path, FILE_REPORT,
                    "!@^     file_path: /data/local/tmp/wd/fs\\.db$ => ^     file_exists: false$\n")
    assert bad.returncode == 1
    assert "UNEXPECTED: a record matching" in bad.stdout


def test_record_scoped_without_an_arrow_is_malformed(tmp_path):
    result = run_check(tmp_path, FILE_REPORT, "@^     file_path: /data/local/tmp/wd$\n")
    assert result.returncode == 1
    assert "MALFORMED" in result.stdout


PREDATOR = Path(__file__).parent / "fixtures" / "expected" / "mercenary_predator_artifacts.patterns"
FILES = Path(__file__).parent / "fixtures" / "expected" / "mercenary_file_artifacts.patterns"


def record_lines(path):
    return "".join(line for line in path.read_text().splitlines(keepends=True) if line.startswith("@"))


def file_records(paths, missing_state=None):
    out = ""
    for i, path in enumerate(paths):
        state = "false" if path == missing_state else "true"
        out += "  [%d] captured 2026-10-23 12:00:01\n     file_exists: %s\n     file_path: %s\n" % (i, state, path)
    return out


@pytest.mark.parametrize("patterns,paths", [
    (PREDATOR, ["/data/local/tmp/wd", "/data/local/tmp/wd/fs.db", "/data/local/tmp/dropbox"]),
    (FILES, ["/data/local/tmp/.raptor", "/data/local/tmp/.stat"]),
])
def test_artifact_scenarios_tie_every_planted_path_to_found(tmp_path, patterns, paths):
    lines = record_lines(patterns)
    assert lines.count("\n") == len(paths), lines
    assert run_check(tmp_path, file_records(paths), lines).returncode == 0
    for path in paths:
        result = run_check(tmp_path, file_records(paths, missing_state=path), lines)
        assert result.returncode == 1, "%s stored but not found must fail: %s" % (path, result.stdout)


# A record-scoped assertion that cannot be evaluated must fail closed. An invalid awk regex used
# to make awk exit with no output; the empty counts broke the numeric tests and the check passed.
@pytest.mark.parametrize("pattern", [
    "@^     file_path: (unclosed$ => ^     file_exists: true$",
    "@^     file_path: /data/local/tmp/wd$ => ^     file_exists: (true$",
    "!@^     file_path: (unclosed$ => ^     file_exists: false$",
    "!@^     file_path: /data/local/tmp/wd$ => ^     file_exists: (false$",
])
def test_record_scoped_invalid_regex_is_malformed(tmp_path, pattern):
    result = run_check(tmp_path, FILE_REPORT, pattern + "\n")
    assert result.returncode == 1, result.stdout
    assert "MALFORMED" in result.stdout


@pytest.mark.parametrize("pattern", [
    "@^     file_path: /data/local/tmp/wd$ => ",
    "!@^     file_path: /data/local/tmp/wd$ => ",
    "@ => ^     file_exists: true$",
])
def test_record_scoped_empty_side_is_malformed(tmp_path, pattern):
    # An empty regex matches every line: "@x => " would reduce to "the record exists".
    result = run_check(tmp_path, FILE_REPORT, pattern + "\n")
    assert result.returncode == 1, result.stdout
    assert "MALFORMED" in result.stdout


GUIDED = Path(__file__).parent / "guided-check.sh"


def guided(tmp_path, pattern, roadmap=""):
    report = tmp_path / "report.txt"
    report.write_text(FILE_REPORT)
    return subprocess.run(["bash", str(GUIDED), str(report), pattern, roadmap], capture_output=True, text=True)


def test_guided_mode_never_excuses_a_malformed_pattern(tmp_path):
    result = guided(tmp_path, "@^     file_path: (unclosed$ => ^     file_exists: true$", roadmap="123")
    assert result.returncode == 1, result.stdout
    assert "MALFORMED" in result.stdout


def test_guided_mode_excuses_a_plain_miss_with_a_roadmap_issue(tmp_path):
    result = guided(tmp_path, "@^     file_path: /data/local/tmp/wd/fs\\.db$ => ^     file_exists: true$",
                    roadmap="123")
    assert result.returncode == 2, result.stdout
    assert "expected fail" in result.stdout


def test_guided_mode_pass_miss_and_absent_label(tmp_path):
    assert guided(tmp_path, "@^     file_path: /data/local/tmp/wd$ => ^     file_exists: true$").returncode == 0
    miss = guided(tmp_path, "@^     file_path: /data/local/tmp/wd/fs\\.db$ => ^     file_exists: true$")
    assert miss.returncode == 1 and "MISS" in miss.stdout
    absent = guided(tmp_path, "!OVERALL RISK: HIGH")
    assert absent.returncode == 0
    assert '"absent: OVERALL RISK: HIGH"' in absent.stdout


def test_run_sh_guided_mode_goes_through_guided_check():
    text = (Path(__file__).parent / "run.sh").read_text()
    assert 'guided-check.sh" "$REPORT" "$pattern" "$roadmap"' in text
    assert "grep_mode" not in text, "guided mode must not keep its own copy of the sigil logic"
