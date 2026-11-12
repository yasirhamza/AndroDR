"""Two faults of the harness found in the 2026-11-12 release battery.

1. Guided mode stopped at the first assertion that did not pass. run.sh runs under `set -e`, and it called
   guided-check.sh as a plain command and then read `$?`; a miss (exit 1) or an expected fail (exit 2)
   ended the script before it was counted, so the walkthrough never reached its summary.
2. alert_dedup_dns_repeat named one live blocklist domain. Indicators age out of the feed (IOC decay), and
   then the scenario fails for a reason that has nothing to do with the app. The scenario now names a
   placeholder, and live-indicator.py picks a domain that is in the feed when the harness runs.
"""
import importlib.util
import pathlib
import re

HERE = pathlib.Path(__file__).resolve().parent
RUN_SH = (HERE / "run.sh").read_text(encoding="utf-8")
PLACEHOLDER = "@LIVE_TIF_DOMAIN@"


def _picker():
    spec = importlib.util.spec_from_file_location("live_indicator", HERE / "live-indicator.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_a_guided_assertion_that_does_not_pass_is_counted_not_fatal():
    call = re.search(r'bash "\$SCRIPT_DIR/guided-check\.sh"[^\n]*', RUN_SH)
    assert call, "guided-check.sh call not found"
    assert "|| check_status=$?" in call.group(0), call.group(0)
    assert 'case "$check_status" in' in RUN_SH


def test_the_dedup_scenario_names_no_fixed_live_domain():
    manifest = (HERE / "manifest.yml").read_text(encoding="utf-8")
    patterns = (HERE / "fixtures/expected/alert_dedup_dns_repeat.patterns").read_text(encoding="utf-8")
    scenario = manifest.split("- id: alert_dedup_dns_repeat", 1)[1].split("\n  - id: ", 1)[0]
    for text in (scenario, patterns):
        assert PLACEHOLDER in text
        domains = re.findall(r"[a-z0-9-]+\.(?:xyz|com|net|org|top|info)\b", text)
        assert domains == [], domains


def test_the_harness_fills_the_placeholder_before_reading_the_manifest():
    fill = RUN_SH.index("live-indicator.py")
    assert fill < RUN_SH.index('SELECTOR_ARGS="$MANIFEST"')
    assert PLACEHOLDER in RUN_SH


def test_the_picker_takes_a_plain_domain_from_the_feed_and_is_stable():
    pick = _picker().pick
    feed = "\n".join([
        "! Title: sample", "[Adblock Plus]", "||bad-example.xyz^", "||sub.other.example^$third-party",
        "||10.0.0.1^", "||xn--80ak6aa92e.com^", "||zz-last.top^", "plain.example",
    ])
    assert pick(feed) == "bad-example.xyz"
    assert pick(feed) == pick(feed)


def test_the_picker_says_so_when_the_feed_has_nothing_usable():
    assert _picker().pick("! only comments\n||10.0.0.1^\n") is None
