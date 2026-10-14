"""Lint test: pipeline conventions that each broke once (2026-10-14 review).

Every assertion here pins a mistake that was fixed, per the CLAUDE.md
regression policy:

- a stale dependency-review base-ref pin reported main's own later
  dependency changes as PR deltas and blocked #385;
- a skill-only edit to update-rules-discover.md never ran the exact-URL
  lock because the file sat outside the CI python bucket;
- rule-ID allocation read `git log` on the checked-out branch only and
  declared IDs live on an unmerged branch (102-107) "dead";
- the top-N NEVER rule was duplicated;
- new pipeline scripts shipped without a trailing newline.
"""
import pathlib
import re

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[3]
CI_PATH = ROOT / ".github" / "workflows" / "ci.yml"
DISPATCHER_PATH = ROOT / ".claude" / "commands" / "update-rules.md"
SCRIPTS_DIR = pathlib.Path(__file__).resolve().parent


def _ci():
    return yaml.safe_load(CI_PATH.read_text())


def _change_filters():
    for step in _ci()["jobs"]["changes"]["steps"]:
        if "paths-filter" in step.get("uses", ""):
            return yaml.safe_load(step["with"]["filters"])
    raise AssertionError("no paths-filter step in the changes job")


def test_dependency_review_has_no_pinned_refs():
    steps = _ci()["jobs"]["dependency-review"]["steps"]
    review = [s for s in steps if "dependency-review-action" in s.get("uses", "")]
    assert len(review) == 1, "expected exactly one dependency-review-action step"
    pinned = sorted(set(review[0].get("with", {})) & {"base-ref", "head-ref"})
    assert not pinned, (
        f"dependency-review pins {pinned}: a pinned base goes stale and "
        "reports main's own dependency changes as PR deltas"
    )


def test_python_bucket_covers_discover_skill():
    python_bucket = _change_filters()["python"]
    assert ".claude/commands/update-rules-discover.md" in python_bucket, (
        "a discover-skill-only edit must trigger the exact-URL lock test"
    )


def _list_items(section):
    """Split markdown into list items with whitespace collapsed, so a
    semantics-preserving rewrap never changes what the tests see."""
    items = re.split(r"\n(?=\s*(?:-|\d+\.) )", section)
    return [" ".join(item.split()) for item in items]


def test_rule_id_allocation_scans_all_refs():
    text = DISPATCHER_PATH.read_text()
    step1 = text[text.index("## Step 1:"):text.index("## Step 2")]
    alloc = [i for i in _list_items(step1) if "next available rule ID" in i]
    assert len(alloc) == 1, "Step 1 must state the rule-ID allocation exactly once"
    assert "git log --all" in alloc[0], (
        "rule-ID allocation must scan every ref (git log --all) so IDs on "
        "unmerged branches are never reused"
    )
    assert "retired-rule-ids.txt" in alloc[0]


def test_top_n_never_rule_stated_once():
    hits = [i for i in _list_items(DISPATCHER_PATH.read_text())
            if i.startswith("- NEVER dispatch") and "discovery pass" in i
            and "top-N" in i]
    assert len(hits) == 1, f"top-N NEVER rule appears {len(hits)} times"


def test_pipeline_scripts_end_with_newline():
    missing = [p.name for p in sorted(SCRIPTS_DIR.glob("*.py"))
               if p.read_bytes() and not p.read_bytes().endswith(b"\n")]
    assert not missing, f"missing trailing newline: {missing}"
