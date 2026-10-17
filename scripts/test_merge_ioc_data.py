import importlib.util, json, pathlib, textwrap
HERE = pathlib.Path(__file__).parent
spec = importlib.util.spec_from_file_location("m", HERE / "merge-ioc-data.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


def repo(tmp_path):
    d = tmp_path / "rules" / "ioc-data"; d.mkdir(parents=True)
    (d / "c2-domains.yml").write_text(textwrap.dedent("""
        entries:
        - indicator: forti.external-muki.com
          family: Graphite (Paragon)
          category: NATION_STATE_SPYWARE
          campaign: graphite
          severity: CRITICAL
          source: threat_research
          reference: https://citizenlab.ca/x
    """))
    for f in ["package-names.yml", "cert-hashes.yml", "malware-hashes.yml"]:
        (d / f).write_text("entries: []\n")
    (d / "campaigns.yml").write_text("campaigns:\n- key: graphite\n  label: Graphite (Paragon)\n  aliases: [paragon]\n  references: []\n")
    return tmp_path / "rules"


def test_generates_campaign_vocabulary(tmp_path):
    out = tmp_path / "raw"; out.mkdir()
    m.generate(repo(tmp_path), out)
    assert json.loads((out / "known_campaigns.json").read_text()) == [
        {"key": "graphite", "label": "Graphite (Paragon)", "aliases": ["paragon"]}]


def test_generates_attributed_domain_list(tmp_path):
    out = tmp_path / "raw"; out.mkdir()
    m.generate(repo(tmp_path), out)
    doms = json.loads((out / "known_bad_domains.json").read_text())
    assert doms == [{"domain": "forti.external-muki.com", "familyName": "Graphite (Paragon)",
                     "category": "NATION_STATE_SPYWARE", "campaign": "graphite", "severity": "CRITICAL",
                     "description": "", "source": "threat_research", "reference": "https://citizenlab.ca/x",
                     "blockByDefault": False}]


def test_check_detects_hand_edit(tmp_path):
    out = tmp_path / "raw"; out.mkdir()
    r = repo(tmp_path)
    m.generate(r, out)
    assert m.check(r, out) == []
    data = json.loads((out / "known_bad_domains.json").read_text())
    data.append({"domain": "candiru-c2.xyz"})
    (out / "known_bad_domains.json").write_text(json.dumps(data))
    assert m.check(r, out) == ["known_bad_domains.json"]


def test_removed_entries_disappear(tmp_path):
    out = tmp_path / "raw"; out.mkdir()
    r = repo(tmp_path)
    m.generate(r, out)
    (r / "ioc-data" / "c2-domains.yml").write_text("entries: []\n")
    m.generate(r, out)
    assert json.loads((out / "known_bad_domains.json").read_text()) == []


REPO_ROOT = HERE.parent


def test_bundle_ci_filter_covers_every_input():
    """The bundle gate must run when its workflow or its pinned requirements change (final review item 5)."""
    import yaml
    jobs = yaml.safe_load((REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text())["jobs"]
    bundle = yaml.safe_load(jobs["changes"]["steps"][1]["with"]["filters"])["bundle"]
    for path in (".github/workflows/ci.yml", "scripts/requirements-ci.in", "scripts/requirements-ci.txt",
                 "scripts/merge-ioc-data.py", "scripts/test_merge_ioc_data.py"):
        assert path in bundle, f"{path} missing from the bundle path filter"


def test_no_compiled_python_is_tracked():
    """Bytecode is ignored (.gitignore) and must not be committed (final review item 4)."""
    import subprocess
    tracked = subprocess.run(["git", "ls-files", "*.pyc", "**/__pycache__/**"], cwd=REPO_ROOT,
                             capture_output=True, text=True, check=True).stdout.split()
    assert tracked == [], f"compiled Python is tracked: {tracked}"


def test_campaign_vocabulary_carries_detected_by(tmp_path):
    root = repo(tmp_path)
    (root / "ioc-data" / "campaigns.yml").write_text(
        "campaigns:\n- key: graphite\n  label: Graphite (Paragon)\n  aliases: [paragon]\n"
        "  detected_by: [dns_monitor]\n  references: []\n")
    out = tmp_path / "raw"; out.mkdir()
    m.generate(root, out)
    assert json.loads((out / "known_campaigns.json").read_text()) == [
        {"key": "graphite", "label": "Graphite (Paragon)", "aliases": ["paragon"], "detected_by": ["dns_monitor"]}]
