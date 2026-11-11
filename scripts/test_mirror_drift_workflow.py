"""The daily mirror-drift job must find the address the app fetches the OEM-prefix list from.

The job reads that address out of the Kotlin source so it cannot drift from what the app
calls. When the app moved to a shared base address plus a relative path (fetching ioc-data
through the verified manifest), the job's search stopped matching and the job failed every
day from 2026-10-17, so nothing compared the live list with the bundled one. The job only
runs on main (a live check on pull requests is red by design during the safe ordering), so
this test runs the job's address step against the current source on every pull request
that touches either side.
"""
import os
import pathlib
import re
import shutil
import subprocess

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github/workflows/mirror-drift.yml"
STEP_NAME = "Resolve the feed URL from OemPrefixResolver"
SOURCES = (
    "app/src/main/java/com/androdr/ioc/IocDataManifest.kt",
    "app/src/main/java/com/androdr/ioc/OemPrefixResolver.kt",
)


def _step_script() -> str:
    jobs = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]
    steps = jobs["oem-prefix-live-drift"]["steps"]
    return next(s["run"] for s in steps if s.get("name") == STEP_NAME)


def _run_step(workdir: pathlib.Path, tmp_path: pathlib.Path) -> tuple[int, str, str]:
    output = tmp_path / "github_output"
    output.write_text("", encoding="utf-8")
    env = {"PATH": os.environ["PATH"], "GITHUB_OUTPUT": str(output)}
    done = subprocess.run(["bash", "-e", "-c", _step_script()], cwd=workdir, env=env,
                          capture_output=True, text=True, timeout=30, check=False)
    return done.returncode, output.read_text(encoding="utf-8"), done.stdout + done.stderr


def _kotlin_const(path: str, name: str) -> str:
    text = (ROOT / path).read_text(encoding="utf-8")
    match = re.search(rf'const val {name} = "([^"]+)"', text)
    assert match, f"{name} not found in {path}"
    return match.group(1)


def test_the_step_finds_the_address_the_app_fetches(tmp_path):
    code, output, log = _run_step(ROOT, tmp_path)
    assert code == 0, log
    expected = (_kotlin_const(SOURCES[0], "RULES_REPO_BASE_URL")
                + _kotlin_const(SOURCES[1], "PREFIXES_PATH"))
    assert output.strip() == f"url={expected}"
    assert expected.startswith("https://raw.githubusercontent.com/")
    assert expected.endswith("/ioc-data/known-oem-prefixes.yml")


def test_the_step_fails_when_the_address_can_no_longer_be_found(tmp_path):
    work = tmp_path / "repo"
    for source in SOURCES:
        target = work / source
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / source, target)
    resolver = work / SOURCES[1]
    resolver.write_text(resolver.read_text(encoding="utf-8").replace("PREFIXES_PATH", "RENAMED_PATH"),
                        encoding="utf-8")
    code, output, log = _run_step(work, tmp_path)
    assert code != 0
    assert output == ""
    assert "no longer watching anything" in log
