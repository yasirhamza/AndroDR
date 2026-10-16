"""Pins run.sh's IOC-seeding SQL to the app's Room schema.

Schema 19 renamed the `indicators` columns (name/campaign -> family/category/
campaignKey/reference) and an earlier migration dropped `cert_hash_ioc_entries`.
run.sh's INSERTs still used the old layout, and their errors went to /dev/null, so
mercenary_cert_hash seeded nothing and failed on the device for setup reasons that
no CI check could see. These tests read the INSERTs out of run.sh and check them
against the exported schema JSON, so the next schema change fails here instead.
"""

import json
import re
from pathlib import Path

import pytest

HERE = Path(__file__).parent
REPO = HERE.parent
RUN_SH = HERE / "run.sh"
SCHEMA_DIR = REPO / "app" / "schemas" / "com.androdr.data.db.AppDatabase"
SANITIZER = REPO / "app" / "src" / "main" / "java" / "com" / "androdr" / "ioc" / "IocSanitizer.kt"

INSERT_RE = re.compile(r"INSERT\s+OR\s+REPLACE\s+INTO\s+(\w+)\s*\(([^)]*)\)\s*VALUES\s*\(")


def latest_schema():
    versions = sorted(SCHEMA_DIR.glob("*.json"), key=lambda p: int(p.stem))
    return json.loads(versions[-1].read_text())


def entities(schema):
    return {e["tableName"]: e for e in schema["database"]["entities"]}


def inserts(text):
    """(table, [columns], [raw values]) for every INSERT OR REPLACE in the text."""
    out = []
    text = text.replace("\\\n", " ")  # join shell line continuations
    for m in INSERT_RE.finditer(text):
        cols = [c.strip() for c in m.group(2).replace("\\", " ").split(",") if c.strip()]
        rest = text[m.end():]
        # The tuple ends at the first ");" -- the closing ")" of $(date +%s000) is
        # followed by ")" then ";", so this keeps the date substitution whole.
        values = [v.strip() for v in rest[: rest.index(");")].replace("\\", " ").split(",")]
        out.append((m.group(1), cols, values))
    return out


def check(text, schema):
    """Problems with text's INSERTs against schema; empty when they match."""
    tables = entities(schema)
    found = inserts(text)
    if not found:
        return ["no INSERT OR REPLACE found in run.sh"]
    problems = []
    for table, cols, values in found:
        if table not in tables:
            problems.append(f"table {table!r} is not in the schema")
            continue
        fields = {f["columnName"]: f for f in tables[table]["fields"]}
        unknown = [c for c in cols if c not in fields]
        if unknown:
            problems.append(f"{table}: unknown column(s) {unknown}")
        required = [n for n, f in fields.items() if f.get("notNull") and "defaultValue" not in f]
        missing = [n for n in required if n not in cols]
        if missing:
            problems.append(f"{table}: NOT NULL column(s) not supplied {missing}")
        if len(values) != len(cols):
            problems.append(f"{table}: {len(cols)} columns but {len(values)} values")
    return problems


def test_run_sh_seeding_matches_the_latest_schema():
    problems = check(RUN_SH.read_text(), latest_schema())
    assert not problems, problems


def test_the_latest_schema_is_19_or_later():
    # Guards the glob above: a renamed schema directory must not leave the check empty.
    assert latest_schema()["formatVersion"] and int(sorted(
        SCHEMA_DIR.glob("*.json"), key=lambda p: int(p.stem))[-1].stem) >= 19


def test_seeded_category_is_one_the_sanitizer_keeps():
    # IocSanitizer drops an unknown category to "" on feed rows; a seed row should
    # look like a real feed row, so its category must be in the same enum.
    allowed = set(re.findall(r'"([A-Z_]+)"', re.search(
        r"CATEGORIES\s*=\s*setOf\(([^)]*)\)", SANITIZER.read_text()).group(1)))
    for table, cols, values in inserts(RUN_SH.read_text()):
        if table == "indicators" and "category" in cols:
            assert values[cols.index("category")].strip("'") in allowed


PRE_19_REGRESSION = """
    $ADB shell "run-as com.androdr.debug sqlite3 $db_path \\
        \\"INSERT OR REPLACE INTO indicators \\
        (type, value, name, campaign, severity, description, source, fetchedAt) \\
        VALUES ('cert_hash', '$cert_hash', 'Test Fixture', 'TEST', 'CRITICAL', \\
        'Adversary simulation test cert', 'adversary-test', $(date +%s000));\\"" 2>/dev/null
"""

PRE_19_LOAD = """
    \\"INSERT OR REPLACE INTO cert_hash_ioc_entries \\
    (certHash, familyName, category, severity, description, source, fetchedAt) \\
    VALUES ('$cert_hash', 'Test Fixture', 'TEST', 'CRITICAL', \\
    'Adversary simulation test cert', 'adversary-test', $(date +%s000));\\""
"""


@pytest.mark.parametrize("old, expected", [
    (PRE_19_REGRESSION, "unknown column(s) ['name', 'campaign']"),
    (PRE_19_LOAD, "table 'cert_hash_ioc_entries' is not in the schema"),
])
def test_the_check_rejects_the_pre_19_inserts(old, expected):
    """The two INSERTs run.sh carried before this fix: both must fail the check."""
    problems = check(old, latest_schema())
    assert any(expected in p for p in problems), problems
