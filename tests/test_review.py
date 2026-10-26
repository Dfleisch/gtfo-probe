"""Promoted discovered findings stay tied to their review (docs/REVIEW-discovered.md)."""
import json
import re
from pathlib import Path

from gtfo_probe import cli, fixtures, spec

ROOT = Path(__file__).parent.parent
REVIEW = (ROOT / "docs" / "REVIEW-discovered.md").read_text()
DB = json.loads((ROOT / "docs" / "examples" / "capabilities.json").read_text())
PROBES = spec.load_dir(cli._bundled_probe_dir(), set(fixtures.PLACEHOLDERS))


def _rows():
    return [r for r in REVIEW.splitlines() if re.match(r"^\| \d+ \|", r)]


def test_review_table_covers_all_17_with_a_verdict():
    rows = _rows()
    assert len(rows) == 17
    verdicts = [r.split("|")[4].strip() for r in rows]
    assert all(re.match(r"^\*\*(promote|reject|needs-more-work)", v) for v in verdicts), verdicts
    assert sum(v.startswith("**promote") for v in verdicts) == 15
    assert sum(v.startswith("**reject") for v in verdicts) == 2


def test_every_discovered_probe_is_reviewed_and_documented():
    disc = [p for p in PROBES if "discovered" in p.tags]
    assert len(disc) == 17                       # 15 promoted findings + 2 abbreviation twins
    for p in disc:
        assert "reviewed" in p.tags, p.id
        assert f"`{p.id}`" in REVIEW, p.id
        assert p.expect, f"{p.id}: a promoted finding must expect an effect"
        assert ".disc." not in p.id              # promoted to hand-probe naming


def test_promoted_findings_are_confirmed_in_the_example_db():
    probes = {pr["id"]: pr for t in DB["tools"].values() for pr in t["probes"]}
    for p in (p for p in PROBES if "discovered" in p.tags):
        got = probes[p.id]
        assert got["status"] == "match", p.id
        assert all(got["confidence"].get(e) in ("confirmed", "attempted") for e in p.expect), p.id


def test_pip_python_runs_a_program_and_is_critical_evidence():
    probes = {pr["id"]: pr for t in DB["tools"].values() for pr in t["probes"]}
    ev = probes["pip.python"]["evidence"]["exec_log"]
    assert ev and "canary-exec ran" in ev[0]


def test_rejected_findings_did_not_become_probes():
    ids = {p.id for p in PROBES}
    flags = {(p.tool, p.flag) for p in PROBES}
    assert ("python3", "-i") not in flags
    assert ("node", "--trace-event-categories") not in flags
    assert not any(".disc." in i for i in ids)
