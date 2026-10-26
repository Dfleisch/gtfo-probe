import json
from datetime import datetime, timezone

import pytest

from gtfo_probe import db, detector, runner, spec


def fake_result(pid, tool, expect, observed, flag="--x"):
    p = spec.ProbeSpec(id=pid, tool=tool, argv=("a",), expect=tuple(expect), flag=flag)
    eff = detector.Effects(effects=set(observed), confidence={o: "confirmed" for o in observed})
    return runner.ProbeResult(probe=p, argv=[tool, "a"], effects=eff, returncode=0,
                              timed_out=False, stdout="", stderr="",
                              status=runner.classify(tuple(expect), set(observed)))


def build():
    results = [fake_result("git.a", "git", ["fs_write"], ["fs_write"], "--output"),
               fake_result("git.b", "git", [], []),
               fake_result("sed.c", "sed", ["exec"], ["exec"], "e")]
    return db.build_database({"git": "git@2.47.3", "sed": "sed@4.9"}, results, "bubblewrap 0.12.0",
                             now=datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc))


def test_structure_and_capability_summary():
    d = build()
    assert d["schema_version"] == 1 and d["generated_at"] == "2026-01-02T03:04:05Z"
    assert d["sandbox"]["network"] == "none"
    git = d["tools"]["git@2.47.3"]
    assert git["capabilities"]["fs_write"] == [
        {"probe": "git.a", "flag": "--output", "confidence": "confirmed"}]
    assert git["capabilities"]["exec"] == [] and len(git["probes"]) == 2
    assert d["tools"]["sed@4.9"]["capabilities"]["exec"][0]["probe"] == "sed.c"


def test_write_and_load_roundtrip(tmp_path):
    p = tmp_path / "caps.json"
    db.write_database(build(), p)
    assert json.loads(p.read_text()) == db.load_database(p)
    assert p.read_text().endswith("\n")


def test_output_is_deterministic():
    assert json.dumps(build(), sort_keys=True) == json.dumps(build(), sort_keys=True)


def test_load_rejects_wrong_schema(tmp_path):
    p = tmp_path / "x.json"
    p.write_text(json.dumps({"schema_version": 99}))
    with pytest.raises(ValueError):
        db.load_database(p)
