import pytest

from gtfo_probe import fixtures, runner, spec

PH = set(fixtures.PLACEHOLDERS)


@pytest.mark.parametrize("exp,obs,status", [
    ((), set(), "match"),
    (("exec",), {"exec"}, "match"),
    ((), {"fs_write"}, "unexpected_effect"),
    (("exec",), set(), "expected_effect_missing"),
    (("exec",), {"fs_write"}, "mismatch"),
])
def test_classify(exp, obs, status):
    assert runner.classify(exp, obs) == status


def probe(id_, argv, expect):
    return spec.validate({"id": id_, "tool": id_.split(".")[0], "argv": argv, "expect": expect}, PH)


@pytest.mark.sandbox
@pytest.mark.parametrize("p,observed", [
    (probe("git.show.output", ["show", "--output=<<out>>", "HEAD"], ["fs_write"]), {"fs_write"}),
    (probe("find.exec", [".", "-maxdepth", "0", "-exec", "<<canary_exec>>", "{}", ";"], ["exec"]), {"exec"}),
    (probe("curl.url", ["<<url>>"], ["net"]), {"net"}),
    (probe("sed.print", ["-n", "p", "<<hello>>"], []), set()),
])
def test_run_probe_end_to_end(sandbox, template, tmp_path, p, observed):
    r = runner.run_probe(sandbox, template, p, tmp_path)
    assert r.effects.effects == observed and r.status == "match"


@pytest.mark.sandbox
def test_probes_are_isolated_from_each_other(sandbox, template, tmp_path):
    """A probe that deletes a canary must not affect the next probe's world."""
    runner.run_probe(sandbox, template, probe("find.delete", ["<<victim>>", "-delete"], ["fs_write"]), tmp_path)
    r = runner.run_probe(sandbox, template, probe("find.again", ["<<victim>>", "-print"], []), tmp_path)
    assert "victim.txt" in r.stdout and r.status == "match"
    assert (template / "canary" / "victim.txt").exists()


@pytest.mark.sandbox
def test_tool_version(sandbox, template, tmp_path):
    assert runner.tool_version(sandbox, template, "git", tmp_path).startswith("git@2.")
