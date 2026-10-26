"""Milestone 3: more tools, runner tools ("critical by design"), skipping of missing tools."""
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

import pytest

from gtfo_probe import allowlist, checker, cli, db, detector, fixtures, report, runner, sandbox, spec
from gtfo_probe.cli import _bundled_probe_dir

PH = set(fixtures.PLACEHOLDERS)
ROOT = Path(__file__).parent.parent
NEW_TOOLS = {"gawk", "mawk", "xargs", "env", "sort", "diff", "cat", "head", "tail", "ls", "grep", "cp", "mv",
             "python3", "node", "npm", "npx", "pip", "make", "wget", "ssh", "scp", "rsync", "zip", "unzip", "gzip"}


@pytest.fixture(scope="module")
def probes():
    return spec.load_dir(_bundled_probe_dir(), PH)


# --------------------------------------------------------------------- spec / probes
def test_all_new_tools_are_allowed_and_have_probes(probes):
    assert NEW_TOOLS <= spec.ALLOWED_TOOLS
    assert NEW_TOOLS <= {p.tool for p in probes}


def test_pagers_are_deliberately_not_probed():
    """less/man only misbehave on a terminal; the sandbox has none, so a probe would lie."""
    assert not ({"less", "man", "more"} & spec.ALLOWED_TOOLS)


def test_every_runner_tool_has_a_runner_probe_that_runs_the_canary(probes):
    """The 'critical by design' claim must be backed by evidence, not just by a name in a set."""
    assert spec.RUNNER_TOOLS <= spec.ALLOWED_TOOLS
    for tool in spec.RUNNER_TOOLS:
        assert any(p.tool == tool and spec.RUNNER_TAG in p.tags and "exec" in p.expect for p in probes), tool


def test_runner_tag_only_on_probes_that_expect_an_effect(probes):
    for p in probes:
        if spec.RUNNER_TAG in p.tags:
            assert p.expect, p.id


def test_abbreviation_twins_have_a_base_probe_and_a_different_flag(probes):
    by_id = {p.id: p for p in probes}
    for p in probes:
        if p.id.endswith("-abbrev"):
            base = by_id[p.id[: -len("-abbrev")]]
            assert base.flag != p.flag and base.tool == p.tool, p.id


def test_each_new_tool_has_a_flag_probe_besides_controls(probes):
    for tool in NEW_TOOLS - {"diff", "cat", "head", "tail", "ls", "grep"}:      # these are control-only by design
        assert any(p.tool == tool and p.expect for p in probes), tool


def test_probe_argv_never_uses_a_shell_string(probes):
    """Same safety rule as milestone 1: no shell -c / sh -c anywhere in a probe."""
    for p in probes:
        assert p.tool not in {"sh", "bash", "dash", "zsh"}


# --------------------------------------------------------------------- fixtures / sandbox
def test_new_fixture_files_exist(world):
    for rel in ("data/Makefile", "data/hello.py", "data/hello.js", "data/unsorted.txt", "data/sample.zip",
                "data/sample.txt.gz", "npmpkg/package.json", "pypkg/pyproject.toml", "pypkg/backend.py"):
        assert (world / rel).exists(), rel
    assert "canary-exec" in (world / "data/Makefile").read_text()
    pkg = json.loads((world / "npmpkg/package.json").read_text())
    assert "canary" in pkg["scripts"] and "preinstall" in pkg["scripts"]
    assert "canary-exec" in (world / "pypkg/backend.py").read_text()


def test_every_placeholder_value_points_inside_the_sandbox_root_or_is_the_test_net_url():
    for name, val in fixtures.PLACEHOLDERS.items():
        assert val.startswith(fixtures.SANDBOX_ROOT) or val.startswith("http://192.0.2.1"), name


def test_sandbox_binds_ca_certs_readonly_but_not_ssl_private():
    sb = sandbox.Sandbox("/usr/bin/bwrap")
    cmd = sb.build_command(Path("/tmp/w"), ["true"])
    if Path("/etc/ssl/certs").exists():
        i = cmd.index("/etc/ssl/certs")
        assert cmd[i - 1] == "--ro-bind"
    assert "/etc/ssl/private" not in cmd


# --------------------------------------------------------------------- detector
@pytest.mark.parametrize("text", [
    "npm ERR! code EAI_AGAIN", "Error: connect ENETUNREACH 192.0.9.9:9", "request failed ECONNREFUSED",
    "getaddrinfo ENOTFOUND registry.example", "<urlopen error [Errno 101] Network is unreachable>"])
def test_node_and_python_network_errors_are_detected(text):
    assert detector.find_net_evidence("", text)


def test_unrelated_text_is_not_a_network_error():
    assert not detector.find_net_evidence("hello world", "usage: tool [options]")


# --------------------------------------------------------------------- runner: versions / missing tools
@pytest.mark.sandbox
@pytest.mark.parametrize("tool", ["ssh", "scp", "zip", "unzip", "make", "rsync", "wget", "gawk", "mawk", "node", "npm", "pip"])
def test_version_detection_for_tools_with_unusual_version_flags(sandbox, template, tmp_path, tool):
    if not shutil.which(tool):
        pytest.skip(f"{tool} not installed")
    v = runner.tool_version(sandbox, template, tool, tmp_path)
    assert v is not None and v.startswith(tool + "@") and v != f"{tool}@unknown", v


@pytest.mark.sandbox
def test_missing_tool_is_reported_as_not_installed(sandbox, template, tmp_path):
    assert runner.tool_version(sandbox, template, "gtfo-no-such-tool", tmp_path) is None


@pytest.mark.sandbox
def test_run_all_skips_missing_tools_instead_of_reporting_bogus_mismatches(sandbox):
    real = spec.ProbeSpec(id="sed.print.control", tool="sed", argv=("-n", "p", "<<hello>>"), expect=())
    fake = spec.ProbeSpec(id="gtfo-no-such-tool.x", tool="gtfo-no-such-tool", argv=("a",), expect=("exec",))
    skipped: list[str] = []
    versions, results = runner.run_all(sandbox, [real, fake], skipped=skipped)
    assert skipped == ["gtfo-no-such-tool"]
    assert list(versions) == ["sed"] and [r.probe.id for r in results] == ["sed.print.control"]


# --------------------------------------------------------------------- db
def _res(pid, tool, observed, tags=(), flag=""):
    p = spec.ProbeSpec(id=pid, tool=tool, argv=("a",), expect=tuple(observed), flag=flag, tags=tuple(tags))
    eff = detector.Effects(effects=set(observed), confidence={o: "confirmed" for o in observed},
                           exec_log=["ran"] if "exec" in observed else [])
    return runner.ProbeResult(probe=p, argv=[tool, "a"], effects=eff, returncode=0, timed_out=False,
                              stdout="", stderr="", status="match")


def test_db_marks_runner_tools_and_lists_runner_probes():
    d = db.build_database({"env": "env@9.7", "git": "git@2.47.3"},
                          [_res("env.runner", "env", ["exec"], ["runner"]), _res("git.a", "git", ["exec"], [], "-c")],
                          "bwrap", now=datetime(2026, 1, 1, tzinfo=timezone.utc))
    assert d["tools"]["env@9.7"]["category"] == "runner"
    assert d["tools"]["git@2.47.3"]["category"] == "standard"
    assert [c["probe"] for c in d["tools"]["env@9.7"]["capabilities"]["runner"]] == ["env.runner"]
    assert d["tools"]["git@2.47.3"]["capabilities"]["runner"] == []
    assert d["tools"]["env@9.7"]["probes"][0]["tags"] == ["runner"]
    assert d["schema_version"] == 1                      # additive change: old readers keep working


# --------------------------------------------------------------------- checker: runner tools
def _rec(pid, argv, flag, observed=(), tags=(), ev=None):
    return {"id": pid, "argv": argv, "flag": flag, "observed": list(observed), "description": "d", "tags": list(tags),
            "confidence": {e: "confirmed" for e in observed}, "evidence": ev or {}}


RUN_EV = {"exec_log": ["canary-exec ran"]}
FAKE_DB = {"schema_version": 1, "generated_at": "T", "generator": "t", "tools": {
    "env@9": {"category": "runner", "probes": [
        _rec("env.print.control", ["env"], ""),
        _rec("env.runner", ["env", "<<canary_exec>>"], "", ["exec"], ["runner"], RUN_EV),
        _rec("env.split-string", ["env", "-S", "<<canary_exec>> a"], "-S", ["exec"], ["runner"], RUN_EV),
        _rec("env.odd", ["env", "--odd"], "--odd", ["fs_write"])]},
    "npm@9": {"category": "standard", "probes": [
        _rec("npm.version.baseline", ["npm", "--version"], "", ["fs_write"], ["baseline"],
             {"fs_changes": [{"change": "created", "path": "home/.npm"}]}),
        _rec("npm.ls", ["npm", "ls"], "", ["fs_write"]),
        _rec("npm.run", ["npm", "run", "canary"], "", ["exec", "fs_write"], ["runner"], RUN_EV),
        _rec("npm.run-script", ["npm", "run-script", "canary"], "", ["exec"], ["runner"], RUN_EV),
        _rec("npm.view", ["npm", "view", "x"], "", ["net"])]},
    "gawk@5": {"probes": [_rec("gawk.system", ["gawk", "BEGIN{system()}"], "system()", ["exec"], [], RUN_EV)]},
    "mawk@1": {"probes": [_rec("mawk.system", ["mawk", "BEGIN{system()}"], "system()", ["exec"], [], RUN_EV)]},
    "cat@9": {"probes": [_rec("cat.plain.control", ["cat", "<<hello>>"], "")]},
}}


def chk(line):
    """Check one plain-text allowlist line against FAKE_DB (`env` = prefix, `env $` = exact)."""
    (entry,) = allowlist.parse_pattern(line, "plain", True)
    return checker.check_entry(entry, FAKE_DB)


def test_runner_tool_with_args_is_one_critical_by_design_finding():
    r = chk("env")
    assert r.status == "findings" and len(r.findings) == 1
    f = r.findings[0]
    assert f.by_design and f.severity == "critical" and f.effect == "exec" and f.flag == "" and f.probe == "env.runner"
    assert "no safe flag list" in r.fix                  # the fix talks about runners, not about flags


def test_runner_tool_other_flag_findings_are_subsumed():
    """env's own odd fs_write flag is not listed separately: env can already do everything."""
    assert [f.probe for f in chk("env").findings] == ["env.runner"]


def test_exact_entry_on_runner_tool_is_not_collapsed_and_says_why():
    r = chk("env $")
    assert not any(f.by_design for f in r.findings)
    assert any("runner tool" in n for n in r.notes)


def test_exact_entry_that_pins_a_runner_flag_is_labelled_by_design():
    r = chk("env -S $")
    # (env.runner also matches: its one placeholder word can stand for any single word, which is
    #  the conservative behaviour milestone 2 chose for exact entries)
    assert "env.split-string" in {f.probe for f in r.findings}
    assert all(f.by_design for f in r.findings)


def test_runner_subcommand_of_a_standard_tool_is_critical_but_only_in_scope():
    run = chk("npm run")
    assert any(f.by_design and f.probe == "npm.run" and f.severity == "critical" for f in run.findings)
    assert not any(f.probe in {"npm.run", "npm.run-script"} and not f.by_design for f in run.findings)
    ls = chk("npm ls")
    assert not any(f.by_design for f in ls.findings)     # `npm ls` is not a runner


def test_run_script_alias_is_not_covered_by_a_run_rule():
    """Honest limit: `npm run` and `npm run-script` are separate scopes (no alias table)."""
    r = chk("npm run-script")
    assert any(f.probe == "npm.run" for f in r.findings) is False
    assert any(f.by_design and f.probe == "npm.run-script" for f in r.findings)


def test_baseline_probe_applies_to_every_subcommand_of_the_tool():
    for line in ("npm ls $", "npm ls", "npm view", "npm"):
        r = chk(line)
        assert any(f.probe == "npm.version.baseline" and f.severity == "low" for f in r.findings), line


def test_awk_is_checked_as_gawk_and_mawk():
    r = chk("awk")
    assert {f.tool_version for f in r.findings} == {"gawk@5", "mawk@1"}
    assert any("whichever your system uses" in n for n in r.notes)


def test_reading_tools_say_no_known_risk_and_report_text_admits_reads_are_not_modelled():
    r = chk("cat")
    assert r.status == "no_known_risk"
    text = report.render_text("x", "plain", FAKE_DB, [r])
    assert "READING files" in text


@pytest.mark.parametrize("tool", ["less", "man", "more"])
def test_pagers_are_unknown_with_an_honest_hint(tool):
    r = chk(tool)
    assert r.status == "unknown_tool"
    assert any("only on a terminal" in n and "NOT probe data" in n for n in r.notes)


def test_old_database_without_category_still_works():
    old = {"schema_version": 1, "generated_at": "T", "generator": "t", "tools": {
        "tar@1": {"probes": [_rec("tar.x", ["tar", "-I", "p"], "-I", ["exec"], [], RUN_EV)]}}}
    (entry,) = allowlist.parse_pattern("tar", "plain", True)
    r = checker.check_entry(entry, old)
    assert r.status == "findings" and not r.findings[0].by_design


def test_text_report_labels_runner_findings_and_lists_runner_tools():
    r = chk("env")
    text = report.render_text("x", "plain", FAKE_DB, [r])
    assert "BY DESIGN" in text
    assert "runner tools (critical by design" in text and "env@9" in text


def test_json_report_carries_by_design_flag_and_summary():
    r = chk("env")
    doc = json.loads(report.render_json("x", "plain", FAKE_DB, [r]))
    assert doc["entries"][0]["findings"][0]["by_design"] is True
    assert doc["summary"]["entries_critical_by_design"] == 1


# --------------------------------------------------------------------- committed example DB
EXAMPLE = json.loads((ROOT / "docs/examples/capabilities.json").read_text())


def test_example_db_has_all_new_tools_and_runner_categories():
    names = {k.split("@")[0] for k in EXAMPLE["tools"]}
    assert NEW_TOOLS <= names and {"git", "sed", "find", "tar", "curl"} <= names
    runners = {k.split("@")[0] for k, v in EXAMPLE["tools"].items() if v.get("category") == "runner"}
    assert runners == set(spec.RUNNER_TOOLS)


def test_example_db_every_probe_matched_its_expectation():
    bad = [p["id"] for v in EXAMPLE["tools"].values() for p in v["probes"] if p["status"] != "match"]
    assert bad == []


def test_example_db_probe_count_matches_bundled_probes(probes):
    n = sum(len(v["probes"]) for v in EXAMPLE["tools"].values())
    assert n == len(probes)
