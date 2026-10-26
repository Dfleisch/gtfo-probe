"""Discovery tests.  Pure logic first (no sandbox), then CLI, then real sandboxed integration."""
import json

import pytest

from gtfo_probe import cli, discover, fixtures, spec
from gtfo_probe.helpparse import Candidate, classify
from gtfo_probe.sandbox import Sandbox, SandboxUnavailable

PH = set(fixtures.PLACEHOLDERS)


def p(id_, argv, expect=("exec",), flag=""):
    return spec.validate({"id": id_, "tool": id_.split(".")[0], "argv": list(argv),
                          "expect": list(expect), "flag": flag}, PH)


# ------------------------------------------------------------------ coverage / dedup
def test_coverage_from_argv_and_flag_field():
    cov = discover.coverage_map([p("tar.a", ["-tf", "<<archive>>", "-I", "<<canary_exec>>"]),
                                 p("sed.w", ["-n", "w <<out>>", "<<hello>>"], flag="w")], "tar")
    flags = {f for (_s, f) in cov}
    assert {"-t", "-f", "-tf", "-I"} <= flags                 # "-tf" is "-t -f" for tar
    assert "w" not in flags                                    # other tools' probes do not leak in
    assert "w" in {f for (_s, f) in discover.coverage_map([p("sed.w", ["-n"], flag="w")], "sed")}


def test_find_single_dash_long_options_are_not_split_into_letters():
    cov = discover.coverage_map([p("find.x", ["<<victim>>", "-exec", "<<canary_exec>>", ";"])], "find")
    assert {f for (_s, f) in cov} == {"-exec"}


def test_covered_by_alias_and_abbreviation():
    cov = discover.coverage_map([p("tar.a", ["-I", "<<canary_exec>>"]), p("sort.b", ["--outp=<<out>>"])], "tar")
    assert discover.covered_by(cov, "", ["-I", "--use-compress-program"]) == "tar.a"     # alias match
    assert discover.covered_by(cov, "", ["--other"]) == ""
    cov = discover.coverage_map([p("sort.b", ["--outp=<<out>>"], expect=("fs_write",))], "sort")
    assert discover.covered_by(cov, "", ["--output"]) == "sort.b"                         # GNU abbreviation
    assert discover.covered_by(cov, "", ["--ou"]) == ""                                    # not the other way round


def test_git_coverage_is_per_subcommand():
    cov = discover.coverage_map([p("git.show.output", ["show", "--output=<<out>>", "HEAD"]),
                                 p("git.status.fs", ["-c", "core.fsmonitor=<<canary_exec>>", "status"])], "git")
    assert discover.covered_by(cov, "show", ["--output"]) == "git.show.output"
    assert discover.covered_by(cov, "log", ["--output"]) == ""        # same flag, other subcommand: not covered
    assert discover.covered_by(cov, "status", ["-c"]) == "git.status.fs"


def test_bundled_probes_cover_known_flags():
    probes = spec.load_dir(cli._bundled_probe_dir(), PH)
    tar = discover.coverage_map(probes, "tar")
    assert discover.covered_by(tar, "", ["-I", "--use-compress-program"]).startswith("tar.")
    assert discover.covered_by(discover.coverage_map(probes, "sed"), "", ["w"]) == "sed.w-command"


# ----------------------------------------------------------- argv building / selection
def test_flag_argv_shapes():
    long_ = Candidate(names=["-I", "--use-compress-program"], arg="required", metavar="PROG")
    assert discover.flag_argv(long_, "<<canary_exec>>") == ["--use-compress-program=<<canary_exec>>"]
    short = Candidate(names=["-o"], arg="required")
    assert discover.flag_argv(short, "<<out>>") == ["-o", "<<out>>"]
    ex = Candidate(names=["-exec"], arg="required", terminator=";")
    assert discover.flag_argv(ex, "<<canary_exec>>") == ["-exec", "<<canary_exec>>", ";"]
    assert discover.flag_argv(Candidate(names=["--delete"]), None) == ["--delete"]
    seed = Candidate(names=["w"], source="seed", full_argv=["-n", "w <<out>>"])
    assert discover.flag_argv(seed, "ignored") == ["-n", "w <<out>>"]


def test_values_follow_hints_and_never_use_url_unless_hinted():
    c = classify(Candidate(names=["--log"], arg="required", metavar="FILE"))
    vals = discover._values(c)
    assert vals[0] == "<<out>>" and "<<url>>" not in vals        # url false-positives are avoided
    c = classify(Candidate(names=["--url"], arg="required", metavar="URL"))
    assert discover._values(c)[0] == "<<url>>"
    opt = classify(Candidate(names=["-i"], arg="optional", metavar="SUFFIX", text="edit files in place"))
    assert discover._values(opt)[0] is None                       # optional argument: bare flag first


def test_select_skips_hintless_and_help_flags_and_caps():
    cands = [classify(Candidate(names=["--delete"], text="delete files")),
             classify(Candidate(names=["--ignore-case"])),
             classify(Candidate(names=["--version"], text="output version information"))]
    cands += [classify(Candidate(names=[f"--out{i}"], arg="required", metavar="FILE")) for i in range(5)]
    chosen, not_selected, over = discover.select(cands, discover.Limits(max_candidates=3))
    assert len(chosen) == 3 and over == 3                        # the cap, reported
    assert not_selected == 1                                      # --ignore-case had no hint
    assert all("--version" not in c.names for c in chosen)       # help/version never tested
    everything, ns, _ = discover.select(cands, discover.Limits(select="all", max_candidates=50))
    assert ns == 0 and any("--ignore-case" in c.names for c in everything)


def test_seeds_come_first():
    seed = Candidate(names=["w"], source="seed", full_argv=["x"], hints=["fs_write"])
    chosen, _, _ = discover.select([classify(Candidate(names=["--delete"], text="delete")), seed], discover.Limits())
    assert chosen[0].source == "seed"


def test_bases_for_git_subcommands_stop_optional_locks():
    prefix, suffix = discover.bases_for("git", "show")[0]
    assert "--no-optional-locks" in prefix and suffix == ["HEAD"]
    assert discover.bases_for("git", "branch")[0][0] == ["--no-optional-locks", "branch"]   # unknown sub: generic


# ------------------------------------------------------------------ safety rules
def test_tool_outside_allowlist_is_refused_before_anything_runs():
    class Boom:
        def run(self, *a, **k):
            raise AssertionError("must not run anything")
    with pytest.raises(spec.SpecError):
        discover.discover_tool(Boom(), "rm", [])


def test_discovery_cannot_run_in_an_unverified_sandbox():
    sb = Sandbox("/usr/bin/bwrap")                               # never preflighted
    with pytest.raises(SandboxUnavailable):
        discover.discover_tool(sb, "tar", [])


def test_lab_builds_probes_with_validate_so_unknown_placeholders_fail(tmp_path):
    lab = discover._Lab(None, tmp_path, tmp_path, "tar", 1.0)
    with pytest.raises(spec.SpecError):
        lab.run(["--evil=<<not_a_placeholder>>"])


# ------------------------------------------------------------------ apply / files
def finding(names, effects=("exec",), known="", conf="confirmed", reproduced=True, source="help", sub=""):
    return discover.Finding(names=names, sub=sub, source=source, hints=[], status="effect",
                            argv=["tar", "--x=<<canary_exec>>", "-tf", "<<archive>>"], effects=list(effects),
                            confidence={e: conf for e in effects}, reproduced=reproduced, known=known)


def report(*findings):
    return discover.DiscoveryReport(tool="tar", version="tar@1.35", findings=list(findings))


def test_confirmed_requires_reproduction_and_a_confirmed_effect():
    assert finding(["--a"]).confirmed
    assert not finding(["--a"], reproduced=False).confirmed
    assert not finding(["--a"], effects=("net",), conf="attempted").confirmed       # net text is only a clue


def test_build_probe_dicts_only_new_confirmed_and_labelled():
    r = report(finding(["--new"]), finding(["--old"], known="tar.old"), finding(["--maybe"], reproduced=False))
    out = discover.build_probe_dicts(r, set())
    assert [d["flag"] for d in out] == ["--new"]
    d = out[0]
    assert d["id"] == "tar.disc.new" and "discovered" in d["tags"] and d["description"].startswith("[discovered]")
    spec.validate(d, PH)                                                            # loads like any probe


def test_slug_handles_uppercase_and_collisions():
    r = report(finding(["-I"]), finding(["-i"]), finding(["--same"]), finding(["--same"]))
    ids = [d["id"] for d in discover.build_probe_dicts(r, set())]
    assert len(set(ids)) == 4 and "tar.disc.cap-i" in ids


def test_write_discovered_merges_and_is_idempotent(tmp_path):
    out = tmp_path / "tar.discovered.json"
    assert discover.write_discovered(report(finding(["--a"])), out, set()) == (1, 1)
    data = json.loads(out.read_text())
    assert "discovery" in data and spec.load_file(out, PH)[0].tags == ("discovered",)
    assert discover.write_discovered(report(finding(["--b"])), out, set()) == (1, 2)    # extends, keeps --a
    assert discover.write_discovered(report(), out, set()) == (0, 2)


def test_write_discovered_refuses_to_overwrite_hand_written_files(tmp_path):
    hand = tmp_path / "tar.json"
    hand.write_text(json.dumps({"probes": []}))
    with pytest.raises(discover.DiscoverError):
        discover.write_discovered(report(finding(["--a"])), hand, set())
    assert json.loads(hand.read_text()) == {"probes": []}                           # untouched
    bad = tmp_path / "bad.json"
    bad.write_text("not json")
    with pytest.raises(discover.DiscoverError):
        discover.write_discovered(report(finding(["--a"])), bad, set())


def test_render_text_is_honest_about_unconfirmed_and_known():
    r = report(finding(["-I", "--use-compress-program"], known="tar.use-compress-program"),
               finding(["--netty"], effects=("net",), conf="attempted"))
    text = discover.render_text(r)
    assert "CONFIRMED" in text and "known: tar.use-compress-program" in text
    assert "NOT confirmed" in text and "net=attempted" in text


# ----------------------------------------------------------------------- CLI
def test_cli_needs_exactly_one_of_tool_or_all(capsys):
    assert cli.main(["discover"]) == 2
    assert cli.main(["discover", "tar", "--all"]) == 2


def test_cli_unknown_tool_is_a_spec_error(capsys):
    assert cli.main(["discover", "rm"]) == 3
    assert "allowlist" in capsys.readouterr().err


def test_cli_refuses_without_sandbox(monkeypatch, capsys):
    def boom():
        raise SandboxUnavailable("no bwrap")
    monkeypatch.setattr(cli, "_verified_sandbox", boom)
    assert cli.main(["discover", "tar"]) == 2
    assert "refusing to run" in capsys.readouterr().err


def test_cli_report_only_writes_nothing(sandbox, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert cli.main(["discover", "sed"]) == 0
    assert "report only" in capsys.readouterr().out
    assert list(tmp_path.iterdir()) == []


# ------------------------------------------------------ integration (real sandbox)
@pytest.fixture(scope="module")
def tar_report(sandbox):
    probes = spec.load_dir(cli._bundled_probe_dir(), PH)
    return discover.discover_tool(sandbox, "tar", probes)


@pytest.mark.sandbox
def test_discovers_tar_use_compress_program_from_help(tar_report):
    """The flag is found by PARSING THE HELP PAGE, then proved by running it (not a hand probe)."""
    f = next(f for f in tar_report.findings if "-I" in f.names and f.source == "help")
    assert f.confirmed and f.effects == ["exec"] and f.confidence["exec"] == "confirmed"
    assert "canary-exec ran" in f.evidence["exec_log"][0]
    assert f.known.startswith("tar.")                                  # and dedup knows we already had it


@pytest.mark.sandbox
def test_discovery_finds_something_new_but_not_everything(tar_report):
    confirmed = {f.primary_name for f in tar_report.findings if f.confirmed}
    assert "--delete" in confirmed or "--append" in confirmed          # writes tar's hand probes never tried
    # honest limit: tar has more dangerous behaviour than discovery proves; many tested flags show nothing
    assert any(f.status == "no_effect" for f in tar_report.findings)
    assert tar_report.not_selected > 0


@pytest.mark.sandbox
def test_sed_seeds_find_w_and_e_which_help_text_cannot_show(sandbox):
    probes = spec.load_dir(cli._bundled_probe_dir(), PH)
    rep = discover.discover_tool(sandbox, "sed", probes)
    seeds = {f.names[0]: f for f in rep.findings if f.source == "seed"}
    assert seeds["w"].effects == ["fs_write"] and seeds["e"].effects == ["exec"]
    assert all(f.known for f in seeds.values())


@pytest.mark.sandbox
def test_control_flags_show_no_effect(sandbox):
    probes = spec.load_dir(cli._bundled_probe_dir(), PH)
    rep = discover.discover_tool(sandbox, "sort", probes, limits=discover.Limits(select="all"))
    quiet = {f.primary_name for f in rep.findings if f.status != "effect"}
    assert {"--reverse", "--numeric-sort", "--unique"} <= quiet          # harmless flags are not accused


@pytest.mark.sandbox
def test_missing_companion_is_a_miss_not_a_false_claim(sandbox):
    """Without sort's merge scaffold, --compress-program shows nothing: discovery must say so, not guess."""
    probes = spec.load_dir(cli._bundled_probe_dir(), PH)
    saved = discover.BASES["sort"]
    discover.BASES["sort"] = [([], ["<<unsorted>>"])]
    try:
        rep = discover.discover_tool(sandbox, "sort", probes)
    finally:
        discover.BASES["sort"] = saved
    f = next(f for f in rep.findings if "--compress-program" in f.names)
    assert f.status == "no_effect" and not f.confirmed


@pytest.mark.sandbox
def test_baseline_effects_are_not_blamed_on_the_flag(sandbox, template, tmp_path):
    """`tar -xf` writes by itself; `--verbose` on top must not be reported as a writer."""
    lab = discover._Lab(sandbox, template, tmp_path, "tar", 3.0)
    base = ([], ["-xf", "<<archive>>"])
    assert "fs_write" in lab.baseline(base)
    f = discover.probe_candidate(lab, Candidate(names=["--verbose"], hints=["fs_write"], arg="none"))
    assert f.status != "effect"


@pytest.mark.sandbox
def test_apply_end_to_end_and_probes_replay(sandbox, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    # find.fprint0 was promoted to a reviewed hand probe (docs/REVIEW-discovered.md), so bundled
    # find has nothing NEW left.  Use a copy of the bundled probes WITHOUT it as "already covered",
    # so discovery still has one real NEW finding to apply.
    covered = tmp_path / "covered"
    covered.mkdir()
    for f in sorted(cli._bundled_probe_dir().glob("*.json")):
        d = json.loads(f.read_text())
        d["probes"] = [p for p in d["probes"] if p["id"] != "find.fprint0"]
        (covered / f.name).write_text(json.dumps(d))
    assert cli.main(["discover", "find", "--apply", "--probes", str(covered)]) == 0
    out = tmp_path / "probes" / "find.discovered.json"
    new = spec.load_file(out, PH)
    assert new and all("discovered" in n.tags and ".disc." in n.id for n in new)
    # the saved probes replay as expected through the normal `run` path
    db_out = tmp_path / "c.json"
    assert cli.main(["run", "--probes", str(out.parent), "--out", str(db_out), "--strict"]) == 0
    capsys.readouterr()
    # second apply: nothing new, file unchanged
    before = out.read_text()
    assert cli.main(["discover", "find", "--apply", "--probes", str(covered)]) == 0
    assert out.read_text() == before


@pytest.mark.sandbox
def test_tool_not_installed_is_reported_not_crashed(sandbox, monkeypatch):
    monkeypatch.setattr(discover.runner, "tool_version", lambda *a, **k: None)
    rep = discover.discover_tool(sandbox, "tar", [])
    assert rep.version is None and "not installed" in discover.render_text(rep)


@pytest.mark.sandbox
def test_time_budget_is_enforced(sandbox):
    rep = discover.discover_tool(sandbox, "tar", [], limits=discover.Limits(max_seconds=0.0))
    assert rep.budget_exhausted and len(rep.findings) == 0


# ----------------------------------------------- false-positive guards (no sandbox needed)
class _FakeResult:
    def __init__(self, effects, conf, stderr="", timed_out=False):
        from gtfo_probe.detector import Effects
        self.effects = Effects(effects=set(effects), confidence=dict(conf))
        self.stderr, self.timed_out = stderr, timed_out

    def to_dict(self):
        return {"evidence": {}}


class _FakeLab:
    """Stands in for the sandbox: returns canned results by argv, records what was asked."""
    tool = "curl"

    def __init__(self, answers):
        self.answers, self.calls = answers, []

    def baseline(self, base):
        return set()

    def run(self, argv):
        self.calls.append(argv)
        return self.answers(argv)


def test_rejected_command_line_echoing_our_canary_url_is_not_a_net_finding():
    """Real false positive from curl: 'option --data=http://192.0.2.1...: is unknown' matched the net heuristic."""
    def answers(argv):
        if any(a.startswith("--data=") for a in argv):
            return _FakeResult({"net"}, {"net": "attempted"}, "curl: option --data=http://192.0.2.1:9/x: is unknown")
        return _FakeResult(set(), {}, "")
    lab = _FakeLab(answers)
    f = discover.probe_candidate(lab, classify(Candidate(names=["-d", "--data"], arg="required", metavar="URL")))
    assert f.status != "effect"
    assert ["--data", "<<url>>"] in [c[:2] for c in lab.calls]       # it retried with the two-word spelling


def test_confirmed_effects_still_count_even_when_the_tool_complained():
    lab = _FakeLab(lambda argv: _FakeResult({"fs_write"}, {"fs_write": "confirmed"}, "unknown option -z"))
    f = discover.probe_candidate(lab, classify(Candidate(names=["--output"], arg="required", metavar="FILE")))
    assert f.status == "effect" and f.confirmed


def test_flaky_effect_that_does_not_reproduce_is_not_confirmed():
    runs = iter([_FakeResult({"exec"}, {"exec": "confirmed"}), _FakeResult(set(), {})])
    lab = _FakeLab(lambda argv: next(runs))
    f = discover.probe_candidate(lab, classify(Candidate(names=["--x"], hints=["exec"])))
    assert f.status == "effect" and f.reproduced is False and not f.confirmed


def test_all_spellings_rejected_is_reported_as_rejected():
    lab = _FakeLab(lambda argv: _FakeResult(set(), {}, "tar: unrecognized option '--bogus'"))
    f = discover.probe_candidate(lab, classify(Candidate(names=["--bogus"], arg="required", metavar="FILE")))
    assert f.status == "rejected"


@pytest.mark.sandbox
def test_curl_needs_its_file_url_scaffold_and_has_no_false_net_finding(sandbox):
    probes = spec.load_dir(cli._bundled_probe_dir(), PH)
    rep = discover.discover_tool(sandbox, "curl", probes)
    by = {f.primary_name: f for f in rep.findings}
    assert by["--output"].confirmed and by["--output"].known.startswith("curl.")
    # `--data` etc. must not be accused of network use just because an error message echoed our URL
    assert by["--data"].status != "effect"
