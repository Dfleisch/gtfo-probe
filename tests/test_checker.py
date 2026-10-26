"""Checker logic against a tiny hand-made DB (no sandbox, no real tools needed)."""
import json
from pathlib import Path

import pytest

from gtfo_probe import allowlist, checker, report
from gtfo_probe.allowlist import parse_pattern


def probe(pid, argv, flag, observed=(), conf=None, ev=None, desc="d"):
    return {"id": pid, "argv": argv, "flag": flag, "observed": list(observed), "description": desc,
            "confidence": conf or {e: "confirmed" for e in observed}, "evidence": ev or {}}


DB = {
    "schema_version": 1, "generated_at": "T", "generator": "test",
    "tools": {
        "git@9.9": {"probes": [
            probe("git.show.control", ["git", "show", "HEAD"], ""),
            probe("git.show.output", ["git", "show", "--output=<<out>>", "HEAD"], "--output", ["fs_write"],
                  ev={"fs_changes": [{"change": "created", "path": "out/x"}]}),
            probe("git.show.output-abbrev", ["git", "show", "--outpu=<<out>>", "HEAD"], "--outpu"),
            probe("git.ls-remote.upload-pack", ["git", "ls-remote", "--upload-pack=<<canary_exec>>", "<<repo>>"],
                  "--upload-pack", ["exec"], ev={"exec_log": ["ran"]}),
            probe("git.ls-remote.upload-pack-abbrev", ["git", "ls-remote", "--upload-pa=<<canary_exec>>", "<<repo>>"],
                  "--upload-pa", ["exec"]),
            probe("git.status.config-fsmonitor", ["git", "-c", "core.fsmonitor=<<canary_exec>>", "status"],
                  "-c", ["exec"]),
            probe("git.status.plain", ["git", "status"], "", ["fs_write"]),
        ]},
        "find@1.0": {"probes": [
            probe("find.name.control", ["find", ".", "-name", "*.txt"], ""),
            probe("find.exec", ["find", ".", "-exec", "<<canary_exec>>", "{}", ";"], "-exec", ["exec"]),
            probe("find.delete", ["find", "<<victim>>", "-delete"], "-delete", ["fs_write"]),
        ]},
        "sed@1.0": {"probes": [probe("sed.print.control", ["sed", "-n", "p", "<<hello>>"], "")]},
        "curl@1.0": {"probes": [
            probe("curl.url", ["curl", "<<url>>"], "", ["net"], conf={"net": "attempted"}, ev={"net": ["refused"]})]},
    },
}


def run(text, fmt="plain", default=True):
    return checker.check_all(parse_pattern(text, fmt, default), DB)[0]


def probes_of(r):
    return {f.probe for f in r.findings}


def test_pinned_subcommand_counts_only_that_subcommands_probes():
    r = run("git show")
    assert probes_of(r) == {"git.show.output"}           # not upload-pack, not -c
    assert r.status == "findings"


def test_bare_git_counts_everything_including_global_flag_probes():
    r = run("git")
    assert probes_of(r) == {"git.show.output", "git.ls-remote.upload-pack",
                            "git.status.config-fsmonitor", "git.status.plain"}


def test_pinned_subcommand_excludes_global_dash_c_probe():
    assert "git.status.config-fsmonitor" not in probes_of(run("git status"))   # `git -c .. status` is not `git status ..`


def test_abbreviation_that_works_is_attached_not_listed_twice():
    r = run("git ls-remote")
    (f,) = r.findings
    assert f.abbreviation["status"] == "works" and f.abbreviation["flag"] == "--upload-pa"
    assert "also works" in f.fix


def test_abbreviation_that_is_rejected_is_reported_as_rejected():
    (f,) = run("git show").findings
    assert f.abbreviation["status"] == "rejected"


def test_unknown_tool_is_not_safe():
    r = run("npm run build")
    assert r.status == "unknown_tool" and not r.findings
    assert any("not safe" in n for n in r.notes)


def test_runner_tools_get_a_hint_but_stay_unknown():
    r = run("bash")
    assert r.status == "unknown_tool" and any("runs other programs" in n for n in r.notes)


def test_known_tool_unprobed_subcommand_is_unknown_scope():
    r = run("git branch")
    assert r.status == "unknown_scope" and r.probes_in_scope == 0


def test_no_known_risk_is_worded_carefully():
    r = run("sed")
    assert r.status == "no_known_risk"
    assert any("not a proof of safety" in n for n in r.notes)


def test_exact_entry_only_checks_flags_written_in_it():
    assert run("find . -name x $").status == "no_known_risk"          # no known-risky flag is written in it
    assert run("git branch -D old $").status == "unknown_scope"       # git branch was never probed
    r = run("find build -type f -delete $")
    assert probes_of(r) == {"find.delete"}


def test_exact_entry_matches_abbreviated_flag_text():
    assert "git.show.output" in probes_of(run("git show --outpu=x $"))


def test_exact_plain_use_finding_for_intrinsic_effect():
    r = run("git status $")
    assert probes_of(r) == {"git.status.plain"}
    assert r.findings[0].severity == "low"                     # plain `git status` touching .git/index is minor
    assert "exact entry" in r.findings[0].fix and "exact entry" in r.fix


def test_exact_curl_url_is_a_network_finding():
    assert probes_of(run("curl https://example.com $")) == {"curl.url"}


def test_severities():
    r = run("find")
    assert {f.probe: f.severity for f in r.findings} == {"find.exec": "critical", "find.delete": "high"}
    assert r.top_severity == "critical"
    assert run("curl").findings[0].severity == "medium"


def test_allow_all_entry():
    r = run("*")
    assert r.status == "allow_all" and r.top_severity == "critical"


def test_skipped_entry():
    (r,) = checker.check_all(allowlist.parse_claude('{"permissions":{"allow":["Read(x)"]}}'), DB)
    assert r.status == "skipped"


def test_multiple_db_versions_are_all_consulted():
    db = json.loads(json.dumps(DB))
    db["tools"]["find@2.0"] = {"probes": [probe("find.exec", ["find", ".", "-exec", "x"], "-exec", ["exec"])]}
    r = checker.check_entry(parse_pattern("find", "plain", True)[0], db)
    assert {f.tool_version for f in r.findings} == {"find@1.0", "find@2.0"}


def test_exit_codes():
    clean = checker.check_all(parse_pattern("sed", "plain", True), DB)
    risky = checker.check_all(parse_pattern("find", "plain", True), DB)
    unknown = checker.check_all(parse_pattern("npm", "plain", True), DB)
    assert checker.exit_code(risky, strict=False) == 0
    assert checker.exit_code(clean, strict=True) == 0
    assert checker.exit_code(risky, strict=True) == 1
    assert checker.exit_code(unknown, strict=True) == 1               # unknown is NOT safe
    assert checker.exit_code(unknown, strict=True, ignore_unknown=True) == 0


def test_text_report_is_honest_and_mentions_evidence():
    reports = checker.check_all(allowlist.parse_plain("git show\nnpm\nsed"), DB)
    text = report.render_text("a.txt", "plain", DB, reports)
    assert "Neither means safe" in text and "git@9.9" in text
    assert "probe git.show.output" in text and "[UNKNOWN] npm" in text and "[no known risk] sed" in text


def test_json_report_roundtrips():
    reports = checker.check_all(allowlist.parse_plain("git show\nnpm"), DB)
    doc = json.loads(report.render_json("a.txt", "plain", DB, reports))
    assert doc["summary"]["by_status"] == {"findings": 1, "unknown_tool": 1}
    assert doc["entries"][0]["findings"][0]["flag"] == "--output"
    assert "disclaimer" in doc


# ---- integration with the real DB produced by `gtfo-probe run` (committed under docs/examples)
REAL_DB = Path(__file__).parent.parent / "docs" / "examples" / "capabilities.json"


@pytest.mark.skipif(not REAL_DB.exists(), reason="example DB missing")
def test_real_db_git_show_and_tar():
    db = json.loads(REAL_DB.read_text())
    (show,) = checker.check_all(parse_pattern("git show", "plain", True), db)
    assert {f.flag for f in show.findings} == {"--output"}
    (tar,) = checker.check_all(parse_pattern("tar", "plain", True), db)
    assert any(f.flag == "-I" and f.abbreviation["status"] == "works" for f in tar.findings)
    (git,) = checker.check_all(parse_pattern("git", "plain", True), db)
    up = next(f for f in git.findings if f.flag == "--upload-pack")
    assert up.abbreviation["flag"] == "--upload-pa" and up.abbreviation["status"] == "works"


def test_fix_is_specific_to_the_entry_and_format():
    r = run("git ls-remote")
    assert "git ls-remote <the exact arguments> $" in r.fix
    assert "decision=" in checker.entry_fix(parse_pattern("tar", "codex", True)[0])
    assert "Bash(find <the exact arguments>)" in checker.entry_fix(parse_pattern("find:*", "claude", False)[0])


def test_claude_find_gets_an_agent_note():
    r = checker.check_entry(parse_pattern("find:*", "claude", False)[0], DB)
    assert any("Not modelled" in n for n in r.notes)
    assert not any("agent note" in n for n in run("find").notes)           # only for claude entries


def _notes(text):
    db = json.loads(REAL_DB.read_text())
    return checker.check_entry(parse_pattern(text, "claude", False)[0], db).notes


def test_claude_read_only_builtin_note():
    assert any("NO allow rule" in n for n in _notes("cat *"))
    assert any("read-only forms of `git`" in n for n in _notes("git show *"))
    assert not any("NO allow rule" in n for n in _notes("tar *"))


def test_claude_flag_write_note_says_edit_rules_do_not_cover_it():
    assert any("written by a flag" in n for n in _notes("tar *"))
    assert any("Read/Edit rules to the paths `sed`" in n for n in _notes("sed *"))


def test_claude_glob_prompt_note_only_for_documented_tools_with_findings():
    assert any("unquoted glob" in n for n in _notes("sort *"))
    assert not any("unquoted glob" in n for n in _notes("tar *"))


def test_claude_exec_wrapper_note_on_unknown_tool():
    assert any("exec wrapper `watch`" in n for n in _notes("watch *"))


def test_claude_agent_notes_cite_the_docs_and_not_for_other_formats():
    assert any(checker.CLAUDE_DOCS in n for n in _notes("find *"))
    assert not any("agent note" in n for n in run("cat").notes)
