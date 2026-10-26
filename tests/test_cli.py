import json

import pytest

from gtfo_probe import cli
from gtfo_probe.sandbox import SandboxUnavailable


def test_list_runs_nothing_and_prints_probes(capsys):
    assert cli.main(["list", "--tool", "tar"]) == 0
    out = capsys.readouterr().out
    assert "tar.use-compress-program" in out and "git." not in out


def test_unknown_tool_filter_is_an_error(capsys):
    assert cli.main(["list", "--tool", "nonexistent"]) == 3


def test_bad_spec_dir_is_reported(tmp_path, capsys):
    (tmp_path / "bad.json").write_text('{"probes": [{"id": "x"}]}')
    assert cli.main(["list", "--probes", str(tmp_path)]) == 3
    assert "probe spec error" in capsys.readouterr().err


def test_run_refuses_without_sandbox_and_writes_nothing(monkeypatch, tmp_path, capsys):
    def boom():
        raise SandboxUnavailable("no bwrap here")
    monkeypatch.setattr(cli, "_verified_sandbox", boom)
    out = tmp_path / "caps.json"
    assert cli.main(["run", "--out", str(out)]) == 2
    assert not out.exists()
    assert "refusing to run" in capsys.readouterr().err


def test_doctor_reports_unavailable(monkeypatch, capsys):
    def boom():
        raise SandboxUnavailable("nope")
    monkeypatch.setattr(cli, "_verified_sandbox", boom)
    assert cli.main(["doctor"]) == 2
    assert "UNAVAILABLE" in capsys.readouterr().out


@pytest.mark.sandbox
def test_doctor_ok(sandbox, capsys):
    assert cli.main(["doctor"]) == 0
    assert "sandbox: OK" in capsys.readouterr().out


@pytest.mark.sandbox
def test_full_run_writes_capabilities_json(sandbox, tmp_path, capsys):
    out = tmp_path / "capabilities.json"
    assert cli.main(["run", "--out", str(out), "--strict"]) == 0
    db = json.loads(out.read_text())
    tools = set(k.split("@")[0] for k in db["tools"])
    assert {"git", "sed", "find", "tar", "curl"} <= tools   # the core five; others are skipped if not installed
    git = next(v for k, v in db["tools"].items() if k.startswith("git@"))
    flags = {c["flag"] for c in git["capabilities"]["fs_write"]}
    assert "--output" in flags
    assert "--upload-pa" in {c["flag"] for c in git["capabilities"]["exec"]}


# ---- `check` (needs no sandbox)
from pathlib import Path

EXAMPLE_DB = Path(__file__).parent.parent / "docs" / "examples" / "capabilities.json"


def _check(tmp_path, text, *extra, name="allow.txt"):
    f = tmp_path / name
    f.write_text(text)
    return cli.main(["check", str(f), "--db", str(EXAMPLE_DB), *extra])


def test_check_text_and_nonstrict_exit_zero(tmp_path, capsys):
    assert _check(tmp_path, "git show\n") == 0
    out = capsys.readouterr().out
    assert "[HIGH] git show" in out and "--output" in out


def test_check_strict_exit_codes(tmp_path, capsys):
    assert _check(tmp_path, "find\n", "--strict") == 1
    assert _check(tmp_path, "git branch\n", "--strict") == 1                       # unknown is not safe
    assert _check(tmp_path, "git branch\n", "--strict", "--ignore-unknown") == 0
    assert _check(tmp_path, "sed --sandbox -n p $\n", "--strict") == 0              # exact, no risky flag written


def test_check_json_output_parses(tmp_path, capsys):
    assert _check(tmp_path, '{"permissions":{"allow":["Bash(tar:*)"]}}', "--format", "json", name="s.json") == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["allowlist"]["format"] == "claude" and doc["entries"][0]["status"] == "findings"


def test_check_codex_file(tmp_path, capsys):
    assert _check(tmp_path, 'prefix_rule(pattern=["find"])\n', name="default.rules") == 0
    assert "format: codex" in capsys.readouterr().out


def test_check_input_errors_exit_2(tmp_path, capsys):
    assert cli.main(["check", str(tmp_path / "nope"), "--db", str(EXAMPLE_DB)]) == 2
    f = tmp_path / "a.txt"
    f.write_text("git show")
    assert cli.main(["check", str(f), "--db", str(tmp_path / "nodb.json")]) == 2
    assert "check:" in capsys.readouterr().err


def test_python_dash_m_entry_point():
    import subprocess, sys
    out = subprocess.run([sys.executable, "-m", "gtfo_probe", "--help"], capture_output=True, text=True)
    assert out.returncode == 0 and "check" in out.stdout
