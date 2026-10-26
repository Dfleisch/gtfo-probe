"""Guard rails for the non-Python deliverables (Dockerfile, README safety text, example files)."""
import json
from pathlib import Path

from gtfo_probe import allowlist, checker, cli
from gtfo_probe.sandbox import SandboxUnavailable

ROOT = Path(__file__).parent.parent
EXAMPLES = ("allowlist.txt", "claude-settings.json", "codex-default.rules", "allowlist-runners.txt",
            "claude-realistic-settings.json")


def test_dockerfile_installs_the_tools_probes_need_and_drops_root():
    text = (ROOT / "Dockerfile").read_text()
    for pkg in ("bubblewrap", "git", "sed", "findutils", "tar", "curl"):
        assert pkg in text
    assert "USER probe" in text                       # never probe as root
    assert "shares the host kernel" in text           # the warning travels with the file
    assert "STATUS:" in text                          # the file says what was and was not verified


def test_readme_has_platform_and_kernel_warnings():
    text = (ROOT / "README.md").read_text()
    assert "shares the host kernel" in text
    assert "WSL2" in text and "Docker" in text
    assert "gtfo-probe check" in text


def test_check_works_without_any_sandbox(monkeypatch, tmp_path, capsys):
    """`check` must run anywhere (macOS/Windows with a DB), so it may never touch the sandbox."""
    def boom():
        raise SandboxUnavailable("no sandbox on this OS")
    monkeypatch.setattr(cli, "_verified_sandbox", boom)
    f = tmp_path / "a.txt"
    f.write_text("tar\n")
    assert cli.main(["check", str(f), "--db", str(ROOT / "docs/examples/capabilities.json")]) == 0


def test_every_example_allowlist_parses_and_checks():
    db = json.loads((ROOT / "docs/examples/capabilities.json").read_text())
    for name in EXAMPLES:
        fmt, entries = allowlist.load(str(ROOT / "docs/examples" / name))
        assert checker.check_all(entries, db), name


def test_committed_example_outputs_are_not_stale():
    """The .out.txt files are real output; regenerate them if this fails (see docs/WALKTHROUGH.md)."""
    db = json.loads((ROOT / "docs/examples/capabilities.json").read_text())
    from gtfo_probe import report
    for name in EXAMPLES:
        path = ROOT / "docs/examples" / name
        fmt, entries = allowlist.load(str(path))
        text = report.render_text(f"docs/examples/{name}", fmt, db, checker.check_all(entries, db))
        assert text + "\n" == (ROOT / "docs/examples" / (name + ".out.txt")).read_text(), name
