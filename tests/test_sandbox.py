import pytest

from gtfo_probe import detector
from gtfo_probe.sandbox import Sandbox, SandboxUnavailable


def test_detect_raises_when_bwrap_missing(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: None)
    with pytest.raises(SandboxUnavailable, match="bubblewrap"):
        Sandbox.detect()


def test_build_command_has_isolation_flags(tmp_path):
    cmd = Sandbox("/usr/bin/bwrap").build_command(tmp_path, ["git", "status"])
    for flag in ("--unshare-net", "--unshare-pid", "--die-with-parent", "--clearenv", "--remount-ro"):
        assert flag in cmd
    assert cmd[-2:] == ["git", "status"]
    assert cmd.index("--") == len(cmd) - 3          # argv comes after the separator
    # the whole host root is never bound in; only /usr etc. are
    assert ["--ro-bind", "/", "/"] != cmd[cmd.index("--ro-bind"):cmd.index("--ro-bind") + 3]


def test_run_refuses_before_preflight(world):
    sb = Sandbox("/usr/bin/bwrap")           # never verified
    with pytest.raises(SandboxUnavailable, match="not verified"):
        sb.run(world, ["true"])


@pytest.mark.sandbox
def test_preflight_rejects_a_sandbox_with_network(monkeypatch, sandbox):
    """If someone removes --unshare-net the self-test must notice and refuse."""
    broken = Sandbox(sandbox.bwrap)
    real = broken.build_command
    monkeypatch.setattr(broken, "build_command",
                        lambda w, a: [x for x in real(w, a) if x != "--unshare-net"])
    with pytest.raises(SandboxUnavailable, match="network interfaces"):
        broken.preflight()
    assert broken._verified is False


def _drop_remount_ro(cmd):
    """Remove the `--remount-ro /` pair from a bwrap command line."""
    i = cmd.index("--remount-ro")
    return cmd[:i] + cmd[i + 2:]


@pytest.mark.sandbox
def test_preflight_rejects_writable_root(monkeypatch, sandbox):
    """Without --remount-ro the tmpfs root is writable; the self-test must notice."""
    broken = Sandbox(sandbox.bwrap)
    real = broken.build_command
    monkeypatch.setattr(broken, "build_command", lambda w, a: _drop_remount_ro(real(w, a)))
    with pytest.raises(SandboxUnavailable, match="root filesystem is writable"):
        broken.preflight()


@pytest.mark.sandbox
def test_runs_command_and_captures_output(sandbox, world):
    res = sandbox.run(world, ["/bin/sh", "-c", "echo out; echo err >&2; exit 3"])
    assert (res.returncode, res.stdout, res.stderr, res.timed_out) == (3, "out\n", "err\n", False)


@pytest.mark.sandbox
def test_timeout_kills_the_process(sandbox, world):
    res = sandbox.run(world, ["sleep", "30"], timeout=0.5)
    assert res.timed_out and res.returncode is None and res.duration < 5


@pytest.mark.sandbox
def test_write_outside_work_is_blocked_and_inside_is_allowed(sandbox, world):
    res = sandbox.run(world, ["/bin/sh", "-c",
                              "echo x > /etc/evil; echo $? > /work/out/code_etc; echo y > /work/out/ok"])
    assert (world / "out" / "ok").read_text() == "y\n"
    assert "Read-only file system" in res.stderr or "Permission denied" in res.stderr \
        or "cannot create" in res.stderr
    assert not (world / "etc").exists()


@pytest.mark.sandbox
def test_environment_and_host_files_are_hidden(sandbox, world, monkeypatch):
    monkeypatch.setenv("SUPER_SECRET_TOKEN", "hunter2")
    res = sandbox.run(world, ["/bin/sh", "-c", "echo [$SUPER_SECRET_TOKEN]; ls /workspace /home 2>&1"])
    assert "[]" in res.stdout and "hunter2" not in res.stdout + res.stderr
    assert "No such file" in res.stdout + res.stderr


@pytest.mark.sandbox
def test_network_really_fails(sandbox, world):
    res = sandbox.run(world, ["curl", "-sS", "--max-time", "3", "http://192.0.2.1:9/"])
    assert res.returncode not in (0, None)
    assert detector.find_net_evidence(res.stdout, res.stderr)
