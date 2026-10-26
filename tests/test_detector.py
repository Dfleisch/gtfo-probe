import os

from gtfo_probe import detector as d


def test_snapshot_and_diff_created_modified_deleted(tmp_path):
    (tmp_path / "a.txt").write_text("1")
    (tmp_path / "b.txt").write_text("2")
    before = d.snapshot(tmp_path)
    (tmp_path / "a.txt").write_text("changed")
    (tmp_path / "b.txt").unlink()
    (tmp_path / "c.txt").write_text("new")
    changes = {(c.path, c.change) for c in d.diff(before, d.snapshot(tmp_path))}
    assert changes == {("a.txt", "modified"), ("b.txt", "deleted"), ("c.txt", "created")}


def test_no_change_means_empty_diff(tmp_path):
    (tmp_path / "a.txt").write_text("1")
    assert d.diff(d.snapshot(tmp_path), d.snapshot(tmp_path)) == []


def test_symlink_is_recorded_not_followed(tmp_path):
    (tmp_path / "t").write_text("x")
    os.symlink("t", tmp_path / "l")
    assert d.snapshot(tmp_path)["l"][0] == "link"


def _eff(tmp_path, before, stdout="", stderr=""):
    return d.detect(before, d.snapshot(tmp_path), tmp_path, stdout, stderr)


def test_detects_fs_write(tmp_path):
    before = d.snapshot(tmp_path)
    (tmp_path / "out").mkdir()
    (tmp_path / "out" / "f").write_text("x")
    e = _eff(tmp_path, before)
    assert e.effects == {"fs_write"} and e.confidence["fs_write"] == "confirmed"


def test_exec_marker_means_exec_and_not_fs_write(tmp_path):
    (tmp_path / "markers").mkdir()
    before = d.snapshot(tmp_path)
    (tmp_path / "markers" / "exec.log").write_text("canary-exec ran: argv=1\n")
    e = _eff(tmp_path, before)
    assert e.effects == {"exec"} and e.exec_log == ["canary-exec ran: argv=1"]


def test_empty_marker_file_is_not_exec(tmp_path):
    (tmp_path / "markers").mkdir()
    (tmp_path / "markers" / "exec.log").write_text("")
    assert "exec" not in _eff(tmp_path, d.snapshot(tmp_path)).effects


def test_net_evidence_from_output(tmp_path):
    e = _eff(tmp_path, d.snapshot(tmp_path), stderr="curl: (7) Failed to connect to 192.0.2.1 port 9\n")
    assert e.effects == {"net"} and e.confidence["net"] == "attempted"


def test_innocent_output_has_no_net_evidence():
    assert d.find_net_evidence("hello world\n", "usage: tool [options]\n") == []


def test_blocked_write_is_attempted_fs_write(tmp_path):
    e = _eff(tmp_path, d.snapshot(tmp_path), stderr="find: '/etc/x': Read-only file system\n")
    assert e.effects == {"fs_write"} and e.confidence["fs_write"] == "attempted"
    assert e.blocked_writes


def test_nothing_happened(tmp_path):
    e = _eff(tmp_path, d.snapshot(tmp_path), stdout="fine\n")
    assert e.effects == set() and e.changes == []
