import os
import subprocess

from gtfo_probe import fixtures


def test_template_layout(template):
    for rel in ("repo/.git", "data/hello.txt", "data/sample.tar", "canary/secret.txt",
                "canary/victim.txt", "bin/canary-exec", "markers", "out", "home", "tmp"):
        assert (template / rel).exists(), rel
    assert os.access(template / "bin" / "canary-exec", os.X_OK)
    assert list((template / "markers").iterdir()) == []      # no exec evidence at start
    assert list((template / "out").iterdir()) == []


def test_fixture_repo_has_two_commits(template):
    out = subprocess.run(["git", "-C", str(template / "repo"), "rev-list", "--count", "HEAD"],
                         capture_output=True, text=True, check=True).stdout
    assert out.strip() == "2"


def test_fresh_copy_is_independent(template, tmp_path):
    a = fixtures.fresh_copy(template, tmp_path / "a")
    (a / "canary" / "victim.txt").unlink()
    assert (template / "canary" / "victim.txt").exists()


def test_placeholders_point_inside_sandbox_root():
    for name, v in fixtures.PLACEHOLDERS.items():
        assert v.startswith("/work") or name == "url", name
    assert fixtures.PLACEHOLDERS["url"].startswith("http://192.0.2.")   # TEST-NET-1
