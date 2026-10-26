"""Fixtures: the small fake world every probe runs in.

Why fixtures exist
------------------
A probe must run somewhere with *something to chew on*: a git repo to `git show`,
a tar archive to list, a file for `find` to match.  And the detector needs
*known landmarks* so it can tell "the tool wrote my canary file" apart from noise.

Layout (host path -> path INSIDE the sandbox, always /work/...):

    repo/            a tiny git repository with one commit      (cwd of every probe)
    data/hello.txt   harmless text file
    data/sample.tar  tar archive containing hello.txt
    canary/secret.txt  "secret" file: reading it is allowed, changing it is a finding
    canary/victim.txt  file that is OK to delete/modify *in the sandbox copy*
    bin/canary-exec  tiny script that appends a line to markers/exec.log
    markers/         ONLY canary-exec writes here => proof that a program ran
    out/             empty dir; probes are told to write results to out/probe-output.txt
    home/, tmp/      HOME and /tmp for the tool, so it cannot touch anything real

One pristine template is built once per run, then *copied* for each probe, so a
probe that damages its world cannot affect the next probe (isolation between probes).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import gzip
import tarfile
import zipfile
from pathlib import Path

SANDBOX_ROOT = "/work"  # where the per-probe directory appears inside the sandbox

# <<name>> -> value inside the sandbox.  This dict is the whole vocabulary specs may use.
PLACEHOLDERS: dict[str, str] = {
    "out": f"{SANDBOX_ROOT}/out/probe-output.txt",
    "canary_exec": f"{SANDBOX_ROOT}/bin/canary-exec",
    # 192.0.2.0/24 is TEST-NET-1 (RFC 5737): reserved for documentation, never routable.
    # Even if the sandbox failed, this address cannot reach a real host.
    "url": "http://192.0.2.1:9/gtfo-canary",
    "repo": f"{SANDBOX_ROOT}/repo",
    "data": f"{SANDBOX_ROOT}/data",
    "hello": f"{SANDBOX_ROOT}/data/hello.txt",
    "archive": f"{SANDBOX_ROOT}/data/sample.tar",
    "secret": f"{SANDBOX_ROOT}/canary/secret.txt",
    "victim": f"{SANDBOX_ROOT}/canary/victim.txt",
    # --- added in milestone 3 (runner tools, packagers, compressors) ---
    "makefile": f"{SANDBOX_ROOT}/data/Makefile",          # one target whose recipe runs the canary
    "pyscript": f"{SANDBOX_ROOT}/data/hello.py",           # harmless: prints a line
    "jsscript": f"{SANDBOX_ROOT}/data/hello.js",           # harmless: prints a line
    "unsorted": f"{SANDBOX_ROOT}/data/unsorted.txt",       # three lines, out of order
    "zipfile": f"{SANDBOX_ROOT}/data/sample.zip",
    "gzfile": f"{SANDBOX_ROOT}/data/sample.txt.gz",
    "npmpkg": f"{SANDBOX_ROOT}/npmpkg",                    # package.json with scripts that run the canary
    "pypkg": f"{SANDBOX_ROOT}/pypkg",                      # setup.py that runs the canary at build time
    "outdir": f"{SANDBOX_ROOT}/out",
}

# Directory (relative to the workdir) whose contents mean "a program was executed".
EXEC_MARKER_DIR = "markers"

# The canary program.  It is the *only* thing probes can cause to execute, and all
# it does is append one line to a file.  No network, no deleting, nothing clever.
CANARY_EXEC = """#!/bin/sh
# gtfo-probe canary program: proves that "something executed me", nothing more.
echo "canary-exec ran: argv=$*" >> /work/markers/exec.log
exit 0
"""


# The fake package's build backend (PEP 517).  Building it = running this file, which is exactly
# why `pip install <directory>` can execute code: the canary line below stands for "attacker code".
PY_BUILD_BACKEND = """import os, subprocess, zipfile

def get_requires_for_build_wheel(config_settings=None):
    return []

def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    subprocess.call(["/work/bin/canary-exec", "build-backend-ran"])
    name = "fixture_pypkg-1.0-py3-none-any.whl"
    meta = "Metadata-Version: 2.1\\nName: fixture-pypkg\\nVersion: 1.0\\n"
    wheel = "Wheel-Version: 1.0\\nGenerator: fixture\\nRoot-Is-Purelib: true\\nTag: py3-none-any\\n"
    with zipfile.ZipFile(os.path.join(wheel_directory, name), "w") as z:
        z.writestr("fixture_pypkg-1.0.dist-info/METADATA", meta)
        z.writestr("fixture_pypkg-1.0.dist-info/WHEEL", wheel)
        z.writestr("fixture_pypkg-1.0.dist-info/RECORD", "")
    return name
"""


def _host_git(args: list[str], cwd: Path) -> None:
    """Run the *host* git to prepare the fixture repo (never inside a probe)."""
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(cwd),                  # keep the host's real ~/.gitconfig out of it
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_AUTHOR_NAME": "fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
        "GIT_COMMITTER_NAME": "fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
        "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z", "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z",
    }
    subprocess.run(["git", *args], cwd=cwd, env=env, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def build_template(dest: Path) -> Path:
    """Create the pristine fake world at `dest` (must not exist) and return it."""
    dest = Path(dest)
    dest.mkdir(parents=True)
    for d in ("repo", "data", "canary", "bin", EXEC_MARKER_DIR, "out", "home", "tmp", "npmpkg", "pypkg"):
        (dest / d).mkdir()

    # --- git repository with two commits so `git log`/`git show` have content ----
    repo = dest / "repo"
    _host_git(["init", "-q", "-b", "main"], repo)
    (repo / "hello.txt").write_text("hello from the fixture repo\n")
    _host_git(["add", "hello.txt"], repo)
    _host_git(["commit", "-q", "-m", "first commit"], repo)
    (repo / "hello.txt").write_text("hello from the fixture repo\nsecond line\n")
    _host_git(["commit", "-q", "-a", "-m", "second commit"], repo)

    # --- plain data files ------------------------------------------------------
    (dest / "data" / "hello.txt").write_text("hello\nworld\n")
    with tarfile.open(dest / "data" / "sample.tar", "w") as tf:
        tf.add(dest / "data" / "hello.txt", arcname="hello.txt")

    # --- milestone 3 data: things the new tools need to chew on --------------------
    (dest / "data" / "Makefile").write_text(f"all:\n\t@{SANDBOX_ROOT}/bin/canary-exec\n")
    (dest / "data" / "hello.py").write_text("print('hello from the fixture script')\n")
    (dest / "data" / "hello.js").write_text("console.log('hello from the fixture script');\n")
    (dest / "data" / "unsorted.txt").write_text("banana\napple\ncherry\n")
    with zipfile.ZipFile(dest / "data" / "sample.zip", "w") as zf:
        zf.write(dest / "data" / "hello.txt", arcname="hello.txt")
    with gzip.open(dest / "data" / "sample.txt.gz", "wb") as gz:
        gz.write(b"hello\nworld\n")
    # An npm project whose scripts run the canary (npm lifecycle scripts / `npm run`).
    (dest / "npmpkg" / "package.json").write_text(
        '{"name": "fixture-pkg", "version": "1.0.0", "scripts": {'
        f'"canary": "{SANDBOX_ROOT}/bin/canary-exec", "preinstall": "{SANDBOX_ROOT}/bin/canary-exec"}}}}\n')
    # A python project whose *build backend* runs the canary when pip builds it.  We use a tiny
    # in-tree backend instead of setuptools so the world needs no third-party packages.
    (dest / "pypkg" / "pyproject.toml").write_text(
        '[build-system]\nrequires = []\nbuild-backend = "backend"\nbackend-path = ["."]\n')
    (dest / "pypkg" / "backend.py").write_text(PY_BUILD_BACKEND)

    # --- canaries --------------------------------------------------------------
    (dest / "canary" / "secret.txt").write_text("CANARY-SECRET-not-a-real-secret\n")
    (dest / "canary" / "victim.txt").write_text("victim file\n")

    prog = dest / "bin" / "canary-exec"
    prog.write_text(CANARY_EXEC)
    prog.chmod(0o755)
    return dest


def fresh_copy(template: Path, dest: Path) -> Path:
    """Copy the pristine world for one probe.  symlinks=True so we never follow links."""
    shutil.copytree(template, dest, symlinks=True)
    return dest
