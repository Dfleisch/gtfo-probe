"""Sandbox runner: run ONE command inside a locked-down box, or refuse.

The one rule of this module
---------------------------
    gtfo-probe never runs a probe outside a *verified* sandbox.

"Verified" means: before the first probe we run a tiny self-test inside the box
and check, with our own eyes, that the properties we rely on really hold
(see `Sandbox.preflight`).  If bubblewrap is missing, or the self-test fails
(e.g. the kernel forbids unprivileged user namespaces), we raise
`SandboxUnavailable`.  There is intentionally NO "run without sandbox" switch.

What the box looks like (bubblewrap flags, in plain words)
---------------------------------------------------------
    --unshare-net      new empty network namespace: no interfaces except a *down*
                       loopback.  Any connect() fails immediately.  This is the
                       "no-network" guarantee.
    --unshare-pid      the tool sees only its own processes; when the box's first
                       process dies, everything inside dies (clean timeout kills).
    --unshare-ipc/uts  isolate SysV IPC and hostname - cheap, removes side channels.
    --die-with-parent  if gtfo-probe crashes, the box is torn down.
    --new-session      detach from our terminal (blocks TIOCSTI keystroke injection).
    (root filesystem)  an *empty* tmpfs root; we bind in only /usr (read-only), the
                       loader cache and a few /etc files.  The host's home dir,
                       ssh keys, the project source... simply do not exist inside.
    --remount-ro /     the whole root is then made read-only.  The only writable
                       places are /work (the per-probe fixture dir) and /tmp
                       (a directory *inside* /work), so every possible write
                       lands somewhere the detector can inspect.
    --clearenv         the tool sees none of our environment variables (tokens!).

Why bubblewrap and not `unshare -n`?
    `unshare -n` only removes the network.  It leaves the real filesystem
    writable, which is exactly the thing we are testing tools for.  It also needs
    privileges that are often missing (on the development box it fails with
    "Operation not permitted").  So it is not an acceptable fallback; we refuse.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

MAX_CAPTURE = 64 * 1024  # bytes of stdout/stderr we keep per stream
DEFAULT_TIMEOUT = 5.0     # seconds; probes are tiny, anything longer is a hang

# Read-only host paths the tools need in order to run at all.
_RO_BINDS = ["/usr", "/etc/ld.so.cache", "/etc/passwd", "/etc/group", "/etc/localtime",
             "/etc/alternatives",
             # Public CA certificates (not secrets).  pip's vendored `requests` refuses to even
             # start without a CA bundle, so without this pip probes only show a traceback.
             "/etc/ssl/certs"]
# Top-level symlinks on merged-/usr systems (Debian/Ubuntu/Fedora).
_USR_SYMLINKS = {"bin": "usr/bin", "sbin": "usr/sbin", "lib": "usr/lib", "lib64": "usr/lib64"}


class SandboxUnavailable(RuntimeError):
    """No safe sandbox: the caller must stop.  Never catch this and run anyway."""


@dataclass
class RunResult:
    returncode: int | None   # None if we had to kill it (timeout)
    timed_out: bool
    stdout: str
    stderr: str
    duration: float          # seconds
    truncated: bool = False


class Sandbox:
    def __init__(self, bwrap_path: str):
        self.bwrap = bwrap_path
        self._verified = False

    # ------------------------------------------------------------------ setup
    @classmethod
    def detect(cls) -> "Sandbox":
        """Find bubblewrap or raise.  Does not yet prove that it works."""
        path = shutil.which("bwrap")
        if path is None:
            raise SandboxUnavailable(
                "bubblewrap (`bwrap`) not found. Install it (e.g. `apt install bubblewrap`). "
                "gtfo-probe refuses to run probes without a sandbox."
            )
        return cls(path)

    def version(self) -> str:
        out = subprocess.run([self.bwrap, "--version"], capture_output=True, text=True)
        return out.stdout.strip() or "unknown"

    # ---------------------------------------------------------- command builder
    def build_command(self, workdir: Path, argv: list[str]) -> list[str]:
        """Assemble the full `bwrap ... -- tool args` command line (pure function)."""
        cmd = [
            self.bwrap,
            "--unshare-net", "--unshare-pid", "--unshare-ipc", "--unshare-uts",
            "--die-with-parent", "--new-session",
        ]
        for name, target in _USR_SYMLINKS.items():
            cmd += ["--symlink", target, f"/{name}"]
        for path in _RO_BINDS:
            if os.path.exists(path):
                cmd += ["--ro-bind", path, path]
        cmd += [
            "--proc", "/proc",
            "--dev", "/dev",
            "--bind", str(workdir), "/work",
            "--bind", str(Path(workdir) / "tmp"), "/tmp",
            "--remount-ro", "/",
            "--chdir", "/work/repo",
            "--clearenv",
            "--setenv", "PATH", "/usr/local/bin:/usr/bin:/bin",  # /usr is read-only; /usr/local/bin covers npm -g style installs
            "--setenv", "HOME", "/work/home",
            "--setenv", "TMPDIR", "/tmp",
            "--setenv", "LC_ALL", "C",
            "--setenv", "TERM", "dumb",
            # git specifics: ignore any user/system config, never prompt, never page.
            "--setenv", "GIT_CONFIG_NOSYSTEM", "1",
            "--setenv", "GIT_CONFIG_GLOBAL", "/dev/null",
            "--setenv", "GIT_TERMINAL_PROMPT", "0",
            "--setenv", "GIT_PAGER", "cat",
            "--setenv", "PAGER", "cat",
            "--",
        ]
        return cmd + argv

    # ------------------------------------------------------------------- run
    def _run_raw(self, workdir: Path, argv: list[str], timeout: float) -> RunResult:
        cmd = self.build_command(workdir, argv)
        # Capture output via temp files OUTSIDE the workdir: a tool cannot fill our
        # memory, and our own capture files can never show up as "files it wrote".
        with tempfile.TemporaryFile() as fo, tempfile.TemporaryFile() as fe:
            start = time.monotonic()
            proc = subprocess.Popen(
                cmd, stdin=subprocess.DEVNULL, stdout=fo, stderr=fe,
                start_new_session=True,  # own process group so we can kill it all
            )
            timed_out = False
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait()
            duration = time.monotonic() - start
            out, o_trunc = _read_capped(fo)
            err, e_trunc = _read_capped(fe)
        return RunResult(
            returncode=None if timed_out else proc.returncode,
            timed_out=timed_out, stdout=out, stderr=err,
            duration=duration, truncated=o_trunc or e_trunc,
        )

    def run(self, workdir: Path, argv: list[str], timeout: float = DEFAULT_TIMEOUT) -> RunResult:
        """Run `argv` (argv[0] looked up on the sandbox's PATH) inside the box."""
        if not self._verified:
            raise SandboxUnavailable("sandbox not verified: call preflight() first")
        return self._run_raw(Path(workdir), argv, timeout)

    # -------------------------------------------------------------- self-test
    def preflight(self) -> None:
        """Prove the sandbox properties hold, or raise SandboxUnavailable.

        We do not trust that flags did what we think; we *measure* it.
        """
        with tempfile.TemporaryDirectory(prefix="gtfo-preflight-") as td:
            work = Path(td)
            (work / "tmp").mkdir()
            (work / "repo").mkdir()
            script = r"""
ifaces=$(tail -n +3 /proc/net/dev | cut -d: -f1 | tr -d ' ' | tr '\n' ',')
echo "IFACES=$ifaces"
if (echo x > /etc/gtfo-write-test) 2>/dev/null; then echo ROOT_WRITABLE=yes; else echo ROOT_WRITABLE=no; fi
if (echo x > /work/preflight-ok) 2>/dev/null; then echo WORK_WRITABLE=yes; else echo WORK_WRITABLE=no; fi
if [ -e /workspace ] || [ -e /home ] || [ -e /root ]; then echo HOST_VISIBLE=yes; else echo HOST_VISIBLE=no; fi
"""
            try:
                res = self._run_raw(work, ["/bin/sh", "-c", script], timeout=10)
            except OSError as exc:  # bwrap not executable etc.
                raise SandboxUnavailable(f"could not start bubblewrap: {exc}") from exc
            if res.returncode != 0:
                raise SandboxUnavailable(
                    "bubblewrap failed to start a sandbox (often: unprivileged user "
                    f"namespaces are disabled). exit={res.returncode} stderr={res.stderr.strip()!r}"
                )
            facts = dict(line.split("=", 1) for line in res.stdout.splitlines() if "=" in line)
            problems = []
            ifaces = {i for i in facts.get("IFACES", "").split(",") if i}
            if ifaces - {"lo"}:
                problems.append(f"network interfaces visible: {sorted(ifaces)}")
            if facts.get("ROOT_WRITABLE") != "no":
                problems.append("root filesystem is writable")
            if facts.get("WORK_WRITABLE") != "yes":
                problems.append("/work is not writable (probes could not run)")
            if facts.get("HOST_VISIBLE") != "no":
                problems.append("host directories (/workspace, /home, /root) are visible")
            if problems:
                raise SandboxUnavailable("sandbox self-test failed: " + "; ".join(problems))
        self._verified = True


def _read_capped(f) -> tuple[str, bool]:
    """Read at most MAX_CAPTURE bytes from a temp file; report if there was more."""
    f.seek(0, os.SEEK_END)
    size = f.tell()
    f.seek(0)
    data = f.read(MAX_CAPTURE)
    return data.decode("utf-8", errors="replace"), size > MAX_CAPTURE
