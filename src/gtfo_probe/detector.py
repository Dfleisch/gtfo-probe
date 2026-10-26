"""Effect detector: decide what a probe *actually did*.

We never ask the tool what it did; we look at the world afterwards.  Three
independent observations, one per effect kind:

  fs_write  Snapshot every file under the probe's workdir BEFORE and AFTER the
            run (path -> type, size, mtime, content hash).  Any created, modified
            or deleted file (except the exec-marker directory) is a write.
            Strength: *confirmed* - we see the actual bytes on disk.

  exec      The fixture contains a canary program (`bin/canary-exec`) that appends
            a line to `markers/exec.log` when run.  If that file exists after the
            run, some program path led to our canary being executed.
            Strength: *confirmed* - only an execution can create that line.

  net       The sandbox has no network, so a connection attempt cannot succeed;
            it just fails.  We recognise the failure message in stdout/stderr
            (and the canary address 192.0.2.1).  Strength: *attempted* -
            this is a text heuristic, weaker than the two above.  (A future
            version can use strace to see connect() syscalls; see DESIGN.md.)

Additionally we record `blocked_write` evidence: the root filesystem is read-only,
so a tool that tries to write outside /work gets "Read-only file system".  That
cannot appear as a changed file, so we notice the error text instead.

Everything here is a pure function of (before, after, run output) so it is easy
to unit-test without a sandbox.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path

from .fixtures import EXEC_MARKER_DIR

# Signature stored per path: (kind, size, mtime_ns, sha256-or-link-target)
Signature = tuple[str, int, int, str]
Snapshot = dict[str, Signature]


@dataclass(frozen=True)
class Change:
    path: str       # relative to the workdir, e.g. "out/probe-output.txt"
    change: str     # "created" | "modified" | "deleted"


@dataclass
class Effects:
    """What we concluded.  `effects` uses the vocabulary in spec.EFFECTS."""
    effects: set[str] = field(default_factory=set)
    changes: list[Change] = field(default_factory=list)       # evidence for fs_write
    exec_log: list[str] = field(default_factory=list)          # evidence for exec
    net_evidence: list[str] = field(default_factory=list)      # evidence for net
    blocked_writes: list[str] = field(default_factory=list)    # attempted-but-denied writes
    confidence: dict[str, str] = field(default_factory=dict)   # effect -> confirmed|attempted


# ------------------------------------------------------------------ filesystem
def snapshot(root: Path) -> Snapshot:
    """Record a signature for every file/dir/symlink under `root` (no link following)."""
    snap: Snapshot = {}
    root = Path(root)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in dirnames + filenames:
            p = Path(dirpath) / name
            rel = str(p.relative_to(root))
            st = p.lstat()
            if stat.S_ISLNK(st.st_mode):
                snap[rel] = ("link", 0, 0, os.readlink(p))
            elif stat.S_ISDIR(st.st_mode):
                # directories: existence matters, their mtime changes whenever a
                # child changes (and the child is reported itself), so ignore it.
                snap[rel] = ("dir", 0, 0, "")
            elif stat.S_ISREG(st.st_mode):
                snap[rel] = ("file", st.st_size, st.st_mtime_ns, _sha256(p))
            else:
                snap[rel] = ("other", 0, 0, "")
    return snap


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def diff(before: Snapshot, after: Snapshot) -> list[Change]:
    """Created / modified / deleted paths, sorted for stable output."""
    changes = []
    for rel in sorted(before.keys() | after.keys()):
        if rel not in before:
            changes.append(Change(rel, "created"))
        elif rel not in after:
            changes.append(Change(rel, "deleted"))
        elif before[rel] != after[rel]:
            changes.append(Change(rel, "modified"))
    return changes


# --------------------------------------------------------------------- network
# Phrases tools print when a connection cannot be made.  Matched case-insensitively.
_NET_PATTERNS = [
    r"could(?:n't| not) resolve host",
    r"could(?:n't| not) connect",
    r"failed to connect",
    r"network is unreachable",
    r"connection refused",
    r"temporary failure in name resolution",
    r"name or service not known",
    r"unable to access ['\"]?https?://",
    r"connection timed out",
    # Node.js / Python style errors (added in milestone 3, found by probing npm and python3):
    r"\bEAI_AGAIN\b", r"\bENOTFOUND\b", r"\bECONNREFUSED\b", r"\bENETUNREACH\b", r"\bEHOSTUNREACH\b",
    r"getaddrinfo",
    r"\[Errno 101\]",         # python: [Errno 101] Network is unreachable
    r"192\.0\.2\.1",           # our canary address appearing in any error
]
_NET_RE = re.compile("|".join(_NET_PATTERNS), re.IGNORECASE)

_BLOCKED_RE = re.compile(r"read-only file system", re.IGNORECASE)


def find_net_evidence(stdout: str, stderr: str) -> list[str]:
    """Return the output lines that look like a failed connection attempt."""
    hits = []
    for line in (stdout + "\n" + stderr).splitlines():
        if _NET_RE.search(line):
            hits.append(line.strip()[:200])
    return hits


def find_blocked_writes(stdout: str, stderr: str) -> list[str]:
    return [l.strip()[:200] for l in (stdout + "\n" + stderr).splitlines() if _BLOCKED_RE.search(l)]


# ------------------------------------------------------------------- top level
def detect(before: Snapshot, after: Snapshot, workdir: Path, stdout: str, stderr: str) -> Effects:
    """Combine the three observations into one `Effects` verdict."""
    eff = Effects()
    marker_prefix = EXEC_MARKER_DIR + os.sep

    # 1. exec: did the canary program leave its mark?
    log = Path(workdir) / EXEC_MARKER_DIR / "exec.log"
    if log.is_file() and log.stat().st_size > 0:
        eff.exec_log = log.read_text(errors="replace").splitlines()[:5]
        eff.effects.add("exec")
        eff.confidence["exec"] = "confirmed"

    # 2. fs_write: any change outside the marker directory.
    #    (The marker dir is excluded so that "exec" does not also read as "fs_write".)
    for ch in diff(before, after):
        if ch.path == EXEC_MARKER_DIR or ch.path.startswith(marker_prefix):
            continue
        eff.changes.append(ch)
    if eff.changes:
        eff.effects.add("fs_write")
        eff.confidence["fs_write"] = "confirmed"

    # 3. net: failure text.
    eff.net_evidence = find_net_evidence(stdout, stderr)
    if eff.net_evidence:
        eff.effects.add("net")
        eff.confidence["net"] = "attempted"

    # 4. Writes the read-only root refused.  The file never appeared, so it is not
    #    "confirmed"; but a tool complaining "Read-only file system" clearly tried.
    eff.blocked_writes = find_blocked_writes(stdout, stderr)
    if eff.blocked_writes and "fs_write" not in eff.effects:
        eff.effects.add("fs_write")
        eff.confidence["fs_write"] = "attempted"
    return eff
