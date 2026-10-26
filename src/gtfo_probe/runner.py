"""Runner: glue that executes probes end to end.

    spec -> fresh fixture copy -> snapshot BEFORE -> sandboxed run
         -> snapshot AFTER -> detector -> ProbeResult

Each probe gets its own copy of the fixture world, so probes cannot influence
each other (a probe that deletes a file does not break the next probe).
"""

from __future__ import annotations

import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from . import detector, fixtures, spec as specmod
from .sandbox import DEFAULT_TIMEOUT, Sandbox

_VERSION_RE = re.compile(r"\d+(?:\.\d+)+")

# How to ask each tool for its version.  Default is `<tool> --version`.  Some tools spell it
# differently (or have no version flag at all: scp ships with ssh, so we ask ssh).
VERSION_COMMANDS: dict[str, list[str]] = {
    "ssh": ["ssh", "-V"],
    "scp": ["ssh", "-V"],        # scp has no version flag; same OpenSSH package as ssh
    "zip": ["zip", "-v"],
    "unzip": ["unzip", "-v"],
}


@dataclass
class ProbeResult:
    probe: specmod.ProbeSpec
    argv: list[str]                  # the real argv that ran (placeholders substituted)
    effects: detector.Effects
    returncode: int | None
    timed_out: bool
    stdout: str
    stderr: str
    status: str                      # see classify()

    def to_dict(self) -> dict:
        """JSON-friendly form used by db.py."""
        e = self.effects
        return {
            "id": self.probe.id,
            "flag": self.probe.flag,
            "description": self.probe.description,
            "argv": [self.probe.tool, *self.probe.argv],       # template form, portable
            "expected": list(self.probe.expect),
            "observed": sorted(e.effects),
            "confidence": dict(sorted(e.confidence.items())),
            "tags": list(self.probe.tags),
            "status": self.status,
            "exit_code": self.returncode,
            "timed_out": self.timed_out,
            "evidence": {
                "fs_changes": [{"path": c.path, "change": c.change} for c in e.changes][:20],
                "exec_log": e.exec_log,
                "net": e.net_evidence[:3],
                "blocked_writes": e.blocked_writes[:3],
            },
        }


def classify(expected: tuple[str, ...], observed: set[str]) -> str:
    """Compare what the spec author expected with what we saw.

    match                  observed == expected (including "nothing" for controls)
    unexpected_effect      saw effects the spec did not list  (a finding, or a bad spec)
    expected_effect_missing  an expected effect did not happen (tool version differs?)
    mismatch               both of the above
    """
    exp, obs = set(expected), set(observed)
    if exp == obs:
        return "match"
    extra, missing = obs - exp, exp - obs
    if extra and missing:
        return "mismatch"
    return "unexpected_effect" if extra else "expected_effect_missing"


def tool_version(sandbox: Sandbox, template: Path, tool: str, scratch: Path) -> str | None:
    """Ask the tool (inside the sandbox) for its version, e.g. 'git@2.47.3'.

    Returns None when the tool is not installed on this machine (the sandbox could not
    start it), so `run_all` can skip its probes instead of reporting dozens of bogus
    "expected effect missing" results.
    """
    work = fixtures.fresh_copy(template, scratch / f"version-{tool}")
    res = sandbox.run(work, VERSION_COMMANDS.get(tool, [tool, "--version"]), timeout=DEFAULT_TIMEOUT)
    if _not_installed(res):
        return None
    text = "\n".join(((res.stdout or "") + "\n" + (res.stderr or "")).splitlines()[:6])
    m = _VERSION_RE.search(text)
    return f"{tool}@{m.group(0) if m else 'unknown'}"


def _not_installed(res) -> bool:
    """bubblewrap prints `bwrap: execvp NAME: No such file or directory` when the program is missing."""
    return res.returncode not in (0, None) and "execvp" in (res.stderr or "") and "No such file" in (res.stderr or "")


def run_probe(sandbox: Sandbox, template: Path, probe: specmod.ProbeSpec,
              scratch: Path, timeout: float = DEFAULT_TIMEOUT) -> ProbeResult:
    work = fixtures.fresh_copy(template, scratch / probe.id)
    argv = [probe.tool, *specmod.substitute(probe, fixtures.PLACEHOLDERS)]

    before = detector.snapshot(work)
    res = sandbox.run(work, argv, timeout=timeout)
    after = detector.snapshot(work)

    effects = detector.detect(before, after, work, res.stdout, res.stderr)
    return ProbeResult(
        probe=probe, argv=argv, effects=effects,
        returncode=res.returncode, timed_out=res.timed_out,
        stdout=res.stdout, stderr=res.stderr,
        status=classify(probe.expect, effects.effects),
    )


def run_all(sandbox: Sandbox, probes: list[specmod.ProbeSpec],
            timeout: float = DEFAULT_TIMEOUT,
            skipped: list[str] | None = None) -> tuple[dict[str, str], list[ProbeResult]]:
    """Run every probe; return ({tool: 'tool@version'}, results).

    Tools that are not installed on this machine are skipped (their names are appended to
    `skipped` if a list is given) rather than producing misleading failures.

    Refuses (SandboxUnavailable) if the sandbox has not been verified, because
    Sandbox.run checks that.  A temporary directory holds all per-probe worlds
    and is deleted afterwards.
    """
    results: list[ProbeResult] = []
    versions: dict[str, str] = {}
    with tempfile.TemporaryDirectory(prefix="gtfo-probe-") as td:
        td_path = Path(td)
        template = fixtures.build_template(td_path / "template")
        scratch = td_path / "worlds"
        scratch.mkdir()
        for tool in sorted({p.tool for p in probes}):
            version = tool_version(sandbox, template, tool, scratch)
            if version is None:
                if skipped is not None:
                    skipped.append(tool)
            else:
                versions[tool] = version
        for probe in probes:
            if probe.tool in versions:
                results.append(run_probe(sandbox, template, probe, scratch, timeout))
    return versions, results
