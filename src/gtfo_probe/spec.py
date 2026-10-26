"""Probe specification: the *data* that describes one experiment.

A probe is deliberately boring: "run THIS command with THIS single flag in THIS
fake world, and tell me whether you expect to see THESE effects".  Keeping probes
as plain JSON data (not code) has three benefits:

  * Anyone can add a probe without understanding the runner internals.
  * Probes are reviewable: a reviewer can read the exact argv that will run.
  * The runner can *validate* probes before running anything (see `validate`).

Example (see src/gtfo_probe/probes/git.json):

    {
      "id": "git.show.output",
      "tool": "git",
      "argv": ["show", "--output=<<out>>", "HEAD"],
      "expect": ["fs_write"],
      "description": "`git show --output=FILE` writes the diff to FILE."
    }

Placeholders like <<out>> are replaced by the runner with *sandbox-internal*
canary paths (see fixtures.PLACEHOLDERS).  We use <<name>> rather than {name} or
$name because those characters are meaningful to find ({}), sed ({} and $) and
the shell.  Nothing here ever goes through a shell: argv is a list.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

# The only effect names the tool knows about.  Keep this list tiny and stable:
# it is the vocabulary of the capability database.
#   fs_write : created / modified / deleted a file in the sandbox
#   exec     : caused another program to run (a "child process" we can prove ran)
#   net      : tried to open a network connection
EFFECTS = ("fs_write", "exec", "net")

# Tools we are willing to probe.  An allowlist of *what we run* is itself a safety
# control: a typo in a spec cannot make us run `rm`.
#   milestone 1: git sed find tar curl
#   milestone 3: awk family, runners, file tools, compressors, remote-access tools
# (`less` and `man` are deliberately NOT here: they only misbehave on a terminal, and the
#  sandbox has none, so a probe would report a misleading "no effect".  See docs/DESIGN.md.)
ALLOWED_TOOLS = frozenset({
    "git", "sed", "find", "tar", "curl",
    "gawk", "mawk", "xargs", "env", "sort", "diff", "cat", "head", "tail", "ls", "grep", "cp", "mv",
    "python3", "node", "npm", "npx", "pip", "make",
    "wget", "ssh", "scp", "rsync", "zip", "unzip", "gzip",
})

# "Runner" tools: programs whose JOB is to run other programs (or arbitrary code you hand them).
# For these, listing flags is the wrong question: `env X`, `xargs X`, `python3 -c X`, `node -e X`,
# `make -f X`, `npx X` all run X.  `check` therefore reports one "critical by design" finding
# instead of a flag list.  This is a decision of the probe author (like the probes themselves),
# and it is *backed by evidence*: every runner tool must have a probe tagged "runner" that
# really ran the canary (tests enforce it).  npm/pip are NOT whole-tool runners (`npm ls` is
# harmless) so only their runner *subcommands* carry the "runner" tag.
RUNNER_TOOLS = frozenset({"env", "xargs", "python3", "node", "make", "npx"})
RUNNER_TAG = "runner"

_PLACEHOLDER_RE = re.compile(r"<<([a-z_]+)>>")
_ID_RE = re.compile(r"^[a-z0-9]+(\.[a-z0-9_-]+)+$")


class SpecError(ValueError):
    """Raised when a probe spec is malformed.  Fail loudly, run nothing."""


@dataclass(frozen=True)
class ProbeSpec:
    id: str                       # unique, dotted: "<tool>.<name>"
    tool: str                     # executable name, looked up inside the sandbox
    argv: tuple[str, ...]         # arguments *after* the tool name
    expect: tuple[str, ...]       # effects we expect (empty tuple = "control": expect nothing)
    description: str = ""
    # Flags we are probing, for the database ("--output").  Purely informational:
    # lets the DB answer "which flag gives capability X" without re-parsing argv.
    flag: str = ""
    # Free-form labels for grouping/filtering later (unused by the runner in M1).
    tags: tuple[str, ...] = field(default_factory=tuple)

    def placeholders(self) -> set[str]:
        """Names of every <<placeholder>> used in argv."""
        return {m for a in self.argv for m in _PLACEHOLDER_RE.findall(a)}


def validate(raw: dict, known_placeholders: set[str] | frozenset[str]) -> ProbeSpec:
    """Check one raw JSON object and turn it into a ProbeSpec, or raise SpecError."""
    required = {"id", "tool", "argv", "expect"}
    missing = required - raw.keys()
    if missing:
        raise SpecError(f"probe missing fields {sorted(missing)}: {raw!r}")
    unknown = raw.keys() - required - {"description", "flag", "tags"}
    if unknown:
        raise SpecError(f"probe {raw['id']!r} has unknown fields {sorted(unknown)}")

    pid, tool = raw["id"], raw["tool"]
    if not isinstance(pid, str) or not _ID_RE.match(pid):
        raise SpecError(f"bad probe id {pid!r} (want e.g. 'git.show.output')")
    if tool not in ALLOWED_TOOLS:
        raise SpecError(f"probe {pid}: tool {tool!r} not in allowlist {sorted(ALLOWED_TOOLS)}")
    if not pid.startswith(tool + "."):
        raise SpecError(f"probe {pid}: id must start with '{tool}.'")

    argv = raw["argv"]
    if not isinstance(argv, list) or not all(isinstance(a, str) for a in argv):
        raise SpecError(f"probe {pid}: argv must be a list of strings (never a shell string)")

    expect = raw["expect"]
    if not isinstance(expect, list) or any(e not in EFFECTS for e in expect):
        raise SpecError(f"probe {pid}: expect must be a list drawn from {EFFECTS}")

    spec = ProbeSpec(
        id=pid,
        tool=tool,
        argv=tuple(argv),
        expect=tuple(sorted(set(expect))),
        description=raw.get("description", ""),
        flag=raw.get("flag", ""),
        tags=tuple(raw.get("tags", [])),
    )
    bad = spec.placeholders() - set(known_placeholders)
    if bad:
        raise SpecError(f"probe {pid}: unknown placeholders {sorted(bad)}")
    return spec


def load_file(path: Path, known_placeholders: set[str] | frozenset[str]) -> list[ProbeSpec]:
    """Load one JSON file containing {"probes": [ ... ]}."""
    try:
        data = json.loads(Path(path).read_text())
    except json.JSONDecodeError as exc:
        raise SpecError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("probes"), list):
        raise SpecError(f"{path}: expected an object with a 'probes' list")
    return [validate(p, known_placeholders) for p in data["probes"]]


def load_dir(directory: Path, known_placeholders: set[str] | frozenset[str]) -> list[ProbeSpec]:
    """Load every *.json file in a directory; ids must be unique across files."""
    specs: list[ProbeSpec] = []
    for f in sorted(Path(directory).glob("*.json")):
        specs.extend(load_file(f, known_placeholders))
    seen: set[str] = set()
    for s in specs:
        if s.id in seen:
            raise SpecError(f"duplicate probe id {s.id!r}")
        seen.add(s.id)
    return specs


def substitute(spec: ProbeSpec, values: dict[str, str]) -> list[str]:
    """Return the final argv with every <<placeholder>> replaced by a real path/URL."""
    def repl(m: re.Match[str]) -> str:
        return values[m.group(1)]
    return [_PLACEHOLDER_RE.sub(repl, a) for a in spec.argv]
