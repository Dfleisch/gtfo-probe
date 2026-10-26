"""Automatic flag discovery: find candidate flags, TEST them in the sandbox, report what happened.

The pipeline, in plain words (one function per step, in this order):

    1. capture_help()    run `tool --help` etc. INSIDE the sandbox, keep the text
    2. helpparse         read the text, list the options it mentions (pure parsing)
    3. select()          pick the options worth testing (hints from words; capped)
    4. probe_candidate()  for each pick: build a one-flag probe, run it through the SAME
                         runner.run_probe -> sandbox -> detector path as every hand-written probe
    5. coverage_map()    mark flags the hand-written probes already cover ("known")
    6. write_discovered() with --apply: save the NEW, confirmed ones as probe JSON

Rules this module keeps (they are the safety story; tests enforce them):

  * Nothing runs outside the sandbox.  Every execution goes through `Sandbox.run`, which itself
    refuses unless `preflight()` passed.  This module has no other way to start a program.
  * Only tools in spec.ALLOWED_TOOLS.  Every synthesized probe is built with spec.validate().
  * Help text is DATA.  It is parsed, never executed, and it never decides a verdict: only the
    detector's observation of the fake world does.  "The help page says `exec`" is a hint for
    what to test, not a finding.
  * Hard caps: at most `max_candidates` flags, `timeout` seconds per run, `max_seconds` per tool.
  * An effect that was already there with NO flag (the "baseline") is not blamed on the flag.
  * A claimed effect must reproduce in a second, fresh world before it is called a finding.
"""

from __future__ import annotations

import json
import re
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import fixtures, runner, spec as specmod
from .helpparse import Candidate, classify, parse_help
from .sandbox import Sandbox

# ---------------------------------------------------------------- small tables
# Flags we never test: they only print text and exit.
SKIP_FLAGS = {"--help", "--version", "--usage", "-?"}

# Tools whose first non-dash word is a subcommand (`git show`).  Discovery runs per subcommand.
SUBCOMMAND_TOOLS = {"git"}
# find writes long options with ONE dash (-exec).  For every other tool "-cf" means "-c -f".
SINGLE_DASH_LONG_TOOLS = {"find"}

# What to hand to a flag that takes a value.  These are the same harmless placeholders the
# hand-written probes use: a canary program, a file inside the fake world, a never-routable URL.
VALUE = {"exec": "<<canary_exec>>", "fs_write": "<<out>>", "net": "<<url>>"}

# Tool output that means "I do not know that option": the help text mentioned something the tool
# will not accept in this form.  Reported as "rejected", a false lead, not as "no effect".
_REJECT_RE = re.compile(r"unrecogni[sz]ed option|invalid option|unknown option|illegal option|"
                        r"unknown predicate|bad option|invalid switch|unknown flag|no such option|"
                        r"option \S+ is unknown|unknown long option", re.I)

# "Minimum companions", per tool: the scaffolding a flag needs to be meaningful at all.
#   (prefix, suffix)   argv = prefix + the flag + suffix
# Several entries = try them in order until one shows an effect (tar's "mode" flags -c/-x/-r
# conflict with -t, so they need a different scaffold).  THIS TABLE IS HAND-WRITTEN KNOWLEDGE
# about how to *use* each tool, not about which flags are dangerous.  Without it, discovery
# misses flags that only work with a companion (e.g. sort --compress-program needs a merge).
_GIT = ["--no-optional-locks"]       # stops `git status` rewriting .git/index (see DESIGN 10.3)
BASES: dict[str, list[tuple[list[str], list[str]]]] = {
    "tar": [([], ["-tf", "<<archive>>"]), ([], ["-f", "<<archive>>", "hello.txt"]), ([], ["-xf", "<<archive>>"])],
    "sed": [([], ["p", "<<hello>>"])],
    "find": [(["<<victim>>"], [])],
    # curl needs a URL it can fetch with no network: file:// URLs read local files.
    "curl": [([], ["file://<<hello>>"])],
    "sort": [([], ["<<unsorted>>"]),
             ([], ["-m", "--batch-size=2", "<<unsorted>>", "<<hello>>", "<<victim>>"])],
    "git show": [(_GIT + ["show"], ["HEAD"])],
    "git log": [(_GIT + ["log"], [])],
    "git diff": [(_GIT + ["diff"], ["HEAD~1", "HEAD"])],
    "git grep": [(_GIT + ["grep"], ["hello"])],
    "git ls-remote": [(_GIT + ["ls-remote"], ["<<repo>>"])],
    "git status": [(_GIT + ["status"], [])],
}
_DEFAULT_BASES = [([], ["<<hello>>"]), ([], [])]

# Seeds: GTFOBins-style patterns that help text CANNOT reveal, written as complete probes.
# (sed's dangerous parts are script commands, not flags; tar's checkpoint action needs a partner
# flag.)  They are still verified by the detector like everything else, and labelled "seed".
SEEDS: dict[str, list[tuple[str, list[str], str]]] = {
    "sed": [("w", ["-n", "w <<out>>", "<<hello>>"], "fs_write"),
            ("e", ["1e <<canary_exec>>", "<<hello>>"], "exec")],
    "tar": [("--checkpoint-action",
             ["-tf", "<<archive>>", "--checkpoint=1", "--checkpoint-action=exec=<<canary_exec>>"], "exec")],
}


def bases_for(tool: str, sub: str) -> list[tuple[list[str], list[str]]]:
    if tool in SUBCOMMAND_TOOLS and sub:
        return BASES.get(f"{tool} {sub}", [(_GIT + [sub], [])])
    return BASES.get(tool, _DEFAULT_BASES)


# ----------------------------------------------------------------- data types
@dataclass
class Limits:
    max_candidates: int = 100        # flags tested per tool/subcommand
    timeout: float = 3.0             # seconds per sandboxed run
    max_seconds: float = 120.0       # wall-clock budget per tool
    select: str = "keywords"         # "keywords" = only flags with hints, "all" = every parsed flag


@dataclass
class Finding:
    names: list[str]
    sub: str
    source: str                      # "help" | "seed"
    hints: list[str]                 # what the words guessed (NOT evidence)
    status: str                      # effect | no_effect | rejected | timeout
    argv: list[str] = field(default_factory=list)       # template argv of the run that showed the effect
    effects: list[str] = field(default_factory=list)    # NEW effects (beyond the no-flag baseline)
    confidence: dict[str, str] = field(default_factory=dict)
    reproduced: bool | None = None
    evidence: dict = field(default_factory=dict)
    known: str = ""                  # id of a hand-written probe that covers this flag, if any
    tried: int = 0

    @property
    def primary_name(self) -> str:
        """The long name if there is one (`--use-compress-program`), else the first alias."""
        return next((n for n in self.names if n.startswith("--")), self.names[0])

    @property
    def confirmed(self) -> bool:
        """True only for detector-proven effects that happened twice (fs_write / exec, not net text)."""
        return (self.status == "effect" and self.reproduced is True
                and any(self.confidence.get(e) == "confirmed" for e in self.effects))


@dataclass
class DiscoveryReport:
    tool: str
    version: str | None = None       # None = tool not installed here
    help_sources: list[dict] = field(default_factory=list)
    parsed: int = 0
    not_selected: int = 0            # parsed but had no hint, so not tested
    over_cap: int = 0                # had hints but exceeded max_candidates
    budget_exhausted: bool = False
    findings: list[Finding] = field(default_factory=list)
    seconds: float = 0.0

    def to_dict(self) -> dict:
        return {**self.__dict__, "findings": [f.__dict__ | {"confirmed": f.confirmed} for f in self.findings]}


# ---------------------------------------------------------------- coverage
def _subcommand(tool: str, argv: tuple[str, ...]) -> str:
    """For git: the first word that is not a (global) flag, e.g. 'show'.  Others: ''."""
    if tool not in SUBCOMMAND_TOOLS:
        return ""
    skip = False
    for a in argv:
        if skip:
            skip = False
        elif a in ("-c", "-C"):
            skip = True                                  # these take a value: `git -c k=v status`
        elif not a.startswith("-"):
            return a
    return ""


def probe_flags(p: specmod.ProbeSpec) -> set[str]:
    """Every flag a hand-written probe mentions (from its `flag` field and its argv)."""
    out: set[str] = set()
    if p.flag:
        out.add(p.flag.split("=", 1)[0])
    for a in p.argv:
        a = a.split("=", 1)[0]
        if a.startswith("-") and len(a) > 1:
            out.add(a)
            if re.fullmatch(r"-[A-Za-z]{2,}", a) and p.tool not in SINGLE_DASH_LONG_TOOLS:
                out.update("-" + ch for ch in a[1:])      # "-cf" is "-c" and "-f"
    return out


def coverage_map(probes: list[specmod.ProbeSpec], tool: str) -> dict[tuple[str, str], str]:
    """{(subcommand, flag): probe id} for one tool: what the existing probes already test."""
    cov: dict[tuple[str, str], str] = {}
    for p in probes:
        if p.tool == tool:
            for f in probe_flags(p):
                cov.setdefault((_subcommand(tool, p.argv), f), p.id)
    return cov


def covered_by(cov: dict[tuple[str, str], str], sub: str, names: list[str]) -> str:
    """Probe id covering any alias of this option, or ''.  An existing LONG flag that is a prefix
    of the candidate counts too (`--outp` covers `--output`: GNU tools accept abbreviations)."""
    for (s, f), pid in cov.items():
        if s != sub:
            continue
        for n in names:
            if f == n or (n.startswith("--") and f.startswith("--") and len(f) >= 4 and n.startswith(f)):
                return pid
    return ""


# -------------------------------------------------------------- help capture
_HELP_ARGS = [["--help"], ["-h"], ["help"]]
_SUB_HELP_ARGS = [["-h"], ["--help"]]


def capture_help(sandbox: Sandbox, template: Path, scratch: Path, tool: str, sub: str,
                 timeout: float) -> tuple[str, list[dict]]:
    """Run the tool's help INSIDE the sandbox.  Returns (all usable text, a log of what happened)."""
    texts: list[str] = []
    log: list[dict] = []
    for i, args in enumerate(_SUB_HELP_ARGS if sub else _HELP_ARGS):
        argv = [tool, *([sub] if sub else []), *args]
        work = fixtures.fresh_copy(template, scratch / f"help-{sub or 'top'}-{i}")
        res = sandbox.run(work, argv, timeout=timeout)             # <- the only place help is run
        shutil.rmtree(work, ignore_errors=True)
        text = (res.stdout or "") + "\n" + (res.stderr or "")
        if res.timed_out:
            why = "timed out"
        elif _REJECT_RE.search("\n".join(text.splitlines()[:3])):
            why = "tool rejected it"
        elif not (re.search(r"(?im)^\s*(usage|or):", text) or (res.returncode == 0 and len(text.strip().splitlines()) >= 3)):
            why = "does not look like a help page"
        else:
            why = ""
            texts.append(text)
        log.append({"command": " ".join(argv), "chars": len(text.strip()), "used": not why, "why_ignored": why})
    return "\n".join(texts), log


# ---------------------------------------------------------------- testing
class _Lab:
    """Runs throw-away probes for one tool and caches each scaffold's no-flag baseline."""

    def __init__(self, sandbox: Sandbox, template: Path, scratch: Path, tool: str, timeout: float):
        self.sandbox, self.template, self.scratch = sandbox, template, scratch
        self.tool, self.timeout = tool, timeout
        self.n = 0
        self._baselines: dict[tuple, set[str]] = {}

    def run(self, argv: list[str]) -> runner.ProbeResult:
        self.n += 1
        # validate() enforces: tool allowlist, argv is a list of strings, only known <<placeholders>>.
        probe = specmod.validate({"id": f"{self.tool}.disc.try{self.n}", "tool": self.tool,
                                  "argv": argv, "expect": []}, set(fixtures.PLACEHOLDERS))
        result = runner.run_probe(self.sandbox, self.template, probe, self.scratch, self.timeout)
        shutil.rmtree(self.scratch / probe.id, ignore_errors=True)
        return result

    def baseline(self, base: tuple[list[str], list[str]]) -> set[str]:
        key = (tuple(base[0]), tuple(base[1]))
        if key not in self._baselines:
            self._baselines[key] = set(self.run(base[0] + base[1]).effects.effects)
        return self._baselines[key]


def flag_argv(c: Candidate, value: str | None) -> list[str]:
    """The argv words for ONE flag (+ its value).  `--long=VALUE`, `-s VALUE`, `-find VALUE ;`."""
    if c.full_argv is not None:
        return list(c.full_argv)
    name = c.primary
    if value is None:
        return [name]
    if name.startswith("--"):
        return [f"{name}={value}"]
    return [name, value] + ([c.terminator] if c.terminator else [])


def _spellings(c: Candidate, value: str | None) -> list[list[str]]:
    """Ways to write the flag.  Long options first as `--flag=VALUE`; if the tool refuses that
    (curl, ssh and others want `--flag VALUE`) the caller falls back to the two-word spelling."""
    first = flag_argv(c, value)
    if value is None or c.full_argv is not None or not c.primary.startswith("--"):
        return [first]
    return [first, [c.primary, value] + ([c.terminator] if c.terminator else [])]


def _values(c: Candidate) -> list[str | None]:
    """Which values to try for a flag: hinted kinds first, then the other harmless ones."""
    if c.arg == "none" or c.full_argv is not None:
        return [None]
    order = c.hints + [h for h in ("exec", "fs_write") if h not in c.hints]
    vals: list[str | None] = [VALUE[h] for h in order][:3]
    return ([None] + vals) if c.arg == "optional" else vals


def probe_candidate(lab: _Lab, c: Candidate) -> Finding:
    """Try one candidate (all scaffolds x values) until some run shows a NEW effect."""
    f = Finding(names=c.names, sub=c.sub, source=c.source, hints=list(c.hints), status="no_effect")
    bases = [([], [])] if c.full_argv is not None else bases_for(lab.tool, c.sub)
    rejected = timed_out = 0
    for base in bases:
        baseline = lab.baseline(base)
        for value in _values(c):
            for flag_part in _spellings(c, value):
                argv = base[0] + flag_part + base[1]
                r = lab.run(argv)
                f.tried += 1
                timed_out += r.timed_out
                refused = bool(_REJECT_RE.search(r.stderr or ""))
                rejected += refused
                seen = set(r.effects.effects)
                if refused:
                    # A tool that rejected its command line attempted nothing.  Its error message
                    # often just ECHOES our canary URL, which the text heuristic would misread as
                    # a network attempt (a real false positive found while testing curl).
                    seen = {e for e in seen if r.effects.confidence[e] == "confirmed"}
                new = seen - baseline                      # blame the flag only for what is NEW
                if new:
                    again = lab.run(argv)                  # reproduce in a second fresh world
                    f.status, f.argv = "effect", [lab.tool, *argv]
                    f.effects = sorted(new)
                    f.confidence = {e: r.effects.confidence[e] for e in new}
                    f.reproduced = new <= (again.effects.effects - baseline)
                    f.evidence = r.to_dict()["evidence"]
                    return f
                if not refused:
                    break                                  # accepted this spelling: no need for the other
    if f.tried and rejected == f.tried:
        f.status = "rejected"
    elif f.tried and timed_out == f.tried:
        f.status = "timeout"
    return f


# ------------------------------------------------------------ orchestration
def select(cands: list[Candidate], limits: Limits) -> tuple[list[Candidate], int, int]:
    """Choose what to test -> (chosen, not_selected, over_cap).  Seeds always go first."""
    seeds = [c for c in cands if c.source == "seed"]
    helped = [c for c in cands if c.source == "help" and not SKIP_FLAGS.intersection(c.names)]
    chosen = [c for c in helped if c.hints] if limits.select == "keywords" else helped
    chosen.sort(key=lambda c: -len(c.hints))              # more hints first; stable otherwise
    kept = chosen[:limits.max_candidates]
    return seeds + kept, len(helped) - len(chosen), len(chosen) - len(kept)


def discover_tool(sandbox: Sandbox, tool: str, existing: list[specmod.ProbeSpec],
                  subs: list[str] | None = None, limits: Limits | None = None) -> DiscoveryReport:
    """Discover flags for one tool.  `sandbox` must be verified (Sandbox.run enforces it)."""
    limits = limits or Limits()
    if tool not in specmod.ALLOWED_TOOLS:
        raise specmod.SpecError(f"tool {tool!r} is not in the allowlist {sorted(specmod.ALLOWED_TOOLS)}")
    report = DiscoveryReport(tool=tool)
    start = time.monotonic()
    cov = coverage_map(existing, tool)
    if tool in SUBCOMMAND_TOOLS:
        subs = subs or sorted({s for (s, _f) in cov if s})
    else:
        subs = [""]

    with tempfile.TemporaryDirectory(prefix="gtfo-discover-") as td:
        template = fixtures.build_template(Path(td) / "template")
        scratch = Path(td) / "worlds"
        scratch.mkdir()
        report.version = runner.tool_version(sandbox, template, tool, scratch)
        if report.version is None:
            return report                                  # not installed here: nothing to discover
        lab = _Lab(sandbox, template, scratch, tool, limits.timeout)

        cands: list[Candidate] = []
        for sub in subs:
            text, log = capture_help(sandbox, template, scratch, tool, sub, limits.timeout)
            report.help_sources += [{**entry, "sub": sub} for entry in log]
            for c in parse_help(text):
                c.sub = sub
                cands.append(classify(c))
        for name, argv, hint in SEEDS.get(tool, []):
            cands.append(Candidate(names=[name], source="seed", full_argv=argv, hints=[hint]))
        report.parsed = sum(c.source == "help" for c in cands)

        chosen, report.not_selected, report.over_cap = select(cands, limits)
        for c in chosen:
            if time.monotonic() - start > limits.max_seconds:
                report.budget_exhausted = True
                break
            finding = probe_candidate(lab, c)
            finding.known = covered_by(cov, c.sub, c.names)
            report.findings.append(finding)
    report.seconds = round(time.monotonic() - start, 2)
    return report


# ---------------------------------------------------------------- reporting
def render_text(r: DiscoveryReport, show_all: bool = False) -> str:
    if r.version is None:
        return f"== {r.tool}: not installed on this machine, nothing to discover =="
    out = [f"== {r.tool}  ({r.version}) =="]
    for h in r.help_sources:
        label = f"{h['command']}"
        out.append(f"  help: {label:28} " + (f"used ({h['chars']} chars)" if h["used"] else f"ignored: {h['why_ignored']}"))
    tested = len(r.findings)
    out.append(f"  parsed {r.parsed} options from help; tested {tested}; "
               f"not tested (no hint) {r.not_selected}; over the cap {r.over_cap}"
               + ("; TIME BUDGET HIT, list incomplete" if r.budget_exhausted else ""))

    def line(f: Finding) -> str:
        tag = f"known: {f.known}" if f.known else "NEW"
        seed = " [seed]" if f.source == "seed" else ""
        conf = ",".join(f"{e}={f.confidence[e]}" for e in f.effects)
        flags = ", ".join(f.names) + (f" (sub: {f.sub})" if f.sub else "")
        return f"    {flags}{seed}\n        {conf}; reproduced={f.reproduced}; {tag}\n        argv: {' '.join(f.argv)}"

    hits = [f for f in r.findings if f.status == "effect"]
    for title, group in (("CONFIRMED effects (detector saw them, twice)", [f for f in hits if f.confirmed]),
                         ("NOT confirmed (text clue only, or did not reproduce)", [f for f in hits if not f.confirmed])):
        if group:
            out.append(f"  {title}:")
            out += [line(f) for f in group]
    for status, title in (("rejected", "rejected by the tool (false leads from the help text)"),
                          ("timeout", "timed out"), ("no_effect", "ran, no effect observed")):
        names = [", ".join(f.names) for f in r.findings if f.status == status]
        if names:
            shown = names if show_all else names[:12]
            more = "" if len(shown) == len(names) else f" ... (+{len(names) - len(shown)} more; --show-all)"
            out.append(f"  {title}: {len(names)}\n      " + "; ".join(shown) + more)
    n_conf = [f for f in hits if f.confirmed]
    out.append(f"  summary: {len(n_conf)} confirmed ({sum(1 for f in n_conf if f.known)} already covered by hand probes, "
               f"{sum(1 for f in n_conf if not f.known)} new), {len(hits) - len(n_conf)} unconfirmed, "
               f"{tested - len(hits)} no effect/rejected/timeout  [{r.seconds}s]")
    return "\n".join(out)


# ------------------------------------------------------------------ --apply
class DiscoverError(ValueError):
    pass


def _slug(finding: Finding) -> str:
    """Probe-id piece from the flag name.  Probe ids are lowercase, so `-I` becomes `cap-i`."""
    name = finding.primary_name.lstrip("-") or "flag"
    name = re.sub(r"[A-Z]", lambda m: "cap-" + m.group().lower(), name)
    name = re.sub(r"[^a-z0-9_-]+", "-", name).strip("-") or "flag"
    return (f"{finding.sub}-" if finding.sub else "") + name


def build_probe_dicts(report: DiscoveryReport, taken_ids: set[str]) -> list[dict]:
    """New probe JSON objects for NEW + confirmed findings.  Hand-written probes are never touched."""
    out = []
    for f in report.findings:
        if not f.confirmed or f.known:
            continue
        pid = f"{report.tool}.disc.{_slug(f)}"
        while pid in taken_ids:
            pid += "-x"
        taken_ids.add(pid)
        raw = {
            "id": pid, "tool": report.tool, "argv": f.argv[1:],
            "expect": sorted(f.effects),
            "description": (f"[discovered] `{report.tool} {' '.join(f.argv[1:])}` showed "
                            f"{'/'.join(f.effects)} in the sandbox (reproduced; tool {report.version}). "
                            "Found by `gtfo-probe discover`, not hand-written: review before trusting."),
            "flag": f.primary_name, "tags": ["discovered"] + (["seed"] if f.source == "seed" else []),
        }
        specmod.validate(raw, set(fixtures.PLACEHOLDERS))         # a bad probe is an error, not a file
        out.append(raw)
    return out


def write_discovered(report: DiscoveryReport, out_path: Path, taken_ids: set[str]) -> tuple[int, int]:
    """Write/extend `out_path` with new discovered probes -> (added, total in file).

    Refuses to touch a file that is not ours (no "discovery" marker): hand-written probe files
    are never overwritten.  Existing discovered probes in the file are kept."""
    out_path = Path(out_path)
    old: list[dict] = []
    if out_path.exists():
        try:
            data = json.loads(out_path.read_text())
        except json.JSONDecodeError as exc:
            raise DiscoverError(f"{out_path} exists but is not valid JSON ({exc}); not touching it") from exc
        if not isinstance(data, dict) or "discovery" not in data or not isinstance(data.get("probes"), list):
            raise DiscoverError(f"{out_path} exists and was not written by `discover`; refusing to overwrite it")
        old = data["probes"]
    new = build_probe_dicts(report, taken_ids | {p["id"] for p in old})
    if not new:
        return 0, len(old)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    doc = {"discovery": {"note": "machine-discovered probes; every one was confirmed by the detector twice "
                                 "in the sandbox, but review before relying on them",
                         "tool_version": report.version,
                         "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")},
           "probes": old + new}
    out_path.write_text(json.dumps(doc, indent=2) + "\n")
    return len(new), len(old) + len(new)
