"""The checking logic: compare allowlist entries with the capability database.

For every Entry we answer ONE question:

    "Which probed capabilities (exec / fs_write / net) can this entry still reach?"

Step by step (see docs/WALKTHROUGH.md section 9 for a worked example):

  1. Find the tool in the DB            -> not there?  status "unknown_tool"
  2. Pick the probes that are in scope  -> none?       status "unknown_scope"
       - `git show:*`  : only probes whose git subcommand is `show`
       - `git:*`       : every git probe
       - `find:*`      : every find probe (find has no subcommands)
       - exact entry   : only probes whose flag literally appears in the entry
  3. Any in-scope probe with an observed effect becomes a Finding.
  4. Nothing observed in scope           -> "no_known_risk"  (NEVER the word "safe")

The DB only knows what the bundled probes tested, on the tool versions listed in
it.  So "no_known_risk" means "we looked and saw nothing", and "unknown_*" means
"we did not look".  The report says this out loud.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace

from .allowlist import Entry
from .spec import RUNNER_TAG

# Tools with real subcommands: the word after the tool name selects the behaviour.
SUBCOMMAND_TOOLS = frozenset({"git", "npm", "pip"})

# Names people write in allowlists that map onto tools we probed under another name.
# `awk` is whichever awk the system has; we probed both common ones.
TOOL_ALIASES = {"awk": ("gawk", "mawk"), "pip3": ("pip",), "python": ("python3",)}

# Pagers (and man, which starts one) can run commands (`!cmd`, LESSOPEN...) but only when
# attached to a terminal.  gtfo-probe's sandbox has no terminal, so probing them would report a
# misleading "no effect"; they are deliberately left UNKNOWN.  Hint only, NOT probe data.
PAGER_HINT = frozenset({"less", "more", "most", "man", "pager"})

# Programs that exist to run OTHER programs.  This is NOT probe data, just a
# built-in hint so "unknown" is not mistaken for "boring".
# Only used when the tool is NOT in the capability DB; tools that were probed (env, xargs, python3,
# node, make, npx...) are reported from probe data instead (see "runner tools" below).
RUNNER_HINT = frozenset({"bash", "sh", "zsh", "dash", "env", "xargs", "sudo", "doas", "nohup", "timeout",
                         "nice", "watch", "python", "python3", "node", "perl", "ruby", "npx", "docker",
                         "make", "awk", "ssh", "php", "lua", "busybox", "setsid", "stdbuf", "script"})

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
# (effect, intrinsic) -> severity.  "intrinsic" = the tool does it in plain use,
# with no special flag (probe has an empty `flag`), e.g. curl -> network.
SEVERITY = {
    ("exec", False): "critical", ("exec", True): "critical",
    ("fs_write", False): "high", ("fs_write", True): "low",
    ("net", False): "medium", ("net", True): "medium",
}


@dataclass
class Finding:
    severity: str
    effect: str                  # exec | fs_write | net
    flag: str                    # the flag that unlocks it ("" = plain use)
    probe: str                   # evidence probe id in the DB
    tool_version: str            # e.g. "git@2.47.3"
    confidence: str              # confirmed | attempted
    evidence: str                # one human-readable line from the DB record
    description: str
    abbreviation: dict | None    # {"status": works|rejected, "flag": ..., "probe": ...} or None
    fix: str = ""
    by_design: bool = False      # True: the tool/subcommand exists to run programs ("runner"), not a flag quirk


@dataclass
class EntryReport:
    entry: Entry
    status: str                  # findings | no_known_risk | unknown_tool | unknown_scope | allow_all | skipped
    tool_versions: list[str] = field(default_factory=list)
    probes_in_scope: int = 0
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    fix: str = ""                # suggested fix for the whole entry (empty when no findings)

    @property
    def top_severity(self) -> str:
        if self.status == "allow_all":
            return "critical"
        return max((f.severity for f in self.findings), key=SEVERITY_ORDER.index, default="")


# ------------------------------------------------------------- scope matching

def _is_placeholder(word: str) -> bool:
    return word.startswith("<<") and word.endswith(">>")


def _git_subcommand(argv_after_tool: list[str]) -> str | None:
    """`git show --output=x HEAD` -> "show".  `git -c a=b status` -> None (starts with a flag)."""
    return argv_after_tool[0] if argv_after_tool and not argv_after_tool[0].startswith("-") else None


def _flag_in_words(flag: str, words: tuple[str, ...]) -> bool:
    """Does the probe's flag literally appear in the entry's pinned words?

    Long flags also match by prefix in either direction (`--outpu` vs `--output`),
    because git/GNU tools accept unique abbreviations.
    """
    for w in words:
        name = w.split("=", 1)[0]
        if name == flag:
            return True
        if flag.startswith("--") and name.startswith("--") and len(name) > 2 and (
                flag.startswith(name) or name.startswith(flag)):
            return True
    return False


def probe_in_scope(entry: Entry, probe: dict) -> bool:
    if "baseline" in probe.get("tags", []):
        return True                                # "every command of this tool does this" (npm's log file)
    argv = probe["argv"][1:]                       # drop the tool name
    if not entry.any_args:
        # Exact entry: nothing can be appended, so only what is written counts.
        if probe["flag"]:
            return _flag_in_words(probe["flag"], entry.words)
        return len(argv) == len(entry.words) and all(
            _is_placeholder(a) or a == w for a, w in zip(argv, entry.words))
    # Prefix entry: extra arguments may follow.
    if entry.tool in SUBCOMMAND_TOOLS and entry.words:
        if entry.words[0].startswith("-"):
            return True                            # pinned global flag: stay conservative, count all
        return _git_subcommand(argv) == entry.words[0]
    return True                                    # bare tool, or a tool without subcommands


# ------------------------------------------------------------------- findings

def _evidence_line(rec: dict, effect: str) -> str:
    ev = rec.get("evidence", {})
    if effect == "exec" and ev.get("exec_log"):
        return f"canary program ran: {ev['exec_log'][0]}"
    if effect == "fs_write" and ev.get("fs_changes"):
        c = ev["fs_changes"][0]
        return f"file {c['change']}: {c['path']}"
    if effect == "net" and ev.get("net"):
        return f"network attempt: {str(ev['net'][0])[:70]}"
    return "see the probe record in the DB"


def _exact_hint(entry: Entry) -> str:
    shown = " ".join((entry.tool, *entry.words))
    return {"claude": f"write the whole command with no `*`/`:*`, e.g. `Bash({shown} <the exact arguments>)`",
            "plain": f"end the line with ` $` and write the whole command, e.g. `{shown} <the exact arguments> $`",
            "codex": "Codex rules are always prefixes, so use decision=\"prompt\" for this command"}[entry.fmt]


def entry_fix(entry: Entry) -> str:
    """The suggested fix for an entry (the same for all its findings, so text output prints it once)."""
    if not entry.any_args:
        return "already an exact entry: the effect comes from the command itself; decide if that is acceptable."
    return f"pin the exact command ({_exact_hint(entry)}), or remove this entry."


def _fix(entry: Entry, f: Finding) -> str:
    """Per-finding fix = the entry fix, plus a warning when the flag also works abbreviated."""
    text = entry_fix(entry)
    if entry.any_args and f.abbreviation and f.abbreviation["status"] == "works":
        text += f" Denying `{f.flag}` is not enough: `{f.abbreviation['flag']}` also works."
    return text


# Mitigations the AGENT applies on its own that gtfo-probe does not model.  Shown as
# notes so a finding is not mistaken for "definitely exploitable in that agent".
# Source for every Claude Code note: https://code.claude.com/docs/en/permissions
# (re-read 2026-10-19, Claude Code 2.1.303).  gtfo-probe does not run Claude Code
# to verify them; they are the docs' claims.
CLAUDE_DOCS = "https://code.claude.com/docs/en/permissions"
AGENT_NOTES = {("claude", "find"): ("Claude Code's docs say a `find` prefix rule cannot auto-approve find with an "
                                    "action that runs commands, deletes or writes files (-exec, -delete, -fprint...) "
                                    "or with -files0-from: it still prompts in Manual mode. Not modelled here; "
                                    "verify on your agent version.")}
# Built-in read-only set: auto-allowed with NO rule, in every mode, not configurable.
CLAUDE_READ_ONLY = frozenset({"ls", "cat", "echo", "pwd", "head", "tail", "grep", "find", "wc", "which",
                              "diff", "stat", "du", "cd", "git"})
# Read-only commands with write/exec-capable flags: an unquoted glob forces a prompt.
CLAUDE_GLOB_PROMPT = frozenset({"find", "sort", "sed", "git"})
# Exec wrappers a prefix rule can never auto-approve.
CLAUDE_EXEC_WRAPPERS = frozenset({"watch", "setsid", "ionice", "flock"})
# File commands whose named paths Claude Code checks against Read/Edit rules.
CLAUDE_FILE_COMMANDS = frozenset({"cat", "head", "tail", "sed", "tee"})


def claude_notes(entry: Entry, findings: list[Finding]) -> list[str]:
    """Agent-side behaviour from Claude Code's docs that changes how to read this entry."""
    out = []
    t = entry.tool
    if findings and ("claude", t) in AGENT_NOTES:
        out.append("agent note: " + AGENT_NOTES[("claude", t)])
    if t in CLAUDE_READ_ONLY:
        what = "read-only forms of `git`" if t == "git" else f"read-only uses of `{t}`"
        out.append(f"agent note: Claude Code auto-allows {what} with NO allow rule (built-in, not configurable), "
                   "so removing this entry does not stop them; add an `ask`/`deny` rule to force a prompt.")
    if findings and t in CLAUDE_GLOB_PROMPT:
        out.append(f"agent note: Claude Code prompts for `{t}` when the command has an unquoted glob (it could "
                   "expand to a flag); a flag typed out literally is not covered by that check.")
    if t in CLAUDE_EXEC_WRAPPERS:
        out.append(f"agent note: Claude Code's docs say a prefix rule cannot auto-approve the exec wrapper `{t}`; "
                   "it still prompts unless the rule is an exact command.")
    writes = [f for f in findings if f.effect == "fs_write" and f.flag]
    if writes:
        if t in CLAUDE_FILE_COMMANDS:
            out.append(f"agent note: Claude Code applies Read/Edit rules to the paths `{t}` names, which may limit "
                       "where these writes land; not modelled, verify on your agent version.")
        else:
            out.append("agent note: Claude Code checks `>`/`>>`/`tee` targets against Edit rules, but its docs list "
                       f"no such check for a file written by a flag (e.g. `{writes[0].flag}`); Edit deny rules "
                       "do not cover it, use the OS sandbox.")
    if out:
        out.append(f"agent notes are Claude Code's documented behaviour ({CLAUDE_DOCS}), not probe data")
    return out


GENERAL_ADVICE = ("deny by CAPABILITY, not by flag string: spellings (abbreviations, config flags like `git -c`, "
                  "wrappers, full paths) dodge string rules, so also run the agent's shell in an OS sandbox "
                  "(no network, read-only except the project) or check the whole argv in a hook.")


def _abbreviations(probes: list[dict]) -> dict[str, dict]:
    """Map base probe id -> info about its `-abbrev` twin (if the DB has one)."""
    by_id = {p["id"]: p for p in probes}
    out = {}
    for p in probes:
        if p["id"].endswith("-abbrev"):
            base = p["id"][: -len("-abbrev")]
            if base in by_id:
                base_effects = set(by_id[base]["observed"])
                works = bool(base_effects) and base_effects <= set(p["observed"])
                out[base] = {"status": "works" if works else "rejected", "flag": p["flag"], "probe": p["id"]}
    return out


def _is_runner_probe(rec: dict) -> bool:
    return RUNNER_TAG in rec.get("tags", [])


def _runner_finding(entry: Entry, key: str, evidence_probe: dict, whole_tool: bool) -> Finding:
    """ONE 'critical by design' finding that stands in for every runner probe in scope."""
    what = key.split("@")[0] if whole_tool else f"this part of {key.split('@')[0]}"
    return Finding(
        severity="critical", effect="exec", flag="", probe=evidence_probe["id"], tool_version=key,
        confidence=evidence_probe["confidence"].get("exec", "unknown"),
        evidence=_evidence_line(evidence_probe, "exec"),
        description=(f"{what} exists to run other programs or code you hand it, so an entry that allows "
                     "arguments allows arbitrary exec (and, through that, any file write and network access)."),
        abbreviation=None, by_design=True,
        fix=("remove this entry or pin the exact command: " + _exact_hint(entry)
             + ". There is no safe flag list for a runner tool."),
    )


def _findings_for(entry: Entry, key: str, tool_rec: dict) -> tuple[list[Finding], int]:
    probes = tool_rec["probes"]
    category = tool_rec.get("category", "standard")       # DBs made before milestone 3 have no category
    abbrevs = _abbreviations(probes)
    twin_ids = {a["probe"] for a in abbrevs.values()}
    findings: list[Finding] = []
    # "How much did we actually test around this entry?"  Always measured as if
    # extra arguments were allowed, so an exact `find . -name x` still counts as
    # "checked against every known find flag" (none of them are in the text).
    as_prefix = replace(entry, any_args=True)
    in_scope = sum(probe_in_scope(as_prefix, rec) for rec in probes)
    for rec in probes:
        if not probe_in_scope(entry, rec):
            continue
        if rec["id"] in twin_ids:                  # reported as a note on its base probe instead
            continue
        for effect in rec["observed"]:
            f = Finding(
                severity=SEVERITY[(effect, rec["flag"] == "")], effect=effect, flag=rec["flag"],
                probe=rec["id"], tool_version=key,
                confidence=rec["confidence"].get(effect, "unknown"),
                evidence=_evidence_line(rec, effect), description=rec["description"],
                abbreviation=abbrevs.get(rec["id"]),
            )
            f.fix = _fix(entry, f)
            findings.append(f)
    # "Runner tools" (critical by design).  Only for entries that let arguments through: an exact
    # entry runs exactly the pinned command, so the normal per-flag analysis applies to it.
    if entry.any_args:
        runner_probes = [rec for rec in probes
                         if "exec" in rec["observed"] and (
                             (category == "runner" and _is_runner_probe(rec))
                             or (_is_runner_probe(rec) and probe_in_scope(entry, rec)))]
        if runner_probes:
            runner_ids = {rec["id"] for rec in runner_probes}
            # prefer the plainest evidence: a probe with no special flag ("it just runs the command")
            evidence = min(runner_probes, key=lambda r: (r["flag"] != "", r["id"]))
            if category == "runner":
                findings = []                                   # everything else is subsumed
            else:
                findings = [f for f in findings if f.probe not in runner_ids]
            findings.append(_runner_finding(entry, key, evidence, whole_tool=(category == "runner")))
    for f in findings:
        if not f.by_design and f.probe in {r["id"] for r in probes if _is_runner_probe(r)}:
            f.by_design = True                                  # exact entry that hits a runner probe
    findings.sort(key=lambda f: (-SEVERITY_ORDER.index(f.severity), f.flag, f.probe))
    return findings, in_scope


def check_entry(entry: Entry, db: dict) -> EntryReport:
    if entry.kind == "skipped":
        return EntryReport(entry, "skipped", notes=list(entry.notes))
    if entry.kind == "allow_all":
        return EntryReport(entry, "allow_all", notes=list(entry.notes) +
                           ["every capability is reachable; gtfo-probe cannot narrow this"])

    names = {entry.tool, *TOOL_ALIASES.get(entry.tool, ())}
    keys = [k for k in db["tools"] if k.split("@")[0] in names]
    notes = list(entry.notes)
    if keys and entry.tool in TOOL_ALIASES:
        notes.append(f"`{entry.tool}` is checked as {', '.join(sorted({k.split('@')[0] for k in keys}))} "
                     "(whichever your system uses)")
    if not keys:
        if entry.tool in RUNNER_HINT:
            notes.append(f"`{entry.tool}` runs other programs; it can reach exec/fs_write/net. "
                         "This is a built-in hint, NOT probe data.")
        if entry.tool in PAGER_HINT:
            notes.append(f"`{entry.tool}` is (or starts) a pager: it can run commands (`!cmd`, LESSOPEN) but only on a terminal, "
                         "and gtfo-probe's sandbox has none, so it cannot be probed. This is a built-in hint, "
                         "NOT probe data.")
        notes.append("tool not in the capability DB: UNKNOWN (not tested), not safe")
        if entry.fmt == "claude":
            notes.extend(claude_notes(entry, []))
        return EntryReport(entry, "unknown_tool", notes=notes)

    findings: list[Finding] = []
    in_scope = 0
    for key in keys:
        f, n = _findings_for(entry, key, db["tools"][key])
        findings += f
        in_scope += n
    if entry.tool in SUBCOMMAND_TOOLS and entry.words and not entry.words[0].startswith("-"):
        if len(entry.words) > 1:
            notes.append("words after the subcommand are not analysed; all probes for the subcommand count")
    if entry.any_args and entry.words and entry.tool not in SUBCOMMAND_TOOLS:
        notes.append("pinned words are not analysed; all probes for this tool count")
    if not entry.any_args:
        notes.append("exact entry: only flags literally written in it were checked")
        if any(db["tools"][k].get("category") == "runner" for k in keys):
            notes.append("runner tool: an exact entry runs exactly the pinned command, so judge THAT command "
                         "(whatever it starts), not gtfo-probe's flag list")
    if entry.fmt == "claude":
        notes.extend(claude_notes(entry, findings))
    elif findings and (entry.fmt, entry.tool) in AGENT_NOTES:
        notes.append("agent note: " + AGENT_NOTES[(entry.fmt, entry.tool)])
    if findings and entry.any_args:
        notes.append("recommendation: " + GENERAL_ADVICE)
    status = "findings" if findings else ("no_known_risk" if in_scope else "unknown_scope")
    if status == "unknown_scope":
        notes.append(f"no probes cover `{entry.tool} {entry.words[0] if entry.words else ''}`: UNKNOWN (not tested)")
    if status == "no_known_risk":
        notes.append("probes for this scope showed no effect; that is not a proof of safety")
    fix = ""
    if findings:
        fix = next((f.fix for f in findings if f.by_design and not f.flag), entry_fix(entry))
    return EntryReport(entry, status, tool_versions=keys, probes_in_scope=in_scope, findings=findings, notes=notes,
                       fix=fix)


def check_all(entries: list[Entry], db: dict) -> list[EntryReport]:
    return [check_entry(e, db) for e in entries]


def summarize(reports: list[EntryReport]) -> dict:
    counts: dict[str, int] = {}
    for r in reports:
        counts[r.status] = counts.get(r.status, 0) + 1
    sev: dict[str, int] = {}
    for r in reports:
        for f in r.findings:
            sev[f.severity] = sev.get(f.severity, 0) + 1
        if r.status == "allow_all":
            sev["critical"] = sev.get("critical", 0) + 1
    by_design = sum(any(f.by_design for f in r.findings) for r in reports)
    return {"entries": len(reports), "by_status": counts, "findings_by_severity": sev,
            "entries_critical_by_design": by_design}


def exit_code(reports: list[EntryReport], strict: bool, ignore_unknown: bool = False) -> int:
    """0 = fine (or not strict).  1 = strict mode and something needs attention."""
    if not strict:
        return 0
    for r in reports:
        if r.status in ("findings", "allow_all"):
            return 1
        if r.status in ("unknown_tool", "unknown_scope") and not ignore_unknown:
            return 1
    return 0
