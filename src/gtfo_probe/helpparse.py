"""Help-text parser: turn `--help` output into a list of *candidate* flags.

This module is PURE TEXT PROCESSING.  It never runs anything.  (The help text itself is
captured elsewhere, inside the verified sandbox: see discover.py.)

Two jobs:

  1. parse_help(text)  ->  [Candidate, ...]   "which options does this help page mention?"
  2. classify(cand)    ->  fills cand.hints   "which capability might it have?"

A "hint" is only a GUESS made from words ("--output", "FILE", "execute PROGRAM").  Words in
a help page are not proof of anything.  discover.py never reports a hint as a finding; it
only uses hints to decide which flags are worth *testing*.  The detector decides the truth.

What a help page looks like (three real shapes this parser has to cope with)

    GNU style (tar, sed, sort):   "  -I, --use-compress-program=PROG  filter through PROG"
    git style:                    "    -L <range:file>       trace the evolution of ..."
    prose style (find):           "      -fprintf FILE FORMAT -print -fprint0 FILE -fprint FILE"
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# ---------------------------------------------------------------- data type
@dataclass
class Candidate:
    names: list[str]                 # aliases of ONE option, e.g. ["-I", "--use-compress-program"]
    arg: str = "none"                # "none" | "required" | "optional"
    metavar: str = ""                # the placeholder the help page uses, e.g. "PROG"
    text: str = ""                   # the description text next to it (used only for hints)
    terminator: str = ""             # ";" for `find -exec COMMAND ;` (the command must be closed)
    sub: str = ""                    # subcommand this flag belongs to ("show" for `git show`)
    source: str = "help"             # "help" (parsed) or "seed" (hand-written starting point)
    full_argv: list[str] | None = None   # seeds only: the complete argv template to run
    hints: list[str] = field(default_factory=list)   # guesses: subset of exec / fs_write / net

    @property
    def primary(self) -> str:
        """The name we will type: the long form if there is one (`--flag=VALUE` is unambiguous)."""
        longs = [n for n in self.names if n.startswith("--")]
        return longs[0] if longs else self.names[0]


# ------------------------------------------------------------ finding flags
# A flag is `-x`, `--long-name` or find-style `-longname`.  The look-behind refuses to start
# in the middle of a word (so "non-existent" is not flag "-existent") or after "=" or "/".
# `--[no-]quiet` is read as `--quiet`.
_FLAG = re.compile(r"(?<![\w/.<>=-])(--?)(?:\[no-\])?([A-Za-z][\w-]*)")

# How an option's argument is written right after the flag.  Tried in this order.
_ARG_OPTIONAL_EQ = re.compile(r"^\[=([^\]\s]+)\]")          # --in-place[=SUFFIX]
_ARG_EQ = re.compile(r"^=([^\s,|\]\[]+)")                     # --output=FILE
_ARG_OPTIONAL = re.compile(r"^\[([^\]\s]+)\]")               # -i[SUFFIX]
_ARG_UPPER = re.compile(r"^ ([A-Z][A-Z0-9_]*|<[^>\s]+>)(?=[\s,;|\]]|$)")   # -I PROG   -L <range>
_ARG_LOWER = re.compile(r"^ ([a-z][\w-]*)\s*(?=,|$)")        # -e script,   (option lines only)
_ALIAS_GLUE = re.compile(r"\s*[,|/]\s*")                      # "-I, --use-..."  or  "-v | --version"
_TERMINATED = re.compile(r"^\s*(?:\{\}\s*)?;")                # "COMMAND ;" or "COMMAND {} ;"


def _parse_arg(tail: str, allow_lower: bool) -> tuple[str, str, int]:
    """Look at the text right after a flag; return (arg kind, metavar, characters used)."""
    for rx, kind in ((_ARG_OPTIONAL_EQ, "optional"), (_ARG_EQ, "required"), (_ARG_OPTIONAL, "optional"),
                     (_ARG_UPPER, "required")):
        m = rx.match(tail)
        if m:
            return kind, m.group(1).strip("<>"), m.end()
    if allow_lower:
        m = _ARG_LOWER.match(tail)
        if m:
            return "required", m.group(1), m.end()
    return "none", "", 0


def _parse_option_part(part: str, allow_lower: bool) -> list[Candidate]:
    """Parse one stretch of text holding one or more flags -> candidates (aliases merged)."""
    matches = list(_FLAG.finditer(part))
    out: list[Candidate] = []
    group: list[tuple[str, str, str, str]] = []          # (name, arg, metavar, terminator)
    for i, m in enumerate(matches):
        stop = matches[i + 1].start() if i + 1 < len(matches) else len(part)
        tail = part[m.end():stop]
        arg, metavar, used = _parse_arg(tail, allow_lower)
        rest = tail[used:]
        term = ";" if arg == "required" and _TERMINATED.match(rest) else ""
        name = m.group(1) + m.group(2).rstrip("-")
        if len(name.lstrip("-")) == 0:
            continue
        group.append((name, arg, metavar, term))
        if _ALIAS_GLUE.fullmatch(rest) and i + 1 < len(matches):
            continue                                       # "-I, --use-..." : same option, keep collecting
        # Merge the aliases into one candidate; the "strongest" argument description wins.
        best = max(group, key=lambda g: {"none": 0, "optional": 1, "required": 2}[g[1]])
        out.append(Candidate(names=[g[0] for g in group], arg=best[1], metavar=best[2], terminator=best[3]))
        group = []
    return out


def parse_help(text: str, max_options: int = 500) -> list[Candidate]:
    """Extract candidate options from help text.  Never raises on odd input; at worst returns []."""
    lines = text.splitlines()[:3000]                       # a runaway help page cannot make us slow
    found: list[Candidate] = []
    seen: set[str] = set()                                 # every name already taken (aliases too)
    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            continue
        # An "option line" starts with a dash: the flags come first, then 2+ spaces, then prose.
        is_option_line = stripped.startswith("-")
        description = ""
        part = stripped
        if is_option_line:
            pieces = re.split(r"\s{2,}|\t", stripped, maxsplit=1)
            part = pieces[0]
            description = pieces[1] if len(pieces) > 1 else ""
            indent = len(line) - len(line.lstrip())
            for nxt in lines[i + 1:i + 6]:                 # continuation lines (indented deeper)
                if not nxt.strip() or nxt.strip().startswith("-") or len(nxt) - len(nxt.lstrip()) <= indent:
                    break
                description += " " + nxt.strip()
        for cand in _parse_option_part(part, allow_lower=is_option_line):
            cand.text = description
            if not seen.intersection(cand.names):           # the same option listed twice: keep the first
                seen.update(cand.names)
                found.append(cand)
        if len(found) >= max_options:
            break
    return found


# ------------------------------------------------------------------- hints
# Words in a flag's name / metavar / description that *suggest* a capability.  Prefix match on
# a word start (so "exec" matches "execute" and "-execdir").  These are guesses used only to
# decide what to test; see the module docstring.
_EXEC_WORDS = re.compile(r"\b(exec|command|program|compress|pager|askpass|proxy|script|shell|eval|open|"
                         r"editor|helper|plugin|hook|run|ok)", re.I)
_WRITE_WORDS = re.compile(r"\b(output|outfile|write|save|dump|log|append|create|extract|delete|remove|"
                          r"in-place|overwrite|store|record|backup|update|truncate|fprint|fls|print)", re.I)
_NET_WORDS = re.compile(r"\b(upload|url|http|ftp|proxy|host|server|remote|connect|fetch|download|socks|resolve)",
                        re.I)

# What a metavar (the placeholder like PROG or FILE) says about the argument's kind.
_PROGRAM_VARS = {"prog", "program", "command", "cmd", "script", "shell", "pager", "editor", "helper",
                 "exe", "executable", "handler"}
_FILE_VARS = {"file", "path", "dir", "directory", "output", "outfile", "dest", "destination", "target",
              "log", "archive"}
_URL_VARS = {"url", "uri", "host", "server", "proxy", "address"}


def metavar_kind(metavar: str) -> str:
    """'exec' for program-like, 'fs_write' for file-like, 'net' for url-like, else ''.
    Only the LAST word counts: "script-file" is a file, not a program."""
    parts = [p for p in re.split(r"[-_:./]", metavar.lower()) if p and not p.isdigit()]
    last = parts[-1] if parts else ""
    last = re.sub(r"\d+$", "", last)
    if last in _PROGRAM_VARS:
        return "exec"
    if last in _FILE_VARS:
        return "fs_write"
    if last in _URL_VARS:
        return "net"
    return ""


def classify(c: Candidate) -> Candidate:
    """Fill c.hints with guesses, most likely first.  Seeds keep the hints they were given."""
    if c.source == "seed" and c.hints:
        return c
    hints: list[str] = []
    kind = metavar_kind(c.metavar) if c.arg != "none" else ""
    if kind:
        hints.append(kind)
    blob = " ".join(c.names + [c.metavar, c.text])
    for rx, effect in ((_EXEC_WORDS, "exec"), (_WRITE_WORDS, "fs_write"), (_NET_WORDS, "net")):
        if rx.search(blob) and effect not in hints:
            hints.append(effect)
    c.hints = hints
    return c
