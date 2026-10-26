"""Allowlist parsing: turn an agent's "commands I may run" file into Entry objects.

An Entry answers three questions about ONE allowed command pattern:

    tool      which program?                      "git"
    words     which words are pinned after it?    ("show",)
    any_args  may extra arguments follow?         True  for `git show:*`
                                                  False for an exact `git show HEAD`

Three input formats are understood (each verified against public docs on
2026-10-16; see docs/DESIGN.md section 9 for the links):

  plain   one pattern per line.  `git show`  means "git show with any arguments".
          A trailing ` $` means "exactly this, nothing more".  `#` starts a comment.
  claude  Claude Code settings.json:  {"permissions": {"allow": ["Bash(git show:*)"]}}
          `Bash(x:*)` and `Bash(x *)` = x plus any arguments; no `*` = exact command;
          a `*` in the middle pins only the words BEFORE it; a leading `*`
          (`Bash(* --version)`) matches ANY program; `:*` is only special at the
          very end (`Bash(git:* push)` has a literal colon and matches nothing).
          Claude Code strips the wrappers timeout/time/nice/nohup/stdbuf/command/
          builtin/noglob (and flag-less `xargs`) before matching, so
          `Bash(timeout 30 make *)` is analysed as `make`.  `ask` and `deny` Bash
          rules are read and attached as notes (they win over allow, but are
          string rules).  Re-checked against
          https://code.claude.com/docs/en/permissions on 2026-10-19 (Claude Code 2.1.303).
  codex   Codex `.rules` file (Starlark):  prefix_rule(pattern=["git","show"])
          = argv starts with these words; `decision` defaults to "allow".

Nothing here executes the input: JSON goes through json.loads and the Codex file
goes through Python's `ast` parser (parse only, never eval/exec).
"""

from __future__ import annotations

import ast
import itertools
import json
import os
import shlex
from dataclasses import dataclass, field

FORMATS = ("plain", "claude", "codex")

# Words that end one command and start another ("a && b").  Each part of a
# compound entry is analysed on its own, because the agents check them that way.
_SEPARATORS = {"&&", "||", ";", "|", "|&", "&"}


class AllowlistError(ValueError):
    """The allowlist file could not be read or understood."""


@dataclass
class Entry:
    raw: str                          # the entry exactly as written, for display
    fmt: str                          # plain | claude | codex
    kind: str = "command"             # "command" | "allow_all" | "skipped"
    tool: str = ""                    # program name, e.g. "git" ("" unless kind == "command")
    words: tuple[str, ...] = ()       # pinned words after the tool name
    any_args: bool = True             # may more arguments follow `words`?
    notes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------- one pattern

def _tokens(text: str) -> list[str]:
    lexer = shlex.shlex(text, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    try:
        return list(lexer)
    except ValueError as exc:             # e.g. unbalanced quote
        raise AllowlistError(f"cannot parse {text!r}: {exc}") from exc


def parse_pattern(text: str, fmt: str, default_any_args: bool, raw: str | None = None) -> list[Entry]:
    """Parse one command pattern into one Entry per command in it.

    `default_any_args` is what happens when the pattern has no explicit marker:
    True for plain (`git show` = prefix), False for Claude Code (no `*` = exact).
    """
    raw = raw if raw is not None else text
    text = text.strip()
    any_args = default_any_args
    notes: list[str] = []

    if text in ("", "*"):
        return [Entry(raw, fmt, kind="allow_all", notes=["matches EVERY command"])]
    if fmt == "claude":
        body = text[:-2] if text.endswith(":*") else text
        if ":*" in body:      # docs: `:*` is only recognised at the END; elsewhere the colon is literal
            return [Entry(raw, fmt, kind="skipped",
                          notes=["`:*` before the end is a literal colon in Claude Code, so this rule matches "
                                 "no real command (write `Bash(git push *)` style instead); not analysed"])]
        if text.startswith("*") and text.strip("* "):
            return [Entry(raw, fmt, kind="allow_all",
                          notes=["a leading `*` stands in for the PROGRAM, so any program matches "
                                 "(Claude Code docs: `Bash(* --version)` matches `bash -c 'echo hi' --version`)"])]

    # Explicit markers.  `:*` and ` *` are the same thing in Claude Code.
    if text.endswith(":*"):
        text, any_args = text[:-2], True
    elif text.endswith(" *"):
        text, any_args = text[:-2], True
    elif text.endswith(" $"):
        text, any_args = text[:-2], False
    # Any other `*` is a wildcard too: only the words before it are pinned.
    if "*" in text:
        text = text.split("*", 1)[0]
        any_args = True
        if text and not text.endswith(" "):          # the `*` touches a word, e.g. `ls*`
            if " " in text:
                text = text.rsplit(" ", 1)[0]          # drop the half word
            else:
                notes.append("wildcard glued to the program name (like `ls*`) also matches longer names")
        notes.append("text after the first `*` is not analysed: everything there is assumed allowed")

    toks = _tokens(text)
    # Split compound commands on && || ; | ...
    parts: list[list[str]] = [[]]
    for t in toks:
        if t in _SEPARATORS:
            parts.append([])
        else:
            parts[-1].append(t)
    parts = [p for p in parts if p]
    if not parts:
        return [Entry(raw, fmt, kind="allow_all", notes=["matches EVERY command"])]
    if len(parts) > 1:
        notes.append("compound entry: each part is checked on its own, like the agents do")

    entries = []
    for i, part in enumerate(parts):
        # Skip leading VAR=value assignments; remember we did.
        n_assign = 0
        while part and "=" in part[0] and not part[0].startswith("-") and part[0].split("=")[0].isidentifier():
            part, n_assign = part[1:], n_assign + 1
        stripped: list[str] = []
        if fmt == "claude":
            part, stripped = _strip_claude_wrappers(part)
        if not part:
            continue
        e_notes = list(notes) + (["leading VAR=value assignments ignored"] if n_assign else [])
        if stripped:
            e_notes.append(f"Claude Code strips the wrapper {' '.join(f'`{w}`' for w in stripped)} before matching; "
                           f"analysed as `{os.path.basename(part[0])}`")
        is_last = i == len(parts) - 1
        entries.append(Entry(raw, fmt, tool=os.path.basename(part[0]), words=tuple(part[1:]),
                             any_args=any_args if is_last else False, notes=e_notes))
    return entries


# Wrappers Claude Code strips before matching a Bash rule (permissions docs, "Wrappers").
# Value = the option letters that take a separate value argument.
_CLAUDE_WRAPPERS = {"timeout": {"-s", "--signal", "-k", "--kill-after"}, "time": set(),
                    "nice": {"-n", "--adjustment"}, "nohup": set(), "stdbuf": {"-i", "-o", "-e"},
                    "command": set(), "builtin": set(), "noglob": set()}


def _strip_claude_wrappers(part: list[str]) -> tuple[list[str], list[str]]:
    """Drop leading wrappers the way Claude Code does.  Returns (inner command, wrapper names)."""
    names: list[str] = []
    while len(part) > 1:
        w = part[0]
        if w == "xargs":                       # only flag-less xargs is stripped
            if part[1].startswith("-"):
                break
            names.append(w); part = part[1:]; continue
        if w not in _CLAUDE_WRAPPERS or (w == "command" and part[1] in ("-v", "-V")):
            break
        rest = part[1:]
        while rest and rest[0].startswith("-") and rest[0] != "--":
            opt = rest.pop(0)
            if opt in _CLAUDE_WRAPPERS[w] and "=" not in opt and rest:
                rest.pop(0)                    # the option's value
        if rest and rest[0] == "--":
            rest.pop(0)
        if w == "timeout" and rest:
            rest.pop(0)                        # the DURATION
        if not rest:
            break
        names.append(w); part = rest
    return part, names


# ------------------------------------------------------------------- formats

def parse_plain(text: str) -> list[Entry]:
    out: list[Entry] = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.extend(parse_pattern(line, "plain", default_any_args=True))
    return out


def _overlaps(allow: Entry, rule: Entry) -> bool:
    """Could some command matched by `allow` also be matched by the ask/deny `rule`?"""
    if allow.tool != rule.tool:
        return False
    k = min(len(allow.words), len(rule.words))
    if allow.words[:k] != rule.words[:k]:
        return False
    return allow.any_args or len(allow.words) >= len(rule.words)


def parse_claude(text: str) -> list[Entry]:
    """Read permissions.allow from a Claude Code settings.json."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise AllowlistError(f"invalid JSON: {exc}") from exc
    allow = (data.get("permissions") or {}).get("allow") if isinstance(data, dict) else None
    if allow is None:
        raise AllowlistError("no permissions.allow list found (is this a Claude Code settings.json?)")
    if not isinstance(allow, list):
        raise AllowlistError("permissions.allow must be a list")
    perms = data["permissions"]
    restrict: list[tuple[str, Entry]] = []          # (list name, parsed Bash ask/deny rule)
    for name in ("deny", "ask"):
        rules = perms.get(name) or []
        if not isinstance(rules, list):
            raise AllowlistError(f"permissions.{name} must be a list")
        for item in rules:
            if isinstance(item, str) and item.startswith("Bash(") and item.endswith(")"):
                for e in parse_pattern(item[5:-1], "claude", default_any_args=False, raw=item):
                    restrict.append((name, e))
    out: list[Entry] = []
    for item in allow:
        if not isinstance(item, str):
            raise AllowlistError(f"permissions.allow entry is not a string: {item!r}")
        if item == "Bash":
            out.append(Entry(item, "claude", kind="allow_all", notes=["bare `Bash` allows every command"]))
        elif item.startswith("Bash(") and item.endswith(")"):
            out.extend(parse_pattern(item[5:-1], "claude", default_any_args=False, raw=item))
        else:   # Read(...), WebFetch(...), mcp__..., not shell commands
            out.append(Entry(item, "claude", kind="skipped", notes=["not a Bash rule; not analysed"]))
    for e in out:
        if e.kind != "command":
            continue
        hits = [f"{name} rule {r.raw}" for name, r in restrict if r.kind == "command" and _overlaps(e, r)]
        if hits:
            e.notes.append("also matched by " + ", ".join(hits) + ": Claude Code checks deny, then ask, then "
                           "allow, so matching calls are blocked/prompted; but these are text rules and the docs "
                           "say other spellings (full path, `sh -c`, `git -C .`) are not matched; findings "
                           "below are NOT reduced")
    return out


def _literal_words(node: ast.AST) -> list[list[str]]:
    """Codex pattern -> list of positions, each a list of alternatives."""
    value = ast.literal_eval(node)          # literals only; raises on anything else
    if not isinstance(value, list) or not value:
        raise ValueError("pattern must be a non-empty list")
    positions = []
    for el in value:
        alts = [el] if isinstance(el, str) else el
        if not (isinstance(alts, list) and alts and all(isinstance(a, str) for a in alts)):
            raise ValueError("pattern elements must be strings or lists of strings")
        positions.append(alts)
    return positions


def parse_codex(text: str) -> list[Entry]:
    """Read `prefix_rule(...)` calls from a Codex .rules file.

    The file is Starlark, which looks like Python.  We only *parse* it (ast.parse)
    and read literal arguments; we never run it.  Anything that is not a literal
    prefix_rule(...) call is ignored (with a note if it looks like a rule).
    """
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        raise AllowlistError(f"cannot parse rules file: {exc}") from exc
    out: list[Entry] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "prefix_rule"):
            continue
        kw = {k.arg: k.value for k in node.keywords if k.arg}
        try:
            positions = _literal_words(kw["pattern"])
            decision = ast.literal_eval(kw["decision"]) if "decision" in kw else "allow"   # docs: default allow
        except (KeyError, ValueError, SyntaxError) as exc:
            out.append(Entry(f"prefix_rule@line{node.lineno}", "codex", kind="skipped",
                             notes=[f"could not read this rule statically: {exc}"]))
            continue
        shown = f"prefix_rule(pattern={ast.unparse(kw['pattern'])})"
        if decision != "allow":
            out.append(Entry(shown, "codex", kind="skipped",
                             notes=[f'decision="{decision}" does not auto-approve; not analysed']))
            continue
        combos = list(itertools.islice(itertools.product(*positions), 50))   # cap alternatives
        for combo in combos:
            e = Entry(shown, "codex", tool=os.path.basename(combo[0]), words=tuple(combo[1:]), any_args=True)
            e.notes.append("Codex allow rules run the command OUTSIDE the sandbox")
            out.append(e)
    return out


# ---------------------------------------------------------------- entry point

def detect_format(path: str, text: str) -> str:
    stripped = text.lstrip()
    if path.endswith(".json") or stripped.startswith("{"):
        return "claude"
    if path.endswith(".rules") or "prefix_rule(" in text:
        return "codex"
    return "plain"


def load(path: str, fmt: str = "auto") -> tuple[str, list[Entry]]:
    """Read an allowlist file.  Returns (format_used, entries)."""
    try:
        text = open(path, encoding="utf-8").read()
    except OSError as exc:
        raise AllowlistError(f"cannot read {path}: {exc}") from exc
    if fmt == "auto":
        fmt = detect_format(path, text)
    parser = {"plain": parse_plain, "claude": parse_claude, "codex": parse_codex}[fmt]
    entries = parser(text)
    if not entries:
        raise AllowlistError(f"{path}: no allowlist entries found (format: {fmt})")
    return fmt, entries
