"""Allowlist parsing: pure functions, no sandbox needed."""
import json

import pytest

from gtfo_probe import allowlist
from gtfo_probe.allowlist import AllowlistError, parse_claude, parse_codex, parse_pattern, parse_plain


def one(text, fmt="plain", default=True):
    (e,) = parse_pattern(text, fmt, default)
    return e


def test_plain_line_is_prefix_with_any_args():
    e = one("git show")
    assert (e.tool, e.words, e.any_args) == ("git", ("show",), True)


def test_trailing_dollar_means_exact():
    e = one("git status $")
    assert (e.words, e.any_args) == (("status",), False)


def test_colon_star_and_space_star_are_the_same():
    assert one("tar:*", "claude", False).any_args and one("tar *", "claude", False).any_args


def test_claude_without_star_is_exact():
    assert one("git show HEAD", "claude", False).any_args is False


def test_star_in_the_middle_pins_only_words_before_it():
    e = one("git log * main", "claude", False)
    assert (e.words, e.any_args) == (("log",), True)
    assert any("not analysed" in n for n in e.notes)


def test_glob_inside_quotes_does_not_break_parsing():
    e = one("find . -name '*.txt'", "claude", False)
    assert e.tool == "find" and e.words == (".", "-name") and e.any_args


def test_glued_star_notes_longer_program_names():
    e = one("ls*", "claude", False)
    assert e.tool == "ls" and any("longer names" in n for n in e.notes)


def test_program_path_is_reduced_to_basename_and_assignments_skipped():
    e = one("FOO=1 /usr/bin/git show", "plain")
    assert e.tool == "git" and any("assignments" in n for n in e.notes)


def test_compound_entry_is_split_and_only_last_part_gets_wildcard():
    a, b = parse_pattern("cd src && git log:*", "claude", False)
    assert (a.tool, a.any_args) == ("cd", False)
    assert (b.tool, b.any_args) == ("git", True)


def test_star_alone_is_allow_all():
    assert one("*").kind == "allow_all"


def test_unbalanced_quote_is_an_error():
    with pytest.raises(AllowlistError):
        parse_pattern("git log 'oops", "plain", True)


def test_plain_ignores_comments_and_blank_lines():
    entries = parse_plain("# hi\n\ngit show\n  tar  \n")
    assert [e.tool for e in entries] == ["git", "tar"]


def test_claude_settings():
    doc = {"permissions": {"allow": ["Bash(git show:*)", "Bash(tar:*)", "Bash", "Read(./src/**)", "Bash(ls)"]}}
    es = parse_claude(json.dumps(doc))
    assert [(e.kind, e.tool, e.any_args) for e in es] == [
        ("command", "git", True), ("command", "tar", True), ("allow_all", "", True),
        ("skipped", "", True), ("command", "ls", False)]


def test_claude_errors():
    with pytest.raises(AllowlistError):
        parse_claude("not json")
    with pytest.raises(AllowlistError):
        parse_claude('{"permissions": {}}')
    with pytest.raises(AllowlistError):
        parse_claude('{"permissions": {"allow": [1]}}')


CODEX = '''
# comment
prefix_rule(pattern = ["git", "show"], decision = "allow", justification = "x")
prefix_rule(pattern = ["gh", ["pr", "issue"], "view"])
prefix_rule(pattern = ["rm"], decision = "forbidden")
prefix_rule(pattern = ["curl"], decision = "prompt")
'''


def test_codex_rules():
    es = parse_codex(CODEX)
    cmds = [(e.tool, e.words) for e in es if e.kind == "command"]
    assert cmds == [("git", ("show",)), ("gh", ("pr", "view")), ("gh", ("issue", "view"))]   # union expanded
    assert all(e.any_args for e in es if e.kind == "command")                       # codex rules are prefixes
    assert [e.kind for e in es].count("skipped") == 2                               # forbidden + prompt


def test_codex_never_executes_the_file(tmp_path):
    marker = tmp_path / "ran"
    evil = f'open({str(marker)!r}, "w")\nprefix_rule(pattern=[open({str(marker)!r}, "w")])\n'
    es = parse_codex(evil)
    assert not marker.exists()
    assert es[0].kind == "skipped"            # non-literal pattern is reported, not evaluated


def test_codex_syntax_error():
    with pytest.raises(AllowlistError):
        parse_codex("prefix_rule(")


def test_detect_format():
    assert allowlist.detect_format("x.json", "") == "claude"
    assert allowlist.detect_format("default.rules", "") == "codex"
    assert allowlist.detect_format("x", 'prefix_rule(pattern=["a"])') == "codex"
    assert allowlist.detect_format("allow.txt", "git show") == "plain"


def test_load_errors(tmp_path):
    with pytest.raises(AllowlistError):
        allowlist.load(str(tmp_path / "missing"))
    empty = tmp_path / "e.txt"
    empty.write_text("# nothing\n")
    with pytest.raises(AllowlistError):
        allowlist.load(str(empty))


# ---- Claude Code format details re-checked 2026-10-19 against
# ---- https://code.claude.com/docs/en/permissions (Claude Code 2.1.303)

def test_claude_leading_star_matches_any_program():
    (e,) = parse_pattern("* --version", "claude", False)
    assert e.kind == "allow_all" and any("PROGRAM" in n for n in e.notes)


def test_claude_colon_star_mid_pattern_is_literal_and_matches_nothing():
    (e,) = parse_pattern("git:* push", "claude", False)
    assert e.kind == "skipped" and any("literal colon" in n for n in e.notes)
    assert one("git push:*", "claude", False).any_args            # at the end it is still the wildcard


def test_claude_glued_star_still_noted():
    e = one("ls*", "claude", False)
    assert e.tool == "ls" and e.any_args and any("longer names" in n for n in e.notes)


@pytest.mark.parametrize("rule,tool,words", [
    ("timeout 30 make *", "make", ()),
    ("timeout -k 5 30s npm test *", "npm", ("test",)),
    ("nice -n 10 tar *", "tar", ()),
    ("nohup time python3 *", "python3", ()),
    ("stdbuf -oL grep *", "grep", ()),
    ("command git status", "git", ("status",)),
    ("xargs grep *", "grep", ()),
])
def test_claude_strips_documented_wrappers(rule, tool, words):
    e = one(rule, "claude", False)
    assert (e.tool, e.words) == (tool, words)
    assert any("strips the wrapper" in n for n in e.notes)


@pytest.mark.parametrize("rule,tool", [("xargs -n1 grep *", "xargs"), ("command -v git", "command"),
                                       ("timeout *", "timeout")])
def test_claude_does_not_strip_when_docs_say_not_to(rule, tool):
    assert one(rule, "claude", False).tool == tool


def test_wrappers_are_only_stripped_for_claude():
    assert one("timeout 30 make", "plain").tool == "timeout"


def _claude(allow, deny=(), ask=()):
    return parse_claude(json.dumps({"permissions": {"allow": list(allow), "deny": list(deny), "ask": list(ask)}}))


def test_claude_ask_and_deny_rules_are_attached_as_notes_only_where_they_overlap():
    es = _claude(["Bash(git *)", "Bash(git diff *)", "Bash(curl *)"],
                 deny=["Bash(curl * -o *)", "Read(./.env)"], ask=["Bash(git push *)"])
    by = {e.raw: e for e in es}
    assert any("ask rule Bash(git push *)" in n for n in by["Bash(git *)"].notes)
    assert not any("also matched" in n for n in by["Bash(git diff *)"].notes)
    assert any("deny rule Bash(curl * -o *)" in n and "NOT reduced" in n for n in by["Bash(curl *)"].notes)


def test_claude_bad_deny_type_is_an_error():
    with pytest.raises(AllowlistError):
        parse_claude(json.dumps({"permissions": {"allow": ["Bash(ls)"], "deny": "Bash(rm *)"}}))
