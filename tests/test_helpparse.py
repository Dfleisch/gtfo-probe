"""Help-text parsing and hint tests.  Pure text in, data out: no sandbox needed."""
import pytest

from gtfo_probe.helpparse import Candidate, classify, metavar_kind, parse_help


def by_name(cands, name):
    return next(c for c in cands if name in c.names)


GNU = """\
Usage: tool [OPTION...] [FILE]...
  -I, --use-compress-program=PROG  filter through PROG
  -n, --quiet, --silent    suppress automatic printing
      --checkpoint[=NUMBER]  display progress messages
  -i[SUFFIX], --in-place[=SUFFIX]
                 edit files in place (makes backup if SUFFIX supplied)
  -e script, --expression=script
                 add the script to the commands to be executed
      --help                   display this help and exit
"""


def test_gnu_aliases_are_merged_into_one_option():
    c = by_name(parse_help(GNU), "-I")
    assert c.names == ["-I", "--use-compress-program"]
    assert c.arg == "required" and c.metavar == "PROG"
    assert c.primary == "--use-compress-program"          # the long form is what we type


def test_three_aliases_and_no_argument():
    c = by_name(parse_help(GNU), "--quiet")
    assert c.names == ["-n", "--quiet", "--silent"] and c.arg == "none"


def test_optional_arguments_both_spellings():
    cands = parse_help(GNU)
    assert by_name(cands, "--checkpoint").arg == "optional"
    inplace = by_name(cands, "--in-place")
    assert inplace.arg == "optional" and "-i" in inplace.names


def test_lowercase_metavar_and_description_on_next_line():
    c = by_name(parse_help(GNU), "--expression")
    assert c.arg == "required" and c.metavar == "script"
    assert "commands to be executed" in c.text            # continuation line was attached


def test_git_style_angle_brackets_and_no_prefix():
    text = "usage: git x [<options>]\n\n    -q, --[no-]quiet      suppress diff output\n" \
           "    --[no-]decorate-refs <pattern>\n                          only decorate refs\n" \
           "    -L <range:file>       trace the evolution\n"
    cands = parse_help(text)
    assert by_name(cands, "--quiet").arg == "none"                       # `--[no-]quiet` -> `--quiet`
    assert by_name(cands, "--decorate-refs").metavar == "pattern"
    assert by_name(cands, "-L").arg == "required"


def test_find_style_prose_single_dash_long_options_and_terminator():
    text = """Actions:
      -delete -print0 -printf FORMAT -fprintf FILE FORMAT -print
      -exec COMMAND ; -exec COMMAND {} + -ok COMMAND ;
"""
    cands = parse_help(text)
    assert by_name(cands, "-delete").arg == "none"
    fp = by_name(cands, "-fprintf")
    assert fp.arg == "required" and fp.metavar == "FILE"
    ex = by_name(cands, "-exec")
    assert ex.terminator == ";" and ex.metavar == "COMMAND"
    assert sum("-exec" in c.names for c in cands) == 1                  # the second -exec line is a duplicate


def test_words_that_merely_contain_a_dash_are_not_flags():
    cands = parse_help("a non-existent thing, e-mail, 3-4 files and 5 - 6\n")
    assert cands == []


def test_garbage_and_empty_input_never_raise():
    assert parse_help("") == []
    assert parse_help("\x00\x01 ---- -- - \n\n\t\t") is not None
    assert len(parse_help("\n".join(f"  --opt{i}  text" for i in range(5000)), max_options=50)) == 50


# ---- hints: guesses only
@pytest.mark.parametrize("metavar,kind", [
    ("PROG", "exec"), ("COMMAND", "exec"), ("script-file", "fs_write"),   # last word wins
    ("FILE", "fs_write"), ("DIR", "fs_write"), ("URL", "net"), ("N", ""), ("PATTERN", ""), ("", ""),
])
def test_metavar_kind(metavar, kind):
    assert metavar_kind(metavar) == kind


def test_classify_uses_metavar_then_keywords():
    c = classify(Candidate(names=["--compress-program"], arg="required", metavar="PROG"))
    assert c.hints[0] == "exec"
    c = classify(Candidate(names=["--delete"], text="delete from the archive"))
    assert c.hints == ["fs_write"]
    c = classify(Candidate(names=["--proxy"], arg="required", metavar="HOST"))
    assert "net" in c.hints and "exec" in c.hints          # a word can suggest several; testing decides


def test_plain_switches_get_no_hints():
    assert classify(Candidate(names=["--ignore-case"], text="ignore case distinctions")).hints == []
    assert classify(Candidate(names=["-n"], arg="required", metavar="N", text="line count")).hints == []


def test_seed_hints_are_kept():
    c = Candidate(names=["w"], source="seed", hints=["fs_write"], full_argv=["x"])
    assert classify(c).hints == ["fs_write"]
