import json

import pytest

from gtfo_probe import fixtures, spec

PH = set(fixtures.PLACEHOLDERS)


def good(**over):
    d = {"id": "git.show.output", "tool": "git", "argv": ["show", "--output=<<out>>"],
         "expect": ["fs_write"]}
    d.update(over)
    return d


def test_valid_probe_roundtrip():
    p = spec.validate(good(flag="--output"), PH)
    assert p.tool == "git" and p.expect == ("fs_write",) and p.placeholders() == {"out"}


@pytest.mark.parametrize("bad", [
    good(tool="rm", id="rm.x"),                 # tool not in allowlist
    good(id="show.output"),                     # id must start with tool name
    good(id="Git Show"),                        # malformed id
    good(argv="show --output=x"),               # shell string instead of list
    good(argv=["show", 3]),                     # non-string argument
    good(expect=["teleport"]),                  # unknown effect
    good(argv=["<<nope>>"]),                    # unknown placeholder
    good(extra="field"),                        # unknown field
])
def test_invalid_probes_rejected(bad):
    with pytest.raises(spec.SpecError):
        spec.validate(bad, PH)


def test_missing_fields_rejected():
    with pytest.raises(spec.SpecError):
        spec.validate({"id": "git.x"}, PH)


def test_control_probe_has_empty_expect():
    assert spec.validate(good(expect=[]), PH).expect == ()


def test_substitute_replaces_placeholders_without_touching_braces():
    p = spec.validate({"id": "find.x", "tool": "find",
                       "argv": ["-exec", "<<canary_exec>>", "{}", ";"], "expect": ["exec"]}, PH)
    assert spec.substitute(p, fixtures.PLACEHOLDERS) == [
        "-exec", fixtures.PLACEHOLDERS["canary_exec"], "{}", ";"]


def test_load_dir_rejects_duplicate_ids(tmp_path):
    for name in ("a.json", "b.json"):
        (tmp_path / name).write_text(json.dumps({"probes": [good()]}))
    with pytest.raises(spec.SpecError, match="duplicate"):
        spec.load_dir(tmp_path, PH)


def test_load_file_rejects_bad_json(tmp_path):
    (tmp_path / "x.json").write_text("{nope")
    with pytest.raises(spec.SpecError):
        spec.load_file(tmp_path / "x.json", PH)


def test_bundled_probes_all_validate():
    from gtfo_probe.cli import _bundled_probe_dir
    probes = spec.load_dir(_bundled_probe_dir(), PH)
    assert {p.tool for p in probes} == set(spec.ALLOWED_TOOLS)      # every allowed tool has probes
    assert len(probes) >= 200
    # every tool has at least one control (expects nothing).  npm/npx are the honest exception:
    # they write their own log under ~/.npm even for `--version`, so their "control" is a
    # probe tagged "baseline" that expects exactly that write (and nothing else).
    for tool in {p.tool for p in probes}:
        assert any(p.tool == tool and (not p.expect or ("baseline" in p.tags and p.expect == ("fs_write",)))
                   for p in probes), tool
