"""Command line interface:  gtfo-probe {doctor,list,run,check,discover}.

Kept thin on purpose: parse arguments, call the modules, print results.
"""

from __future__ import annotations

import argparse
import json
import sys
from importlib import resources
from pathlib import Path

from . import allowlist, checker, db, discover, fixtures, report, runner, spec
from .sandbox import Sandbox, SandboxUnavailable


def _bundled_probe_dir() -> Path:
    return Path(str(resources.files("gtfo_probe") / "probes"))


def _load_probes(args) -> list[spec.ProbeSpec]:
    directory = Path(args.probes) if args.probes else _bundled_probe_dir()
    probes = spec.load_dir(directory, set(fixtures.PLACEHOLDERS))
    if args.tool:
        probes = [p for p in probes if p.tool in set(args.tool)]
    if not probes:
        raise spec.SpecError("no probes selected")
    return probes


def _verified_sandbox() -> Sandbox:
    sb = Sandbox.detect()
    sb.preflight()
    return sb


def cmd_doctor(args) -> int:
    try:
        sb = _verified_sandbox()
    except SandboxUnavailable as exc:
        print(f"sandbox: UNAVAILABLE\n  {exc}\ngtfo-probe will refuse to run probes.")
        return 2
    print(f"sandbox: OK ({sb.version()})")
    print("  verified: no network interfaces, read-only root, writable /work only, host dirs hidden")
    return 0


def cmd_list(args) -> int:
    for p in _load_probes(args):
        print(f"{p.id:40} expect={','.join(p.expect) or '-':8} {p.tool} {' '.join(p.argv)}")
    return 0


def cmd_run(args) -> int:
    probes = _load_probes(args)           # validate specs BEFORE touching the sandbox
    try:
        sb = _verified_sandbox()
    except SandboxUnavailable as exc:
        print(f"refusing to run: {exc}", file=sys.stderr)
        return 2
    skipped: list[str] = []
    versions, results = runner.run_all(sb, probes, timeout=args.timeout, skipped=skipped)
    if not results:
        print("refusing to write an empty database: none of the selected tools are installed "
              f"({', '.join(skipped)})", file=sys.stderr)
        return 2
    database = db.build_database(versions, results, sb.version())
    db.write_database(database, Path(args.out))

    for r in results:
        obs = ",".join(sorted(r.effects.effects)) or "-"
        print(f"{r.status:24} {r.probe.id:38} observed={obs}")
    n_bad = sum(r.status != "match" for r in results)
    if skipped:
        print(f"\nSKIPPED (not installed on this machine, so not in the database): {', '.join(sorted(skipped))}")
    print(f"\n{len(results)} probes, {len(results) - n_bad} as expected, {n_bad} differ."
          f"\nwrote {args.out}")
    return 1 if (args.strict and n_bad) else 0


def cmd_check(args) -> int:
    """Compare an allowlist with the capability DB.  Needs no sandbox, so it runs on any OS."""
    try:
        database = db.load_database(Path(args.db))
        fmt, entries = allowlist.load(args.allowlist, args.input_format)
    except (OSError, ValueError) as exc:               # AllowlistError is a ValueError
        print(f"check: {exc}", file=sys.stderr)
        return 2
    reports = checker.check_all(entries, database)
    render = report.render_json if args.format == "json" else report.render_text
    print(render(args.allowlist, fmt, database, reports))
    return checker.exit_code(reports, args.strict, args.ignore_unknown)


def cmd_discover(args) -> int:
    """Find candidate flags from help text, test them in the sandbox, report (and with --apply, save)."""
    if bool(args.tool) == bool(args.all):
        print("discover: give exactly one of <tool> or --all", file=sys.stderr)
        return 2
    tools = sorted(spec.ALLOWED_TOOLS) if args.all else [args.tool]
    for t in tools:                                    # validate BEFORE touching the sandbox
        if t not in spec.ALLOWED_TOOLS:
            raise spec.SpecError(f"tool {t!r} is not in the allowlist {sorted(spec.ALLOWED_TOOLS)}")
    # Where --apply writes.  One tool: --out is a FILE.  --all: --out is a DIRECTORY of <tool>.discovered.json.
    out_dir = Path(args.out) if (args.all and args.out) else Path("probes")
    def out_file(tool: str) -> Path:
        return Path(args.out) if (args.out and not args.all) else out_dir / f"{tool}.discovered.json"

    # Existing probes = what "already covered" means.  Include earlier discovered files so
    # re-running --apply adds only what is genuinely new.
    directory = Path(args.probes) if args.probes else _bundled_probe_dir()
    existing = {p.id: p for p in spec.load_dir(directory, set(fixtures.PLACEHOLDERS))}
    for t in tools:
        f = out_file(t)
        if f.exists():
            try:
                existing.update({p.id: p for p in spec.load_file(f, set(fixtures.PLACEHOLDERS))})
            except spec.SpecError:
                pass                                   # not a probe file: write_discovered will refuse it
    try:
        sb = _verified_sandbox()
    except SandboxUnavailable as exc:
        print(f"refusing to run: {exc}", file=sys.stderr)
        return 2

    limits = discover.Limits(max_candidates=args.max_candidates, timeout=args.timeout,
                             max_seconds=args.max_seconds, select="all" if args.all_flags else "keywords")
    reports, rc = [], 0
    for t in tools:
        rep = discover.discover_tool(sb, t, list(existing.values()), subs=args.sub or None, limits=limits)
        reports.append(rep)
        if args.format == "text":
            print(discover.render_text(rep, show_all=args.show_all))
        if args.apply and rep.version is not None:
            try:
                added, total = discover.write_discovered(rep, out_file(t), set(existing))
            except discover.DiscoverError as exc:
                print(f"discover: {exc}", file=sys.stderr)
                rc = 2
                continue
            if args.format == "text":
                print(f"  --apply: {added} new probe(s) written to {out_file(t)} ({total} in file)" if added
                      else f"  --apply: nothing new to write for {t}")
        elif args.format == "text" and rep.version is not None:
            print("  (report only: nothing written; add --apply to save the NEW confirmed ones)")
        if args.format == "text":
            print()
    if args.format == "json":
        print(json.dumps([r.to_dict() for r in reports], indent=2))
    if not args.all and reports and reports[0].version is None:
        return 2
    return rc


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="gtfo-probe",
        description="Find the flags that let 'read-only' commands write files, run programs "
                    "or reach the network, and check AI agent allowlists against that evidence.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("--probes", help="directory of probe *.json files (default: bundled)")
        p.add_argument("--tool", action="append", help="only this tool (repeatable)")

    sub.add_parser("doctor", help="check that a safe sandbox is available").set_defaults(fn=cmd_doctor)
    p_list = sub.add_parser("list", help="show the probes that would run (runs nothing)")
    common(p_list)
    p_list.set_defaults(fn=cmd_list)
    p_run = sub.add_parser("run", help="run probes in the sandbox and write the capability DB")
    common(p_run)
    p_run.add_argument("--out", default="capabilities.json")
    p_run.add_argument("--timeout", type=float, default=5.0, help="seconds per probe")
    p_run.add_argument("--strict", action="store_true", help="exit 1 if any probe differs from its expectation")
    p_run.set_defaults(fn=cmd_run)

    p_check = sub.add_parser("check", help="compare an agent allowlist with the capability DB (runs nothing)")
    p_check.add_argument("allowlist", help="allowlist file: plain text, Claude Code settings.json or Codex .rules")
    p_check.add_argument("--db", default="capabilities.json", help="capability DB made by `run`")
    p_check.add_argument("--format", choices=["text", "json"], default="text", help="output format")
    p_check.add_argument("--input-format", choices=["auto", *allowlist.FORMATS], default="auto",
                         help="allowlist format (default: guess from name/content)")
    p_check.add_argument("--strict", action="store_true",
                         help="exit 1 if any entry has findings, allows everything, or is UNKNOWN (untested)")
    p_check.add_argument("--ignore-unknown", action="store_true", help="with --strict: do not fail on UNKNOWN entries")
    p_check.set_defaults(fn=cmd_check)

    p_disc = sub.add_parser("discover", help="find candidate flags from help text and TEST them in the sandbox")
    p_disc.add_argument("tool", nargs="?", help="tool to discover flags for (must be in the allowlist)")
    p_disc.add_argument("--all", action="store_true", help="every tool in the allowlist")
    p_disc.add_argument("--apply", action="store_true",
                        help="write NEW, confirmed, reproduced findings as probe JSON (default: report only)")
    p_disc.add_argument("--out", help="with --apply: probe file (one tool; default probes/<tool>.discovered.json) "
                                     "or, with --all, a directory (default probes/)")
    p_disc.add_argument("--probes", help="probe directory that defines 'already covered' (default: bundled probes)")
    p_disc.add_argument("--sub", action="append", help="git only: subcommand to discover (repeatable; "
                                                       "default: the ones the hand-written probes use)")
    p_disc.add_argument("--max-candidates", type=int, default=100, help="most flags tested per tool/subcommand")
    p_disc.add_argument("--timeout", type=float, default=3.0, help="seconds per sandboxed run")
    p_disc.add_argument("--max-seconds", type=float, default=120.0, help="wall-clock budget per tool")
    p_disc.add_argument("--all-flags", action="store_true",
                        help="test every parsed flag, not only those with keyword/metavar hints (slower, more noise)")
    p_disc.add_argument("--format", choices=["text", "json"], default="text")
    p_disc.add_argument("--show-all", action="store_true", help="list every no-effect flag, not just the first few")
    p_disc.set_defaults(fn=cmd_discover)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except spec.SpecError as exc:
        print(f"probe spec error: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
