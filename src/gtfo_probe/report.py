"""Rendering check results as text (for people) or JSON (for CI and other tools)."""

from __future__ import annotations

import json
from dataclasses import asdict

from .checker import EntryReport, summarize

HONESTY = ("Results reflect only the probes that were run, on the tool versions listed above.\n"
           "\"no known risk\" means probes saw no effect; \"UNKNOWN\" means nothing was tested. Neither means safe.\n"
           "Not modelled: READING files (a `cat` or `grep` entry can still read secrets).")


def _db_header(db: dict) -> list[str]:
    versions = ", ".join(sorted(db["tools"])) or "(none)"
    runners = ", ".join(k for k, v in sorted(db["tools"].items()) if v.get("category") == "runner")
    lines = [f"capability DB: generated {db.get('generated_at', '?')} by {db.get('generator', '?')}",
             f"tool versions probed: {versions}"]
    if runners:
        lines.append(f"runner tools (critical by design, they run what you give them): {runners}")
    return lines


def render_text(path: str, fmt: str, db: dict, reports: list[EntryReport]) -> str:
    out = [f"gtfo-probe check: {path} (format: {fmt})", *_db_header(db), HONESTY, ""]
    for r in reports:
        e = r.entry
        label = {"findings": r.top_severity.upper(), "allow_all": "CRITICAL", "no_known_risk": "no known risk",
                 "unknown_tool": "UNKNOWN", "unknown_scope": "UNKNOWN", "skipped": "skipped"}[r.status]
        shown = e.raw if e.kind != "command" else f"{e.raw}   [{' '.join((e.tool, *e.words))}{' ...' if e.any_args else ''}]"
        out.append(f"[{label}] {shown}")
        for f in r.findings:
            via = ("BY DESIGN (runs any program you hand it)" if f.by_design and not f.flag
                   else f"via {f.flag}" if f.flag else "in plain use")
            out.append(f"    {f.severity:8} {f.effect:8} {via}  (probe {f.probe}, {f.confidence}, {f.tool_version})")
            out.append(f"             evidence: {f.evidence}")
            if f.abbreviation:
                a = f.abbreviation
                msg = (f"WORKS in a variant spelling, {a['flag']} (probe {a['probe']}); deny by capability, not by flag string"
                       if a["status"] == "works" else f"abbreviation {a['flag']} was rejected by this version (probe {a['probe']})")
                out.append(f"             abbreviation: {msg}")
        if r.fix:
            out.append(f"    fix: {r.fix}")
        for n in r.notes:
            out.append(f"    note: {n}")
        out.append("")
    s = summarize(reports)
    status = ", ".join(f"{n} {k}" for k, n in sorted(s["by_status"].items()))
    sev = ", ".join(f"{n} {k}" for k, n in sorted(s["findings_by_severity"].items())) or "none"
    out.append(f"summary: {s['entries']} entries ({status}); findings by severity: {sev}")
    return "\n".join(out)


def render_json(path: str, fmt: str, db: dict, reports: list[EntryReport]) -> str:
    doc = {
        "schema_version": 1,
        "allowlist": {"path": path, "format": fmt},
        "db": {"generated_at": db.get("generated_at"), "generator": db.get("generator"),
               "tool_versions": sorted(db["tools"])},
        "disclaimer": HONESTY.replace("\n", " "),
        "summary": summarize(reports),
        "entries": [{
            "raw": r.entry.raw, "status": r.status, "kind": r.entry.kind, "tool": r.entry.tool,
            "pinned_words": list(r.entry.words), "any_args": r.entry.any_args,
            "tool_versions": r.tool_versions, "probes_in_scope": r.probes_in_scope,
            "fix": r.fix, "findings": [asdict(f) for f in r.findings], "notes": r.notes,
        } for r in reports],
    }
    return json.dumps(doc, indent=2, sort_keys=True)
