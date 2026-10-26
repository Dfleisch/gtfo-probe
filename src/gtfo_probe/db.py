"""Capability database writer.

The database answers: "for tool@version, which flags give which capability?"
It is plain JSON so other programs (allowlist checkers, CI jobs, other people's
tools) can consume it without importing gtfo-probe.

Shape (schema_version 1):

{
  "schema_version": 1,
  "generator": "gtfo-probe 0.1.0",
  "generated_at": "2026-10-16T16:40:00Z",
  "sandbox": {"backend": "bubblewrap", "version": "bubblewrap 0.12.0", "network": "none"},
  "tools": {
    "git@2.47.3": {
      "category": "standard",                 # "runner" for env/xargs/python3/node/make/npx (milestone 3)
      "capabilities": {                       # <- the summary people will query
        "fs_write": [ {"probe": "git.show.output", "flag": "--output", "confidence": "confirmed"} ],
        "exec":     [ ... ],
        "net":      [ ... ],
        "runner":   [ ... ]                   # probes tagged "runner" that really ran the canary (milestone 3)
      },
      "probes": [ { ...full per-probe record, see runner.ProbeResult.to_dict... } ]
    }
  }
}

Two layers on purpose: `capabilities` is the quick answer, `probes` is the
evidence behind it (argv used, what changed on disk, exit code...) so a human
can verify any claim instead of trusting it.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .runner import ProbeResult
from .sandbox import Sandbox
from .spec import RUNNER_TAG, RUNNER_TOOLS

SCHEMA_VERSION = 1


def build_database(versions: dict[str, str], results: list[ProbeResult],
                   sandbox_version: str, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    tools: dict[str, dict] = {}
    for tool, key in sorted(versions.items()):
        tools[key] = {
            # "runner" = the tool's job is to run other programs (env, xargs, python3...): `check`
            # reports it as critical-by-design instead of listing flags.  Added in milestone 3.
            "category": "runner" if tool in RUNNER_TOOLS else "standard",
            "capabilities": {"fs_write": [], "exec": [], "net": [], "runner": []},
            "probes": [],
        }

    for r in results:
        entry = tools[versions[r.probe.tool]]
        rec = r.to_dict()
        entry["probes"].append(rec)
        for effect in rec["observed"]:
            entry["capabilities"][effect].append({
                "probe": rec["id"],
                "flag": rec["flag"],
                "confidence": rec["confidence"].get(effect, "unknown"),
            })
        if RUNNER_TAG in rec["tags"] and "exec" in rec["observed"]:
            entry["capabilities"]["runner"].append({
                "probe": rec["id"], "flag": rec["flag"], "confidence": rec["confidence"].get("exec", "unknown"),
            })
    return {
        "schema_version": SCHEMA_VERSION,
        "generator": f"gtfo-probe {__version__}",
        "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sandbox": {"backend": "bubblewrap", "version": sandbox_version, "network": "none"},
        "tools": tools,
    }


def write_database(db: dict, path: Path) -> None:
    """Write pretty, key-sorted JSON (stable diffs when you re-run later)."""
    Path(path).write_text(json.dumps(db, indent=2, sort_keys=True) + "\n")


def load_database(path: Path) -> dict:
    db = json.loads(Path(path).read_text())
    if db.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"unsupported schema_version {db.get('schema_version')!r}")
    return db
