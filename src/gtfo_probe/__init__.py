"""gtfo-probe: empirically discover what a command's flags can really do.

Package map (read in this order, see docs/WALKTHROUGH.md):
    spec.py      - what a "probe" is (data format + validation)
    fixtures.py  - the fake world a probe runs in (canary files, canary program)
    sandbox.py   - the locked-down box (bubblewrap, no network, read-only root)
    detector.py  - decides what a probe actually did (files, exec, network)
    db.py        - turns results into the capabilities.json database
    runner.py    - glue: spec -> fixtures -> sandbox -> detector -> result
    cli.py       - the `gtfo-probe` command line
"""

__version__ = "0.1.0"
