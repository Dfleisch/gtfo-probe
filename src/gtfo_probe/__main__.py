"""Allow `python -m gtfo_probe ...` as well as the `gtfo-probe` command."""

import sys

from .cli import main

sys.exit(main())
