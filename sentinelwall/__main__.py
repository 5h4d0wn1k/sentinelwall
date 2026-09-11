"""Allow running sentinelwall as a module: python3 -m sentinelwall."""
from __future__ import annotations
import sys
from sentinelwall.cli.main import main

sys.exit(main())
