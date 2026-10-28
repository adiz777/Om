"""Entrypoint for `python -m om`."""
from __future__ import annotations

from om.cli.main import main

if __name__ == "__main__":
    raise SystemExit(main())
