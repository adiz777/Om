#!/usr/bin/env bash
# OM 2.0 — Automated Reconnaissance & Intelligence Platform
# Author: Major_ADI (https://github.com/adiz777/Om)
# License: GPL-3.0
# Note: The original legacy Bash script is preserved in scripts/legacy/Om.sh.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
else
    echo "[ERROR] Python 3.10+ is required to run Om 2.0." >&2
    exit 1
fi

export PYTHONPATH="${SCRIPT_DIR}${PYTHONPATH:+:${PYTHONPATH}}"
exec "${PYTHON_BIN}" -m om.cli.main "$@"
