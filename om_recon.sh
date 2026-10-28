#!/usr/bin/env bash
# OM 2.0 — Backwards-compatible CLI wrapper (`./om_recon.sh`)
# Author: Major_ADI (https://github.com/adiz777/Om)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "${SCRIPT_DIR}/Om.sh" "$@"
