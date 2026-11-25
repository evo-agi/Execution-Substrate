#!/usr/bin/env bash
# Move the Remote Alpha box's ES to one named commit and put its Nomad behind
# HTTPS (from the shape ES PR #54's upgrade left; see the contract).
#   scripts/remote_alpha_upgrade_es.sh build --out <dir outside the checkout> --commit <sha>
#   sudo scripts/remote_alpha_upgrade_es.sh check --payload <dir> --commit <sha>
#   sudo scripts/remote_alpha_upgrade_es.sh apply --payload <dir> --commit <sha>
#   sudo scripts/remote_alpha_upgrade_es.sh rollback --backup-dir <dir>
# Contract: .docs/system_overview/remote_supported_host_alpha.md, section
# "Remote ES Upgrade And Nomad HTTPS".
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# -I: ignore PYTHON* variables, the user site directory and the script's
# directory on the import path. -B: write no bytecode next to the script.
exec /usr/bin/python3 -I -B "${SCRIPT_DIR}/internal/remote_alpha_upgrade_es.py" "$@"
