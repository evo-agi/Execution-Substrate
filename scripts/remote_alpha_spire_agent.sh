#!/usr/bin/env bash
# SPIRE agent bootstrap trust and recovery on the Remote Alpha box.
#   sudo scripts/remote_alpha_spire_agent.sh status
#   sudo scripts/remote_alpha_spire_agent.sh pin [--apply]
#   sudo scripts/remote_alpha_spire_agent.sh recover [--apply] [--evict-old-agent]
# Contract: .docs/system_overview/remote_supported_host_alpha.md, section
# "Remote SPIRE Agent Bootstrap Trust And Recovery Helper".
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# -I: ignore PYTHON* variables, the user site directory and the script's
# directory on the import path. -B: write no bytecode next to the script.
exec /usr/bin/python3 -I -B "${SCRIPT_DIR}/internal/remote_alpha_spire_agent.py" "$@"
