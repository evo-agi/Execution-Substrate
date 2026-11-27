#!/usr/bin/env bash
# Give the Remote Alpha box's AGS and EGS new signing keys, and point EGS and
# ES at them.
#   sudo scripts/remote_alpha_rotate_signing_keys.sh check
#   sudo scripts/remote_alpha_rotate_signing_keys.sh apply
#   sudo scripts/remote_alpha_rotate_signing_keys.sh rollback --backup-dir <dir>
# Contract: .docs/system_overview/remote_supported_host_alpha.md, section
# "Remote Signing Key Rotation".
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# -I: ignore PYTHON* variables, the user site directory and the script's
# directory on the import path. -B: write no bytecode next to the script.
exec /usr/bin/python3 -I -B "${SCRIPT_DIR}/internal/remote_alpha_rotate_signing_keys.py" "$@"
