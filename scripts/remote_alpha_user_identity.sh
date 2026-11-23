#!/usr/bin/env bash
# Named user caller identities (spiffe://execution.internal/user/<name>) for
# AGS and ES on the Remote Alpha box.
#   On the box, as root:
#     sudo scripts/remote_alpha_user_identity.sh status
#     sudo scripts/remote_alpha_user_identity.sh init-ca [--apply]
#     sudo scripts/remote_alpha_user_identity.sh issue --name NAME --csr FILE --out FILE [--apply]
#     sudo scripts/remote_alpha_user_identity.sh allow --name NAME [--apply]
#     sudo scripts/remote_alpha_user_identity.sh revoke --name NAME [--apply] [--remove-ca]
#   On the caller's machine, as the caller:
#     scripts/remote_alpha_user_identity.sh request --name NAME [--renew]
#     scripts/remote_alpha_user_identity.sh install --name NAME --cert FILE [--server-ca FILE]
#     scripts/remote_alpha_user_identity.sh check --name NAME [--url https://HOST:PORT [--service es|ags]]
# Contract: .docs/system_overview/remote_supported_host_alpha.md, section
# "Remote Alpha User Caller Identities".
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# -I: ignore PYTHON* variables, the user site directory and the script's
# directory on the import path. -B: write no bytecode next to the script.
exec /usr/bin/python3 -I -B "${SCRIPT_DIR}/internal/remote_alpha_user_identity.py" "$@"
