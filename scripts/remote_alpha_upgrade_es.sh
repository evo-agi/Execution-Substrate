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

# check, apply and rollback refuse a clone reached through a symbolic link,
# so the upgrade must see the path this file was read from. A ".." breaks
# that: the kernel resolves it after following any link before it, while
# cd -L drops it with the name before it, so the two can be different
# folders. Such a path is refused here, before anything else runs.
case "/${BASH_SOURCE[0]}/" in
  */../*)
    echo "remote alpha ES upgrade refused: start it by a path without \"..\" (${BASH_SOURCE[0]}); nothing was changed" >&2
    exit 1 ;;
esac
# The folder as it was named, symbolic links kept (pwd -L); resolving them
# here would hide them from the upgrade. CDPATH is cleared so that cd goes
# only to that folder.
SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -L)"
# -I: ignore PYTHON* variables, the user site directory and the script's
# directory on the import path. -B: write no bytecode next to the script.
exec /usr/bin/python3 -I -B "${SCRIPT_DIR}/internal/remote_alpha_upgrade_es.py" "$@"
