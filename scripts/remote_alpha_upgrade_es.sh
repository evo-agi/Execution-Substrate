#!/usr/bin/env bash
# Move the Remote Alpha box's ES to one named commit and put its Nomad behind
# HTTPS (from the shape ES PR #54's upgrade left; see the contract).
#   scripts/remote_alpha_upgrade_es.sh build --out <dir outside the checkout> --commit <sha>
#   sudo scripts/remote_alpha_upgrade_es.sh check --payload <dir> --commit <sha> [--allow-downgrade <installed>..<sha>]
#   sudo scripts/remote_alpha_upgrade_es.sh apply --payload <dir> --commit <sha> [--allow-downgrade <installed>..<sha>]
#   sudo scripts/remote_alpha_upgrade_es.sh rollback --backup-dir <dir>
# Contract: .docs/system_overview/remote_supported_host_alpha.md, section
# "Remote ES Upgrade And Nomad HTTPS".
set -euo pipefail

# A path with ".." is refused before anything else runs. The kernel reads a
# ".." after following the symbolic link before it, while a reading of the
# text drops the ".." with that link's name, so the two can name different
# folders. The program below finds this file's folder the kernel's way;
# this keeps a ".." from being read the other way anywhere.
case "/${BASH_SOURCE[0]}/" in
  */../*)
    echo "remote alpha ES upgrade refused: start it by a path without \"..\" (${BASH_SOURCE[0]}); nothing was changed" >&2
    exit 1 ;;
esac

# The program below is part of this file and runs before any of the clone's
# code. It finds that code by the physical path of this file: the path it
# was started by, read from the kernel's working folder (never an inherited
# PWD, never CDPATH), with every symbolic link resolved, as the kernel did
# when it opened this file. It then refuses, for every command:
#   1. unless no account but root (for a run by another user: root and that
#      user) can change that code: every folder from / down to this file's
#      folder belongs to one of them and is writable by neither its group
#      nor others, unless it has the sticky bit; this file's folder, its
#      internal folder, this file and internal/remote_alpha_upgrade_es.py
#      belong to one of them, are not symbolic links and are writable by
#      neither group nor others (the sticky bit does not help there);
#   2. unless the path it was started by is that physical path: a symbolic
#      link to this file, or a path through one, is refused on its own.
# Only then does it run internal/remote_alpha_upgrade_es.py by that physical
# path. -I: ignore PYTHON* variables, the user site directory and the
# current folder on the import path. -B: write no bytecode. The program
# holds no single quote, so that the shell passes it whole.
exec /usr/bin/python3 -I -B -c '
import os
import stat
import sys

start, args = sys.argv[1], sys.argv[2:]
euid = os.geteuid()
owners = (0, euid)


def refuse(why):
    sys.stderr.write("remote alpha ES upgrade refused: " + why + "; nothing was changed\n")
    sys.exit(1)


def problems_of(path, folder, sticky_helps):
    try:
        st = os.lstat(path)
    except OSError as exc:
        return [path + ": " + exc.strerror]
    if stat.S_ISLNK(st.st_mode):
        return [path + " is a symbolic link"]
    if folder and not stat.S_ISDIR(st.st_mode):
        return [path + " is not a folder"]
    if not folder and not stat.S_ISREG(st.st_mode):
        return [path + " is not a regular file"]
    found = []
    if st.st_uid not in owners:
        found.append("%s belongs to uid %d" % (path, st.st_uid))
    mode = stat.S_IMODE(st.st_mode)
    if mode & 0o022 and not (sticky_helps and mode & stat.S_ISVTX):
        found.append("%s is writable by its group or others (%04o)%s"
                     % (path, mode, " without the sticky bit" if sticky_helps else ""))
    return found


# backup and restore are steps of apply and rollback: restore puts back any
# backup with no rollback check and no record (audit 47, O47-1). The first
# word that names a command of the upgrade is the command (only the test
# option --host-root and its value can come before it).
command = None
for word in args:
    if word in ("build", "check", "apply", "rollback", "backup", "restore", "migrate-config", "provision-key"):
        command = word
        break
if command in ("backup", "restore"):
    refuse(command + " is a step of apply and rollback, not a command of this script; use rollback --backup-dir <dir>")

try:
    here = os.getcwd()
except OSError as exc:
    refuse("the current folder cannot be read (" + exc.strerror + ")")
named = os.path.join(here, start)
wrapper = os.path.realpath(named)
scripts = os.path.dirname(wrapper)
internal = os.path.join(scripts, "internal")
upgrade = os.path.join(internal, "remote_alpha_upgrade_es.py")

problems = []
above = []
folder = scripts
while os.path.dirname(folder) != folder:
    folder = os.path.dirname(folder)
    above.insert(0, folder)
for folder in above:
    problems += problems_of(folder, True, True)
problems += problems_of(scripts, True, False)
problems += problems_of(internal, True, False)
problems += problems_of(wrapper, False, False)
problems += problems_of(upgrade, False, False)
if problems:
    if euid == 0:
        refuse("someone other than root can change the code the wrapper would run as root: "
               + "; ".join(problems)
               + "; hand the clone to root first (chown -R root:root and chmod -R go-w),"
               + " in folders that only root can change")
    refuse("someone other than root and uid %d can change the code the wrapper would run: %s;"
           " run chmod -R go-w on the clone and keep it in folders that only root and uid %d can change"
           % (euid, "; ".join(problems), euid))

# "//" names "/" here, but realpath writes it as "/".
invoked = os.path.normpath(named)
if invoked.startswith("//"):
    invoked = invoked[1:]
if invoked != wrapper:
    how = "is a symbolic link" if os.path.islink(invoked) else "is reached through a symbolic link"
    refuse("start it by the path of the clone itself, not through a symbolic link: %s %s (%s)"
           % (invoked, how, wrapper))

argv = ["/usr/bin/python3", "-I", "-B", upgrade] + args
try:
    os.execv(argv[0], argv)
except OSError as exc:
    refuse("%s could not be started (%s)" % (upgrade, exc.strerror))
' "${BASH_SOURCE[0]}" "$@"
