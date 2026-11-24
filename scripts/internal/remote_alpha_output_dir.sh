#!/usr/bin/env bash
# The one definition of remote_alpha_prepare_output_dir.
#
# Several Remote Alpha helpers are staged to the host on their own, so each
# helper that writes as root carries a copy of the function below instead of
# sourcing this file. TestRemoteAlphaOutputDirCopiesMatch keeps every copy
# identical to this one; change it here and then in the copies.

# remote_alpha_prepare_output_dir DIR
#
# Root writes summaries, preflights, backups and staged helpers into DIR by
# name, so only root, the user running this step and the user who ran sudo may
# be able to change DIR or a directory above it. /var/tmp is writable by every
# account, so without this check another account could create
# /var/tmp/execution-substrate-remote-alpha first and plant links in it
# (whole-trunk red-team follow-up N-1, 2026-11-24). The function creates the
# missing directories of DIR one at a time without following links, and
# refuses a symbolic link anywhere on the way, a directory another account
# owns, a directory its group or others can write unless it is root's and
# sticky (such as /var/tmp), a DIR its group or others can write, and a DIR
# with a '..' component. It needs no read permission on the directories it
# checks, so a DIR that only root can read passes when root owns it.
remote_alpha_prepare_output_dir() {
  python3 -I - "$1" <<'REMOTE_ALPHA_OUTPUT_DIR_PY'
import os
import stat
import sys

if not sys.argv[1]:
    sys.exit("remote alpha output folder: no folder given")
if ".." in sys.argv[1].split("/"):
    sys.exit(f"remote alpha output folder: {sys.argv[1]} has a '..' component; refusing to check a path that is not canonical")
# The path is checked as given, never normalized: dropping "link/.." would
# check another folder than the one a later write through the link reaches.
parts = [part for part in os.path.join(os.getcwd(), sys.argv[1]).split("/") if part not in ("", ".")]
trusted = {0, os.geteuid()}
if os.environ.get("SUDO_UID", "").isdigit():
    trusted.add(int(os.environ["SUDO_UID"]))
# O_PATH reads a folder's owner and mode without read permission on it, so a
# folder that root keeps private still passes and sudo can hand it over.
flags = getattr(os, "O_PATH", os.O_RDONLY) | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
shown = "/"
fd = os.open("/", flags)
try:
    for index in range(len(parts) + 1):
        info = os.fstat(fd)
        last = index == len(parts)
        if info.st_uid not in trusted:
            sys.exit(
                f"remote alpha output folder: {shown} belongs to uid {info.st_uid}, not to root, "
                "the user running this step or the user who ran sudo; refusing to write under it"
            )
        if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH) and (
            last or info.st_uid != 0 or not info.st_mode & stat.S_ISVTX
        ):
            sys.exit(f"remote alpha output folder: {shown} can be written by its group or others; refusing to write under it")
        if last:
            break
        shown = "/" + "/".join(parts[: index + 1])
        try:
            next_fd = os.open(parts[index], flags, dir_fd=fd)
        except FileNotFoundError:
            try:
                os.mkdir(parts[index], 0o755, dir_fd=fd)
            except FileExistsError:
                pass
            next_fd = os.open(parts[index], flags, dir_fd=fd)
        os.close(fd)
        fd = next_fd
except OSError as exc:
    sys.exit(f"remote alpha output folder: {shown} is not a directory or is a symbolic link ({exc.strerror})")
finally:
    os.close(fd)
REMOTE_ALPHA_OUTPUT_DIR_PY
}

# remote_alpha_prepare_output_dir_as_root DIR [SUDO_OPTION...]
#
# Mac-side routes that stage helpers under the host's artifact folder send this
# whole file at the front of their remote batch and call this before any other
# sudo step. It runs remote_alpha_prepare_output_dir DIR as root, so the folders
# it creates belong to root, and the SSH user stays trusted through SUDO_UID.
remote_alpha_prepare_output_dir_as_root() {
  local dir=$1
  shift
  {
    declare -f remote_alpha_prepare_output_dir
    printf '%s\n' 'remote_alpha_prepare_output_dir "$1"'
  } | sudo "$@" /bin/bash -s -- "${dir}"
}
