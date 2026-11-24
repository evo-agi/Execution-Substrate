#!/usr/bin/env bash

control_plane_image_ref() {
  printf '%s\n' "${CONTROL_PLANE_IMAGE:-execution-substrate/control-plane:local}"
}

control_plane_dockerfile_path() {
  printf '%s\n' "${CONTROL_PLANE_DOCKERFILE:-$(bringup_repo_root)/.out/Dockerfile}"
}

control_plane_dockerfile_generator_path() {
  printf '%s\n' "$(bringup_repo_root)/scripts/generate_control_plane_dockerfile.sh"
}

ensure_default_control_plane_dockerfile() {
  local dockerfile_path=$1
  local generator

  if [[ -n "${CONTROL_PLANE_DOCKERFILE:-}" ]]; then
    return 0
  fi

  generator="$(control_plane_dockerfile_generator_path)"
  require_readable_path "control-plane Dockerfile generator" "${generator}" || return 1

  mkdir -p "$(dirname "${dockerfile_path}")"
  if ! bash "${generator}" "${dockerfile_path}" >/dev/null; then
    echo "control-plane Dockerfile generation failed for ${dockerfile_path}" >&2
    return 1
  fi
}

control_plane_image_build_mode() {
  printf '%s\n' "${CONTROL_PLANE_IMAGE_BUILD:-always}"
}

control_plane_target_arch() {
  local machine
  local goarch

  if [[ -n "${CONTROL_PLANE_TARGETARCH:-}" ]]; then
    printf '%s\n' "${CONTROL_PLANE_TARGETARCH}"
    return 0
  fi

  machine="$(uname -m)"
  case "${machine}" in
    x86_64|amd64)
      printf 'amd64\n'
      return 0
      ;;
    aarch64|arm64)
      printf 'arm64\n'
      return 0
      ;;
  esac

  if command -v go >/dev/null 2>&1; then
    goarch="$(env GOTOOLCHAIN=local go env GOARCH 2>/dev/null || true)"
    case "${goarch}" in
      amd64|arm64)
        printf '%s\n' "${goarch}"
        return 0
        ;;
    esac
  fi

  echo "unable to determine control-plane image target architecture for ${machine}" >&2
  return 1
}

control_plane_binary_path() {
  local service=$1
  case "${service}" in
    ars|ags|egs|es|cgs)
      printf '/usr/local/bin/%s\n' "${service}"
      ;;
    *)
      echo "unknown control-plane service: ${service}" >&2
      return 1
      ;;
  esac
}

control_plane_container_name() {
  local service=$1
  python3 -I - <<'PY' "${service}" "${BRINGUP_DIR:-$(bringup_repo_root)/.tmp/bringup}"
import hashlib
import re
import sys

service = sys.argv[1]
seed = sys.argv[2]
digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:12]
name = f"execution-substrate-{digest}-{service}"
print(re.sub(r"[^A-Za-z0-9_.-]+", "-", name))
PY
}

ensure_control_plane_image() {
  local log_file=$1
  local image
  local dockerfile
  local mode
  local repo_root
  local target_arch

  image="$(control_plane_image_ref)"
  dockerfile="$(control_plane_dockerfile_path)"
  mode="$(control_plane_image_build_mode)"
  repo_root="$(bringup_repo_root)"
  target_arch="$(control_plane_target_arch)" || return 1

  ensure_default_control_plane_dockerfile "${dockerfile}" || return 1
  require_readable_path "control-plane Dockerfile" "${dockerfile}" || return 1

  case "${mode}" in
    always)
      ;;
    if-missing)
      if docker image inspect "${image}" >/dev/null 2>&1; then
        return 0
      fi
      ;;
    never)
      if docker image inspect "${image}" >/dev/null 2>&1; then
        return 0
      fi
      echo "control-plane image ${image} is missing and CONTROL_PLANE_IMAGE_BUILD=never" >&2
      return 1
      ;;
    *)
      echo "CONTROL_PLANE_IMAGE_BUILD must be always, if-missing, or never" >&2
      return 1
      ;;
  esac

  if docker image inspect "${image}" >/dev/null 2>&1; then
    echo "==> rebuilding control-plane image ${image}"
  else
    echo "==> building control-plane image ${image}"
  fi

  mkdir -p "$(dirname "${log_file}")"
  if ! docker build --build-arg "TARGETARCH=${target_arch}" -t "${image}" -f "${dockerfile}" "${repo_root}" >"${log_file}" 2>&1; then
    echo "control-plane image build failed; see ${log_file}" >&2
    return 1
  fi
}

# control_plane_operator_user prints the calling operator's numeric effective
# UID and primary GID as UID:GID for docker run --user. The generic bring-up
# launchers run ARS, EGS, AGS and ES as that identity, so no service holds more
# host authority than the operator who started it and every file a service
# writes belongs to that operator. Docker gives the identity no supplementary
# groups. Both IDs must be numeric, because docker run --user with an empty UID
# runs as root. Command substitutions do not inherit errexit, so each id call
# is checked explicitly.
control_plane_operator_user() {
  local service=$1
  local uid
  local gid

  uid="$(id -u)" || return 1
  gid="$(id -g)" || return 1
  if [[ ! "${uid}" =~ ^[0-9]+$ || ! "${gid}" =~ ^[0-9]+$ ]]; then
    printf 'cannot run %s as the operator: id -u and id -g must print numeric IDs, got %q and %q\n' "${service}" "${uid}" "${gid}" >&2
    return 1
  fi
  printf '%s:%s\n' "${uid}" "${gid}"
}

# verify_ars_storage_for_operator checks, before ARS starts, that ARS can use
# its storage, by doing what ARS does with it in a short-lived container that
# runs exactly as ARS will: the same image, the UID:GID that
# control_plane_operator_user printed (passed as the second argument), the
# same mounts (control_plane_mount_specs ars), and ARS's container name, so
# that Docker refuses the check while an ARS container still exists. The
# kernel, and on macOS Docker Desktop's file sharing, therefore decides every
# step for that identity, with whatever groups Docker gives it, through the
# mounts ARS will see; nothing about owners, groups, modes, ACLs or the sticky
# rule is emulated.
#
# On the host, as the caller, the check only reads the config:
# storage.root_dir and storage.index_file must be absolute paths written in
# normal form (no surrounding whitespace, no "." or ".." component, no
# repeated or trailing slash). ARS opens both strings exactly as written,
# while its mounts are built from their normal form, so only a path already in
# normal form names the same file for ARS as for its mounts and for this check.
# The root is created as the caller when it is missing (otherwise Docker would
# create the bind source as root), and the index file must already exist as a
# regular file, not a symbolic link (ARS refuses to start without it, and
# replaces it with a regular file at its first write).
#
# In the container, as ARS's identity, it then:
#   1. changes into every directory on the way to the storage root and to the
#      index directory;
#   2. creates and removes a file in the index directory, and reads the index;
#   3. walks the storage root: creates a file in every directory, finds it
#      again by listing that directory, and opens every regular file for
#      reading. Any other entry (a symbolic link, FIFO, socket or device) is
#      refused: ARS never creates one, and ARS would pass through a link at a
#      blob or shard path, so the check can neither skip a link nor safely
#      follow one. It removes the files it created in batches, the files of
#      every 256 walked directories and the rest when the walk is done, and
#      refuses the first directory where one could not be removed;
#   4. last, only when everything above passed, writes the index the way ARS
#      does: a new 0600 file with the index's current content, renamed over
#      it. The index then belongs to ARS's identity, as after ARS's first write.
# Each step is one ARS takes, so a refusal names a step ARS would fail.
# The walk starts no process per directory (the shell's own cd, redirections
# and pattern matching do the work), because ARS's sha256/xx/yy layout grows to
# 65,794 directories. A refusal before step 4 leaves storage as it was, except
# for a root created in the host step and a file the check could not remove.
# So does a check stopped by SIGHUP, SIGINT or SIGTERM: the host part passes
# the signal on to the probe and waits for it, and the probe removes its files
# before it exits. A probe killed outright, for example by docker rm -f, can
# leave at most one batch of its empty files, which are named
# .ars-storage-check.* and which the next check reads as ordinary files.
# Storage that an earlier bring-up wrote as root, or that is shared through
# another group, fails with the exact sudo chown that hands it back; the check
# does not repair ownership itself. The
# image must provide /bin/sh with mktemp, xargs, rm, cat, chmod and mv, as the
# generated control-plane image does through Alpine's BusyBox.
verify_ars_storage_for_operator() {
  local config_path=$1
  local container_user=$2
  local mount_specs=()
  local spec

  while IFS= read -r spec; do
    [[ -n "${spec}" ]] || continue
    mount_specs+=("${spec}")
  done < <(control_plane_mount_specs ars "${config_path}")

  python3 -I - "${config_path}" "${container_user}" "$(control_plane_image_ref)" "$(control_plane_container_name ars)" "${mount_specs[@]}" <<'PY'
import json
import os
import pathlib
import re
import shlex
import signal
import stat
import subprocess
import sys

prefix = "ARS storage check failed"
user_match = re.fullmatch(r"([0-9]+):([0-9]+)", sys.argv[2])
if user_match is None:
    print(f"{prefix}: the container identity must be numeric UID:GID, got {sys.argv[2]!r}", file=sys.stderr)
    raise SystemExit(1)
IDENTITY = f"{user_match.group(1)}:{user_match.group(2)}"
IMAGE = sys.argv[3]
CONTAINER_NAME = sys.argv[4]
MOUNT_SPECS = sys.argv[5:]
cfg = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
storage = cfg.get("storage") if isinstance(cfg.get("storage"), dict) else {}
root_dir = storage.get("root_dir") if isinstance(storage.get("root_dir"), str) else ""
index_file = storage.get("index_file") if isinstance(storage.get("index_file"), str) else ""


def refuse(message, path=None, fix=None, recursive=False):
    if path is not None:
        message += f": {path}"
    if fix is not None:
        chown = "chown -R" if recursive else "chown"
        message += (
            f". ARS runs as {IDENTITY}, your UID and primary group, with no"
            f" supplementary groups; if an earlier bring-up wrote this storage as root,"
            f" or it is shared through another group, hand it back with:"
            f" sudo {chown} {IDENTITY} {shlex.quote(str(fix))}"
        )
    print(f"{prefix}: {message}", file=sys.stderr)
    raise SystemExit(1)


def configured_path(key, value):
    # ARS stats and opens the configured string exactly as written, while its
    # mounts are built from the string's normal form. Only a path already in
    # normal form names the same file both ways, so any other is refused, with
    # the form to write instead.
    if value.strip() and (value != value.strip() or os.path.normpath(value) != value):
        refuse(
            f"storage.{key} must be written in normal form, because ARS opens it exactly as written and its"
            f" mounts use the normal form: {value!r}; write {os.path.normpath(value.strip())!r}"
        )
    if not os.path.isabs(value):
        refuse(f"storage.{key} must be an absolute path")
    return pathlib.Path(value)


root = configured_path("root_dir", root_dir)
index = configured_path("index_file", index_file)

# The caller must be able to reach both paths to create the root and to see
# the index; a permission error is a refusal with the path, not a traceback.
try:
    root_info = os.stat(root)
except FileNotFoundError:
    try:
        root.mkdir(parents=True)
        root_info = os.stat(root)
    except OSError as error:
        refuse(f"cannot create storage.root_dir as you: {root} ({error.strerror})")
except NotADirectoryError:
    refuse(f"storage.root_dir is not a directory: {root}")
except OSError as error:
    refuse(f"cannot reach storage.root_dir as you: {root} ({error.strerror}); you need search permission on every directory above it")
if not stat.S_ISDIR(root_info.st_mode):
    refuse(f"storage.root_dir is not a directory: {root}")
try:
    index_info = os.lstat(index)
except (FileNotFoundError, NotADirectoryError):
    refuse(f"storage.index_file must be an existing regular file: {index}")
except OSError as error:
    refuse(f"cannot reach storage.index_file as you: {index} ({error.strerror}); you need search permission on every directory above it")
if stat.S_ISLNK(index_info.st_mode):
    refuse(f"storage.index_file must be a regular file, not a symbolic link, because ARS replaces it with a regular file at its first write: {index}")
if not stat.S_ISREG(index_info.st_mode):
    refuse(f"storage.index_file must be an existing regular file: {index}")

# A refusal of the probe is one record, the only thing it prints on stdout:
# REFUSE, the kind, the message and the path, separated by tabs. The path
# comes last because it may contain any character but NUL.
PROBE = r'''
set -u
root=$1
index=$2
dir=${index%/*}
[ -n "$dir" ] || dir=/
current_tmp=
list=
# The walk's own files are named with one random name, which no earlier,
# interrupted check used.
marker=$(mktemp -u -p / .ars-storage-check.XXXXXX) || exit 1
marker=${marker##*/}
cleanup() {
  trap '' HUP INT TERM
  exec 3>&-
  [ -z "$list" ] || { xargs -0 rm -f -- < "$list"; rm -f -- "$list"; } 2>/dev/null
  [ -z "$current_tmp" ] || rm -f -- "$current_tmp" 2>/dev/null
}
trap cleanup EXIT
# Stopped by a signal, for example by Ctrl-C, the probe still removes its
# files. It runs as PID 1 of its container, which gets no default action for
# these signals, so each needs a trap; a second signal, as from pressing
# Ctrl-C again, must not cut the removal short.
trap 'trap "" HUP INT TERM; exit 129' HUP
trap 'trap "" HUP INT TERM; exit 130' INT
trap 'trap "" HUP INT TERM; exit 143' TERM
refuse() {
  printf 'REFUSE\t%s\t%s\t%s' "$1" "$3" "$2"
  exit 42
}
# chdir needs search permission, so each step is the kernel's decision. A
# component is entered as ./component, so that one named "-" is not taken for
# the previous directory.
reach() {
  target=$1
  kind=$2
  cd / || refuse "$kind" / "ARS cannot search this directory"
  path=
  rest=${target#/}
  while [ -n "$rest" ]; do
    case $rest in
      */*) component=${rest%%/*}; rest=${rest#*/} ;;
      *) component=$rest; rest= ;;
    esac
    [ -n "$component" ] || continue
    path=$path/$component
    if ! cd -P -- "./$component" 2>/dev/null; then
      [ -z "$rest" ] || refuse above "$path" "$3"
      refuse "$kind" "$path" "ARS cannot search this directory"
    fi
  done
}
writable() {
  current_tmp=$(mktemp -p "$1" .ars-storage-check.XXXXXX 2>/dev/null) || {
    current_tmp=
    refuse "$2" "$1" "ARS cannot create files in this directory"
  }
  rm -f -- "$current_tmp" 2>/dev/null || refuse remove "$1" "ARS cannot remove its own file from this directory"
  current_tmp=
}
# walk starts no process: cd, the redirections, test and the patterns are the
# shell's own. A directory the kernel does not let ARS list expands no pattern,
# so the file just created there is not found. The file's path goes to the
# list on descriptor 3 before the file is created, so that a check stopped in
# between still removes it. Once 256 directories have been walked, the files on
# the list are removed and the list starts again (remove_walk_files), so a
# probe killed outright leaves at most that many. A directory still being
# walked has already expanded its patterns, so its file can go too.
walk() {
  local d=$1 e seen=
  cd -P -- "$d" 2>/dev/null || refuse storage "$d" "ARS cannot search this directory"
  printf '%s\0' "$d/$marker" >&3
  true 2>/dev/null > "$d/$marker" || refuse storage "$d" "ARS cannot create files in this directory"
  for e in "$d"/* "$d"/.*; do
    if [ "$e" = "$d/$marker" ]; then
      seen=1
    elif [ "$e" = "$d/." ] || [ "$e" = "$d/.." ]; then
      continue
    elif [ -L "$e" ]; then
      refuse entry "$e" "storage.root_dir holds a symbolic link, which ARS never creates"
    elif [ -d "$e" ]; then
      walk "$e"
    elif [ -f "$e" ]; then
      true 2>/dev/null < "$e" || refuse storage "$e" "ARS cannot read this file"
    elif [ -e "$e" ]; then
      refuse entry "$e" "storage.root_dir holds a special file, which ARS never creates"
    fi
  done
  [ -n "$seen" ] || refuse storage "$d" "the check cannot see the files below this directory, because ARS cannot list it"
  walked=$((walked + 1))
  [ "$walked" -lt 256 ] || remove_walk_files
}
# remove_walk_files removes the files on the list, refuses the first directory
# that still holds one, and starts the list again.
remove_walk_files() {
  exec 3>&-
  if ! xargs -0 rm -f -- < "$list" 2>/dev/null; then
    left=$root
    left_behind "$root" || true
    refuse remove "$left" "ARS cannot remove its own file from this directory"
  fi
  exec 3>| "$list"
  walked=0
}
# left_behind finds, in the walk's order, the first directory that still holds
# the walk's file.
left_behind() {
  local d=$1 e
  if [ -e "$d/$marker" ] || [ -L "$d/$marker" ]; then
    left=$d
    return 0
  fi
  for e in "$d"/* "$d"/.*; do
    if [ "$e" != "$d/." ] && [ "$e" != "$d/.." ] && [ ! -L "$e" ] && [ -d "$e" ] && left_behind "$e"; then
      return 0
    fi
  done
  return 1
}
reach "$root" storage "ARS cannot search this directory on its way to storage.root_dir"
reach "$dir" "index directory" "ARS cannot search this directory on its way to storage.index_file"
writable "$dir" "index directory"
true 2>/dev/null < "$index" || refuse index "$index" "ARS cannot read the index file"
list=$(mktemp 2>/dev/null) || {
  list=
  echo "cannot create a temporary file in the check container" >&2
  exit 1
}
exec 3> "$list"
walked=0
set -C
walk "$root"
set +C
remove_walk_files
exec 3>&-
rm -f -- "$list"
list=
current_tmp=$(mktemp -p "$dir" .artifact-index-check.XXXXXX 2>/dev/null) || {
  current_tmp=
  refuse "index directory" "$dir" "ARS cannot create files in this directory"
}
cat -- "$index" 2>/dev/null > "$current_tmp" || refuse index "$index" "ARS cannot read the index file"
chmod 600 "$current_tmp" 2>/dev/null || refuse "index directory" "$dir" "ARS cannot set the mode of its own file in this directory"
mv -f -- "$current_tmp" "$index" 2>/dev/null || refuse "index replace" "$index" "ARS cannot rename a new file over the index file"
current_tmp=
'''

command = ["docker", "run", "--rm", "--name", CONTAINER_NAME, "--network", "none", "--user", IDENTITY]
for spec in MOUNT_SPECS:
    command += ["-v", spec]
command += ["--entrypoint", "/bin/sh", IMAGE, "-c", PROBE, "ars-storage-probe", str(root), str(index)]
# Stopped by SIGHUP, SIGINT or SIGTERM, the check passes the first such signal
# on to the docker client, which passes it on to the probe, and waits until the
# probe has removed its files and ended. Only the first: the docker client
# gives up waiting once it has received three such signals, and the probe
# ignores every signal after the first anyway. The client runs in a session of
# its own, so that only this process signals it: 01_bringup.sh stops ARS's
# launcher by signalling the launcher's own child processes, which is this
# one, and Ctrl-C signals the terminal's whole foreground process group. A
# signal that this process was started to ignore stays ignored.
received = []
child = None
# Whoever takes this one item passes the signal on; list.pop is atomic, so a
# signal handler that runs in the middle of forward() cannot pass it on twice.
forward_once = [True]


def forward():
    if received and child is not None:
        try:
            forward_once.pop()
        except IndexError:
            return
        child.send_signal(received[0])


def stop(signum, frame):
    received.append(signum)
    forward()


for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
    if signal.getsignal(signum) != signal.SIG_IGN:
        signal.signal(signum, stop)
if not received:
    child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    forward()
    stdout, stderr = child.communicate()
if received:
    print("ARS storage check interrupted", file=sys.stderr)
    raise SystemExit(128 + received[0])
result = subprocess.CompletedProcess(command, child.returncode, stdout, stderr)
if result.returncode == 0:
    raise SystemExit(0)
record = result.stdout.decode("utf-8", "surrogateescape")
if result.returncode == 42 and record.startswith("REFUSE\t"):
    fields = record.split("\t", 3)
    if len(fields) == 4:
        _, kind, message, path = fields
        if kind == "entry":
            refuse(
                message, path + ". ARS creates only directories and regular files there; replace a link with"
                " what it points to, or move the entry out of storage.root_dir"
            )
        message += f" as {IDENTITY}"
        if kind == "storage":
            refuse(message, path, fix=root, recursive=True)
        if kind == "index directory":
            refuse(message, path, fix=index.parent)
        if kind == "index":
            refuse(message, path, fix=index)
        if kind == "remove":
            # It created the file a moment ago, so ownership and modes are not
            # the cause.
            refuse(
                message, path + ". ARS removes its own files there, and an append-only or immutable attribute on"
                " this directory prevents that for everyone"
            )
        if kind == "index replace":
            refuse(
                message, path + ". ARS writes the index that way. In a directory with the sticky bit, only the owner"
                " of the file or of the directory may, and an immutable or append-only attribute on the index or"
                " its directory prevents it for everyone", fix=index
            )
        if kind == "above":
            refuse(
                message, path + f". ARS runs as {IDENTITY}, your UID and primary group, with no supplementary"
                f" groups; give that identity search permission on this directory, or choose a path it can reach"
            )
# The docker CLI ends its errors with a pointer to docker run --help, which
# does not apply here.
details = "\n".join(
    line for line in (result.stderr or result.stdout).decode("utf-8", "replace").strip().splitlines()
    if not re.fullmatch(r"Run '.*--help' for more information\.?", line.strip())
).strip()
hint = ""
if "is already in use" in details:
    hint = "; ARS's container still exists, so stop it first, for example with scripts/01_bringup.sh down"
refuse(f"could not run the check container as {IDENTITY} (exit {result.returncode}): {details}{hint}")
PY
}

control_plane_mount_specs() {
  local service=$1
  local config_path=$2

  python3 -I - <<'PY' "${service}" "${config_path}"
import json
import os
import pathlib
import sys

service = sys.argv[1]
config_path = pathlib.Path(sys.argv[2]).resolve()
cfg = json.loads(config_path.read_text(encoding="utf-8"))

ro_files = {str(config_path)}
rw_dirs = set()

def walk(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if isinstance(child, str) and key.endswith("_file") and os.path.isabs(child):
                ro_files.add(os.path.normpath(child))
            else:
                walk(child)
    elif isinstance(value, list):
        for child in value:
            walk(child)

def get_path(*segments):
    current = cfg
    for segment in segments:
        if not isinstance(current, dict) or segment not in current:
            return ""
        current = current[segment]
    return current.strip() if isinstance(current, str) else ""

walk(cfg)

if service == "ars":
    root_dir = get_path("storage", "root_dir")
    index_file = get_path("storage", "index_file")
    if root_dir and os.path.isabs(root_dir):
        rw_dirs.add(os.path.normpath(root_dir))
    if index_file and os.path.isabs(index_file):
        rw_dirs.add(os.path.normpath(str(pathlib.Path(index_file).parent)))
elif service == "es":
    staging_root = get_path("execution", "staging_root_dir")
    results_root = get_path("execution", "results_root_dir")
    spire_socket = get_path("execution", "spire_workload_api_socket_path")
    if staging_root and os.path.isabs(staging_root):
        rw_dirs.add(os.path.normpath(staging_root))
    if results_root and os.path.isabs(results_root):
        rw_dirs.add(os.path.normpath(results_root))
    if spire_socket and os.path.isabs(spire_socket):
        ro_files.add(os.path.normpath(spire_socket))

def is_ancestor(parent, child):
    if parent == child:
        return True
    parent_parts = pathlib.Path(parent).parts
    child_parts = pathlib.Path(child).parts
    return len(parent_parts) < len(child_parts) and child_parts[:len(parent_parts)] == parent_parts

rw_dirs = {path for path in rw_dirs if os.path.isabs(path)}
collapsed_rw = sorted(
    path for path in rw_dirs
    if not any(other != path and is_ancestor(other, path) for other in rw_dirs)
)

ro_files = {path for path in ro_files if os.path.isabs(path)}
ro_files = sorted(
    path for path in ro_files
    if not any(is_ancestor(parent, path) for parent in collapsed_rw)
)

for path in collapsed_rw:
    print(f"{path}:{path}:rw")
for path in ro_files:
    print(f"{path}:{path}:ro")
PY
}

verify_supported_local_es_root_profile() {
  local config_path=$1
  local error_prefix=$2
  local proof_dir="${SUPPORTED_LOCAL_PROOF_DIR:-}"
  local staging_root
  local results_root
  local roots_helper
  local mount_specs
  local spec
  local staging_found=0
  local results_found=0

  if [[ -z "${proof_dir}" || -z "${SUPPORTED_LOCAL_PROOF_ID:-}" ||
        "${config_path}" != "${proof_dir}/es.json" ]]; then
    echo "${error_prefix}: supported-local proof config or roots are mismatched" >&2
    return 1
  fi
  if [[ "$(control_plane_image_ref)" != "execution-substrate/control-plane:supported-local" ]]; then
    echo "${error_prefix}: supported-local service image is incompatible" >&2
    return 1
  fi
  if [[ "${CONTROL_PLANE_DOCKERFILE:-}" != "${proof_dir}/Dockerfile" ]]; then
    echo "${error_prefix}: supported-local service Dockerfile is incompatible" >&2
    return 1
  fi

  roots_helper="$(bringup_repo_root)/scripts/internal/supported_local_execution_roots.py"
  if ! python3 -I "${roots_helper}" check "${proof_dir}" "${SUPPORTED_LOCAL_PROOF_ID}" "${config_path}" >/dev/null 2>&1; then
    echo "${error_prefix}: supported-local root owner, mode, or identity is invalid" >&2
    return 1
  fi

  # The checked helper binds both config fields to these exact proof children.
  # Require the ES container mount derivation to retain each same-path rw bind.
  staging_root="${proof_dir}/es-staging"
  results_root="${proof_dir}/es-results"
  if ! mount_specs="$(control_plane_mount_specs es "${config_path}" 2>/dev/null)"; then
    echo "${error_prefix}: supported-local ES mounts are invalid" >&2
    return 1
  fi
  while IFS= read -r spec; do
    if [[ "${spec}" == "${staging_root}:${staging_root}:rw" ]]; then
      staging_found=1
    fi
    if [[ "${spec}" == "${results_root}:${results_root}:rw" ]]; then
      results_found=1
    fi
  done <<< "${mount_specs}"
  if (( staging_found == 0 )); then
    echo "${error_prefix}: ES container is not mounted with ${staging_root}:${staging_root}:rw" >&2
    return 1
  fi
  if (( results_found == 0 )); then
    echo "${error_prefix}: ES container is not mounted with ${results_root}:${results_root}:rw" >&2
    return 1
  fi
}

verify_es_staging_invariant() {
  local config_path=$1
  local proof_path
  local staging_root
  local results_root
  local roots_profile="${SUPPORTED_LOCAL_ES_ROOTS_PROFILE:-}"
  local roots_output
  local root_line
  local -a es_roots
  local staging_found=0
  local results_found=0

  case "${roots_profile}" in
    "")
      ;;
    service-root-v1)
      ;;
    *)
      echo "ES staging invariant failed: unsupported supported-local roots profile" >&2
      return 1
      ;;
  esac

  if ! roots_output="$(python3 -I - "${config_path}" 2>/dev/null <<'PY'
import json
import pathlib
import sys

cfg = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
execution = cfg.get("execution") or {}
staging_root = (execution.get("staging_root_dir") or "").strip()
results_root = (execution.get("results_root_dir") or "").strip()
if not staging_root:
    raise SystemExit("missing execution.staging_root_dir")
if not results_root:
    raise SystemExit("missing execution.results_root_dir")
print(staging_root)
print(results_root)
PY
)"; then
    echo "ES staging invariant failed: execution roots config is invalid" >&2
    return 1
  fi
  es_roots=()
  while IFS= read -r root_line; do
    es_roots+=("${root_line}")
  done <<< "${roots_output}"
  if (( ${#es_roots[@]} != 2 )); then
    echo "ES staging invariant failed: execution roots config is invalid" >&2
    return 1
  fi
  staging_root="${es_roots[0]}"
  results_root="${es_roots[1]}"

  if [[ "${staging_root}" != /* ]]; then
    echo "ES staging invariant failed: execution.staging_root_dir must be absolute: ${staging_root}" >&2
    return 1
  fi
  if [[ "${results_root}" != /* ]]; then
    echo "ES staging invariant failed: execution.results_root_dir must be absolute: ${results_root}" >&2
    return 1
  fi
  if python3 -I - <<'PY' "${staging_root}" "${results_root}"
import os
import sys

staging_root = sys.argv[1]
results_root = sys.argv[2]
raise SystemExit(0 if os.path.commonpath([staging_root, results_root]) in {staging_root, results_root} else 1)
PY
  then
    echo "ES staging invariant failed: execution.results_root_dir must be separate from execution.staging_root_dir" >&2
    return 1
  fi
  if [[ "${roots_profile}" == "service-root-v1" ]]; then
    verify_supported_local_es_root_profile "${config_path}" "ES staging invariant failed" || return 1
  fi
  if [[ -z "${roots_profile}" ]]; then
    if [[ ! -d "${staging_root}" ]]; then
      mkdir -p "${staging_root}"
    fi
    if [[ ! -d "${results_root}" ]]; then
      mkdir -p "${results_root}"
    fi
    if [[ ! -d "${staging_root}" ]]; then
      echo "ES staging invariant failed: staging root does not exist: ${staging_root}" >&2
      return 1
    fi
    if [[ ! -d "${results_root}" ]]; then
      echo "ES staging invariant failed: results root does not exist: ${results_root}" >&2
      return 1
    fi
    if [[ ! -w "${staging_root}" ]]; then
      echo "ES staging invariant failed: staging root is not writable: ${staging_root}" >&2
      return 1
    fi
    if [[ ! -w "${results_root}" ]]; then
      echo "ES staging invariant failed: results root is not writable: ${results_root}" >&2
      return 1
    fi
  fi

  while IFS= read -r spec; do
    [[ -n "${spec}" ]] || continue
    if [[ "${spec}" == "${staging_root}:${staging_root}:rw" ]]; then
      staging_found=1
    fi
    if [[ "${spec}" == "${results_root}:${results_root}:rw" ]]; then
      results_found=1
    fi
  done < <(control_plane_mount_specs es "${config_path}")

  if (( staging_found == 0 )); then
    echo "ES staging invariant failed: ES container is not mounted with ${staging_root}:${staging_root}:rw" >&2
    return 1
  fi
  if (( results_found == 0 )); then
    echo "ES staging invariant failed: ES container is not mounted with ${results_root}:${results_root}:rw" >&2
    return 1
  fi

  proof_path="${BRINGUP_DIR}/staging-invariant.json"
  mkdir -p "$(dirname "${proof_path}")"
  python3 -I - <<'PY' "${proof_path}" "${staging_root}" "${results_root}" "${roots_profile}"
import json
import pathlib
import sys

payload = {
    "host_staging_path": sys.argv[2],
    "es_container_mount_path": sys.argv[2],
    "host_results_path": sys.argv[3],
    "es_container_results_path": sys.argv[3],
    "path_translation": False,
}
if sys.argv[4] == "service-root-v1":
    payload.update({
        "supported_local_es_roots_profile": "service-root-v1",
        "static_root_owner_mode_checked": True,
        "configured_root_uid": 0,
        "configured_root_gid": 0,
        "configured_root_mode": "0755",
        "operator_write_access_required": False,
        "container_identity_or_behavioral_capability_proved": False,
    })
pathlib.Path(sys.argv[1]).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

probe_control_plane_host_loopback() {
  local temp_dir=""
  local probe_path=""
  local port
  local server_pid=""
  local output
  local image

  cleanup_probe_control_plane_host_loopback() {
    if [[ -n "${server_pid:-}" ]]; then
      kill "${server_pid}" >/dev/null 2>&1 || true
      wait "${server_pid}" >/dev/null 2>&1 || true
    fi
    if [[ -n "${temp_dir:-}" ]]; then
      rm -rf "${temp_dir}"
    fi
  }

  temp_dir="$(mktemp -d)"
  probe_path="${temp_dir}/index.html"
  printf 'slice0-host-loopback-ok\n' >"${probe_path}"
  image="$(control_plane_image_ref)"

  port="$(python3 -I - <<'PY'
import socket

sock = socket.socket()
sock.bind(("127.0.0.1", 0))
print(sock.getsockname()[1])
sock.close()
PY
)"

  python3 -I -m http.server "${port}" --bind 127.0.0.1 --directory "${temp_dir}" >/dev/null 2>&1 &
  server_pid=$!
  trap cleanup_probe_control_plane_host_loopback RETURN
  sleep 1

  if ! output="$(docker run --rm --network host "${image}" wget -q -O - "http://127.0.0.1:${port}" 2>/dev/null)"; then
    echo "slice-0 requires Docker host networking that can reach host loopback from a container; current host does not provide that capability" >&2
    return 1
  fi
  if [[ "${output}" != "slice0-host-loopback-ok" ]]; then
    echo "slice-0 requires Docker host networking that preserves host loopback semantics; probe returned unexpected output" >&2
    return 1
  fi

  trap - RETURN
  cleanup_probe_control_plane_host_loopback
}
