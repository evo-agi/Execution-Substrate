#!/usr/bin/env bash

# Pure metadata check for the supported-local operator inputs. This file has
# no top-level setup effects and never opens the referenced key file.
supported_local_validate_retained_result_auth() {
  local store_id=$1
  local key_id=$2
  local key_file=$3
  shift 3

  python3 -I - "${store_id}" "${key_id}" "${key_file}" "$@" <<'PY'
import posixpath
import re
import sys

store_id, key_id, key_file, *forbidden_scopes = sys.argv[1:]
identifier = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z", re.ASCII)

def overlaps(left, right):
    if left == "/" or right == "/":
        return True
    return left == right or left.startswith(right + "/") or right.startswith(left + "/")

valid = bool(identifier.fullmatch(store_id) and identifier.fullmatch(key_id))
valid = valid and bool(key_file) and key_file.startswith("/") and not key_file.startswith("//")
valid = valid and key_file.strip() == key_file and posixpath.normpath(key_file) == key_file
valid = valid and posixpath.dirname(key_file) != "/" and "\x00" not in key_file
for scope in forbidden_scopes:
    if not scope or scope == "/" or not scope.startswith("/") or scope.startswith("//") or posixpath.normpath(scope) != scope:
        valid = False
    elif overlaps(key_file, scope):
        valid = False

# The proof wrapper's stale-scratch cleanup owns /tmp/es-proof-* directories,
# including earlier IDs that are not the current proof or bootstrap path.
parts = key_file.split("/")
if len(parts) > 2 and parts[1] == "tmp" and parts[2].startswith("es-proof-"):
    valid = False

if not valid:
    raise SystemExit("supported-local retained-result auth metadata or key placement is invalid")
PY
}
