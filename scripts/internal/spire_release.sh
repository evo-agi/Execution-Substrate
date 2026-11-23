#!/usr/bin/env bash

# The SPIRE release files that this repository may unpack, and the check that
# a file is one of them. scripts/72_supported_local_setup.sh,
# scripts/73_supported_local_proof.sh and the CI workflow source this file. It
# has no top-level effects besides setting SPIRE_RELEASE_PIN_FILE.
#
# spire_release.sha256, next to this file, holds one line per release file, in
# the form of the release's own checksum file
# (spire-<version>-linux-<arch>-musl_sha256sum.txt on
# https://github.com/spiffe/spire/releases): the SHA-256, two spaces, the file
# name. A line is added only after the file was downloaded and its hash was
# compared with that checksum file. A file with no line is refused, so a new
# SPIRE version or architecture needs a reviewed line there first. That
# checksum file is not signed and comes from the same place as the release
# file, so a line pins the file that was reviewed; it does not prove who
# published it.

SPIRE_RELEASE_PIN_FILE="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/spire_release.sha256"

# Prints the SHA-256 pinned for one release file name, such as
# spire-1.14.4-linux-arm64-musl.tar.gz. Fails, with the reason on stderr, when
# the pin file has no line or more than one line for it, or a malformed line.
spire_release_pinned_sha256() {
  local asset=$1
  local line
  local found=""
  local count=0
  local pattern='^([0-9a-f]{64})  ([^[:space:]/]+)$'

  if [[ -z "${asset}" || "${asset}" == */* || "${asset}" =~ [[:space:]] ]]; then
    echo "invalid SPIRE release file name: ${asset}" >&2
    return 1
  fi
  if [[ ! -f "${SPIRE_RELEASE_PIN_FILE}" || ! -r "${SPIRE_RELEASE_PIN_FILE}" ]]; then
    echo "SPIRE release pin file is not readable: ${SPIRE_RELEASE_PIN_FILE}" >&2
    return 1
  fi
  while IFS= read -r line || [[ -n "${line}" ]]; do
    if [[ ! "${line}" =~ ${pattern} ]]; then
      echo "malformed line in ${SPIRE_RELEASE_PIN_FILE}: each line must be a SHA-256, two spaces and a file name" >&2
      return 1
    fi
    if [[ "${BASH_REMATCH[2]}" == "${asset}" ]]; then
      found="${BASH_REMATCH[1]}"
      count=$((count + 1))
    fi
  done < "${SPIRE_RELEASE_PIN_FILE}"
  if [[ "${count}" -eq 0 ]]; then
    echo "no SHA-256 is pinned for the SPIRE release file ${asset}: add its line from the release's checksum file to ${SPIRE_RELEASE_PIN_FILE} after checking it" >&2
    return 1
  fi
  if [[ "${count}" -ne 1 ]]; then
    echo "the SPIRE release file ${asset} has more than one line in ${SPIRE_RELEASE_PIN_FILE}" >&2
    return 1
  fi
  printf '%s\n' "${found}"
}

# Succeeds only when the file's SHA-256 is the one pinned for the release file
# name. Callers run it after the file is in its final place and before they
# unpack or copy it on, so that the bytes checked are the bytes used.
spire_release_verify() {
  local file=$1
  local asset=$2
  local expected
  local observed

  if ! expected="$(spire_release_pinned_sha256 "${asset}")"; then
    return 1
  fi
  if ! observed="$(python3 -I -c '
import hashlib
import sys

digest = hashlib.sha256()
with open(sys.argv[1], "rb") as source:
    for block in iter(lambda: source.read(1 << 20), b""):
        digest.update(block)
print(digest.hexdigest())
' "${file}")"; then
    echo "cannot read the SPIRE release file ${file}" >&2
    return 1
  fi
  if [[ "${observed}" != "${expected}" ]]; then
    echo "SPIRE release file ${file} has SHA-256 ${observed}, not ${expected}, which ${SPIRE_RELEASE_PIN_FILE} pins for ${asset}" >&2
    return 1
  fi
}
