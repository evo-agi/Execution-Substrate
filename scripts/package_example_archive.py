#!/usr/bin/env python3
"""Create a deterministic single-file tar.gz example payload."""

from __future__ import annotations

import gzip
import os
from pathlib import Path
import sys
import tarfile
import tempfile


def usage() -> None:
    print(
        "usage: package_example_archive.py SOURCE OUTPUT ARCNAME",
        file=sys.stderr,
    )


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        usage()
        return 2

    source = Path(argv[1])
    output = Path(argv[2])
    arcname = argv[3]
    if not source.is_file():
        print(f"source is not a file: {source}", file=sys.stderr)
        return 1
    if arcname.startswith("/") or "/../" in f"/{arcname}/":
        print(f"unsafe archive name: {arcname}", file=sys.stderr)
        return 1

    output.parent.mkdir(parents=True, exist_ok=True)
    stat = source.stat()
    info = tarfile.TarInfo(arcname)
    info.size = stat.st_size
    info.mode = stat.st_mode & 0o777
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""

    fd, temp_name = tempfile.mkstemp(
        prefix=f".{output.name}.",
        suffix=".tmp",
        dir=str(output.parent),
    )
    try:
        with os.fdopen(fd, "wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as gz:
                with tarfile.open(fileobj=gz, mode="w") as archive:
                    with source.open("rb") as source_file:
                        archive.addfile(info, source_file)
        os.replace(temp_name, output)
    except Exception:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise

    print(f"Wrote {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
