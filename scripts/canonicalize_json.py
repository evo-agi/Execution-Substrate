#!/usr/bin/env python3
"""Canonicalize JSON values and compute labeled SHA-256 digests."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


def _load_json(path: str) -> Any:
    if path == "-":
        return json.load(sys.stdin)
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _canonical_text(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Canonicalize JSON using sorted keys and no insignificant whitespace.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    canonicalize = subparsers.add_parser("canonicalize")
    canonicalize.add_argument("input", help="JSON file path or - for stdin")

    digest = subparsers.add_parser("digest")
    digest.add_argument("input", help="JSON file path or - for stdin")

    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    value = _load_json(args.input)
    canonical = _canonical_text(value)
    canonical_bytes = canonical.encode("utf-8")

    if args.command == "canonicalize":
        sys.stdout.buffer.write(canonical_bytes)
        sys.stdout.buffer.write(b"\n")
        return 0

    if args.command == "digest":
        sys.stdout.write(_digest(canonical_bytes))
        sys.stdout.write("\n")
        return 0

    raise AssertionError(f"unexpected command {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
