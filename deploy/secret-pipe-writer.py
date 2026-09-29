#!/usr/bin/env python3
"""Forward one bounded secret document from stdin to a private FIFO."""

import os
import stat
import sys


MAX_SECRET_BYTES = 64 * 1024


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("secret FIFO path is required")
    payload = sys.stdin.buffer.read(MAX_SECRET_BYTES + 1)
    if not payload or len(payload) > MAX_SECRET_BYTES:
        raise SystemExit("runtime secret is empty or exceeds 64 KiB")
    if not stat.S_ISFIFO(os.stat(sys.argv[1]).st_mode):
        raise SystemExit("runtime secret target must be a FIFO")
    with open(sys.argv[1], "wb", buffering=0) as fifo:
        fifo.write(payload)


if __name__ == "__main__":
    main()
