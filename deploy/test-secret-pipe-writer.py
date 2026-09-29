#!/usr/bin/env python3
"""Exercise secret-pipe-writer's no-stdout FIFO contract with dummy data."""

import os
import subprocess
import sys
import tempfile
import threading


def main() -> None:
    payload = b'{"fixture":"not-a-secret"}'
    writer_path = os.path.join(os.path.dirname(__file__), "secret-pipe-writer.py")
    with tempfile.TemporaryDirectory(prefix="dex-secret-pipe-test-") as directory:
        fifo_path = os.path.join(directory, "secret.pipe")
        received = bytearray()
        os.mkfifo(fifo_path, 0o600)

        def read_pipe() -> None:
            with open(fifo_path, "rb") as fifo:
                received.extend(fifo.read())

        reader = threading.Thread(target=read_pipe)
        reader.start()
        result = subprocess.run(
            [sys.executable, writer_path, fifo_path],
            input=payload,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )
        reader.join(timeout=10)
        if reader.is_alive():
            raise SystemExit("FIFO reader did not finish")
        if result.returncode != 0 or result.stdout or result.stderr or received != payload:
            raise SystemExit("secret-pipe-writer violated its stdin-to-FIFO contract")


if __name__ == "__main__":
    main()
