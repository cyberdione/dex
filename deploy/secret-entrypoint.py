#!/usr/bin/env python3
"""Consume Dex runtime secrets from stdin, materialize private files, exec Dex."""

import json
import os
import re
import sys


def main() -> None:
    payload = sys.stdin.buffer.read(1024 * 1024 + 1)
    if len(payload) > 1024 * 1024:
        raise SystemExit("runtime secret exceeds 1 MiB")
    secrets = json.loads(payload)
    required = {
        "db_password",
        "atproto_client_key",
        "atproto_state_encryption_key_base64",
        "roster_yaml",
    }
    if not isinstance(secrets, dict) or required - secrets.keys():
        raise SystemExit("runtime secret is missing required fields")

    client_secrets = secrets.get("client_secrets", {})
    if not isinstance(client_secrets, dict):
        raise SystemExit("client_secrets must be a JSON object")
    for name, value in client_secrets.items():
        if not re.fullmatch(r"DEX_CLIENT_[A-Z0-9_]{1,48}", name) or not isinstance(value, str) or not value:
            raise SystemExit("client_secrets contains an invalid entry")
        os.environ[name] = value

    os.makedirs("/run/dex", mode=0o700, exist_ok=True)
    files = {
        "/run/dex/atproto-client-key": secrets["atproto_client_key"].encode(),
        "/run/dex/atproto-state-key": __import__("base64").b64decode(
            secrets["atproto_state_encryption_key_base64"], validate=True
        ),
        "/run/dex/roster.yaml": secrets["roster_yaml"].encode(),
    }
    if len(files["/run/dex/atproto-state-key"]) != 32:
        raise SystemExit("atproto state encryption key must decode to exactly 32 bytes")
    for path, content in files.items():
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o400)
        with os.fdopen(fd, "wb") as target:
            target.write(content)
        os.chmod(path, 0o400)

    os.environ["DEX_POSTGRES_PASSWORD"] = secrets["db_password"]
    os.execv("/usr/local/bin/dex", ["dex", "serve", "/etc/dex/config.yaml"])


if __name__ == "__main__":
    main()
