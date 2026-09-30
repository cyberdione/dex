#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
grep -Fq 'ferruleos-bootc-os@sha256:' "$root/Containerfile"
grep -Fq 'COPY caddy.container /etc/containers/systemd/caddy.container' "$root/Containerfile"
grep -Fq '<service name="http"/>' "$root/public.xml"
grep -Fq '<service name="https"/>' "$root/public.xml"
grep -Fq 'EnvironmentFile=/etc/dex/deploy.env' "$root/dex.service"
grep -Fq 'EnvironmentFile=/etc/dex/deploy.env' "$root/dex-storage-init.service"
grep -Fq 'login.federate.to' "$root/Caddyfile"
test -s "$root/rds-ca-rsa2048-g1.pem"
grep -Fq 'COPY rds-ca-rsa2048-g1.pem /etc/dex/rds-ca-rsa2048-g1.pem' "$root/Containerfile"
if grep -Eqi 'DEX_POSTGRES_PASSWORD=|BEGIN[^[:cntrl:]]*PRIVATE KEY|private_multibase|atproto_state_encryption_key_base64=|roster_yaml=' \
  "$root"/run-dex "$root"/dex-storage-init "$root"/caddy.container; then
  echo 'runtime secret material must not be baked into the image' >&2
  exit 1
fi
echo 'identity bootc image contract passed'
