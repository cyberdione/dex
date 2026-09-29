# Cyberdione production image

The `cyberdione` Dockerfile target adds the pinned-at-build Dex binary plus
`asm-exec` and a minimal stdin secret loader. Metal starts a short-lived
host-network resolver container to read the runtime secret. It writes to a
private FIFO under host `/run`; the long-running Dex container reads that FIFO
through stdin on a bridge network. The resolver never prints secret bytes. The
Dex container never uses host networking and cannot reach instance metadata
(EC2 metadata hop limit is 1). Secret values do not appear in user data,
Terraform state, image layers, arguments, or logs.

The runtime secret is a JSON object with `db_password`, `atproto_client_key`,
`atproto_state_encryption_key_base64` (32 decoded bytes), and `roster_yaml`.
The stack creates the Secrets Manager secret metadata only. Operators populate
its value after creating a least-privilege PostgreSQL role in RDS.
