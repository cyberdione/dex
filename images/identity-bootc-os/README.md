# Cyberdione identity bootc host

This image layers the stable Dex host service, Caddy Quadlet, and public
firewalld zone over the generic FerruleOS bootc image. It contains no runtime
secret values. Protected GitLab CI publishes commit-SHA tags only to this
private project's container registry. The FerruleOS image builder converts
the pinned arm64 image digest into a private AMI shared only with the
production account. Ignition supplies
`/etc/dex/deploy.env` and `/etc/dex/config.yaml` for the specific instance; the
runtime secret itself is retrieved from Secrets Manager at service start.

The image is intentionally specific to `login.federate.to`. Keep both the OCI
image and any derived AMI private.
