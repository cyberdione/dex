#!/usr/bin/env bash
set -euo pipefail

image_ref="${1:?image digest reference required}"
bucket="${2:?builder bucket required}"
ami_name="${3:?AMI name required}"
[[ "$image_ref" =~ ^registry\.gitlab\.com/cyberdione/dex/identity-bootc-os@sha256:[0-9a-f]{64}$ ]]
[[ "$bucket" =~ ^[a-z0-9.-]+$ ]]
[[ "$ami_name" =~ ^cyberdione-identity-bootc-os-arm64-[0-9]+$ ]]

auth=/run/identity-ami-registry-auth.json
cleanup() {
  podman logout --authfile "$auth" registry.gitlab.com >/dev/null 2>&1 || true
  rm -f "$auth" /home/rocky/.identity-registry-token
}
trap cleanup EXIT

chmod 0600 /home/rocky/.identity-registry-token
podman login --authfile "$auth" --username gitlab-ci-token --password-stdin \
  registry.gitlab.com < /home/rocky/.identity-registry-token
rm -f /home/rocky/.identity-registry-token

# bootc-image-builder inspects the host's rootful Podman storage. Keep the
# target image there and use the exact same digest in the builder tool layer.
podman pull --authfile "$auth" "$image_ref"
podman build --authfile "$auth" --build-arg "FERRULEOS_REF=$image_ref" \
  -t localhost/identity-bootc-image-builder-fixed \
  -f /home/rocky/Containerfile.bootc-image-builder-fixed /home/rocky

cat > /tmp/identity-ami-config.toml <<'EOF'
[customizations.ignition.firstboot]
empty = true

[customizations.kernel]
append = "ignition.platform.id=aws ignition.firstboot rd.neednet=1 ip=dhcp"
EOF

podman run --rm --privileged \
  -v /dev:/dev \
  -v /tmp/identity-ami-config.toml:/config.toml:ro \
  -v /var/lib/containers/storage:/var/lib/containers/storage \
  --security-opt label=disable \
  localhost/identity-bootc-image-builder-fixed \
  build "$image_ref" \
  --type ami \
  --rootfs ext4 \
  --aws-ami-name "$ami_name" \
  --aws-region us-east-1 \
  --aws-bucket "$bucket"
