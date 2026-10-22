#!/usr/bin/env bash
set -uo pipefail

export AWS_DEFAULT_REGION=us-east-1
export AWS_ROLE_ARN="${TF_BOOTC_BUILD_ROLE_ARN:-}"
export AWS_WEB_IDENTITY_TOKEN_FILE="$CI_PROJECT_DIR/.ami-oidc-token"
if [[ -f "$CI_PROJECT_DIR/.ami-build.env" ]]; then
  # Values in this file are generated only from AWS IDs and a validated
  # checkip.amazonaws.com IPv4 address by build-private-ami.sh.
  source "$CI_PROJECT_DIR/.ami-build.env"
fi

if [[ -n "${INSTANCE_ID:-}" ]]; then
  aws ec2 terminate-instances --instance-ids "$INSTANCE_ID" >/dev/null || true
fi
if [[ -n "${KEY_NAME:-}" ]]; then
  aws ec2 delete-key-pair --key-name "$KEY_NAME" >/dev/null || true
fi
if [[ -n "${MY_IP:-}" && -n "${BOOTC_BUILDER_SG_ID:-}" ]]; then
  aws ec2 revoke-security-group-ingress --group-id "$BOOTC_BUILDER_SG_ID" \
    --protocol tcp --port 22 --cidr "${MY_IP}/32" >/dev/null || true
fi
rm -f "$CI_PROJECT_DIR/.ami-oidc-token" "$CI_PROJECT_DIR/.identity-registry-token" \
  "$CI_PROJECT_DIR/.builder-key" "$CI_PROJECT_DIR/.builder-key.pub"
