#!/usr/bin/env bash
set -euo pipefail

[[ "$CI_PROJECT_PATH" == cyberdione/dex ]]
[[ "$CI_COMMIT_BRANCH" == main ]]
[[ "$CI_COMMIT_REF_PROTECTED" == true ]]
[[ "$CI_COMMIT_SHA" =~ ^[0-9a-f]{40}$ ]]

for key in TF_BOOTC_BUILD_ROLE_ARN BOOTC_BUILDER_SUBNET_ID BOOTC_BUILDER_SG_ID \
  BOOTC_BUILDER_BUCKET BOOTC_BUILDER_INSTANCE_PROFILE; do
  [[ -n "${!key:-}" ]] || { echo "missing $key" >&2; exit 1; }
done

digest="$(cat identity-bootc-arm64.digest)"
[[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]
image_ref="$CI_REGISTRY_IMAGE/identity-bootc-os@$digest"
[[ "$image_ref" =~ ^registry\.gitlab\.com/cyberdione/dex/identity-bootc-os@sha256:[0-9a-f]{64}$ ]]
ami_name="cyberdione-identity-bootc-os-arm64-${CI_PIPELINE_ID}"

umask 077
printf '%s' "$GITLAB_OIDC_TOKEN" > "$CI_PROJECT_DIR/.ami-oidc-token"
export AWS_WEB_IDENTITY_TOKEN_FILE="$CI_PROJECT_DIR/.ami-oidc-token"
export AWS_ROLE_ARN="$TF_BOOTC_BUILD_ROLE_ARN"
export AWS_DEFAULT_REGION=us-east-1
[[ "$(aws sts get-caller-identity --query Account --output text)" == 473231598202 ]]

my_ip="$(curl -fsS https://checkip.amazonaws.com)"
[[ "$my_ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]
printf 'export MY_IP=%q\n' "$my_ip" >> "$CI_PROJECT_DIR/.ami-build.env"
aws ec2 authorize-security-group-ingress --group-id "$BOOTC_BUILDER_SG_ID" \
  --protocol tcp --port 22 --cidr "${my_ip}/32" >/dev/null

key_name="identity-ami-builder-${CI_JOB_ID}"
ssh-keygen -t ed25519 -N '' -f "$CI_PROJECT_DIR/.builder-key" -q
aws ec2 import-key-pair --key-name "$key_name" \
  --public-key-material "fileb://$CI_PROJECT_DIR/.builder-key.pub" >/dev/null
printf 'export KEY_NAME=%q\n' "$key_name" >> "$CI_PROJECT_DIR/.ami-build.env"

base_ami="$(aws ec2 describe-images --owners 666468248896 \
  --filters 'Name=name,Values=cyberdione-rocky10-podman-base-arm64-*' 'Name=state,Values=available' \
  --query 'sort_by(Images,&CreationDate)[-1].ImageId' --output text)"
[[ "$base_ami" =~ ^ami-[0-9a-f]+$ ]]
instance_id="$(aws ec2 run-instances \
  --image-id "$base_ami" --instance-type t4g.large \
  --key-name "$key_name" --subnet-id "$BOOTC_BUILDER_SUBNET_ID" \
  --security-group-ids "$BOOTC_BUILDER_SG_ID" \
  --iam-instance-profile "Name=$BOOTC_BUILDER_INSTANCE_PROFILE" \
  --associate-public-ip-address \
  --block-device-mappings 'DeviceName=/dev/sda1,Ebs={VolumeSize=60,VolumeType=gp3,DeleteOnTermination=true}' \
  --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=identity-ami-builder-${CI_PIPELINE_ID}}]" \
  --query 'Instances[0].InstanceId' --output text)"
[[ "$instance_id" =~ ^i-[0-9a-f]+$ ]]
printf 'export INSTANCE_ID=%q\n' "$instance_id" >> "$CI_PROJECT_DIR/.ami-build.env"
aws ec2 wait instance-running --instance-ids "$instance_id"
builder_ip="$(aws ec2 describe-instances --instance-ids "$instance_id" \
  --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)"
[[ "$builder_ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]

ssh_opts=(-o StrictHostKeyChecking=no -o ConnectTimeout=5 -i "$CI_PROJECT_DIR/.builder-key")
for attempt in $(seq 1 30); do
  if ssh "${ssh_opts[@]}" "rocky@${builder_ip}" true 2>/dev/null; then break; fi
  if (( attempt == 30 )); then echo 'builder SSH did not become ready' >&2; exit 1; fi
  sleep 10
done

printf '%s' "$CI_JOB_TOKEN" > "$CI_PROJECT_DIR/.identity-registry-token"
scp "${ssh_opts[@]}" ci/remote-build-private-ami.sh \
  ci/Containerfile.bootc-image-builder-fixed "$CI_PROJECT_DIR/.identity-registry-token" \
  "rocky@${builder_ip}:/home/rocky/"
ssh "${ssh_opts[@]}" "rocky@${builder_ip}" \
  "sudo bash /home/rocky/remote-build-private-ami.sh '$image_ref' '$BOOTC_BUILDER_BUCKET' '$ami_name'" \
  2>&1 | tee "$CI_PROJECT_DIR/.identity-ami-build.log"

ami_id="$(sed -nE 's/.*AMI registered: (ami-[0-9a-f]+).*/\1/p' \
  "$CI_PROJECT_DIR/.identity-ami-build.log" | tail -1)"
[[ "$ami_id" =~ ^ami-[0-9a-f]+$ ]] || { echo 'builder did not register an AMI' >&2; exit 1; }
if grep -Eq 'Regex version mismatch|Could not set context for .* Invalid argument|org\.osbuild\.selinux.*Traceback|manifest - failed' \
  "$CI_PROJECT_DIR/.identity-ami-build.log"; then
  echo 'builder reported a SELinux image conversion failure' >&2
  exit 1
fi
aws ec2 wait image-available --image-ids "$ami_id"
ami_state="$(aws ec2 describe-images --image-ids "$ami_id" \
  --query 'Images[0].State' --output text)"
[[ "$ami_state" == available ]]

# This path is intentionally account-private. Never add Group=all here.
aws ec2 modify-image-attribute --image-id "$ami_id" \
  --launch-permission 'Add=[{UserId=666468248896}]'
for snapshot_id in $(aws ec2 describe-images --image-ids "$ami_id" \
  --query 'Images[0].BlockDeviceMappings[].Ebs.SnapshotId' --output text); do
  aws ec2 modify-snapshot-attribute --snapshot-id "$snapshot_id" \
    --attribute createVolumePermission --operation-type add --user-ids 666468248896
done
launch_permissions="$(aws ec2 describe-image-attribute --image-id "$ami_id" \
  --attribute launchPermission --query 'LaunchPermissions' --output json)"
printf '%s' "$launch_permissions" | jq -e 'any(.[]; .UserId == "666468248896") and all(.[]; .Group != "all")' >/dev/null
printf '%s\n' "$ami_id" > identity-ami-id.txt
echo "Private identity AMI: $ami_id ($ami_name, source $image_ref)"
