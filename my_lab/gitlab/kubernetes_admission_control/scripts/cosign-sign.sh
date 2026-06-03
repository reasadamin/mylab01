#!/bin/bash
set -e

IMAGE_DIGEST=$(cat "$LOCAL_OUTPUT_DIR/image-digest.txt")

mkdir -p "$LOCAL_OUTPUT_DIR/cosign"

echo "$CI_REGISTRY_PASSWORD" | docker login "$CI_REGISTRY" \
  -u "$CI_REGISTRY_USER" \
  --password-stdin

printf '%s\n' "$COSIGN_PRIVATE_KEY" > "$LOCAL_OUTPUT_DIR/cosign/cosign.key"
chmod 600 "$LOCAL_OUTPUT_DIR/cosign/cosign.key"

echo "$COSIGN_PASSWORD" | cosign sign \
  --key "$LOCAL_OUTPUT_DIR/cosign/cosign.key" \
  "$IMAGE_DIGEST" \
  --yes

echo "Signed image:"
echo "$IMAGE_DIGEST"