#!/bin/bash
set -e

IMAGE_DIGEST=$(cat "$LOCAL_OUTPUT_DIR/image-digest.txt")

mkdir -p "$LOCAL_OUTPUT_DIR/trivy"

echo "$CI_REGISTRY_PASSWORD" | docker login "$CI_REGISTRY" \
  -u "$CI_REGISTRY_USER" \
  --password-stdin

trivy image \
  --skip-db-update \
  --scanners vuln \
  --severity HIGH,CRITICAL \
  --exit-code 1 \
  --no-progress \
  --format table \
  --output "$LOCAL_OUTPUT_DIR/trivy/trivy-report.txt" \
  "$IMAGE_DIGEST"

cat "$LOCAL_OUTPUT_DIR/trivy/trivy-report.txt"