#!/usr/bin/env bash
#
# Scan stage: scan the built image for HIGH/CRITICAL vulnerabilities with Trivy.
# Advisory by default (does not fail the pipeline). Add --exit-code 1 to enforce.
set -euo pipefail

IMAGE_DIGEST=$(cat "${LOCAL_OUTPUT_DIR}/image-digest.txt")
mkdir -p "${LOCAL_OUTPUT_DIR}/trivy"

echo "${CI_REGISTRY_PASSWORD}" | docker login "${CI_REGISTRY}" \
  --username "${CI_REGISTRY_USER}" --password-stdin

# --skip-db-update reuses the cached Trivy DB on the runner for speed.
trivy image \
  --scanners vuln \
  --severity HIGH,CRITICAL \
  --skip-db-update \
  --no-progress \
  --format table \
  --output "${LOCAL_OUTPUT_DIR}/trivy/trivy-report.txt" \
  "${IMAGE_DIGEST}"

cat "${LOCAL_OUTPUT_DIR}/trivy/trivy-report.txt"