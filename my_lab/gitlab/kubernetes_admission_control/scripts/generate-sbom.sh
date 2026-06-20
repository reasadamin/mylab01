#!/usr/bin/env bash
#
# SBOM stage: generate a Software Bill of Materials for the built image with Syft,
# in both SPDX and CycloneDX JSON. These list every OS and Python package shipped.
set -euo pipefail

IMAGE_DIGEST=$(cat "${LOCAL_OUTPUT_DIR}/image-digest.txt")
SBOM_DIR="${LOCAL_OUTPUT_DIR}/sbom"
mkdir -p "${SBOM_DIR}"

# One scan, both formats written straight to disk.
syft "${IMAGE_DIGEST}" \
  -o "spdx-json=${SBOM_DIR}/sbom.spdx.json" \
  -o "cyclonedx-json=${SBOM_DIR}/sbom.cdx.json"

echo "SBOM files written to ${SBOM_DIR}"