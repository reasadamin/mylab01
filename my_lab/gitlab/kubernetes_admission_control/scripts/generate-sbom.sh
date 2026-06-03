#!/bin/bash
set -e

IMAGE_DIGEST=$(cat "$LOCAL_OUTPUT_DIR/image-digest.txt")

mkdir -p "$LOCAL_OUTPUT_DIR/sbom"

syft "$IMAGE_DIGEST" -o spdx-json > "$LOCAL_OUTPUT_DIR/sbom/sbom.spdx.json"
syft "$IMAGE_DIGEST" -o cyclonedx-json > "$LOCAL_OUTPUT_DIR/sbom/sbom.cdx.json"

echo "SBOM files saved in:"
echo "$LOCAL_OUTPUT_DIR/sbom"