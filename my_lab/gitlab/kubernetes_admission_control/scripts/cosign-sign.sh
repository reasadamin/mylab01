#!/usr/bin/env bash
#
# Sign stage: sign the image digest with Cosign and attach the SBOM as a signed
# attestation. Both use the same env:// key - nothing is written to disk.
# cosign reads the key passphrase from $COSIGN_PASSWORD itself.
set -euo pipefail

IMAGE_DIGEST=$(cat "${LOCAL_OUTPUT_DIR}/image-digest.txt")
SBOM_FILE="${LOCAL_OUTPUT_DIR}/sbom/sbom.spdx.json"

echo "${CI_REGISTRY_PASSWORD}" | docker login "${CI_REGISTRY}" \
  --username "${CI_REGISTRY_USER}" --password-stdin

# Sign the image.
cosign sign --yes --key env://COSIGN_PRIVATE_KEY "${IMAGE_DIGEST}"

# Attest the SBOM to the same image.
cosign attest --yes \
  --key env://COSIGN_PRIVATE_KEY \
  --type spdxjson \
  --predicate "${SBOM_FILE}" \
  "${IMAGE_DIGEST}"

echo "Signed and attested: ${IMAGE_DIGEST}"