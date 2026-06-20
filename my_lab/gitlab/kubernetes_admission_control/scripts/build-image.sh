#!/usr/bin/env bash
#
# Build stage: build the app image, push it, and save its immutable digest.
# Downstream stages pin to this digest, not the mutable tag.
set -euo pipefail

mkdir -p "${LOCAL_OUTPUT_DIR}"

echo "${CI_REGISTRY_PASSWORD}" | docker login "${CI_REGISTRY}" \
  --username "${CI_REGISTRY_USER}" --password-stdin

docker build --pull --tag "${IMAGE_TAG}" .
docker push "${IMAGE_TAG}"

# Record the digest of the image we just pushed.
IMAGE_DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' "${IMAGE_TAG}")
echo "${IMAGE_DIGEST}" > "${LOCAL_OUTPUT_DIR}/image-digest.txt"

echo "Image digest saved: ${IMAGE_DIGEST}"