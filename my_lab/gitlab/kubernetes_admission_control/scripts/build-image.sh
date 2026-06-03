#!/bin/bash
set -e

mkdir -p "$LOCAL_OUTPUT_DIR"

echo "$CI_REGISTRY_PASSWORD" | docker login "$CI_REGISTRY" \
  -u "$CI_REGISTRY_USER" \
  --password-stdin

docker build --pull -t "$IMAGE_TAG" .

docker push "$IMAGE_TAG"

IMAGE_DIGEST=$(docker inspect \
  --format='{{index .RepoDigests 0}}' \
  "$IMAGE_TAG")

echo "$IMAGE_DIGEST" > "$LOCAL_OUTPUT_DIR/image-digest.txt"

echo "Image digest saved:"
cat "$LOCAL_OUTPUT_DIR/image-digest.txt"