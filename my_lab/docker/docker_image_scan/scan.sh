#!/bin/bash

IMAGE_NAME="trivy-demo"

echo "[*] Building Docker image: $IMAGE_NAME"
docker build -t $IMAGE_NAME .

echo "[*] Running Trivy scan..."
trivy image $IMAGE_NAME
