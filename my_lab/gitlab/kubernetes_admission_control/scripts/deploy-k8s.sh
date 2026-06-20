#!/usr/bin/env bash
#
# Deploy stage: apply the manifests, pinning in the signed image digest.
# Kyverno's signature policy gates admission (installed once, separately).
set -euo pipefail
 
export KUBECONFIG="${KUBECONFIG:-/home/shamrat/.kube/config}"
 
IMAGE_DIGEST=$(cat "${LOCAL_OUTPUT_DIR}/image-digest.txt")
 
kubectl apply -f k8s/namespace.yaml
 
# Registry pull secret, created from CI variables (idempotent).
kubectl create secret docker-registry gitlab-regcred \
  --namespace pep-test \
  --docker-server="${CI_REGISTRY}" \
  --docker-username="${CI_REGISTRY_USER}" \
  --docker-password="${CI_REGISTRY_PASSWORD}" \
  --dry-run=client -o yaml | kubectl apply -f -
 
kubectl apply -f k8s/service.yaml
sed "s|IMAGE_PLACEHOLDER|${IMAGE_DIGEST}|g" k8s/deployment.yaml | kubectl apply -f -
 
kubectl rollout status deployment/ai-embedding-app -n pep-test
 
