#!/bin/bash
set -e

export KUBECONFIG=/home/shamrat/.kube/config

echo "Checking Kubernetes connection..."
kubectl config current-context
kubectl get nodes

IMAGE_DIGEST=$(cat "$LOCAL_OUTPUT_DIR/image-digest.txt")

echo "Deploying image:"
echo "$IMAGE_DIGEST"

kubectl apply -f k8s/namespace.yaml

kubectl create secret docker-registry gitlab-regcred \
  --namespace pep-test \
  --docker-server="$CI_REGISTRY" \
  --docker-username="$CI_REGISTRY_USER" \
  --docker-password="$CI_REGISTRY_PASSWORD" \
  --docker-email="gitlab@example.com" \
  --dry-run=client -o yaml | kubectl apply -f -

sed "s|IMAGE_PLACEHOLDER|$IMAGE_DIGEST|g" k8s/deployment.yaml | kubectl apply -f -

kubectl apply -f k8s/service.yaml

kubectl rollout status deployment/clean-signed-app -n pep-test

kubectl get pods -n pep-test
kubectl get svc -n pep-test