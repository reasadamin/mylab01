#!/usr/bin/env bash
#
# Check stage: confirm the deployed app is reachable and healthy via its NodePort.
# --fail makes curl exit non-zero on an HTTP error, so the job fails if unhealthy.
set -euo pipefail

export KUBECONFIG="${KUBECONFIG:-/home/shamrat/.kube/config}"

APP_URL="http://$(minikube ip):30221/health"

echo "Checking ${APP_URL}"
curl --fail --silent --show-error "${APP_URL}"
echo ""
echo "App is healthy."