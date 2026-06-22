#!/usr/bin/env bash
#
# Remove Falco and its namespace.
set -euo pipefail

NAMESPACE="${FALCO_NAMESPACE:-falco}"
RELEASE="${FALCO_RELEASE:-falco}"

helm uninstall "${RELEASE}" -n "${NAMESPACE}" || true
kubectl delete namespace "${NAMESPACE}" --ignore-not-found
echo "Falco removed."