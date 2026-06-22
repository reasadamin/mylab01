#!/usr/bin/env bash
#
# Deploy Falco with the Zero Trust runtime rules into the cluster.
# Falco is a node-level DaemonSet; this is installed once, independently of the
# app's CI/CD pipeline. Re-run any time to apply rule changes (idempotent).
#
# Prereqs: helm, kubectl, a running cluster (Minikube).
set -euo pipefail

NAMESPACE="${FALCO_NAMESPACE:-falco}"
RELEASE="${FALCO_RELEASE:-falco}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> Adding/updating Falco Helm repo"
helm repo add falcosecurity https://falcosecurity.github.io/charts >/dev/null 2>&1 || true
helm repo update falcosecurity >/dev/null

echo "==> Installing/upgrading Falco (release=${RELEASE} ns=${NAMESPACE})"
helm upgrade --install "${RELEASE}" falcosecurity/falco \
  --namespace "${NAMESPACE}" --create-namespace \
  -f "${SCRIPT_DIR}/values.yaml" \
  --set-file "customRules.zt-embedding-app-rules\.yaml=${SCRIPT_DIR}/rules/zt-embedding-app-rules.yaml" \
  --wait --timeout 5m

echo
echo "==> Falco pods"
kubectl get pods -n "${NAMESPACE}" -o wide

cat <<EOF

Done. Useful commands:

  # Tail live Falco events
  kubectl logs -n ${NAMESPACE} -l app.kubernetes.io/name=falco -c falco -f

  # Confirm the custom ZT rules loaded
  kubectl logs -n ${NAMESPACE} -l app.kubernetes.io/name=falco -c falco | grep -i "zt-embedding-app-rules"

  # Open the Falcosidekick web UI (default login: admin / admin)
  kubectl port-forward -n ${NAMESPACE} svc/${RELEASE}-falcosidekick-ui 2802:2802
  #   then browse http://localhost:2802

  # Prove detection works
  ./test/trigger-zt-alerts.sh
EOF