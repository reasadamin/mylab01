#!/usr/bin/env bash
#
# Deliberately trip each ZT rule against the running workload to prove the
# runtime CDM layer detects baseline violations. This is your demo / evidence
# script - run it while tailing Falco in another terminal:
#
#   kubectl logs -n falco -l app.kubernetes.io/name=falco -c falco -f
#
# Each step below SHOULD produce a matching "ZT violation" alert.
set -uo pipefail

NS="${APP_NAMESPACE:-pep-test}"
SELECTOR="${APP_SELECTOR:-app=ai-embedding-app}"

POD="$(kubectl get pod -n "${NS}" -l "${SELECTOR}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)"
if [[ -z "${POD}" ]]; then
  echo "No pod found in ns=${NS} matching ${SELECTOR}. Is the app deployed?"
  exit 1
fi
echo "Target pod: ${NS}/${POD}"
echo

echo "==> [1] Shell spawn        (expect rule: ZT Embedding App Shell Spawned)"
kubectl exec -n "${NS}" "${POD}" -- sh -c 'echo zt-test' || true
echo

echo "==> [2] Unexpected process (expect rule: ZT Embedding App Unexpected Process)"
kubectl exec -n "${NS}" "${POD}" -- cat /etc/hostname || true
echo

echo "==> [3] Sensitive file     (expect rule: ZT Embedding App Sensitive File Access)"
kubectl exec -n "${NS}" "${POD}" -- cat /var/run/secrets/kubernetes.io/serviceaccount/token || true
echo

echo "==> [4] Outbound network   (expect rule: ZT Embedding App Outbound Connection)"
kubectl exec -n "${NS}" "${POD}" -- python -c \
  "import socket; socket.setdefaulttimeout(3); socket.create_connection(('1.1.1.1',53))" || true
echo

echo "Done. Check the Falco logs / Falcosidekick UI for the four alerts above."