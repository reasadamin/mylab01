# Task 06 — Services & Networking — NetworkPolicy (intra-namespace, port-scoped)

> **CKA domain:** Services & Networking · 20% of the exam  
> **Lab:** minikube (multi-node), Kubernetes v1.26.1

## Objective

Create a `NetworkPolicy` `allow-port-from-namespace` so pods in the `internal` namespace can reach port 8080 of other pods **in the same namespace** — and nothing from outside it, and nothing on other ports.

## Manifests

- [`manifests/network-policy.yaml`](../manifests/network-policy.yaml)

## Session — original output

```console
shamrat@shamrat-k8s:~/k8s_playbooks$ cat network_policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
 name: allow-port-from-namespace
 namespace: internal
spec:
 podSelector: {}
 policyTypes:
   - Ingress
 ingress:
   - from:
       - podSelector: {}
     ports:
       - port: 8080
shamrat@shamrat-k8s:~/k8s_playbooks$ k get networkpolicy -n internal
NAME                        POD-SELECTOR   AGE
allow-port-from-namespace   <none>         110s
shamrat@shamrat-k8s:~/k8s_playbooks$ k describe networkpolicy -n internal
Name:         allow-port-from-namespace
Namespace:    internal
Created on:   2023-12-28 16:35:22 +0600 +06
Labels:       <none>
Annotations:  <none>
Spec:
 PodSelector:     <none> (Allowing the specific traffic to all pods in this namespace)
 Allowing ingress traffic:
   To Port: 8080/TCP
   From:
     PodSelector: <none>
 Not affecting egress traffic
 Policy Types: Ingress
```

## Notes

An empty `podSelector: {}` under `from` means *all pods in this namespace*. Because there is no `namespaceSelector`, traffic from other namespaces is implicitly denied. Scoping the `ports` entry to 8080 satisfies the 'no other ports' requirement.

---

[← Back to all tasks](../README.md#tasks)
