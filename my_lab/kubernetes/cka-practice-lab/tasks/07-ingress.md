# Task 07 — Services & Networking — Ingress resource

> **CKA domain:** Services & Networking · 20% of the exam  
> **Lab:** minikube (multi-node), Kubernetes v1.26.1

## Objective

Create an Ingress `ping` in namespace `ing-internal` that routes path `/hi` to service `hi` on port 5678.

## Manifests

- [`manifests/ingress.yaml`](../manifests/ingress.yaml)

## Session — original output

```console
shamrat@shamrat-k8s:~$ cat ingress_exam.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
 name: ping
 namespace: ing-internal
spec:
 ingressClassName: nginx-example
 rules:
 - http:
     paths:
     - path: /hi
       pathType: Prefix
       backend:
         service:
           name: hi
           port:
             number: 5678
shamrat@shamrat-k8s:~$ k create -f ingress_exam.yaml
ingress.networking.k8s.io/ping created
```

## Notes

Start from the kubernetes.io Ingress example and edit in place — far faster than writing it from memory. Mind `pathType` and the nested `backend.service.port.number` structure (networking.k8s.io/v1).

---

[← Back to all tasks](../README.md#tasks)
