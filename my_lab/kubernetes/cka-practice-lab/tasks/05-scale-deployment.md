# Task 05 — Workloads — Scale a Deployment

> **CKA domain:** Workloads & Scheduling · 15% of the exam  
> **Lab:** minikube (multi-node), Kubernetes v1.26.1

## Objective

Scale the `presentation` deployment to 3 replicas.

## Session — original output

```console
shamrat@shamrat-k8s:~$ k create deployment presentation --image=nginx
deployment.apps/presentation created
shamrat@shamrat-k8s:~$ k get deployment
NAME           READY   UP-TO-DATE   AVAILABLE   AGE
presentation   1/1     1            1           3m6s
shamrat@shamrat-k8s:~$ k scale deployment presentation --replicas=3
deployment.apps/presentation scaled
shamrat@shamrat-k8s:~$ k get deployment
NAME           READY   UP-TO-DATE   AVAILABLE   AGE
presentation   3/3     3            3           3m57s
```

## Notes

`kubectl scale` is imperative and instant — the highest-value answer when the task is purely a replica count. Verify with `kubectl get deployment`.

---

[← Back to all tasks](../README.md#tasks)
