# Task 10 — Workloads — multi-container Pod

> **CKA domain:** Workloads & Scheduling · 15% of the exam  
> **Lab:** minikube (multi-node), Kubernetes v1.26.1

## Objective

Create a single Pod `kucc8` running both an nginx and a redis container.

## Manifests

- [`manifests/multi-container-pod.yaml`](../manifests/multi-container-pod.yaml)

## Session — original output

```console
shamrat@shamrat-k8s:~$ k run kucc8 --image=nginx --dry-run=client -o yaml > kucc8.yaml
shamrat@shamrat-k8s:~$ cat kucc8.yaml
apiVersion: v1
kind: Pod
metadata:
 creationTimestamp: null
 name: kucc8
spec:
 containers:
 - image: nginx
   name: nginx
 - image: redis
   name: redis
   resources: {}
 dnsPolicy: ClusterFirst
 restartPolicy: Always
status: {}
shamrat@shamrat-k8s:~$ k create -f kucc8.yaml
pod/kucc8 created
shamrat@shamrat-k8s:~$ k get pods --watch
NAME             READY   STATUS              RESTARTS   AGE
cpu-loader-pod   1/1     Running             0          78m
kucc8            0/2     ContainerCreating   0          3s
ngin             1/1     Running             0          86m
kucc8            2/2     Running
shamrat@shamrat-k8s:~$  k get pods
NAME             READY   STATUS    RESTARTS   AGE
cpu-loader-pod   1/1     Running   0          79m
kucc8            2/2     Running   0          23s
ngin             1/1     Running   0          87m
```

## Notes

Generate the base with `kubectl run --dry-run=client -o yaml`, then add the second container by hand. Far less error-prone than writing the whole manifest from scratch.

---

[← Back to all tasks](../README.md#tasks)
