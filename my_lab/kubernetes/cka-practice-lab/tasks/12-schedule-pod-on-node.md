# Task 12 — Scheduling — pin a Pod to a node

> **CKA domain:** Workloads & Scheduling · 15% of the exam  
> **Lab:** minikube (multi-node), Kubernetes v1.26.1

## Objective

Schedule a Pod `nginx-kusc00401` (image nginx) onto a specific node, e.g. via `nodeSelector` (or `nodeName` in this lab).

## Manifests

- [`manifests/pod-nodeselector.yaml`](../manifests/pod-nodeselector.yaml)

## Session — original output

```console
shamrat@shamrat-k8s:~$ k run nginx --image=nginx --dry-run=client -o yaml >schedule_on_node.yaml
shamrat@shamrat-k8s:~$ cat schedule_on_node.yaml
apiVersion: v1
kind: Pod
metadata:
 creationTimestamp: null
 labels:
   run: nginx2
 name: nginx2
spec:
 containers:
 - image: nginx
   name: nginx
#  nodeSelector:
#    disktype: ssd
#    or
#    disktype: spinning
 nodeName: minikube-m02
 dnsPolicy: ClusterFirst
 restartPolicy: Always
status: {}
shamrat@shamrat-k8s:~$ k get pods -o wide
NAME             READY   STATUS    RESTARTS   AGE     IP            NODE           NOMINATED NODE   READINESS GATES
cpu-loader-pod   1/1     Running   0          111m    10.244.2.12   minikube-m03   <none>           <none>
kucc8            2/2     Running   0          32m     10.244.2.15   minikube-m03   <none>           <none>
ngin             1/1     Running   0          119m    10.244.2.9    minikube-m03   <none>           <none>
nginx            1/1     Running   0          2m58s   10.244.1.12   minikube-m02   <none>           <none>
nginx2           1/1     Running   0          43s     10.244.1.13   minikube-m02   <none>           <none>
```

## Notes

`nodeSelector` matches a node label and is the exam-intended answer; `nodeName` is a blunter pin used here to demonstrate placement. Verify with `kubectl get pods -o wide` and check the NODE column.

---

[← Back to all tasks](../README.md#tasks)
