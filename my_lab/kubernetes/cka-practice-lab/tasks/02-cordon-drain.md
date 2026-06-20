# Task 02 — Node maintenance — Cordon & Drain

> **CKA domain:** Cluster Architecture, Installation & Configuration · 25% of the exam  
> **Lab:** minikube (multi-node), Kubernetes v1.26.1

## Objective

Mark a node as unschedulable and safely evict its pods onto another node, simulating taking a node out for maintenance.

## Session — original output

```console
shamrat@shamrat-k8s:~$ k get nodes
NAME       STATUS   ROLES           AGE   VERSION
minikube   Ready    control-plane   26d   v1.26.1
shamrat@shamrat-k8s:~$ minikube node add
shamrat@shamrat-k8s:~$ k get nodes
NAME           STATUS   ROLES           AGE     VERSION
minikube       Ready    control-plane   26d     v1.26.1
minikube-m02   Ready    <none>          7m44s   v1.26.1
shamrat@shamrat-k8s:~$ k run nginx-pod --image=nginx
pod/nginx-pod created
shamrat@shamrat-k8s:~$ k get pods --watch
NAME        READY   STATUS    RESTARTS   AGE
nginx-pod   1/1     Running   0          20s
shamrat@shamrat-k8s:~$ k get pods -o wide
NAME        READY   STATUS    RESTARTS   AGE   IP           NODE           NOMINATED NODE   READINESS GATES
nginx-pod   1/1     Running   0          34s   10.244.1.2   minikube-m02   <none>           <none>
Now Drain & Cordon:
shamrat@shamrat-k8s:~$  k get nodes
NAME           STATUS   ROLES           AGE     VERSION
minikube       Ready    control-plane   26d     v1.26.1
minikube-m02   Ready    <none>          9m15s   v1.26.1
shamrat@shamrat-k8s:~$ k cordon minikube-m02
node/minikube-m02 cordoned
shamrat@shamrat-k8s:~$ k get node minikube-m02
NAME           STATUS                     ROLES    AGE     VERSION
minikube-m02   Ready,SchedulingDisabled   <none>   9m38s   v1.26.1
--
shamrat@shamrat-k8s:~$  k get nodes
NAME           STATUS   ROLES           AGE     VERSION
minikube       Ready    control-plane   26d     v1.26.1
minikube-m02   Ready    <none>          9m15s   v1.26.1
shamrat@shamrat-k8s:~$ k cordon minikube-m02
node/minikube-m02 cordoned
shamrat@shamrat-k8s:~$ k get nodes
NAME           STATUS                     ROLES           AGE   VERSION
minikube       Ready                      control-plane   26d   v1.26.1
minikube-m02   Ready,SchedulingDisabled   <none>          10m   v1.26.1
shamrat@shamrat-k8s:~$ k get pod -o wide
NAME        READY   STATUS    RESTARTS   AGE    IP           NODE           NOMINATED NODE   READINESS GATES
nginx-pod   1/1     Running   0          7m7s   10.244.1.2   minikube-m02   <none>           <none>
shamrat@shamrat-k8s:~$ k drain minikube-m02
node/minikube-m02 already cordoned
error: unable to drain node "minikube-m02" due to error:[cannot delete Pods declare no controller (use --force to override): default/nginx-pod, cannot delete DaemonSet-managed Pods (use --ignore-daemonsets to ignore): kube-system/kindnet-zv2mc, kube-system/kube-proxy-h8qwz], continuing command...
There are pending nodes to be drained:
minikube-m02
cannot delete Pods declare no controller (use --force to override): default/nginx-pod
cannot delete DaemonSet-managed Pods (use --ignore-daemonsets to ignore): kube-system/kindnet-zv2mc, kube-system/kube-proxy-h8qwz
shamrat@shamrat-k8s:~$ k drain minikube-m02 --delete-local-data --ignore-daemonsets --force
Flag --delete-local-data has been deprecated, This option is deprecated and will be deleted. Use --delete-emptydir-data.
node/minikube-m02 already cordoned
Warning: deleting Pods that declare no controller: default/nginx-pod; ignoring DaemonSet-managed Pods: kube-system/kindnet-zv2mc, kube-system/kube-proxy-h8qwz
evicting pod default/nginx-pod
pod/nginx-pod evicted
node/minikube-m02 drained
```

## Notes

`cordon` only stops *new* scheduling; `drain` is what actually evicts running pods. Bare pods with no controller need `--force`, and DaemonSet pods need `--ignore-daemonsets`. Note `--delete-local-data` is deprecated in favour of `--delete-emptydir-data`.

---

[← Back to all tasks](../README.md#tasks)
