# Task 11 — Cluster Architecture — count Ready (non-tainted) nodes

> **CKA domain:** Cluster Architecture, Installation & Configuration · 25% of the exam  
> **Lab:** minikube (multi-node), Kubernetes v1.26.1

## Objective

Count the nodes that are `Ready` and **not** tainted `NoSchedule`, and write the number to a file.

## Session — original output

```console
shamrat@shamrat-k8s:~$ k get nodes --no-headers| grep -ie ready
minikube       Ready   control-plane   33d    v1.26.1
minikube-m02   Ready   <none>          6d1h   v1.26.1
minikube-m03   Ready   <none>          6d1h   v1.26.1
shamrat@shamrat-k8s:~$ k get nodes --no-headers| grep -ie ready | wc -l
or, simpley
shamrat@shamrat-k8s:~$ k get nodes -o wide
NAME           STATUS   ROLES           AGE    VERSION   INTERNAL-IP      EXTERNAL-IP   OS-IMAGE               KERNEL-VERSION   CONTAINER-RUNTIME
minikube       Ready    control-plane   33d    v1.26.1   192.168.59.105   <none>        Buildroot 2021.02.12   5.10.57          docker://20.10.23
minikube-m02   Ready    <none>          6d1h   v1.26.1   192.168.59.108   <none>        Buildroot 2021.02.12   5.10.57          docker://20.10.23
minikube-m03   Ready    <none>          6d1h   v1.26.1   192.168.59.107   <none>        Buildroot 2021.02.12   5.10.57          docker://20.10.23
shamrat@shamrat-k8s:~$ #echo "2" > /mentioned/location
```

## Notes

Two-step approach: `kubectl get nodes` filtered for Ready, then for each candidate check `kubectl describe node <n> | grep Taint` for `NoSchedule`. Subtract the tainted ones before writing the count.

---

[← Back to all tasks](../README.md#tasks)
