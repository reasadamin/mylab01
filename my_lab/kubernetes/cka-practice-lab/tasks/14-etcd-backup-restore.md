# Task 14 — Cluster Maintenance — etcd backup & restore

> **CKA domain:** Cluster Architecture, Installation & Configuration · 25% of the exam  
> **Lab:** minikube (multi-node), Kubernetes v1.26.1

## Objective

Take an etcd snapshot using the cluster's certs, verify it, and restore from a snapshot file.

## Session — original output

```console
controlplane ~ ➜  k describe pod etcd-controlplane -n kube-system | grep "\--cert-file"
     --cert-file=/etc/kubernetes/pki/etcd/server.crt
controlplane ~ ➜  k describe pod etcd-controlplane -n kube-system | grep "\--trusted-ca-file"
     --trusted-ca-file=/etc/kubernetes/pki/etcd/ca.crt
etcd version:
controlplane ~ ➜  k describe pod etcd-controlplane -n kube-system | grep -i "image:"
   Image:         registry.k8s.io/etcd:3.5.7-0
--cacert=/etc/kubernetes/pki/etcd/ca.crt \
--cert=/etc/kubernetes/pki/etcd/server.crt \
--key=/etc/kubernetes/pki/etcd/server.key \
controlplane ~ ➜  export ETCDCTL_API=3
controlplane ~ ➜  etcdctl --endpoints=https://127.0.0.1:2379 --cacert=/etc/kubernetes/pki/etcd/ca.crt --cert=/etc/kubernetes/pki/etcd/server.crt  --key=/etc/kubernetes/pki/etcd/server.key  snapshot save /opt/snapshot-pre-boot.db
Snapshot saved at /opt/snapshot-pre-boot.db
controlplane ~ ➜  etcdctl --endpoints=https://127.0.0.1:2379 --cacert=/etc/kubernetes/pki/etcd/ca.crt --cert=/etc/kubernetes/pki/etcd/server.crt --key=/etc/kubernetes/pki/etcd/server.key snapshot status /opt/snapshot-pre-boot.db
c8137dcf, 1917, 987, 2.2 MB
controlplane ~ ➜ etcdctl snapshot restore /svr/data/etcd-snapshot-previous.db
controlplane ~ ➜ sudo systemctl restart etcd.service
```

## Notes

Pull the cert/key/CA paths from the etcd static-pod spec, set `ETCDCTL_API=3`, then `snapshot save` / `snapshot status` / `snapshot restore`. On a real restore you also repoint `--data-dir` in the etcd manifest at the restored directory.

---

[← Back to all tasks](../README.md#tasks)
