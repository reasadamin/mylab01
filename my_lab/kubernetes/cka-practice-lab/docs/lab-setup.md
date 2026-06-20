# Lab setup

How the local cluster used for these tasks was built and configured.

## Cluster

A multi-node minikube cluster was used so that scheduling, draining, and
node-placement tasks behave realistically.

```bash
# Single control-plane to start
minikube start --kubernetes-version v1.26.1

# Add worker nodes as needed
minikube node add        # -> minikube-m02
minikube node add        # -> minikube-m03

kubectl get nodes -o wide
```

Resulting topology during the session:

```console
NAME           STATUS   ROLES           AGE    VERSION
minikube       Ready    control-plane   33d    v1.26.1
minikube-m02   Ready    <none>          6d1h   v1.26.1
minikube-m03   Ready    <none>          6d1h   v1.26.1
```

## Convenience alias

Every task uses `k` as a shorthand for `kubectl`:

```bash
alias k=kubectl
```

## Addons

Some tasks need optional minikube addons:

```bash
# Storage (Task 03) — provides the csi-hostpath-sc StorageClass
minikube addons enable volumesnapshots
minikube addons enable csi-hostpath-driver

# Resource metrics (Task 09) — required for `kubectl top`
minikube addons enable metrics-server
```

Verify the StorageClass and snapshot class are present:

```bash
kubectl get storageclass
kubectl get volumesnapshotclasses
```

## A note on the cluster-upgrade task

Task 13 (kubeadm control-plane upgrade) is **not** performed on minikube — minikube
manages its own versioning and does not expose the `kubeadm upgrade` workflow the exam
tests. That task was completed on a standard kubeadm cluster (`controlplane` + `node01`)
and the session demonstrates the v1.26 → v1.27 upgrade path. Everything else runs on the
minikube cluster above.
