# CKA Practice Lab — minikube

Hands-on solutions to **14 Certified Kubernetes Administrator (CKA)** practice tasks,
worked end-to-end on a local **multi-node minikube** cluster. Every task page keeps the
**original terminal output** captured during the session, alongside a clean objective,
the manifests used, and a short practitioner note on the gotcha that mattered.

![Kubernetes](https://img.shields.io/badge/Kubernetes-v1.26.1-326CE5?logo=kubernetes&logoColor=white)
![minikube](https://img.shields.io/badge/cluster-minikube%20(multi--node)-blue)
![CKA](https://img.shields.io/badge/CKA-Certified%20Kubernetes%20Administrator-326CE5)
![License](https://img.shields.io/badge/license-MIT-green)

> These are real working notes from CKA preparation — kept verbatim as a record of the
> commands run and the output they produced, then organized by the official exam domains.

---

## Lab environment

| | |
|---|---|
| **Cluster** | minikube, multi-node (`minikube node add` → `minikube-m02`, `minikube-m03`) |
| **Kubernetes** | v1.26.1 (cluster-upgrade task demonstrated v1.26 → v1.27 on a kubeadm cluster) |
| **Runtime** | Docker |
| **Addons** | `csi-hostpath-driver`, `volumesnapshots`, `metrics-server` |
| **Shell alias** | `alias k=kubectl` |

Full reproduction steps are in [`docs/lab-setup.md`](docs/lab-setup.md).

---

## Tasks

Grouped by the five official CKA domains (and their approximate exam weighting).

### Cluster Architecture, Installation & Configuration · 25%
| # | Task | |
|---|------|---|
| 01 | RBAC — ClusterRole, ServiceAccount & namespaced RoleBinding | [open](tasks/01-rbac-clusterrole.md) |
| 02 | Node maintenance — Cordon & Drain | [open](tasks/02-cordon-drain.md) |
| 11 | Count Ready (non-tainted) nodes | [open](tasks/11-count-ready-nodes.md) |
| 13 | kubeadm control-plane upgrade | [open](tasks/13-cluster-upgrade.md) |
| 14 | etcd backup & restore | [open](tasks/14-etcd-backup-restore.md) |

### Workloads & Scheduling · 15%
| # | Task | |
|---|------|---|
| 05 | Scale a Deployment | [open](tasks/05-scale-deployment.md) |
| 10 | Multi-container Pod | [open](tasks/10-multi-container-pod.md) |
| 12 | Pin a Pod to a node | [open](tasks/12-schedule-pod-on-node.md) |

### Services & Networking · 20%
| # | Task | |
|---|------|---|
| 04 | Named container port + NodePort service | [open](tasks/04-deployment-port-nodeport-service.md) |
| 06 | NetworkPolicy (intra-namespace, port-scoped) | [open](tasks/06-network-policy.md) |
| 07 | Ingress resource | [open](tasks/07-ingress.md) |

### Storage · 10%
| # | Task | |
|---|------|---|
| 03 | PVC, mounted Pod & online expansion | [open](tasks/03-pv-pvc.md) |

### Troubleshooting · 30%
| # | Task | |
|---|------|---|
| 08 | Filter pod logs to a file | [open](tasks/08-pod-log-grep.md) |
| 09 | Identify the highest-CPU pod | [open](tasks/09-high-cpu-pod.md) |

---

## Manifests

Reusable YAML extracted from the tasks, ready to `kubectl apply -f`:

| File | Used in |
|------|---------|
| [`manifests/pv.yaml`](manifests/pv.yaml) | Task 03 |
| [`manifests/pvc-pod.yaml`](manifests/pvc-pod.yaml) | Task 03 |
| [`manifests/network-policy.yaml`](manifests/network-policy.yaml) | Task 06 |
| [`manifests/ingress.yaml`](manifests/ingress.yaml) | Task 07 |
| [`manifests/multi-container-pod.yaml`](manifests/multi-container-pod.yaml) | Task 10 |
| [`manifests/pod-nodeselector.yaml`](manifests/pod-nodeselector.yaml) | Task 12 |

---

## How to use

```bash
# 1. Start a multi-node minikube cluster
minikube start --nodes 3 --kubernetes-version v1.26.1

# 2. (For the storage task) enable CSI + snapshot addons
minikube addons enable volumesnapshots
minikube addons enable csi-hostpath-driver

# 3. (For the CPU task) enable metrics-server
minikube addons enable metrics-server

# 4. Apply any manifest and follow the matching task page
kubectl apply -f manifests/pvc-pod.yaml
```

Each task page is self-contained: read the objective, scan the original session output,
and reuse the manifest.

---

## Author

**Reasad Amin Shamrat** — Platform / Cloud Infrastructure Engineer
Certified Kubernetes Administrator (CKA) · OCI Certified Architect Associate

- GitHub: [github.com/reasadamin](https://github.com/reasadamin)
- LinkedIn: [linkedin.com/in/reasadamin](https://linkedin.com/in/reasadamin)

MSc candidate in Privacy, Information Security & Cybersecurity (University of Skövde),
researching Zero Trust architecture for Kubernetes workloads.

---

## License

Released under the [MIT License](LICENSE).
