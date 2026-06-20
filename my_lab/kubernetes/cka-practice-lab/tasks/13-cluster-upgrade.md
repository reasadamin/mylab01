# Task 13 — Cluster Maintenance — kubeadm control-plane upgrade

> **CKA domain:** Cluster Architecture, Installation & Configuration · 25% of the exam  
> **Lab:** minikube (multi-node), Kubernetes v1.26.1

## Objective

Upgrade the control-plane node (kubeadm, kubelet, kubectl) to the target version, draining it before and uncordoning it after, without touching worker nodes, etcd, the CNI, or DNS.

## Session — original output

```console
controlplane ~ ➜  k get node
NAME           STATUS   ROLES           AGE   VERSION
controlplane   Ready    control-plane   59m   v1.26.0
node01         Ready    <none>          59m   v1.26.0
controlplane ~ ➜  kubeadm upgrade plan
[upgrade/config] Making sure the configuration is correct:
[upgrade/config] Reading configuration from the cluster...
[upgrade/config] FYI: You can look at this config file with 'kubectl -n kube-system get cm kubeadm-config -o yaml'
[preflight] Running pre-flight checks.
[upgrade] Running cluster health checks
[upgrade] Fetching available versions to upgrade to
[upgrade/versions] Cluster version: v1.26.0
[upgrade/versions] kubeadm version: v1.26.0
I0104 01:30:26.743158   17412 version.go:256] remote version is much newer: v1.29.0; falling back to: stable-1.26
[upgrade/versions] Target version: v1.26.12
[upgrade/versions] Latest version in the v1.26 series: v1.26.12
Components that must be upgraded manually after you have upgraded the control plane with 'kubeadm upgrade apply':
COMPONENT   CURRENT       TARGET
kubelet     2 x v1.26.0   v1.26.12
Upgrade to the latest version in the v1.26 series:
COMPONENT                 CURRENT   TARGET
kube-apiserver            v1.26.0   v1.26.12
kube-controller-manager   v1.26.0   v1.26.12
kube-scheduler            v1.26.0   v1.26.12
kube-proxy                v1.26.0   v1.26.12
CoreDNS                   v1.9.3    v1.9.3
etcd                      3.5.6-0   3.5.6-0
You can now apply the upgrade by executing the following command:
       kubeadm upgrade apply v1.26.12
Note: Before you can perform this upgrade, you have to update kubeadm to v1.26.12.
controlplane ~ ➜  k get nodes
NAME           STATUS   ROLES           AGE   VERSION
controlplane   Ready    control-plane   70m   v1.26.0
node01         Ready    <none>          69m   v1.26.0
controlplane ~ ✖ k cordon controlplane
node/controlplane cordoned
controlplane ~ ➜  k get nodes
NAME           STATUS                     ROLES           AGE   VERSION
controlplane   Ready,SchedulingDisabled   control-plane   71m   v1.26.0
node01         Ready                      <none>          70m   v1.26.0
controlplane ~ ➜  k drain controlplane --delete-local-data --ignore-daemonsets --force
Flag --delete-local-data has been deprecated, This option is deprecated and will be deleted. Use --delete-emptydir-data.
node/controlplane already cordoned
Warning: ignoring DaemonSet-managed Pods: kube-flannel/kube-flannel-ds-pk9k4, kube-system/kube-proxy-jl7jn
evicting pod kube-system/coredns-787d4945fb-txvkj
evicting pod default/blue-987f68cb5-t5flp
evicting pod kube-system/coredns-787d4945fb-cggv4
evicting pod default/blue-987f68cb5-cdtgr
pod/blue-987f68cb5-t5flp evicted
pod/blue-987f68cb5-cdtgr evicted
pod/coredns-787d4945fb-txvkj evicted
pod/coredns-787d4945fb-cggv4 evicted
node/controlplane drained
controlplane ~ ➜  k get nodes
NAME           STATUS                     ROLES           AGE   VERSION
controlplane   Ready,SchedulingDisabled   control-plane   72m   v1.26.0
node01         Ready                      <none>          71m   v1.26.0
controlplane ~ ➜  k get pods -o wide
NAME                   READY   STATUS    RESTARTS   AGE   IP            NODE     NOMINATED NODE   READINESS GATES
blue-987f68cb5-hs6p9   1/1     Running   0          13m   10.244.1.4    node01   <none>           <none>
blue-987f68cb5-lwlc2   1/1     Running   0          27s   10.244.1.8    node01   <none>           <none>
blue-987f68cb5-m2gz4   1/1     Running   0          13m   10.244.1.2    node01   <none>           <none>
blue-987f68cb5-mpnl2   1/1     Running   0          13m   10.244.1.3    node01   <none>           <none>
blue-987f68cb5-wgcml   1/1     Running   0          27s   10.244.1.10   node01   <none>           <none>
controlplane ~ ➜  kubeadm version
kubeadm version: &version.Info{Major:"1", Minor:"27", GitVersion:"v1.27.0", GitCommit:"1b4df30b3cdfeaba6024e81e559a6cd09a089d65", GitTreeState:"clean", BuildDate:"2023-04-11T17:09:06Z", GoVersion:"go1.20.3", Compiler:"gc", Platform:"linux/amd64"}
controlplane ~ ➜  hostname ;whoami
controlplane
root
controlplane ~ ➜  apt install kubeadm=1.27.0-00 -y
Reading package lists... Done
Building dependency tree
Reading state information... Done
kubeadm is already the newest version (1.27.0-00).
0 upgraded, 0 newly installed, 0 to remove and 20 not upgraded.
controlplane ~ ✖ kubeadm upgrade apply v1.27.0
[upgrade/config] Making sure the configuration is correct:
[upgrade/config] Reading configuration from the cluster...
[upgrade/config] FYI: You can look at this config file with 'kubectl -n kube-system get cm kubeadm-config -o yaml'
[preflight] Running pre-flight checks.
[upgrade] Running cluster health checks
[upgrade/version] You have chosen to change the cluster version to "v1.27.0"
[upgrade/versions] Cluster version: v1.26.0
[upgrade/versions] kubeadm version: v1.27.0
[upgrade] Are you sure you want to proceed? [y/N]: y
.
.
.
upgrade/successful] SUCCESS! Your cluster was upgraded to "v1.27.0". Enjoy!
[upgrade/kubelet] Now that your control plane is upgraded, please proceed with upgrading your kubelets if you haven't already done so.
---
Update kubelet:
controlplane ~ ➜  k get nodes
NAME           STATUS                     ROLES           AGE   VERSION
controlplane   Ready,SchedulingDisabled   control-plane   96m   v1.26.0
node01         Ready                      <none>          96m   v1.26.0
controlplane ~ ➜  apt install kubelet=1.27.0-00 -y
Reading package lists... Done
Building dependency tree
Reading state information... Done
The following packages will be upgraded:
 kubelet
1 upgraded, 0 newly installed, 0 to remove and 20 not upgraded.
Need to get 18.8 MB of archives.
After this operation, 15.1 MB disk space will be freed.
Get:1 https://packages.cloud.google.com/apt kubernetes-xenial/main amd64 kubelet amd64 1.27.0-00 [18.8 MB]
Fetched 18.8 MB in 0s (55.5 MB/s)
debconf: delaying package configuration, since apt-utils is not installed
(Reading database ... 20439 files and directories currently installed.)
Preparing to unpack .../kubelet_1.27.0-00_amd64.deb ...
/usr/sbin/policy-rc.d returned 101, not running 'stop kubelet.service'
Unpacking kubelet (1.27.0-00) over (1.26.0-00) ...
Setting up kubelet (1.27.0-00) ...
/usr/sbin/policy-rc.d returned 101, not running 'start kubelet.service'
controlplane ~ ➜  k get nodes
NAME           STATUS                     ROLES           AGE   VERSION
controlplane   Ready,SchedulingDisabled   control-plane   97m   v1.26.0
node01         Ready                      <none>          96m   v1.26.0
controlplane ~ ✖ systemctl restart kubelet
controlplane ~ ➜  k get nodes
The connection to the server controlplane:6443 was refused - did you specify the right host or port?
controlplane ~ ✖ k get nodes
NAME           STATUS                     ROLES           AGE   VERSION
controlplane   Ready,SchedulingDisabled   control-plane   98m   v1.27.0
node01         Ready                      <none>          98m   v1.26.0
controlplane ~ ➜  k uncordon controlplane
node/controlplane uncordoned
controlplane ~ ➜  k get nodes
NAME           STATUS   ROLES           AGE    VERSION
controlplane   Ready    control-plane   100m   v1.27.0
node01         Ready    <none>          99m    v1.26.0
```

## Notes

Order matters: `kubeadm upgrade plan` → drain → `apt install kubeadm=<ver>` → `kubeadm upgrade apply` → upgrade `kubelet`/`kubectl` → `systemctl restart kubelet` → `uncordon`. The brief API-server connection drop after the kubelet restart is expected. (This lab session upgraded v1.26 → v1.27.)

---

[← Back to all tasks](../README.md#tasks)
