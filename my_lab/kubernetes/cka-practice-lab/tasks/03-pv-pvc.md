# Task 03 — Storage — PersistentVolumeClaim, mounted Pod & online expansion

> **CKA domain:** Storage · 10% of the exam  
> **Lab:** minikube (multi-node), Kubernetes v1.26.1

## Objective

Create a `PersistentVolumeClaim` `pv-volume` (StorageClass `csi-hostpath-sc`, 10Mi, `ReadWriteOnce`), mount it into an nginx Pod `web-server` at `/usr/share/nginx/html`, then expand the PVC to 70Mi via `kubectl edit`/`patch`.

## Manifests

- [`manifests/pv.yaml`](../manifests/pv.yaml)
- [`manifests/pvc-pod.yaml`](../manifests/pvc-pod.yaml)

## Session — original output

```console
shamrat@shamrat-k8s:~/k8s_playbooks$ minikube addons enable volumesnapshots
💡  volumesnapshots is an addon maintained by Kubernetes. For any concerns contact minikube on GitHub.
You can view the list of minikube maintainers at: https://github.com/kubernetes/minikube/blob/master/OWNERS
   ▪ Using image k8s.gcr.io/sig-storage/snapshot-controller:v4.0.0
🌟  The 'volumesnapshots' addon is enabled
shamrat@shamrat-k8s:~/k8s_playbooks$ minikube addons enable csi-hostpath-driver
💡  csi-hostpath-driver is an addon maintained by Kubernetes. For any concerns contact minikube on GitHub.
You can view the list of minikube maintainers at: https://github.com/kubernetes/minikube/blob/master/OWNERS
   ▪ Using image k8s.gcr.io/sig-storage/csi-external-health-monitor-controller:v0.2.0
   ▪ Using image k8s.gcr.io/sig-storage/livenessprobe:v2.2.0
   ▪ Using image k8s.gcr.io/sig-storage/csi-snapshotter:v4.0.0
   ▪ Using image k8s.gcr.io/sig-storage/csi-external-health-monitor-agent:v0.2.0
   ▪ Using image k8s.gcr.io/sig-storage/csi-provisioner:v2.1.0
   ▪ Using image k8s.gcr.io/sig-storage/csi-attacher:v3.1.0
   ▪ Using image k8s.gcr.io/sig-storage/csi-node-driver-registrar:v2.0.1
   ▪ Using image k8s.gcr.io/sig-storage/hostpathplugin:v1.6.0
   ▪ Using image k8s.gcr.io/sig-storage/csi-resizer:v1.1.0
🔎  Verifying csi-hostpath-driver addon...
🌟  The 'csi-hostpath-driver' addon is enabled
shamrat@shamrat-k8s:~/k8s_playbooks$ kubectl get volumesnapshotclasses
NAME                     DRIVER                DELETIONPOLICY   AGE
csi-hostpath-snapclass   hostpath.csi.k8s.io   Delete           3m39s
- run pvc & pod playbook
shamrat@shamrat-k8s:~/k8s_playbooks$ cat pv2.yaml
apiVersion: v1
kind: PersistentVolume
metadata:
  name: app-config
spec:
  capacity:
    storage: 1Gi
  accessModes:
    - ReadWriteMany
  hostPath:
    path: "/srv/app-config"
shamrat@shamrat-k8s:~/k8s_playbooks$ cat pvc_pod2.yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: pv-volume
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Mi
  storageClassName: csi-hostpath-sc
---
apiVersion: v1
kind: Pod
metadata:
  name: web-server
spec:
  containers:
    - name: web-server
      image: nginx
      volumeMounts:
        - mountPath: "/usr/share/nginx/html"
          name: pv-volume
  volumes:
    - name: pv-volume
      persistentVolumeClaim:
          claimName: pv-volume
shamrat@shamrat-k8s:~/k8s_playbooks$ k create -f pvc_pod2.yaml
persistentvolumeclaim/pv-volume created
pod/web-server created
shamrat@shamrat-k8s:~/k8s_playbooks$ k get pvc
NAME        STATUS   VOLUME                                     CAPACITY   ACCESS MODES   STORAGECLASS      AGE
pv-volume   Bound    pvc-5018e12b-a9b7-49eb-8816-30ebe829db6a   10Mi       RWO            csi-hostpath-sc   4s
shamrat@shamrat-k8s:~/k8s_playbooks$ k get pod
NAME         READY   STATUS              RESTARTS   AGE
web-server   0/1     ContainerCreating   0          13s
shamrat@shamrat-k8s:~/k8s_playbooks$ k get pod --watch
NAME         READY   STATUS              RESTARTS   AGE
web-server   1/1     Running             0          25s
========================================================================
kubectl rub busybox --rm -it --image=busybox -- /bin/sh [to create a pod and directly login to it]
# wget --spider --timeout=1 nginx [to check nginx pod internally, from cluster network]
service:
shamrat@shamrat-k8s:~$ k run red --image=nginx --restart=Never
pod/red created
shamrat@shamrat-k8s:~$ k run blue --image=nginx --port=80 --restart=Never
pod/blue created
shamrat@shamrat-k8s:~$ k get pods
NAME   READY   STATUS    RESTARTS   AGE
blue   1/1     Running   0          10s
red    1/1     Running   0          28s
shamrat@shamrat-k8s:~$ k expose pod blue --type=NodePort --name=blue-svc
service/blue-svc exposed
shamrat@shamrat-k8s:~$ k get svc
NAME         TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)        AGE
blue-svc     NodePort    10.108.15.197   <none>        80:30425/TCP   6s
kubernetes   ClusterIP   10.96.0.1       <none>        443/TCP        29d
shamrat@shamrat-k8s:~$ minikube service blue-svc --url
http://192.168.59.105:30425
shamrat@shamrat-k8s:~$ k expose pod red --type=ClusterIP --port=80
service/red exposed
shamrat@shamrat-k8s:~$ k get services
NAME         TYPE        CLUSTER-IP       EXTERNAL-IP   PORT(S)        AGE
blue-svc     NodePort    10.108.15.197    <none>        80:30425/TCP   6m51s
kubernetes   ClusterIP   10.96.0.1        <none>        443/TCP        30d
red          ClusterIP   10.105.170.111   <none>        80/TCP         4s
shamrat@shamrat-k8s:~$ minikube service red --url
😿  service default/red has no node port
Deployment:
shamrat@shamrat-k8s:~$ kubectl create deployment front-end --image=nginx --replicas=3
deployment.apps/front-end created
shamrat@shamrat-k8s:~$ k get all
NAME                             READY   STATUS    RESTARTS   AGE
pod/blue                         1/1     Running   0          89m
pod/front-end-576d7fd544-49srj   1/1     Running   0          17s
pod/front-end-576d7fd544-khcnh   1/1     Running   0          17s
pod/front-end-576d7fd544-xkrgp   1/1     Running   0          17s
pod/red                          1/1     Running   0          89m
NAME                 TYPE        CLUSTER-IP       EXTERNAL-IP   PORT(S)        AGE
service/blue-svc     NodePort    10.108.15.197    <none>        80:30425/TCP   87m
service/kubernetes   ClusterIP   10.96.0.1        <none>        443/TCP        30d
service/red          ClusterIP   10.105.170.111   <none>        80/TCP         80m
NAME                        READY   UP-TO-DATE   AVAILABLE   AGE
deployment.apps/front-end   3/3     3            3           18s
NAME                                   DESIRED   CURRENT   READY   AGE
replicaset.apps/front-end-576d7fd544   3         3         3       18s
```

## Notes

On minikube the `csi-hostpath-driver` and `volumesnapshots` addons must be enabled first so the `csi-hostpath-sc` StorageClass exists. Online expansion only works when the StorageClass has `allowVolumeExpansion: true`.

---

[← Back to all tasks](../README.md#tasks)
