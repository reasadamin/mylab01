# Task 04 — Workloads & Networking — named container port + NodePort service

> **CKA domain:** Services & Networking · 20% of the exam  
> **Lab:** minikube (multi-node), Kubernetes v1.26.1

## Objective

Reconfigure the existing `front-end` deployment to add a named container port `http` (80/TCP), then expose it through a new `front-end-svc` of type `NodePort`.

## Session — original output

```console
shamrat@shamrat-k8s:~$ k create deployment front-end --image=nginx
deployment.apps/front-end created
shamrat@shamrat-k8s:~$ k get deployment
NAME        READY   UP-TO-DATE   AVAILABLE   AGE
front-end   0/1     1            0           5s
 We have to edit this deployment!!
shamrat@shamrat-k8s:~$ k get all
NAME                             READY   STATUS    RESTARTS   AGE
pod/front-end-576d7fd544-45fnb   1/1     Running   0          13s
NAME                 TYPE        CLUSTER-IP   EXTERNAL-IP   PORT(S)   AGE
service/kubernetes   ClusterIP   10.96.0.1    <none>        443/TCP   36d
NAME                        READY   UP-TO-DATE   AVAILABLE   AGE
deployment.apps/front-end   1/1     1            1           13s
NAME                                   DESIRED   CURRENT   READY   AGE
replicaset.apps/front-end-576d7fd544   1         1         1       13s
shamrat@shamrat-k8s:~$ k edit deployment front-end
deployment.apps/front-end edited
    spec:
      containers:
      - image: nginx
        imagePullPolicy: Always
        name: nginx
        ports:
        - containerPort: 80
          protocol: TCP
shamrat@shamrat-k8s:~$ k expose deployment front-end --name=front-end-svc --port=80 --type=NodePort --protocol=TCP
service/front-end-svc exposed
shamrat@shamrat-k8s:~$ k get services
NAME            TYPE        CLUSTER-IP       EXTERNAL-IP   PORT(S)        AGE
front-end-svc   NodePort    10.100.140.245   <none>        80:30794/TCP   4m17s
kubernetes      ClusterIP   10.96.0.1        <none>        443/TCP        36d
shamrat@shamrat-k8s:~$ k describe services front-end-svc
Name:                     front-end-svc
Namespace:                default
Labels:                   app=front-end
Annotations:              <none>
Selector:                 app=front-end
Type:                     NodePort
IP Family Policy:         SingleStack
IP Families:              IPv4
IP:                       10.100.140.245
IPs:                      10.100.140.245
Port:                     <unset>  80/TCP
TargetPort:               80/TCP
NodePort:                 <unset>  30794/TCP
Endpoints:                10.244.2.18:80
Session Affinity:         None
External Traffic Policy:  Cluster
Events:                   <none>
shamrat@shamrat-k8s:~$ k get all
NAME                            READY   STATUS    RESTARTS   AGE
pod/front-end-555698f45-mzrqx   1/1     Running   0          4m55s
NAME                    TYPE        CLUSTER-IP       EXTERNAL-IP   PORT(S)        AGE
service/front-end-svc   NodePort    10.100.140.245   <none>        80:30794/TCP   4s
service/kubernetes      ClusterIP   10.96.0.1        <none>        443/TCP        36d
NAME                        READY   UP-TO-DATE   AVAILABLE   AGE
deployment.apps/front-end   1/1     1            1           9m51s
NAME                                   DESIRED   CURRENT   READY   AGE
replicaset.apps/front-end-555698f45    1         1         1       4m55s
replicaset.apps/front-end-576d7fd544   0         0         0       9m51s
```

## Notes

Adding the named port to the Pod template first lets the Service target the port by name. `kubectl expose deployment ... --type=NodePort` is the fast path under exam time pressure versus hand-writing the Service YAML.

---

[← Back to all tasks](../README.md#tasks)
