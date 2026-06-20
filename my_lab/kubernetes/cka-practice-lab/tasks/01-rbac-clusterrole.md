# Task 01 — RBAC — ClusterRole, ServiceAccount & namespaced RoleBinding

> **CKA domain:** Cluster Architecture, Installation & Configuration · 25% of the exam  
> **Lab:** minikube (multi-node), Kubernetes v1.26.1

## Objective

Create a `ClusterRole` named `deployment-clusterrole` that permits **only** the creation of `Deployment`, `StatefulSet`, and `DaemonSet` resources. Create a `ServiceAccount` named `cicd-token` in the existing `app-team1` namespace, then bind the ClusterRole to that ServiceAccount **scoped to `app-team1` only** (a `RoleBinding`, not a `ClusterRoleBinding`).

## Session — original output

```console
shamrat@shamrat-k8s:~$ alias k='kubectl'
shamrat@shamrat-k8s:~$ k create clusterrole deployment-clusterrole --verb=create --resource=deployment,statefulset,daemonset
clusterrole.rbac.authorization.k8s.io/deployment-clusterrole created
shamrat@shamrat-k8s:~$ k describe clusterrole deployment-clusterrole
Name:         deployment-clusterrole
Labels:       <none>
Annotations:  <none>
PolicyRule:
 Resources          Non-Resource URLs  Resource Names  Verbs
 ---------          -----------------  --------------  -----
 daemonsets.apps    []                 []              [create]
 deployments.apps   []                 []              [create]
 statefulsets.apps  []                 []              [create]
ServiceAccount:
shamrat@shamrat-k8s:~$ k create serviceaccount cicd-token -n app-team1
serviceaccount/cicd-token created
shamrat@shamrat-k8s:~$ k get serviceaccount -n app-team1
NAME         SECRETS   AGE
cicd-token   0         22s
default      0         72s
RoleBinding:
shamrat@shamrat-k8s:~$ k create rolebinding cicd-clusterrole --clusterrole=deployment-clusterrole --serviceaccount=app-team1:cicd-token
rolebinding.rbac.authorization.k8s.io/cicd-clusterrole created
shamrat@shamrat-k8s:~$ k get rolebinding
NAME               ROLE                                 AGE
cicd-clusterrole   ClusterRole/deployment-clusterrole   18s
shamrat@shamrat-k8s:~$ k describe rolebinding cicd-clusterrole
Name:         cicd-clusterrole
Labels:       <none>
Annotations:  <none>
Role:
 Kind:  ClusterRole
 Name:  deployment-clusterrole
Subjects:
 Kind            Name        Namespace
 ----            ----        ---------
 ServiceAccount  cicd-token  app-team1
```

## Notes

The trick is using a **RoleBinding** (namespaced) that references a **ClusterRole**. This is the canonical pattern for reusing one ClusterRole's permission set across namespaces while keeping the grant scoped. `--resource` accepts the short names and the API group is resolved automatically (`deployments.apps`).

---

[← Back to all tasks](../README.md#tasks)
