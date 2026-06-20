# Task 09 — Troubleshooting — identify highest-CPU pod

> **CKA domain:** Troubleshooting · 30% of the exam  
> **Lab:** minikube (multi-node), Kubernetes v1.26.1

## Objective

From pods matching a label, find the one consuming the most CPU and write its name to a given file.

## Session — original output

```console
shamrat@shamrat-k8s:~$ k top pods
NAME             CPU(cores)   MEMORY(bytes)
cpu-loader-pod   0m           2Mi
ngin             0m           2Mi
or,
kubectl top pods --sort-by=cpu
then echo "pod_name" > /mentioned/file/location
Or,
Kubectl top pods -l name=name-cpu-loader –sort-by=cpu
```

## Notes

`kubectl top pods -l <label> --sort-by=cpu` puts the busiest pod at the top. Requires the metrics-server addon (`minikube addons enable metrics-server`). Then `echo <pod> > /path/file`.

---

[← Back to all tasks](../README.md#tasks)
