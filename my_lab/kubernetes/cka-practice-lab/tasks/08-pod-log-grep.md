# Task 08 — Troubleshooting — filter pod logs to a file

> **CKA domain:** Troubleshooting · 30% of the exam  
> **Lab:** minikube (multi-node), Kubernetes v1.26.1

## Objective

Read a pod's logs, extract the matching lines, and redirect them to a file on disk.

## Session — original output

```console
shamrat@shamrat-k8s:~$ k logs cpu-loader-pod
/docker-entrypoint.sh: /docker-entrypoint.d/ is not empty, will attempt to perform configuration
/docker-entrypoint.sh: Looking for shell scripts in /docker-entrypoint.d/
/docker-entrypoint.sh: Launching /docker-entrypoint.d/10-listen-on-ipv6-by-default.sh
10-listen-on-ipv6-by-default.sh: info: Getting the checksum of /etc/nginx/conf.d/default.conf
10-listen-on-ipv6-by-default.sh: info: Enabled listen on IPv6 in /etc/nginx/conf.d/default.conf
/docker-entrypoint.sh: Sourcing /docker-entrypoint.d/15-local-resolvers.envsh
/docker-entrypoint.sh: Launching /docker-entrypoint.d/20-envsubst-on-templates.sh
/docker-entrypoint.sh: Launching /docker-entrypoint.d/30-tune-worker-processes.sh
/docker-entrypoint.sh: Configuration complete; ready for start up
2023/12/30 08:36:49 [notice] 1#1: using the "epoll" event method
2023/12/30 08:36:49 [notice] 1#1: nginx/1.25.3
2023/12/30 08:36:49 [notice] 1#1: built by gcc 12.2.0 (Debian 12.2.0-14)
2023/12/30 08:36:49 [notice] 1#1: OS: Linux 5.10.57
2023/12/30 08:36:49 [notice] 1#1: getrlimit(RLIMIT_NOFILE): 1048576:1048576
2023/12/30 08:36:49 [notice] 1#1: start worker processes
2023/12/30 08:36:49 [notice] 1#1: start worker process 29
2023/12/30 08:36:49 [notice] 1#1: start worker process 30
shamrat@shamrat-k8s:~$ k logs cpu-loader-pod | grep 'Linux'
2023/12/30 08:36:49 [notice] 1#1: OS: Linux 5.10.57
shamrat@shamrat-k8s:~$ k logs cpu-loader-pod | grep 'Linux' > /home/shamrat/bar
shamrat@shamrat-k8s:~$ cat /home/shamrat/bar
2023/12/30 08:36:49 [notice] 1#1: OS: Linux 5.10.57
```

## Notes

`kubectl logs <pod> | grep <pattern> > /path/file` is the whole job. Confirm with `cat` so you can see the captured line before moving on — cheap insurance on a graded file-output task.

---

[← Back to all tasks](../README.md#tasks)
