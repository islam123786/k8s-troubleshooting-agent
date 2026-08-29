---
name: k8s-crashloop
description: Diagnose CrashLoopBackOff and other repeatedly-restarting containers. Use when a pod shows CrashLoopBackOff, Error, or a climbing RESTARTS count.
---

# CrashLoopBackOff

The container starts, exits, and Kubernetes restarts it with growing backoff. The
restart is a symptom; the exit is the event to explain.

## Establish the facts first

```
get pod <pod> -n <ns> -o wide
describe pod <pod> -n <ns>
logs <pod> -n <ns> --previous     # the run that died, not the one starting now
logs <pod> -n <ns> --all-containers
```

`--previous` is the important one. Without it you are reading a container that has
not failed yet, which is why crashloops are so often misdiagnosed.

## Read the exit code

`describe` shows `Last State: Terminated` with a reason and exit code.

| Exit code | Almost always means |
|---|---|
| 0 | The process finished. It is not a server, or its command exits immediately. Not an error — a design mismatch. |
| 1 | Application error. The logs have the answer. |
| 2 | Shell misuse — usually a malformed command or args. |
| 126 | Command found but not executable. |
| 127 | Command not found. Wrong binary name, or wrong image. |
| 137 | SIGKILL. If `Reason: OOMKilled`, use [[k8s-oom-and-limits]]. Otherwise a failed liveness probe kill — see [[k8s-probes]]. |
| 139 | SIGSEGV. Application crash. |
| 143 | SIGTERM. Something asked it to stop. |

## Decision tree

1. **`Reason: OOMKilled`** → this is a memory problem, not a crash problem. Go to
   [[k8s-oom-and-limits]].
2. **Exit 127 or 126** → the `command`/`args` in the spec do not match what the
   image contains. Check the image's real entrypoint before editing the spec.
3. **Exit 0 with `restartPolicy: Always`** → the workload is not long-running.
   Either it is the wrong image, or it should be a Job rather than a Deployment.
4. **Non-zero exit with application output** → read the logs. Common causes are a
   missing environment variable, an unreachable dependency at startup, or a
   config file that is not where the app expects it.
5. **No logs at all** → the container never started. Look at
   `describe` events for the image pull ([[k8s-image-pull]]) or a volume mount
   failure ([[k8s-storage-pvc]]).

## Fix patterns

- Wrong command → correct `spec.containers[].command` / `args`.
- Missing env or config → see [[k8s-probes]] is *not* the issue; check the
  referenced ConfigMap exists and has the key the pod asks for.
- Dependency not ready at startup → the real fix is usually a retry loop in the
  app or an init container, not a longer probe delay.

## Verify

```
get pod <pod> -n <ns> -w
logs <pod> -n <ns>
```

The restart count must stop climbing. A pod that reaches `Running` once and then
restarts again in two minutes is not fixed.
