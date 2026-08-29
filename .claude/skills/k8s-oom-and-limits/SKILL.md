---
name: k8s-oom-and-limits
description: Diagnose OOMKilled containers, memory and CPU limit problems, and throttling. Use when a container is killed with exit 137 or reason OOMKilled, or is unexpectedly slow.
---

# OOMKilled and resource limits

## Establish the facts

```
describe pod <pod> -n <ns>            # Last State: Terminated, Reason: OOMKilled
get pod <pod> -n <ns> -o yaml         # resources.requests / resources.limits
top pod <pod> -n <ns>                 # needs metrics-server
```

`Reason: OOMKilled` with exit code 137 is conclusive. Exit 137 *without* that
reason is a SIGKILL from something else, usually a failed liveness probe —
see [[k8s-probes]].

## The distinction that matters

- **Requests** decide scheduling. Too high and the pod never schedules
  ([[k8s-pending-scheduling]]). They do not limit anything at runtime.
- **Limits** are enforced at runtime. Exceeding a memory limit is fatal and
  immediate; exceeding a CPU limit only throttles.

So: a pod that is *killed* has a memory problem. A pod that is merely *slow* has
a CPU limit problem, and `describe` will show no OOM at all.

## Decision tree

1. **OOMKilled and the limit looks small** — compare `limits.memory` against what
   the process actually needs. A JVM or Node app with no heap configuration will
   size itself to the *node's* memory, not the container's, and be killed. Set the
   runtime's own heap flag as well as the limit.
2. **OOMKilled and the limit looks generous** — suspect a leak or an unbounded
   buffer. Look at whether the kill happens at a consistent uptime.
3. **No OOM, but slow** — check `limits.cpu`. CPU throttling is invisible in pod
   status; the symptom is latency, not restarts.
4. **Killed shortly after start, every time** — the process needs more memory to
   *initialise* than to run. Raising the limit is the correct fix here.

## Fix patterns

Raise the limit only when the number is genuinely too low for the workload:

```yaml
resources:
  requests: { memory: "256Mi", cpu: "100m" }
  limits:   { memory: "512Mi" }        # no cpu limit is often the better default
```

Omitting a CPU limit while keeping a CPU request is frequently right: it
guarantees a share without introducing throttling.

## Verify

```
get pod <pod> -n <ns>
describe pod <pod> -n <ns>
top pod <pod> -n <ns>
```

Restart count stable, and observed usage comfortably under the limit. Usage
sitting at 99% of the limit is a fix that will fail again next week.
