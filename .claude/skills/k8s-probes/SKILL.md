---
name: k8s-probes
description: Diagnose failing liveness, readiness and startup probes. Use when a pod restarts without an application crash, or stays 0/1 Ready while the process is running fine.
---

# Probes

Two very different symptoms, one mechanism:

- **Liveness fails** → the container is killed and restarted. Looks like a crash,
  but the application never exited on its own.
- **Readiness fails** → the container keeps running but is removed from Service
  endpoints. The pod shows `Running` and `0/1`, and traffic silently goes nowhere.

## Establish the facts

```
describe pod <pod> -n <ns>        # events: "Liveness probe failed: ..."
get pod <pod> -n <ns> -o yaml     # the probe definitions
logs <pod> -n <ns> --previous
```

The probe failure message names the reason: `connection refused`, `404`,
`timeout`. That distinction is the whole diagnosis.

## Decision tree

1. **`connection refused`** → nothing is listening on that port *inside the
   container*. Either the probe port is wrong, or the app binds `127.0.0.1`
   instead of `0.0.0.0`. The latter is common and invisible from outside.
2. **`404` or unexpected status** → the path is wrong, or the app serves health
   on a different route than assumed.
3. **`timeout`** → the app is alive but slower than `timeoutSeconds`, usually
   under load or during startup.
4. **Fails only at startup, succeeds later** → `initialDelaySeconds` is too short.
   Prefer a `startupProbe` over inflating the liveness delay: it gives slow starts
   room without weakening liveness for the rest of the pod's life.
5. **Restarting with exit 137 and no OOM** → this is a liveness kill.
   See [[k8s-crashloop]] for the exit-code table.

## A trap worth knowing

A liveness probe pointing at a dependency (a database, another service) will
restart your pod when *that* dependency is down. Liveness should test only whether
this process is wedged. Dependency health belongs in readiness, if anywhere.

## Fix patterns

```yaml
startupProbe:                    # tolerate a slow boot without weakening liveness
  httpGet: { path: /healthz, port: 8080 }
  failureThreshold: 30
  periodSeconds: 2
livenessProbe:
  httpGet: { path: /healthz, port: 8080 }
  periodSeconds: 10
```

## Verify

```
get pod <pod> -n <ns>
describe pod <pod> -n <ns>
```

`READY` reaching `1/1`, restart count stable, and no probe-failure events in the
last few minutes.
