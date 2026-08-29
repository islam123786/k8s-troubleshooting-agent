---
name: k8s-networking-dns
description: Diagnose Services with no endpoints, wrong targetPort, NetworkPolicy blocks and cluster DNS failures. Use when traffic does not reach a pod that is otherwise healthy.
---

# Services, NetworkPolicy and DNS

The hardest family to diagnose, because every symptom is "it does not connect" and
nothing is in a failed state. Work from the endpoints outward.

## The single most useful command

```
get endpoints <service> -n <ns>
```

An empty `ENDPOINTS` column means the Service matches no ready pods. That one
observation splits the problem cleanly in two.

## Establish the facts

```
get svc <service> -n <ns> -o yaml
get endpoints <service> -n <ns>
get pods -n <ns> --show-labels
describe svc <service> -n <ns>
get networkpolicy -n <ns>
get pods -n kube-system -l k8s-app=kube-dns
```

## Decision tree

**Endpoints empty:**

1. **Selector matches nothing** — compare `spec.selector` against the pods'
   actual labels. `--show-labels` makes the mismatch obvious. This is the most
   common Service defect by a wide margin.
2. **Pods match but are not Ready** — endpoints only include ready pods. The
   Service is fine; the readiness probe is the problem ([[k8s-probes]]).

**Endpoints populated but connections fail:**

3. **`targetPort` wrong** — the Service forwards to a port nothing listens on.
   Compare `spec.ports[].targetPort` with the container's real port. Note that
   `port` is what clients dial and `targetPort` is where it lands; confusing them
   produces exactly this symptom.
4. **NetworkPolicy** — a default-deny policy with no matching allow rule silently
   drops traffic. There is no error anywhere; connections simply time out. Check
   for a policy selecting these pods with an empty `ingress` list.
5. **Wrong protocol** — a UDP service exposed as TCP.

**Name resolution fails:**

6. **CoreDNS down** — `get pods -n kube-system -l k8s-app=kube-dns`. Zero replicas
   or crashlooping CoreDNS breaks every in-cluster name at once, which usually
   presents as many unrelated services failing simultaneously.
7. **Wrong DNS name** — in-cluster names are
   `<service>.<namespace>.svc.cluster.local`. A bare `<service>` only resolves
   from within the same namespace.

## A note on scope

CoreDNS lives in `kube-system`, which this agent may read but never modify. If the
root cause is CoreDNS, report it with the exact command a human should run — do
not attempt a fix.

## Verify

```
get endpoints <service> -n <ns>
```

Endpoints populated with the expected pod IPs and ports.
