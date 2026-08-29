---
name: k8s-pending-scheduling
description: Diagnose pods stuck in Pending, unschedulable pods, resource-quota rejections and affinity or nodeSelector mismatches.
---

# Pending pods

A Pending pod has been accepted by the API server but not placed on a node. It has
no logs, because no container has been created. The scheduler's own explanation is
the evidence.

## Establish the facts

```
describe pod <pod> -n <ns>                 # Events: FailedScheduling, with a reason
get nodes -o wide
describe nodes
get resourcequota -n <ns>
get events -n <ns> --sort-by=.lastTimestamp
```

The `FailedScheduling` message enumerates every node and why each was rejected.
Read it literally — it is unusually precise.

## Decision tree by message

| Message fragment | Cause | Fix |
|---|---|---|
| `Insufficient cpu` / `Insufficient memory` | Requests exceed any node's free capacity | Lower `resources.requests`, or add capacity |
| `didn't match Pod's node affinity/selector` | `nodeSelector` or affinity matches no node | Correct the label, or label a node |
| `had untolerated taint` | Nodes are tainted | Add a toleration, or remove the taint |
| `pod has unbound immediate PersistentVolumeClaims` | Storage, not scheduling | [[k8s-storage-pvc]] |
| `exceeded quota` | ResourceQuota rejection | See below |
| `0/N nodes are available` with no further detail | Usually all nodes cordoned or NotReady | `get nodes` |

## Requests versus capacity

A request is not a measurement of what the app uses — it is a reservation. A pod
requesting 500 CPU will never schedule on any realistic cluster no matter how idle
it looks, because the scheduler compares against *allocatable*, not current usage.

```
describe node <node>          # "Allocatable" and "Allocated resources"
```

## ResourceQuota

A quota rejection appears on the *ReplicaSet*, not the pod — the pod may not exist
at all. If a Deployment reports fewer replicas than desired and there are no
pending pods, look here:

```
describe rs -n <ns>
describe resourcequota -n <ns>
```

## Verify

```
get pod <pod> -n <ns> -o wide
```

The pod reaches `Running` with a node assigned. A pod that schedules and then
immediately fails is a different problem — see [[k8s-crashloop]].
