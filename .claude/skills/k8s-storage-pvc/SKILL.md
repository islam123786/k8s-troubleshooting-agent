---
name: k8s-storage-pvc
description: Diagnose unbound PersistentVolumeClaims, missing StorageClasses and volume mount failures.
---

# PVCs and volumes

A pod waiting on storage is Pending with `pod has unbound immediate
PersistentVolumeClaims`, or ContainerCreating with a mount error.

## Establish the facts

```
get pvc -n <ns>
describe pvc <pvc> -n <ns>
get storageclass
describe pod <pod> -n <ns>
```

`get pvc` shows `STATUS: Pending` and, importantly, the `STORAGECLASS` column.

## Decision tree

1. **PVC Pending, `storageclass.storage.k8s.io "x" not found`** → the named class
   does not exist. Compare against `get storageclass`. On kind the default is
   `standard`; a manifest written for a cloud provider will name something like
   `gp2` or `fast-ssd` and never bind.
2. **PVC Pending, no events at all** → no default StorageClass and none named.
   `get storageclass` will show no entry marked `(default)`.
3. **PVC Pending with a class that exists** → the provisioner is not running, or
   for static provisioning there is no matching PV. Check
   `get pv` and the provisioner pod.
4. **PVC Bound but the pod will not start** → read the mount error in `describe
   pod`. A `ReadWriteOnce` volume already attached to a pod on another node will
   block scheduling of a second pod.
5. **`volume node affinity conflict`** → the PV is bound to a node the pod cannot
   be scheduled onto.

## The access-mode trap

`ReadWriteOnce` means one *node*, not one pod. A Deployment with more than one
replica and an RWO volume will have exactly one working replica and the rest
stuck, which looks like a scheduling bug and is not.

## Fix patterns

```yaml
spec:
  storageClassName: standard      # what kind actually provides
  accessModes: [ReadWriteOnce]
  resources:
    requests:
      storage: 1Gi
```

Note that most PVC fields are immutable once created: correcting a StorageClass
usually means deleting and recreating the claim, which is destructive and needs a
deliberate decision about the data.

## Verify

```
get pvc -n <ns>
get pod <pod> -n <ns>
```

PVC `Bound`, pod `Running`.
