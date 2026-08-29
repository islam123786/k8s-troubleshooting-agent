---
name: k8s-image-pull
description: Diagnose ImagePullBackOff and ErrImagePull. Use when a pod cannot start because its image cannot be fetched.
---

# ImagePullBackOff / ErrImagePull

The kubelet could not fetch the image. The pod has never run, so there are no
application logs — the evidence is entirely in the events.

## Establish the facts

```
describe pod <pod> -n <ns>
get events -n <ns> --sort-by=.lastTimestamp
```

Read the `Failed to pull image` event verbatim. Its wording distinguishes every
cause below, and guessing without it wastes the most time.

## Decision tree

| Event text contains | Cause | Fix |
|---|---|---|
| `not found`, `manifest unknown` | The tag does not exist | Correct the tag. Confirm it exists before editing. |
| `repository does not exist` | Wrong image name or registry | Correct the repository path. |
| `unauthorized`, `authentication required` | Private registry, no or wrong credentials | Check `imagePullSecrets` on the pod and the ServiceAccount. |
| `no such host`, `i/o timeout`, `connection refused` | The node cannot reach the registry | Network, not configuration. On kind, check whether the image needs `kind load docker-image`. |
| `toomanyrequests` | Registry rate limit | Authenticate, or use a mirror. |

## A kind-specific trap

On a kind cluster, an image built locally is not visible to the nodes unless it
has been loaded:

```
kind load docker-image <image> --name <cluster>
```

A pod referencing a locally-built image with `imagePullPolicy: Always` will fail
even though `docker images` shows it present. `IfNotPresent` plus a loaded image
is the usual intent.

## Verify

```
get pod <pod> -n <ns>
describe pod <pod> -n <ns>
```

Expect the events to show `Successfully pulled image`. `ImagePullBackOff`
clearing to `Running` can take up to the current backoff interval, so allow time
before concluding a fix failed.
