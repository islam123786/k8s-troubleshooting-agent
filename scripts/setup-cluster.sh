#!/usr/bin/env bash
# Create the local kind cluster the agent is pinned to.
#
# Idempotent: re-running against an existing cluster verifies it and exits 0
# rather than recreating it, so this is safe to put in front of other commands.
set -euo pipefail

CLUSTER="k8s-troubleshooting-agent"
CONTEXT="kind-${CLUSTER}"
NAMESPACE="chaos"

say()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33m warn:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

for binary in kind kubectl docker; do
  command -v "$binary" >/dev/null 2>&1 || die "$binary is not on PATH."
done

if ! docker info >/dev/null 2>&1; then
  die "Docker is not running. Start Docker Desktop and try again — kind runs its nodes as containers."
fi

if kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  say "Cluster '${CLUSTER}' already exists; leaving it alone."
else
  say "Creating cluster '${CLUSTER}' (1 control-plane + 2 workers)..."
  kind create cluster --name "$CLUSTER" --wait 120s --config=- <<'KIND'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
  - role: worker
  - role: worker
KIND
fi

say "Waiting for all nodes to be Ready..."
kubectl --context "$CONTEXT" wait --for=condition=Ready nodes --all --timeout=180s

say "Ensuring namespace '${NAMESPACE}' exists..."
kubectl --context "$CONTEXT" create namespace "$NAMESPACE" --dry-run=client -o yaml \
  | kubectl --context "$CONTEXT" apply -f -

# metrics-server backs `kubectl top`, which the OOM playbook relies on. kind's
# kubelets serve certs the metrics-server will not trust by default, hence the
# insecure-tls patch — acceptable on a local throwaway cluster, and nowhere else.
if kubectl --context "$CONTEXT" get deployment metrics-server -n kube-system >/dev/null 2>&1; then
  say "metrics-server already installed."
else
  say "Installing metrics-server (for 'kubectl top')..."
  kubectl --context "$CONTEXT" apply -f \
    https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml
  kubectl --context "$CONTEXT" patch deployment metrics-server -n kube-system --type=json \
    -p '[{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--kubelet-insecure-tls"}]'
  kubectl --context "$CONTEXT" rollout status deployment/metrics-server -n kube-system --timeout=120s \
    || warn "metrics-server did not become ready; 'kubectl top' may not work yet."
fi

say "Ready."
kubectl --context "$CONTEXT" get nodes
echo
echo "  Break something:  ./scripts/chaos.sh break crashloop"
echo "  Talk to it:       uv run python -m agent.cli"
