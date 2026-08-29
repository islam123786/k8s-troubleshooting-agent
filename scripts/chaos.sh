#!/usr/bin/env bash
# Break the cluster on purpose, so the agent has something real to diagnose.
#
#   ./scripts/chaos.sh list
#   ./scripts/chaos.sh break  <scenario>
#   ./scripts/chaos.sh heal   <scenario>
#   ./scripts/chaos.sh status
#   ./scripts/chaos.sh heal-all
#
# Everything lives in the `chaos` namespace, which is also the only namespace the
# agent may modify — so healing is a clean teardown and the agent's writable
# surface is exactly the surface this script owns.
set -euo pipefail

CLUSTER="k8s-troubleshooting-agent"
CONTEXT="kind-${CLUSTER}"
NAMESPACE="chaos"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCENARIOS="${ROOT}/chaos/scenarios"

say() { printf '\033[1m==>\033[0m %s\n' "$*"; }
die() { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

k() { kubectl --context "$CONTEXT" "$@"; }

require_cluster() {
  kubectl config get-contexts "$CONTEXT" >/dev/null 2>&1 \
    || die "Context '${CONTEXT}' not found. Run ./scripts/setup-cluster.sh first."
  k get namespace "$NAMESPACE" >/dev/null 2>&1 \
    || k create namespace "$NAMESPACE" >/dev/null
}

scenario_dir() {
  local name="$1"
  [ -d "${SCENARIOS}/${name}" ] || die "Unknown scenario '${name}'. Try: $0 list"
  printf '%s' "${SCENARIOS}/${name}"
}

cmd_list() {
  printf '%-22s %s\n' "SCENARIO" "WHAT BREAKS"
  for dir in "${SCENARIOS}"/*/; do
    local name title
    name="$(basename "$dir")"
    title="$(sed -n 's/^title:[[:space:]]*//p' "${dir}/expect.yaml" | head -1)"
    printf '%-22s %s\n' "$name" "${title:-—}"
  done
}

cmd_break() {
  local name="${1:?usage: $0 break <scenario>}"
  local dir; dir="$(scenario_dir "$name")"
  require_cluster

  # dns-broken is applied by scaling a kube-system deployment rather than by
  # creating a resource — deliberately out of the agent's reach.
  if [ "$name" = "dns-broken" ]; then
    say "Scaling CoreDNS to zero (kube-system)..."
    k scale deployment coredns -n kube-system --replicas=0
    say "Broken. DNS resolution is down cluster-wide."
    echo "Note: the fix lives in kube-system, which the agent must refuse to touch."
    return
  fi

  say "Applying scenario '${name}'..."
  k apply -n "$NAMESPACE" -f "${dir}/broken.yaml"
  say "Broken. Give it a few seconds, then: ./scripts/chaos.sh status"
}

cmd_heal() {
  local name="${1:?usage: $0 heal <scenario>}"
  local dir; dir="$(scenario_dir "$name")"
  require_cluster

  if [ "$name" = "dns-broken" ]; then
    say "Restoring CoreDNS..."
    k scale deployment coredns -n kube-system --replicas=2
    k rollout status deployment/coredns -n kube-system --timeout=120s
    return
  fi

  say "Removing scenario '${name}'..."
  k delete -n "$NAMESPACE" -f "${dir}/broken.yaml" --ignore-not-found
}

cmd_heal_all() {
  require_cluster
  say "Removing everything in namespace '${NAMESPACE}'..."
  # Scoped to the sandbox namespace by construction — this script owns it.
  k delete all --all -n "$NAMESPACE" --ignore-not-found
  k delete pvc,networkpolicy,resourcequota,configmap --all -n "$NAMESPACE" --ignore-not-found \
    2>/dev/null || true
  if [ "$(k get deployment coredns -n kube-system -o jsonpath='{.spec.replicas}')" = "0" ]; then
    say "Restoring CoreDNS..."
    k scale deployment coredns -n kube-system --replicas=2
  fi
  say "Clean."
}

cmd_status() {
  require_cluster
  say "Namespace '${NAMESPACE}'"
  k get pods -n "$NAMESPACE" -o wide 2>/dev/null || true
  echo
  k get svc,endpoints,pvc -n "$NAMESPACE" 2>/dev/null || true
  echo
  say "Recent events"
  k get events -n "$NAMESPACE" --sort-by=.lastTimestamp 2>/dev/null | tail -15 || true
  echo
  local dns; dns="$(k get deployment coredns -n kube-system -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo 0)"
  say "CoreDNS ready replicas: ${dns:-0}"
}

case "${1:-}" in
  list)     cmd_list ;;
  break)    shift; cmd_break "$@" ;;
  heal)     shift; cmd_heal "$@" ;;
  heal-all) cmd_heal_all ;;
  status)   cmd_status ;;
  *) sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
