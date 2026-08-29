#!/usr/bin/env bash
# Delete the kind cluster. Everything in it goes with it.
set -euo pipefail

CLUSTER="k8s-troubleshooting-agent"

if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  echo "Cluster '${CLUSTER}' does not exist; nothing to do."
  exit 0
fi

printf 'Delete kind cluster "%s" and everything in it? [y/N] ' "$CLUSTER"
read -r reply
case "$reply" in
  y|Y|yes|YES) kind delete cluster --name "$CLUSTER" ;;
  *) echo "Left alone." ;;
esac
