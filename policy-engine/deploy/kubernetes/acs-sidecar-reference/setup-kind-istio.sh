#!/usr/bin/env bash
set -euo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-acs-istio-reference}"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command $1" >&2
    exit 1
  fi
}

require_cmd kind
require_cmd kubectl
require_cmd istioctl

printf '%s\n' "Untested reference script"
printf '%s\n' "Creating kind cluster $CLUSTER_NAME"
kind create cluster --name "$CLUSTER_NAME" --image kindest/node:v1.30.0 || true

printf '%s\n' "Installing Istio demo profile"
istioctl install -y --set profile=demo

printf '%s\n' "Applying ACS reference manifests"
kubectl apply -k deploy/kubernetes/acs-sidecar-reference

printf '%s\n' "Run bash deploy/kubernetes/acs-sidecar-reference/test.sh after replacing the app image"
