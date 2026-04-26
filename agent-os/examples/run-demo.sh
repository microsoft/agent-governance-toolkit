#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Agent OS Demo Runner
# Usage: ./run-demo.sh <demo-name> [options]

set -e

DEMO_NAME="${1:-carbon-auditor}"
shift || true

DEMOS="carbon-auditor grid-balancing defi-sentinel pharma-compliance"

usage() {
    echo "Agent OS Demo Runner"
    echo ""
    echo "Usage: ./run-demo.sh <demo-name> [options]"
    echo ""
    echo "Available demos:"
    echo "  carbon-auditor     - Carbon credit fraud detection"
    echo "  grid-balancing     - Energy trading swarm"
    echo "  defi-sentinel      - DeFi attack response"
    echo "  pharma-compliance  - Document contradiction finder"
    echo ""
    echo "Options:"
    echo "  --docker    Run with Docker (default)"
    echo "  --local     Run locally with Python"
    echo "  --k8s       Deploy to Kubernetes"
    echo ""
    echo "Examples:"
    echo "  ./run-demo.sh carbon-auditor"
    echo "  ./run-demo.sh grid-balancing --local"
    echo "  ./run-demo.sh defi-sentinel --k8s"
}

if [[ "$DEMO_NAME" == "-h" || "$DEMO_NAME" == "--help" ]]; then
    usage
    exit 0
fi

# Check if demo exists
if [[ ! -d "examples/$DEMO_NAME" ]]; then
    echo "Error: Demo '$DEMO_NAME' not found"
    echo "Available demos: $DEMOS"
    exit 1
fi

cd "examples/$DEMO_NAME"

# Parse mode
MODE="docker"
for arg in "$@"; do
    case $arg in
        --docker) MODE="docker" ;;
        --local)  MODE="local" ;;
        --k8s)    MODE="k8s" ;;
    esac
done

echo "╔════════════════════════════════════════════════════════════╗"
echo "║           Agent OS Demo: $DEMO_NAME"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

case $MODE in
    docker)
        echo "🐳 Running with Docker..."
        docker-compose up --build
        ;;
    local)
        echo "🐍 Running locally..."
        # Install local package (Scorecard: pinned via pyproject.toml)
        pip install --no-cache-dir -e ".[dev]" -q 2>/dev/null || pip install --no-cache-dir -e . -q
        python demo.py "$@"
        ;;
    k8s)
        echo "☸️  Deploying to Kubernetes..."
        if [[ -d "k8s" ]]; then
            kubectl apply -f k8s/
        else
            echo "Creating k8s manifests..."
            mkdir -p k8s
            cat > k8s/deployment.yaml << EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: agent-os-$DEMO_NAME
  labels:
    app: agent-os
    demo: $DEMO_NAME
spec:
  replicas: 1
  selector:
    matchLabels:
      app: agent-os
      demo: $DEMO_NAME
  template:
    metadata:
      labels:
        app: agent-os
        demo: $DEMO_NAME
    spec:
      containers:
      - name: demo
        image: agent-os/$DEMO_NAME:latest
        ports:
        - containerPort: 8080
          name: http
        - containerPort: 9090
          name: metrics
        env:
        - name: AGENT_OS_METRICS_PORT
          value: "9090"
        resources:
          limits:
            cpu: "1"
            memory: "1Gi"
          requests:
            cpu: "500m"
            memory: "512Mi"
---
apiVersion: v1
kind: Service
metadata:
  name: agent-os-$DEMO_NAME
spec:
  selector:
    app: agent-os
    demo: $DEMO_NAME
  ports:
  - name: http
    port: 8080
    targetPort: 8080
  - name: metrics
    port: 9090
    targetPort: 9090
EOF
            kubectl apply -f k8s/
        fi
        echo ""
        echo "Deployment created. Access metrics at:"
        echo "  kubectl port-forward svc/agent-os-$DEMO_NAME 9090:9090"
        ;;
esac
