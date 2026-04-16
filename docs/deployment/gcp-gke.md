# Deploying AGT on Google Cloud GKE

> **No Azure Required** — AGT is pure Python with zero cloud-vendor dependencies.
> It runs anywhere containers run: GCP, AWS, on-prem, or your laptop.

## Prerequisites

- `gcloud` CLI configured with GKE permissions
- Docker installed locally
- A GKE cluster running

## 1. Dockerfile

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8080
CMD ["python", "-m", "agent_os.server", "--port", "8080"]
```

## 2. Build & Push to Artifact Registry

```bash
gcloud auth configure-docker us-central1-docker.pkg.dev

docker build -t agt-governance .
docker tag agt-governance:latest \
  us-central1-docker.pkg.dev/<PROJECT>/agt/agt-governance:latest
docker push us-central1-docker.pkg.dev/<PROJECT>/agt/agt-governance:latest
```

## 3. GKE Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: agt-governance
spec:
  replicas: 2
  selector:
    matchLabels:
      app: agt-governance
  template:
    metadata:
      labels:
        app: agt-governance
    spec:
      containers:
        - name: agt
          image: us-central1-docker.pkg.dev/<PROJECT>/agt/agt-governance:latest
          ports:
            - containerPort: 8080
          env:
            - name: AGT_POLICY_PATH
              value: /app/policies/
            - name: AGT_LOG_LEVEL
              value: audit
          resources:
            requests:
              cpu: 250m
              memory: 512Mi
            limits:
              cpu: 500m
              memory: 1Gi
---
apiVersion: v1
kind: Service
metadata:
  name: agt-governance
spec:
  type: ClusterIP
  selector:
    app: agt-governance
  ports:
    - port: 80
      targetPort: 8080
```

## 4. Deploy

```bash
kubectl apply -f agt-deployment.yaml
kubectl rollout status deployment/agt-governance
```

## Using with Google ADK Agents

AGT includes a native Google ADK adapter. Wrap your ADK agent's tool calls
with `PolicyEvaluator.evaluate()` — see
[examples/quickstart/google_adk_governed.py](../../examples/quickstart/google_adk_governed.py).

## See Also

- [AWS ECS Deployment](aws-ecs.md)
- [Azure Container Apps Deployment](azure-container-apps.md)
- [Deployment Overview](README.md)
