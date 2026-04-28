# Deploying AGT on AWS ECS/Fargate

> **No Azure Required** — AGT is pure Python with zero cloud-vendor dependencies.
> It runs anywhere containers run: AWS, GCP, on-prem, or your laptop.

## Prerequisites

- AWS CLI configured with ECS permissions
- Docker installed locally
- An ECR repository (or any container registry)

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

## 2. Build & Push to ECR

```bash
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin <ACCOUNT>.dkr.ecr.us-east-1.amazonaws.com

docker build -t agt-governance .
docker tag agt-governance:latest <ACCOUNT>.dkr.ecr.us-east-1.amazonaws.com/agt-governance:latest
docker push <ACCOUNT>.dkr.ecr.us-east-1.amazonaws.com/agt-governance:latest
```

## 3. ECS Task Definition

```json
{
  "family": "agt-governance",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "containerDefinitions": [
    {
      "name": "agt",
      "image": "<ACCOUNT>.dkr.ecr.us-east-1.amazonaws.com/agt-governance:latest",
      "portMappings": [{ "containerPort": 8080, "protocol": "tcp" }],
      "environment": [
        { "name": "AGT_POLICY_PATH", "value": "/app/policies/" },
        { "name": "AGT_LOG_LEVEL", "value": "audit" }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/agt-governance",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "agt"
        }
      }
    }
  ]
}
```

## 4. Create Fargate Service

```bash
aws ecs create-service \
  --cluster my-cluster \
  --service-name agt-governance \
  --task-definition agt-governance \
  --desired-count 2 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[subnet-xxx],securityGroups=[sg-xxx],assignPublicIp=ENABLED}"
```

## Using with AWS Bedrock Agents

AGT works with any agent framework. For Bedrock agents, wrap the agent's
tool calls with `PolicyEvaluator.evaluate()` — see
[examples/quickstart/govern_in_60_seconds.py](../../examples/quickstart/govern_in_60_seconds.py).

## See Also

- [GCP GKE Deployment](gcp-gke.md)
- [Azure Container Apps Deployment](azure-container-apps.md)
- [Deployment Overview](README.md)
