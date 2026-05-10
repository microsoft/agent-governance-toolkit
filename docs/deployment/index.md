# Deployment Guides

Deploy AGT on any cloud or container platform. AGT is pure Python/TypeScript/.NET with zero cloud-vendor lock-in.

!!! info "Cloud-agnostic"
    AGT has no cloud-vendor dependencies. Every deployment guide below produces the same governance behavior, whether you run on Azure, AWS, GCP, or on-prem.

## Cloud Platforms

| Guide | Platform | Pattern |
|-------|----------|---------|
| [Azure Container Apps](azure-container-apps.md) | :material-microsoft-azure: Azure | Managed containers |
| [Azure Foundry Agent Service](azure-foundry-agent-service.md) | :material-microsoft-azure: Azure | Foundry-native hosting |
| [AWS ECS / Fargate](aws-ecs.md) | :material-aws: AWS | Serverless containers |
| [Google Cloud GKE](gcp-gke.md) | :material-google-cloud: GCP | Kubernetes |

## Deployment Patterns

| Guide | Use Case |
|-------|----------|
| [OpenClaw Sidecar](openclaw-sidecar.md) | Sidecar governance proxy alongside any agent |
| [Private Endpoints](private-endpoints.md) | Secure networking with private links |
