# Lightweight Python image for the AgentMesh example server and agent sidecars.
# In production, use the root-level Dockerfile.server and Dockerfile.sidecar instead.

FROM python:3.11-slim@sha256:4057d02a202f69bfbfe10f65300519f612eb00fc595b8499f77d3cfe5b1b9fd4

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 agentmesh
WORKDIR /app

COPY --chown=agentmesh:agentmesh app/ /app/

RUN pip install --no-cache-dir \
    fastapi==0.110.0 \
    uvicorn[standard]==0.27.1 \
    redis==5.0.1 \
    pyyaml==6.0.1 \
    prometheus-client==0.20.0 \
    httpx==0.27.0

USER agentmesh

EXPOSE 8080 8081 8082 9090 9091 9092

CMD ["python", "server.py"]
