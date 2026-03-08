FROM python:3.12-slim@sha256:d51616d5860ba60aa1786987d93b6aaebc05dd70f59f4cc36b008e9768cb88f1

WORKDIR /app

# Install the hypervisor package and API dependencies (pinned for reproducibility)
RUN pip install --no-cache-dir \
    "agent-hypervisor[api]==0.1.0" \
    redis==5.2.1 \
    pyyaml==6.0.2 \
    httpx==0.28.1

COPY app/ /app/app/
COPY config/ /app/config/

EXPOSE 8000 8501
