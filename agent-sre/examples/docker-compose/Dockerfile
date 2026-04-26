FROM python:3.12-slim@sha256:d51616d5860ba60aa1786987d93b6aaebc05dd70f59f4cc36b008e9768cb88f1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src/ src/

RUN pip install --no-cache-dir -e ".[api]"  # pinned: local package, deps in pyproject.toml

EXPOSE 8080

CMD ["uvicorn", "agent_sre.api.server:app", "--host", "0.0.0.0", "--port", "8080"]
