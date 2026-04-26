FROM python:3.11-slim@sha256:4057d02a202f69bfbfe10f65300519f612eb00fc595b8499f77d3cfe5b1b9fd4

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY pyproject.toml .

# Install Python dependencies (pinned for reproducibility)
RUN pip install --no-cache-dir \
    pydantic==2.10.3 \
    && pip install --no-cache-dir -e .  # pinned: local package, deps in pyproject.toml

# Copy application code
COPY . .

# Default command
CMD ["python", "demo.py", "--reports", "50"]
