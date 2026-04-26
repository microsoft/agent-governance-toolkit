# Use Python 3.11 slim image
FROM python:3.11-slim@sha256:4057d02a202f69bfbfe10f65300519f612eb00fc595b8499f77d3cfe5b1b9fd4

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
# pinned: versions declared in requirements.txt with upper bounds
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application
COPY . .

# Install the package in development mode
# pinned: local package, dependencies declared in pyproject.toml
RUN pip install --no-cache-dir -e .

# Create directory for document storage
RUN mkdir -p /app/data/documents /app/data/storage

# Expose the API port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run the API server
CMD ["uvicorn", "caas.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
