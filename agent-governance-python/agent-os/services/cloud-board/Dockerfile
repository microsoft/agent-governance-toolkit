# Nexus Cloud Board
# The Agent Trust Exchange API Service

FROM python:3.11-slim@sha256:4057d02a202f69bfbfe10f65300519f612eb00fc595b8499f77d3cfe5b1b9fd4

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for caching
COPY requirements.txt .
# pinned: versions declared in requirements.txt with upper bounds
RUN pip install --no-cache-dir -r requirements.txt

# Copy the nexus module
COPY ../../modules/nexus /app/modules/nexus

# Copy the cloud-board service
COPY . /app/services/cloud-board

# Set Python path
ENV PYTHONPATH=/app

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run the API
CMD ["uvicorn", "services.cloud-board.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
