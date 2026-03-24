# Base stage: Python and Node.js
FROM python:3.11-slim as base
RUN apt-get update && apt-get install -y curl gnupg && \
    curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && \
    apt-get install -y nodejs && \
    rm -rf /var/lib/apt/lists/*

# Dev stage: Editable install
FROM base as dev
WORKDIR /app
COPY . .
RUN pip install -e .
CMD ["bash"]

# Test stage: Run suite
FROM dev as test
CMD ["pytest"]
