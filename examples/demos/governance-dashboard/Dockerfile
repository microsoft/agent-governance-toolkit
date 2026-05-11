FROM python:3.12-slim@sha256:804ddf3251a60bbf9c92e73b7566c40428d54d0e79d3428194edf40da6521286

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Run as a non-root user. Streamlit's default behavior plus a 0.0.0.0
# bind made the previous image trivially network-reachable as root.
RUN useradd --create-home --shell /bin/bash --uid 1000 dashboard \
    && chown -R dashboard:dashboard /app

USER dashboard

EXPOSE 8501

# Bind to localhost by default. Docker networking still allows the
# container to be reached from sibling containers on a user-defined
# network; deployments that need to expose the dashboard outside the
# Docker host must explicitly opt in by passing
# `--server.address=0.0.0.0` AND placing the dashboard behind an auth
# proxy (OAuth2 Proxy, Nginx, etc.). The previous default shipped
# ready-to-deploy on a public interface without authentication.
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=127.0.0.1"]
