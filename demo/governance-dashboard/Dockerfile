FROM python:3.12-slim@sha256:804ddf3251a60bbf9c92e73b7566c40428d54d0e79d3428194edf40da6521286

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8501

# NOTE: Binds to 0.0.0.0 inside the container for Docker networking.
# In production, place behind an auth proxy (OAuth2 Proxy, Nginx, etc.).
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
