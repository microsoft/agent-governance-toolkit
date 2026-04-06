FROM python:3.11.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY . /app
RUN useradd --create-home --uid 10001 appuser && chown -R appuser:appuser /app

EXPOSE 8501

USER appuser

CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0", "--server.port=8501"]
