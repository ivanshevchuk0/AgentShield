# AgentShield gateway. One process on port 8080.
# docker-compose.yml bind-mounts the audit directory and backend/policy.yaml.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    AGENTSHIELD_DATA_DIR=/app/data \
    AGENTSHIELD_POLICY=/app/backend/policy.yaml

WORKDIR /app

RUN useradd --create-home --uid 1000 agentshield

COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

COPY backend backend
COPY frontend frontend

# The audit directory must be writable by the non-root user. A bind mount
# replaces this directory; docker-compose.yml and `make docker` prepare ./data.
RUN mkdir -p /app/data \
    && chown -R agentshield:agentshield /app/data /app/backend /app/frontend

USER agentshield

EXPOSE 8080

# python:3.12-slim has no curl. /health is the gateway liveness route.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/health' % __import__('os').environ.get('PORT', '8080'), timeout=4).read()"]

# Railway and similar hosts inject PORT; locally it stays 8080.
CMD ["sh", "-c", "exec uvicorn --factory app.main:create_app --app-dir backend --host 0.0.0.0 --port ${PORT:-8080}"]
