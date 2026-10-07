# syntax=docker/dockerfile:1
FROM python:3.12-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY pyproject.toml README.md ./
COPY src/ src/

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

# Production Runner Stage (Rootless UID 10001:10001)
FROM python:3.12-slim AS runner

WORKDIR /app

RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /sbin/nologin -M appuser

COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /build/src /app/src

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER 10001:10001

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')" || exit 1

ENTRYPOINT ["uvicorn", "webscan.api.app:api_app", "--host", "0.0.0.0", "--port", "8000"]
