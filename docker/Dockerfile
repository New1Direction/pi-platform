# PI Platform Production Image
# Multi-stage deterministic build — Python 3.11-slim, zero build artifacts in final layer.

FROM python:3.11-slim as builder

WORKDIR /build
COPY pyproject.toml ./
COPY src/ ./src/
COPY docker/requirements.txt ./requirements.txt

# Install only production deps from a hash-pinned, fully-resolved lockfile.
# --require-hashes makes the build reproducible (exact versions every time) and
# supply-chain safe (a tampered/yanked release fails the hash check instead of
# being installed). Regenerate the lock with the command documented in
# docker/requirements.in after changing a dependency.
RUN pip install --no-cache-dir --require-hashes -r requirements.txt \
    && find /usr/local/lib/python3.11/site-packages -name "*.pyc" -delete \
    && find /usr/local/lib/python3.11/site-packages -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true

FROM python:3.11-slim

# Non-root user for least-privilege
RUN groupadd -r piuser && useradd -r -g piuser piuser

WORKDIR /app

# Copy installed deps
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin/uvicorn /usr/local/bin/uvicorn

# Copy source code (deterministic ordering)
COPY --chown=piuser:piuser src/ /app/src/
COPY --chown=piuser:piuser docker/entrypoint.sh /app/entrypoint.sh

# Deterministic environment
ENV PYTHONPATH=/app/src \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PI_ENV=production \
    PI_STORAGE_PATH=/data/pi_production.db \
    PI_LOG_LEVEL=INFO

# Data directory (append-only SQLite)
RUN mkdir -p /data && chown piuser:piuser /data

USER piuser

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/v1/health/ready')" || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]
