#!/bin/sh
# PI Platform Production Entrypoint
# Deterministic startup sequence

set -e

echo "[pi-platform] Starting production server..."
echo "[pi-platform] Environment: ${PI_ENV}"
echo "[pi-platform] Storage: ${PI_STORAGE_PATH}"
echo "[pi-platform] Version: 1.2.0-prod"

# Initialize storage directory
mkdir -p "$(dirname "${PI_STORAGE_PATH}")"

# Health check before binding
python -c "
import sys
sys.path.insert(0, '/app/src')
from pi_production.storage.engine import ConnectionPool, install_append_only_triggers
pool = ConnectionPool('${PI_STORAGE_PATH}')
install_append_only_triggers(pool)
print('[pi-platform] Storage initialized')
"

# Start ASGI server
exec uvicorn pi_production.api.server:app \
    --host 0.0.0.0 \
    --port 8000 \
    --workers 1 \
    --log-level info \
    --proxy-headers \
    --forwarded-allow-ips '*'
