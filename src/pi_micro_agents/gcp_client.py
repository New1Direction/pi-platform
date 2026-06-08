from __future__ import annotations

import logging

logger = logging.getLogger("gcp_client")

# central place for graceful imports of GCP SDKs
try:
    from google.cloud import aiplatform

    VERTEX_AVAILABLE = True
except ImportError:
    VERTEX_AVAILABLE = False
    aiplatform = None

try:
    from google.cloud import bigquery

    BIGQUERY_AVAILABLE = True
except ImportError:
    BIGQUERY_AVAILABLE = False
    bigquery = None

try:
    from google.cloud import pubsub_v1

    PUBSUB_AVAILABLE = True
except ImportError:
    PUBSUB_AVAILABLE = False
    pubsub_v1 = None

try:
    from google.cloud import secretmanager

    SECRETMANAGER_AVAILABLE = True
except ImportError:
    SECRETMANAGER_AVAILABLE = False
    secretmanager = None

try:
    from google.cloud import asset_v1

    ASSET_AVAILABLE = True
except ImportError:
    ASSET_AVAILABLE = False
    asset_v1 = None

try:
    from google.cloud import run_v2

    RUN_AVAILABLE = True
except ImportError:
    RUN_AVAILABLE = False
    run_v2 = None

try:
    import redis

    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    redis = None

try:
    from google.cloud import spanner

    SPANNER_AVAILABLE = True
except ImportError:
    SPANNER_AVAILABLE = False
    spanner = None

try:
    from google.cloud import trace_v2

    TRACE_AVAILABLE = True
except ImportError:
    TRACE_AVAILABLE = False
    trace_v2 = None


def check_gcp_dependencies() -> dict[str, bool]:
    """Returns a map indicating which GCP dependencies are installed and available."""
    return {
        "vertex": VERTEX_AVAILABLE,
        "bigquery": BIGQUERY_AVAILABLE,
        "pubsub": PUBSUB_AVAILABLE,
        "secretmanager": SECRETMANAGER_AVAILABLE,
        "asset": ASSET_AVAILABLE,
        "run": RUN_AVAILABLE,
        "redis": REDIS_AVAILABLE,
        "spanner": SPANNER_AVAILABLE,
        "trace": TRACE_AVAILABLE,
    }
