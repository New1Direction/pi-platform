# PI Platform — Deployment Guide

This guide covers Docker, local development, and production deployment.

## Local Development (One-Command Setup)

```bash
python -m venv venv
source venv/bin/activate
make dev         # Installs all deps
make test        # Runs full suite (409 tests)
```

## Console Frontend

```bash
cd pi-console-frontend
npm install
npm run dev       # → http://localhost:3000 (proxies /api to :8080)
```

## Docker Compose

```bash
docker compose -f docker/docker-compose.yml up --build
```

Services:
- `pi-console-backend` — FastAPI proxy on `:8080`
- `pi-core-api` — Deterministic execution kernel on `:9000`
- `pi-console-frontend` — Next.js dev server on `:3000`

## Production Checklist

- [ ] Set strong `SECRET_KEY` and tenant encryption keys
- [ ] Configure external PostgreSQL / Redis for persistent state
- [ ] Enable GPG commit signing on the CI/CD pipeline
- [ ] Disable `fail_open` in all orchestrator configs
- [ ] Verify all 409 conformance tests pass
- [ ] Run blast-radius simulation before each deployment
- [ ] Enable immutable audit logging to external SIEM

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PI_CORE_ENDPOINT` | `http://localhost:9000` | Core API base URL |
| `PI_CONSOLE_PORT` | `8080` | Console backend port |
| `PI_FRONTEND_PORT` | `3000` | Console frontend port |
| `PI_MAX_REQUEST_SIZE_MB` | `1` | Max request body size |
| `PI_REQUEST_TIMEOUT_SECONDS` | `30` | Request timeout |
| `PI_CORS_ORIGINS` | `http://localhost:3000` | Allowed CORS origins |
