# Getting Started

This walks you through booting the backend and a console locally.

## Prerequisites

- Python 3.9+ (3.12 recommended)
- Node 18+ (for either front-end)
- For the desktop console: the [Tauri prerequisites](https://tauri.app/start/prerequisites/) (Rust + platform webview)

## 1. Install the backend

```bash
pip install -e ".[dev,all]"
```

## 2. Run the backend

The console boundary is the FastAPI app `pi_console.main:app`.

```bash
PI_SECRET_JWT=$(openssl rand -hex 32) \
PI_SECRET_REQUEST_SIGNING=$(openssl rand -hex 32) \
PI_STATE_LEDGER_PATH=/tmp/pi.db \
PYTHONPATH=src uvicorn pi_console.main:app --reload --port 8088
```

!!! warning "Set `PI_STATE_LEDGER_PATH`"
    The ledger **writer** and **reader** must point at the same SQLite file. The
    writer uses `PI_STATE_LEDGER_PATH`; the reader falls back to it as well. If you
    leave it unset across separate adapters, the Ledger tab may read an empty store.
    See [Ledger & Replay](architecture/ledger-replay.md).

Verify it's up:

```bash
curl -s localhost:8088/health        # → {"status":"HEALTHY", ...}
```

For local development without auth, the backend honors
`PI_CONSOLE_ALLOW_UNAUTHENTICATED=1` to open up the read endpoints.

## 3. Run the desktop console

```bash
cd pi-tauri
npm install
npm run dev          # Vite dev server on http://localhost:1420
```

The dev server proxies `/api` → `http://localhost:8088`, so the console talks to
the backend you started above. To produce a production bundle:

```bash
npm run build        # → dist/ (target: esnext, for Tauri's evergreen webview)
```

## 4. (Alternative) Run the web console

```bash
cd pi-console-frontend
npm install && npm run build && npm start   # http://localhost:3000
```

## Smoke test the whole stack

The repo ships a driver that boots the backend, probes ten endpoints, and exits:

```bash
python3 .claude/skills/run-pi-platform/driver.py smoke
```

Expected highlights:

```
✓ /capabilities/list → 248 agents (live AgentRouter)
✓ /compositions/simulate → can_execute=True
✓ /compositions/submit  → ledger=ledger_…
✓ /replay/get → chained event(s) integrity=True
```

Next: take the [Desktop Console tour](console/index.md).
