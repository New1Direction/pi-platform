# Desktop Console

The desktop console (`pi-tauri/`) is a Tauri 2 + React 19 + Vite application with a
deliberate Windows 98 visual theme. It's the primary interface to the platform and
talks to the FastAPI backend over [`/api/v1`](../api-reference.md).

## Layout

The shell is a Win98 desktop: each feature is a folder icon on the teal wallpaper
that opens its window. A PC-stats widget and connection indicator sit on the right;
a taskbar runs along the bottom.

## The tabs

| Tab | Purpose |
|-----|---------|
| **Ledger** | Hash-chained audit log of every execution — traces, risk scores, anomalies. |
| **Agents** | Browse all 248 micro-agents; filter by trust tier, runtime, or capability. |
| **[Builder](builder.md)** | Compose agents into a pipeline, simulate, and run — each node dispatched by keyword. |
| **Compose** | Advanced raw-DAG editor (manual runtimes/operations) + a chat copilot. |
| **Quota** | Tenant usage, rate limits, resource consumption. |
| **[Agent Forge](forge.md)** | AI-assisted micro-agent generator with a static-audit gate. |

## Bring-your-own-key (BYOK)

The Ask-AI panel and Agent Forge use **your** Anthropic API key, stored only in
`localStorage` under `pi_ai_apikey` and passed per-request as a header. The key is
never persisted server-side.

## Tech notes

- **Build target** is `esnext` — Tauri renders in the system webview (WKWebView /
  WebView2), which is evergreen, so no syntax down-leveling is needed.
- The dev server runs on `:1420` and proxies `/api` to the backend on `:8088`.
- Trust-tier chips throughout the UI map to the
  [trust-tier lifecycle](../architecture/trust-tiers.md).
