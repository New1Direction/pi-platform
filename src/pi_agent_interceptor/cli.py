"""CLI Wrapper for the PI Agent Interceptor Proxy.

Provides a unified command-line entrypoint to launch the proxy, configure environment,
and optionally boot a target autonomous agent (e.g. Aider, Claude Engineer) piped through
the security gateway transparently.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time

import uvicorn


def run_proxy(host: str, port: int) -> None:
    """Helper function to run the uvicorn uvicorn uvicorn uvicorn uvicorn uvicorn uvicorn server."""
    # Launch uvicorn programmatically in synchronous context
    uvicorn.run("pi_agent_interceptor.proxy:app", host=host, port=port, log_level="info")


def main() -> None:
    parser = argparse.ArgumentParser(description="Unified CLI Bootstrapper for the PI Agent Interceptor Proxy")
    parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Host address to bind the safety proxy server to (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Port number to bind the safety proxy server to (default: 8080)",
    )
    parser.add_argument(
        "--llm-url",
        type=str,
        default="https://api.openai.com/v1/chat/completions",
        help="Target LLM completions endpoint to route approved completions to",
    )
    parser.add_argument(
        "--db-path",
        type=str,
        default="pi_audit_ledger.db",
        help="SQLite database path for the append-only audit log",
    )
    parser.add_argument(
        "--slack-webhook",
        type=str,
        default=None,
        help="Slack Webhook url for sending Human-in-the-Loop review notifications",
    )
    parser.add_argument(
        "--target-command",
        type=str,
        default=None,
        help="An optional CLI agent command to execute (e.g. 'agy -i', 'aider --model gpt-4o') wrapped by the proxy",
    )

    args = parser.parse_args()

    # 1. Inject configurations into environment variables for proxy.py to consume
    os.environ["PI_TARGET_LLM_URL"] = args.llm_url
    os.environ["PI_LEDGER_DB_PATH"] = args.db_path
    if args.slack_webhook:
        os.environ["PI_SLACK_WEBHOOK_URL"] = args.slack_webhook

    # 2. If a target command is provided, launch the proxy in the background and pipe the agent
    if args.target_command:
        print(f"[*] Starting PI Interceptor Proxy in background on http://{args.host}:{args.port}")

        from pathlib import Path

        src_root = str(Path(__file__).resolve().parent.parent)

        # Set up base environment with PYTHONPATH for uvicorn
        base_env = os.environ.copy()
        current_pythonpath = base_env.get("PYTHONPATH", "")
        if current_pythonpath:
            base_env["PYTHONPATH"] = f"{src_root}:{current_pythonpath}"
        else:
            base_env["PYTHONPATH"] = src_root

        # Start uvicorn proxy in a background subprocess
        proxy_proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "pi_agent_interceptor.proxy:app",
                "--host",
                args.host,
                "--port",
                str(args.port),
                "--log-level",
                "warning",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=base_env,
        )

        # Give uvicorn a brief moment to boot and bind to the port
        time.sleep(1.5)

        if proxy_proc.poll() is not None:
            print("[ERROR] Failed to launch PI Interceptor Proxy backend. Aborting.")
            sys.exit(1)

        print("[*] Proxy running! Injecting environment redirects for target CLI agent...")

        # Set up proxy redirection environment variables
        proxy_env = os.environ.copy()

        # Point LLM requests from Aider, Claude Engineer, Cursor, etc. to our local interceptor
        proxy_url = f"http://{args.host}:{args.port}/v1"
        proxy_env["OPENAI_API_BASE"] = proxy_url
        proxy_env["OPENAI_BASE_URL"] = proxy_url
        proxy_env["ANTHROPIC_BASE_URL"] = proxy_url
        proxy_env["PI_AGENT_INTERCEPTOR_ACTIVE"] = "1"

        print(f"[*] Launching target CLI Agent: `{args.target_command}`\n" + "=" * 60)

        try:
            # Execute the target agent command in a foreground subprocess, sharing stdin/stdout/stderr
            # Security note: shell=True is intentional — this is a developer-facing interceptor tool
            # where the operator supplies their own trusted CLI command (e.g. "aider", "cursor ...",
            # compound shell aliases). Input is not derived from any user-facing web endpoint.
            agent_proc = subprocess.run(  # noqa: S602
                args.target_command,
                shell=True,  # noqa: S604
                env=proxy_env,
                stdin=sys.stdin,
                stdout=sys.stdout,
                stderr=sys.stderr,
            )
            print("=" * 60 + f"\n[*] Target CLI Agent exited with status code: {agent_proc.returncode}")
        except KeyboardInterrupt:
            print("\n[*] Interrupted! Shutting down...")
        finally:
            # Gracefully terminate uvicorn background server
            proxy_proc.terminate()
            try:
                proxy_proc.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                proxy_proc.kill()
            print("[*] PI Interceptor Proxy closed successfully.")

    else:
        # Standard foreground proxy boot
        print(f"[*] Starting PI Interceptor Proxy on http://{args.host}:{args.port}")
        run_proxy(args.host, args.port)


if __name__ == "__main__":
    main()
