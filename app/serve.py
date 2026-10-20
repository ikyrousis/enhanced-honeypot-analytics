"""Serve one condition on loopback for manual inspection; runs no playbooks.

Usage:
    python serve.py                     # enhanced on http://127.0.0.1:8000
    python serve.py baseline --port 8010

Browsing events are appended to logs/manual-<condition>.jsonl, never to
logs/events.jsonl, so inspection cannot contaminate the experiment record.
"""

import argparse
from pathlib import Path

import uvicorn

from app.config import ROOT
from app.main import create_app


def main():
    parser = argparse.ArgumentParser(description="Manual inspection server.")
    parser.add_argument(
        "condition",
        nargs="?",
        choices=("baseline", "enhanced"),
        default="enhanced",
        help="condition to serve; enhanced is the honeypot proper (default)",
    )
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    log_path = ROOT / "logs" / f"manual-{args.condition}.jsonl"
    print(
        f"Serving {args.condition} on http://127.0.0.1:{args.port} "
        f"(events: {log_path.name}); Ctrl-C to stop."
    )
    uvicorn.run(
        create_app(args.condition, log_path),
        host="127.0.0.1",
        port=args.port,
        log_level="warning",
    )


if __name__ == "__main__":
    main()
