"""Shared agent helper: build normalized events and ship them to the collector.

Agents are deliberately simple and OUTBOUND-ONLY: they POST to the collector
and nothing ever connects back into the monitored host. If an endpoint is
compromised, the monitor must not become a doorway into the rest of the fleet.
This is why the collector has no "command the agent" endpoint at all.
"""
from __future__ import annotations

import json
import os
import socket
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


def _load_dotenv() -> None:
    """Pick up SM_* settings from the project's .env (real env vars win)."""
    env_file = Path(__file__).resolve().parent.parent / ".env"
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                os.environ.setdefault(key.strip(), value.strip())


_load_dotenv()

DEFAULT_COLLECTOR_URL = "http://127.0.0.1:8000"
# No built-in fallback key on purpose: each agent gets its own key from
# scripts/setup.py (SM_API_KEY in its environment).
DEFAULT_API_KEY = ""


@dataclass
class Event:
    agent_id: str
    host: str
    source: str
    event_type: str
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    user: Optional[str] = None
    source_ip: Optional[str] = None
    process: Optional[str] = None
    message: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


def ship(events: list[Event], collector_url: str, api_key: str) -> None:
    """POST a batch of events to the collector's /ingest endpoint."""
    if not api_key:
        raise SystemExit("No API key: set SM_API_KEY (run `python scripts/setup.py` to create one).")
    payload = json.dumps({"events": [asdict(e) for e in events]}).encode()
    req = urllib.request.Request(
        f"{collector_url.rstrip('/')}/ingest",
        data=payload,
        headers={"Content-Type": "application/json", "X-API-Key": api_key},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        body = json.loads(resp.read().decode())
    print(f"shipped {len(events)} event(s) -> {body}")


def hostname() -> str:
    return socket.gethostname()
