"""Collector API - the heart of the pipeline.

Flow for each request:
    agent --POST /ingest--> authenticate (per-source API key)
        --> store each event (append-only)
        --> detection rules  -> alerts   (attacks)
        --> posture rules    -> findings (misconfigurations: open / resolved)
        --> notify: instant for high/critical, the rest in the daily digest

Run it (from the project root):
    uvicorn collector.main:app --port 8000
"""
import asyncio
import hmac
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query

from . import config, db
from .alerting.notifier import notify_alert, notify_finding
from .detections.engine import run_detections, run_posture
from .digest import send_digest
from .models import IngestBatch


async def _digest_scheduler() -> None:
    """Send the digest once a day at DIGEST_HOUR_UTC."""
    last_sent = None
    while True:
        now = datetime.now(timezone.utc)
        if now.hour == config.DIGEST_HOUR_UTC and last_sent != now.date():
            last_sent = now.date()
            try:
                await asyncio.to_thread(send_digest)
            except Exception as exc:
                print(f"[digest] failed: {exc}", flush=True)
        await asyncio.sleep(60)


@asynccontextmanager
async def lifespan(app: FastAPI):
    problems = config.config_problems()
    if problems:
        # Secure by default: refuse to run rather than run unprotected.
        raise RuntimeError("Refusing to start: " + "; ".join(problems))
    db.init_db()
    task = None
    if config.DIGEST_HOUR_UTC is not None:
        task = asyncio.create_task(_digest_scheduler())
    yield
    if task:
        task.cancel()


app = FastAPI(title="Security Monitor Collector", version="0.2.0", lifespan=lifespan)


def require_api_key(x_api_key: str = Header(default="")) -> str:
    """Accept any configured per-source key; return that source's name.

    hmac.compare_digest takes the same time whether the first or the last
    character is wrong, so an attacker can't guess a key one character at a
    time by measuring response times (a "timing attack"). We also check every
    key rather than stopping at the first match, for the same reason.
    """
    matched: Optional[str] = None
    for name, key in config.API_KEYS.items():
        if hmac.compare_digest(x_api_key.encode(), key.encode()):
            matched = name
    if matched is None:
        raise HTTPException(status_code=401, detail="invalid or missing API key")
    return matched


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/ingest")
def ingest(batch: IngestBatch, source: str = Depends(require_api_key)) -> dict:
    alerts, changes = [], []
    with db.connect() as conn:
        for event in batch.events:
            db.insert_event(conn, event)
            # The row we just inserted is visible to the rules' queries on this
            # same connection, so the current event counts toward thresholds.
            for alert in run_detections(event, conn):
                db.insert_alert(
                    conn, alert.rule_id, alert.technique, alert.severity,
                    alert.title, alert.detail, alert.entity, alert.fix,
                )
                alerts.append(alert)
            changes.extend(run_posture(event, conn))
    # Notify only after the commit: a slow or failing Slack/email must never
    # lose or roll back the evidence.
    for alert in alerts:
        notify_alert(alert)
    for change in changes:
        notify_finding(change)
    return {
        "stored": len(batch.events),
        "alerts": len(alerts),
        "findings_opened": sum(c.kind == "opened" for c in changes),
        "findings_resolved": sum(c.kind == "resolved" for c in changes),
    }


@app.get("/findings")
def findings(
    status: str = Query("open", pattern="^(open|resolved|all)$"),
    _source: str = Depends(require_api_key),
) -> list[dict]:
    """Current findings, worst first. Authenticated: the list of what's wrong
    with your systems is exactly what an attacker would like to read."""
    with db.connect() as conn:
        return db.list_findings(conn, None if status == "all" else status)
