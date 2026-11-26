"""Normalized event schema shared by the API.

A core idea in detection engineering: every agent, whatever OS or log source,
reports events in ONE normalized shape. Detections are then written once
against that shape instead of against each raw log format. (This is the idea
behind schemas like the Elastic Common Schema (ECS) and OSSEM.)

We still keep the original fields in `raw` so no information is lost.
"""
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Event(BaseModel):
    # When the activity happened (UTC). Agents should send the log's own time.
    timestamp: datetime = Field(default_factory=_utcnow)
    agent_id: str                        # which agent sent this
    host: str                            # machine the event came from
    source: str                          # "windows_security", "sysmon", "simulator", ...
    event_type: str                      # normalized, e.g. "authentication_failure"
    user: Optional[str] = None           # account involved, if any
    source_ip: Optional[str] = None      # origin IP, if any
    process: Optional[str] = None        # process / image path, if any
    message: str = ""                    # short human-readable summary
    raw: dict[str, Any] = Field(default_factory=dict)  # original fields, verbatim


class IngestBatch(BaseModel):
    """Agents ship events in batches to cut down on round-trips."""
    events: list[Event]
