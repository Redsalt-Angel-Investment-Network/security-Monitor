"""Base classes for the two kinds of rule.

DETECTION rules spot attacker behaviour ("20 failed logons in 2 minutes") and
produce ALERTS. Each maps to a MITRE ATT&CK technique (e.g. T1110), which lets
you measure coverage against the ATT&CK matrix - "which attacker behaviours can
I actually see?" - instead of collecting unrelated rules.

POSTURE rules judge configuration ("the TLS cert expires in 5 days") and
produce FINDINGS. A finding stays open while the problem exists and closes by
itself when a later check passes - so the user gets a checklist that turns
green, not a stream of repeated alerts.

Every rule ships plain-language `fix` text. Our users are developers without a
security background: an alert they can't act on is just noise.
"""
from dataclasses import dataclass
from sqlite3 import Connection
from typing import Optional, Union

from ..models import Event


@dataclass
class Alert:
    rule_id: str
    technique: str      # ATT&CK technique id, e.g. "T1110"
    severity: str       # "low" | "medium" | "high" | "critical"
    title: str
    detail: str
    # WHAT the alert is about (an account, a URL...). The engine uses
    # (rule_id, entity) to suppress repeats inside the cooldown window.
    entity: str = ""
    fix: str = ""       # what to do, in plain language


class Rule:
    """A detection rule. `evaluate` runs once per incoming event; it may look
    back over history via the DB connection. Returns an Alert or None."""

    rule_id: str = "base"
    technique: str = ""
    severity: str = "medium"
    # Minutes to suppress repeat alerts for the same entity. None = global
    # default (SM_ALERT_COOLDOWN_MINUTES); 0 = never suppress.
    cooldown_minutes: Optional[int] = None

    def evaluate(self, event: Event, conn: Connection) -> Optional[Alert]:
        raise NotImplementedError


@dataclass
class Finding:
    """A posture problem that exists right now."""
    rule_id: str
    entity: str         # what it's about: a URL, host:port, domain...
    severity: str
    title: str
    detail: str
    fix: str


@dataclass
class Passed:
    """A check that came back clean - closes any open finding for it."""
    rule_id: str
    entity: str


Result = Union[Finding, Passed]


class PostureRule:
    """Judges one kind of check event. Returns a result per entity checked
    (an empty list = this event tells us nothing either way, e.g. the check
    itself errored)."""

    event_type: str = ""

    def assess(self, event: Event) -> list[Result]:
        raise NotImplementedError
