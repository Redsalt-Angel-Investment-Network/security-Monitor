"""Detection engine: run every registered rule against each incoming event.

Two paths:

* DETECTION rules -> alerts, de-duplicated by a cooldown per rule + entity, so
  a 20-attempt brute force is one alert, not sixteen.
* POSTURE rules -> findings with a lifecycle. We only report CHANGES: a finding
  opening, getting worse, or being resolved. A missing header checked every 5
  minutes is reported once, then stays quietly open until someone fixes it.

Alert fatigue is how real incidents get missed; both paths exist to keep the
number of messages a human sees small and meaningful.
"""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from sqlite3 import Connection

from .. import db
from ..config import ALERT_COOLDOWN_MINUTES, SEVERITY_RANK
from ..models import Event
from .base import Alert, Finding, Passed, PostureRule, Rule
from .rules.email_dns import DmarcRule, DomainExpiryRule, SpfRule
from .rules.exposure import ExposedFilesRule, OpenPortsRule
from .rules.t1110_brute_force import BruteForceRule
from .rules.web_posture import SecurityHeadersRule, SiteDownRule, TlsCertificateRule

# Register rules here as you build coverage.
DETECTION_RULES: list[Rule] = [
    BruteForceRule(),
]

POSTURE_RULES: list[PostureRule] = [
    SiteDownRule(),
    TlsCertificateRule(),
    SecurityHeadersRule(),
    ExposedFilesRule(),
    OpenPortsRule(),
    SpfRule(),
    DmarcRule(),
    DomainExpiryRule(),
]


@dataclass
class FindingChange:
    kind: str           # "opened" | "worsened" | "resolved"
    finding: Finding


def _cooldown(rule: Rule) -> int:
    return ALERT_COOLDOWN_MINUTES if rule.cooldown_minutes is None else rule.cooldown_minutes


def run_detections(event: Event, conn: Connection) -> list[Alert]:
    alerts: list[Alert] = []
    now = datetime.now(timezone.utc)
    for rule in DETECTION_RULES:
        alert = rule.evaluate(event, conn)
        if alert is None:
            continue
        minutes = _cooldown(rule)
        if minutes and db.recent_alert_exists(
            conn, alert.rule_id, alert.entity, since=now - timedelta(minutes=minutes)
        ):
            continue  # already alerted on this entity recently
        alerts.append(alert)
    return alerts


def run_posture(event: Event, conn: Connection) -> list[FindingChange]:
    changes: list[FindingChange] = []
    for rule in POSTURE_RULES:
        if rule.event_type != event.event_type:
            continue
        for result in rule.assess(event):
            existing = db.get_open_finding(conn, result.rule_id, result.entity)

            if isinstance(result, Passed):
                if existing is not None:
                    db.resolve_finding(conn, existing["id"])
                    changes.append(FindingChange("resolved", _from_row(existing)))
                continue

            f = result
            if existing is None:
                db.open_finding(conn, f.rule_id, f.entity, f.severity, f.title, f.detail, f.fix)
                changes.append(FindingChange("opened", f))
            else:
                worse = SEVERITY_RANK[f.severity] > SEVERITY_RANK[existing["severity"]]
                db.refresh_finding(conn, existing["id"], f.severity, f.title, f.detail, f.fix)
                if worse:
                    changes.append(FindingChange("worsened", f))
    return changes


def _from_row(row) -> Finding:
    return Finding(
        rule_id=row["rule_id"],
        entity=row["entity"],
        severity=row["severity"],
        title=row["title"],
        detail=row["detail"],
        fix=row["fix"],
    )
