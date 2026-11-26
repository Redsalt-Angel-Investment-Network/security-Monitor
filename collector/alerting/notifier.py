"""Alert delivery: console always; Slack and/or email when configured.

Routing keeps interruptions rare, because a tool that pings all day gets muted:
  * attack alerts and findings at/above SM_INSTANT_MIN_SEVERITY (default
    "high") are sent IMMEDIATELY;
  * everything else, and "resolved" notices, wait for the daily digest
    (collector/digest.py).

We send short summaries plus the fix - never raw events, which may contain
secrets or personal data. Deciding what leaves the system is part of the job.
"""
import json
import smtplib
import urllib.request
from email.message import EmailMessage

from .. import config
from ..config import SEVERITY_RANK
from ..detections.base import Alert
from ..detections.engine import FindingChange

_TAG = {"low": "[.]", "medium": "[*]", "high": "[!]", "critical": "[!!]"}


def _is_instant(severity: str) -> bool:
    return SEVERITY_RANK.get(severity, 0) >= SEVERITY_RANK[config.INSTANT_MIN_SEVERITY]


def notify_alert(alert: Alert) -> None:
    print(
        f"{_TAG.get(alert.severity, '[?]')} {alert.severity.upper():8} {alert.technique:7} "
        f"{alert.rule_id}: {alert.title}\n        {alert.detail}",
        flush=True,
    )
    if _is_instant(alert.severity):
        send(
            subject=f"[{alert.severity.upper()}] {alert.title}",
            body=f"{alert.detail}\n\nWhat to do: {alert.fix}\n\n(ATT&CK {alert.technique})",
        )


def notify_finding(change: FindingChange) -> None:
    f = change.finding
    if change.kind == "resolved":
        print(f"[ok] RESOLVED  {f.rule_id}: {f.title}", flush=True)
        return  # good news goes in the digest; no need to interrupt anyone
    verb = "NEW" if change.kind == "opened" else "WORSE"
    print(
        f"{_TAG.get(f.severity, '[?]')} {f.severity.upper():8} {verb:5} {f.rule_id}: {f.title}\n"
        f"        {f.detail}",
        flush=True,
    )
    if _is_instant(f.severity):
        send(
            subject=f"[{f.severity.upper()}] {f.title}",
            body=f"{f.detail}\n\nWhat to do: {f.fix}",
        )


def channels() -> list[str]:
    out = []
    if config.SLACK_WEBHOOK_URL:
        out.append("slack")
    if config.SMTP_HOST and config.EMAIL_TO:
        out.append("email")
    return out


def send(subject: str, body: str) -> None:
    """Deliver to every configured channel. Never raises: alerting must not
    break ingestion."""
    if config.SLACK_WEBHOOK_URL:
        _post_slack(f"*{subject}*\n{body}")
    if config.SMTP_HOST and config.EMAIL_TO:
        _send_email(subject, body)


def _post_slack(text: str) -> None:
    req = urllib.request.Request(
        config.SLACK_WEBHOOK_URL,
        data=json.dumps({"text": text}).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        urllib.request.urlopen(req, timeout=10)
    except Exception as exc:
        print(f"[alerting] Slack delivery failed: {exc}", flush=True)


def _send_email(subject: str, body: str) -> None:
    msg = EmailMessage()
    msg["Subject"] = f"[security-monitor] {subject}"
    msg["From"] = config.EMAIL_FROM
    msg["To"] = ", ".join(config.EMAIL_TO)
    msg.set_content(body)
    try:
        with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=15) as smtp:
            smtp.starttls()  # never send credentials or alerts in clear text
            if config.SMTP_USER:
                smtp.login(config.SMTP_USER, config.SMTP_PASSWORD)
            smtp.send_message(msg)
    except Exception as exc:
        print(f"[alerting] email delivery failed: {exc}", flush=True)
