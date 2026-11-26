"""Daily digest: one message a day with everything that didn't need to
interrupt anyone - open findings (worst first), what got fixed, and the last
24 hours of alerts. This is the "checklist that turns green".

The collector sends it automatically at SM_DIGEST_HOUR_UTC. To preview or send
one by hand, from the project root:
    python -m collector.digest            # print it
    python -m collector.digest --send     # print and send it
"""
import argparse
from datetime import datetime, timedelta, timezone
from typing import Optional

from . import db
from .alerting.notifier import channels, send


def build_digest(now: Optional[datetime] = None) -> Optional[str]:
    """Return the digest text, or None when there is nothing to say."""
    now = now or datetime.now(timezone.utc)
    since = now - timedelta(hours=24)
    with db.connect() as conn:
        open_findings = db.list_findings(conn, "open")
        resolved = db.list_findings(conn, None, resolved_since=since)
        alerts = db.list_alerts(conn, since)

    if not (open_findings or resolved or alerts):
        return None

    lines = [f"Security digest for {now:%Y-%m-%d}"]
    if open_findings:
        lines.append(f"\nOPEN - {len(open_findings)} thing(s) to fix, worst first:")
        for i, f in enumerate(open_findings, 1):
            lines.append(f"\n{i}. [{f['severity'].upper()}] {f['title']}  (since {f['first_seen'][:10]})")
            lines.append(f"   {f['detail']}")
            lines.append(f"   Fix: {f['fix']}")
    else:
        lines.append("\nNo open findings.")
    if resolved:
        lines.append(f"\nFIXED in the last 24h ({len(resolved)}):")
        lines.extend(f"  - {f['title']}" for f in resolved)
    if alerts:
        lines.append(f"\nALERTS in the last 24h ({len(alerts)}):")
        lines.extend(f"  - [{a['severity'].upper()}] {a['title']}" for a in alerts)
    lines.append(
        "\nThis covers only what the monitor checks - it is not a guarantee that "
        "nothing else is wrong."
    )
    return "\n".join(lines)


def send_digest() -> bool:
    text = build_digest()
    if text is None:
        return False
    print(text, flush=True)
    send(subject="Daily security digest", body=text)
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description="Preview or send the daily digest")
    parser.add_argument("--send", action="store_true", help="also deliver to Slack/email")
    args = parser.parse_args()
    db.init_db()
    if args.send:
        sent = send_digest()
        print(f"\nsent via: {', '.join(channels()) or 'console only'}" if sent else "nothing to report")
    else:
        print(build_digest() or "nothing to report")


if __name__ == "__main__":
    main()
