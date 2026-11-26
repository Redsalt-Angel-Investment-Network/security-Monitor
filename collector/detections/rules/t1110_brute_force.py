"""T1110 - Brute Force (repeated password guessing against an account).

ATT&CK: https://attack.mitre.org/techniques/T1110/

Fires when a single account sees too many authentication failures inside a
short window. This is the canonical first detection and a clean template for
any "threshold" rule: pick an event, a count, and a time window.

Test it with the simulator (agent/simulate.py) or a real Atomic Red Team
T1110 test - see atomic-tests/README.md.
"""
from datetime import timedelta
from sqlite3 import Connection
from typing import Optional

from ... import db
from ...models import Event
from ..base import Alert, Rule

# Tunables. Start loose, then tighten once you know your environment's normal
# baseline. Too sensitive = alert fatigue; too loose = you miss slow attacks.
FAILURE_THRESHOLD = 5          # this many failures...
WINDOW_MINUTES = 5             # ...within this many minutes


class BruteForceRule(Rule):
    rule_id = "T1110-auth-failure-burst"
    technique = "T1110"
    severity = "high"

    def evaluate(self, event: Event, conn: Connection) -> Optional[Alert]:
        # Only authentication failures tied to a named account are of interest.
        if event.event_type != "authentication_failure" or not event.user:
            return None

        since = event.timestamp - timedelta(minutes=WINDOW_MINUTES)
        failures = db.count_recent(
            conn, "authentication_failure", since, user=event.user
        )
        if failures < FAILURE_THRESHOLD:
            return None

        return Alert(
            rule_id=self.rule_id,
            technique=self.technique,
            severity=self.severity,
            entity=event.user,
            title=f"Possible brute force against '{event.user}'",
            detail=(
                f"{failures} authentication failures for account '{event.user}' "
                f"within {WINDOW_MINUTES} min (threshold {FAILURE_THRESHOLD}). "
                f"Latest from host={event.host} source_ip={event.source_ip}."
            ),
            fix=(
                "1) Check whether the account owner was simply mistyping a password. "
                "2) If not, block the source IP (firewall or fail2ban) and make sure the "
                "account has a strong, unique password and MFA. "
                "3) Look for a SUCCESSFUL logon for this account afterwards - that would "
                "mean the attacker got in."
            ),
        )
