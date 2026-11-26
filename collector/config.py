"""Collector configuration, loaded from environment variables.

Keeping config in one place (and out of the code) is a basic security habit:
secrets like API keys and webhook URLs are never hard-coded or committed. This
is the "12-factor" config idea - the same code runs in dev and prod, only the
environment differs.
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)


def _load_dotenv() -> None:
    """Minimal .env loader so you don't have to export vars by hand in dev.

    Real values in .env take a back seat to anything already set in the real
    environment (os.environ wins), which is what you want in production.
    """
    env_file = BASE_DIR / ".env"
    if not env_file.exists():
        return
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip())


_load_dotenv()

# SQLite file that holds the (append-only) event log.
DB_PATH = os.environ.get("SM_DB_PATH") or str(DATA_DIR / "events.db")

# --- Agent authentication -------------------------------------------------
# Agents send a key in the X-API-Key header. Give each source its OWN key so a
# leaked key can be revoked for one machine without touching the others:
#   SM_API_KEYS=webcheck=<key>,office-pc=<key>
# A single SM_API_KEY is still accepted (named "default") for quick starts.
INSECURE_DEFAULT_KEY = "dev-insecure-key-change-me"
MIN_KEY_LENGTH = 24


def _parse_keys(spec: str) -> dict[str, str]:
    keys: dict[str, str] = {}
    for item in spec.split(","):
        name, sep, key = item.strip().partition("=")
        if sep and name.strip() and key.strip():
            keys[name.strip()] = key.strip()
    return keys


API_KEYS: dict[str, str] = _parse_keys(os.environ.get("SM_API_KEYS", ""))
if os.environ.get("SM_API_KEY"):
    API_KEYS.setdefault("default", os.environ["SM_API_KEY"])


def config_problems() -> list[str]:
    """Reasons the collector must NOT start. Secure by default: a monitoring
    server reachable with a guessable key is worse than no monitor at all,
    because it hands an attacker a trusted way to feed (or flood) your alerts."""
    problems = []
    if not API_KEYS:
        problems.append("no API key set: run `python scripts/setup.py` or set SM_API_KEYS")
    for name, key in API_KEYS.items():
        if key == INSECURE_DEFAULT_KEY or key.startswith("change-me"):
            problems.append(f"API key '{name}' is a placeholder value")
        elif len(key) < MIN_KEY_LENGTH:
            problems.append(f"API key '{name}' is shorter than {MIN_KEY_LENGTH} characters")
    return problems


# --- Alerting ---------------------------------------------------------------
SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# Findings/alerts at or above this severity are sent immediately; the rest
# wait for the daily digest. Fewer interruptions = alerts people still read.
INSTANT_MIN_SEVERITY = os.environ.get("SM_INSTANT_MIN_SEVERITY", "high").lower()
if INSTANT_MIN_SEVERITY not in SEVERITY_RANK:
    INSTANT_MIN_SEVERITY = "high"

# Hour of day (UTC, 0-23) to send the daily digest. Empty = no scheduled digest.
_digest_hour = os.environ.get("SM_DIGEST_HOUR_UTC", "7").strip()
DIGEST_HOUR_UTC = int(_digest_hour) if _digest_hour.isdigit() else None

# Optional Slack Incoming Webhook.
SLACK_WEBHOOK_URL = os.environ.get("SM_SLACK_WEBHOOK_URL", "")

# Optional email (any SMTP provider; STARTTLS on port 587 by default).
SMTP_HOST = os.environ.get("SM_SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SM_SMTP_PORT") or 587)
SMTP_USER = os.environ.get("SM_SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SM_SMTP_PASSWORD", "")
EMAIL_FROM = os.environ.get("SM_EMAIL_FROM", "") or SMTP_USER
EMAIL_TO = [a.strip() for a in os.environ.get("SM_EMAIL_TO", "").split(",") if a.strip()]

# Window (minutes) in which a repeat ALERT for the same rule + entity is
# suppressed. Individual rules can override it (see Rule.cooldown_minutes).
# (Findings don't need this: they notify only when they open or get worse.)
ALERT_COOLDOWN_MINUTES = int(os.environ.get("SM_ALERT_COOLDOWN_MINUTES") or 30)
