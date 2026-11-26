# security-monitor

An open-source, self-hosted security monitor for startups that can't afford a
security team. It watches your web apps and servers and tells you, in plain
language, **what is wrong and how to fix it**, on a $5–10/month server.

```
 SOURCES (push only)            COLLECTOR                                OUTPUT
 web checker  (outside-in)  ─┐                                        ┌─ instant: Slack / email
 Windows agent (Sysmon)     ─┼─► /ingest ─► append-only ─► rules ─────┤   (high + critical)
 simulator                  ─┘   per-source  SQLite      │            └─ daily digest: everything
                                 API keys                ├─ detection rules → ALERTS (attacks)
                                                         └─ posture rules   → FINDINGS (open until fixed)
```

- **Alerts** are things that *happened* (a brute-force attack). They fire once
  per incident, with a cooldown so one attack doesn't send 16 messages.
- **Findings** are things that are *wrong right now* (an expiring certificate,
  an exposed `.env`). They open once, stay open quietly, and close by
  themselves when a check sees them fixed: a checklist that turns green.
- Every alert and finding says what it means and how to fix it.

## What it checks today

| Check | Severity when it fails |
|---|---|
| `/.env`, `/.git/HEAD`, `/.git/config` downloadable | critical |
| Redis, MongoDB, Elasticsearch, Docker API open to the internet | critical |
| Postgres, MySQL, SQL Server, Memcached, RDP open to the internet | high |
| Invalid TLS certificate / expiring within 7 or 21 days | critical / high / medium |
| Site down (two failed checks in a row) | high |
| Domain expiring within 14 or 30 days (via RDAP) | high / medium |
| SPF / DMARC missing or weak (email spoofing) | high … low |
| Security headers missing, server versions leaked | medium / low |
| Brute-force logons (Windows agent; MITRE ATT&CK T1110) | high |

Linux servers, cloud accounts (AWS/GCP) and dependency scanning come next:
see [ROADMAP.md](ROADMAP.md). This covers only what it checks. It is not a
guarantee that nothing else is wrong.

## Quickstart (Docker, recommended)

```bash
python scripts/setup.py          # asks for your URLs + alert channel, writes .env with fresh keys
docker compose up -d --build
docker compose logs -f collector # findings appear here, and in Slack/email if configured

python scripts/targets.py add https://other.example.com   # change what's checked later
python scripts/targets.py list                            # (also: remove); restarts the checker
```

Only point it at sites you own or have permission to test.

## Quickstart (without Docker)

```bash
python -m venv .venv
.venv\Scripts\activate             # Linux/mac: source .venv/bin/activate
pip install -r requirements.txt
python scripts/setup.py

uvicorn collector.main:app --port 8000                # terminal 1
python agent/web_checker.py --once                    # terminal 2: checks SM_CHECK_URLS
python agent/simulate.py --failures 6                 # fires a test brute-force alert
python -m collector.digest                            # preview the daily digest
```

Current findings as JSON: `GET /findings` with your `X-API-Key` header.

## Layout

```
collector/                the API server
  main.py                 /health, /ingest, /findings; refuses to start with weak keys
  config.py               env-based config (+ .env loader)
  db.py                   SQLite (WAL): append-only events, alerts, findings
  digest.py               daily digest (also: python -m collector.digest)
  detections/
    base.py               Rule/Alert (attacks) and PostureRule/Finding (misconfig)
    engine.py             runs rules; cooldowns; finding open/worse/resolved
    rules/
      t1110_brute_force.py   ATT&CK T1110
      web_posture.py         site down, TLS, security headers
      exposure.py            exposed files, open database/admin ports
      email_dns.py           SPF, DMARC, domain expiry
  alerting/notifier.py    console + Slack + email; instant vs digest routing
agent/
  shipper.py              shared: build + POST events (outbound-only)
  web_checker.py          outside-in checks, nothing installed on the target
  windows_agent.py        Windows Security log + Sysmon
  simulate.py             synthetic events for testing
scripts/setup.py          generates .env with per-source keys
tests/                    python -m unittest discover -s tests
atomic-tests/             attack yourself to verify detections
```

## Security principles

- **Secure by default.** The collector refuses to start with a placeholder or
  short key; keys are compared in constant time; each source has its own key.
- **Agents push; the collector never dials in.** A compromised endpoint can't
  use the monitor as a pivot.
- **The event log is append-only** (enforced with SQLite triggers). Attackers
  delete logs first; make that hard.
- **Only summaries leave the box.** Alerts carry the finding and its fix, never
  raw events that might contain secrets or personal data.
- **The monitor is a high-value target.** The collector binds to localhost by
  default; put it behind TLS before accepting agents from other machines.
- **Monitoring people needs consent.** See the privacy note in
  [agent/README.md](agent/README.md).

## References

- MITRE ATT&CK: https://attack.mitre.org/
- OWASP Secure Headers: https://owasp.org/www-project-secure-headers/
- Atomic Red Team: https://github.com/redcanaryco/atomic-red-team
- Sigma: https://github.com/SigmaHQ/sigma
