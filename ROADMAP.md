# Roadmap — security-monitor

**Goal:** an open-source, self-hosted security monitor that tells a startup with
no security team *what is wrong and how to fix it*, in plain language, on a
$5–10/month server.

**Who it's for:** early-stage startups with no security staff and little budget.
Every feature has to be **low-cost** (open source, one cheap VPS), **simple**
(a non-security developer can set it up and understand it), **lightweight**
(~512 MB RAM, SQLite) and **actionable** (few alerts, each with a fix).

**Priorities:** web apps and cloud accounts first, then Linux servers, then
Windows servers and laptops. Most startup breaches come from leaked secrets,
cloud misconfiguration and exposed services, and outside-in checks work even
for startups on PaaS with no server of their own.

## How this roadmap works

- **Phases end at gates.** A gate is a test with a real pilot startup. Don't
  start the next phase until the gate passes; the pilot's feedback is worth
  more than the next feature.
- **Each box is roughly one focused session** (1–2 hours). Tick boxes as you go
  and commit at the end of every session.
- **🟣 Purple-team reps** stay in: run the real attack or misconfiguration
  against your own lab and confirm the tool catches it. A detection you
  haven't tested is a guess.
- **Living docs** to keep current: `COVERAGE.md` (what we detect, mapped to
  MITRE ATT&CK), `THREAT_MODEL.md` (threats to the monitor itself),
  `RUNBOOKS.md` (what to do when each alert fires).

## At a glance

| Phase | Delivers | Estimate | Gate to pass |
|---|---|---|---|
| 0 ✅ | Working pipeline, web/TLS/header checks, alert cooldown | done | — |
| 1 | Useful to one pilot startup | 3–4 weeks | A pilot runs it for 2 weeks and fixes at least one real finding |
| 2 | Linux servers + PaaS logs | 3 weeks | Pilot's servers report in; target ≤ 1 false alert a week |
| 3 | Cloud accounts + dependencies | 2–3 weeks | Cloud findings appear in plain language for the pilot |
| 4 | Self-host ready | 3 weeks | A new user installs it from the README in under 30 minutes |
| 5 | Broaden | later | — |

Estimates assume part-time work.

---

## Phase 0 — Pipeline works ✅

- [x] Agent → collector (FastAPI) → append-only SQLite → rules → alerts
- [x] T1110 brute-force detection, tested with the simulator
- [x] Windows agent (Security log + Sysmon)
- [x] Web checker: uptime, TLS validity/expiry, security headers, leaky
      `Server`/`X-Powered-By` headers
- [x] Alert de-duplication (cooldown per rule + entity)
- [x] Automated tests (`python -m unittest discover -s tests`)

## Phase 1 — Useful to one pilot startup

**Secure by default** (the monitor is the most valuable target in the company)
- [x] Collector refuses to start with the default or a short API key
- [x] Constant-time key comparison (`hmac.compare_digest`)
- [x] Per-source API keys, so one leaked key can be revoked alone
- [ ] Day: `THREAT_MODEL.md` — STRIDE over the collector; pick the top risk

**Findings: a checklist that goes green**
- [x] Findings table: posture problems stay *open* until the check passes,
      then close automatically ("resolved" notice)
- [x] Notify only when a finding opens or gets worse, never on every check
- [x] Every rule carries plain-language *what this means* + *how to fix*

**New outside-in checks**
- [x] Exposed secrets: `/.env`, `/.git/HEAD`, `/.git/config` reachable
      (content-validated, so SPA catch-all pages don't cause false alarms)
- [x] Databases / admin services open to the internet (Postgres, MySQL, Mongo,
      Redis, Elasticsearch, Memcached, SQL Server, Docker API, RDP)
- [x] Email spoofing: SPF and DMARC records
- [x] Domain expiry (via RDAP; not every country TLD supports it)
- [ ] 🟣 Purple rep: put a dummy `.env` on a dev site and open Redis on a lab
      VM; confirm both findings fire, then fix and watch them resolve

**Delivery**
- [x] Instant alerts for high/critical (Slack, email); daily digest for the rest
- [x] Docker Compose: collector + web checker in one command
- [x] `scripts/setup.py`: generates keys and `.env` by asking a few questions
- [ ] Day: `RUNBOOKS.md` — one paragraph per rule: confirm it's real, then fix
- [ ] **Find a pilot startup.** Install it with them; write down every
      question they ask — each one is a docs or UX bug

**Gate 1:** a pilot runs it for 2 weeks and fixes at least one real finding.

## Phase 2 — Linux servers + PaaS

- [ ] Linux agent: read `journald` / `/var/log/auth.log` → SSH success/failure,
      `sudo`, new users/groups; ship like the Windows agent
- [ ] T1110 works unchanged on SSH failures (normalized schema pays off)
- [ ] Linux posture: `sshd` password auth / root login enabled, pending
      security updates, unattended-upgrades off
- [ ] Detection: successful login from a never-seen IP for that user (T1078);
      tune with an allowlist and a warm-up period
- [ ] Log-drain endpoint for PaaS (Vercel/Render/Heroku) → `http_request` events
- [ ] Web rules: 401/403 spike per IP (credential stuffing), path-traversal and
      SQLi patterns in URLs
- [ ] 🟣 Purple reps: SSH brute force (`hydra` against a lab VM), then a
      successful login from a new IP; `' OR 1=1` against a dev endpoint
- [ ] Update `COVERAGE.md`

**Gate 2:** the pilot's servers report in, with a target of ≤ 1 false alert a week.

## Phase 3 — Cloud accounts + dependencies

- [ ] Run [Prowler](https://github.com/prowler-cloud/prowler) (AWS first) with
      a read-only `SecurityAudit` role; import its JSON
- [ ] Map Prowler output to our top ~15 cloud findings with plain-language
      fixes: root/IAM MFA, old access keys, public buckets, `0.0.0.0/0` on
      22/3389/DB ports, CloudTrail off, default VPC exposure
- [ ] Dependencies and containers: [Trivy](https://github.com/aquasecurity/trivy)
      or [OSV](https://osv.dev/) → findings for critical/high CVEs only
- [ ] Secrets in git history: [gitleaks](https://github.com/gitleaks/gitleaks)
- [ ] 🟣 Purple rep: make a test bucket public in a sandbox account; confirm the
      finding fires and resolves

**Gate 3:** cloud findings appear in plain language for the pilot's account.

## Phase 4 — Self-host ready

- [ ] Small web UI (FastAPI + HTMX): open findings, recent alerts, agent
      health — with login
- [ ] TLS for the collector (Caddy in the Compose file)
- [ ] Agents buffer to disk when the collector is down, resend later
- [ ] Missing-heartbeat alerts (a silent agent may be a stopped agent)
- [ ] Retention: monthly archive files instead of row deletes (the events
      table is append-only); configurable retention period
- [ ] Hash-chain the event log so edited rows are detectable
- [ ] Backup and restore of the monitor itself, documented and tested
- [ ] Install docs; re-threat-model and write down residual risks honestly

**Gate 4:** a new user installs it from the README in under 30 minutes.

## Phase 5 — Broaden (later)

- [ ] [Sigma](https://github.com/SigmaHQ/sigma) rule loader; adopt a few
      community rules
- [ ] Windows server polish; Linux and Windows on the same rules
- [ ] Laptop posture only (disk encryption, OS updates, firewall, screen lock),
      with a clear consent policy
- [ ] Decide on a hosted option — and who would operate it securely

---

## Risks we design around

| Risk | Mitigation |
|---|---|
| The monitor becomes the target | Secure defaults, per-source keys, UI login, TLS, read-only cloud roles |
| Alert fatigue | Few high-confidence rules, cooldowns, findings that close, daily digest |
| Silent agent | Missing-heartbeat alerts; outside ping on the collector |
| Self-hosted install rots | One-command install and update |
| Storage grows forever | Monthly archives + retention setting |
| False sense of security | Say clearly what isn't covered; never show "you're secure" |
| Tool pointed at others' systems | Verify domain ownership (DNS TXT) before active checks |
| Personal data in logs | Collect the minimum, retention limits, local data-protection law |

## References

- MITRE ATT&CK — https://attack.mitre.org/
- Atomic Red Team — https://github.com/redcanaryco/atomic-red-team
- OWASP Top 10 — https://owasp.org/www-project-top-ten/
- OWASP Secure Headers — https://owasp.org/www-project-secure-headers/
- Sigma — https://github.com/SigmaHQ/sigma
