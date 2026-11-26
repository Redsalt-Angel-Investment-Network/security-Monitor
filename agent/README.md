# Endpoint agent

Two ways to feed the collector:

- **`simulate.py`** — sends synthetic events. No admin, no Sysmon, works
  anywhere. Use it to learn the pipeline and to test detections.
- **`windows_agent.py`** — the real thing: reads the Windows Event Log and
  Sysmon, normalizes, and ships to the collector.

Both are **outbound-only** — they POST to the collector and nothing ever
connects back in.

## Running the simulator

```bash
python agent/simulate.py --failures 6 --user victim
```

## Running the Windows agent

1. Install the dependency (into the project venv):
   ```bash
   pip install pywin32
   ```
2. Open **PowerShell as Administrator** — the Security channel is off-limits to
   a normal user.
3. From the project root:
   ```bash
   python agent/windows_agent.py --once
   ```
   `--once` polls a single time and exits (good for testing). Drop it to poll
   continuously (`--interval` seconds, default 30).

Point it elsewhere with `--collector http://host:8000` and `--api-key ...`, or
the `SM_COLLECTOR_URL` / `SM_API_KEY` environment variables.

## Add Sysmon (strongly recommended)

The raw Security log is thin. [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon)
(Sysinternals) records process creation with full command lines and hashes,
network connections, image loads, and more — the telemetry real endpoint
detection is built on. The agent reads the `Microsoft-Windows-Sysmon/Operational`
channel automatically once Sysmon is installed; until then that channel is
skipped.

```powershell
# Download Sysmon, then install with a good community config:
# (SwiftOnSecurity's config is the usual starting point)
sysmon64.exe -accepteula -i sysmonconfig.xml
```

Learning exercise: install Sysmon, run `windows_agent.py`, launch a few
programs, and watch `process_create` events arrive with their command lines.

## ⚠️ Privacy / consent

Endpoint agents see a lot — logons, processes, command lines. Before putting
this on anyone else's machine at redsalt, get sign-off from whoever owns
HR/policy and tell staff what's collected and why. This is a legal and ethical
requirement, not just a technical one.
