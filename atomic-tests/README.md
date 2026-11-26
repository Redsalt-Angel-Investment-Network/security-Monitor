# Testing detections with Atomic Red Team

A detection you haven't tested by running the real attack is a guess. The
loop every detection engineer lives by:

```
run the attack  ->  did the alert fire?  ->  tune  ->  repeat
```

[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) is a free
library of small, precise tests mapped to MITRE ATT&CK techniques. Each
"atomic" runs one technique so you can check your coverage of exactly that
behaviour.

> Run atomics only on machines you own and can afford to get dirty — ideally a
> throwaway VM, never a production box.

## Install (PowerShell as Administrator)

```powershell
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics
```

## Run the T1110 (Brute Force) atomic

```powershell
Invoke-AtomicTest T1110 -ShowDetails   # see what each test does FIRST
Invoke-AtomicTest T1110 -TestNumbers 1 # run one
```

This generates real failed-logon events (Security 4625). With the Windows
agent running, those ship to the collector and should trip the
`T1110-auth-failure-burst` rule.

## Confirm the detection fired

```bash
# From the project root, look at the alerts table:
sqlite3 data/events.db "SELECT created_at, technique, severity, title FROM alerts ORDER BY id DESC LIMIT 5;"
```

(No `sqlite3` CLI? `python -c "import sqlite3,os;[print(r) for r in sqlite3.connect('data/events.db').execute('SELECT created_at,technique,title FROM alerts ORDER BY id DESC LIMIT 5')]"`)

## The exercise

1. Pick an ATT&CK technique you want to cover.
2. Run its atomic and capture which events it produces.
3. Write a rule in `collector/detections/rules/` that catches it.
4. Re-run the atomic and confirm the alert fires — then tune out false
   positives. Each cycle is one rep toward thinking like a detection engineer.
