"""Windows endpoint agent.

Reads security-relevant events from the Windows Event Log and ships them,
normalized, to the collector. Two channels are polled:

  * "Security"                               (built in; needs Administrator)
        4625  failed logon
        4624  successful logon
        4688  process creation
  * "Microsoft-Windows-Sysmon/Operational"   (only if Sysmon is installed)
        1     process create  (rich: command line, hashes, parent image)
        3     network connect

Sysmon gives far richer, harder-to-evade telemetry than the raw Security log,
which is why real endpoint detection leans on it. See agent/README.md to
install it. If Sysmon isn't present, that channel is simply skipped.

The agent is OUTBOUND-ONLY - it never listens for connections.

Run from the project root in an ELEVATED PowerShell:
    python agent/windows_agent.py --once      # one poll then exit (for testing)
    python agent/windows_agent.py             # poll forever

Requires: pip install pywin32
"""
from __future__ import annotations

import argparse
import os
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

import win32evtlog  # from pywin32

from shipper import DEFAULT_API_KEY, DEFAULT_COLLECTOR_URL, Event, hostname, ship

# Windows renders event XML in this namespace.
_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

# (channel, EventID) -> our normalized event_type.
_TYPES = {
    ("Security", 4625): "authentication_failure",
    ("Security", 4624): "authentication_success",
    ("Security", 4688): "process_create",
    ("Microsoft-Windows-Sysmon/Operational", 1): "process_create",
    ("Microsoft-Windows-Sysmon/Operational", 3): "network_connect",
}

# Which event IDs to pull from each channel.
_CHANNELS = {
    "Security": [4625, 4624, 4688],
    "Microsoft-Windows-Sysmon/Operational": [1, 3],
}

AGENT_ID = os.environ.get("SM_AGENT_ID") or f"win-{hostname()}"


def _parse(event_xml: str) -> dict:
    """Pull System fields + EventData name/value pairs out of event XML."""
    root = ET.fromstring(event_xml)
    system = root.find("e:System", _NS)
    fields: dict = {
        "EventID": int(system.find("e:EventID", _NS).text),
        "Channel": system.find("e:Channel", _NS).text,
        "TimeCreated": system.find("e:TimeCreated", _NS).get("SystemTime"),
    }
    record = system.find("e:EventRecordID", _NS)
    fields["EventRecordID"] = record.text if record is not None else None
    for data in root.findall(".//e:EventData/e:Data", _NS):
        name = data.get("Name")
        if name:
            fields[name] = data.text or ""
    return fields


def _blank(value) -> bool:
    return value in (None, "", "-")


def _to_event(fields: dict) -> Event | None:
    event_type = _TYPES.get((fields.get("Channel"), fields.get("EventID")))
    if event_type is None:
        return None
    # Field names vary a little by channel/ID, so try sensible fallbacks.
    user = fields.get("TargetUserName") or fields.get("User") or fields.get("SubjectUserName")
    source_ip = fields.get("IpAddress") or fields.get("SourceIp")
    process = fields.get("NewProcessName") or fields.get("Image")
    is_sysmon = "Sysmon" in (fields.get("Channel") or "")
    return Event(
        agent_id=AGENT_ID,
        host=hostname(),
        source="sysmon" if is_sysmon else "windows_security",
        event_type=event_type,
        timestamp=fields.get("TimeCreated") or datetime.now(timezone.utc).isoformat(),
        user=None if _blank(user) else user,
        source_ip=None if _blank(source_ip) or source_ip in ("::1", "127.0.0.1") else source_ip,
        process=None if _blank(process) else process,
        message=f"{fields.get('Channel')} EventID {fields.get('EventID')}",
        raw=fields,
    )


def _query(channel: str, event_ids: list[int], minutes: int):
    """Yield recent event XML strings for a channel, filtered to event_ids.

    The XPath filter asks the Event Log to return only the IDs we care about,
    created within the last `minutes` - so we don't haul the whole log over.
    """
    id_filter = " or ".join(f"EventID={i}" for i in event_ids)
    window_ms = minutes * 60 * 1000
    xpath = f"*[System[({id_filter}) and TimeCreated[timediff(@SystemTime) <= {window_ms}]]]"
    try:
        handle = win32evtlog.EvtQuery(
            channel, win32evtlog.EvtQueryReverseDirection, xpath, None
        )
    except Exception as exc:
        # Channel missing (e.g. Sysmon not installed) or access denied.
        print(f"[agent] cannot query {channel!r}: {exc}")
        return
    while True:
        events = win32evtlog.EvtNext(handle, 20)
        if not events:
            break
        for handle_ev in events:
            yield win32evtlog.EvtRender(handle_ev, win32evtlog.EvtRenderEventXml)


def poll_once(collector: str, api_key: str, minutes: int, seen: set) -> None:
    batch: list[Event] = []
    for channel, ids in _CHANNELS.items():
        for xml_str in _query(channel, ids, minutes):
            fields = _parse(xml_str)
            # De-dupe across overlapping polls using the unique record id.
            record = fields.get("EventRecordID") or f"{channel}:{fields.get('TimeCreated')}"
            key = (channel, record)
            if key in seen:
                continue
            seen.add(key)
            event = _to_event(fields)
            if event is not None:
                batch.append(event)
    if batch:
        ship(batch, collector, api_key)
    else:
        print("[agent] no new events this poll")


def main() -> None:
    parser = argparse.ArgumentParser(description="Windows endpoint agent")
    parser.add_argument("--collector", default=os.environ.get("SM_COLLECTOR_URL", DEFAULT_COLLECTOR_URL))
    parser.add_argument("--api-key", default=os.environ.get("SM_API_KEY", DEFAULT_API_KEY))
    parser.add_argument("--interval", type=int, default=30, help="seconds between polls")
    parser.add_argument("--lookback", type=int, default=5, help="minutes of history per poll")
    parser.add_argument("--once", action="store_true", help="poll once then exit")
    args = parser.parse_args()

    seen: set = set()
    print(f"[agent] {AGENT_ID} -> {args.collector}  (Ctrl+C to stop)")
    while True:
        try:
            poll_once(args.collector, args.api_key, args.lookback, seen)
        except Exception as exc:
            print(f"[agent] poll error: {exc}")
        if args.once:
            break
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
