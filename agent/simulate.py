"""Simulator "agent" - exercises the whole pipeline without admin rights or
Sysmon, so you can watch a detection fire on day one.

It sends a burst of fake authentication failures for one account, which should
trip the T1110 brute-force rule in the collector.

Usage (collector must already be running):
    python agent/simulate.py --failures 6 --user victim
"""
import argparse
import os

from shipper import DEFAULT_API_KEY, DEFAULT_COLLECTOR_URL, Event, hostname, ship


def main() -> None:
    parser = argparse.ArgumentParser(description="Send synthetic events to the collector")
    parser.add_argument("--collector", default=os.environ.get("SM_COLLECTOR_URL", DEFAULT_COLLECTOR_URL))
    parser.add_argument("--api-key", default=os.environ.get("SM_API_KEY", DEFAULT_API_KEY))
    parser.add_argument("--user", default="victim")
    parser.add_argument("--source-ip", default="203.0.113.10")
    parser.add_argument("--failures", type=int, default=6, help="how many failed logons to send")
    args = parser.parse_args()

    events = [
        Event(
            agent_id="simulator",
            host=hostname(),
            source="simulator",
            event_type="authentication_failure",
            user=args.user,
            source_ip=args.source_ip,
            message=f"Simulated failed logon for {args.user}",
            raw={"EventID": 4625, "simulated": True, "attempt": i + 1},
        )
        for i in range(args.failures)
    ]
    ship(events, args.collector, args.api_key)


if __name__ == "__main__":
    main()
