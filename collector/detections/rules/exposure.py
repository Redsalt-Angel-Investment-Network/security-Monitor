"""Exposure rules: things that should never be reachable from the internet.

These are among the most common ways small companies actually get breached,
and bots scan the whole internet for them around the clock:

* Exposed files - `/.env` (every secret the app has) and `/.git/` (the full
  source code and history, including secrets that were "deleted" later).
* Open database / admin ports - Redis, MongoDB, Elasticsearch, Postgres...
  exposed databases are routinely wiped and held for ransom within hours.

The checker only reports what it could reach; these rules say how bad it is
and what to do.
"""
from ...models import Event
from ..base import Finding, Passed, PostureRule, Result

FILE_ADVICE = {
    "/.env": (
        "This file usually holds database passwords, API keys and secret keys. "
        "1) Block it now in your web server (or move .env out of the public web root). "
        "2) ROTATE every secret in it - assume it has already been downloaded; bots "
        "request /.env on every site, constantly. 3) Check your cloud/billing and "
        "database logs for use of those credentials."
    ),
    "/.git/HEAD": (
        "Your git repository is downloadable, which means the full source code and "
        "its history - including any secret ever committed. 1) Block /.git in the web "
        "server, or deploy without the .git folder. 2) Rotate any secret that was ever "
        "committed (scan history with gitleaks)."
    ),
}
FILE_ADVICE["/.git/config"] = FILE_ADVICE["/.git/HEAD"]

# port -> (service, severity)
PORT_INFO = {
    2375: ("Docker API (unencrypted)", "critical"),  # = root on the host
    6379: ("Redis", "critical"),                     # often no password at all
    9200: ("Elasticsearch", "critical"),             # often no password at all
    27017: ("MongoDB", "critical"),
    11211: ("Memcached", "high"),
    5432: ("PostgreSQL", "high"),
    3306: ("MySQL/MariaDB", "high"),
    1433: ("SQL Server", "high"),
    3389: ("Remote Desktop (RDP)", "high"),
}


class ExposedFilesRule(PostureRule):
    event_type = "exposed_files"
    rule_id = "web-exposed-file"

    def assess(self, event: Event) -> list[Result]:
        origin = event.raw.get("target", "?")
        exposed = set(event.raw.get("exposed", []))
        results: list[Result] = []
        for path in event.raw.get("checked", []):
            entity = f"{origin}{path}"
            if path not in exposed:
                results.append(Passed(self.rule_id, entity))
                continue
            results.append(Finding(
                rule_id=self.rule_id,
                entity=entity,
                severity="critical",
                title=f"Sensitive file exposed: {entity}",
                detail=f"Anyone on the internet can download {entity}.",
                fix=FILE_ADVICE.get(path, "Block this path in your web server and rotate any secrets in it."),
            ))
        return results


class OpenPortsRule(PostureRule):
    event_type = "port_check"
    rule_id = "net-open-port"

    def assess(self, event: Event) -> list[Result]:
        host = event.raw.get("target", "?")
        ip = event.raw.get("ip", "")
        open_ports = set(event.raw.get("open", []))
        results: list[Result] = []
        for port in event.raw.get("checked", []):
            entity = f"{host}:{port}"
            if port not in open_ports:
                results.append(Passed(self.rule_id, entity))
                continue
            service, severity = PORT_INFO.get(port, (f"port {port}", "high"))
            if port == 3389:
                fix = (
                    "Remote Desktop is one of the most attacked services there is. Close "
                    "port 3389 to the internet in the firewall / cloud security group and "
                    "reach the machine over a VPN instead."
                )
            else:
                fix = (
                    f"{service} should never be reachable from the internet. Close port "
                    f"{port} in the firewall / cloud security group so only your app servers "
                    "(or a VPN) can reach it, and make sure it requires a strong password. "
                    "If it was open without a password, check its data for tampering."
                )
            results.append(Finding(
                rule_id=self.rule_id,
                entity=entity,
                severity=severity,
                title=f"{service} open to the internet on {host}",
                detail=f"{host} ({ip}) accepts connections on port {port} from where the checker runs.",
                fix=fix,
            ))
        return results
