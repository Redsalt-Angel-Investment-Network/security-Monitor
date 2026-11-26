"""Web posture checker - an "agentless" agent for your public sites and APIs.

Most small companies are breached through what faces the internet, not their
laptops. This checker looks at your sites from the outside, the way an
attacker's scanner would, and ships what it finds to the collector:

  every round (default 5 min)
    http_check     is it up? status code + response time
    tls_check      is the certificate valid, and how long until it expires?
    header_check   are the standard security headers set? leaking versions?
    exposed_files  can anyone download /.env or /.git/ ?
  hourly
    port_check     are databases / admin services open to the internet?
  every 6 hours / daily
    email_dns      SPF + DMARC (stops others sending email as you)
    domain_check   when does the domain registration expire?

Nothing is installed on the target - it only makes ordinary requests, so run
it against sites YOU own or have permission to test. Like every agent here it
is OUTBOUND-ONLY; the collector judges the results.

Usage (collector must be running):
    python agent/web_checker.py --url https://example.com --once
    python agent/web_checker.py --url https://app.example.com --url https://api.example.com
    # or set SM_CHECK_URLS=https://a.com,https://b.com (and optionally SM_CHECK_DOMAINS)
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import socket
import ssl
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import urlsplit

from shipper import DEFAULT_API_KEY, DEFAULT_COLLECTOR_URL, Event, hostname, ship

AGENT_ID = os.environ.get("SM_AGENT_ID") or f"webcheck-{hostname()}"
USER_AGENT = "security-monitor-webcheck/0.2"
TIMEOUT = 10

# Header -> why it matters.
SECURITY_HEADERS = {
    "strict-transport-security": "forces HTTPS, defeats SSL-stripping",
    "content-security-policy": "restricts script sources - the main XSS backstop",
    "x-content-type-options": "stops MIME-sniffing ('nosniff')",
    "x-frame-options": "blocks clickjacking (or use CSP frame-ancestors)",
    "referrer-policy": "stops URLs (and tokens in them) leaking to other sites",
}
# Headers that advertise your stack to attackers.
LEAKY_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version")

# Files that must never be public. Each is validated by content (below).
SENSITIVE_PATHS = ("/.env", "/.git/HEAD", "/.git/config")

# Services that should never face the internet (names/severity live in the
# collector's exposure rule).
RISKY_PORTS = (2375, 6379, 9200, 27017, 11211, 5432, 3306, 1433, 3389)

# Second-level labels used under country TLDs (example.co.ug, example.co.uk).
_SLD = {"co", "com", "org", "net", "ac", "gov", "edu", "or", "ne", "go", "sc", "me"}


# --- HTTP / TLS -------------------------------------------------------------

def tls_context() -> ssl.SSLContext:
    """Verify certs against Mozilla's CA bundle (certifi) when available.

    Why not just the OS store? Windows downloads root CAs lazily, the first
    time a *browser* needs one, so Python often sees only a few dozen roots and
    perfectly valid sites fail verification. A checker that cries "invalid
    certificate!" at healthy sites is worse than none - it trains people to
    ignore it. certifi is the same root list Firefox ships.
    """
    try:
        import certifi
    except ImportError:
        return ssl.create_default_context()
    return ssl.create_default_context(cafile=certifi.where())


def fetch(url: str) -> tuple[int | None, dict[str, str], float, str | None]:
    """GET url -> (status, lower-cased headers, latency_ms, error)."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    start = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=tls_context()) as resp:
            status, headers = resp.status, resp.headers
    except urllib.error.HTTPError as exc:  # 4xx/5xx still has headers
        status, headers = exc.code, exc.headers
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, ssl.SSLCertVerificationError):
            # Tagged so the TLS rule owns it (one problem = one alert).
            msg = exc.reason.verify_message or str(exc.reason)
            return None, {}, (time.monotonic() - start) * 1000, f"TLS: {msg}"
        return None, {}, (time.monotonic() - start) * 1000, f"URLError: {exc.reason}"
    except Exception as exc:
        return None, {}, (time.monotonic() - start) * 1000, f"{type(exc).__name__}: {exc}"
    latency = (time.monotonic() - start) * 1000
    return status, {k.lower(): v for k, v in headers.items()}, latency, None


def analyze_headers(url: str, headers: dict[str, str]) -> dict:
    """Pure function: which security headers are missing / which leak info."""
    is_https = urlsplit(url).scheme == "https"
    missing = []
    for name in SECURITY_HEADERS:
        if name in headers:
            continue
        if name == "strict-transport-security" and not is_https:
            continue  # HSTS is only honoured over HTTPS
        if name == "x-frame-options" and "frame-ancestors" in headers.get(
            "content-security-policy", ""
        ):
            continue  # modern equivalent is present
        missing.append(name)

    leaky = {}
    for name in LEAKY_HEADERS:
        value = headers.get(name)
        if not value:
            continue
        # A bare "nginx" or "cloudflare" is fine; a version number is not.
        if name != "server" or re.search(r"\d", value):
            leaky[name] = value
    return {"missing": missing, "leaky": leaky}


def check_tls(host: str, port: int = 443) -> dict:
    ctx = tls_context()
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                version = tls.version()
    except ssl.SSLCertVerificationError as exc:
        return {"ok": False, "error_kind": "verify", "error": exc.verify_message or str(exc)}
    except Exception as exc:
        return {"ok": False, "error_kind": "connect", "error": f"{type(exc).__name__}: {exc}"}

    expires = ssl.cert_time_to_seconds(cert["notAfter"])
    issuer = dict(item[0] for item in cert.get("issuer", ()))
    return {
        "ok": True,
        "days_left": int((expires - time.time()) // 86400),
        "not_after": cert["notAfter"],
        "issuer": issuer.get("organizationName") or issuer.get("commonName"),
        "tls_version": version,
    }


# --- exposed files ------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None  # a redirect means "not served here" - don't follow it


def fetch_small(url: str, limit: int = 4096) -> tuple[int | None, str, str]:
    """GET without following redirects -> (status, content-type, first bytes)."""
    opener = urllib.request.build_opener(
        _NoRedirect, urllib.request.HTTPSHandler(context=tls_context())
    )
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with opener.open(req, timeout=TIMEOUT) as resp:
            body = resp.read(limit).decode("utf-8", "replace")
            return resp.status, resp.headers.get("content-type", ""), body
    except urllib.error.HTTPError as exc:
        return exc.code, "", ""
    except Exception:
        return None, "", ""


def looks_exposed(path: str, status: int | None, content_type: str, body: str) -> bool:
    """Pure function: is this response really the sensitive file?

    Many modern sites answer EVERY path with 200 and their HTML app shell, so a
    status code alone would flag every single-page app. We check the content.
    """
    if status != 200 or "html" in content_type.lower() or body.lstrip().startswith("<"):
        return False
    if path == "/.env":
        assignments = re.findall(r"^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=", body, re.M)
        return len(assignments) >= 2
    if path == "/.git/HEAD":
        text = body.strip()
        return text.startswith("ref: refs/") or bool(re.fullmatch(r"[0-9a-f]{40}", text))
    if path == "/.git/config":
        return "[core]" in body
    return False


def check_exposed_files(origin: str) -> dict:
    checked, exposed = [], []
    for path in SENSITIVE_PATHS:
        status, ctype, body = fetch_small(origin + path)
        if status is None:
            continue  # couldn't tell - don't claim it's safe
        checked.append(path)
        if looks_exposed(path, status, ctype, body):
            exposed.append(path)
    return {"checked": checked, "exposed": exposed}


# --- open ports ---------------------------------------------------------------

def _is_public(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return addr.is_global


def _port_open(ip: str, port: int) -> bool:
    with socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET) as s:
        s.settimeout(3)
        return s.connect_ex((ip, port)) == 0


def check_ports(host: str) -> dict | None:
    """Try a TCP connection to each risky port. Returns None for hosts that
    aren't on the public internet (a LAN result would be misleading)."""
    try:
        ip = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)[0][4][0]
    except OSError as exc:
        return {"ip": None, "checked": [], "open": [], "error": str(exc)}
    if not _is_public(ip):
        return None
    with ThreadPoolExecutor(max_workers=len(RISKY_PORTS)) as pool:
        results = list(pool.map(lambda p: (p, _port_open(ip, p)), RISKY_PORTS))
    return {"ip": ip, "checked": list(RISKY_PORTS), "open": [p for p, ok in results if ok]}


# --- domain: email DNS + expiry -----------------------------------------------

def registrable_domain(host: str) -> str | None:
    """app.example.co.ug -> example.co.ug ; www.example.com -> example.com"""
    host = (host or "").lower().rstrip(".")
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass
    labels = host.split(".")
    if len(labels) < 2:
        return None
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _SLD:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _txt(name: str) -> list[str]:
    import dns.resolver  # dnspython

    try:
        answer = dns.resolver.resolve(name, "TXT", lifetime=8)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    return [b"".join(r.strings).decode("utf-8", "replace") for r in answer]


def check_email_dns(domain: str) -> dict:
    try:
        spf = [t for t in _txt(domain) if t.lower().startswith("v=spf1")]
        dmarc = [t for t in _txt(f"_dmarc.{domain}") if t.lower().startswith("v=dmarc1")]
    except ImportError:
        return {"error": "dnspython not installed"}
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}
    return {"spf": spf, "dmarc": dmarc}


def check_domain_expiry(domain: str) -> dict:
    """Registration expiry via RDAP (the modern, JSON replacement for WHOIS).
    Not every country-code registry supports it; then we just say so."""
    req = urllib.request.Request(
        f"https://rdap.org/domain/{domain}",
        headers={"User-Agent": USER_AGENT, "Accept": "application/rdap+json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15, context=tls_context()) as resp:
            data = json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        return {"supported": False, "error": f"RDAP HTTP {exc.code}"}
    except Exception as exc:
        return {"supported": False, "error": f"{type(exc).__name__}: {exc}"}
    for ev in data.get("events", []):
        if ev.get("eventAction") == "expiration":
            expires = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
            days = (expires - datetime.now(timezone.utc)).days
            return {"supported": True, "expires": expires.date().isoformat(), "days_left": days}
    return {"supported": False, "error": "registry publishes no expiry date"}


# --- orchestration ------------------------------------------------------------

def _event(event_type: str, target: str, message: str, raw: dict) -> Event:
    return Event(
        agent_id=AGENT_ID,
        host=hostname(),
        source="web_check",
        event_type=event_type,
        message=message,
        raw={"target": target, **raw},
    )


def check_url(url: str) -> list[Event]:
    events: list[Event] = []

    status, headers, latency, error = fetch(url)
    if error or (status or 0) >= 500:
        time.sleep(3)  # retry once - don't page anyone over a single blip
        status, headers, latency, error = fetch(url)
    ok = error is None and status is not None and status < 500
    tls_error = error[len("TLS: "):] if error and error.startswith("TLS: ") else None
    events.append(_event(
        "http_check", url, f"{url} -> {status or error} in {latency:.0f} ms",
        {"ok": ok, "status": status, "latency_ms": round(latency), "error": error,
         "error_kind": "tls" if tls_error else None},
    ))

    if headers:
        events.append(_event("header_check", url, f"header audit of {url}", analyze_headers(url, headers)))

    parts = urlsplit(url)
    if parts.scheme == "https" and parts.hostname:
        tls = check_tls(parts.hostname, parts.port or 443)
        if tls_error and tls.get("error_kind") != "verify":
            # The HTTP request already proved the cert is bad, even if this
            # second handshake got dropped (some servers reset repeat probes).
            tls = {"ok": False, "error_kind": "verify", "error": tls_error}
        target = f"{parts.hostname}:{parts.port or 443}"
        events.append(_event("tls_check", target, f"TLS check of {target}", tls))
    return events


class Schedule:
    """Remembers when each slow check last ran, so DNS/RDAP/port checks don't
    run every 5 minutes (they change rarely, and registries rate-limit)."""

    def __init__(self) -> None:
        self.last: dict[str, float] = {}

    def due(self, key: str, every_seconds: int) -> bool:
        now = time.monotonic()
        if now - self.last.get(key, -1e12) >= every_seconds:
            self.last[key] = now
            return True
        return False


def run_round(urls: list[str], domains: list[str], schedule: Schedule, ports: bool) -> list[Event]:
    events: list[Event] = []
    origins, hosts = [], []
    for url in urls:
        events.extend(check_url(url))
        p = urlsplit(url)
        origin = f"{p.scheme}://{p.netloc}"
        if origin not in origins:
            origins.append(origin)
        if p.hostname and p.hostname not in hosts:
            hosts.append(p.hostname)

    for origin in origins:
        result = check_exposed_files(origin)
        events.append(_event("exposed_files", origin, f"sensitive-file check of {origin}", result))

    if ports:
        for host in hosts:
            if schedule.due(f"ports:{host}", 3600):
                result = check_ports(host)
                if result is not None:
                    events.append(_event("port_check", host, f"port check of {host}", result))

    for domain in domains:
        if schedule.due(f"email:{domain}", 6 * 3600):
            events.append(_event("email_dns", domain, f"SPF/DMARC check of {domain}", check_email_dns(domain)))
        if schedule.due(f"expiry:{domain}", 24 * 3600):
            events.append(_event("domain_check", domain, f"expiry check of {domain}", check_domain_expiry(domain)))
    return events


def _split(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


def main() -> None:
    parser = argparse.ArgumentParser(description="External web posture checker")
    parser.add_argument("--url", action="append", default=[], help="URL to check (repeatable)")
    parser.add_argument("--domain", action="append", default=[],
                        help="domain for SPF/DMARC/expiry checks (default: derived from the URLs)")
    parser.add_argument("--no-ports", action="store_true", help="skip the open-port check")
    parser.add_argument("--collector", default=os.environ.get("SM_COLLECTOR_URL", DEFAULT_COLLECTOR_URL))
    parser.add_argument("--api-key", default=os.environ.get("SM_API_KEY", DEFAULT_API_KEY))
    parser.add_argument("--interval", type=int, default=300, help="seconds between rounds")
    parser.add_argument("--once", action="store_true", help="check once then exit")
    args = parser.parse_args()

    urls = args.url or _split(os.environ.get("SM_CHECK_URLS", ""))
    if not urls:
        parser.error("give at least one --url (or set SM_CHECK_URLS)")
    domains = args.domain or _split(os.environ.get("SM_CHECK_DOMAINS", ""))
    if not domains:
        for url in urls:
            d = registrable_domain(urlsplit(url).hostname or "")
            if d and d not in domains:
                domains.append(d)

    print(f"[webcheck] {AGENT_ID}: {len(urls)} URL(s), domains {domains} -> {args.collector}")
    schedule = Schedule()
    while True:
        try:
            batch = run_round(urls, domains, schedule, ports=not args.no_ports)
        except Exception as exc:
            print(f"[webcheck] round failed: {exc}")
            batch = []
        for e in batch:
            print(f"  {e.event_type:13} {e.message}")
        if batch:
            try:
                ship(batch, args.collector, args.api_key)
            except SystemExit:
                raise
            except Exception as exc:
                print(f"[webcheck] could not reach collector: {exc}")
        if args.once:
            break
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
