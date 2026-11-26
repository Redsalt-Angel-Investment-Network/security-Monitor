"""End-to-end tests: POST events to the real FastAPI app, check alerts/findings.

Run from the project root:
    python -m unittest discover -s tests -v
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

# Point the collector at a throwaway DB and test keys *before* importing it.
_TMP = tempfile.mkdtemp()
os.environ["SM_DB_PATH"] = os.path.join(_TMP, "test.db")
KEY = "test-key-webcheck-0123456789abcdef"
OTHER_KEY = "test-key-laptop-0123456789abcdefgh"
os.environ["SM_API_KEYS"] = f"webcheck={KEY},laptop={OTHER_KEY}"
os.environ.pop("SM_API_KEY", None)
os.environ["SM_SLACK_WEBHOOK_URL"] = ""
os.environ["SM_SMTP_HOST"] = ""
os.environ["SM_DIGEST_HOUR_UTC"] = ""

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "agent"))

from fastapi.testclient import TestClient  # noqa: E402

from collector import config, db  # noqa: E402
from collector.digest import build_digest  # noqa: E402
from collector.main import app  # noqa: E402
from web_checker import analyze_headers, looks_exposed, registrable_domain  # noqa: E402

HEADERS = {"X-API-Key": KEY}
_counter = 0


def ev(event_type, user=None, **raw):
    return {"agent_id": "test", "host": "test-host", "source": "test",
            "event_type": event_type, "user": user, "raw": raw}


def unique(name):
    """Fresh entity per test so state from other tests doesn't interfere."""
    global _counter
    _counter += 1
    return f"{name}-{_counter}"


def open_finding(rule_id, entity):
    with db.connect() as conn:
        row = db.get_open_finding(conn, rule_id, entity)
        return dict(row) if row else None


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ctx = TestClient(app)
        cls.client = cls.ctx.__enter__()  # runs lifespan -> init_db

    @classmethod
    def tearDownClass(cls):
        cls.ctx.__exit__(None, None, None)

    def post(self, *events, headers=HEADERS):
        r = self.client.post("/ingest", json={"events": list(events)}, headers=headers)
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()


class SecurityDefaultsTests(Base):
    def test_rejects_bad_api_key(self):
        r = self.client.post("/ingest", json={"events": []}, headers={"X-API-Key": "nope"})
        self.assertEqual(r.status_code, 401)

    def test_each_source_has_its_own_key(self):
        self.post(ev("authentication_failure", "x"), headers={"X-API-Key": OTHER_KEY})

    def test_findings_endpoint_requires_key(self):
        self.assertEqual(self.client.get("/findings").status_code, 401)
        self.assertEqual(self.client.get("/findings", headers=HEADERS).status_code, 200)

    def test_refuses_placeholder_or_short_keys(self):
        saved = dict(config.API_KEYS)
        try:
            config.API_KEYS.clear()
            self.assertTrue(config.config_problems())  # no keys at all
            config.API_KEYS.update({"a": "dev-insecure-key-change-me"})
            self.assertIn("placeholder", config.config_problems()[0])
            config.API_KEYS.update({"a": "short"})
            self.assertIn("shorter", config.config_problems()[0])
        finally:
            config.API_KEYS.clear()
            config.API_KEYS.update(saved)
        self.assertEqual(config.config_problems(), [])


class DetectionTests(Base):
    def test_brute_force_fires_once_not_per_event(self):
        user = unique("victim")
        self.assertEqual(self.post(*[ev("authentication_failure", user) for _ in range(10)])["alerts"], 1)
        self.assertEqual(self.post(*[ev("authentication_failure", user) for _ in range(5)])["alerts"], 0)

    def test_below_threshold_is_quiet(self):
        user = unique("ok-user")
        self.assertEqual(self.post(*[ev("authentication_failure", user) for _ in range(4)])["alerts"], 0)


class FindingLifecycleTests(Base):
    def test_site_down_opens_once_then_resolves(self):
        url = unique("https://down.example")
        self.assertEqual(self.post(ev("http_check", target=url, ok=False, error="timeout"))["findings_opened"], 1)
        # Still down on the next check: no new message.
        r = self.post(ev("http_check", target=url, ok=False, error="timeout"))
        self.assertEqual((r["findings_opened"], r["findings_resolved"]), (0, 0))
        self.assertEqual(self.post(ev("http_check", target=url, ok=True, status=200))["findings_resolved"], 1)
        self.assertIsNone(open_finding("web-site-down", url))

    def test_bad_cert_is_not_also_reported_as_site_down(self):
        url = unique("https://expired.example")
        r = self.post(ev("http_check", target=url, ok=False, error="TLS: expired", error_kind="tls"))
        self.assertEqual(r["findings_opened"], 0)

    def test_tls_finding_escalates(self):
        host = unique("soon.example:443")
        self.assertEqual(self.post(ev("tls_check", target=host, ok=True, days_left=60))["findings_opened"], 0)
        self.assertEqual(self.post(ev("tls_check", target=host, ok=True, days_left=15))["findings_opened"], 1)
        self.assertEqual(open_finding("web-tls-certificate", host)["severity"], "medium")
        self.post(ev("tls_check", target=host, ok=True, days_left=5))
        self.assertEqual(open_finding("web-tls-certificate", host)["severity"], "high")
        self.post(ev("tls_check", target=host, ok=True, days_left=89))  # renewed
        self.assertIsNone(open_finding("web-tls-certificate", host))

    def test_tls_invalid_cert_is_critical(self):
        host = unique("bad.example:443")
        self.post(ev("tls_check", target=host, ok=False, error_kind="verify", error="self-signed"))
        self.assertEqual(open_finding("web-tls-certificate", host)["severity"], "critical")

    def test_tls_connect_error_changes_nothing(self):
        host = unique("unreachable.example:443")
        self.assertEqual(self.post(ev("tls_check", target=host, ok=False, error_kind="connect"))["findings_opened"], 0)

    def test_header_gaps_carry_a_fix(self):
        url = unique("https://hdr.example")
        self.post(ev("header_check", target=url, missing=["content-security-policy"], leaky={"server": "nginx/1.18.0"}))
        f = open_finding("web-security-headers", url)
        self.assertEqual(f["severity"], "medium")
        self.assertIn("Content-Security-Policy", f["fix"])
        self.assertIn("server_tokens off", f["fix"])

    def test_exposed_env_is_critical_and_resolves(self):
        origin = unique("https://leaky.example")
        self.post(ev("exposed_files", target=origin, checked=["/.env", "/.git/HEAD"], exposed=["/.env"]))
        self.assertEqual(open_finding("web-exposed-file", origin + "/.env")["severity"], "critical")
        self.assertIsNone(open_finding("web-exposed-file", origin + "/.git/HEAD"))
        self.post(ev("exposed_files", target=origin, checked=["/.env", "/.git/HEAD"], exposed=[]))
        self.assertIsNone(open_finding("web-exposed-file", origin + "/.env"))

    def test_open_redis_is_critical(self):
        host = unique("db.example")
        self.post(ev("port_check", target=host, ip="203.0.113.5", checked=[6379, 5432], open=[6379]))
        f = open_finding("net-open-port", f"{host}:6379")
        self.assertEqual(f["severity"], "critical")
        self.assertIn("Redis", f["title"])
        self.assertIsNone(open_finding("net-open-port", f"{host}:5432"))


class EmailDomainTests(Base):
    def test_missing_spf_and_dmarc(self):
        d = unique("nomail.example")
        self.assertEqual(self.post(ev("email_dns", target=d, spf=[], dmarc=[]))["findings_opened"], 2)

    def test_good_records_pass(self):
        d = unique("good.example")
        self.post(ev("email_dns", target=d, spf=["v=spf1 include:_spf.google.com ~all"],
                     dmarc=["v=DMARC1; p=reject; rua=mailto:d@good.example"]))
        self.assertIsNone(open_finding("email-spf", d))
        self.assertIsNone(open_finding("email-dmarc", d))

    def test_weak_records(self):
        d = unique("weak.example")
        self.post(ev("email_dns", target=d, spf=["v=spf1 +all"], dmarc=["v=DMARC1; p=none"]))
        self.assertEqual(open_finding("email-spf", d)["severity"], "high")
        self.assertEqual(open_finding("email-dmarc", d)["severity"], "low")

    def test_dns_error_changes_nothing(self):
        d = unique("flaky.example")
        self.assertEqual(self.post(ev("email_dns", target=d, error="Timeout"))["findings_opened"], 0)

    def test_domain_expiry(self):
        d = unique("lapsing.example")
        self.post(ev("domain_check", target=d, supported=True, days_left=10, expires="2026-12-05"))
        self.assertEqual(open_finding("domain-expiry", d)["severity"], "high")
        # A registry without RDAP support tells us nothing either way.
        d2 = unique("nordap.example")
        self.assertEqual(self.post(ev("domain_check", target=d2, supported=False, error="RDAP HTTP 404"))["findings_opened"], 0)


class DigestTests(Base):
    def test_digest_lists_open_findings_with_fixes(self):
        origin = unique("https://digest.example")
        self.post(ev("exposed_files", target=origin, checked=["/.env"], exposed=["/.env"]))
        text = build_digest()
        self.assertIn(f"Sensitive file exposed: {origin}/.env", text)
        self.assertIn("ROTATE every secret", text)
        self.assertIn("[CRITICAL]", text)


class CheckerUnitTests(unittest.TestCase):
    def test_flags_missing_and_versioned_server(self):
        result = analyze_headers("https://x.example", {"server": "nginx/1.18.0", "x-powered-by": "PHP/8.1"})
        self.assertIn("strict-transport-security", result["missing"])
        self.assertEqual(result["leaky"], {"server": "nginx/1.18.0", "x-powered-by": "PHP/8.1"})

    def test_well_configured_site_is_clean(self):
        headers = {
            "strict-transport-security": "max-age=63072000",
            "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin-when-cross-origin",
            "server": "cloudflare",
        }
        self.assertEqual(analyze_headers("https://x.example", headers), {"missing": [], "leaky": {}})

    def test_hsts_not_required_over_http(self):
        self.assertNotIn("strict-transport-security", analyze_headers("http://x.example", {})["missing"])

    def test_real_env_file_detected(self):
        self.assertTrue(looks_exposed("/.env", 200, "text/plain", "DB_PASSWORD=hunter2\nSECRET_KEY=abc\n"))

    def test_spa_catch_all_is_not_a_false_positive(self):
        html = "<!doctype html><html><body><div id=root></div></body></html>"
        self.assertFalse(looks_exposed("/.env", 200, "text/html", html))
        self.assertFalse(looks_exposed("/.git/HEAD", 200, "application/octet-stream", html))
        self.assertFalse(looks_exposed("/.env", 404, "text/plain", "A=1\nB=2"))

    def test_git_head_detected(self):
        self.assertTrue(looks_exposed("/.git/HEAD", 200, "text/plain", "ref: refs/heads/main\n"))
        self.assertTrue(looks_exposed("/.git/config", 200, "", "[core]\n\trepositoryformatversion = 0\n"))

    def test_registrable_domain(self):
        self.assertEqual(registrable_domain("app.example.com"), "example.com")
        self.assertEqual(registrable_domain("www.shop.co.ug"), "shop.co.ug")
        self.assertEqual(registrable_domain("api.startup.co.uk"), "startup.co.uk")
        self.assertIsNone(registrable_domain("203.0.113.5"))
        self.assertIsNone(registrable_domain("localhost"))


if __name__ == "__main__":
    unittest.main()
