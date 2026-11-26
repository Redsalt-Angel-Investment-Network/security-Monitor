"""Web posture rules - fed by agent/web_checker.py.

  * site down            - you find out before your customers do
  * TLS cert invalid     - users get trained to click through warnings
  * TLS cert expiring    - the classic self-inflicted outage
  * security headers     - cheap, well-understood browser defences left off
                           (OWASP Secure Headers Project); and headers like
                           `Server: nginx/1.18.0` that tell an attacker
                           exactly which CVEs to try

The checker does the network work; these rules only judge the result, so the
thresholds and the advice live in one place on the collector.
"""
from ...models import Event
from ..base import Finding, Passed, PostureRule, Result

# Days left -> severity. Let's Encrypt certs last 90 days and renew at 30, so
# < 21 days usually means auto-renewal is broken.
TLS_THRESHOLDS = [(7, "high"), (21, "medium")]

IMPORTANT_HEADERS = {"strict-transport-security", "content-security-policy"}

# What to send for each missing header.
HEADER_ADVICE = {
    "strict-transport-security": "Strict-Transport-Security: max-age=31536000; includeSubDomains",
    "content-security-policy": "Content-Security-Policy: default-src 'self'  "
    "(start with Content-Security-Policy-Report-Only and loosen until nothing breaks)",
    "x-content-type-options": "X-Content-Type-Options: nosniff",
    "x-frame-options": "X-Frame-Options: DENY  (or CSP frame-ancestors 'none')",
    "referrer-policy": "Referrer-Policy: strict-origin-when-cross-origin",
}


class SiteDownRule(PostureRule):
    event_type = "http_check"
    rule_id = "web-site-down"

    def assess(self, event: Event) -> list[Result]:
        raw = event.raw
        url = raw.get("target", "?")
        if raw.get("ok"):
            return [Passed(self.rule_id, url)]
        if raw.get("error_kind") == "tls":
            return []  # a bad certificate: the TLS rule reports that one
        why = raw.get("error") or f"HTTP {raw.get('status')}"
        return [Finding(
            rule_id=self.rule_id,
            entity=url,
            severity="high",
            title=f"Site is down: {url}",
            detail=f"{url} failed its health check twice in a row ({why}).",
            fix=(
                "Check the server or hosting dashboard, recent deploys and the app's error "
                "logs. If it is a 5xx error the app is running but failing; a timeout or "
                "connection error means the server, DNS or firewall. You'll get a "
                "'resolved' notice when it's back."
            ),
        )]


class TlsCertificateRule(PostureRule):
    event_type = "tls_check"
    rule_id = "web-tls-certificate"

    def assess(self, event: Event) -> list[Result]:
        raw = event.raw
        target = raw.get("target", "?")

        if raw.get("error_kind") == "verify":
            return [Finding(
                rule_id=self.rule_id,
                entity=target,
                severity="critical",
                title=f"Invalid TLS certificate on {target}",
                detail=f"Certificate verification failed: {raw.get('error')}.",
                fix=(
                    "Visitors see a full-page browser warning. Renew or reissue the "
                    "certificate (e.g. `certbot renew`, or re-enable your host's managed "
                    "certificate) and make sure it covers this exact hostname."
                ),
            )]
        if not raw.get("ok") or raw.get("days_left") is None:
            return []  # couldn't connect: the site-down rule covers that

        days_left = raw["days_left"]
        for limit, severity in TLS_THRESHOLDS:
            if days_left < limit:
                return [Finding(
                    rule_id=self.rule_id,
                    entity=target,
                    severity=severity,
                    title=f"TLS certificate for {target} expires in {days_left} day(s)",
                    detail=f"Expires {raw.get('not_after')} (issuer: {raw.get('issuer')}).",
                    fix=(
                        "Renew the certificate now. If you use Let's Encrypt it should have "
                        "renewed itself at 30 days left, so auto-renewal is broken: check "
                        "`certbot renew --dry-run` or your host's certificate settings."
                    ),
                )]
        return [Passed(self.rule_id, target)]


class SecurityHeadersRule(PostureRule):
    event_type = "header_check"
    rule_id = "web-security-headers"

    def assess(self, event: Event) -> list[Result]:
        raw = event.raw
        url = raw.get("target", "?")
        missing = raw.get("missing", [])
        leaky = raw.get("leaky", {})
        if not missing and not leaky:
            return [Passed(self.rule_id, url)]

        parts, fixes = [], []
        if missing:
            parts.append("missing " + ", ".join(missing))
            fixes.append("Add these response headers: " + "; ".join(
                HEADER_ADVICE.get(h, h) for h in missing))
        if leaky:
            parts.append("revealing software versions (" + ", ".join(
                f"{k}: {v}" for k, v in leaky.items()) + ")")
            fixes.append(
                "Hide version details: e.g. nginx `server_tokens off;`, Apache "
                "`ServerTokens Prod`, Express `app.disable('x-powered-by')`, PHP `expose_php = Off`."
            )
        fixes.append("Reference: https://owasp.org/www-project-secure-headers/")
        return [Finding(
            rule_id=self.rule_id,
            entity=url,
            severity="medium" if IMPORTANT_HEADERS & set(missing) else "low",
            title=f"Security header gaps on {url}",
            detail="; ".join(parts) + ".",
            fix=" ".join(fixes),
        )]
