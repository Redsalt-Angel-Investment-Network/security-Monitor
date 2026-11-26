"""Domain rules: email spoofing protection and domain expiry.

* SPF and DMARC tell the world's mail servers which servers may send email as
  your domain, and what to do with mail that fails the check. Without them,
  anyone can send convincing phishing "from" you@yourstartup.com to your
  customers and staff - one of the cheapest attacks there is.
  (DKIM matters too, but checking it needs to know your selector names.)
* An expired domain takes down your site AND email, and a lapsed domain can be
  bought by someone else - who then receives your password-reset emails.
"""
from ...models import Event
from ..base import Finding, Passed, PostureRule, Result

DOMAIN_THRESHOLDS = [(0, "critical"), (14, "high"), (30, "medium")]


class SpfRule(PostureRule):
    event_type = "email_dns"
    rule_id = "email-spf"

    def assess(self, event: Event) -> list[Result]:
        raw = event.raw
        if raw.get("error"):
            return []
        domain = raw.get("target", "?")
        records = raw.get("spf", [])
        problem = None
        if not records:
            severity, problem = "medium", f"{domain} has no SPF record"
        elif len(records) > 1:
            severity, problem = "medium", f"{domain} has {len(records)} SPF records; receivers treat that as an error"
        else:
            mechanisms = records[0].lower().split()
            if "+all" in mechanisms or "all" in mechanisms:
                severity, problem = "high", f"{domain}'s SPF record ends in '+all', which lets ANY server send as you"
            elif "?all" in mechanisms:
                severity, problem = "low", f"{domain}'s SPF record ends in '?all', which doesn't reject anything"
        if problem is None:
            return [Passed(self.rule_id, domain)]
        return [Finding(
            rule_id=self.rule_id,
            entity=domain,
            severity=severity,
            title=f"Email spoofing risk: SPF on {domain}",
            detail=f"{problem}. Current: {records or 'none'}.",
            fix=(
                "Publish ONE TXT record on the domain listing the services that send your mail, "
                "ending in -all or ~all, e.g. `v=spf1 include:_spf.google.com ~all` for Google "
                "Workspace (your email provider documents its include). A domain that never sends "
                "email should publish `v=spf1 -all`."
            ),
        )]


class DmarcRule(PostureRule):
    event_type = "email_dns"
    rule_id = "email-dmarc"

    def assess(self, event: Event) -> list[Result]:
        raw = event.raw
        if raw.get("error"):
            return []
        domain = raw.get("target", "?")
        records = raw.get("dmarc", [])
        problem = None
        if not records:
            severity, problem = "medium", f"{domain} has no DMARC record"
        elif len(records) > 1:
            severity, problem = "medium", f"{domain} has {len(records)} DMARC records; receivers ignore them all"
        else:
            tags = {
                k.strip().lower(): v.strip().lower()
                for k, _, v in (t.partition("=") for t in records[0].split(";"))
            }
            if tags.get("p", "none") == "none":
                severity, problem = "low", f"{domain}'s DMARC policy is p=none (monitoring only; spoofed mail is still delivered)"
        if problem is None:
            return [Passed(self.rule_id, domain)]
        return [Finding(
            rule_id=self.rule_id,
            entity=domain,
            severity=severity,
            title=f"Email spoofing risk: DMARC on {domain}",
            detail=f"{problem}. Current: {records or 'none'}.",
            fix=(
                f"Add a TXT record at _dmarc.{domain}. Start with "
                f"`v=DMARC1; p=none; rua=mailto:dmarc@{domain}` to see who sends as you, then "
                "move to p=quarantine and finally p=reject once SPF/DKIM pass for your real mail."
            ),
        )]


class DomainExpiryRule(PostureRule):
    event_type = "domain_check"
    rule_id = "domain-expiry"

    def assess(self, event: Event) -> list[Result]:
        raw = event.raw
        domain = raw.get("target", "?")
        days_left = raw.get("days_left")
        if raw.get("error") or days_left is None:
            return []  # registry doesn't publish expiry over RDAP, or lookup failed
        for limit, severity in DOMAIN_THRESHOLDS:
            if days_left < limit:
                return [Finding(
                    rule_id=self.rule_id,
                    entity=domain,
                    severity=severity,
                    title=f"Domain {domain} expires in {days_left} day(s)",
                    detail=f"Registry expiry date: {raw.get('expires')}.",
                    fix=(
                        "Renew it at your registrar now and turn on auto-renew with a payment "
                        "card that won't expire. If the domain lapses, your site and email stop, "
                        "and someone else can register it and receive your password-reset emails."
                    ),
                )]
        return [Passed(self.rule_id, domain)]
