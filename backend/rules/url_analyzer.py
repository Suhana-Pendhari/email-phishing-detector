"""
URL Analyzer
Examines URLs found in emails for phishing indicators:
homoglyph attacks, suspicious TLDs, IP-based URLs, shortened URLs,
and known brand impersonation patterns.
"""
import re
from typing import Dict, List
from urllib.parse import urlparse
from dataclasses import dataclass, asdict


@dataclass
class URLFinding:
    rule_id: str
    name: str
    severity: str
    description: str
    url: str = ""

    def to_dict(self):
        return asdict(self)


# ── Homoglyph Detection ──

HOMOGLYPH_MAP = {
    # Cyrillic → Latin lookalikes
    '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p',
    '\u0441': 'c', '\u0443': 'y', '\u0445': 'x', '\u0455': 's',
    '\u0456': 'i', '\u0458': 'j', '\u0501': 'd', '\u04bb': 'h',
    '\u043d': 'h', '\u043c': 'm', '\u0442': 't', '\u0432': 'v',
    # Common ASCII substitutions
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
    '7': 't', '8': 'b', '@': 'a',
}

LEGITIMATE_DOMAINS = {
    "microsoft.com", "office.com", "outlook.com", "live.com",
    "google.com", "gmail.com", "youtube.com",
    "apple.com", "icloud.com",
    "amazon.com", "aws.amazon.com",
    "paypal.com",
    "facebook.com", "instagram.com", "whatsapp.com",
    "twitter.com", "x.com",
    "linkedin.com",
    "netflix.com",
    "dropbox.com",
    "docusign.com",
    "adobe.com",
    "zoom.us",
    "slack.com",
    "github.com",
    "chase.com", "bankofamerica.com", "wellsfargo.com", "citibank.com",
    "dhl.com", "fedex.com", "ups.com", "usps.com",
}

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".buzz", ".club", ".icu", ".work", ".click", ".link",
    ".info", ".biz", ".rest", ".fit", ".cam", ".monster",
    ".site", ".online", ".space", ".fun",
}

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rb.gy", "cutt.ly", "shorturl.at", "tiny.cc",
}


def analyze_urls(email_text: str) -> Dict:
    """
    Extract and analyze all URLs found in the email text.
    Returns findings and a risk score.
    """
    urls = re.findall(r'https?://[^\s<>"\')\]]+', email_text)
    findings = []
    analyzed_urls = []

    for url in urls:
        url_info = _analyze_single_url(url)
        analyzed_urls.append(url_info)
        findings.extend(url_info["findings"])

    # Check for URL-text mismatch (hyperlink shows different URL than href)
    mismatches = _check_link_text_mismatch(email_text)
    findings.extend(mismatches)

    return {
        "urls_found": len(urls),
        "analyzed_urls": analyzed_urls,
        "findings": [f.to_dict() for f in findings],
        "score_contribution": _calculate_url_score(findings),
    }


def _analyze_single_url(url: str) -> Dict:
    """Analyze a single URL for phishing indicators."""
    findings = []
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()

    # Strip port
    domain_no_port = domain.split(":")[0]

    # ── IP-based URL ──
    if re.match(r'^\d+\.\d+\.\d+\.\d+', domain_no_port):
        findings.append(URLFinding(
            rule_id="URL-001",
            name="IP address used instead of domain",
            severity="high",
            description="This URL uses a raw IP address instead of a domain name. "
                        "Legitimate services almost always use domain names. "
                        "IP-based URLs are commonly used in phishing to avoid domain reputation checks.",
            url=url,
        ))

    # ── Suspicious TLD ──
    for tld in SUSPICIOUS_TLDS:
        if domain_no_port.endswith(tld):
            findings.append(URLFinding(
                rule_id="URL-002",
                name=f"Suspicious TLD: {tld}",
                severity="medium",
                description=f"The domain uses the '{tld}' top-level domain, which is "
                            f"disproportionately associated with phishing and malware "
                            f"distribution due to low registration costs and minimal verification.",
                url=url,
            ))
            break

    # ── URL Shortener ──
    if any(domain_no_port == d or domain_no_port.endswith("." + d) for d in SHORTENER_DOMAINS):
        findings.append(URLFinding(
            rule_id="URL-003",
            name="URL shortener detected",
            severity="medium",
            description="This URL uses a URL shortening service to hide the actual destination. "
                        "Phishing emails use shorteners to bypass URL reputation filters and "
                        "conceal malicious domains from the recipient.",
            url=url,
        ))

    # ── Homoglyph Attack ──
    homoglyph_found = _check_homoglyphs(domain_no_port)
    if homoglyph_found:
        findings.append(URLFinding(
            rule_id="URL-004",
            name="Homoglyph characters detected in domain",
            severity="critical",
            description=f"The domain '{domain_no_port}' contains characters that visually "
                        f"resemble legitimate characters but are actually different Unicode "
                        f"code points ({homoglyph_found}). This is a sophisticated attack "
                        f"technique designed to make a malicious domain look identical to a "
                        f"trusted one.",
            url=url,
        ))

    # ── Brand Impersonation in Domain ──
    brand_match = _check_brand_impersonation(domain_no_port)
    if brand_match:
        findings.append(URLFinding(
            rule_id="URL-005",
            name=f"Possible {brand_match} impersonation",
            severity="high",
            description=f"The domain '{domain_no_port}' contains the brand name "
                        f"'{brand_match}' but is not the official domain. This pattern "
                        f"(e.g., 'microsoft-security-alert.com') is commonly used in "
                        f"phishing to create a false sense of legitimacy.",
            url=url,
        ))

    # ── Excessive Subdomain Depth ──
    subdomain_parts = domain_no_port.split(".")
    if len(subdomain_parts) > 4:
        findings.append(URLFinding(
            rule_id="URL-006",
            name="Excessive subdomain depth",
            severity="medium",
            description=f"The URL has {len(subdomain_parts)} subdomain levels. Deep subdomain "
                        f"nesting (e.g., 'login.secure.account.verify.evil.com') is used in "
                        f"phishing to push the actual domain out of the visible portion of "
                        f"the address bar.",
            url=url,
        ))

    # ── Suspicious Path Keywords ──
    phish_path_words = ["login", "signin", "verify", "secure", "account",
                         "update", "confirm", "password", "credential",
                         "webscr", "cmd=_login", "wallet", ".php"]
    path_matches = [w for w in phish_path_words if w in path]
    if len(path_matches) >= 2:
        findings.append(URLFinding(
            rule_id="URL-007",
            name="Suspicious keywords in URL path",
            severity="medium",
            description=f"The URL path contains phishing-associated keywords: "
                        f"{', '.join(path_matches)}. Combinations of these words in a URL "
                        f"path are strong indicators of a credential harvesting page.",
            url=url,
        ))

    # ── Data URI / JavaScript URI ──
    if url.lower().startswith("data:") or url.lower().startswith("javascript:"):
        findings.append(URLFinding(
            rule_id="URL-008",
            name="Data or JavaScript URI detected",
            severity="critical",
            description="This link uses a data: or javascript: URI scheme, which can "
                        "execute code or display attacker-controlled content directly in "
                        "the browser without navigating to an external server.",
            url=url,
        ))

    return {
        "url": url,
        "domain": domain_no_port,
        "path": path,
        "findings": findings,
    }


def _check_homoglyphs(domain: str) -> str:
    """Check if domain contains homoglyph characters. Returns description or empty string."""
    found = []
    for char in domain:
        if char in HOMOGLYPH_MAP:
            found.append(f"'{char}' looks like '{HOMOGLYPH_MAP[char]}'")
    return "; ".join(found) if found else ""


def _check_brand_impersonation(domain: str) -> str:
    """Check if domain tries to impersonate a known brand."""
    brand_keywords = {
        "microsoft": "Microsoft", "apple": "Apple", "google": "Google",
        "amazon": "Amazon", "paypal": "PayPal", "netflix": "Netflix",
        "facebook": "Facebook", "instagram": "Instagram", "linkedin": "LinkedIn",
        "dropbox": "Dropbox", "docusign": "DocuSign", "adobe": "Adobe",
        "chase": "Chase", "wellsfargo": "Wells Fargo", "citibank": "Citibank",
        "dhl": "DHL", "fedex": "FedEx", "ups": "UPS",
    }

    for keyword, brand_name in brand_keywords.items():
        if keyword in domain:
            # Check it's not the legitimate domain
            legit = [d for d in LEGITIMATE_DOMAINS if keyword in d]
            if domain not in LEGITIMATE_DOMAINS and not any(domain.endswith(d) for d in legit):
                return brand_name
    return ""


def _check_link_text_mismatch(html_text: str) -> List[URLFinding]:
    """Detect when visible link text shows a different URL than the href."""
    findings = []
    pattern = re.compile(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL)

    for match in pattern.finditer(html_text):
        href = match.group(1).strip()
        link_text = re.sub(r'<[^>]+>', '', match.group(2)).strip()

        # Check if link text looks like a URL
        text_url_match = re.search(r'https?://[^\s]+', link_text)
        if text_url_match:
            visible_domain = urlparse(text_url_match.group()).netloc.lower()
            actual_domain = urlparse(href).netloc.lower()

            if visible_domain and actual_domain and visible_domain != actual_domain:
                findings.append(URLFinding(
                    rule_id="URL-009",
                    name="Link text shows different URL than actual destination",
                    severity="critical",
                    description=f"The visible link text shows '{visible_domain}' but the actual "
                                f"link goes to '{actual_domain}'. This is a classic phishing "
                                f"technique to trick users into clicking a malicious link that "
                                f"appears to be a legitimate website.",
                    url=href,
                ))

    return findings


def _calculate_url_score(findings: List[URLFinding]) -> int:
    """Calculate a 0-100 risk score from URL findings."""
    if not findings:
        return 0
    severity_weights = {"critical": 30, "high": 20, "medium": 10, "low": 5, "info": 0}
    score = sum(severity_weights.get(f.severity, 0) for f in findings)
    return min(score, 100)
