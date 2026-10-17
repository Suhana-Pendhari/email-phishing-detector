"""
Content Analyzer
Examines email body text for social engineering patterns:
urgency language, brand impersonation, suspicious requests,
and structural phishing indicators.
"""
import re
from typing import Dict, List
from dataclasses import dataclass, asdict


@dataclass
class ContentFinding:
    rule_id: str
    name: str
    severity: str
    description: str
    evidence: str = ""

    def to_dict(self):
        return asdict(self)


def analyze_content(email_text: str, subject: str = "") -> Dict:
    """
    Analyze email body and subject for phishing content patterns.
    Returns findings and a risk score.
    """
    findings = []
    text_lower = email_text.lower()
    full_text = (subject + " " + email_text).lower()

    # ── Urgency & Pressure Language ──
    urgency_patterns = [
        (r'(act now|action required|immediate(ly)?|urgent(ly)?)', "Urgency pressure"),
        (r'(within \d+ hours?|within \d+ days?|expires? (today|soon|tomorrow))', "Time deadline"),
        (r'(account.{0,20}(suspend|clos|lock|disabl|terminat|restrict))', "Account threat"),
        (r'(verify your (account|identity|email|information))', "Verification demand"),
        (r'(confirm your (account|identity|payment|details))', "Confirmation demand"),
        (r'(update your (account|password|payment|information|details))', "Update demand"),
        (r'(unauthorized.{0,30}(access|activity|transaction|login))', "Unauthorized activity claim"),
        (r'(unusual.{0,20}(activity|sign.?in|login|access))', "Unusual activity claim"),
        (r'(security (alert|notice|warning|update))', "Security scare"),
        (r'(final (warning|notice|reminder|chance))', "Final warning pressure"),
    ]

    urgency_matches = []
    for pattern, label in urgency_patterns:
        matches = re.findall(pattern, full_text)
        if matches:
            urgency_matches.append(label)

    if len(urgency_matches) >= 3:
        findings.append(ContentFinding(
            rule_id="CON-001",
            name="Heavy urgency and pressure language",
            severity="high",
            description=f"This email uses {len(urgency_matches)} different urgency/pressure "
                        f"tactics: {', '.join(urgency_matches[:5])}. Legitimate organizations "
                        f"rarely combine this many high-pressure elements in a single email.",
            evidence=", ".join(urgency_matches),
        ))
    elif len(urgency_matches) >= 1:
        findings.append(ContentFinding(
            rule_id="CON-002",
            name="Urgency language detected",
            severity="medium",
            description=f"This email contains urgency indicators: {', '.join(urgency_matches)}. "
                        f"While not conclusive on its own, urgency language is a common social "
                        f"engineering tactic used to prevent the recipient from thinking critically.",
            evidence=", ".join(urgency_matches),
        ))

    # ── Credential / Sensitive Data Requests ──
    credential_patterns = [
        (r'(enter|provide|submit|send).{0,30}(password|passcode|pin)', "Password request"),
        (r'(enter|provide|submit|send).{0,30}(credit card|card number|cvv|cvc)', "Credit card request"),
        (r'(enter|provide|submit|send).{0,30}(social security|ssn|tax.?id)', "SSN/Tax ID request"),
        (r'(enter|provide|submit|send).{0,30}(bank account|routing number|sort code)', "Bank details request"),
        (r'(enter|provide|submit|send).{0,30}(login|username|user.?id)', "Login credentials request"),
    ]

    cred_matches = []
    for pattern, label in credential_patterns:
        if re.search(pattern, full_text):
            cred_matches.append(label)

    if cred_matches:
        findings.append(ContentFinding(
            rule_id="CON-003",
            name="Sensitive information requested",
            severity="critical",
            description=f"This email explicitly asks for sensitive information: "
                        f"{', '.join(cred_matches)}. Legitimate organizations never ask "
                        f"for passwords, credit card numbers, or SSNs via email.",
            evidence=", ".join(cred_matches),
        ))

    # ── Generic Greeting ──
    generic_greetings = [
        r'dear (customer|user|member|account holder|sir|madam|valued|client)',
        r'dear (sir or madam|sir/madam)',
        r'(hello|hi|greetings),?\s*(customer|user|member|valued)',
        r'to whom it may concern',
    ]
    for pattern in generic_greetings:
        if re.search(pattern, full_text):
            findings.append(ContentFinding(
                rule_id="CON-004",
                name="Generic greeting used",
                severity="low",
                description="This email uses a generic greeting instead of your actual name. "
                            "Legitimate emails from services you use typically address you by "
                            "name. Generic greetings suggest a mass-sent phishing campaign.",
                evidence=re.search(pattern, full_text).group(),
            ))
            break

    # ── Brand Impersonation in Content ──
    brand_claims = {
        "microsoft": [r'microsoft (team|support|security|account|365|office)',
                       r'(outlook|onedrive|sharepoint|teams).{0,20}(team|support)'],
        "apple": [r'apple (support|id|account|security|icloud)',
                   r'(itunes|app store|icloud).{0,20}(team|support)'],
        "google": [r'google (team|support|security|account|workspace)',
                    r'(gmail|drive|chrome|youtube).{0,20}(team|support)'],
        "amazon": [r'amazon (team|support|security|account|prime)',
                    r'(aws|kindle|alexa).{0,20}(team|support)'],
        "paypal": [r'paypal (team|support|security|account|service)'],
        "netflix": [r'netflix (team|support|account|billing|membership)'],
    }

    for brand, patterns in brand_claims.items():
        for pattern in patterns:
            if re.search(pattern, full_text):
                findings.append(ContentFinding(
                    rule_id="CON-005",
                    name=f"Claims to be from {brand.title()}",
                    severity="medium",
                    description=f"This email claims to be from {brand.title()}. Verify the sender "
                                f"address matches an official {brand.title()} domain before taking "
                                f"any action. Phishing emails frequently impersonate major brands.",
                    evidence=re.search(pattern, full_text).group(),
                ))
                break

    # ── Suspicious Attachment References ──
    attachment_patterns = [
        (r'(open|download|view|see).{0,30}attach(ed|ment)', "Attachment action request"),
        (r'attach(ed|ment).{0,30}(invoice|receipt|document|file|form)', "Document attachment"),
        (r'\.(exe|scr|bat|cmd|ps1|vbs|js|jar|msi|dll)\b', "Executable file reference"),
        (r'\.(zip|rar|7z|tar|gz)\b', "Archive file reference"),
    ]

    for pattern, label in attachment_patterns:
        if re.search(pattern, full_text):
            sev = "high" if "Executable" in label else "medium" if "Archive" in label else "low"
            findings.append(ContentFinding(
                rule_id="CON-006",
                name=f"Suspicious attachment reference: {label}",
                severity=sev,
                description=f"The email references an attachment ({label}). "
                            + ("Executable files (.exe, .scr, .bat, etc.) should never be "
                               "opened from unsolicited emails — they can install malware."
                               if "Executable" in label else
                               "Verify the sender's identity before opening any attachments."),
                evidence=label,
            ))
            break  # Only report the most severe attachment finding

    # ── Spelling and Grammar Indicators ──
    # Simple heuristic: count obvious errors common in phishing
    error_patterns = [
        r'\b(recieve|verifiy|securty|informations|datas|kindly do the needful)\b',
        r'\b(click bellow|clik here|dowload|pasword|acount)\b',
        r'\b(deactiveted|suspented|restrected|cancell)\b',
    ]
    error_count = sum(len(re.findall(p, full_text)) for p in error_patterns)
    if error_count >= 2:
        findings.append(ContentFinding(
            rule_id="CON-007",
            name="Multiple spelling/grammar errors",
            severity="medium",
            description=f"This email contains {error_count} common phishing-associated "
                        f"misspellings. While legitimate emails can have typos, systematic "
                        f"errors in security-critical communications are a red flag.",
            evidence=f"{error_count} errors detected",
        ))

    # ── Excessive Capitalization ──
    caps_words = re.findall(r'\b[A-Z]{4,}\b', email_text)
    # Filter out common acronyms
    real_caps = [w for w in caps_words if w not in
                 {"HTML", "HTTP", "HTTPS", "URL", "PDF", "SMTP", "IMAP", "POP3",
                  "DKIM", "DMARC", "MIME", "FROM", "DATE", "SUBJECT", "UUID"}]
    if len(real_caps) >= 3:
        findings.append(ContentFinding(
            rule_id="CON-008",
            name="Excessive capitalization",
            severity="low",
            description=f"This email contains {len(real_caps)} words in ALL CAPS "
                        f"(e.g., {', '.join(real_caps[:3])}). Excessive capitalization is "
                        f"used to create urgency and grab attention — a common phishing tactic.",
            evidence=", ".join(real_caps[:5]),
        ))

    # ── Threatening Consequences ──
    threat_patterns = [
        r'(legal action|law enforcement|prosecut|arrest|warrant)',
        r'(account.{0,15}(permanently|forever).{0,15}(clos|delet|remov))',
        r'(fail(ure)? to.{0,30}(result|lead|cause).{0,20}(suspend|terminat|clos|legal))',
        r'(we will be forced to|you will lose access)',
    ]
    threat_matches = [p for p in threat_patterns if re.search(p, full_text)]
    if threat_matches:
        findings.append(ContentFinding(
            rule_id="CON-009",
            name="Threatening consequences mentioned",
            severity="high",
            description="This email threatens negative consequences (legal action, account "
                        "closure, etc.) to pressure the recipient into acting quickly. "
                        "Legitimate organizations communicate policy changes through "
                        "official channels, not threatening emails.",
            evidence=f"{len(threat_matches)} threat patterns detected",
        ))

    # ── Money / Wire Transfer Requests ──
    money_patterns = [
        r'(wire transfer|bank transfer|send.{0,20}(money|funds|payment))',
        r'(gift card|itunes card|google play card|steam card)',
        r'(bitcoin|crypto|btc).{0,20}(send|transfer|pay|wallet)',
        r'(western union|moneygram)',
    ]
    for pattern in money_patterns:
        match = re.search(pattern, full_text)
        if match:
            findings.append(ContentFinding(
                rule_id="CON-010",
                name="Money transfer request detected",
                severity="critical",
                description="This email requests a money transfer, gift card purchase, or "
                            "cryptocurrency payment. These are irreversible payment methods "
                            "favored by scammers because they cannot be traced or refunded.",
                evidence=match.group(),
            ))
            break

    return {
        "findings": [f.to_dict() for f in findings],
        "score_contribution": _calculate_content_score(findings),
        "urgency_level": "high" if len(urgency_matches) >= 3 else
                         "medium" if len(urgency_matches) >= 1 else "low",
        "requests_credentials": len(cred_matches) > 0,
    }


def _calculate_content_score(findings: List[ContentFinding]) -> int:
    """Calculate a 0-100 risk score from content findings."""
    if not findings:
        return 0
    severity_weights = {"critical": 30, "high": 20, "medium": 10, "low": 5, "info": 0}
    score = sum(severity_weights.get(f.severity, 0) for f in findings)
    return min(score, 100)
