"""
Email Header Analyzer
Parses raw email headers to detect authentication failures,
sender spoofing, and routing anomalies.
"""
import re
import email
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict


@dataclass
class HeaderFinding:
    """A single header analysis finding."""
    rule_id: str
    name: str
    severity: str       # critical, high, medium, low, info
    description: str
    raw_value: str = ""

    def to_dict(self):
        return asdict(self)


def analyze_headers(raw_headers: str) -> Dict:
    """
    Analyze raw email headers for security indicators.
    
    Args:
        raw_headers: Raw email header text (everything before the body)
    
    Returns:
        Dict with parsed header data and security findings
    """
    findings = []
    parsed = _parse_headers(raw_headers)

    # ── SPF Check ──
    spf_result = _extract_auth_result(raw_headers, "spf")
    parsed["spf"] = spf_result
    if spf_result in ("fail", "softfail"):
        findings.append(HeaderFinding(
            rule_id="HDR-001",
            name="SPF authentication failed",
            severity="high",
            description=f"The sender's domain SPF record returned '{spf_result}'. "
                        f"This means the sending server is not authorized to send email "
                        f"for this domain — a strong indicator of spoofing.",
            raw_value=spf_result,
        ))
    elif spf_result == "none":
        findings.append(HeaderFinding(
            rule_id="HDR-002",
            name="No SPF record configured",
            severity="medium",
            description="The sender's domain has no SPF record. Legitimate organizations "
                        "typically publish SPF records to prevent spoofing.",
            raw_value=spf_result,
        ))

    # ── DKIM Check ──
    dkim_result = _extract_auth_result(raw_headers, "dkim")
    parsed["dkim"] = dkim_result
    if dkim_result == "fail":
        findings.append(HeaderFinding(
            rule_id="HDR-003",
            name="DKIM signature verification failed",
            severity="high",
            description="The DKIM signature on this email failed verification. "
                        "The message may have been modified in transit or the signature was forged.",
            raw_value=dkim_result,
        ))
    elif dkim_result == "none":
        findings.append(HeaderFinding(
            rule_id="HDR-004",
            name="No DKIM signature present",
            severity="medium",
            description="This email has no DKIM signature. Most legitimate senders "
                        "sign their emails with DKIM to prove authenticity.",
            raw_value=dkim_result,
        ))

    # ── DMARC Check ──
    dmarc_result = _extract_auth_result(raw_headers, "dmarc")
    parsed["dmarc"] = dmarc_result
    if dmarc_result == "fail":
        findings.append(HeaderFinding(
            rule_id="HDR-005",
            name="DMARC policy check failed",
            severity="critical",
            description="This email failed DMARC validation. The sender domain's DMARC policy "
                        "indicates this email should not be trusted. This is a strong spoofing signal.",
            raw_value=dmarc_result,
        ))

    # ── Sender Analysis ──
    from_header = parsed.get("from", "")
    reply_to = parsed.get("reply_to", "")

    # Display name vs actual email mismatch
    display_name, from_email = _parse_from_header(from_header)
    parsed["from_display_name"] = display_name
    parsed["from_email"] = from_email

    if display_name and from_email:
        # Check if display name contains a different email address
        name_email = re.search(r'[\w.+-]+@[\w-]+\.[\w.-]+', display_name)
        if name_email and name_email.group() != from_email:
            findings.append(HeaderFinding(
                rule_id="HDR-006",
                name="Display name contains different email address",
                severity="critical",
                description=f"The display name '{display_name}' contains a different email "
                            f"than the actual sender address '{from_email}'. This is a common "
                            f"spoofing technique to trick recipients.",
                raw_value=f"{display_name} <{from_email}>",
            ))

    # Reply-To mismatch
    if reply_to and from_email:
        _, reply_email = _parse_from_header(reply_to)
        if reply_email and reply_email != from_email:
            from_domain = from_email.split("@")[-1] if "@" in from_email else ""
            reply_domain = reply_email.split("@")[-1] if "@" in reply_email else ""
            if from_domain != reply_domain:
                findings.append(HeaderFinding(
                    rule_id="HDR-007",
                    name="Reply-To domain differs from sender",
                    severity="high",
                    description=f"The Reply-To address ({reply_email}) is on a different domain "
                                f"than the From address ({from_email}). Phishing emails often use "
                                f"this to redirect replies to attacker-controlled addresses.",
                    raw_value=f"From: {from_email}, Reply-To: {reply_email}",
                ))

    # ── Routing Anomalies ──
    received_headers = _extract_received_chain(raw_headers)
    parsed["received_count"] = len(received_headers)

    if len(received_headers) > 8:
        findings.append(HeaderFinding(
            rule_id="HDR-008",
            name="Unusually long delivery chain",
            severity="low",
            description=f"This email passed through {len(received_headers)} mail servers. "
                        f"A long routing chain can indicate the email was relayed through "
                        f"multiple systems to obscure its origin.",
            raw_value=f"{len(received_headers)} hops",
        ))

    # ── X-Mailer / User-Agent ──
    x_mailer = parsed.get("x_mailer", "")
    if x_mailer:
        suspicious_mailers = ["phpmailer", "swiftmailer", "mass mailer",
                              "bulk mail", "email sender", "turbo mailer"]
        if any(m in x_mailer.lower() for m in suspicious_mailers):
            findings.append(HeaderFinding(
                rule_id="HDR-009",
                name="Suspicious mail client detected",
                severity="medium",
                description=f"The email was sent using '{x_mailer}', which is commonly "
                            f"associated with mass-mailing tools used in phishing campaigns.",
                raw_value=x_mailer,
            ))

    return {
        "parsed": parsed,
        "findings": [f.to_dict() for f in findings],
        "score_contribution": _calculate_header_score(findings),
    }


def _parse_headers(raw: str) -> Dict:
    """Parse key header fields into a dictionary."""
    msg = email.message_from_string(raw)
    return {
        "from": msg.get("From", ""),
        "to": msg.get("To", ""),
        "subject": msg.get("Subject", ""),
        "date": msg.get("Date", ""),
        "reply_to": msg.get("Reply-To", ""),
        "return_path": msg.get("Return-Path", ""),
        "x_mailer": msg.get("X-Mailer", "") or msg.get("User-Agent", ""),
        "message_id": msg.get("Message-ID", ""),
        "content_type": msg.get("Content-Type", ""),
    }


def _parse_from_header(from_str: str):
    """Extract display name and email from a From header."""
    match = re.match(r'"?([^"<]*)"?\s*<?([^>]*)>?', from_str.strip())
    if match:
        return match.group(1).strip(), match.group(2).strip()
    return "", from_str.strip()


def _extract_auth_result(headers: str, protocol: str) -> str:
    """Extract SPF/DKIM/DMARC result from Authentication-Results header."""
    pattern = rf'{protocol}=(\w+)'
    match = re.search(pattern, headers, re.IGNORECASE)
    if match:
        return match.group(1).lower()
    return "unknown"


def _extract_received_chain(headers: str) -> List[str]:
    """Extract the Received header chain."""
    return re.findall(r'^Received:.*$', headers, re.MULTILINE | re.IGNORECASE)


def _calculate_header_score(findings: List[HeaderFinding]) -> int:
    """Calculate a 0-100 risk score from header findings."""
    if not findings:
        return 0
    severity_weights = {"critical": 30, "high": 20, "medium": 10, "low": 5, "info": 0}
    score = sum(severity_weights.get(f.severity, 0) for f in findings)
    return min(score, 100)
