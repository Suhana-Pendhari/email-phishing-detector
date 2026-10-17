"""
EML File Parser for DetectPhish
Parses .eml files and extracts:
  - Headers (From, To, Subject, Date, Reply-To, Authentication-Results, etc.)
  - Body text (plain text and HTML)
  - Attachments (filename, type, size, SHA-256 hash)
  - Raw headers for SPF/DKIM/DMARC analysis
"""
import email
import hashlib
import base64
import re
from email import policy
from email.parser import BytesParser
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    sha256: str
    is_suspicious: bool
    risk_note: str

    def to_dict(self):
        return asdict(self)


SUSPICIOUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".msi", ".dll", ".com",
    ".pif", ".hta", ".cpl", ".jar", ".reg", ".inf", ".lnk",
    ".docm", ".xlsm", ".pptm",  # Macro-enabled Office files
}

SUSPICIOUS_CONTENT_TYPES = {
    "application/x-msdownload",
    "application/x-executable",
    "application/x-dosexec",
    "application/x-msdos-program",
    "application/java-archive",
    "application/x-javascript",
    "application/hta",
}


def parse_eml(file_bytes: bytes) -> Dict:
    """
    Parse a raw .eml file and extract all components.

    Args:
        file_bytes: Raw bytes of the .eml file

    Returns:
        Dict with headers, body, attachments, and raw header text
    """
    msg = BytesParser(policy=policy.default).parsebytes(file_bytes)

    # ── Extract Headers ──
    raw_headers = _extract_raw_headers(file_bytes)
    parsed_headers = {
        "from": str(msg.get("From", "")),
        "to": str(msg.get("To", "")),
        "cc": str(msg.get("Cc", "")),
        "subject": str(msg.get("Subject", "")),
        "date": str(msg.get("Date", "")),
        "reply_to": str(msg.get("Reply-To", "")),
        "return_path": str(msg.get("Return-Path", "")),
        "message_id": str(msg.get("Message-ID", "")),
        "x_mailer": str(msg.get("X-Mailer", "") or msg.get("User-Agent", "")),
        "content_type": str(msg.get("Content-Type", "")),
        "authentication_results": str(msg.get("Authentication-Results", "")),
        "received_spf": str(msg.get("Received-SPF", "")),
        "dkim_signature": str(msg.get("DKIM-Signature", "")),
    }

    # ── Extract Body ──
    plain_body, html_body = _extract_body(msg)

    # Use plain text body if available, otherwise strip HTML
    email_text = plain_body
    if not email_text and html_body:
        email_text = _strip_html(html_body)

    # ── Extract Attachments ──
    attachments = _extract_attachments(msg)

    # ── Build Result ──
    result = {
        "parsed_successfully": True,
        "subject": parsed_headers["subject"],
        "headers": parsed_headers,
        "raw_headers": raw_headers,
        "body_text": email_text,
        "body_html": html_body,
        "has_html": bool(html_body),
        "attachments": [a.to_dict() for a in attachments],
        "attachment_count": len(attachments),
        "suspicious_attachments": [
            a.to_dict() for a in attachments if a.is_suspicious
        ],
        "stats": {
            "body_length": len(email_text) if email_text else 0,
            "header_count": len(msg.keys()),
            "attachment_count": len(attachments),
            "suspicious_attachment_count": sum(
                1 for a in attachments if a.is_suspicious
            ),
        },
    }

    return result


def _extract_raw_headers(file_bytes: bytes) -> str:
    """Extract the raw header section from the email bytes."""
    try:
        text = file_bytes.decode("utf-8", errors="replace")
    except Exception:
        text = file_bytes.decode("latin-1", errors="replace")

    # Headers end at the first blank line
    header_end = text.find("\n\n")
    if header_end == -1:
        header_end = text.find("\r\n\r\n")
    if header_end == -1:
        return text[:2000]  # Fallback: first 2000 chars

    return text[:header_end]


def _extract_body(msg) -> Tuple[str, str]:
    """Extract plain text and HTML body from the email."""
    plain_body = ""
    html_body = ""

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition", ""))

            # Skip attachments
            if "attachment" in disposition:
                continue

            try:
                payload = part.get_content()
            except Exception:
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        payload = payload.decode(charset, errors="replace")
                    else:
                        continue
                except Exception:
                    continue

            if not isinstance(payload, str):
                continue

            if content_type == "text/plain" and not plain_body:
                plain_body = payload
            elif content_type == "text/html" and not html_body:
                html_body = payload
    else:
        content_type = msg.get_content_type()
        try:
            payload = msg.get_content()
        except Exception:
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    charset = msg.get_content_charset() or "utf-8"
                    payload = payload.decode(charset, errors="replace")
                else:
                    payload = ""
            except Exception:
                payload = ""

        if isinstance(payload, str):
            if content_type == "text/html":
                html_body = payload
            else:
                plain_body = payload

    return plain_body, html_body


def _extract_attachments(msg) -> List[Attachment]:
    """Extract attachments with metadata and hash."""
    attachments = []

    if not msg.is_multipart():
        return attachments

    for part in msg.walk():
        disposition = str(part.get("Content-Disposition", ""))
        content_type = part.get_content_type()

        # Check if it's an attachment
        if "attachment" not in disposition and content_type in (
            "text/plain", "text/html", "multipart/alternative",
            "multipart/mixed", "multipart/related"
        ):
            continue

        if "attachment" not in disposition:
            continue

        filename = part.get_filename()
        if not filename:
            filename = f"unnamed_attachment.{_guess_extension(content_type)}"

        try:
            payload = part.get_payload(decode=True)
        except Exception:
            continue

        if not payload:
            continue

        # Calculate SHA-256
        sha256 = hashlib.sha256(payload).hexdigest()

        # Check if suspicious
        is_suspicious, risk_note = _check_attachment_risk(
            filename, content_type, len(payload)
        )

        attachments.append(Attachment(
            filename=filename,
            content_type=content_type,
            size=len(payload),
            sha256=sha256,
            is_suspicious=is_suspicious,
            risk_note=risk_note,
        ))

    return attachments


def _check_attachment_risk(
    filename: str, content_type: str, size: int
) -> Tuple[bool, str]:
    """Check if an attachment is suspicious."""
    ext = ""
    if "." in filename:
        ext = "." + filename.rsplit(".", 1)[-1].lower()

    # Double extension trick (e.g., "invoice.pdf.exe")
    parts = filename.split(".")
    if len(parts) >= 3:
        real_ext = "." + parts[-1].lower()
        if real_ext in SUSPICIOUS_EXTENSIONS:
            return True, f"Double extension detected: '{filename}' — real type is {real_ext}"

    # Suspicious file extension
    if ext in SUSPICIOUS_EXTENSIONS:
        return True, f"Dangerous file type: {ext} files can execute code on your system"

    # Suspicious MIME type
    if content_type.lower() in SUSPICIOUS_CONTENT_TYPES:
        return True, f"Suspicious content type: {content_type}"

    # Password-protected archives (often used to bypass scanning)
    if ext in (".zip", ".rar", ".7z"):
        return True, "Archive file — may contain hidden malicious files"

    # Macro-enabled documents
    if ext in (".docm", ".xlsm", ".pptm"):
        return True, "Macro-enabled Office document — macros can execute malicious code"

    return False, ""


def _strip_html(html: str) -> str:
    """Convert HTML to plain text."""
    # Remove script and style tags with content
    text = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r'<style[^>]*>.*?</style>', '', text, flags=re.DOTALL | re.IGNORECASE)
    # Replace br and p tags with newlines
    text = re.sub(r'<br\s*/?\s*>', '\n', text, flags=re.IGNORECASE)
    text = re.sub(r'</p>', '\n', text, flags=re.IGNORECASE)
    # Remove all remaining tags
    text = re.sub(r'<[^>]+>', '', text)
    # Decode HTML entities
    text = text.replace('&amp;', '&').replace('&lt;', '<').replace('&gt;', '>')
    text = text.replace('&quot;', '"').replace('&#39;', "'").replace('&nbsp;', ' ')
    # Clean up whitespace
    text = re.sub(r'\n\s*\n', '\n\n', text)
    return text.strip()


def _guess_extension(content_type: str) -> str:
    """Guess file extension from MIME type."""
    mapping = {
        "application/pdf": "pdf",
        "application/zip": "zip",
        "image/png": "png",
        "image/jpeg": "jpg",
        "application/octet-stream": "bin",
        "application/msword": "doc",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx",
    }
    return mapping.get(content_type, "bin")
