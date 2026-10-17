"""
Feature extraction for phishing email classification.
Extracts structural, linguistic, and statistical features from raw email text.
"""
import re
import math
from collections import Counter
from typing import Dict, List
from urllib.parse import urlparse


# ── Trigger Word Sets ──

URGENCY_WORDS = [
    "urgent", "immediately", "suspend", "verify", "confirm", "expire",
    "unauthorized", "locked", "disabled", "compromised", "alert",
    "action required", "act now", "limited time", "within 24 hours",
    "within 48 hours", "account will be", "click here", "update your",
    "verify your", "confirm your", "validate", "reactivate",
    "security alert", "unusual activity", "suspicious activity",
    "final warning", "last chance",
]

FINANCIAL_WORDS = [
    "bank", "credit card", "payment", "invoice", "wire transfer",
    "refund", "billing", "transaction", "overdue", "amount due",
    "routing number", "account number", "ssn", "social security",
    "paypal", "bitcoin", "crypto",
]

THREAT_WORDS = [
    "terminate", "legal action", "arrest", "warrant", "prosecute",
    "suspend", "deactivate", "close your account", "permanently",
    "penalty", "fine", "violation", "illegal",
]

REWARD_WORDS = [
    "congratulations", "winner", "won", "prize", "lottery", "reward",
    "free", "gift", "bonus", "exclusive offer", "selected",
    "guaranteed", "claim", "inheritance", "million",
]

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".buzz", ".club", ".icu", ".work", ".click", ".link",
    ".info", ".biz", ".rest", ".fit", ".cam",
]


def extract_features(email_text: str) -> Dict:
    """
    Extract all features from an email body for ML classification.
    Returns a flat dictionary of numerical features.
    """
    text_lower = email_text.lower()
    words = re.findall(r'[a-zA-Z]+', text_lower)
    word_count = len(words) if words else 1

    urls = re.findall(r'https?://[^\s<>"\']+', email_text)
    email_addrs = re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', email_text)

    features = {}

    # ── Length & Structure ──
    features["char_count"] = len(email_text)
    features["word_count"] = word_count
    features["line_count"] = email_text.count("\n") + 1
    features["avg_word_length"] = sum(len(w) for w in words) / word_count if words else 0

    # ── URL Features ──
    features["url_count"] = len(urls)
    features["unique_domain_count"] = len(set(urlparse(u).netloc for u in urls))
    features["url_to_text_ratio"] = len(urls) / word_count
    features["has_ip_url"] = int(any(re.search(r'https?://\d+\.\d+\.\d+\.\d+', u) for u in urls))
    features["suspicious_tld_count"] = sum(
        1 for u in urls if any(u.lower().endswith(tld) for tld in SUSPICIOUS_TLDS)
    )
    features["url_max_depth"] = max(
        (urlparse(u).path.count("/") for u in urls), default=0
    )
    features["has_shortened_url"] = int(any(
        d in u.lower() for u in urls for d in ["bit.ly", "tinyurl", "t.co", "goo.gl", "ow.ly", "is.gd"]
    ))

    # ── Email Address Features ──
    features["email_addr_count"] = len(email_addrs)
    features["has_reply_to_mismatch"] = 0  # Set during header analysis

    # ── Keyword Scores ──
    features["urgency_score"] = _keyword_score(text_lower, URGENCY_WORDS)
    features["financial_score"] = _keyword_score(text_lower, FINANCIAL_WORDS)
    features["threat_score"] = _keyword_score(text_lower, THREAT_WORDS)
    features["reward_score"] = _keyword_score(text_lower, REWARD_WORDS)

    # ── Text Statistics ──
    features["caps_ratio"] = sum(1 for c in email_text if c.isupper()) / max(len(email_text), 1)
    features["exclamation_count"] = email_text.count("!")
    features["question_count"] = email_text.count("?")
    features["special_char_ratio"] = sum(
        1 for c in email_text if not c.isalnum() and not c.isspace()
    ) / max(len(email_text), 1)

    # ── Entropy (randomness indicator) ──
    features["char_entropy"] = _shannon_entropy(email_text)

    # ── HTML Indicators ──
    features["has_html"] = int(bool(re.search(r'<[a-zA-Z][^>]*>', email_text)))
    features["html_tag_count"] = len(re.findall(r'<[a-zA-Z][^>]*>', email_text))
    features["has_form_tag"] = int(bool(re.search(r'<form', text_lower)))
    features["has_script_tag"] = int(bool(re.search(r'<script', text_lower)))
    features["has_hidden_element"] = int(bool(re.search(
        r'display\s*:\s*none|visibility\s*:\s*hidden|type\s*=\s*["\']hidden', text_lower
    )))

    # ── Attachment Indicators ──
    suspicious_exts = [".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs",
                       ".js", ".jar", ".msi", ".dll", ".zip", ".rar", ".7z"]
    features["suspicious_attachment_ref"] = int(any(
        ext in text_lower for ext in suspicious_exts
    ))

    # ── Impersonation Signals ──
    features["greeting_generic"] = int(bool(re.search(
        r'dear (customer|user|member|account holder|sir|madam|valued)',
        text_lower
    )))
    features["has_unsubscribe"] = int("unsubscribe" in text_lower)
    features["has_copyright"] = int(bool(re.search(r'©|copyright|\(c\)', text_lower)))

    return features


def get_feature_names() -> List[str]:
    """Return ordered list of feature names matching extract_features output."""
    sample = extract_features("sample text")
    return sorted(sample.keys())


def _keyword_score(text: str, keywords: List[str]) -> float:
    """Count keyword matches normalized by text length."""
    count = sum(1 for kw in keywords if kw in text)
    return count / max(len(keywords), 1)


def _shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of text (higher = more random)."""
    if not text:
        return 0.0
    freq = Counter(text)
    length = len(text)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )
