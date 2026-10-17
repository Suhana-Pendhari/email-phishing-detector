"""
VirusTotal Scanner
Checks file hashes and URLs against VirusTotal's database.

Free API key: https://www.virustotal.com/gui/my-apikey
Rate limit: 4 requests/minute, 500/day (free tier)
"""
import os
import re
import time
import hashlib
import logging
import requests
from typing import Dict, List

logger = logging.getLogger(__name__)

VT_BASE = "https://www.virustotal.com/api/v3"


class VTScanner:
    """VirusTotal API client for file and URL analysis."""

    def __init__(self, api_key: str = ""):
        self.api_key = api_key or os.environ.get("VIRUSTOTAL_API_KEY", "")
        self.headers = {"x-apikey": self.api_key}
        self._last_request = 0
        self._min_interval = 15

    def is_available(self) -> bool:
        return bool(self.api_key)

    def _rate_limit(self):
        elapsed = time.time() - self._last_request
        if elapsed < self._min_interval:
            time.sleep(self._min_interval - elapsed)
        self._last_request = time.time()

    # ── File Hash Lookup ──

    def lookup_hash(self, file_hash: str) -> Dict:
        """Look up a file hash (MD5/SHA1/SHA256) on VirusTotal."""
        if not self.is_available():
            return {"error": "No API key configured", "found": False, "findings": []}

        self._rate_limit()
        try:
            resp = requests.get(
                f"{VT_BASE}/files/{file_hash}",
                headers=self.headers,
                timeout=15,
            )

            if resp.status_code == 404:
                return {
                    "found": False,
                    "hash": file_hash,
                    "message": "File not in VirusTotal database. Use mode=full to upload.",
                    "findings": [],
                }

            resp.raise_for_status()
            attrs = resp.json().get("data", {}).get("attributes", {})

            stats = attrs.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total = malicious + suspicious + harmless + undetected
            detection_rate = round((malicious / total) * 100, 1) if total > 0 else 0

            results = attrs.get("last_analysis_results", {})
            malware_names = list(set(
                r.get("result", "") for r in results.values()
                if r.get("category") == "malicious" and r.get("result")
            ))[:10]

            findings = []
            vt_link = f"https://www.virustotal.com/gui/file/{file_hash}"

            if malicious >= 5:
                findings.append({
                    "rule_id": "VT-F01",
                    "name": f"File flagged by {malicious}/{total} antivirus engines",
                    "severity": "critical" if malicious >= 10 else "high",
                    "description": f"{malicious} out of {total} engines detect this file as "
                                   f"malicious. Detections: {', '.join(malware_names[:5])}.",
                    "vt_link": vt_link,
                })
            elif malicious >= 1:
                findings.append({
                    "rule_id": "VT-F02",
                    "name": f"File flagged by {malicious}/{total} engines",
                    "severity": "medium",
                    "description": f"Low detection ({malicious}/{total}). Could be a false "
                                   f"positive or newly emerging threat.",
                    "vt_link": vt_link,
                })

            return {
                "found": True,
                "hash": file_hash,
                "detection_rate": detection_rate,
                "malicious": malicious,
                "suspicious": suspicious,
                "total_engines": total,
                "malware_names": malware_names,
                "file_type": attrs.get("type_description", "Unknown"),
                "file_size": attrs.get("size"),
                "file_name": attrs.get("meaningful_name", ""),
                "tags": attrs.get("tags", [])[:10],
                "vt_link": vt_link,
                "findings": findings,
            }

        except requests.HTTPError as e:
            if e.response.status_code == 429:
                return {"error": "Rate limit hit. Free tier: 4 req/min.", "found": False, "findings": []}
            return {"error": str(e), "found": False, "findings": []}
        except Exception as e:
            return {"error": str(e), "found": False, "findings": []}

    # ── File Upload ──

    def upload_file(self, file_bytes: bytes, filename: str = "unknown") -> Dict:
        """Upload a file to VirusTotal for full scanning."""
        if not self.is_available():
            return {"error": "No API key configured", "findings": []}

        self._rate_limit()
        try:
            resp = requests.post(
                f"{VT_BASE}/files",
                headers=self.headers,
                files={"file": (filename, file_bytes)},
                timeout=60,
            )
            resp.raise_for_status()
            analysis_id = resp.json().get("data", {}).get("id", "")

            if analysis_id:
                time.sleep(5)
                self._rate_limit()
                result_resp = requests.get(
                    f"{VT_BASE}/analyses/{analysis_id}",
                    headers=self.headers,
                    timeout=15,
                )
                if result_resp.status_code == 200:
                    data = result_resp.json().get("data", {}).get("attributes", {})
                    stats = data.get("stats", {})
                    malicious = stats.get("malicious", 0)
                    total = sum(stats.values())
                    findings = []
                    if malicious >= 1:
                        findings.append({
                            "rule_id": "VT-F01",
                            "name": f"File flagged by {malicious}/{total} engines",
                            "severity": "critical" if malicious >= 5 else "high" if malicious >= 3 else "medium",
                            "description": f"Fresh scan: {malicious}/{total} detections.",
                        })
                    return {"found": True, "malicious": malicious, "total_engines": total, "findings": findings}

            return {"submitted": True, "message": "Scan in progress", "findings": []}
        except Exception as e:
            return {"error": str(e), "findings": []}

    # ── URL Scanning ──

    def scan_url(self, url: str) -> Dict:
        """Check a single URL against VirusTotal."""
        if not self.is_available():
            return {"url": url, "error": "No API key", "findings": []}

        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        self._rate_limit()
        try:
            resp = requests.get(
                f"{VT_BASE}/urls/{url_id}",
                headers=self.headers,
                timeout=15,
            )

            if resp.status_code == 404:
                return self._submit_url(url)

            resp.raise_for_status()
            attrs = resp.json().get("data", {}).get("attributes", {})

            stats = attrs.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total = malicious + suspicious + harmless + undetected

            vt_link = f"https://www.virustotal.com/gui/url/{hashlib.sha256(url.encode()).hexdigest()}"

            findings = []
            if malicious >= 3:
                findings.append({
                    "rule_id": "VT-U01",
                    "name": f"URL flagged by {malicious}/{total} security vendors",
                    "severity": "critical" if malicious >= 5 else "high",
                    "description": f"{malicious}/{total} security vendors flag this URL as malicious.",
                    "evidence": url,
                    "vt_link": vt_link,
                })
            elif malicious >= 1:
                findings.append({
                    "rule_id": "VT-U02",
                    "name": f"URL flagged by {malicious} vendor(s)",
                    "severity": "medium",
                    "description": f"{malicious} vendor(s) flag this URL.",
                    "evidence": url,
                    "vt_link": vt_link,
                })

            if suspicious > 0:
                findings.append({
                    "rule_id": "VT-U03",
                    "name": f"URL suspicious to {suspicious} vendor(s)",
                    "severity": "medium",
                    "description": f"{suspicious} vendor(s) consider this URL suspicious.",
                    "evidence": url,
                    "vt_link": vt_link,
                })

            categories = attrs.get("categories", {})
            bad_cats = [v for v in categories.values()
                        if any(w in v.lower() for w in ["phish", "malware", "malicious", "scam"])]
            if bad_cats:
                findings.append({
                    "rule_id": "VT-U04",
                    "name": f"Categorized as: {', '.join(bad_cats[:3])}",
                    "severity": "high",
                    "description": f"Vendors categorize this URL as: {', '.join(bad_cats[:3])}.",
                    "evidence": url,
                    "vt_link": vt_link,
                })

            return {
                "url": url,
                "found": True,
                "malicious": malicious,
                "suspicious": suspicious,
                "total_engines": total,
                "categories": categories,
                "final_url": attrs.get("last_final_url", url),
                "vt_link": vt_link,
                "findings": findings,
            }

        except requests.HTTPError as e:
            if e.response.status_code == 429:
                return {"url": url, "error": "Rate limit hit", "findings": []}
            return {"url": url, "error": str(e), "findings": []}
        except Exception as e:
            return {"url": url, "error": str(e), "findings": []}

    def _submit_url(self, url: str) -> Dict:
        """Submit a new URL for scanning."""
        self._rate_limit()
        try:
            resp = requests.post(
                f"{VT_BASE}/urls",
                headers=self.headers,
                data={"url": url},
                timeout=15,
            )
            resp.raise_for_status()
            analysis_id = resp.json().get("data", {}).get("id", "")

            if analysis_id:
                time.sleep(3)
                self._rate_limit()
                result = requests.get(
                    f"{VT_BASE}/analyses/{analysis_id}",
                    headers=self.headers,
                    timeout=15,
                )
                if result.status_code == 200:
                    data = result.json().get("data", {}).get("attributes", {})
                    stats = data.get("stats", {})
                    malicious = stats.get("malicious", 0)
                    total = sum(stats.values())
                    findings = []
                    if malicious >= 1:
                        findings.append({
                            "rule_id": "VT-U01",
                            "name": f"URL flagged by {malicious}/{total} vendors",
                            "severity": "critical" if malicious >= 5 else "high" if malicious >= 3 else "medium",
                            "description": f"Fresh scan: {malicious}/{total} vendors flag this URL.",
                            "evidence": url,
                        })
                    return {"url": url, "found": True, "malicious": malicious, "total_engines": total, "findings": findings}

            return {"url": url, "submitted": True, "message": "Scan in progress", "findings": []}
        except Exception as e:
            return {"url": url, "error": str(e), "findings": []}

    # ── Batch URL Scan ──

    def scan_urls(self, urls: List[str], max_urls: int = 5) -> Dict:
        """Scan multiple URLs. Limits to max_urls for rate limiting."""
        unique = list(dict.fromkeys(urls))[:max_urls]
        results = []
        all_findings = []
        total_malicious = 0

        for url in unique:
            result = self.scan_url(url)
            results.append(result)
            all_findings.extend(result.get("findings", []))
            total_malicious += result.get("malicious", 0)

        return {
            "urls_checked": len(unique),
            "urls_skipped": max(0, len(urls) - max_urls),
            "total_malicious_flags": total_malicious,
            "url_results": results,
            "findings": all_findings,
        }


# ── Helper Functions ──

_scanner = None


def get_scanner() -> VTScanner:
    """Get singleton scanner instance."""
    global _scanner
    if _scanner is None:
        _scanner = VTScanner()
    return _scanner


def compute_file_hash(file_bytes: bytes) -> Dict:
    """Compute MD5, SHA1, SHA256 of file bytes."""
    return {
        "md5": hashlib.md5(file_bytes).hexdigest(),
        "sha1": hashlib.sha1(file_bytes).hexdigest(),
        "sha256": hashlib.sha256(file_bytes).hexdigest(),
    }


def extract_urls_from_email(email_text: str) -> List[str]:
    """Extract unique URLs from email text."""
    urls = re.findall(r'https?://[^\s<>"\')\]]+', email_text)
    return list(dict.fromkeys(urls))
