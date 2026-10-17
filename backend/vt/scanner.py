"""
VirusTotal Integration for DetectPhish
Supports:
  1. Hash Lookup   — instant check if file is known-malicious
  2. File Upload   — full scan by 70+ AV engines (1-2 min)
  3. URL Scanning  — check URLs against VT reputation database

Free API: 4 requests/minute, 500/day
Get your key: https://www.virustotal.com/gui/my-apikey
"""
import os
import re
import time
import base64
import hashlib
import logging
import requests
from typing import Dict, List

logger = logging.getLogger(__name__)


class VirusTotalScanner:
    """VirusTotal API v3 client."""

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.environ.get("VT_API_KEY", "")
        self.session = requests.Session()
        if self.api_key:
            self.session.headers.update({
                "x-apikey": self.api_key,
                "Accept": "application/json",
            })

    def is_available(self) -> bool:
        """Check if the API key is configured."""
        return bool(self.api_key)

    # ── Hash Lookup ──

    def lookup_hash(self, file_hash: str) -> Dict:
        """
        Look up a file hash (MD5, SHA-1, or SHA-256) on VirusTotal.
        Returns detection results instantly if the file is in VT's database.
        """
        if not self.is_available():
            return {"error": "VT_API_KEY not set", "found": False}

        try:
            resp = self.session.get(
                f"{self.BASE_URL}/files/{file_hash}",
                timeout=15,
            )

            if resp.status_code == 404:
                return {
                    "found": False,
                    "hash": file_hash,
                    "message": "File not found in VirusTotal database. "
                               "Use full scan mode to upload and scan it.",
                }

            if resp.status_code == 429:
                return {"error": "Rate limit exceeded. Free tier: 4 requests/minute.", "found": False}

            resp.raise_for_status()
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            undetected = stats.get("undetected", 0)
            total = malicious + suspicious + undetected + stats.get("harmless", 0)

            detection_rate = round((malicious / total) * 100, 1) if total > 0 else 0

            if malicious >= 10:
                severity = "critical"
                verdict = "malicious"
            elif malicious >= 3:
                severity = "high"
                verdict = "malicious"
            elif malicious >= 1 or suspicious >= 2:
                severity = "medium"
                verdict = "suspicious"
            else:
                severity = "low"
                verdict = "clean"

            findings = []
            if malicious > 0:
                findings.append({
                    "rule_id": "VT-FILE-001",
                    "name": f"File flagged by {malicious}/{total} antivirus engines",
                    "severity": severity,
                    "description": f"VirusTotal reports {malicious} out of {total} antivirus engines "
                                   f"detected this file as malicious ({detection_rate}% detection rate). "
                                   f"Additionally, {suspicious} engines flagged it as suspicious.",
                    "evidence": f"{malicious}/{total} engines, detection rate: {detection_rate}%",
                })

            return {
                "found": True,
                "hash": file_hash,
                "verdict": verdict,
                "severity": severity,
                "detection_rate": detection_rate,
                "malicious_count": malicious,
                "suspicious_count": suspicious,
                "undetected_count": undetected,
                "total_engines": total,
                "file_type": data.get("type_description", "Unknown"),
                "file_size": data.get("size"),
                "file_names": data.get("names", [])[:5],
                "tags": data.get("tags", [])[:10],
                "first_seen": data.get("first_submission_date"),
                "last_analysis": data.get("last_analysis_date"),
                "findings": findings,
                "score_contribution": min(detection_rate, 100),
                "vt_link": f"https://www.virustotal.com/gui/file/{file_hash}",
            }

        except requests.RequestException as e:
            logger.error(f"VT hash lookup error: {e}")
            return {"error": str(e), "found": False}

    # ── File Upload & Scan ──

    def upload_bytes_and_scan(self, file_bytes: bytes, filename: str = "uploaded_file") -> Dict:
        """
        Upload a file to VirusTotal for full scanning.
        Takes 1-2 minutes as 70+ AV engines analyze the file.
        Free tier limit: files up to 32MB.
        """
        if not self.is_available():
            return {"error": "VT_API_KEY not set"}

        file_hash = hashlib.sha256(file_bytes).hexdigest()

        # First check if already in VT database
        existing = self.lookup_hash(file_hash)
        if existing.get("found"):
            existing["scan_mode"] = "hash_hit"
            existing["message"] = "File already in VT database — showing cached results."
            return existing

        # Upload to VT
        try:
            resp = self.session.post(
                f"{self.BASE_URL}/files",
                files={"file": (filename, file_bytes)},
                timeout=60,
            )

            if resp.status_code == 429:
                return {"error": "Rate limit exceeded. Wait 60 seconds.", "found": False}

            resp.raise_for_status()
            analysis_id = resp.json().get("data", {}).get("id")

            if not analysis_id:
                return {"error": "Upload succeeded but no analysis ID returned.", "found": False}

            # Poll for results (max 2 minutes)
            result = self._poll_analysis(analysis_id, max_wait=120)
            result["scan_mode"] = "full_upload"
            result["hash"] = file_hash
            return result

        except requests.RequestException as e:
            logger.error(f"VT file upload error: {e}")
            return {"error": str(e), "found": False}

    def _poll_analysis(self, analysis_id: str, max_wait: int = 120) -> Dict:
        """Poll VT for analysis results until complete or timeout."""
        start = time.time()
        poll_interval = 10

        while time.time() - start < max_wait:
            try:
                resp = self.session.get(
                    f"{self.BASE_URL}/analyses/{analysis_id}",
                    timeout=15,
                )
                resp.raise_for_status()
                data = resp.json().get("data", {}).get("attributes", {})
                status = data.get("status")

                if status == "completed":
                    stats = data.get("stats", {})
                    malicious = stats.get("malicious", 0)
                    total = sum(stats.values())
                    detection_rate = round((malicious / total) * 100, 1) if total > 0 else 0

                    findings = []
                    if malicious > 0:
                        findings.append({
                            "rule_id": "VT-FILE-002",
                            "name": f"Uploaded file flagged by {malicious}/{total} engines",
                            "severity": "critical" if malicious >= 10 else "high" if malicious >= 3 else "medium",
                            "description": f"Full VirusTotal scan: {malicious}/{total} engines flagged this file.",
                            "evidence": f"Detection rate: {detection_rate}%",
                        })

                    return {
                        "found": True,
                        "verdict": "malicious" if malicious >= 3 else "suspicious" if malicious >= 1 else "clean",
                        "detection_rate": detection_rate,
                        "malicious_count": malicious,
                        "total_engines": total,
                        "analysis_stats": stats,
                        "findings": findings,
                        "score_contribution": min(detection_rate, 100),
                    }

                time.sleep(poll_interval)

            except requests.RequestException:
                time.sleep(poll_interval)

        return {
            "found": False,
            "error": f"Analysis timed out after {max_wait}s. Check VT dashboard for results.",
            "analysis_id": analysis_id,
            "findings": [],
        }

    # ── URL Scanning ──

    def scan_url(self, url: str) -> Dict:
        """Check a URL against VirusTotal's database."""
        if not self.is_available():
            return {"error": "VT_API_KEY not set", "findings": [], "score_contribution": 0}

        try:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

            resp = self.session.get(
                f"{self.BASE_URL}/urls/{url_id}",
                timeout=15,
            )

            if resp.status_code == 404:
                return self._submit_url(url)

            if resp.status_code == 429:
                return {"error": "Rate limit. Wait 60 seconds.", "findings": [], "score_contribution": 0}

            resp.raise_for_status()
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = malicious + suspicious + stats.get("undetected", 0) + stats.get("harmless", 0)

            findings = []
            score = 0

            if malicious > 0:
                severity = "critical" if malicious >= 5 else "high" if malicious >= 2 else "medium"
                score = min(malicious * 15, 100)
                categories = ", ".join(data.get("categories", {}).values())[:100] or "N/A"
                findings.append({
                    "rule_id": "VT-URL-001",
                    "name": f"URL flagged by {malicious}/{total} engines on VirusTotal",
                    "severity": severity,
                    "description": f"VirusTotal reports {malicious} security vendors flagged "
                                   f"this URL as malicious. Categories: {categories}.",
                    "url": url,
                    "evidence": f"{malicious}/{total} detections",
                })

            return {
                "found": True,
                "url": url,
                "malicious_count": malicious,
                "suspicious_count": suspicious,
                "total_engines": total,
                "verdict": "malicious" if malicious >= 2 else "suspicious" if malicious >= 1 or suspicious >= 2 else "clean",
                "categories": data.get("categories", {}),
                "final_url": data.get("last_final_url", url),
                "findings": findings,
                "score_contribution": score,
                "vt_link": f"https://www.virustotal.com/gui/url/{url_id}",
            }

        except requests.RequestException as e:
            logger.error(f"VT URL scan error for {url}: {e}")
            return {"error": str(e), "url": url, "findings": [], "score_contribution": 0}

    def _submit_url(self, url: str) -> Dict:
        """Submit a URL for scanning if it's not in VT's database."""
        try:
            resp = self.session.post(
                f"{self.BASE_URL}/urls",
                data={"url": url},
                timeout=15,
            )

            if resp.status_code == 429:
                return {"error": "Rate limit", "findings": [], "score_contribution": 0}

            resp.raise_for_status()

            return {
                "found": False,
                "url": url,
                "message": "URL submitted to VirusTotal for scanning. Results available in ~60 seconds.",
                "verdict": "pending",
                "findings": [],
                "score_contribution": 0,
            }

        except requests.RequestException as e:
            return {"error": str(e), "url": url, "findings": [], "score_contribution": 0}

    # ── Batch URL Scanning (from email text) ──

    def scan_urls_from_email(self, email_text: str, max_urls: int = 5) -> Dict:
        """Extract URLs from email text and scan each on VirusTotal."""
        urls = list(set(re.findall(r'https?://[^\s<>"\')\]]+', email_text)))

        if not urls:
            return {"urls_scanned": 0, "findings": [], "score_contribution": 0}

        results = []
        all_findings = []
        total_score = 0

        for url in urls[:max_urls]:
            result = self.scan_url(url)
            result["scanned_url"] = url
            results.append(result)
            all_findings.extend(result.get("findings", []))
            total_score += result.get("score_contribution", 0)

            # Respect rate limit (4 req/min on free tier)
            time.sleep(15)

        return {
            "urls_scanned": len(results),
            "total_urls_found": len(urls),
            "results": results,
            "findings": all_findings,
            "score_contribution": min(total_score, 100),
        }
