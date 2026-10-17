"""
DetectPhish — AI-Powered Phishing Email Detector
Flask API Backend

Four-layer detection:
  1. ML Classifier   — scikit-learn model (TF-IDF + structural features)
  2. Rule Engine     — header, URL, and content heuristics
  3. AI Analysis     — Ollama/Claude/Gemini social engineering analysis
  4. VirusTotal      — file hash/upload scanning + URL reputation checks
"""
import os
import re
import sys
import pickle
import json
import hashlib
import logging
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS

from rules.header_analyzer import analyze_headers
from rules.url_analyzer import analyze_urls
from rules.content_analyzer import analyze_content
from rules.eml_parser import parse_eml
from ai.analyzer import get_ai_analyzer
from vt.scanner import VirusTotalScanner
from ml.train import StructuralFeatureExtractor

# Fix pickle deserialization for the ML model
sys.modules['__main__'].StructuralFeatureExtractor = StructuralFeatureExtractor

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app, origins=["http://localhost:3000", "http://localhost:5173"])

# ── Load ML Model ──

MODEL_DIR = os.path.join(os.path.dirname(__file__), "ml")
_model = None
_model_metadata = None


def get_model():
    global _model, _model_metadata
    if _model is None:
        model_path = os.path.join(MODEL_DIR, "model.pkl")
        meta_path = os.path.join(MODEL_DIR, "model_metadata.json")
        if os.path.exists(model_path):
            with open(model_path, "rb") as f:
                _model = pickle.load(f)
            logger.info("ML model loaded successfully")
        else:
            logger.warning(f"No trained model at {model_path}")
        if os.path.exists(meta_path):
            with open(meta_path) as f:
                _model_metadata = json.load(f)
    return _model, _model_metadata


# ── Load AI Analyzer ──

_ai_analyzer = None


def get_ai():
    global _ai_analyzer
    if _ai_analyzer is None:
        config = {
            "OLLAMA_MODEL": os.environ.get("OLLAMA_MODEL", "llama3"),
            "OLLAMA_URL": os.environ.get("OLLAMA_URL", "http://localhost:11434"),
            "CLAUDE_API_KEY": os.environ.get("CLAUDE_API_KEY", ""),
            "GEMINI_API_KEY": os.environ.get("GEMINI_API_KEY", ""),
        }
        _ai_analyzer = get_ai_analyzer(config)
    return _ai_analyzer


# ── Load VirusTotal Scanner ──

_vt_scanner = None


def get_vt():
    global _vt_scanner
    if _vt_scanner is None:
        _vt_scanner = VirusTotalScanner()
    return _vt_scanner


# ══════════════════════════════════════════════════════════════════
# API Routes
# ══════════════════════════════════════════════════════════════════

@app.route("/api/health")
def health():
    model, metadata = get_model()
    ai = get_ai()
    vt = get_vt()
    return jsonify({
        "status": "healthy",
        "ml_model_loaded": model is not None,
        "ml_model_info": {
            "name": metadata.get("model_name") if metadata else None,
            "accuracy": metadata.get("test_metrics", {}).get("accuracy") if metadata else None,
            "f1": metadata.get("test_metrics", {}).get("f1_phishing") if metadata else None,
        } if metadata else None,
        "ai_backend": type(ai).__name__ if ai else "none",
        "ai_available": ai is not None,
        "vt_available": vt.is_available(),
        "timestamp": datetime.utcnow().isoformat(),
    })


@app.route("/api/analyze", methods=["POST"])
def analyze_email():
    """
    Main analysis endpoint.

    Request body:
        email_text:    (required) Full email body text
        headers:       (optional) Raw email headers
        subject:       (optional) Email subject line
        skip_ai:       (optional) Skip AI analysis for speed
        scan_urls_vt:  (optional) Scan extracted URLs on VirusTotal
    """
    data = request.get_json()
    if not data or not data.get("email_text"):
        return jsonify({"error": "email_text is required"}), 400

    email_text = data["email_text"]
    headers = data.get("headers", "")
    subject = data.get("subject", "")
    skip_ai = data.get("skip_ai", False)
    scan_urls_vt = data.get("scan_urls_vt", False)

    results = {
        "analyzed_at": datetime.utcnow().isoformat(),
        "email_length": len(email_text),
    }

    # ── Layer 1: ML Classification ──
    model, metadata = get_model()
    if model:
        try:
            proba = model.predict_proba([email_text])[0]
            ml_score = round(float(proba[1]) * 100, 1)
            results["ml"] = {
                "available": True,
                "phishing_probability": ml_score,
                "legitimate_probability": round(float(proba[0]) * 100, 1),
                "verdict": "phishing" if ml_score >= 70 else
                           "suspicious" if ml_score >= 40 else "legitimate",
                "model_name": metadata.get("model_name") if metadata else "unknown",
            }
        except Exception as e:
            logger.error(f"ML prediction error: {e}")
            results["ml"] = {"available": False, "error": str(e)}
    else:
        results["ml"] = {"available": False, "error": "Model not trained yet"}

    # ── Layer 2: Rule Engine ──
    header_results = analyze_headers(headers) if headers else {
        "parsed": {}, "findings": [], "score_contribution": 0
    }
    url_results = analyze_urls(email_text)
    content_results = analyze_content(email_text, subject)

    all_findings = (
        header_results["findings"] +
        url_results["findings"] +
        content_results["findings"]
    )

    rule_score = min(
        header_results["score_contribution"] +
        url_results["score_contribution"] +
        content_results["score_contribution"],
        100
    )

    results["rules"] = {
        "available": True,
        "score": rule_score,
        "verdict": "phishing" if rule_score >= 60 else
                   "suspicious" if rule_score >= 30 else "legitimate",
        "total_findings": len(all_findings),
        "findings_by_severity": {
            "critical": len([f for f in all_findings if f["severity"] == "critical"]),
            "high": len([f for f in all_findings if f["severity"] == "high"]),
            "medium": len([f for f in all_findings if f["severity"] == "medium"]),
            "low": len([f for f in all_findings if f["severity"] == "low"]),
        },
        "headers": header_results,
        "urls": url_results,
        "content": content_results,
        "all_findings": all_findings,
    }

    # ── Layer 3: AI Analysis ──
    if not skip_ai:
        ai = get_ai()
        if ai:
            results["ai"] = ai.analyze(email_text)
        else:
            results["ai"] = {"ai_available": False, "error": "No AI backend configured"}
    else:
        results["ai"] = {"ai_available": False, "error": "Skipped"}

    # ── Layer 4: VirusTotal URL Scanning ──
    if scan_urls_vt:
        vt = get_vt()
        if vt.is_available():
            vt_result = vt.scan_urls_from_email(email_text, max_urls=5)
            results["virustotal"] = vt_result
            all_findings.extend(vt_result.get("findings", []))
        else:
            results["virustotal"] = {"error": "VT_API_KEY not set", "findings": []}

    # ── Combined Verdict ──
    results["combined"] = _calculate_combined_verdict(results)

    return jsonify(results)


@app.route("/api/analyze/quick", methods=["POST"])
def quick_analyze():
    """Fast analysis: ML + rules only."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body required"}), 400
    data["skip_ai"] = True
    data["scan_urls_vt"] = False
    with app.test_request_context(
        "/api/analyze", method="POST", json=data,
        content_type="application/json"
    ):
        return analyze_email()


@app.route("/api/upload-eml", methods=["POST"])
def upload_eml():
    """
    Upload a .eml file for analysis.
    Parses the file, extracts headers, body, subject, and attachments,
    then runs the full analysis pipeline.

    Request: multipart/form-data with 'file' field
    Optional query param: ?skip_ai=true
    """
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    if not file.filename:
        return jsonify({"error": "No file selected"}), 400

    if not file.filename.lower().endswith(".eml"):
        return jsonify({"error": "Only .eml files are supported"}), 400

    try:
        file_bytes = file.read()
        parsed = parse_eml(file_bytes)

        if not parsed.get("parsed_successfully"):
            return jsonify({"error": "Failed to parse .eml file"}), 400

        # Build the analysis request from parsed data
        email_text = parsed.get("body_text", "")
        if not email_text:
            return jsonify({"error": "No email body text found in the .eml file"}), 400

        skip_ai = request.args.get("skip_ai", "false").lower() == "true"

        # Run the analysis using the extracted data
        analysis_data = {
            "email_text": email_text,
            "headers": parsed.get("raw_headers", ""),
            "subject": parsed.get("subject", ""),
            "skip_ai": skip_ai,
        }

        # Use the analyze function internally
        with app.test_request_context(
            "/api/analyze", method="POST", json=analysis_data,
            content_type="application/json"
        ):
            analysis_result = analyze_email()

        # Parse the analysis response and add EML-specific data
        if hasattr(analysis_result, "get_json"):
            result = analysis_result.get_json()
        else:
            result = analysis_result

        result["eml"] = {
            "filename": file.filename,
            "parsed": True,
            "subject": parsed.get("subject", ""),
            "from": parsed.get("headers", {}).get("from", ""),
            "to": parsed.get("headers", {}).get("to", ""),
            "date": parsed.get("headers", {}).get("date", ""),
            "has_html_body": parsed.get("has_html", False),
            "body_length": parsed.get("stats", {}).get("body_length", 0),
            "attachments": parsed.get("attachments", []),
            "attachment_count": parsed.get("attachment_count", 0),
            "suspicious_attachments": parsed.get("suspicious_attachments", []),
        }

        return jsonify(result)

    except Exception as e:
        logger.error(f"EML parsing error: {e}")
        return jsonify({"error": f"Failed to parse file: {str(e)}"}), 500


@app.route("/api/parse-eml", methods=["POST"])
def parse_eml_only():
    """
    Parse a .eml file without running analysis.
    Returns extracted headers, body, and attachments.
    Useful for previewing the email before running a full scan.
    """
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    if not file.filename or not file.filename.lower().endswith(".eml"):
        return jsonify({"error": "Only .eml files are supported"}), 400

    try:
        file_bytes = file.read()
        parsed = parse_eml(file_bytes)
        parsed["filename"] = file.filename
        return jsonify(parsed)
    except Exception as e:
        return jsonify({"error": f"Parse failed: {str(e)}"}), 500


@app.route("/api/model/info")
def model_info():
    _, metadata = get_model()
    if metadata:
        return jsonify(metadata)
    return jsonify({"error": "No model trained yet"}), 404


@app.route("/api/ai/status")
def ai_status():
    ai = get_ai()
    if ai:
        return jsonify({"available": True, "backend": type(ai).__name__, "model": getattr(ai, "model", "unknown")})
    return jsonify({"available": False, "message": "No AI backend available"})


# ══════════════════════════════════════════════════════════════════
# VirusTotal Routes
# ══════════════════════════════════════════════════════════════════

@app.route("/api/vt/status")
def vt_status():
    """Check if VirusTotal is configured."""
    vt = get_vt()
    return jsonify({
        "available": vt.is_available(),
        "message": "VirusTotal API ready" if vt.is_available()
                   else "Set VT_API_KEY env variable. Free: https://www.virustotal.com/gui/my-apikey",
    })


@app.route("/api/vt/hash", methods=["POST"])
def vt_hash_lookup():
    """
    Look up a file hash on VirusTotal (instant).
    Body: { "hash": "sha256_or_md5_or_sha1" }
    """
    data = request.get_json()
    file_hash = data.get("hash", "").strip()
    if not file_hash:
        return jsonify({"error": "hash is required"}), 400
    if len(file_hash) not in (32, 40, 64):
        return jsonify({"error": "Invalid hash. Provide MD5 (32), SHA-1 (40), or SHA-256 (64)."}), 400

    vt = get_vt()
    if not vt.is_available():
        return jsonify({"error": "VT_API_KEY not configured"}), 503
    return jsonify(vt.lookup_hash(file_hash))


@app.route("/api/vt/file", methods=["POST"])
def vt_file_scan():
    """
    Scan a file on VirusTotal.
    Upload as multipart form with key "file".
    Query param: ?mode=hash (fast, default) or ?mode=full (upload to VT)

    Hash mode: computes SHA-256 and checks VT database. Instant.
    Full mode: uploads file to VT for scanning by 70+ AV engines. Takes 1-2 min.
    """
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded. Use multipart form with key 'file'."}), 400

    file = request.files["file"]
    file_bytes = file.read()

    if len(file_bytes) == 0:
        return jsonify({"error": "Empty file"}), 400
    if len(file_bytes) > 32 * 1024 * 1024:
        return jsonify({"error": "File too large. Max 32MB on free tier."}), 400

    hashes = {
        "md5": hashlib.md5(file_bytes).hexdigest(),
        "sha1": hashlib.sha1(file_bytes).hexdigest(),
        "sha256": hashlib.sha256(file_bytes).hexdigest(),
    }

    mode = request.args.get("mode", "hash")
    vt = get_vt()

    if not vt.is_available():
        return jsonify({
            "error": "VT_API_KEY not configured. Get a free key at https://www.virustotal.com/gui/my-apikey",
            "hashes": hashes,
            "filename": file.filename,
            "file_size_bytes": len(file_bytes),
        }), 503

    if mode == "full":
        result = vt.upload_bytes_and_scan(file_bytes, file.filename)
    else:
        result = vt.lookup_hash(hashes["sha256"])

    result["hashes"] = hashes
    result["filename"] = file.filename
    result["file_size_bytes"] = len(file_bytes)
    result["scan_mode"] = mode
    return jsonify(result)


@app.route("/api/vt/urls", methods=["POST"])
def vt_url_scan():
    """
    Scan URLs on VirusTotal.
    Body: { "urls": ["https://...", ...] }
      OR: { "email_text": "full email text to extract URLs from" }
    """
    data = request.get_json()
    urls = data.get("urls", [])

    if not urls and data.get("email_text"):
        urls = list(set(re.findall(r'https?://[^\s<>"\')\]]+', data["email_text"])))

    if not urls:
        return jsonify({"error": "No URLs provided"}), 400

    vt = get_vt()
    if not vt.is_available():
        return jsonify({"error": "VT_API_KEY not configured"}), 503

    results = []
    all_findings = []
    total_score = 0

    for url in urls[:5]:
        result = vt.scan_url(url)
        result["scanned_url"] = url
        results.append(result)
        all_findings.extend(result.get("findings", []))
        total_score += result.get("score_contribution", 0)

    return jsonify({
        "urls_scanned": len(results),
        "total_urls_found": len(urls),
        "results": results,
        "findings": all_findings,
        "score_contribution": min(total_score, 100),
    })


# ══════════════════════════════════════════════════════════════════
# Combined Scoring
# ══════════════════════════════════════════════════════════════════

def _calculate_combined_verdict(results: dict) -> dict:
    scores = {}
    weights = {}

    ml = results.get("ml", {})
    if ml.get("available"):
        scores["ml"] = ml["phishing_probability"]
        weights["ml"] = 0.40

    rules = results.get("rules", {})
    if rules.get("available"):
        scores["rules"] = rules["score"]
        weights["rules"] = 0.35

    ai = results.get("ai", {})
    if ai.get("ai_available") and ai.get("confidence"):
        ai_verdict = ai.get("verdict", "unknown")
        if ai_verdict == "phishing":
            scores["ai"] = max(ai["confidence"], 70)
        elif ai_verdict == "suspicious":
            scores["ai"] = min(ai["confidence"], 65)
        elif ai_verdict == "legitimate":
            scores["ai"] = max(100 - ai["confidence"], 5)
        else:
            scores["ai"] = 50
        weights["ai"] = 0.25

    if not weights:
        return {"score": 0, "verdict": "unknown", "confidence": 0}

    total_weight = sum(weights.values())
    normalized = {k: v / total_weight for k, v in weights.items()}

    combined_score = round(sum(scores[k] * normalized[k] for k in scores), 1)

    if combined_score >= 70:
        verdict = "phishing"
    elif combined_score >= 40:
        verdict = "suspicious"
    else:
        verdict = "legitimate"

    # Critical findings override
    critical = results.get("rules", {}).get("findings_by_severity", {}).get("critical", 0)
    if critical >= 2 and verdict == "legitimate":
        verdict = "suspicious"
        combined_score = max(combined_score, 45)

    # VT boost
    vt = results.get("virustotal", {})
    vt_score = vt.get("score_contribution", 0)
    if vt_score > 0:
        combined_score = min(round(combined_score + vt_score * 0.15, 1), 100)
        if combined_score >= 70:
            verdict = "phishing"

    return {
        "score": combined_score,
        "verdict": verdict,
        "layer_scores": scores,
        "layer_weights": {k: round(v, 2) for k, v in normalized.items()},
        "layers_active": list(scores.keys()),
    }


if __name__ == "__main__":
    app.run(debug=True, port=5000)
