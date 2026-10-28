"""
TRUSTMESH — AI-Powered Personal Digital Trust & Scam Intelligence Platform
Phase 2: Improved Trust Analysis Engine + Relational SQLite Database Integration

This Flask application provides:
1. Web interface serving (GET /)
2. Rule-based message & URL analysis API with transaction persistence (POST /analyze)
3. Safe analysis history endpoint (GET /api/history)
4. System aggregation metrics endpoint (GET /api/analytics)
5. Health status endpoint (GET /health)

Developed for educational and demonstration purposes.
"""

import ipaddress
import logging
import os
import re
from urllib.parse import urlparse

from flask import Flask, jsonify, render_template, request

from database import (
    DEFAULT_DB_PATH,
    check_db_health,
    generate_content_fingerprint,
    get_analytics,
    get_history,
    init_db,
    save_analysis_transaction,
)

# Engine Version
ENGINE_VERSION = "2.0.0"

# Initialize Flask application
app = Flask(__name__)

# Configure minimal, safe logging (avoids logging full user text for privacy)
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s in %(module)s: %(message)s"
)
logger = logging.getLogger("trustmesh")

# Maximum permitted character length for input
MAX_INPUT_LENGTH = 5000

# ---------------------------------------------------------------------------
# Scoring Configuration & Weights
# Transparent, adjustable weights for rule-based heuristics.
# ---------------------------------------------------------------------------
RULE_WEIGHTS = {
    "urgency": 20,
    "sensitive_info": 30,
    "payment_pressure": 25,
    "threats_suspension": 20,
    "prize_reward": 15,
    "url_insecure_http": 15,
    "url_ip_hostname": 20,
    "url_punycode": 20,
    "url_suspicious_formatting": 15,
}

# Heuristic pattern definitions (compiled regular expressions)
PATTERNS = {
    "urgency": [
        r"\burgent\b",
        r"\burgently\b",
        r"\bhurry\b",
        r"\bimmediately\b",
        r"\bact now\b",
        r"\bfinal warning\b",
        r"\bwithin \d+ hours?\b",
        r"\baccount will close\b",
        r"\baccount will be closed\b",
        r"\blast chance\b",
        r"\blimited time\b",
        r"\bexpires? (?:today|soon|in \d+)\b",
        r"\btime is running out\b",
        r"\bdo not delay\b",
    ],
    "sensitive_info": [
        r"\bshare your password\b",
        r"\bsend your otp\b",
        r"\bverify your pin\b",
        r"\bprovide your one-time password\b",
        r"\benter your otp\b",
        r"\bconfirm (?:your )?password\b",
        r"\bshare (?:your )?password\b",
        r"\bsend (?:your )?password\b",
        r"\bpin number\b",
        r"\bcvv\b",
        r"\bcredit card (?:details|number)\b",
        r"\bbank account (?:details|number)\b",
        r"\bsocial security\b",
        r"\bssn\b",
        r"\bone-time password\b",
        r"\blogin credentials\b",
        r"\bsecret code\b",
    ],
    "payment_pressure": [
        r"\bpay now\b",
        r"\bsend money\b",
        r"\btransfer money\b",
        r"\bprocessing fee\b",
        r"\bregistration fee\b",
        r"\bwire transfer\b",
        r"\bpayment required\b",
        r"\bdeposit required\b",
        r"\bcrypto payment\b",
        r"\bgift card\b",
        r"\badvance fee\b",
        r"\bpay immediately\b",
        r"\bwire money\b",
    ],
    "threats_suspension": [
        r"\baccount blocked\b",
        r"\baccount suspended\b",
        r"\blegal action\b",
        r"\baccount will be closed\b",
        r"\baccount will close\b",
        r"\blaw enforcement\b",
        r"\barrest warrant\b",
        r"\bpolice action\b",
        r"\baccount deactivated\b",
        r"\bsuspended immediately\b",
        r"\bunauthorized access detected\b",
        r"\bcourt order\b",
    ],
    "prize_reward": [
        r"\byou have won\b",
        r"\bclaim your prize\b",
        r"\bfree gift\b",
        r"\bcongratulations winner\b",
        r"\bwon a lottery\b",
        r"\blucky winner\b",
        r"\bclaim reward\b",
        r"\bcash prize\b",
        r"\bselected to receive\b",
        r"\bgiveaway winner\b",
    ],
}

# Regex to detect standard URLs in text
URL_REGEX = re.compile(
    r"https?://[^\s<>\"'{}|\\^`]+|www\.[^\s<>\"'{}|\\^`]+",
    re.IGNORECASE
)

# Regex to identify standalone domain strings (e.g. example.com/login)
DOMAIN_CANDIDATE_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s]*)?$|^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?(?:/[^\s]*)?$",
    re.IGNORECASE
)

# Known high-value target brands commonly spoofed in phishing lures
SPOOFED_BRANDS = [
    "paypal", "apple", "google", "microsoft", "netflix", "amazon",
    "chase", "wellsfargo", "bankofamerica", "binance", "facebook",
    "instagram", "whatsapp"
]


def extract_urls(text: str) -> list[str]:
    """
    Safely extracts URL strings from the given text without visiting them.
    Supports full http/https URLs, www prefixed URLs, and single domain inputs.
    """
    urls = URL_REGEX.findall(text)
    
    # If no URL was matched by standard regex, test if the whole input looks like a bare domain
    if not urls:
        stripped = text.strip()
        if DOMAIN_CANDIDATE_REGEX.match(stripped):
            urls = [stripped]
            
    return urls


def is_ip_address(hostname: str) -> bool:
    """Checks whether the hostname is a direct IPv4 or IPv6 address."""
    host = hostname.split(":")[0].strip("[]")
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def classify_content_type(text: str, urls: list[str]) -> str:
    """
    Classifies the input content as 'url', 'message', or 'mixed'.
    Used for normalized incident categorization in the database.
    """
    stripped = text.strip()
    if not urls:
        return "message"
    
    # Check if the entire input is essentially just the URL
    if len(urls) == 1 and (stripped == urls[0] or stripped == f"http://{urls[0]}" or stripped == f"https://{urls[0]}"):
        return "url"
    
    return "mixed"


def inspect_url(raw_url: str) -> list[tuple[str, str]]:
    """
    Analyzes a URL string statically using urllib.parse without network requests.
    Returns a list of tuples: (finding_key, human_readable_description).
    """
    findings = []
    
    # Normalize URL if missing scheme
    url_to_parse = raw_url
    if not re.match(r"^https?://", raw_url, re.IGNORECASE):
        url_to_parse = "http://" + raw_url
        
    try:
        parsed = urlparse(url_to_parse)
    except Exception:
        findings.append((
            "url_suspicious_formatting",
            "Malformed URL structure could not be parsed safely."
        ))
        return findings

    hostname = (parsed.hostname or "").lower()
    netloc = parsed.netloc.lower()
    scheme = parsed.scheme.lower()

    # 1. Unencrypted HTTP connection check
    if scheme == "http":
        findings.append((
            "url_insecure_http",
            "Insecure connection: URL uses unencrypted HTTP instead of HTTPS (data transmitted in plain text)."
        ))

    # 2. Hostname is a raw IP address
    if hostname and is_ip_address(hostname):
        findings.append((
            "url_ip_hostname",
            "Direct IP address used as hostname instead of a standard domain name."
        ))

    # 3. Internationalized Domain Name (Punycode)
    if "xn--" in hostname:
        findings.append((
            "url_punycode",
            "Internationalized domain encoding ('xn--' Punycode) detected; may be used to visually mimic authentic domains."
        ))

    # 4. Deceptive '@' symbol in user authority
    if "@" in netloc:
        findings.append((
            "url_suspicious_formatting",
            "Deceptive authority format: '@' symbol in URL domain section can disguise the actual destination."
        ))

    # 5. Excessive subdomains (more than 3 dot-separated labels)
    labels = hostname.split(".")
    if len(labels) > 4 and not is_ip_address(hostname):
        findings.append((
            "url_suspicious_formatting",
            "Excessive subdomain depth detected; attackers often nest multiple subdomains to mimic genuine URLs."
        ))

    # 6. Potential brand impersonation in hostname
    for brand in SPOOFED_BRANDS:
        if brand in hostname:
            if not hostname.endswith(f".{brand}.com") and hostname != f"{brand}.com":
                findings.append((
                    "url_suspicious_formatting",
                    f"Brand keyword '{brand}' found in suspicious domain context (possible impersonation)."
                ))
                break

    return findings


def analyze_interaction(text: str) -> dict:
    """
    Executes the rule-based scam detection engine on the user text or URL.
    Returns structured results including detected signals and points awarded.
    """
    detected_keys = set()
    finding_descriptions = []
    
    # 1. Text Heuristic Analysis
    for category, regex_list in PATTERNS.items():
        matched_samples = []
        for pattern in regex_list:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                matched_samples.append(match.group(0))
        
        if matched_samples:
            detected_keys.add(category)
            unique_samples = list(dict.fromkeys(matched_samples))[:2]
            samples_str = ", ".join(f"'{s}'" for s in unique_samples)
            
            if category == "urgency":
                finding_descriptions.append(
                    f"Urgency or pressure detected ({samples_str}) designed to induce hasty action."
                )
            elif category == "sensitive_info":
                finding_descriptions.append(
                    f"Sensitive credential request detected ({samples_str}) asking for passwords, OTPs, or private codes."
                )
            elif category == "payment_pressure":
                finding_descriptions.append(
                    f"Payment pressure detected ({samples_str}) requesting upfront fees or funds transfer."
                )
            elif category == "threats_suspension":
                finding_descriptions.append(
                    f"Threats or suspension warning detected ({samples_str}) threatening account closure or legal penalties."
                )
            elif category == "prize_reward":
                finding_descriptions.append(
                    f"Prize or reward incentive detected ({samples_str}) promising unverified gifts or lotteries."
                )

    # 2. URL Static Inspection
    urls_found = extract_urls(text)
    url_findings_set = set()
    
    for url in urls_found:
        url_results = inspect_url(url)
        for key, desc in url_results:
            detected_keys.add(key)
            if desc not in url_findings_set:
                url_findings_set.add(desc)
                finding_descriptions.append(desc)

    # 3. Calculate Risk Score & Detected Signals Map
    score = 0
    detected_signals_map = {}
    for key in detected_keys:
        pts = RULE_WEIGHTS.get(key, 0)
        score += pts
        detected_signals_map[key] = pts
        
    score = min(score, 100)

    # 4. Determine Preliminary Risk Level & Recommendation
    if score >= 60:
        level = "High risk"
        recommendation = (
            "High risk detected. Multiple severe warning patterns were identified. "
            "Do not respond, do not click links, and never transfer money or share credentials. "
            "Verify this interaction directly through verified official channels."
        )
    elif score >= 30:
        level = "Suspicious"
        recommendation = (
            "Exercise caution. Several warning patterns were identified. "
            "Do not click links, make payments, or share sensitive details until you verify the sender independently."
        )
    else:
        level = "Lower detected risk"
        recommendation = (
            "No immediate high-risk patterns were detected, but always remain cautious. "
            "Independently verify senders before sharing personal information or following instructions."
        )

    # 5. Fallback Finding if Nothing Detected
    if not finding_descriptions:
        finding_descriptions = [
            "No configured warning patterns were detected. This does not prove the content is safe."
        ]

    disclaimer = (
        "This preliminary rule-based assessment cannot guarantee that content is safe or fraudulent."
    )

    content_type = classify_content_type(text, urls_found)

    return {
        "score": score,
        "level": level,
        "findings": finding_descriptions,
        "urls_found": len(urls_found),
        "content_type": content_type,
        "recommendation": recommendation,
        "disclaimer": disclaimer,
        "engine_version": ENGINE_VERSION,
        "detected_signals": detected_signals_map,
    }


def get_active_db_path() -> str:
    """Returns the configured or default database file path."""
    return app.config.get("DATABASE_PATH", DEFAULT_DB_PATH)


# ---------------------------------------------------------------------------
# HTTP Route Handlers
# ---------------------------------------------------------------------------

@app.route("/", methods=["GET"])
def index():
    """Renders the main web interface with analyzer and history dashboard."""
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    """
    Analyzes submitted text or URL for scam indicators and persists
    the incident, assessment, and detected signals in a single database transaction.
    Expects JSON: { "text": "message or URL" }
    """
    # 1. Validate JSON presence
    if not request.is_json:
        return jsonify({
            "error": "Invalid request body. Expected Content-Type: application/json."
        }), 400

    data = request.get_json(silent=True)
    if data is None:
        return jsonify({
            "error": "Malformed JSON payload provided."
        }), 400

    # 2. Validate 'text' field existence and type
    if "text" not in data or not isinstance(data["text"], str):
        return jsonify({
            "error": "Field 'text' is required and must be a string."
        }), 400

    raw_text = data["text"]
    stripped_text = raw_text.strip()

    # 3. Validate empty input
    if not stripped_text:
        return jsonify({
            "error": "Input cannot be empty. Please provide a message or URL to analyze."
        }), 400

    # 4. Validate input length limit
    if len(raw_text) > MAX_INPUT_LENGTH:
        return jsonify({
            "error": f"Input exceeds maximum allowed limit of {MAX_INPUT_LENGTH} characters."
        }), 400

    # 5. Process analysis safely
    try:
        result = analyze_interaction(raw_text)
        fingerprint = generate_content_fingerprint(raw_text)
        db_path = get_active_db_path()

        # 6. Atomic Transaction: Persist Incident, Assessment, and Signals
        incident_id, assessment_id = save_analysis_transaction(
            user_id=1,  # Anonymous dev user for Phase 2
            content_type=result["content_type"],
            content_fingerprint=fingerprint,
            score=result["score"],
            level=result["level"],
            engine_version=result["engine_version"],
            recommendation=result["recommendation"],
            detected_signals=result["detected_signals"],
            db_path=db_path
        )
        
        # Attach incident_id to the response
        result["incident_id"] = incident_id

        logger.info(
            "Analysis saved. Incident #%d, Score: %d, Level: %s",
            incident_id, result["score"], result["level"]
        )

        # Remove internal detected_signals dictionary before returning response
        response_data = {
            "incident_id": result["incident_id"],
            "score": result["score"],
            "level": result["level"],
            "findings": result["findings"],
            "urls_found": result["urls_found"],
            "recommendation": result["recommendation"],
            "disclaimer": result["disclaimer"],
            "engine_version": result["engine_version"],
        }
        return jsonify(response_data), 200

    except Exception as exc:
        logger.error("Analysis or persistence error: %s", str(exc))
        return jsonify({
            "error": "An internal error occurred during analysis or database persistence. Please try again."
        }), 500


@app.route("/api/history", methods=["GET"])
def api_history():
    """
    Returns the latest 20 safe analysis history records.
    Never exposes raw submitted text or URLs.
    """
    try:
        db_path = get_active_db_path()
        history = get_history(limit=20, db_path=db_path)
        return jsonify({"history": history}), 200
    except Exception as exc:
        logger.error("Failed to query history: %s", str(exc))
        return jsonify({"error": "Unable to retrieve analysis history."}), 500


@app.route("/api/analytics", methods=["GET"])
def api_analytics():
    """
    Returns aggregate platform statistics calculated from the SQLite database.
    """
    try:
        db_path = get_active_db_path()
        analytics = get_analytics(db_path=db_path)
        return jsonify({"analytics": analytics}), 200
    except Exception as exc:
        logger.error("Failed to query analytics: %s", str(exc))
        return jsonify({"error": "Unable to retrieve platform analytics."}), 500


@app.route("/health", methods=["GET"])
def health():
    """
    Returns the minimal system and database connectivity status.
    Does not expose sensitive paths or credentials.
    """
    db_path = get_active_db_path()
    is_healthy = check_db_health(db_path=db_path)
    
    status_code = 200 if is_healthy else 503
    return jsonify({
        "status": "healthy" if is_healthy else "unhealthy",
        "database": "connected" if is_healthy else "disconnected",
        "engine_version": ENGINE_VERSION
    }), status_code


# ---------------------------------------------------------------------------
# Database Automatic Initialization on Start
# ---------------------------------------------------------------------------
def setup_database_if_needed():
    """Ensures database is initialized on server startup."""
    db_path = get_active_db_path()
    if not os.path.exists(db_path):
        logger.info("Database file not found at %s. Initializing from schema.sql...", db_path)
        init_db(db_path=db_path)


# Initialize DB on import/start
setup_database_if_needed()


if __name__ == "__main__":
    # Local development server only
    # Note: Debug mode must be disabled in production environments
    app.run(host="127.0.0.1", port=5000, debug=True)
