"""
TRUSTMESH — AI-Powered Personal Digital Trust & Scam Intelligence Platform
Phase 3: Secure Authentication, Role-Based Access Control (RBAC) & Application Security

Features:
1. User registration with Werkzeug password hashing.
2. Secure session management (HttpOnly, SameSite, secret key rotation support).
3. Role-Based Access Control (RBAC: USER and ADMIN).
4. User-scoped incident history (privacy isolation).
5. CSRF protection on state-changing operations via Flask-WTF.
6. Security audit logging (login, logout, registration, authorization events).
7. Comprehensive HTTP security headers (nosniff, CSP, frame-ancestors).

Developed for educational and demonstration purposes.
"""

from datetime import datetime, timedelta, timezone
from functools import wraps
import io
import ipaddress
import json
import logging
import os
import re
from urllib.parse import urlparse

# Load environment configuration from .env
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from flask_wtf.csrf import CSRFError, CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash

from config import get_config
from database import (
    DEFAULT_DB_PATH,
    check_db_health,
    create_exported_report,
    create_user,
    generate_content_fingerprint,
    get_admin_audit_logs,
    get_admin_overview,
    get_admin_users,
    get_analytics,
    get_analytics_overview,
    get_assessment_for_export,
    get_assessment_trends,
    get_database_mode,
    get_database_status,
    get_exported_report_by_id,
    get_exported_reports_by_user,
    get_history,
    get_risk_level_distribution,
    get_risk_signal_frequency,
    get_user_by_email,
    get_user_by_id,
    init_db,
    log_audit_event,
    save_analysis_transaction,
    update_report_storage_status,
)
from services.analytics_service import (
    generate_anonymized_csv,
    get_analytics_dashboard_bundle,
)
from services.blob_storage_service import (
    check_blob_storage_health,
    download_report,
    generate_safe_blob_name,
    is_blob_storage_configured,
    upload_report,
)

# Engine Version
ENGINE_VERSION = "3.0.0"

# Initialize Flask application
app = Flask(__name__)

# Apply Centralized Environment Configuration (Development, Production, Testing)
app.config.from_object(get_config())

# Initialize CSRF Protection
csrf = CSRFProtect(app)

# Configure safe logging (never logs passwords or sensitive payloads)
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s in %(module)s: %(message)s"
)
logger = logging.getLogger("trustmesh")

# Input length boundaries
MAX_INPUT_LENGTH = 5000
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


# ---------------------------------------------------------------------------
# Heuristic Scoring Configuration & Patterns
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

URL_REGEX = re.compile(
    r"https?://[^\s<>\"'{}|\\^`]+|www\.[^\s<>\"'{}|\\^`]+",
    re.IGNORECASE
)

DOMAIN_CANDIDATE_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s]*)?$|^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?(?:/[^\s]*)?$",
    re.IGNORECASE
)

SPOOFED_BRANDS = [
    "paypal", "apple", "google", "microsoft", "netflix", "amazon",
    "chase", "wellsfargo", "bankofamerica", "binance", "facebook",
    "instagram", "whatsapp"
]


# ---------------------------------------------------------------------------
# Helper & Analysis Functions
# ---------------------------------------------------------------------------

def get_active_db_path() -> str:
    """Returns the configured or default database file path."""
    if os.environ.get("VERCEL") or os.environ.get("VERCEL_ENV") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
        return DEFAULT_DB_PATH
    return app.config.get("DATABASE_PATH") or os.environ.get("DATABASE_PATH") or DEFAULT_DB_PATH


def extract_urls(text: str) -> list[str]:
    urls = URL_REGEX.findall(text)
    if not urls:
        stripped = text.strip()
        if DOMAIN_CANDIDATE_REGEX.match(stripped):
            urls = [stripped]
    return urls


def is_ip_address(hostname: str) -> bool:
    host = hostname.split(":")[0].strip("[]")
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def classify_content_type(text: str, urls: list[str]) -> str:
    stripped = text.strip()
    if not urls:
        return "message"
    if len(urls) == 1 and (stripped == urls[0] or stripped == f"http://{urls[0]}" or stripped == f"https://{urls[0]}"):
        return "url"
    return "mixed"


def inspect_url(raw_url: str) -> list[tuple[str, str]]:
    findings = []
    url_to_parse = raw_url
    if not re.match(r"^https?://", raw_url, re.IGNORECASE):
        url_to_parse = "http://" + raw_url
        
    try:
        parsed = urlparse(url_to_parse)
    except Exception:
        findings.append(("url_suspicious_formatting", "Malformed URL structure could not be parsed safely."))
        return findings

    hostname = (parsed.hostname or "").lower()
    netloc = parsed.netloc.lower()
    scheme = parsed.scheme.lower()

    if scheme == "http":
        findings.append(("url_insecure_http", "Insecure connection: URL uses unencrypted HTTP instead of HTTPS (data transmitted in plain text)."))

    if hostname and is_ip_address(hostname):
        findings.append(("url_ip_hostname", "Direct IP address used as hostname instead of a standard domain name."))

    if "xn--" in hostname:
        findings.append(("url_punycode", "Internationalized domain encoding ('xn--' Punycode) detected; may be used to visually mimic authentic domains."))

    if "@" in netloc:
        findings.append(("url_suspicious_formatting", "Deceptive authority format: '@' symbol in URL domain section can disguise the actual destination."))

    labels = hostname.split(".")
    if len(labels) > 4 and not is_ip_address(hostname):
        findings.append(("url_suspicious_formatting", "Excessive subdomain depth detected; attackers often nest multiple subdomains to mimic genuine URLs."))

    for brand in SPOOFED_BRANDS:
        if brand in hostname:
            if not hostname.endswith(f".{brand}.com") and hostname != f"{brand}.com":
                findings.append(("url_suspicious_formatting", f"Brand keyword '{brand}' found in suspicious domain context (possible impersonation)."))
                break

    return findings


def analyze_interaction(text: str) -> dict:
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
                finding_descriptions.append(f"Urgency or pressure detected ({samples_str}) designed to induce hasty action.")
            elif category == "sensitive_info":
                finding_descriptions.append(f"Sensitive credential request detected ({samples_str}) asking for passwords, OTPs, or private codes.")
            elif category == "payment_pressure":
                finding_descriptions.append(f"Payment pressure detected ({samples_str}) requesting upfront fees or funds transfer.")
            elif category == "threats_suspension":
                finding_descriptions.append(f"Threats or suspension warning detected ({samples_str}) threatening account closure or legal penalties.")
            elif category == "prize_reward":
                finding_descriptions.append(f"Prize or reward incentive detected ({samples_str}) promising unverified gifts or lotteries.")

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

    # 3. Calculate Risk Score
    score = 0
    detected_signals_map = {}
    for key in detected_keys:
        pts = RULE_WEIGHTS.get(key, 0)
        score += pts
        detected_signals_map[key] = pts
        
    score = min(score, 100)

    # 4. Risk Categorization
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


# ---------------------------------------------------------------------------
# Security Context, Decorators & Middleware (Phase 3)
# ---------------------------------------------------------------------------

@app.context_processor
def inject_auth_state():
    """Provides current_user identity and authentication status to all templates."""
    db_path = get_active_db_path()
    db_status = get_database_status(db_path=db_path)
    state = {
        "db_status": db_status
    }
    if "user_id" in session:
        state.update({
            "is_authenticated": True,
            "current_user": {
                "user_id": session["user_id"],
                "display_name": session.get("display_name", "User"),
                "email": session.get("email"),
                "role": session.get("role", "user")
            }
        })
    else:
        state.update({
            "is_authenticated": False,
            "current_user": None
        })
    return state


def login_required(f):
    """Enforces authentication for protected endpoints."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"error": "Authentication required. Please log in."}), 401
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return decorated_function


def role_required(required_role: str):
    """Enforces server-side Role-Based Access Control (RBAC)."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if "user_id" not in session:
                if request.is_json or request.path.startswith("/api/"):
                    return jsonify({"error": "Authentication required. Please log in."}), 401
                return redirect(url_for("login", next=request.path))
            
            db_path = get_active_db_path()
            user = get_user_by_id(session["user_id"], db_path=db_path)
            if not user or user.get("role_name") != required_role:
                log_audit_event(
                    session.get("user_id"),
                    "AUTHORIZATION_FAILURE",
                    "FORBIDDEN",
                    f"Forbidden access attempt to {request.path} (Role required: {required_role})",
                    db_path=db_path
                )
                if request.is_json or request.path.startswith("/api/"):
                    return jsonify({"error": f"Access denied. Requires {required_role} role."}), 403
                return render_template(
                    "error.html",
                    code=403,
                    message="Access Denied: You do not have permission to access this administrative resource."
                ), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator


@app.after_request
def apply_security_headers(response):
    """Injects security headers on all HTTP responses."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "font-src 'self' https://fonts.gstatic.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "script-src 'self'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    )
    return response


@app.errorhandler(CSRFError)
def handle_csrf_error(err):
    """Handles missing or invalid CSRF tokens safely."""
    logger.warning("CSRF validation failure on %s %s: %s", request.method, request.path, str(err))
    if request.is_json or request.path.startswith("/api/"):
        return jsonify({"error": "CSRF token missing or invalid. Please refresh the page and try again."}), 400
    return render_template(
        "error.html",
        code=400,
        message="CSRF Verification Failed: Invalid or missing security token."
    ), 400


@app.errorhandler(404)
def handle_404(err):
    """Handles 404 Not Found errors safely."""
    if request.is_json or request.path.startswith("/api/"):
        return jsonify({"error": "Resource not found."}), 404
    return render_template(
        "error.html",
        code=404,
        message="The requested page or endpoint could not be found."
    ), 404


@app.errorhandler(500)
def handle_500(err):
    """Handles 500 Internal Server errors safely without leaking stack traces."""
    logger.error("Internal server error: %s", str(err))
    if request.is_json or request.path.startswith("/api/"):
        return jsonify({"error": "An internal server error occurred. Please try again later."}), 500
    return render_template(
        "error.html",
        code=500,
        message="An internal server error occurred. Please try again later."
    ), 500


@app.errorhandler(413)
def handle_413(err):
    """Handles request payload size exceeding MAX_CONTENT_LENGTH (16 MB)."""
    logger.warning("Request payload exceeded size ceiling: %s", str(err))
    if request.is_json or request.path.startswith("/api/"):
        return jsonify({"error": "Request payload exceeds maximum allowed size limit (16 MB)."}), 413
    return render_template(
        "error.html",
        code=413,
        message="Payload Too Large: The submitted data exceeds the maximum allowed upload limit."
    ), 413


# ---------------------------------------------------------------------------
# Authentication Routes (Phase 3)
# ---------------------------------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    """User registration page and handler."""
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "GET":
        return render_template("register.html")

    display_name = request.form.get("display_name", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")

    # Server-side validation
    if not display_name or not email or not password or not confirm_password:
        return render_template("register.html", error="All fields are required."), 400

    if len(display_name) < 2 or len(display_name) > 60:
        return render_template("register.html", error="Display name must be between 2 and 60 characters."), 400

    if not EMAIL_REGEX.match(email) or len(email) > 120:
        return render_template("register.html", error="Please enter a valid email address."), 400

    if len(password) < 8 or len(password) > 128:
        return render_template("register.html", error="Password must be between 8 and 128 characters long."), 400

    if password != confirm_password:
        return render_template("register.html", error="Passwords do not match."), 400

    db_path = get_active_db_path()
    try:
        password_hash = generate_password_hash(password)
        user_id = create_user(
            display_name=display_name,
            email=email,
            password_hash=password_hash,
            role_id=1,  # Standard user role
            account_status="ACTIVE",
            db_path=db_path
        )
        log_audit_event(user_id, "REGISTER_SUCCESS", "SUCCESS", f"Account created for {email}", db_path=db_path)
        logger.info("Registration successful for %s", email)
        flash("Account created successfully! Please sign in with your credentials.", "success")
        return redirect(url_for("login"))
    except ValueError as val_err:
        return render_template("register.html", error=str(val_err)), 409
    except Exception as exc:
        logger.error("Registration error: %s", str(exc))
        return render_template("register.html", error="An internal error occurred during registration. Please try again."), 500


@app.route("/login", methods=["GET", "POST"])
def login():
    """User authentication login page and handler."""
    if request.method == "GET" and "user_id" in session:
        return redirect(url_for("dashboard"))
    elif request.method == "POST" and "user_id" in session:
        session.clear()

    next_url = request.args.get("next", "")

    if request.method == "GET":
        return render_template("login.html", next_url=next_url)

    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    if not email or not password:
        return render_template("login.html", error="Please provide both email and password.", next_url=next_url), 400

    db_path = get_active_db_path()
    user = get_user_by_email(email, db_path=db_path)

    # Generic credential check (mitigates account enumeration)
    if not user or not user.get("password_hash") or not check_password_hash(user["password_hash"], password):
        log_audit_event(
            user["user_id"] if user else None,
            "LOGIN_FAILED",
            "FAILURE",
            f"Failed login attempt for email {email}",
            db_path=db_path
        )
        return render_template("login.html", error="Invalid email or password.", next_url=next_url), 401

    if user.get("account_status") != "ACTIVE":
        log_audit_event(user["user_id"], "LOGIN_BLOCKED", "SUSPENDED", "Suspended account login attempt", db_path=db_path)
        return render_template("login.html", error="This account is currently suspended. Please contact support.", next_url=next_url), 403

    # Establish clean server session
    session.clear()
    session["user_id"] = user["user_id"]
    session["display_name"] = user["display_name"]
    session["email"] = user["email"]
    session["role"] = user["role_name"]
    session.permanent = True

    log_audit_event(user["user_id"], "LOGIN_SUCCESS", "SUCCESS", "User authenticated successfully", db_path=db_path)
    logger.info("User logged in: #%d (%s, Role: %s)", user["user_id"], user["email"], user["role_name"])

    # Safe redirect
    if next_url and next_url.startswith("/") and not next_url.startswith("//"):
        return redirect(next_url)
    return redirect(url_for("dashboard"))


@app.route("/logout", methods=["POST"])
def logout():
    """Clears authenticated user session."""
    user_id = session.get("user_id")
    db_path = get_active_db_path()

    if user_id:
        log_audit_event(user_id, "LOGOUT", "SUCCESS", "User logged out", db_path=db_path)

    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Web Portal & Dashboard Routes
# ---------------------------------------------------------------------------

@app.route("/", methods=["GET"])
def index():
    """Renders the main public web interface."""
    return render_template("index.html")


@app.route("/dashboard", methods=["GET"])
@login_required
def dashboard():
    """Renders the authenticated user dashboard."""
    return render_template("index.html")


@app.route("/admin", methods=["GET"])
@role_required("admin")
def admin_dashboard():
    """Renders the administrative management console."""
    db_path = get_active_db_path()
    overview = get_admin_overview(db_path=db_path)
    users = get_admin_users(limit=50, db_path=db_path)
    audit_logs = get_admin_audit_logs(limit=50, db_path=db_path)
    analytics_bundle = get_analytics_dashboard_bundle(db_path=db_path)

    return render_template(
        "admin.html",
        overview=overview,
        users=users,
        audit_logs=audit_logs,
        analytics_bundle=analytics_bundle
    )


# ---------------------------------------------------------------------------
# API Routes (Phase 3 User-Scoped & Protected)
# ---------------------------------------------------------------------------

@app.route("/analyze", methods=["POST"])
def analyze():
    """
    Analyzes submitted text or URL for scam indicators and persists
    the incident, assessment, and detected signals in a single database transaction.
    Phase 3: Associates incident with session['user_id'] if authenticated,
    otherwise with anonymous user (id=1).
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

        # Phase 3: Scope to authenticated user identity if logged in, otherwise anonymous (id=1)
        active_user_id = session.get("user_id", 1)

        # 6. Atomic Transaction: Persist Incident, Assessment, and Signals
        incident_id, assessment_id = save_analysis_transaction(
            user_id=active_user_id,
            content_type=result["content_type"],
            content_fingerprint=fingerprint,
            score=result["score"],
            level=result["level"],
            engine_version=result["engine_version"],
            recommendation=result["recommendation"],
            detected_signals=result["detected_signals"],
            db_path=db_path
        )
        
        result["incident_id"] = incident_id

        logger.info(
            "Analysis saved. Incident #%d for User #%d, Score: %d, Level: %s",
            incident_id, active_user_id, result["score"], result["level"]
        )

        response_data = {
            "incident_id": result["incident_id"],
            "assessment_id": assessment_id,
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
@login_required
def api_history():
    """
    Returns the authenticated user's private analysis history records.
    Enforces privacy: users can only view their own evaluations.
    Never exposes raw submitted text or URLs.
    """
    try:
        db_path = get_active_db_path()
        # Security: Scoped to authenticated user_id from server session
        history = get_history(user_id=session["user_id"], limit=20, db_path=db_path)
        return jsonify({"history": history}), 200
    except Exception as exc:
        logger.error("Failed to query history: %s", str(exc))
        return jsonify({"error": "Unable to retrieve analysis history."}), 500


@app.route("/api/analytics", methods=["GET"])
def api_analytics():
    """
    Returns platform statistics.
    If authenticated, returns personal scan statistics.
    If unauthenticated, returns global platform statistics.
    """
    try:
        db_path = get_active_db_path()
        user_id = session.get("user_id")
        analytics = get_analytics(user_id=user_id, db_path=db_path)
        return jsonify({"analytics": analytics}), 200
    except Exception as exc:
        logger.error("Failed to query analytics: %s", str(exc))
        return jsonify({"error": "Unable to retrieve platform analytics."}), 500


@app.route("/api/admin/users", methods=["GET"])
@role_required("admin")
def api_admin_users():
    """Returns registered user account metadata for administrative audit."""
    try:
        db_path = get_active_db_path()
        users = get_admin_users(limit=50, db_path=db_path)
        return jsonify({"users": users}), 200
    except Exception as exc:
        logger.error("Failed to fetch admin users: %s", str(exc))
        return jsonify({"error": "Unable to retrieve user directory."}), 500


@app.route("/api/admin/audit-logs", methods=["GET"])
@role_required("admin")
def api_admin_audit_logs():
    """Returns system security audit logs for administrative review."""
    try:
        db_path = get_active_db_path()
        audit_logs = get_admin_audit_logs(limit=50, db_path=db_path)
        return jsonify({"audit_logs": audit_logs}), 200
    except Exception as exc:
        logger.error("Failed to fetch audit logs: %s", str(exc))
        return jsonify({"error": "Unable to retrieve audit logs."}), 500


# ---------------------------------------------------------------------------
# Power BI & Administrative Analytics APIs (Phase 4, Task 4)
# ---------------------------------------------------------------------------

@app.route("/api/analytics/overview", methods=["GET"])
@role_required("admin")
def api_analytics_overview():
    """
    Returns platform-wide KPI aggregate metrics from v_analytics_overview view.
    Restricted to system administrators.
    """
    try:
        db_path = get_active_db_path()
        overview = get_analytics_overview(db_path=db_path)
        return jsonify({"overview": overview}), 200
    except Exception as exc:
        logger.error("Failed to fetch analytics overview: %s", str(exc))
        return jsonify({"error": "Unable to compute analytics overview."}), 500


@app.route("/api/analytics/risk-distribution", methods=["GET"])
@role_required("admin")
def api_analytics_risk_distribution():
    """
    Returns assessment distribution across risk levels from v_risk_level_distribution.
    Restricted to system administrators.
    """
    try:
        db_path = get_active_db_path()
        distribution = get_risk_level_distribution(db_path=db_path)
        return jsonify({"risk_distribution": distribution}), 200
    except Exception as exc:
        logger.error("Failed to fetch risk distribution: %s", str(exc))
        return jsonify({"error": "Unable to compute risk distribution."}), 500


@app.route("/api/analytics/risk-signals", methods=["GET"])
@role_required("admin")
def api_analytics_risk_signals():
    """
    Returns detection frequency and prevalence for all risk signals from v_risk_signal_frequency.
    Restricted to system administrators.
    """
    try:
        db_path = get_active_db_path()
        signals = get_risk_signal_frequency(db_path=db_path)
        return jsonify({"risk_signals": signals}), 200
    except Exception as exc:
        logger.error("Failed to fetch risk signal analytics: %s", str(exc))
        return jsonify({"error": "Unable to compute risk signal frequencies."}), 500


@app.route("/api/analytics/trends", methods=["GET"])
@role_required("admin")
def api_analytics_trends():
    """
    Returns time-based assessment counts and risk trends.
    Supports ?interval=daily (default), ?interval=weekly, or ?interval=monthly.
    Restricted to system administrators.
    """
    interval = request.args.get("interval", "daily").lower().strip()
    if interval not in ("daily", "weekly", "monthly"):
        return jsonify({"error": "Invalid interval parameter. Allowed values: daily, weekly, monthly."}), 400

    try:
        db_path = get_active_db_path()
        trends = get_assessment_trends(interval=interval, db_path=db_path)
        return jsonify({
            "interval": interval,
            "trends": trends
        }), 200
    except Exception as exc:
        logger.error("Failed to fetch assessment trends (interval=%s): %s", interval, str(exc))
        return jsonify({"error": "Unable to compute assessment trends."}), 500


@app.route("/api/analytics/export", methods=["GET"])
@role_required("admin")
def api_analytics_export():
    """
    Exports sanitized, anonymized assessment telemetry as CSV for Power BI Desktop.
    Guarantees zero leakage of user identities, emails, passwords, raw text, or full URLs.
    Restricted to system administrators.
    """
    try:
        db_path = get_active_db_path()
        csv_text, count = generate_anonymized_csv(db_path=db_path)

        log_audit_event(
            session.get("user_id"),
            "ANALYTICS_CSV_EXPORTED",
            "SUCCESS",
            f"Admin exported {count} anonymized assessment records for Power BI",
            db_path=db_path
        )

        return send_file(
            io.BytesIO(csv_text.encode("utf-8")),
            mimetype="text/csv",
            as_attachment=True,
            download_name="trustmesh_analytics_export.csv"
        )
    except Exception as exc:
        logger.error("Failed to export analytics CSV: %s", str(exc))
        return jsonify({"error": "Unable to generate analytics CSV export."}), 500


@app.route("/health", methods=["GET"])
def health():
    """Returns system, database mode, and connectivity health status."""
    db_path = get_active_db_path()
    status_info = get_database_status(db_path=db_path)
    is_healthy = status_info["status"] == "connected"
    storage_info = check_blob_storage_health()

    status_code = 200 if is_healthy else 503
    return jsonify({
        "status": "healthy" if is_healthy else "unhealthy",
        "environment": app.config.get("ENV_NAME", "development"),
        "database": "connected" if is_healthy else "disconnected",
        "database_mode": status_info["mode"],
        "database_status_indicator": status_info["indicator"],
        "database_details": status_info["details"],
        "is_cloud": status_info["is_cloud"],
        "storage_status": storage_info["status"],
        "storage_indicator": storage_info["indicator"],
        "storage_details": storage_info["details"],
        "engine_version": ENGINE_VERSION
    }), status_code


# ---------------------------------------------------------------------------
# Report Export & Azure Blob Storage Routes (Phase 4, Task 3)
# ---------------------------------------------------------------------------

@app.route("/api/reports/export", methods=["POST"])
@login_required
def api_export_report():
    """
    Exports an assessment report to JSON.
    Allows authenticated users to optionally archive their report to Azure Blob Storage.
    Never exposes passwords, session tokens, or raw user message content.
    """
    if not request.is_json:
        return jsonify({"error": "Invalid request body. Expected JSON."}), 400

    data = request.get_json(silent=True) or {}
    assessment_id = data.get("assessment_id")
    save_to_cloud = bool(data.get("save_to_cloud", False))

    if not assessment_id or not isinstance(assessment_id, int):
        return jsonify({"error": "Valid assessment_id (integer) is required."}), 400

    db_path = get_active_db_path()
    active_user_id = session["user_id"]

    # Verify assessment exists and belongs to current user
    assessment = get_assessment_for_export(assessment_id, user_id=active_user_id, db_path=db_path)
    if not assessment:
        # Check if assessment exists at all (to distinguish 404 from 403)
        any_asm = get_assessment_for_export(assessment_id, user_id=None, db_path=db_path)
        if any_asm:
            log_audit_event(
                active_user_id,
                "UNAUTHORIZED_REPORT_EXPORT",
                "FORBIDDEN",
                f"User attempted to export Assessment #{assessment_id} belonging to another user",
                db_path=db_path
            )
            return jsonify({"error": "Access denied: You do not have permission to export this assessment."}), 403
        return jsonify({"error": f"Assessment #{assessment_id} not found."}), 404

    # Build structured, standardized export payload
    report_payload = {
        "report_metadata": {
            "platform": "TRUSTMESH AI-Powered Personal Digital Trust Platform",
            "report_version": "1.0.0",
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "exported_by_user": session.get("display_name", "User"),
            "content_fingerprint_sha256": assessment["content_fingerprint"],
        },
        "assessment_details": {
            "assessment_id": assessment["assessment_id"],
            "incident_id": assessment["incident_id"],
            "incident_type": assessment["content_type"],
            "created_at_utc": str(assessment["assessment_time"]),
            "risk_score": assessment["risk_score"],
            "risk_level": assessment["risk_level"],
            "engine_version": assessment["engine_version"],
        },
        "detected_risk_signals": assessment.get("signals", []),
        "actionable_guidance": {
            "recommendation": assessment["recommendation"],
            "disclaimer": "This preliminary rule-based assessment cannot guarantee that content is safe or fraudulent."
        }
    }

    # Encode report to JSON bytes
    json_bytes = json.dumps(report_payload, indent=2).encode("utf-8")
    blob_name = generate_safe_blob_name(active_user_id, assessment_id, "json")

    storage_status = "LOCAL"
    storage_message = "Report exported and ready for local download."

    if save_to_cloud:
        # User requested cloud storage in Azure Blob Storage
        if is_blob_storage_configured():
            upload_ok, upload_msg = upload_report(blob_name, json_bytes, "application/json")
            if upload_ok:
                storage_status = "UPLOADED"
                storage_message = "Report successfully saved to Azure Blob Storage."
            else:
                storage_status = "LOCAL"
                storage_message = f"Cloud upload unavailable ({upload_msg}). Report saved locally."
        else:
            storage_status = "LOCAL"
            storage_message = "Azure Blob Storage is not configured in this environment. Report saved locally."

    # Persist report tracking metadata in database
    try:
        report_id = create_exported_report(
            user_id=active_user_id,
            assessment_id=assessment_id,
            blob_name=blob_name,
            file_type="json",
            file_size=len(json_bytes),
            storage_status=storage_status,
            db_path=db_path
        )
        log_audit_event(
            active_user_id,
            "REPORT_EXPORTED",
            "SUCCESS",
            f"Exported Report #{report_id} for Assessment #{assessment_id} (Storage: {storage_status})",
            db_path=db_path
        )
    except Exception as exc:
        logger.error("Failed to record exported report in database: %s", str(exc))
        return jsonify({"error": "Failed to persist report record in database."}), 500

    return jsonify({
        "success": True,
        "report_id": report_id,
        "assessment_id": assessment_id,
        "blob_name": blob_name,
        "storage_status": storage_status,
        "message": storage_message,
        "download_url": url_for("api_download_report", report_id=report_id),
        "report_data": report_payload
    }), 200


@app.route("/api/reports/<int:report_id>/download", methods=["GET"])
@login_required
def api_download_report(report_id: int):
    """
    Downloads an assessment report file.
    Enforces server-side ownership verification: users can only download their own reports.
    Retrieves from Azure Blob Storage if uploaded; otherwise uses local fallback.
    """
    db_path = get_active_db_path()
    active_user_id = session["user_id"]

    report_record = get_exported_report_by_id(report_id, db_path=db_path)
    if not report_record:
        return jsonify({"error": f"Report #{report_id} not found."}), 404

    # Ownership check: standard users cannot download another's report
    if report_record["user_id"] != active_user_id and session.get("role") != "admin":
        log_audit_event(
            active_user_id,
            "UNAUTHORIZED_REPORT_DOWNLOAD",
            "FORBIDDEN",
            f"User attempted unauthorized download of Report #{report_id} (Owned by User #{report_record['user_id']})",
            db_path=db_path
        )
        return jsonify({"error": "Access denied: You do not own this report."}), 403

    data_bytes = None
    blob_name = report_record["blob_name"]

    # 1. Try retrieving from Azure Blob Storage if status is UPLOADED
    if report_record["storage_status"] == "UPLOADED":
        downloaded, msg = download_report(blob_name)
        if downloaded:
            data_bytes = downloaded
        else:
            logger.warning("Blob retrieval failed for Report #%d ('%s'): %s. Using local regeneration fallback.",
                           report_id, blob_name, msg)

    # 2. Local fallback if not uploaded or cloud retrieval was unavailable
    if data_bytes is None:
        assessment = get_assessment_for_export(report_record["assessment_id"], user_id=None, db_path=db_path)
        if not assessment:
            return jsonify({"error": "Associated assessment record is no longer available."}), 404

        fallback_payload = {
            "report_metadata": {
                "platform": "TRUSTMESH AI-Powered Personal Digital Trust Platform",
                "report_version": "1.0.0",
                "generated_at_utc": datetime.now(timezone.utc).isoformat(),
                "exported_by_user": session.get("display_name", "User"),
                "content_fingerprint_sha256": assessment["content_fingerprint"],
                "source": "Local Database Fallback"
            },
            "assessment_details": {
                "assessment_id": assessment["assessment_id"],
                "incident_id": assessment["incident_id"],
                "incident_type": assessment["content_type"],
                "created_at_utc": str(assessment["assessment_time"]),
                "risk_score": assessment["risk_score"],
                "risk_level": assessment["risk_level"],
                "engine_version": assessment["engine_version"],
            },
            "detected_risk_signals": assessment.get("signals", []),
            "actionable_guidance": {
                "recommendation": assessment["recommendation"],
                "disclaimer": "This preliminary rule-based assessment cannot guarantee that content is safe or fraudulent."
            }
        }
        data_bytes = json.dumps(fallback_payload, indent=2).encode("utf-8")

    filename = f"trustmesh_report_{report_record['assessment_id']}.json"
    return send_file(
        io.BytesIO(data_bytes),
        mimetype="application/json",
        as_attachment=True,
        download_name=filename
    )


@app.route("/api/reports", methods=["GET"])
@login_required
def api_list_user_reports():
    """Returns the list of exported reports owned by the authenticated user."""
    try:
        db_path = get_active_db_path()
        reports = get_exported_reports_by_user(session["user_id"], limit=20, db_path=db_path)
        return jsonify({"reports": reports}), 200
    except Exception as exc:
        logger.error("Failed to query user reports: %s", str(exc))
        return jsonify({"error": "Unable to retrieve exported reports."}), 500


@app.route("/api/storage/status", methods=["GET"])
def api_storage_status():
    """Returns live Azure Blob Storage connectivity and container status."""
    return jsonify({"storage": check_blob_storage_health()}), 200


# ---------------------------------------------------------------------------
# Database Automatic Initialization & Migration on Start
# ---------------------------------------------------------------------------
def setup_database_if_needed():
    """Ensures database is initialized and migrated on server startup."""
    mode = get_database_mode()
    if mode == "sqlite":
        db_path = get_active_db_path()
        if not os.path.exists(db_path):
            logger.info("Database file not found at %s. Initializing from schema.sql...", db_path)
            init_db(db_path=db_path)
            try:
                if not get_user_by_email("admin@trustmesh.test", db_path=db_path):
                    create_user(
                        display_name="System Administrator",
                        email="admin@trustmesh.test",
                        password_hash=generate_password_hash("Password123!"),
                        role_id=2,
                        account_status="ACTIVE",
                        db_path=db_path
                    )
                    logger.info("Auto-seeded default administrator account: admin@trustmesh.test")
            except Exception as seed_err:
                logger.warning("Could not auto-seed admin account: %s", str(seed_err))
        else:
            # Run safe migration check on existing database
            from database import migrate_db
            migrate_db(db_path=db_path)
    else:
        logger.info("Server started in Azure SQL Cloud Mode (DATABASE_MODE=%s). Skipping local SQLite migration.", mode)


setup_database_if_needed()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug_mode = app.config.get("DEBUG", False)
    app.run(host="0.0.0.0", port=port, debug=debug_mode)
