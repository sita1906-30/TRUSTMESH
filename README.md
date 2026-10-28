# TRUSTMESH — AI-Powered Personal Digital Trust & Scam Intelligence Platform

**Phase 3: Secure Authentication, Role-Based Access Control (RBAC) & Application Security**

---

## 1. Project Overview

* **Project Name:** TRUSTMESH
* **Full Title:** AI-Powered Personal Digital Trust & Scam Intelligence Platform
* **Academic Level:** 2nd Year B.Tech Computer Science and Engineering (AI/ML)
* **Academic Phase:** Phase 3 (Authentication, RBAC, Session Management & Application Hardening)
* **Target Environment:** Local Development on Windows (Prepared for future Azure Cloud Migration)

### Problem Statement
Digital communications increasingly expose individuals to phishing campaigns, urgency-driven financial extortion, credential harvesting scams, and deceptive links. Everyday users lack the technical background to parse suspicious headers, analyze obfuscated IP domains, or identify deceptive social engineering triggers.

**TRUSTMESH** functions as an explainable, privacy-preserving personal digital trust layer. It evaluates suspicious text messages and URLs, flags identifiable risk indicators, calculates a preliminary heuristic risk score (0–100), isolates personal scan histories through secure authentication and Role-Based Access Control (RBAC), protects state-changing browser actions with CSRF tokens, logs security audit events, and presents actionable guidance to safeguard everyday users.

> **Academic & Legal Disclaimer:** TRUSTMESH provides a preliminary rule-based heuristic assessment and indicator breakdown. It does **not** guarantee whether any message or URL is completely safe or fraudulent. It is an educational assistive tool designed to promote digital hygiene and threat awareness.

---

## 2. Phase 3 Architecture & Security Enhancements

Building upon the Phase 1 heuristic engine and Phase 2 relational database, Phase 3 implements an enterprise-grade local application security model:

1. **User Registration & Validation:** Server-side input sanitization, RFC 5322 email regex verification, field length bounds, and duplicate email prevention.
2. **Cryptographic Password Hashing:** Powered by Werkzeug's modern password hashing utility (salting and key-derivation via Scrypt/PBKDF2). Plaintext passwords are never stored or logged.
3. **Session Management & Hardening:** Server-managed Flask sessions configured with `HttpOnly`, `SameSite=Lax`, lifetime expiration, and conditional `Secure` cookie flags.
4. **Role-Based Access Control (RBAC):** Distinct `user` and `admin` roles enforced entirely on the backend via reusable `@login_required` and `@role_required("admin")` Python decorators.
5. **User-Scoped Incident Privacy:** Authenticated users only see their own incident history and metrics. Anonymous guest scans are supported but isolated from user accounts.
6. **Administrative Console:** Protected admin dashboard displaying platform-wide analytics, user account directory, and real-time security audit trails.
7. **Cross-Site Request Forgery (CSRF) Protection:** Seamless integration of `Flask-WTF` (`CSRFProtect`) guarding HTML forms and AJAX/fetch JSON requests via `X-CSRFToken`.
8. **Comprehensive HTTP Security Headers:** Enforces `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, `Referrer-Policy: strict-origin-when-cross-origin`, and strict `Content-Security-Policy`.
9. **Security Audit Logging:** Persistent recording of authentication successes, failed logins, logouts, registrations, and authorization violations in the SQLite `AUDIT_LOGS` table.
10. **Idempotent Database Migration:** Non-destructive migration utility (`migrate_db()`) that safely extends existing Phase 2 SQLite databases without data loss.

---

## 3. Technology Stack

Phase 3 is built entirely with free, open-source, and locally runnable technologies:

| Layer | Technology | Purpose & Architectural Decision |
| :--- | :--- | :--- |
| **Backend Framework** | Python 3.12+ / Flask 3.1+ | Lightweight WSGI microframework offering complete control over middleware and routing. |
| **Password Security** | Werkzeug (`generate_password_hash`, `check_password_hash`) | Industry-standard password salting and hashing using Scrypt / PBKDF2 HMAC-SHA256. |
| **CSRF Defense** | Flask-WTF 1.2+ (`CSRFProtect`) | Synchronizer token pattern protecting forms and asynchronous JSON POST requests. |
| **Database** | SQLite 3 (Normalized 3NF) | Serverless, zero-configuration ACID relational storage stored locally in `instance/trustmesh.db`. |
| **Frontend UI** | Semantic HTML5 & Vanilla CSS3 | Modern dark navy (`#070b14`) & mint-green (`#00f090`) cybersecurity operations dashboard. |
| **Client Logic** | Vanilla JavaScript (ES6) | Asynchronous `fetch()` API with CSRF token header injection and safe DOM updates via `textContent`. |
| **Automated Testing** | Python `unittest` | 51 automated test cases verifying engine heuristics, SQL integrity, authentication, and RBAC. |

---

## 4. Route Authorization Table

Every route in TRUSTMESH is classified and enforced strictly on the server:

| Method | Endpoint | Access Level | Description & Protection Mechanism |
| :--- | :--- | :--- | :--- |
| `GET` | `/` | **Public** | Landing page & heuristic scanner interface. |
| `GET` | `/register` | **Public** | User registration form (redirects to dashboard if already authenticated). |
| `POST` | `/register` | **Public** | Creates user account with hashed password and CSRF token verification. |
| `GET` | `/login` | **Public** | Login interface (redirects to dashboard if already authenticated). |
| `POST` | `/login` | **Public** | Authenticates credentials, establishes session, logs audit event. |
| `POST` | `/logout` | **Authenticated** | Clears session cookie, invalidates auth state, redirects to `/`. |
| `GET` | `/dashboard` | **Authenticated (`user` / `admin`)** | Personal user dashboard with isolated history and scan telemetry. |
| `POST` | `/analyze` | **Public / Authenticated** | Analyzes content; tags incident with authenticated `user_id` if logged in. |
| `GET` | `/api/history` | **Authenticated (`user` / `admin`)** | Returns private incident history for the current session's `user_id` (401 if unauthenticated). |
| `GET` | `/api/analytics` | **Public / Authenticated** | Returns user-scoped scan analytics if authenticated; platform totals if guest. |
| `GET` | `/admin` | **Admin Only (`admin`)** | Admin management console (returns 403 Forbidden for standard users). |
| `GET` | `/api/admin/users` | **Admin Only (`admin`)** | JSON user directory (omits password hashes and credentials). |
| `GET` | `/api/admin/audit-logs`| **Admin Only (`admin`)** | JSON system security event stream. |
| `GET` | `/health` | **Public** | Minimal service and database connectivity check. |

---

## 5. Security Architecture Deep Dive

### A. Password Hashing (Werkzeug)
Passwords are **never** stored in plaintext. When a user registers:
1. The plaintext password and confirmation are checked for length (8–128 characters) and exact match.
2. `generate_password_hash(password, method='scrypt')` generates a cryptographically secure random salt and runs an iterative key-derivation function.
3. The stored string looks like `scrypt:32768:8:1$salt$hash`. Even if the SQLite file were compromised, the attacker cannot reverse the hash back into the user's password.
4. During authentication, `check_password_hash(stored_hash, candidate_password)` securely compares the hashes in constant time to prevent timing attacks.

### B. Session Management
Flask uses cryptographically signed client-side cookies for session storage:
* **`SECRET_KEY`:** Loaded securely from environment variables (`.env`). If not provided during development, a stable local fallback is used to prevent session invalidation on restart.
* **`SESSION_COOKIE_HTTPONLY = True`:** Prevents client-side JavaScript from accessing `document.cookie`, mitigating credential theft via Cross-Site Scripting (XSS).
* **`SESSION_COOKIE_SAMESITE = 'Lax'`:** Ensures cookies are not sent on cross-site subrequests (such as malicious image loads), protecting against Cross-Site Request Forgery.
* **`SESSION_COOKIE_SECURE = False (Dev) / True (Prod)`:** Kept `False` for localhost HTTP development to ensure local sessions function properly; switched to `True` over HTTPS in production.
* **Minimal Session Footprint:** Only non-sensitive identity markers (`user_id`, `email`, `display_name`, `role`) are stored in the session. Passwords and hashes are never placed in the session.

### C. Role-Based Access Control (RBAC)
TRUSTMESH defines two roles in the `ROLES` database table:
* `user` (Role ID 1): Can scan messages, view their own private history, and view their own personal analytics.
* `admin` (Role ID 2): Can access `/admin`, inspect the user accounts directory, and view security audit logs.

Authorization is enforced on the server using custom Python decorators:
```python
@role_required("admin")
def admin_dashboard():
    # Enforced strictly on backend: checks session["role"] == "admin"
```
Client-side tampering (such as altering hidden inputs, query parameters, or localStorage) cannot elevate privileges because all role lookups occur from trusted server-side session state.

### D. Cross-Site Request Forgery (CSRF) Protection
* **HTML Forms:** Rendered with hidden CSRF tokens:
  ```html
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  ```
* **JavaScript Fetch Requests:** The frontend reads `<meta name="csrf-token" content="...">` and includes it in the `X-CSRFToken` HTTP header on all `POST` requests.
* **Server Verification:** `Flask-WTF` validates the token against the user's session before passing control to route handlers. Missing or invalid tokens are immediately rejected with HTTP 400.

### E. Security Headers
Injected automatically into every HTTP response via `@app.after_request`:
* `X-Content-Type-Options: nosniff` — Prevents browsers from MIME-sniffing response content types.
* `X-Frame-Options: SAMEORIGIN` — Mitigates clickjacking attacks by forbidding external iframe embedding.
* `Referrer-Policy: strict-origin-when-cross-origin` — Protects user privacy when navigating external links.
* `Content-Security-Policy` — Restricts script execution, style sources, fonts, and forbids framing.

### F. Audit Logging
Every significant security event is recorded in the `AUDIT_LOGS` table:
* `REGISTER_SUCCESS` — Account created with email.
* `LOGIN_SUCCESS` — Successful user authentication.
* `LOGIN_FAILED` — Failed login attempt (generic, without password logging).
* `LOGOUT` — User ended their authenticated session.
* `ACCESS_DENIED` — Unauthorized access attempt to administrative endpoints.

---

## 6. Project Structure

```
TRUST MESH/
│
├── app.py                  # Flask web backend, RBAC decorators, CSRF & security headers
├── database.py             # SQLite connection pooling, schema migration, & auth queries
├── schema.sql              # Normalized 3NF SQL DDL schema, view, indexes, & triggers
├── create_admin.py         # Administrative provisioning CLI utility
├── test_phase3.py          # Phase 3 Security verification test suite (29 tests)
├── test_phase2.py          # Phase 2 Database & engine test suite (14 tests)
├── test_engine.py          # Phase 1 Heuristic engine test suite (8 tests)
├── requirements.txt        # Python dependencies (Flask, Flask-WTF)
├── .env.example            # Environment variable configuration template
├── README.md               # Complete documentation & college viva defense guide
├── .gitignore              # Excludes virtualenv, SQLite DB, cache, and .env
│
├── instance/
│   └── trustmesh.db        # Local SQLite database (auto-migrated)
│
├── templates/
│   ├── index.html          # Main application & heuristic scanner interface
│   ├── login.html          # Authentication login page
│   ├── register.html       # User account registration page
│   ├── dashboard.html      # Personal telemetry & private history dashboard
│   ├── admin.html          # Administrative console & security audit log viewer
│   └── error.html          # Standardized security error display (400, 403, 404, 500)
│
└── static/
    ├── style.css           # Responsive dark navy & mint-green design system
    └── script.js           # Vanilla JavaScript async controller & CSRF handling
```

---

## 7. Setup & Execution Guide (Windows)

### Prerequisites
* Windows 10 or 11
* Python 3.10+ installed and added to `PATH`
* Git (optional)

### Step 1: Open Terminal in Project Directory
Open **PowerShell** or **Command Prompt** and navigate to the project directory:
```powershell
cd "c:\Users\simran\OneDrive\Desktop\TRUST MESH"
```

### Step 2: Activate the Virtual Environment
```powershell
# In PowerShell:
.\.venv\Scripts\Activate.ps1

# Or in Command Prompt (cmd.exe):
.\.venv\Scripts\activate.bat
```

### Step 3: Install Dependencies
```powershell
pip install -r requirements.txt
```

### Step 4: Configure Environment Variables
Copy the example environment file:
```powershell
# PowerShell:
cp .env.example .env

# Or Command Prompt:
copy .env.example .env
```
*(Optional)* Generate your own cryptographic secret key:
```powershell
python -c "import secrets; print(secrets.token_hex(32))"
```
Paste this token as `SECRET_KEY=...` in your `.env` file.

### Step 5: Provision an Administrator Account
Run the one-time admin provisioning CLI utility:
```powershell
python create_admin.py admin@trustmesh.local "System Administrator" "AdminPass123!Secure"
```

### Step 6: Run the Flask Web Application
```powershell
python app.py
```
Open your web browser and navigate to:
**`http://127.0.0.1:5000`**

---

## 8. Automated Testing Guide

Run the comprehensive test suites verifying all 51 automated security and functional scenarios:

### Run the Phase 3 Security Suite (29 Tests)
```powershell
python test_phase3.py
```
*Tests registration validation, password hashing, generic login responses, session clearing, RBAC access denial, parameter tampering protection, CSRF token validation, privacy guarantees, SQL injection resistance, audit log hygiene, and security headers.*

### Run All Platform Test Suites (51 Tests Total)
```powershell
python -m unittest test_engine.py test_phase2.py test_phase3.py
```

---

## 9. College Viva Defense & Technical Interview Preparation

Here are simple, professional answers to common questions asked during university viva examinations:

### Q1: What is the difference between Authentication and Authorization?
* **Authentication ("Who are you?"):** The process of verifying an entity's claimed identity using credentials such as an email and a password hash. In TRUSTMESH, this occurs via `/login`.
* **Authorization ("What are you allowed to do?"):** The process of verifying whether an authenticated user has the necessary permissions to access a specific resource. In TRUSTMESH, this is enforced by `@role_required("admin")`.

### Q2: What is the difference between Hashing and Encryption?
* **Hashing is a one-way mathematical function:** Given an input, it produces a fixed-length digest that cannot be decrypted back into the original text. It is used for passwords (via Scrypt/PBKDF2) so even developers cannot view user passwords.
* **Encryption is a two-way process:** Plaintext is converted to ciphertext using a secret key and can be decrypted back into plaintext with the corresponding key.

### Q3: What is Role-Based Access Control (RBAC)?
* RBAC is an authorization mechanism where permissions are assigned to specific roles (e.g., `user` and `admin`) rather than directly to individual users. Users are assigned roles, and access to application endpoints is restricted based on those roles.

### Q4: What is Cross-Site Request Forgery (CSRF) and how does TRUSTMESH prevent it?
* **CSRF:** An attack where a malicious website tricks a victim's browser into executing an unwanted action on a web application where the victim is currently authenticated.
* **Defense:** TRUSTMESH uses `Flask-WTF` to implement the **Synchronizer Token Pattern**. Every state-changing form and fetch request requires a unique, unpredictable secret token tied to the user's session. Since external malicious sites cannot read this token (due to the Same-Origin Policy), forged requests are rejected with HTTP 400.

### Q5: What is Cross-Site Scripting (XSS) and how is it mitigated here?
* **XSS:** An attack where malicious JavaScript is injected into a web page viewed by other users.
* **Defense:** TRUSTMESH uses safe DOM manipulation (`element.textContent = ...` instead of `innerHTML`) when rendering dynamic text, escapes all Jinja2 templates, and enforces a strict `Content-Security-Policy` restricting script sources.

### Q6: How is SQL Injection prevented?
* By strictly using **parameterized queries** (`cursor.execute("SELECT ... WHERE email = ?", (email,))`). User input is treated strictly as literal data, never as executable SQL code.

### Q7: Why do session cookies require `HttpOnly` and `SameSite` flags?
* `HttpOnly` blocks JavaScript from accessing the session cookie via `document.cookie`, protecting session tokens from being stolen during an XSS attack.
* `SameSite=Lax` stops the browser from sending the session cookie with cross-site requests, providing an additional layer of CSRF protection.

### Q8: Why must authorization be enforced on the backend rather than the frontend?
* Frontend code (HTML, CSS, JavaScript) runs on the client device and can be modified or bypassed using browser Developer Tools, Postman, or `curl`. The backend server is the only trusted boundary and must independently verify identity and permissions on every request.

---

## 10. Known Limitations & Future Roadmap

* **In-Memory Rate Limiting:** Local development does not currently integrate a persistent Redis rate limiter for login brute-force mitigation.
* **Single-Node SQLite:** SQLite is ideal for local solo development and viva demonstrations. When scaling to multi-instance cloud deployments (such as Azure App Service), the database will migrate to **Azure SQL** and **Azure Key Vault** for centralized secret rotation.
* **Heuristic Engine:** Current risk scoring uses rule-based heuristic pattern matching rather than a trained deep-learning classifier. In Phase 4, a fine-tuned lightweight NLP model will complement the rule engine.
