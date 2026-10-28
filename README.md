# TRUSTMESH — AI-Powered Personal Digital Trust & Scam Intelligence Platform

**Phase 2: Improved Trust Analysis Engine + Relational SQL Database Integration**

---

## 1. Project Overview

**Project Name:** TRUSTMESH  
**Full Title:** AI-Powered Personal Digital Trust & Scam Intelligence Platform  
**Developer:** Student, 2nd Year B.Tech Computer Science and Engineering (AI/ML)  
**Academic Phase:** Phase 2 (Local Relational Database Integration & Threat Analytics)  
**Target Environment:** Local Development (Prepared for future Azure Cloud Migration)

### Problem Statement
Digital communication has made it increasingly challenging for individuals to distinguish authentic interactions from fraudulent attempts, phishing campaigns, deceptive payment solicitations, sensitive credential harvesting, and malicious URLs.

**TRUSTMESH** functions as an accessible, explainable personal digital trust layer. It evaluates suspicious text messages and URLs, flags identifiable risk indicators, calculates a preliminary heuristic risk score (0–100), logs safe telemetry to a normalized local database, and presents actionable guidance to safeguard everyday users.

> **Important Academic & Legal Disclaimer:** TRUSTMESH provides a preliminary rule-based assessment and indicator breakdown. It does **not** guarantee whether any message or URL is completely safe or fraudulent.

---

## 2. Phase 2 Features & Enhancements

Building upon the Phase 1 web interface and rule engine, Phase 2 implements a robust persistence and telemetry layer:

1. **Normalized Relational SQLite Database:** Designed strictly to Third Normal Form (3NF) with 7 interconnected tables.
2. **Automatic Database Lifecycle:** Self-initializing SQLite database stored in `instance/trustmesh.db` with zero manual configuration required.
3. **Atomic Transactional Writes:** Saves each incident, risk assessment, and detected signals in a single atomic database transaction (`conn.commit()` / `conn.rollback()`).
4. **Interactive Digital Trust History Dashboard:** Displays recent incident evaluations with score pills, content classifications, and signal counts without exposing raw user text.
5. **Real-Time Platform Analytics Bar:** Real-time database aggregations (`COUNT`, `AVG`, `GROUP BY`) displaying total analyses, risk distributions, average score, and top detected warning indicators.
6. **Detailed Signal Breakdown Inspection:** HTML5 dialog modal to safely inspect the specific warning signals and points awarded for any historical scan.
7. **Database Triggers & Reporting Views:** Includes a dedicated SQLite audit trigger (`trg_audit_assessment_insert`) and a reporting view (`v_incident_summary`).
8. **Privacy-Preserving Telemetry:** Raw submitted messages and URLs are **never** persisted to disk, database, or logs. Cryptographic SHA-256 fingerprinting is used for correlation.

---

## 3. Technology Stack

Phase 2 remains 100% free and open-source, utilizing standard library modules and lightweight dependencies:

| Component | Technology | Rationale |
| :--- | :--- | :--- |
| **Backend Framework** | Python 3.12+ / Flask 3.1+ | Lightweight, understandable WSGI microframework. |
| **Database Engine** | SQLite 3 (via built-in `sqlite3`) | Zero-configuration, serverless, self-contained relational database. |
| **Database Design** | Third Normal Form (3NF) SQL | Eliminates data redundancy and prepares schema for Azure SQL migration. |
| **Frontend UI** | Semantic HTML5 | Accessible, structured markup with native `<dialog>` modals. |
| **Styling** | Vanilla CSS3 | Dark navy (`#070b14`) & mint-green (`#00f090`) cybersecurity enterprise aesthetic. |
| **Client Scripting** | Vanilla JavaScript (ES6) | Native `fetch()` async API, safe DOM rendering via `textContent` (Zero XSS). |
| **Automated Testing** | Python `unittest` | Comprehensive unit and integration test suite with temporary test databases. |

---

## 4. Project Folder Structure

```
TRUSTMESH/
│
├── app.py                  # Flask web backend, API endpoints, & detection engine
├── database.py             # SQLite connection pooling, transactions, & analytical queries
├── schema.sql              # Normalized 3NF DDL schema, view, indexes, trigger, & seed data
├── test_phase2.py          # Phase 2 automated test suite (14 comprehensive test cases)
├── test_engine.py          # Phase 1 verification test suite (8 test cases)
├── requirements.txt        # Minimal Python dependencies (Flask)
├── README.md               # Complete architecture, viva defense, & user manual
├── .gitignore              # Excludes virtual environments, database files, & cache
│
├── instance/
│   └── trustmesh.db        # Automatically initialized SQLite development database
│
├── templates/
│   └── index.html          # Frontend single-page application with history dashboard & modal
│
└── static/
    ├── style.css           # Vanilla CSS stylesheet (responsive cards, tables, & modals)
    └── script.js           # Client controller for fetch API, DOM rendering, & polling
```

---

## 5. Relational Database Design & Third Normal Form (3NF)

The database schema comprises **7 related tables** designed to adhere to Third Normal Form (3NF):

```
 ┌───────────────┐          ┌───────────────┐
 │     USERS     │◄──┐      │     ROLES     │
 └───────┬───────┘   │      └───────────────┘
         │ 1:N       │
         ▼           │
 ┌───────────────┐   │ 1:N
 │   INCIDENTS   │   │ (audit)
 └───────┬───────┘   │
         │ 1:1       │
         ▼           │
 ┌───────────────────────┐  │      ┌───────────────┐
 │    RISK_ASSESSMENTS   ├──┴─────►│  AUDIT_LOGS   │
 └───────────┬───────────┘         └───────────────┘
             │ 1:N
             ▼
 ┌───────────────────────┐
 │  ASSESSMENT_SIGNALS   │ (Junction / Bridge Table)
 └───────────┬───────────┘
             │ N:1
             ▼
 ┌───────────────────────┐
 │     RISK_SIGNALS      │ (Signals Catalog)
 └───────────────────────┘
```

### Table Definitions

| Table Name | Primary Key | Foreign Keys | Functional Purpose |
| :--- | :--- | :--- | :--- |
| **`USERS`** | `user_id` | *None* | Represents application users or anonymous development sessions. |
| **`ROLES`** | `role_id` | *None* | Stores role reference values (`user`, `admin`) for future authorization. |
| **`INCIDENTS`** | `incident_id` | `user_id` &rarr; `USERS` | Logs an interaction event, content type, SHA-256 fingerprint, and status. |
| **`RISK_ASSESSMENTS`** | `assessment_id` | `incident_id` &rarr; `INCIDENTS` | Stores the evaluated risk score (0–100), risk level, and recommendation. |
| **`RISK_SIGNALS`** | `signal_id` | *None* | Normalized catalog of all detectable warning indicators and categories. |
| **`ASSESSMENT_SIGNALS`**| `(assessment_id, signal_id)` | `assessment_id` &rarr; `RISK_ASSESSMENTS`<br>`signal_id` &rarr; `RISK_SIGNALS` | Resolves the Many-to-Many relationship between assessments and warning signals. |
| **`AUDIT_LOGS`** | `audit_id` | `user_id` &rarr; `USERS` | Records non-sensitive security events triggered automatically by the database. |

---

### Academic Explanation of 3NF Normalization (For College Viva)

Examiners frequently ask students to defend database normalization. Here is the formal explanation:

1. **What each table represents:** Each table has a single, well-defined entity or relationship. `USERS` models actor identity; `INCIDENTS` captures submission metadata; `RISK_ASSESSMENTS` isolates evaluation results; `RISK_SIGNALS` serves as a master catalog; and `ASSESSMENT_SIGNALS` represents the link between them.
2. **Why Users and Incidents are separate:** Separating users from incidents respects First and Second Normal Forms. A user can submit multiple interactions over time (1:N relationship). Combining user profiles and incidents into a single table would cause repeated user details on every submission, creating update and deletion anomalies.
3. **Why Risk Assessments are separate from Incidents:** An incident represents the *intake event* (timestamp, content classification, processing status), whereas an assessment represents the *analytical outcome* (score, level, engine version, recommendation). Separating them decouples event intake from evaluation, enabling future features such as re-evaluating an incident with a newer engine version without altering intake history.
4. **Why Warning Indicators use a separate catalog (`RISK_SIGNALS`):** Storing signal names, categories, and descriptions directly inside assessment rows would cause massive text duplication across thousands of records. Normalizing them into a master catalog table (`RISK_SIGNALS`) means each signal is defined exactly once.
5. **Why `ASSESSMENT_SIGNALS` resolves the Many-to-Many (M:N) relationship:** A single risk assessment can trigger multiple warning signals (e.g. Urgency AND Insecure HTTP). Conversely, a single warning signal (e.g. Urgency) can be detected across many different assessments. Relational databases cannot directly store arrays or multi-valued lists in columns without violating 1NF. `ASSESSMENT_SIGNALS` acts as an associative junction table with composite primary key `(assessment_id, signal_id)`.
6. **How the design avoids unnecessary duplication (3NF achieved):** Every non-key attribute is non-transitively dependent exclusively on the primary key (*"The key, the whole key, and nothing but the key, so help me Codd"*). If a signal's descriptive text changes, it is updated in one place in `RISK_SIGNALS` without modifying millions of historical records.

---

## 6. SQL Operations Implemented & Demonstrated

### A. INSERT (Parameterized Transaction)
In [`database.py`](file:///c:/Users/simran/OneDrive/Desktop/TRUST%20MESH/database.py#L90-L158), incidents, assessments, and signals are inserted using strictly parameterized `?` placeholders:
```sql
INSERT INTO INCIDENTS (user_id, content_type, content_fingerprint, processing_status)
VALUES (?, ?, ?, 'COMPLETED');
```

### B. JOIN (Multi-Table Relational Queries)
To display an incident's detected signals in the inspection modal, a relational join connects `ASSESSMENT_SIGNALS` to `RISK_SIGNALS`:
```sql
SELECT 
    rs.signal_name,
    rs.category,
    rs.description,
    asig.points_awarded
FROM ASSESSMENT_SIGNALS asig
JOIN RISK_SIGNALS rs ON asig.signal_id = rs.signal_id
WHERE asig.assessment_id = ?
ORDER BY asig.points_awarded DESC;
```

### C. SQL VIEW (`v_incident_summary`)
Created in [`schema.sql`](file:///c:/Users/simran/OneDrive/Desktop/TRUST%20MESH/schema.sql#L91-L108) to provide a standardized, safe summary of incidents without exposing raw content:
```sql
CREATE VIEW IF NOT EXISTS v_incident_summary AS
SELECT 
    i.incident_id,
    i.user_id,
    i.content_type,
    i.created_at AS incident_time,
    ra.assessment_id,
    ra.risk_score,
    ra.risk_level,
    ra.engine_version,
    ra.recommendation,
    COUNT(asig.signal_id) AS signal_count
FROM INCIDENTS i
JOIN RISK_ASSESSMENTS ra ON i.incident_id = ra.incident_id
LEFT JOIN ASSESSMENT_SIGNALS asig ON ra.assessment_id = asig.assessment_id
GROUP BY i.incident_id, ra.assessment_id;
```

### D. AGGREGATIONS (`COUNT`, `AVG`, `GROUP BY`)
Used in [`database.py:get_analytics()`](file:///c:/Users/simran/OneDrive/Desktop/TRUST%20MESH/database.py#L225-L290) to compute platform metrics:
```sql
-- Frequency of warning indicators across all scans
SELECT 
    rs.signal_name,
    rs.category,
    COUNT(asig.assessment_id) AS frequency
FROM RISK_SIGNALS rs
JOIN ASSESSMENT_SIGNALS asig ON rs.signal_id = asig.signal_id
GROUP BY rs.signal_id
ORDER BY frequency DESC
LIMIT 5;

-- Average risk score
SELECT COALESCE(ROUND(AVG(risk_score), 1), 0.0) AS avg_score FROM RISK_ASSESSMENTS;
```

### E. INDEXES
Created to optimize sorting and foreign key lookups:
```sql
CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON INCIDENTS(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_risk_assessments_level ON RISK_ASSESSMENTS(risk_level);
CREATE INDEX IF NOT EXISTS idx_risk_assessments_score ON RISK_ASSESSMENTS(risk_score);
CREATE INDEX IF NOT EXISTS idx_assessment_signals_signal_id ON ASSESSMENT_SIGNALS(signal_id);
```

### F. SQLite TRIGGER (Automated Audit Trail)
Created in [`schema.sql`](file:///c:/Users/simran/OneDrive/Desktop/TRUST%20MESH/schema.sql#L120-L135). Whenever a new assessment record is inserted into `RISK_ASSESSMENTS`, the database engine automatically writes an entry into `AUDIT_LOGS`:
```sql
CREATE TRIGGER IF NOT EXISTS trg_audit_assessment_insert
AFTER INSERT ON RISK_ASSESSMENTS
BEGIN
    INSERT INTO AUDIT_LOGS (user_id, event_type, event_status, created_at)
    VALUES (
        (SELECT user_id FROM INCIDENTS WHERE incident_id = NEW.incident_id),
        'ASSESSMENT_CREATED',
        'SUCCESS',
        CURRENT_TIMESTAMP
    );
END;
```

---

## 7. API Endpoint Reference

| Method & Route | Purpose | Request Body | Response Format |
| :--- | :--- | :--- | :--- |
| **`GET /`** | Renders web application with analyzer and history dashboard | None | HTML5 page |
| **`POST /analyze`** | Evaluates message/URL, executes atomic database transaction, and returns analysis result | `{"text": "suspicious string"}` | `{"incident_id": 1, "score": 60, "level": "High risk", "findings": [...], "recommendation": "...", "disclaimer": "...", "urls_found": 0, "engine_version": "2.0.0"}` |
| **`GET /api/history`** | Returns latest 20 safe incident evaluations | None | `{"history": [{"incident_id": 1, "created_at": "...", "content_type": "message", "risk_score": 60, "risk_level": "High risk", "signal_count": 3, "signals": [...], ...}]}` |
| **`GET /api/analytics`** | Returns real-time platform statistics from SQLite | None | `{"analytics": {"total_analyses": 8, "high_risk_count": 2, "suspicious_count": 2, "lower_risk_count": 4, "average_score": 31.3, "top_signals": [...]}}` |
| **`GET /health`** | System & SQLite connectivity health check | None | `{"status": "healthy", "database": "connected", "engine_version": "2.0.0"}` (HTTP 200 / 503) |

---

## 8. Installation & Local Setup

### Prerequisites
- Python 3.10+ installed on your machine.
- PowerShell or Command Prompt in Windows.

### Step 1: Open Terminal in Project Directory
```powershell
cd "c:\Users\simran\OneDrive\Desktop\TRUST MESH"
```

### Step 2: Activate the Virtual Environment
- **Windows PowerShell:**
  ```powershell
  .\.venv\Scripts\Activate.ps1
  ```
  *(If execution is restricted, run: `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process`)*

- **Windows Command Prompt (cmd.exe):**
  ```cmd
  .venv\Scripts\activate.bat
  ```

### Step 3: Install Dependencies (if not already installed)
```powershell
python -m pip install -r requirements.txt
```

### Step 4: Run the Application
```powershell
python app.py
```
*(On first execution, `instance/trustmesh.db` is created and initialized automatically from `schema.sql`)*

### Step 5: Open in Browser
Navigate to:
```
http://127.0.0.1:5000
```

---

## 9. Automated Testing Suites

TRUSTMESH includes two comprehensive automated test suites using Python's built-in `unittest` framework:

### Suite 1: Phase 2 Database & Integration Suite (`test_phase2.py`)
Uses an isolated temporary database to test all 14 Phase 2 requirements:
```powershell
python test_phase2.py
```
**Test Coverage:**
- `Test 1:` Schema initialization & catalog seeding
- `Test 2:` Foreign key enforcement (`PRAGMA foreign_keys = ON`)
- `Test 3:` Valid analysis persistence & automated audit trigger
- `Test 4:` Many-to-Many signal relationships in `ASSESSMENT_SIGNALS`
- `Test 5:` Transaction rollback on constraint violation (zero orphaned records)
- `Test 6:` History chronological descending order
- `Test 7:` Privacy assurance (raw content absent from history)
- `Test 8:` Analytics aggregations (`COUNT`, `AVG`, `GROUP BY`)
- `Test 9:` Empty input rejection (HTTP 400)
- `Test 10:` Length > 5,000 characters rejection (HTTP 400)
- `Test 11:` SQL injection parameterization safety
- `Test 12:` Database failure safe handling (HTTP 500 without stack trace)
- `Test 13:` Phase 1 rule scoring backward compatibility
- `Test 14:` System health endpoint verification

### Suite 2: Phase 1 Detection Engine Verification (`test_engine.py`)
```powershell
python test_engine.py
```

---

## 10. Privacy & Security Architecture

1. **Zero Raw Content Storage:** Submitted messages, emails, SMS texts, and URLs are analyzed strictly in volatile memory. No user text is stored in SQLite tables or written to log files.
2. **Cryptographic Content Fingerprinting:** A one-way SHA-256 hash (`content_fingerprint`) is stored in `INCIDENTS`. This permits duplicate detection and auditing without retaining reversible text. (Documented limitation: short predictable strings could be dictionary-tested, hence it is treated as pseudonymous metadata, not absolute anonymity).
3. **No Automatic Network Requests:** URLs are parsed geometrically and syntactically using `urllib.parse`. The backend **never** makes outbound HTTP connections or visits submitted links.
4. **Strict Parameterization:** Every database operation uses `?` placeholders. User input is never concatenated into SQL strings, completely neutralizing SQL Injection attacks.
5. **Cross-Site Scripting (XSS) Prevention:** Dynamic UI updates in JavaScript strictly employ `textContent` and `document.createElement()`. Untrusted user data is never parsed via `innerHTML` or `eval()`.
6. **Relational Integrity Enforcement:** Every SQLite connection executes `PRAGMA foreign_keys = ON;`, ensuring orphaned records cannot exist.

---

## 11. SQLite vs. Azure SQL Database (Viva Defense Guide)

In your college viva, examiners will ask why SQLite was chosen and how the system will transition to **Azure SQL Database** in Phase 3/4.

| Architectural Dimension | SQLite (Phase 2 Local Development) | Azure SQL Database (Planned Cloud Migration) |
| :--- | :--- | :--- |
| **Deployment Model** | Serverless, single-file database (`instance/trustmesh.db`). Zero network latency for local testing. | Fully managed PaaS cloud database hosted on Microsoft Azure cloud infrastructure. |
| **Concurrency** | Single-writer, multiple-reader via file locking. Ideal for single-developer local projects. | Enterprise multi-threaded concurrency with distributed transactions and connection pooling. |
| **Foreign Keys** | Disabled by default in SQLite; must be explicitly turned on via `PRAGMA foreign_keys = ON;`. | Enforced natively by default at the database engine level. |
| **Stored Procedures** | Not supported in standard SQLite. Emulated via SQLite triggers (`CREATE TRIGGER`). | Supported natively via T-SQL (`CREATE PROCEDURE ... EXEC`). |
| **Data Types** | Dynamic typing / type affinity (`INTEGER`, `TEXT`, `REAL`, `BLOB`). | Strict static typing (`INT`, `NVARCHAR(MAX)`, `DATETIME2`, `DECIMAL`). |
| **Cost** | 100% Free and open-source. Requires no cloud account or credentials. | Cloud subscription model (consumes Azure credits / monthly subscription). |

### Cloud Migration Pathway (How to Explain It):
Because our database logic is completely modularized in [`database.py`](file:///c:/Users/simran/OneDrive/Desktop/TRUST%20MESH/database.py) rather than scattered inside `app.py`, migrating to Azure SQL Database requires:
1. Swapping `sqlite3` for a cloud database connector like `pyodbc` or `azure-identity`.
2. Updating connection strings to point to the Azure SQL Server endpoint (`tcp:trustmesh-server.database.windows.net,1433`).
3. Adapting `schema.sql` syntax from SQLite to T-SQL (converting `INTEGER PRIMARY KEY AUTOINCREMENT` to `INT IDENTITY(1,1) PRIMARY KEY` and converting triggers into T-SQL stored procedures).
4. **The entire Flask application (`app.py`), detection engine, and frontend will continue working without redesign.**

---

## 12. Current Limitations & Planned Future Phases

- **Rule-Based Heuristics (Not Machine Learning Yet):** Phase 2 still relies on deterministic regex patterns and weighted indicators. It is explainable, but cannot yet infer subtle semantic nuances or evasion techniques.
- **Phase 3 (Planned):** Integration of a local Scikit-Learn / TF-IDF or DistilBERT machine learning model to compute semantic fraud probability.
- **Phase 4 (Planned):** User registration, password hashing (`bcrypt`), JWT sessions, and migration to Azure SQL Database.
