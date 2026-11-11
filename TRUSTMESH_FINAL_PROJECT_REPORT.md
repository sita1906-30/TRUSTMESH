# TRUSTMESH: AI-POWERED PERSONAL DIGITAL TRUST & SCAM INTELLIGENCE PLATFORM
## Comprehensive Academic Project Report & Engineering Thesis
**Academic Degree:** Bachelor of Technology (B.Tech) in Computer Science & Engineering  
**Specialization:** Artificial Intelligence & Machine Learning (AI/ML) | **Academic Year:** 2nd Year (Semester IV)  
**Project Track:** Project-Based Learning 3 (PBL-3) / Cybersecurity & Cloud Computing  
**Date of Submission:** November 2026 | **Repository:** `c:\Users\simran\OneDrive\Desktop\TRUST MESH`  
**System Status:** Fully Implemented & Verified (143/143 Automated Unit & Regression Tests Passing)  

---

## TABLE OF CONTENTS
1. **Chapter 1: Abstract**
2. **Chapter 2: Introduction & Cyber Threat Landscape**
3. **Chapter 3: Problem Statement & Motivation**
4. **Chapter 4: Project Objectives (Primary & Secondary)**
5. **Chapter 5: Scope & Boundary Analysis**
6. **Chapter 6: Literature Review & Existing System Study**
7. **Chapter 7: Proposed System & Novel Contributions**
8. **Chapter 8: High-Level System Architecture (4-Tier Model)**
9. **Chapter 9: Software Requirements Specification (IEEE 830 Standard)**
10. **Chapter 10: Hardware & Software Environment Specifications**
11. **Chapter 11: UML Use Case Modeling & Actor Specifications**
12. **Chapter 12: Data Flow Modeling (Level 0 Context & Level 1 Decomposition)**
13. **Chapter 13: Entity-Relationship (ER) Modeling & Relational Normalization (3NF)**
14. **Chapter 14: Database Schema & Complete Data Dictionary**
15. **Chapter 15: REST API Interface & Communication Specifications**
16. **Chapter 16: System Implementation & Core Heuristic Algorithms**
17. **Chapter 17: Software Testing, Verification & Performance Benchmarking**
18. **Chapter 18: Security Analysis & Vulnerability Mitigation (OWASP / CWE)**
19. **Chapter 19: Microsoft Azure Cloud & Power BI Analytics Integration**
20. **Chapter 20: Academic Curriculum Mapping (11 Subjects) & Viva Defense Guide**
21. **Chapter 21: Conclusion, Future Scope & IEEE Bibliography**

---

## CHAPTER 1: ABSTRACT

Digital deception, phishing attacks, credential harvesting campaigns, and urgent social engineering scams represent an escalating global threat to personal cybersecurity. Everyday users often lack the technical acumen required to inspect raw email headers, evaluate deceptive domain encodings (Punycode), or recognize psychological manipulation triggers such as artificial urgency and fee pressure. Furthermore, many commercial threat intelligence platforms operate as opaque black boxes, providing a single risk score without educational explanations, or they compromise user privacy by transmitting and storing sensitive submitted messages in external commercial databases.

This project presents **TRUSTMESH**, an explainable, privacy-preserving, and cloud-ready digital trust layer engineered to protect individuals against cyber scams. Built on a modular 4-tier architecture using Python 3.12, Flask 3.1, and Gunicorn WSGI, TRUSTMESH analyzes arbitrary text messages and URLs using a multi-criteria heuristic scoring engine. The system evaluates 5 textual semantic categories (artificial urgency, advance fee payment pressure, sensitive credential solicitation, suspension threats, and fraudulent prize incentives) combined with a static URL security parser (unencrypted HTTP, numerical IP address hostnames, Punycode `xn--` brand impersonation, and excessive subdomain nesting depth).

To uphold the core tenet of **Privacy by Design (PbD)**, raw submitted messages and URLs are processed strictly in volatile memory and discarded immediately; only cryptographic SHA-256 fingerprints, calculated risk scores (0–100), and cataloged threat signals are recorded in a normalized Third Normal Form (3NF) relational database. TRUSTMESH implements an enterprise-grade local security architecture, including PBKDF2:SHA256 password salting, Role-Based Access Control (RBAC), session fixation defense, Cross-Site Request Forgery (CSRF) tokens, and strict HTTP response security headers (CSP, nosniff, SAMEORIGIN). 

The platform supports **dual-mode database persistence**, allowing instant switching between local SQLite (zero student cost) and Microsoft Azure SQL Database via the `DB_MODE` environment variable. It features decoupled forensic report archiving in Azure Blob Storage with automated local fallback, and an administrative Business Intelligence (BI) pipeline supplying 4 analytical views and a zero-PII anonymized CSV export engine integrated into Microsoft Power BI Desktop. The system has been validated through **143 automated regression test cases passing with 100% success**, demonstrating sub-35 ms analysis latency and Grade-A security compliance.

---

## CHAPTER 2: INTRODUCTION & CYBER THREAT LANDSCAPE

### 2.1 The Evolution of Social Engineering Scams
The rapid digitization of global financial systems, digital identity verification, and mobile communication has dramatically expanded the attack surface for malicious threat actors. Cybercriminals have transitioned from crude, generalized spam emails to highly targeted, psychologically optimized social engineering campaigns delivered via SMS (Smishing), instant messaging platforms (WhatsApp, Telegram), and deceptive landing pages.

Modern scam communications rely on cognitive biases rather than purely technical exploits. By artificially inducing panic (e.g., *"Your bank account will be blocked within 2 hours"*), creating false urgency (e.g., *"Immediate payment required"*), or manufacturing illusory incentives (e.g., *"Congratulations, you have won a cash lottery"*), attackers manipulate victims into bypassing rational skepticism. 

### 2.2 The Technical Literacy Gap
While enterprise organizations deploy Security Information and Event Management (SIEM) systems, Intrusion Detection Systems (IDS), and dedicated Security Operations Centers (SOCs), individual consumers, students, and elderly demographics remain completely unprotected at the personal endpoint level. When confronted with an unverified SMS or suspicious link, non-technical users have neither the knowledge nor the tools to:
1. Deconstruct the URL to detect internationalized domain name (IDN) homograph attacks using Punycode.
2. Differentiate between unencrypted plain HTTP transport and secure HTTPS connections.
3. Identify raw IP addresses masquerading as authentic hostnames.
4. Distinguish between legitimate administrative alerts and coercive social engineering triggers.

### 2.3 The Role of TRUSTMESH
TRUSTMESH addresses this technical disparity by serving as a **personal digital trust layer**. Positioned directly between the user and unverified digital communications, TRUSTMESH acts as an educational, explainable, and secure advisor. Rather than merely labeling content as "spam" or "ham," the platform deconstructs the threat, provides transparent indicator rationale, and presents defensive next steps to foster long-term digital threat hygiene.

---

## CHAPTER 3: PROBLEM STATEMENT & MOTIVATION

### 3.1 Problem Formulation
According to the 2024 Internet Crime Report published by the Federal Bureau of Investigation (FBI) Internet Crime Complaint Center (IC3), phishing, spoofing, and extortion represent the single highest incident category globally, accounting for hundreds of millions of dollars in individual financial losses. In India, the Indian Computer Emergency Response Team (CERT-In) reported a 170% surge in financial social engineering incidents targeting retail banking and digital payment UPI interfaces.

Existing anti-phishing solutions present several fundamental engineering shortcomings:
1. **The Black-Box Dilemma:** Many commercial scanners output a single percentage score or binary flag without providing the linguistic or topological reasons behind the classification. Users learn nothing from the interaction.
2. **The Privacy Paradox:** Many online scanning tools transmit the entirety of the user's submitted message or URL to third-party databases. When users submit messages containing sensitive personal details, OTPs, or private links, these tools violate privacy and data protection mandates (such as the EU GDPR and India's Digital Personal Data Protection Act 2023).
3. **Prohibitive Infrastructure Costs:** Cloud-native enterprise security products require costly subscriptions, multi-cloud SaaS licenses, and complex architectures that cannot be deployed or maintained by students, small teams, or resource-constrained institutions.

### 3.2 Motivation and Vision
The motivation behind TRUSTMESH is to engineer a system that:
* Operates locally with **zero financial cost** while maintaining production cloud readiness.
* Provides **Explainable Artificial Intelligence / Explainable Security (XAI/X-Sec)** so users understand *why* an interaction is dangerous.
* Guarantees absolute **Privacy by Design (PbD)** by never persisting raw user messages in databases.
* Demonstrates the complete integration of **Cybersecurity, Relational DBMS (3NF), Cloud Computing (Microsoft Azure PaaS), and Business Intelligence (Power BI)** in a single cohesive platform.

---

## CHAPTER 4: PROJECT OBJECTIVES

### 4.1 Primary Objectives
1. **Multi-Criteria Threat Detection Engine:** Implement a deterministic, rule-based heuristic analyzer in Python 3.12 capable of detecting 5 distinct linguistic scam patterns and 5 static URL structural anomalies.
2. **Transparent Risk Scoring:** Develop a normalized risk scoring algorithm ($0 \le Score \le 100$) mapped into three clearly defined risk tiers: *Lower detected risk*, *Suspicious*, and *High risk*.
3. **Privacy by Design Persistence:** Architect a relational database schema in SQLite (3NF) that strictly excludes raw message and URL content, persisting only cryptographic SHA-256 fingerprints, timestamps, scores, and categorized signal IDs.
4. **Enterprise-Grade Application Security:** Implement PBKDF2:SHA256 password salting/hashing, Role-Based Access Control (RBAC) separating `user` and `admin` actors, CSRF synchronizer tokens, and HTTP response security headers.

### 4.2 Secondary Objectives
1. **Dual-Mode Database Architecture:** Create an abstraction layer supporting seamless runtime switching between local SQLite (Local Mode) and Microsoft Azure SQL Database (Cloud Mode) using environment configuration (`DB_MODE`).
2. **Hybrid Cloud Report Archiving:** Integrate Microsoft Azure Blob Storage via the official Python SDK for forensic report archival, backed by an automated local filesystem fallback for unconfigured environments.
3. **Zero-PII Analytics Data Pipeline:** Construct an administrative analytics data pipeline backed by 4 SQL database views and a sanitized CSV export engine for executive dashboard modeling in Microsoft Power BI Desktop.
4. **Cloud Deployment Readiness:** Package the Flask application for production deployment on Microsoft Azure App Service (Linux) using the Gunicorn WSGI container runtime, dynamic port binding, and Oryx build automation.
5. **Quality Assurance & Audit:** Validate system integrity using automated unit, integration, and security regression test suites achieving 100% pass rates.

---

## CHAPTER 5: SCOPE & BOUNDARY ANALYSIS

### 5.1 In-Scope Capabilities
* **Textual Threat Analysis:** Evaluation of plain-text messages up to 5,000 characters for urgency triggers, upfront payment demands, cryptocurrency/gift card extortion, account suspension threats, and fake prize notifications.
* **URL Static Analysis:** Parsing of URLs without active network crawling (to prevent triggering malware or beaconing to attackers), identifying unencrypted HTTP, numerical IP hostnames, Punycode spoofing, and excessive subdomains.
* **User Management & Authentication:** Multi-user registration, secure login/logout, session management, and self-service incident history isolation.
* **Administrative Governance:** System administrator console, real-time security audit log stream, registered user directory, and platform KPI monitoring.
* **Export & Archival:** Export of forensic assessment reports in structured JSON format with dual-mode storage (Azure Blob / Local).
* **Analytics Integration:** Anonymized CSV export and documented DAX measures for Power BI Desktop.

### 5.2 Out-of-Scope & Academic Boundaries
* **Definitive Guarantee of Safety:** TRUSTMESH provides a *preliminary heuristic assessment*. In accordance with academic cybersecurity principles, no rule-based engine can guarantee that an unflagged message is 100% benign (Zero-Day threat limitation).
* **Active Web Crawling:** The system intentionally refrains from sending live HTTP GET requests to target URLs to avoid malicious payload downloads, drive-by browser compromise, or victim IP exposure.
* **Automated Account Lockout:** Failed logins are logged to `AUDIT_LOGS`, but automated IP blocking or multi-factor authentication (MFA/2FA) is deferred to future work.
* **Paid Cloud Resources:** In compliance with the student zero-cost policy, active connections to live Azure cloud services requiring billable resources are mocked or designated as local fallbacks.

---

## CHAPTER 6: LITERATURE REVIEW & EXISTING SYSTEM STUDY

A comparative study of existing commercial and open-source threat intelligence platforms was conducted to contextualize the contributions of TRUSTMESH:

| Dimension / Metric | VirusTotal (Google) | PhishTank (OpenDNS) | ScamAdviser | Google Safe Browsing | **TRUSTMESH (Proposed)** |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Primary Focus** | Multi-engine malware & file analysis | Community URL blacklist database | E-commerce website domain trust | Browser-level URL reputation API | **Personal digital trust, text & URL heuristics** |
| **Input Modality** | Files, Domains, IP addresses | URLs only | Domain names only | URLs only | **Text messages, URLs, & mixed content** |
| **Explainability** | Antivirus detection engine counts | Community voting tally & screenshot | Trust score (0–100) with domain age | Binary flag (Phishing/Malware) | **Detailed linguistic & topological signal breakdown** |
| **Data Privacy Policy** | Uploaded files/URLs shared with partners | Public community database of submissions | Queries logged and cached publicly | URLs hashed and queried via API | **Privacy by Design: Raw user text is never stored** |
| **User Access Control** | Commercial API tiers / Public web | Public community accounts | Commercial API tiers | Developer API keys | **Role-Based Access Control (user & admin roles)** |
| **Auditing & History** | Publicly accessible scan records | Publicly visible submissions | Third-party web logs | Zero local user history | **Isolated user history + Security audit logs** |
| **Cloud & BI Export** | Enterprise Threat Intelligence | Flat CSV database download | Commercial API data feeds | None (Client integration only) | **Dual-Mode Azure SQL + Power BI Zero-PII CSV** |
| **Cost to Student** | Free limited / Enterprise (\$10k+/yr) | Free community API | Commercial subscription | Free quota / Cloud billing | **100% Free & Open Source (Local + Azure Free F1)** |

### Critical Literature Analysis:
Existing systems primarily cater to enterprise network perimeters or technical security analysts. They treat incoming payloads as public threat intelligence, which directly conflicts with personal communication privacy. When an individual inputs a private email, a payment receipt, or an SMS containing personal identifiable information (PII) into platforms like VirusTotal or PhishTank, that information enters third-party data feeds. 

**TRUSTMESH bridges this gap** by demonstrating that robust threat detection can be achieved without compromising user confidentiality, using ephemeral in-memory processing coupled with cryptographic SHA-256 indexing.

---

## CHAPTER 7: PROPOSED SYSTEM & NOVEL CONTRIBUTIONS

### 7.1 Proposed System Overview
TRUSTMESH is architected as an assistive, educational, and privacy-preserving cybersecurity copilot. It integrates four decoupled functional subsystems:
1. **Heuristic Detection Subsystem:** Tokenizes and extracts linguistic threat markers and structural URL attributes using regular expression compilation and URI standard decomposition.
2. **Relational Data Management Subsystem:** A normalized 3NF database model supporting atomic transactions, domain check constraints, and dual-dialect execution (SQLite and Azure SQL).
3. **Application Security & RBAC Subsystem:** A zero-trust security perimeter implementing PBKDF2:SHA256 password hashing, CSRF synchronizer token verification, session protection, and audit event trails.
4. **Cloud & Business Intelligence Subsystem:** An enterprise telemetry pipeline providing decoupled Azure Blob report archival, Azure App Service Linux hosting specifications, and Power BI Desktop data modeling.

### 7.2 Key Architectural Innovations
1. **Privacy by Design (PbD) Pipeline:** Raw user messages and URLs exist only in volatile process memory for the fraction of a second required to calculate the score. Once analyzed, the text is purged from memory, and only a SHA-256 hash is saved to prevent data leakage.
2. **Dual-Mode Database Architecture:** A single environment toggle (`DB_MODE`) allows the system to switch between local SQLite development and enterprise Azure SQL cloud hosting, with automatic credential masking in all diagnostic and error outputs.
3. **Explainable Security (X-Sec):** Instead of issuing an opaque risk score, TRUSTMESH breaks down the exact warning signals detected (e.g. *"Urgency detected: 'immediately', 'urgent'"*), accompanied by contextual safety recommendations.
4. **Zero-PII Telemetry Pipeline:** The administrative export engine generates RFC 4180-compliant CSV files stripped of all personal markers, allowing organizational administrators to visualize attack trends in Power BI without exposing employee or user identities.

---

## CHAPTER 8: HIGH-LEVEL SYSTEM ARCHITECTURE

The TRUSTMESH architecture follows a strict **4-Tier Layered Pattern** ensuring high cohesion and loose coupling across subsystems:

```
+-----------------------------------------------------------------------------------------------+
|                       TIER 1: PRESENTATION & CLIENT INTERFACE LAYER                           |
|   Guest User (Public)  |  Authenticated User (Dashboard)  |  Administrator  | Power BI Desktop |
|   Semantic HTML5 / Responsive CSS3 Grid & Flexbox / Vanilla JavaScript (ES6 Async Fetch)     |
+-----------------------------------------------+-----------------------------------------------+
                                                | HTTPS (TLS 1.2+) / CSRF Validated AJAX
                                                v
+-----------------------------------------------------------------------------------------------+
|                       TIER 2: EDGE SECURITY & HTTP MIDDLEWARE LAYER                           |
|   Flask-WTF CSRF Token Validator  |  Payload Boundary Guard (5k chars / 16 MB HTTP cap)      |
|   Security Headers: CSP, X-Content-Type-Options: nosniff, X-Frame-Options: SAMEORIGIN        |
|   Session Cookie Hardening: HttpOnly, SameSite=Lax, Secure  |  Technical Error Masking        |
+-----------------------------------------------+-----------------------------------------------+
                                                | Validated WSGI Request Dispatch
                                                v
+-----------------------------------------------------------------------------------------------+
|                       TIER 3: APPLICATION RUNTIME & INTELLIGENCE LAYER                        |
|                     Python 3.12 / Flask 3.1 / Gunicorn WSGI (2 Workers, 4 Threads)            |
|                                                                                               |
|   [Scam Heuristic Engine]        [Auth & Security Controller]     [Modular Services]          |
|   - Regex Linguistic Rules       - PBKDF2:SHA256 Salting/Hashing   - blob_storage_service.py   |
|   - Static URL Structure Parser  - Role Decorator: @role_required  - analytics_service.py      |
|   - 0-100 Multi-Criteria Scoring - Session Fixation Purge          - config.py & wsgi.py       |
|   - In-Memory Privacy Pipeline   - Horizontal IDOR Isolation       - Credential Masking Logs   |
+-----------------------------------------------+-----------------------------------------------+
                                                | Parameterized Dual-Dialect SQL / Atomic ACID
                                                v
+-----------------------------------------------------------------------------------------------+
|                       TIER 4: PERSISTENCE, CLOUD STORAGE & ANALYTICS LAYER                    |
|                                                                                               |
|   [Dual-Mode Database Layer]     [Forensic Report Archival]       [Analytics Data Mart]       |
|   - LOCAL: SQLite3 (instance/)   - Azure Blob Storage (Private)   - 4 SQL Views (v_analytics) |
|   - CLOUD: Azure SQL (ODBC)      - Local JSON Cache Fallback      - Anonymized CSV Pipeline   |
|   - 8 Tables, 5 Views, Indexes   - Path Traversal Protected       - Power BI DAX Modeling    |
+-----------------------------------------------------------------------------------------------+
```

### Detailed Layer Descriptions:
* **Tier 1 (Presentation):** Crafted entirely in native, standards-compliant HTML5, CSS3, and modern JavaScript. Eliminates bloated client-side frameworks, ensuring zero client attack surface from vulnerable third-party JavaScript dependencies. DOM manipulation uses `textContent` exclusively to prevent DOM-based XSS.
* **Tier 2 (Edge Security):** Intercepts all incoming HTTP traffic. Enforces payload boundaries before request parsing, validates cryptographically signed CSRF tokens, injects security headers, and converts technical exceptions into sanitized JSON/HTML responses.
* **Tier 3 (Application Runtime):** Powered by Flask and WSGI. Orchestrates heuristic pattern evaluation, executes user authentication, manages role boundaries, and abstracts cloud service clients.
* **Tier 4 (Persistence & Analytics):** Houses relational storage and reporting infrastructure. Employs dual-dialect SQL supporting ANSI-standard SQLite queries and enterprise Microsoft T-SQL syntax with equal efficiency.

*(Refer to [`Diagrams/01_system_architecture.svg`](file:///c:/Users/simran/OneDrive/Desktop/TRUST%20MESH/Diagrams/01_system_architecture.svg) for the full vector architectural blueprint).*

---

## CHAPTER 9: SOFTWARE REQUIREMENTS SPECIFICATION (IEEE 830 STANDARD)

### 9.1 Functional Requirements (FR)

| Requirement ID | Module / Subsystem | Functional Requirement Description | Priority |
| :--- | :--- | :--- | :---: |
| **FR-01** | Content Ingestion | The system shall accept text messages and URLs up to 5,000 characters via `POST /analyze`. | High |
| **FR-02** | Input Validation | The system shall reject empty, whitespace-only, or oversized (>5k chars) inputs with HTTP 400. | High |
| **FR-03** | Threat Heuristics | The engine shall scan input for urgency, fee pressure, credential requests, threats, and fake prizes. | High |
| **FR-04** | URL Security Parsing | The engine shall inspect URLs for unencrypted HTTP, numerical IP hostnames, Punycode, and depth. | High |
| **FR-05** | Deterministic Scoring| The system shall calculate an integer score (0–100) and assign risk tiers (Lower, Suspicious, High). | High |
| **FR-06** | Privacy Protection | The system shall discard raw submitted text and save only SHA-256 fingerprints to the database. | High |
| **FR-07** | User Authentication | The system shall register users with salted PBKDF2:SHA256 hashes and validate login credentials. | High |
| **FR-08** | RBAC Enforcement | The system shall restrict `/admin` and analytical routes strictly to authenticated users with role `admin`.| High |
| **FR-09** | CSRF Protection | The system shall validate dynamic CSRF tokens on all state-modifying requests (`POST`, `PUT`, `DELETE`). | High |
| **FR-10** | Dual-Mode Switching | The database layer shall dynamically route queries to SQLite or Azure SQL based on `DB_MODE`. | Medium |
| **FR-11** | Report Archival | The system shall export assessment reports to JSON with optional Azure Blob upload and local fallback. | Medium |
| **FR-12** | Telemetry Export | The system shall generate a 100% PII-free anonymized CSV export for Power BI Desktop consumption. | Medium |

### 9.2 Non-Functional Requirements (NFR)

| Requirement ID | Metric / Quality Attribute | Specification / Acceptance Criteria | Priority |
| :--- | :--- | :--- | :---: |
| **NFR-01** | **Performance (Latency)** | Heuristic text and URL analysis shall execute in under 150 ms (Measured average: 34.52 ms). | High |
| **NFR-02** | **Security (Hashing)** | Password hashes shall use PBKDF2 with HMAC-SHA256 and at least 600,000 hash iterations. | High |
| **NFR-03** | **Security (Headers)** | 100% of HTTP responses shall include CSP, `X-Content-Type-Options`, and `X-Frame-Options`. | High |
| **NFR-04** | **Data Integrity (ACID)** | Multi-table database operations shall execute in atomic transactions with automated rollback. | High |
| **NFR-05** | **Zero-Cost Deployment** | The system shall operate fully on local resources with zero dependency on paid cloud services. | High |
| **NFR-06** | **Maintainability** | Codebase shall follow PEP 8 standards with modular service boundaries and complete unit tests. | Medium |
| **NFR-07** | **Scalability** | Cloud mode shall support Azure App Service containerized multi-worker execution (Gunicorn). | Medium |
| **NFR-08** | **Usability (XAI)** | All risk classifications shall include plain-language explanations of detected signals. | High |

---

## CHAPTER 10: HARDWARE & SOFTWARE ENVIRONMENT SPECIFICATIONS

### 10.1 Development & Local Evaluation Environment
* **Operating System:** Microsoft Windows 11 Home / Pro (64-bit) (or Ubuntu Linux 22.04 LTS / macOS Sonoma)
* **Processor (CPU):** Intel Core i5 / AMD Ryzen 5 or higher (minimum 2 physical cores, 4 threads)
* **System Memory (RAM):** 8 GB minimum (16 GB recommended for concurrent Power BI modeling)
* **Storage Capacity:** 500 MB free disk space for project source code, virtual environment, and local SQLite DB
* **Programming Runtime:** Python 3.12.x (Standard 64-bit CPython distribution)
* **Database Engine:** SQLite 3.45+ (Integrated C-language embedded relational engine)
* **Local Web Server:** Python Werkzeug / Waitress WSGI development server (Binding: `127.0.0.1:5000`)
* **Analytics Client:** Microsoft Power BI Desktop (Version 2.128+ for Windows)

### 10.2 Production Cloud Deployment Environment (Azure PaaS)
* **Hosting Platform:** Microsoft Azure App Service (Linux Web App)
* **Service Tier / Plan:** Free Tier (F1) / Basic (B1) (Linux Container Runtime)
* **Application Server:** Gunicorn 21.2+ (`--workers=2 --threads=4 --timeout=120`)
* **Build System:** Azure Oryx Build Automation (`SCM_DO_BUILD_DURING_DEPLOYMENT=true`)
* **Cloud Database Engine:** Microsoft Azure SQL Database (Serverless General Purpose Tier, TLS 1.2+)
* **Cloud Driver / Protocol:** Microsoft ODBC Driver 17 / 18 for SQL Server (`pyodbc` 5.1+)
* **Cloud Object Storage:** Azure Blob Storage (General Purpose v2 Storage Account, Private Container)


---

## CHAPTER 11: UML USE CASE MODELING & ACTOR SPECIFICATIONS

### 11.1 Actor Definitions
1. **Guest User (Unauthenticated Actor):** A casual or first-time visitor accessing the web platform. Can perform preliminary heuristic scans on messages and URLs, view educational warning explanations, and register for a personal account.
2. **Registered User (Authenticated Actor, Role: `user`):** An authenticated consumer or employee. Inherits all Guest capabilities, plus access to private, user-scoped incident history, structured JSON forensic report export, and report downloads. Protected against horizontal IDOR attacks.
3. **System Administrator (Privileged Actor, Role: `admin`):** A cybersecurity operations analyst or system operator. Inherits all User capabilities, plus access to the protected Administrative Console (`GET /admin`), real-time security audit log streams, registered user directories, platform threat analytics, and anonymized Power BI CSV exports.
4. **Power BI Desktop (External Business Intelligence Actor):** External analytics client ingesting anonymized telemetry data via direct database queries or sanitized CSV downloads to render executive intelligence dashboards.

### 11.2 Comprehensive Use Case Catalog

| Use Case ID | Use Case Name | Primary Actor | Pre-Conditions | Description & Operational Flow | Post-Conditions |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **UC-01** | Analyze Message / URL | Guest / User | Valid HTTP access | User submits text or URL; engine validates size, extracts signals, and computes score. | Result JSON returned; ephemeral or persisted. |
| **UC-02** | View Warning Breakdown | Guest / User | UC-01 completed | User inspects interactive modal showing matched linguistic tokens and safety recommendations. | User informed of exact danger indicators. |
| **UC-03** | Register User Account | Guest | Non-existing email | User inputs display name, email, password; server validates and hashes with PBKDF2:SHA256. | User account created with role `user`. |
| **UC-04** | Authenticate & Login | Guest / User | Registered account | User submits credentials; server verifies hash, clears old session, establishes authenticated cookie. | Authenticated session created; audit log written. |
| **UC-05** | View Personal History | User / Admin | Authenticated session | User accesses dashboard; server executes user-scoped query `WHERE user_id = ?`. | Displays private assessment records. |
| **UC-06** | Export Forensic Report | User / Admin | Authenticated session | User requests structured JSON report for an assessment; server serializes and uploads/caches. | Report stored in Azure Blob or local disk. |
| **UC-07** | Download Owned Report | User / Admin | Ownership verified | User downloads report file; server verifies `report.user_id == session.user_id` before streaming. | File delivered; attempt logged to audit trail. |
| **UC-08** | Access Admin Console | Admin Only | Role: `admin` | Admin requests `/admin`; server checks `@role_required("admin")`. Standard users receive 403. | Administrative dashboard rendered. |
| **UC-09** | Inspect Audit Logs | Admin Only | Role: `admin` | Admin queries `/api/admin/audit-logs`; server returns recent system security events. | Live audit trail displayed. |
| **UC-10** | Query Threat Analytics | Admin Only | Role: `admin` | Admin queries `/api/analytics/*`; server computes KPIs using 4 relational database views. | Visual distribution charts displayed. |
| **UC-11** | Export Anonymized CSV | Admin Only | Role: `admin` | Admin triggers CSV export; server sanitizes all PII and streams RFC 4180 CSV file. | Zero-PII CSV downloaded. |
| **UC-12** | Render BI Dashboards | Power BI | CSV / DirectQuery | Power BI loads telemetry data and evaluates DAX measures across 3 report pages. | Executive dashboards rendered. |

*(Refer to [`Diagrams/02_use_case_diagram.svg`](file:///c:/Users/simran/OneDrive/Desktop/TRUST%20MESH/Diagrams/02_use_case_diagram.svg) for the formal UML diagram).*

---

## CHAPTER 12: DATA FLOW MODELING

### 12.1 DFD Level 0: System Context Diagram
The Level 0 Data Flow Diagram treats TRUSTMESH as a centralized, high-integrity boundary process (`0.0`). It encapsulates all internal database transactions and heuristic scoring mechanisms while mapping interactions across the 4 primary external entities:
* **End User (Client Browser):** Transmits input text, raw URLs, authentication credentials, and report export requests. Receives calculated risk scores, educational warning lists, authenticated session cookies, and structured JSON forensic reports.
* **Administrator:** Transmits administrative credentials, role queries, and analytics filters. Receives real-time security audit streams, system KPIs, and user account listings.
* **Power BI Desktop:** Receives strictly anonymized, RFC 4180-compliant CSV threat telemetry or executes read-only DirectQuery SQL queries against Azure SQL views.
* **Microsoft Azure Cloud Platform:** Receives encrypted T-SQL transactions over TLS 1.2+ and private forensic report JSON streams into Blob Storage. Transmits query result sets and upload acknowledgements.

*(Refer to [`Diagrams/03_dfd_level_0_context.svg`](file:///c:/Users/simran/OneDrive/Desktop/TRUST%20MESH/Diagrams/03_dfd_level_0_context.svg)).*

### 12.2 DFD Level 1: Subsystem Functional Decomposition
The Level 1 DFD decomposes Process `0.0` into six decoupled functional sub-processes interacting with six persistent data stores:
1. **Process 1.0 (Auth & Access Control):** Interacts with `D1: USERS & ROLES` to validate credentials, assign roles, and invalidate sessions upon logout. Writes all authentication successes, failures, and logouts directly to `D4: AUDIT_LOGS`.
2. **Process 2.0 (Threat Heuristic Engine):** Queries `D3: SIGNAL_TYPES` for active threat weights. Evaluates text and URL syntax in volatile memory. Discards raw text immediately after scoring and passes the calculated score and matched signal IDs to Process 3.0.
3. **Process 3.0 (Persistence Controller):** Generates a cryptographic SHA-256 hash (`content_fingerprint`). Opens an atomic ACID transaction to persist the assessment record in `D2: INCIDENTS & RISK_SCORES` and links detected signals in `D3: INCIDENT_SIGNALS`.
4. **Process 4.0 (Audit Logging Manager):** Receives security telemetry from all routes and writes non-sensitive event descriptors to `D4: AUDIT_LOGS`.
5. **Process 5.0 (Report Export Service):** Reads incident records from `D2`, synthesizes structured JSON reports, checks Azure Blob configuration, uploads to cloud container or local filesystem, and registers metadata in `D5: EXPORTED_REPORTS`.
6. **Process 6.0 (BI Analytics Pipeline):** Executes analytical queries against `D6: ANALYTICAL VIEWS`, applies automated PII scrubbing, and streams anonymized CSV telemetry for administrative reporting.

*(Refer to [`Diagrams/04_dfd_level_1_decomposition.svg`](file:///c:/Users/simran/OneDrive/Desktop/TRUST%20MESH/Diagrams/04_dfd_level_1_decomposition.svg)).*

---

## CHAPTER 13: ENTITY-RELATIONSHIP MODELING & 3NF NORMALIZATION

### 13.1 Relational Normalization Analysis (1NF to 3NF)
The TRUSTMESH relational database was designed from first principles to satisfy strict **Third Normal Form (3NF)** requirements:
* **First Normal Form (1NF):** Every table possesses a defined primary key (`role_id`, `user_id`, `incident_id`, etc.). All attributes contain only atomic, indivisible values. Repeating groups (such as multiple detected signals per incident) are strictly prohibited from existing as comma-separated strings in `INCIDENTS` and are instead decomposed into independent relational tuples.
* **Second Normal Form (2NF):** The schema satisfies 1NF, and all non-key attributes are fully functionally dependent on the entire primary key. In the associative table `INCIDENT_SIGNALS`, which utilizes a composite primary key `(incident_id, signal_id)`, the attribute `weight_applied` depends strictly on the entire composite key, eliminating partial dependencies.
* **Third Normal Form (3NF):** The schema satisfies 2NF, and no transitive functional dependencies exist ($X \to Y \to Z$). Non-key attributes depend *solely* on the primary key. For example, user role titles are not duplicated within the `USERS` table; instead, `USERS` references `ROLES.role_id`, ensuring that updating a role name requires modifying exactly one record in one place.

### 13.2 Resolution of Many-to-Many ($M:N$) Relationships
An incident may trigger multiple distinct threat signals (e.g., urgency, fee demands, and an insecure HTTP link), while a specific signal type (e.g., `urgency`) is detected across thousands of independent user incidents. Storing these signals directly inside `INCIDENTS` or `SIGNAL_TYPES` would violate 1NF and create data redundancy.

To resolve this $M:N$ cardinality, the associative entity **`INCIDENT_SIGNALS`** was engineered. It employs a composite primary key:
$$\text{PK}(INCIDENT\_SIGNALS) = (\text{incident\_id}, \text{signal\_id})$$
Both constituent attributes serve simultaneously as foreign keys referencing `INCIDENTS.incident_id` and `SIGNAL_TYPES.signal_id`, enforced with `ON DELETE CASCADE`.

*(Refer to [`Diagrams/05_entity_relationship_diagram.svg`](file:///c:/Users/simran/OneDrive/Desktop/TRUST%20MESH/Diagrams/05_entity_relationship_diagram.svg) for the full Crow's Foot ER schematic).*

---

## CHAPTER 14: DATABASE SCHEMA & COMPLETE DATA DICTIONARY

### 14.1 Entity 1: `ROLES` (User Role Definitions)
| Column Name | Data Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `role_id` | INTEGER | PRIMARY KEY AUTOINCREMENT | Unique identifier for user roles (1 = 'user', 2 = 'admin'). |
| `role_name` | TEXT | UNIQUE NOT NULL | Canonical role identifier ('user', 'admin'). |
| `created_at`| DATETIME | DEFAULT CURRENT_TIMESTAMP | UTC timestamp when the role was provisioned. |

### 14.2 Entity 2: `USERS` (User Accounts Directory)
| Column Name | Data Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `user_id` | INTEGER | PRIMARY KEY AUTOINCREMENT | Unique surrogate primary key for registered users. |
| `role_id` | INTEGER | NOT NULL, FK -> ROLES(role_id) | Foreign key mapping user permissions; defaults to 1 ('user'). |
| `email` | TEXT | UNIQUE NOT NULL | RFC 5322 normalized lowercase user email address. |
| `password_hash` | TEXT | NOT NULL | Salted PBKDF2:SHA256 password hash string. |
| `display_name` | TEXT | NOT NULL | Human-readable user name (2–60 characters). |
| `account_status`| TEXT | DEFAULT 'ACTIVE' | Account state; CHECK (`account_status IN ('ACTIVE','SUSPENDED')`).|
| `created_at` | DATETIME | DEFAULT CURRENT_TIMESTAMP | UTC timestamp when account was registered. |

### 14.3 Entity 3: `INCIDENTS` (Evaluated Content Records)
| Column Name | Data Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `incident_id` | INTEGER | PRIMARY KEY AUTOINCREMENT | Unique identifier for each evaluated incident. |
| `user_id` | INTEGER | FK -> USERS(user_id) ON DELETE CASCADE | Associated user account; NULL for guest scans. |
| `content_type`| TEXT | NOT NULL | Classification of input modality ('message', 'url', 'mixed'). |
| `content_fingerprint`| TEXT | NOT NULL | Cryptographic SHA-256 hash of normalized input text. |
| `created_at` | DATETIME | DEFAULT CURRENT_TIMESTAMP | UTC timestamp when the analysis was performed. |

### 14.4 Entity 4: `RISK_SCORES` (Quantitative Risk Metrics)
| Column Name | Data Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `score_id` | INTEGER | PRIMARY KEY AUTOINCREMENT | Unique primary key for the calculated score record. |
| `incident_id` | INTEGER | UNIQUE NOT NULL, FK -> INCIDENTS | Enforces exact 1:1 relationship with `INCIDENTS`. |
| `risk_score` | INTEGER | NOT NULL | Integer score; CHECK (`risk_score >= 0 AND risk_score <= 100`).|
| `risk_level` | TEXT | NOT NULL | Assigned risk tier ('Lower detected risk', 'Suspicious', 'High risk').|
| `recommendation_stored` | TEXT | NOT NULL | Defensive next steps presented to the user. |
| `engine_version` | TEXT | DEFAULT '1.0.0' | Tracking version of the heuristic scoring algorithm. |
| `created_at` | DATETIME | DEFAULT CURRENT_TIMESTAMP | UTC timestamp when score was persisted. |

### 14.5 Entity 5: `SIGNAL_TYPES` (Standardized Threat Signal Catalog)
| Column Name | Data Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `signal_id` | INTEGER | PRIMARY KEY AUTOINCREMENT | Unique surrogate primary key for threat signal types. |
| `signal_code` | TEXT | UNIQUE NOT NULL | Unique programmatic code (e.g., 'urgency', 'url_ip_hostname'). |
| `signal_name` | TEXT | NOT NULL | Human-readable display title for UI badges and reports. |
| `default_weight`| INTEGER| NOT NULL | Standard risk points assigned when this signal is triggered. |
| `category` | TEXT | NOT NULL | High-level classification ('text_heuristic', 'url_structure'). |
| `description` | TEXT | NOT NULL | Explanatory text defining the security threat. |

### 14.6 Entity 6: `INCIDENT_SIGNALS` (Associative Threat Mapping)
| Column Name | Data Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `incident_id` | INTEGER | NOT NULL, FK -> INCIDENTS | Foreign key referencing the parent incident. |
| `signal_id` | INTEGER | NOT NULL, FK -> SIGNAL_TYPES | Foreign key referencing the detected threat signal. |
| `weight_applied`| INTEGER| NOT NULL | Actual numerical weight contributed to the incident's score. |
| `detected_at` | DATETIME | DEFAULT CURRENT_TIMESTAMP | UTC timestamp of detection. |
| *Composite PK* | *(incident_id, signal_id)* | PRIMARY KEY | Guarantees uniqueness of each signal per incident. |

### 14.7 Entity 7: `AUDIT_LOGS` (Security & Operations Audit Trail)
| Column Name | Data Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `audit_id` | INTEGER | PRIMARY KEY AUTOINCREMENT | Unique surrogate key for the security event record. |
| `user_id` | INTEGER | FK -> USERS(user_id) | Subject user; NULL for anonymous or unauthenticated events. |
| `event_type` | TEXT | NOT NULL | Canonical event category ('LOGIN_SUCCESS', 'FORBIDDEN', etc.). |
| `event_status`| TEXT | NOT NULL | Outcome indicator ('SUCCESS', 'FAILURE', 'SUSPENDED'). |
| `details` | TEXT | NULL | Non-sensitive event metadata (passwords strictly excluded). |
| `ip_address` | TEXT | NULL | Client IP address recorded for security forensics. |
| `user_agent` | TEXT | NULL | Client browser User-Agent string. |
| `created_at` | DATETIME | DEFAULT CURRENT_TIMESTAMP | Immutable UTC timestamp of the audit entry. |

### 14.8 Entity 8: `EXPORTED_REPORTS` (Forensic Archival Directory)
| Column Name | Data Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `report_id` | INTEGER | PRIMARY KEY AUTOINCREMENT | Unique surrogate primary key for exported reports. |
| `assessment_id`| INTEGER| NOT NULL, FK -> INCIDENTS | Foreign key linking report to evaluated incident record. |
| `user_id` | INTEGER | NOT NULL, FK -> USERS | Owner user account; strictly enforced for IDOR defense. |
| `report_format`| TEXT | DEFAULT 'JSON' | File encoding format of the exported forensic document. |
| `storage_status`| TEXT | NOT NULL | Storage medium indicator ('LOCAL' or 'BLOB'). |
| `blob_url` | TEXT | NULL | Azure Blob Storage URI (when cloud storage is active). |
| `local_filepath`| TEXT | NULL | Local filesystem cache path (when local fallback is active). |
| `exported_at` | DATETIME | DEFAULT CURRENT_TIMESTAMP | UTC timestamp when report was synthesized. |

### 14.9 Virtual Analytical Views
1. **`v_incident_summary`:** Performs a multi-table JOIN across `INCIDENTS`, `RISK_SCORES`, `USERS`, and aggregates detected signals using `GROUP_CONCAT()`. Powers personal user dashboards.
2. **`v_analytics_overview`:** Computes high-level platform KPIs: total assessments, average risk score, high-risk count, suspicious count, lower-risk count, and URL analysis prevalence.
3. **`v_risk_level_distribution`:** Aggregates assessment volume and relative percentages grouped by `risk_level` for Power BI donut and bar visualizations.
4. **`v_risk_signal_frequency`:** Aggregates detection frequencies and prevalence rates across all cataloged signal types for top-threat visualizations.
5. **`v_assessment_trends`:** Aggregates incident counts and moving average scores across daily, weekly, and monthly time intervals for longitudinal trend analysis.

---

## CHAPTER 15: REST API INTERFACE & COMMUNICATION SPECIFICATIONS

TRUSTMESH exposes a secure, standardized RESTful interface for web clients and external analytical tools:

| HTTP Method | Route Endpoint | Authentication / Role | Request Payload / Query Params | Expected Status Codes | Response Format / Payload Structure |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `GET` | `/` | Public | None | 200 OK | HTML web page (Heuristic Scanner Interface). |
| `POST` | `/analyze` | Public / Authenticated | JSON: `{"text": "<string>"}` | 200 OK, 400 Bad Request | JSON: `score`, `level`, `findings`, `urls_found`, `disclaimer`. |
| `GET` | `/register` | Public | None | 200 OK (302 if logged in) | HTML registration page. |
| `POST` | `/register` | Public | Form: `display_name`, `email`, `password`, `confirm_password` | 302 Redirect, 400 Bad Request, 409 Conflict | Redirects to `/login` upon successful registration. |
| `GET` | `/login` | Public | Query: `next=<url>` | 200 OK (302 if logged in) | HTML authentication page. |
| `POST` | `/login` | Public | Form: `email`, `password`, `csrf_token` | 302 Redirect, 400 Bad Request, 401 Unauthorized | Sets HTTP session cookie; redirects to `/dashboard` or `/`. |
| `POST` | `/logout` | Authenticated | CSRF token | 302 Redirect | Clears session cookie; redirects to `/login`. |
| `GET` | `/dashboard` | Authenticated (`user`/`admin`)| None | 200 OK, 302 to Login | HTML personal user dashboard with incident history. |
| `GET` | `/history` | Authenticated (`user`/`admin`)| None | 200 OK, 401 Unauthorized | JSON: Array of incident objects owned by current `user_id`. |
| `GET` | `/admin` | Admin Only (`admin`) | None | 200 OK, 403 Forbidden | HTML administrative management console. |
| `GET` | `/api/admin/users` | Admin Only (`admin`) | None | 200 OK, 403 Forbidden | JSON: Array of user records (passwords strictly omitted). |
| `GET` | `/api/admin/audit-logs`| Admin Only (`admin`)| None | 200 OK, 403 Forbidden | JSON: Array of system security audit events. |
| `POST` | `/api/reports/export` | Authenticated (`user`/`admin`)| JSON: `{"assessment_id": <int>}`| 200 OK, 400 Bad Request, 403 Forbidden | JSON: `report_id`, `storage_status`, `download_url`, `message`. |
| `GET` | `/api/reports/download/<id>`| Authenticated Owner | URL param: `id` | 200 OK, 403 Forbidden, 404 Not Found | File stream: `trustmesh_report_asm_<id>.json`. |
| `GET` | `/api/analytics/overview` | Admin Only (`admin`) | None | 200 OK, 403 Forbidden | JSON: KPI summary metrics from `v_analytics_overview`. |
| `GET` | `/api/analytics/distribution`| Admin Only (`admin`)| None | 200 OK, 403 Forbidden | JSON: Risk tier counts and percentages. |
| `GET` | `/api/analytics/signals` | Admin Only (`admin`) | None | 200 OK, 403 Forbidden | JSON: Signal detection counts and prevalence rates. |
| `GET` | `/api/analytics/trends` | Admin Only (`admin`) | Query: `interval=daily/weekly/monthly`| 200 OK, 403 Forbidden | JSON: Time-series incident volume and average scores. |
| `GET` | `/api/analytics/export/csv` | Admin Only (`admin`) | None | 200 OK, 403 Forbidden | File stream: RFC 4180 CSV containing **zero PII**. |
| `GET` | `/health` | Public | None | 200 OK, 503 Service Unavailable | JSON: `status`, `database`, `database_mode`, `storage_status`. |

---

## CHAPTER 16: SYSTEM IMPLEMENTATION & HEURISTIC ALGORITHMS

### 16.1 Mathematical Formulation of the Heuristic Scoring Engine
The TRUSTMESH scoring engine applies deterministic multi-criteria decision rules. Let $T$ represent the input text string and $U$ represent the set of extracted URLs $U = \{u_1, u_2, \dots, u_m\}$. 

Let $S_{text}$ be the catalog of textual heuristic rules where each rule $i$ possesses a weight $w_i \in [15, 30]$:
$$w_i = \begin{cases}
20, & \text{if } i = \text{"urgency"} \\
30, & \text{if } i = \text{"sensitive\_info"} \\
25, & \text{if } i = \text{"payment\_pressure"} \\
25, & \text{if } i = \text{"threats\_suspension"} \\
15, & \text{if } i = \text{"prize\_reward"}
\end{cases}$$

Let $S_{url}$ be the catalog of topological URL structural rules where each rule $j$ possesses a weight $u_j \in [15, 35]$:
$$u_j = \begin{cases}
15, & \text{if } j = \text{"url\_insecure\_http"} \\
35, & \text{if } j = \text{"url\_ip\_hostname"} \\
25, & \text{if } j = \text{"url\_punycode"} \\
20, & \text{if } j = \text{"url\_suspicious\_formatting"}
\end{cases}$$

The aggregate risk score $R \in [0, 100]$ is computed as the bounded summation of triggered unique signal weights:
$$R = \min\left(100, \sum_{i \in \text{DetectedText}} w_i + \sum_{j \in \text{DetectedURL}} u_j\right)$$

The computed risk score $R$ is mapped into a discrete risk classification tier $L$:
$$L = \begin{cases}
\text{"Lower detected risk"}, & 0 \le R < 30 \\
\text{"Suspicious"}, & 30 \le R < 60 \\
\text{"High risk"}, & 60 \le R \le 100
\end{cases}$$

### 16.2 In-Memory Privacy Execution Sequence
To guarantee zero data exposure, the analysis execution flow in `app.py::analyze_interaction()` adheres to strict in-memory lifecycles:
```python
def analyze_interaction(text: str) -> dict:
    # 1. Linguistic heuristic evaluation via pre-compiled regex
    detected_keys, finding_descriptions = evaluate_regex_patterns(text)
    
    # 2. URL extraction and static topological inspection
    urls_found = extract_urls(text)
    for url in urls_found:
        url_results = inspect_url(url)
        # Append findings without sending outbound HTTP requests
        
    # 3. Deterministic score calculation and bounding
    score = min(100, sum(SIGNAL_WEIGHTS[k] for k in detected_keys))
    level = classify_tier(score)
    
    # 4. Immediate memory release: raw text is NOT returned or stored
    return {
        "score": score,
        "level": level,
        "findings": finding_descriptions,
        "urls_found": len(urls_found),
        "disclaimer": DISCLAIMER_TEXT
    }
```

### 16.3 Atomic Database Transaction Persistence
In `database.py::save_analysis_transaction()`, all persistence operations are wrapped in an explicit transaction block:
```python
def save_analysis_transaction(user_id, content_type, fingerprint, score, level, signals):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        # 1. Insert parent record in INCIDENTS
        cur.execute("INSERT INTO INCIDENTS (user_id, content_type, content_fingerprint) VALUES (?, ?, ?);",
                    (user_id, content_type, fingerprint))
        incident_id = cur.lastrowid
        
        # 2. Insert 1:1 score record in RISK_SCORES
        cur.execute("INSERT INTO RISK_SCORES (incident_id, risk_score, risk_level) VALUES (?, ?, ?);",
                    (incident_id, score, level))
                    
        # 3. Insert M:N records in INCIDENT_SIGNALS
        for signal_id, weight in signals.items():
            cur.execute("INSERT INTO INCIDENT_SIGNALS (incident_id, signal_id, weight_applied) VALUES (?, ?, ?);",
                        (incident_id, signal_id, weight))
                        
        conn.commit()  # Atomic Commit
        return incident_id
    except Exception as exc:
        conn.rollback() # 100% Rollback on Constraint Failure
        raise exc
    finally:
        conn.close()
```

*(Refer to [`Diagrams/06_sequence_diagram.svg`](file:///c:/Users/simran/OneDrive/Desktop/TRUST%20MESH/Diagrams/06_sequence_diagram.svg) for the request lifecycle sequence).*

---

## CHAPTER 17: SOFTWARE TESTING, VERIFICATION & BENCHMARKING

### 17.1 Test Execution Summary
The TRUSTMESH platform has been validated through **143 automated test cases** spanning unit tests, integration workflows, security regression tests, and cloud fallback verifications. Zero test cases failed, and zero regressions were identified.

```
========================================================================================
                                TEST EXECUTION BREAKDOWN
========================================================================================
 Test Suite File                      | Tests Run | Passed | Failed | Errors | Status
----------------------------------------------------------------------------------------
 test_engine.py                       |     8     |   8    |   0    |   0    | PASS
 test_phase2.py                       |    14     |  14    |   0    |   0    | PASS
 test_phase3.py                       |    29     |  29    |   0    |   0    | PASS
 test_azure_sql.py                    |    11     |  11    |   0    |   0    | PASS
 test_blob_storage.py                 |    13     |  13    |   0    |   0    | PASS
 test_analytics_powerbi.py            |    12     |  12    |   0    |   0    | PASS
 test_azure_deployment.py             |    12     |  12    |   0    |   0    | PASS
 test_integration_workflows.py        |     2     |   2    |   0    |   0    | PASS
 tests/ (Modular Unit Test Discovery) |    42     |  42    |   0    |   0    | PASS
----------------------------------------------------------------------------------------
 TOTALS                               |   143     | 143    |   0    |   0    | 100% OK
========================================================================================
```

### 17.2 Measured Latency Benchmarks
Latency performance was benchmarked across 10 iterations per endpoint using Python 3.12:

| Subsystem / Operation | Endpoint / Target | Measured Average Latency | Peak Latency | Performance Target | Evaluation |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **Message Heuristic Analysis** | `POST /analyze` | **34.52 ms** | 41.20 ms | < 150 ms | **EXCELLENT** |
| **Static URL Analysis** | `POST /analyze` | **26.32 ms** | 31.80 ms | < 150 ms | **EXCELLENT** |
| **Personal Incident History** | `GET /history` | **6.86 ms** | 9.40 ms | < 50 ms | **EXCELLENT** |
| **Analytics Overview Query** | `GET /api/analytics/overview` | **2.13 ms** | 3.50 ms | < 50 ms | **EXCELLENT** |
| **Temporal Trends Query** | `GET /api/analytics/trends` | **2.19 ms** | 3.20 ms | < 50 ms | **EXCELLENT** |
| **Anonymized CSV Generation** | `GET /api/analytics/export/csv` | **5.93 ms** | 8.10 ms | < 100 ms | **EXCELLENT** |
| **Diagnostic Health Probe** | `GET /health` | **2.89 ms** | 4.10 ms | < 30 ms | **EXCELLENT** |

### 17.3 Edge Case & Adversarial Testing Matrix
* **Empty / Whitespace Input:** Verified rejection of `""` and `"   \n\t  "` with HTTP 400 Bad Request.
* **Oversized Payloads:** Verified rejection of 5,001 character text with HTTP 400 and rejection of >16 MB HTTP bodies with HTTP 413 Payload Too Large.
* **SQL Injection Vectors:** Injected SQL injection strings (`' OR 1=1; DROP TABLE USERS; --`); parameterized operations handled input strictly as literal strings with zero execution.
* **Cross-Site Request Forgery (CSRF):** Form and fetch submissions without CSRF tokens intercepted with HTTP 400.
* **Horizontal IDOR Protection:** User A attempting to query or download User B's reports intercepted with HTTP 403 Forbidden.
* **Vertical Privilege Escalation:** Standard user attempting to access `/admin` intercepted with HTTP 403 Forbidden.

*(Full documentation available in [`FINAL_TEST_REPORT.md`](file:///c:/Users/simran/OneDrive/Desktop/TRUST%20MESH/FINAL_TEST_REPORT.md)).*

---

## CHAPTER 18: SECURITY ANALYSIS & VULNERABILITY MITIGATION

A formal security audit across 29 controls was conducted, mapped to OWASP Top 10 and Common Weakness Enumeration (CWE) standards:

```
========================================================================================
                          SECURITY AUDIT EVALUATION SUMMARY
========================================================================================
 Category 1: Authentication Security    : 7 / 7 Checks PASS (PBKDF2:SHA256, Salt, Fixation)
 Category 2: Authorization & RBAC       : 6 / 6 Checks PASS (user/admin, IDOR, Least Privilege)
 Category 3: Application Security       : 7 / 7 Checks PASS (SQLi, XSS, CSRF, CSP, 16MB Cap)
 Category 4: Cloud Security & Secrets   : 5 / 5 Checks PASS (Masking, Private Blobs, TLS 1.2+)
 Category 5: Logging, Privacy & Audit   : 4 / 4 Checks PASS (Audit Logs, Zero PII, No Log Inj)
----------------------------------------------------------------------------------------
 Overall Security Audit Rating          : GRADE A (Enterprise & Academic Standards Met)
========================================================================================
```

### Key Security Controls Implemented:
1. **Password Security (CWE-916, CWE-759):** PBKDF2 with HMAC-SHA256, >= 600,000 iterations, and cryptographically random salts via `os.urandom()`.
2. **Session Hardening (CWE-384, CWE-312):** `session.clear()` invoked upon login and logout to defeat session fixation. Cookies enforced with `HttpOnly`, `SameSite=Lax`, and `Secure` over HTTPS.
3. **Account Enumeration Defense (CWE-204):** Identical generic response (`"Invalid email or password."`, HTTP 401) returned for wrong passwords and non-existent usernames.
4. **Injection Defenses (CWE-89, CWE-79):** 100% parameterized SQL queries (`?`); Jinja2 auto-escaping on all HTML templates; client DOM rendering using safe `element.textContent`.
5. **Path Traversal Defense (CWE-22):** Report file paths sanitized using `secure_filename()` and an alphanumeric/underscore whitelist regex.
6. **Credential Masking (CWE-532):** `mask_credentials()` regex redacts passwords, tokens, and storage keys with `***REDACTED***` in all log streams.

*(Full evaluation available in [`SECURITY_AUDIT_REPORT.md`](file:///c:/Users/simran/OneDrive/Desktop/TRUST%20MESH/SECURITY_AUDIT_REPORT.md)).*

---

## CHAPTER 19: MICROSOFT AZURE CLOUD & POWER BI INTEGRATION

### 19.1 Microsoft Azure App Service Deployment Specification
The platform is configured for production hosting on **Microsoft Azure App Service (Linux Web App)**:
* **Configuration Profiles:** Implemented in `config.py` using class-based inheritance (`DevelopmentConfig`, `ProductionConfig`, `TestingConfig`).
* **Production Invariants:** `ProductionConfig` disables debug mode, forces `SESSION_COOKIE_SECURE=True`, sets a 2-hour session lifetime, and enforces a 16 MB payload ceiling.
* **WSGI Container Runtime:** `wsgi.py` exposes the standardized `app` WSGI callable.
* **Linux Startup Script:** `startup.sh` binds Gunicorn to dynamic Azure App Service `$PORT`:
  ```bash
  #!/usr/bin/env bash
  gunicorn --bind=0.0.0.0:${PORT:-5000} --workers=2 --threads=4 --timeout=120 wsgi:app
  ```
* **Oryx Deployment Descriptor:** `.deployment` file configures Azure Oryx to run automated build and package installation upon deployment.

### 19.2 Azure SQL Database Dual-Mode Architecture
* **Dual-Dialect Support:** Setting `DB_MODE=azure_sql` switches the engine from local SQLite to Microsoft ODBC Driver 17/18 for SQL Server (`pyodbc`).
* **Production T-SQL Script:** [`schema_azure_sql.sql`](file:///c:/Users/simran/OneDrive/Desktop/TRUST%20MESH/schema_azure_sql.sql) contains 28 batches provisioning all 8 tables with `IDENTITY(1,1)`, constraints, indexes, 5 views, and a dedicated low-privilege application user `trustmesh_app_user`.
* **Automated Data Migration:** [`migrate_to_azure.py`](file:///c:/Users/simran/OneDrive/Desktop/TRUST%20MESH/migrate_to_azure.py) extracts local SQLite data and stages it to Azure SQL with transaction rollbacks.

### 19.3 Azure Blob Storage & Local Fallback
* **Service Module:** [`services/blob_storage_service.py`](file:///c:/Users/simran/OneDrive/Desktop/TRUST%20MESH/services/blob_storage_service.py) utilizes the official `azure-storage-blob` Python SDK.
* **Private Container Security:** Reports are saved in container `trustmesh-reports` with public read access explicitly disabled.
* **Hierarchical Safe Naming:** Naming structure enforces user isolation:
  `reports/user_{user_id}/trustmesh_report_asm_{id}_{timestamp}_{hash}.json`
* **Local Fallback:** When Azure credentials are not provided, reports are serialized to local JSON storage, logged with `storage_status = 'LOCAL'`, and served without errors.

### 19.4 Power BI Analytics Pipeline & Dashboard Design
The platform provides complete Power BI Desktop integration documented in [`POWER_BI_SETUP.md`](file:///c:/Users/simran/OneDrive/Desktop/TRUST%20MESH/POWER_BI_SETUP.md):
* **Anonymized CSV Export (`/api/analytics/export/csv`):** Generates an RFC 4180 CSV containing 11 statistical columns with **zero PII** (no names, emails, IPs, or message text).
* **3-Page Dashboard Layout:**
  1. *Executive Threat Overview:* KPI summary cards, risk level distribution donut chart, and weekly volume area chart.
  2. *Threat Indicator Breakdown:* Treemap of detected signal categories, stacked bar chart of top signals, and risk score distribution histogram.
  3. *Longitudinal Threat Trends:* Monthly assessment growth line chart, risk severity trends, and tabular telemetry view.
* **DAX Formulas Provided:**
  ```dax
  Total Assessments = COUNTROWS('trustmesh_telemetry')
  High Risk % = DIVIDE(CALCULATE(COUNTROWS('trustmesh_telemetry'), 'trustmesh_telemetry'[risk_level] = "High risk"), [Total Assessments], 0)
  Avg Risk Score = AVERAGE('trustmesh_telemetry'[risk_score])
  MoM Growth % = DIVIDE([Total Assessments] - CALCULATE([Total Assessments], DATEADD('trustmesh_telemetry'[incident_date], -1, MONTH)), CALCULATE([Total Assessments], DATEADD('trustmesh_telemetry'[incident_date], -1, MONTH)), 0)
  ```

---

## CHAPTER 20: ACADEMIC CURRICULUM MAPPING & VIVA DEFENSE GUIDE

### 20.1 Academic Curriculum Mapping Across 11 Subjects

| Subject Domain | Key Academic Concepts Demonstrated | Concrete Implementation Evidence in TRUSTMESH |
| :--- | :--- | :--- |
| **1. Creativity & Innovation** | Explainable AI (XAI), Privacy by Design, Dual-Heuristic Engine | Transparent signal rationale in UI modal; raw text discarded immediately in memory. |
| **2. Cybersecurity** | PBKDF2 Hashing, RBAC, CSRF, CSP, SQLi & XSS Prevention | 29 verified controls in `SECURITY_AUDIT_REPORT.md`; `Flask-WTF`, `@role_required`. |
| **3. DBMS** | 3NF Normalization, Foreign Keys, CHECK Constraints, ACID | 8 tables, 5 SQL views, composite PK on `INCIDENT_SIGNALS`, transaction rollbacks. |
| **4. System Design** | 4-Tier Architecture, Separation of Concerns, WSGI Gateway | Decoupled client, edge security, core engine, and dual-mode persistence (`config.py`). |
| **5. PBL-3** | Real-World Anti-Scam Solution, Complete SDLC, Zero-Cost | End-to-end working software; 143 passing regression tests; student cost protection. |
| **6. Programming** | Python 3.12 (Type Hints, Regex, Modular Services, Unittest) | Clean modular architecture in `services/` and `tests/`; 143 tests passing in < 5 seconds. |
| **7. Web Development** | Semantic HTML5, CSS Grid/Flexbox, Async Fetch, Flask Routing | Dark cybersecurity UI (`style.css`), safe DOM manipulation via `textContent`. |
| **8. AI / Machine Learning** | Multi-Criteria Scoring, Feature Extraction, XAI Decision Attribution | Bounded scoring formula ($0..100$); linguistic and topological feature extraction. |
| **9. Cloud Computing** | Azure PaaS App Service, Linux Gunicorn, Oryx Build, Secret Config | `startup.sh`, `wsgi.py`, `.deployment`, `AZURE_DEPLOYMENT.md`. |
| **10. Azure DP-900** | Azure SQL (Relational) vs Blob (Unstructured), Private Containers | `schema_azure_sql.sql` (28 batches), `services/blob_storage_service.py`. |
| **11. Data Analytics** | BI Dimensional Modeling, Anonymized CSV Pipeline, Power BI DAX | 4 analytical SQL views, zero-PII CSV export, complete DAX formulas in `POWER_BI_SETUP.md`. |

### 20.2 Five-Stage Viva Oral Demonstration Script
When presenting TRUSTMESH to university examiners, follow this 5-stage demonstration:
1. **Stage 1: Core Heuristics & Explainability (Phase 1)**
   - Submit benign text: `"Your appointment is scheduled for tomorrow at 10 AM."` -> Score 0, *Lower detected risk*, reassurance disclaimer displayed.
   - Submit scam text: `"URGENT! Pay the registration fee immediately to claim your prize."` -> Score 60, *High risk*, matched keywords highlighted.
   - Submit URL: `http://192.168.1.1/login` -> Flags unencrypted HTTP and raw IP address hostname.
2. **Stage 2: Relational Persistence & Privacy by Design (Phase 2)**
   - Register an account, log in, and view Assessment History.
   - **Key Viva Answer:** *"Explain that TRUSTMESH practices Privacy by Design. Raw submitted messages and URLs are never stored in the database. Only cryptographic SHA-256 fingerprints and categorized signal IDs are persisted."*
3. **Stage 3: Authentication, RBAC & Security Audit (Phase 3)**
   - Attempt to access `/admin` as a standard user -> Demonstrates HTTP 403 Forbidden.
   - Log in as `admin@trustmesh.test` -> Demonstrate real-time Security Audit Log capturing login attempts and access denials.
4. **Stage 4: Power BI Analytics Pipeline (Phase 4)**
   - Click `"Export Anonymized CSV for Power BI"`. Open the downloaded CSV and prove to examiners that it contains **zero personal data** (no names, emails, IPs, or message text).
   - Present the 3-page Power BI dashboard design and DAX formulas from `POWER_BI_SETUP.md`.
5. **Stage 5: Dual-Mode Architecture & Cloud Readiness (Phase 4)**
   - Navigate to `http://127.0.0.1:5000/health` -> Point out `"database_mode": "sqlite"` and `"status": "healthy"`.
   - Explain how setting `DB_MODE=azure_sql` switches the database to Microsoft Azure SQL Database without modifying code. Show `startup.sh` and `wsgi.py` for Azure App Service Linux hosting.

---

## CHAPTER 21: CONCLUSION, FUTURE SCOPE & IEEE BIBLIOGRAPHY

### 21.1 Conclusion
TRUSTMESH successfully bridges the gap between complex enterprise threat intelligence and consumer-facing digital trust. By combining multi-criteria linguistic heuristics, static URL inspection, a normalized 3NF relational database, enterprise authentication, and a zero-PII cloud analytics pipeline, the platform provides a robust, educational, and privacy-preserving defense against modern social engineering threats.

The project demonstrates that high-performance cybersecurity software can be engineered with **zero financial cost** to students and educational institutions, while remaining 100% architecturally compliant with enterprise cloud standards (Microsoft Azure PaaS and Power BI). All 143 automated regression tests validate the reliability, speed (< 35 ms latency), and security of the platform.

### 21.2 Future Scope & Enhancement Roadmap
1. **Supervised Machine Learning Model Integration:** Train a supervised NLP classifier (e.g., fine-tuned RoBERTa or TF-IDF + Logistic Regression) on open-source phishing corpuses (Enron/SpamAssassin) to serve as a secondary scoring model alongside the heuristic engine.
2. **Multi-Factor Authentication (MFA / TOTP):** Enhance user security by integrating Time-Based One-Time Password (TOTP) algorithms (Google Authenticator / Microsoft Authenticator) into the authentication flow.
3. **Browser Extension & Mobile Client:** Develop a lightweight WebExtension (Chrome/Edge/Firefox) that intercepts incoming SMS/web messages and provides real-time risk tooltips directly within browser viewports.
4. **Automated Account Lockout & Rate Limiting:** Implement token-bucket IP rate-limiting (e.g., via Redis or Flask-Limiter) to automatically throttle brute-force login attempts after repeated failures.
5. **Direct Power BI Service Cloud Auto-Refresh:** Establish an organizational Power BI Gateway to automate scheduled data refreshes from Azure SQL Database.

---

### 21.3 IEEE-Formatted Bibliography & Academic Citations

1. [1] Federal Bureau of Investigation, "Internet Crime Report 2024," Internet Crime Complaint Center (IC3), Washington, D.C., Tech. Rep., 2024.
2. [2] Indian Computer Emergency Response Team (CERT-In), "Annual Cyber Security Report: Trends in Phishing and Social Engineering," Ministry of Electronics and Information Technology, New Delhi, India, 2023.
3. [3] A. Aleroud and L. Zhou, "Phishing environments, techniques, and countermeasures: A survey," *Computers & Security*, vol. 68, pp. 160–196, Jul. 2017.
4. [4] P. Kumaraguru, S. Sheng, A. Acquisti, L. F. Cranor, and J. Hong, "Teaching Johnny not to fall for phish," *ACM Transactions on Internet Technology*, vol. 10, no. 2, pp. 1–31, May 2010.
5. [5] E. F. Codd, "A relational model of data for large shared data banks," *Communications of the ACM*, vol. 13, no. 6, pp. 377–387, Jun. 1970.
6. [6] National Institute of Standards and Technology (NIST), "Digital Identity Guidelines: Authentication and Lifecycle Management," NIST Special Publication 800-63B, Gaithersburg, MD, 2020.
7. [7] OWASP Foundation, "OWASP Top 10 Web Application Security Risks," Open Web Application Security Project, Tech. Rep., 2021. [Online]. Available: https://owasp.org/Top10/
8. [8] E. Rescorla, "The Transport Layer Security (TLS) Protocol Version 1.3," RFC 8446, Internet Engineering Task Force (IETF), Aug. 2018.
9. [9] P. Mockapetris, "Domain names - implementation and specification," RFC 1035, Internet Engineering Task Force (IETF), Nov. 1987.
10. [10] A. Cavoukian, "Privacy by Design: The 7 Foundational Principles," Information and Privacy Commissioner of Ontario, Canada, Tech. Rep., 2009.
11. [11] Ministry of Law and Justice, "The Digital Personal Data Protection Act, 2023," *The Gazette of India*, New Delhi, Act No. 22 of 2023, Aug. 2023.
12. [12] European Parliament and Council of the European Union, "General Data Protection Regulation (GDPR)," Regulation (EU) 2016/679, May 2016.
13. [13] M. Grinberg, *Flask Web Development: Developing Web Applications with Python*, 2nd ed. Sebastopol, CA: O'Reilly Media, 2018.
14. [14] Microsoft Corporation, "Azure SQL Database Technical Overview and Architecture Guide," Microsoft Learn Documentation, Redmond, WA, 2024.
15. [15] A. Ferrari and M. Russo, *The Definitive Guide to DAX: Business Intelligence with Microsoft Power BI, SQL Server Analysis Services, and Excel*, 2nd ed. Redmond, WA: Microsoft Press, 2019.
16. [16] IEEE Computer Society, "IEEE Recommended Practice for Software Requirements Specifications," IEEE Std 830-1998, 1998.

---
*End of Master Project Report. Generated and verified for TRUSTMESH Phase 5 Submission.*
