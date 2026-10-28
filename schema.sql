-- ============================================================================
-- TRUSTMESH Relational Database Schema (Phase 2)
-- Target DBMS: SQLite 3 (Prepared for future Azure SQL Database migration)
-- Normalization: 3rd Normal Form (3NF)
-- ============================================================================

-- Enforce foreign keys (SQLite specific pragma, executed per connection)
PRAGMA foreign_keys = ON;

-- ----------------------------------------------------------------------------
-- Table 1: USERS
-- Purpose: Represents application users or development anonymous sessions.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS USERS (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    display_name TEXT,
    email TEXT UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ----------------------------------------------------------------------------
-- Table 2: ROLES
-- Purpose: Defines role definitions for future authorization controls.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ROLES (
    role_id INTEGER PRIMARY KEY AUTOINCREMENT,
    role_name TEXT UNIQUE NOT NULL,
    description TEXT
);

-- ----------------------------------------------------------------------------
-- Table 3: INCIDENTS
-- Purpose: Records each submitted interaction event without storing raw content.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS INCIDENTS (
    incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL DEFAULT 1,
    content_type TEXT NOT NULL CHECK (content_type IN ('message', 'url', 'mixed')),
    content_fingerprint TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    processing_status TEXT NOT NULL DEFAULT 'COMPLETED' CHECK (processing_status IN ('PENDING', 'COMPLETED', 'FAILED')),
    FOREIGN KEY (user_id) REFERENCES USERS(user_id) ON DELETE CASCADE
);

-- ----------------------------------------------------------------------------
-- Table 4: RISK_ASSESSMENTS
-- Purpose: Stores the evaluation outcome, risk score, level, and recommendation.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS RISK_ASSESSMENTS (
    assessment_id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL UNIQUE,
    risk_score INTEGER NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    risk_level TEXT NOT NULL CHECK (risk_level IN ('Lower detected risk', 'Suspicious', 'High risk')),
    engine_version TEXT NOT NULL,
    recommendation TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (incident_id) REFERENCES INCIDENTS(incident_id) ON DELETE CASCADE
);

-- ----------------------------------------------------------------------------
-- Table 5: RISK_SIGNALS
-- Purpose: Standard catalog of detectable warning indicators and heuristics.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS RISK_SIGNALS (
    signal_id INTEGER PRIMARY KEY AUTOINCREMENT,
    signal_name TEXT UNIQUE NOT NULL,
    category TEXT NOT NULL,
    description TEXT NOT NULL
);

-- ----------------------------------------------------------------------------
-- Table 6: ASSESSMENT_SIGNALS
-- Purpose: Resolves the Many-to-Many relationship between Assessments and Signals.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ASSESSMENT_SIGNALS (
    assessment_id INTEGER NOT NULL,
    signal_id INTEGER NOT NULL,
    points_awarded INTEGER NOT NULL CHECK (points_awarded >= 0),
    PRIMARY KEY (assessment_id, signal_id),
    FOREIGN KEY (assessment_id) REFERENCES RISK_ASSESSMENTS(assessment_id) ON DELETE CASCADE,
    FOREIGN KEY (signal_id) REFERENCES RISK_SIGNALS(signal_id) ON DELETE RESTRICT
);

-- ----------------------------------------------------------------------------
-- Table 7: AUDIT_LOGS
-- Purpose: Records non-sensitive system events for auditability.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS AUDIT_LOGS (
    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    event_type TEXT NOT NULL,
    event_status TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES USERS(user_id) ON DELETE SET NULL
);

-- ----------------------------------------------------------------------------
-- Reporting View: v_incident_summary
-- Purpose: Summarizes incident records with assessment metrics and signal count.
-- ----------------------------------------------------------------------------
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

-- ----------------------------------------------------------------------------
-- Performance Indexes
-- ----------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON INCIDENTS(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_user_id ON INCIDENTS(user_id);
CREATE INDEX IF NOT EXISTS idx_risk_assessments_level ON RISK_ASSESSMENTS(risk_level);
CREATE INDEX IF NOT EXISTS idx_risk_assessments_score ON RISK_ASSESSMENTS(risk_score);
CREATE INDEX IF NOT EXISTS idx_assessment_signals_signal_id ON ASSESSMENT_SIGNALS(signal_id);

-- ----------------------------------------------------------------------------
-- SQLite Trigger: Automated Audit Logging for New Assessments
-- ----------------------------------------------------------------------------
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

-- ----------------------------------------------------------------------------
-- Baseline Reference Data
-- ----------------------------------------------------------------------------

-- 1. Default Anonymous Development User (Phase 2 placeholder)
INSERT OR IGNORE INTO USERS (user_id, display_name, email)
VALUES (1, 'Anonymous Development User', NULL);

-- 2. Initial Application Roles
INSERT OR IGNORE INTO ROLES (role_id, role_name, description)
VALUES 
    (1, 'user', 'Standard user with scan and personal history permissions'),
    (2, 'admin', 'Administrative operator with system monitoring permissions');

-- 3. Catalog of Detectable Warning Signals
INSERT OR IGNORE INTO RISK_SIGNALS (signal_id, signal_name, category, description)
VALUES
    (1, 'urgency', 'Psychological Pressure', 'Urgent language or false deadlines designed to induce hasty action.'),
    (2, 'sensitive_info', 'Credential Harvesting', 'Requests for passwords, OTPs, PINs, or confidential security credentials.'),
    (3, 'payment_pressure', 'Financial Solicitation', 'Direct payment demands, advance fees, or cryptocurrency/gift card transfer requests.'),
    (4, 'threats_suspension', 'Coercion & Intimidation', 'Threats of immediate account closure, deactivation, or legal consequences.'),
    (5, 'prize_reward', 'Lure & Baiting', 'Unsolicited lottery winnings, gifts, or prize rewards.'),
    (6, 'url_insecure_http', 'Transport Security', 'Insecure unencrypted HTTP protocol transmitted in cleartext.'),
    (7, 'url_ip_hostname', 'Infrastructure Obfuscation', 'Direct numerical IP address used as hostname instead of a domain name.'),
    (8, 'url_punycode', 'Domain Spoofing', 'Internationalized domain name (xn--) homograph spoofing risk.'),
    (9, 'url_suspicious_formatting', 'Structural Deception', 'Suspicious subdomain hierarchy, embedded @ credentials, or brand spoofing keywords.');
