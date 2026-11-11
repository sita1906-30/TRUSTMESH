-- ============================================================================
-- TRUSTMESH Relational Database Schema for Microsoft Azure SQL Database
-- Target DBMS: Azure SQL Database / Microsoft SQL Server 2016+
-- Normalization: 3rd Normal Form (3NF) with RBAC & Enterprise Security
-- Phase 4: Cloud Integration & Dual-Mode Deployment
-- ============================================================================

-- Note for Administrators / Students:
-- Always ensure you have a backup of any existing database before applying schema changes.
-- For Azure SQL, point-in-time restore (PITR) is enabled by default.
-- For local SQLite, copy instance/trustmesh.db to instance/trustmesh_backup.db.

-- ----------------------------------------------------------------------------
-- Table 1: ROLES
-- Purpose: Defines role definitions for Role-Based Access Control (RBAC).
-- ----------------------------------------------------------------------------
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'ROLES')
BEGIN
    CREATE TABLE ROLES (
        role_id INT IDENTITY(1,1) PRIMARY KEY,
        role_name NVARCHAR(50) UNIQUE NOT NULL,
        description NVARCHAR(255)
    );
END;
GO

-- ----------------------------------------------------------------------------
-- Table 2: USERS
-- Purpose: Represents application users with secure password hashes & assigned roles.
-- ----------------------------------------------------------------------------
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'USERS')
BEGIN
    CREATE TABLE USERS (
        user_id INT IDENTITY(1,1) PRIMARY KEY,
        display_name NVARCHAR(100) NOT NULL,
        email NVARCHAR(255) UNIQUE,
        password_hash NVARCHAR(255),
        role_id INT NOT NULL DEFAULT 1,
        account_status NVARCHAR(20) NOT NULL DEFAULT 'ACTIVE' CHECK (account_status IN ('ACTIVE', 'SUSPENDED')),
        created_at DATETIME2 DEFAULT SYSUTCDATETIME(),
        CONSTRAINT FK_USERS_ROLES FOREIGN KEY (role_id) REFERENCES ROLES(role_id)
    );
END;
GO

-- ----------------------------------------------------------------------------
-- Table 3: INCIDENTS
-- Purpose: Records each submitted interaction event without storing raw content.
-- ----------------------------------------------------------------------------
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'INCIDENTS')
BEGIN
    CREATE TABLE INCIDENTS (
        incident_id INT IDENTITY(1,1) PRIMARY KEY,
        user_id INT NOT NULL DEFAULT 1,
        content_type NVARCHAR(20) NOT NULL CHECK (content_type IN ('message', 'url', 'mixed')),
        content_fingerprint NVARCHAR(64),
        created_at DATETIME2 DEFAULT SYSUTCDATETIME(),
        processing_status NVARCHAR(20) NOT NULL DEFAULT 'COMPLETED' CHECK (processing_status IN ('PENDING', 'COMPLETED', 'FAILED')),
        CONSTRAINT FK_INCIDENTS_USERS FOREIGN KEY (user_id) REFERENCES USERS(user_id) ON DELETE CASCADE
    );
END;
GO

-- ----------------------------------------------------------------------------
-- Table 4: RISK_ASSESSMENTS
-- Purpose: Stores the evaluation outcome, risk score, level, and recommendation.
-- ----------------------------------------------------------------------------
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'RISK_ASSESSMENTS')
BEGIN
    CREATE TABLE RISK_ASSESSMENTS (
        assessment_id INT IDENTITY(1,1) PRIMARY KEY,
        incident_id INT NOT NULL UNIQUE,
        risk_score INT NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
        risk_level NVARCHAR(50) NOT NULL CHECK (risk_level IN ('Lower detected risk', 'Suspicious', 'High risk')),
        engine_version NVARCHAR(20) NOT NULL,
        recommendation NVARCHAR(MAX) NOT NULL,
        created_at DATETIME2 DEFAULT SYSUTCDATETIME(),
        CONSTRAINT FK_ASSESSMENTS_INCIDENTS FOREIGN KEY (incident_id) REFERENCES INCIDENTS(incident_id) ON DELETE CASCADE
    );
END;
GO

-- ----------------------------------------------------------------------------
-- Table 5: RISK_SIGNALS
-- Purpose: Standard catalog of detectable warning indicators and heuristics.
-- ----------------------------------------------------------------------------
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'RISK_SIGNALS')
BEGIN
    CREATE TABLE RISK_SIGNALS (
        signal_id INT IDENTITY(1,1) PRIMARY KEY,
        signal_name NVARCHAR(100) UNIQUE NOT NULL,
        category NVARCHAR(100) NOT NULL,
        description NVARCHAR(MAX) NOT NULL
    );
END;
GO

-- ----------------------------------------------------------------------------
-- Table 6: ASSESSMENT_SIGNALS
-- Purpose: Resolves the Many-to-Many relationship between Assessments and Signals.
-- ----------------------------------------------------------------------------
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'ASSESSMENT_SIGNALS')
BEGIN
    CREATE TABLE ASSESSMENT_SIGNALS (
        assessment_id INT NOT NULL,
        signal_id INT NOT NULL,
        points_awarded INT NOT NULL CHECK (points_awarded >= 0),
        CONSTRAINT PK_ASSESSMENT_SIGNALS PRIMARY KEY (assessment_id, signal_id),
        CONSTRAINT FK_AS_ASSESSMENT FOREIGN KEY (assessment_id) REFERENCES RISK_ASSESSMENTS(assessment_id) ON DELETE CASCADE,
        CONSTRAINT FK_AS_SIGNAL FOREIGN KEY (signal_id) REFERENCES RISK_SIGNALS(signal_id)
    );
END;
GO

-- ----------------------------------------------------------------------------
-- Table 7: AUDIT_LOGS
-- Purpose: Records non-sensitive authentication and system security events.
-- ----------------------------------------------------------------------------
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'AUDIT_LOGS')
BEGIN
    CREATE TABLE AUDIT_LOGS (
        audit_id INT IDENTITY(1,1) PRIMARY KEY,
        user_id INT NULL,
        event_type NVARCHAR(100) NOT NULL,
        event_status NVARCHAR(50) NOT NULL,
        details NVARCHAR(MAX),
        created_at DATETIME2 DEFAULT SYSUTCDATETIME(),
        CONSTRAINT FK_AUDIT_USERS FOREIGN KEY (user_id) REFERENCES USERS(user_id) ON DELETE SET NULL
    );
END;
GO

-- ----------------------------------------------------------------------------
-- Table 8: EXPORTED_REPORTS (Phase 4, Task 3: Azure Blob Storage Integration)
-- Purpose: Records metadata of exported assessment reports and cloud storage status.
-- ----------------------------------------------------------------------------
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'EXPORTED_REPORTS')
BEGIN
    CREATE TABLE EXPORTED_REPORTS (
        report_id INT IDENTITY(1,1) PRIMARY KEY,
        user_id INT NOT NULL,
        assessment_id INT NOT NULL,
        blob_name NVARCHAR(255) UNIQUE NOT NULL,
        file_type NVARCHAR(20) NOT NULL DEFAULT 'json',
        file_size INT NOT NULL DEFAULT 0,
        storage_status NVARCHAR(20) NOT NULL DEFAULT 'LOCAL' CHECK (storage_status IN ('LOCAL', 'UPLOADED', 'FAILED')),
        created_at DATETIME2 DEFAULT SYSUTCDATETIME(),
        CONSTRAINT FK_REPORTS_USERS FOREIGN KEY (user_id) REFERENCES USERS(user_id) ON DELETE CASCADE,
        CONSTRAINT FK_REPORTS_ASSESSMENTS FOREIGN KEY (assessment_id) REFERENCES RISK_ASSESSMENTS(assessment_id) ON DELETE CASCADE
    );
END;
GO

-- ----------------------------------------------------------------------------
-- Reporting View: v_incident_summary
-- Purpose: Summarizes incident records with assessment metrics and signal count.
-- ----------------------------------------------------------------------------
CREATE OR ALTER VIEW v_incident_summary AS
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
GROUP BY 
    i.incident_id,
    i.user_id,
    i.content_type,
    i.created_at,
    ra.assessment_id,
    ra.risk_score,
    ra.risk_level,
    ra.engine_version,
    ra.recommendation;
GO

-- ----------------------------------------------------------------------------
-- Analytics View 1: v_analytics_overview (Phase 4, Task 4: Power BI Analytics)
-- Purpose: Global platform KPI aggregates (counts, score averages, risk ratios).
-- ----------------------------------------------------------------------------
CREATE OR ALTER VIEW v_analytics_overview AS
SELECT
    COUNT(ra.assessment_id) AS total_assessments,
    COALESCE(SUM(CASE WHEN ra.risk_level = 'Lower detected risk' THEN 1 ELSE 0 END), 0) AS total_low_risk,
    COALESCE(SUM(CASE WHEN ra.risk_level = 'Suspicious' THEN 1 ELSE 0 END), 0) AS total_medium_risk,
    COALESCE(SUM(CASE WHEN ra.risk_level = 'High risk' THEN 1 ELSE 0 END), 0) AS total_high_risk,
    COALESCE(ROUND(AVG(CAST(ra.risk_score AS FLOAT)), 2), 0.0) AS avg_risk_score,
    COALESCE(ROUND(100.0 * SUM(CASE WHEN ra.risk_level = 'Lower detected risk' THEN 1 ELSE 0 END) / NULLIF(COUNT(ra.assessment_id), 0), 2), 0.0) AS pct_low_risk,
    COALESCE(ROUND(100.0 * SUM(CASE WHEN ra.risk_level = 'Suspicious' THEN 1 ELSE 0 END) / NULLIF(COUNT(ra.assessment_id), 0), 2), 0.0) AS pct_medium_risk,
    COALESCE(ROUND(100.0 * SUM(CASE WHEN ra.risk_level = 'High risk' THEN 1 ELSE 0 END) / NULLIF(COUNT(ra.assessment_id), 0), 2), 0.0) AS pct_high_risk,
    (SELECT COUNT(*) FROM ASSESSMENT_SIGNALS) AS total_signals_detected
FROM RISK_ASSESSMENTS ra;
GO

-- ----------------------------------------------------------------------------
-- Analytics View 2: v_risk_level_distribution (Phase 4, Task 4: Power BI Analytics)
-- Purpose: Aggregated breakdown by risk classification category.
-- ----------------------------------------------------------------------------
CREATE OR ALTER VIEW v_risk_level_distribution AS
SELECT
    ra.risk_level,
    COUNT(ra.assessment_id) AS assessment_count,
    COALESCE(ROUND(AVG(CAST(ra.risk_score AS FLOAT)), 2), 0.0) AS avg_score,
    COALESCE(ROUND(100.0 * COUNT(ra.assessment_id) / NULLIF((SELECT COUNT(*) FROM RISK_ASSESSMENTS), 0), 2), 0.0) AS percentage
FROM RISK_ASSESSMENTS ra
GROUP BY ra.risk_level;
GO

-- ----------------------------------------------------------------------------
-- Analytics View 3: v_risk_signal_frequency (Phase 4, Task 4: Power BI Analytics)
-- Purpose: Distribution and detection frequency of all catalog warning signals.
-- ----------------------------------------------------------------------------
CREATE OR ALTER VIEW v_risk_signal_frequency AS
SELECT
    rs.signal_id,
    rs.signal_name,
    rs.category,
    rs.description,
    COUNT(asig.assessment_id) AS detection_count,
    COALESCE(ROUND(100.0 * COUNT(asig.assessment_id) / NULLIF((SELECT COUNT(*) FROM RISK_ASSESSMENTS), 0), 2), 0.0) AS prevalence_pct
FROM RISK_SIGNALS rs
LEFT JOIN ASSESSMENT_SIGNALS asig ON rs.signal_id = asig.signal_id
GROUP BY rs.signal_id, rs.signal_name, rs.category, rs.description;
GO

-- ----------------------------------------------------------------------------
-- Analytics View 4: v_assessment_trends (Phase 4, Task 4: Power BI Analytics)
-- Purpose: Daily assessment volume, risk level counts, and score averages over time.
-- ----------------------------------------------------------------------------
CREATE OR ALTER VIEW v_assessment_trends AS
SELECT
    CONVERT(VARCHAR(10), ra.created_at, 120) AS assessment_date,
    COUNT(ra.assessment_id) AS total_assessments,
    COALESCE(SUM(CASE WHEN ra.risk_level = 'Lower detected risk' THEN 1 ELSE 0 END), 0) AS low_risk_count,
    COALESCE(SUM(CASE WHEN ra.risk_level = 'Suspicious' THEN 1 ELSE 0 END), 0) AS medium_risk_count,
    COALESCE(SUM(CASE WHEN ra.risk_level = 'High risk' THEN 1 ELSE 0 END), 0) AS high_risk_count,
    COALESCE(ROUND(AVG(CAST(ra.risk_score AS FLOAT)), 2), 0.0) AS avg_risk_score
FROM RISK_ASSESSMENTS ra
GROUP BY CONVERT(VARCHAR(10), ra.created_at, 120);
GO

-- ----------------------------------------------------------------------------
-- Performance & Security Indexes
-- ----------------------------------------------------------------------------
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_incidents_created_at')
    CREATE INDEX idx_incidents_created_at ON INCIDENTS(created_at DESC);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_incidents_user_id')
    CREATE INDEX idx_incidents_user_id ON INCIDENTS(user_id);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_risk_assessments_level')
    CREATE INDEX idx_risk_assessments_level ON RISK_ASSESSMENTS(risk_level);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_risk_assessments_score')
    CREATE INDEX idx_risk_assessments_score ON RISK_ASSESSMENTS(risk_score);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_assessment_signals_signal_id')
    CREATE INDEX idx_assessment_signals_signal_id ON ASSESSMENT_SIGNALS(signal_id);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_users_email')
    CREATE INDEX idx_users_email ON USERS(email);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_users_role_id')
    CREATE INDEX idx_users_role_id ON USERS(role_id);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_audit_logs_event')
    CREATE INDEX idx_audit_logs_event ON AUDIT_LOGS(event_type, created_at DESC);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_exported_reports_user')
    CREATE INDEX idx_exported_reports_user ON EXPORTED_REPORTS(user_id);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_exported_reports_assessment')
    CREATE INDEX idx_exported_reports_assessment ON EXPORTED_REPORTS(assessment_id);
GO

-- ----------------------------------------------------------------------------
-- Trigger: Automated Audit Logging for New Assessments
-- ----------------------------------------------------------------------------
CREATE OR ALTER TRIGGER trg_audit_assessment_insert
ON RISK_ASSESSMENTS
AFTER INSERT
AS
BEGIN
    SET NOCOUNT ON;
    INSERT INTO AUDIT_LOGS (user_id, event_type, event_status, details, created_at)
    SELECT 
        i.user_id,
        'ASSESSMENT_CREATED',
        'SUCCESS',
        'Assessment auto-logged by database trigger',
        SYSUTCDATETIME()
    FROM inserted ra
    JOIN INCIDENTS i ON ra.incident_id = i.incident_id;
END;
GO

-- ----------------------------------------------------------------------------
-- Baseline Reference Data & Seed Records
-- ----------------------------------------------------------------------------

-- 1. Initial Application Roles
SET IDENTITY_INSERT ROLES ON;
IF NOT EXISTS (SELECT 1 FROM ROLES WHERE role_id = 1)
    INSERT INTO ROLES (role_id, role_name, description) VALUES (1, 'user', 'Standard user with scan and personal history permissions');
IF NOT EXISTS (SELECT 1 FROM ROLES WHERE role_id = 2)
    INSERT INTO ROLES (role_id, role_name, description) VALUES (2, 'admin', 'Administrative operator with system monitoring and user review permissions');
SET IDENTITY_INSERT ROLES OFF;
GO

-- 2. Default Anonymous Development User (Backward compatibility & Guest Scans)
SET IDENTITY_INSERT USERS ON;
IF NOT EXISTS (SELECT 1 FROM USERS WHERE user_id = 1)
    INSERT INTO USERS (user_id, display_name, email, password_hash, role_id, account_status)
    VALUES (1, 'Anonymous Cloud User', NULL, NULL, 1, 'ACTIVE');
SET IDENTITY_INSERT USERS OFF;
GO

-- 3. Catalog of Detectable Warning Signals
SET IDENTITY_INSERT RISK_SIGNALS ON;
IF NOT EXISTS (SELECT 1 FROM RISK_SIGNALS WHERE signal_id = 1)
    INSERT INTO RISK_SIGNALS (signal_id, signal_name, category, description)
    VALUES (1, 'urgency', 'Psychological Pressure', 'Urgent language or false deadlines designed to induce hasty action.');

IF NOT EXISTS (SELECT 1 FROM RISK_SIGNALS WHERE signal_id = 2)
    INSERT INTO RISK_SIGNALS (signal_id, signal_name, category, description)
    VALUES (2, 'sensitive_info', 'Credential Harvesting', 'Requests for passwords, OTPs, PINs, or confidential security credentials.');

IF NOT EXISTS (SELECT 1 FROM RISK_SIGNALS WHERE signal_id = 3)
    INSERT INTO RISK_SIGNALS (signal_id, signal_name, category, description)
    VALUES (3, 'payment_pressure', 'Financial Solicitation', 'Direct payment demands, advance fees, or cryptocurrency/gift card transfer requests.');

IF NOT EXISTS (SELECT 1 FROM RISK_SIGNALS WHERE signal_id = 4)
    INSERT INTO RISK_SIGNALS (signal_id, signal_name, category, description)
    VALUES (4, 'threats_suspension', 'Coercion & Intimidation', 'Threats of immediate account closure, deactivation, or legal consequences.');

IF NOT EXISTS (SELECT 1 FROM RISK_SIGNALS WHERE signal_id = 5)
    INSERT INTO RISK_SIGNALS (signal_id, signal_name, category, description)
    VALUES (5, 'prize_reward', 'Lure & Baiting', 'Unsolicited lottery winnings, gifts, or prize rewards.');

IF NOT EXISTS (SELECT 1 FROM RISK_SIGNALS WHERE signal_id = 6)
    INSERT INTO RISK_SIGNALS (signal_id, signal_name, category, description)
    VALUES (6, 'url_insecure_http', 'Transport Security', 'Insecure unencrypted HTTP protocol transmitted in cleartext.');

IF NOT EXISTS (SELECT 1 FROM RISK_SIGNALS WHERE signal_id = 7)
    INSERT INTO RISK_SIGNALS (signal_id, signal_name, category, description)
    VALUES (7, 'url_ip_hostname', 'Infrastructure Obfuscation', 'Direct numerical IP address used as hostname instead of a domain name.');

IF NOT EXISTS (SELECT 1 FROM RISK_SIGNALS WHERE signal_id = 8)
    INSERT INTO RISK_SIGNALS (signal_id, signal_name, category, description)
    VALUES (8, 'url_punycode', 'Domain Spoofing', 'Internationalized domain name (xn--) homograph spoofing risk.');

IF NOT EXISTS (SELECT 1 FROM RISK_SIGNALS WHERE signal_id = 9)
    INSERT INTO RISK_SIGNALS (signal_id, signal_name, category, description)
    VALUES (9, 'url_suspicious_formatting', 'Structural Deception', 'Suspicious subdomain hierarchy, embedded @ credentials, or brand spoofing keywords.');
SET IDENTITY_INSERT RISK_SIGNALS OFF;
GO

-- 4. Cloud Integration Verification Dummy Data (For Initial Cloud Testing Only)
-- Password hash below corresponds to 'CloudTestPass123!' (Werkzeug scrypt)
IF NOT EXISTS (SELECT 1 FROM USERS WHERE email = 'cloud_test@trustmesh.local')
BEGIN
    INSERT INTO USERS (display_name, email, password_hash, role_id, account_status)
    VALUES (
        'Cloud Test User',
        'cloud_test@trustmesh.local',
        'scrypt:32768:8:1$9uA7D3bV2$c8e2fb81b4d3752e825a072cfa65a2a19ceb649d21ecb0b04a43ad73a116b042459c5f6e6900f606346200ebbf6019a861618337725916056637b77ce5f05322',
        1,
        'ACTIVE'
    );
END;
GO

