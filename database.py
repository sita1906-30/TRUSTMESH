"""
TRUSTMESH Centralized Database Module (Phase 4: Dual-Mode Architecture)
Supports two operational modes:
1. LOCAL MODE (Default): Embedded SQLite database (instance/trustmesh.db)
2. CLOUD MODE: Microsoft Azure SQL Database (via pyodbc / SQLAlchemy)

Switching between modes is managed via the DATABASE_MODE environment variable.
Never exposes credentials in logs, error messages, or API outputs.
"""

import hashlib
import logging
import os
import re
import sqlite3
from typing import Any, Dict, List, Optional, Tuple

# Load environment configuration if python-dotenv is available
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

logger = logging.getLogger("trustmesh.database")

# Default paths for local SQLite storage (handles Vercel /tmp read-only filesystem)
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
if os.environ.get("VERCEL"):
    DEFAULT_INSTANCE_DIR = "/tmp"
    DEFAULT_DB_PATH = "/tmp/trustmesh.db"
else:
    DEFAULT_INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
    DEFAULT_DB_PATH = os.path.join(DEFAULT_INSTANCE_DIR, "trustmesh.db")

SCHEMA_SQLITE_PATH = os.path.join(BASE_DIR, "schema.sql")
SCHEMA_AZURE_PATH = os.path.join(BASE_DIR, "schema_azuresql.sql")


# ---------------------------------------------------------------------------
# Centralized Database Configuration & Mode Management
# ---------------------------------------------------------------------------

class DatabaseMode:
    SQLITE = "sqlite"
    AZURE_SQL = "azure_sql"


def get_database_mode() -> str:
    """
    Returns the active database mode configured in environment variables.
    Defaults safely to 'sqlite' if unspecified.
    """
    raw_mode = os.environ.get("DATABASE_MODE", DatabaseMode.SQLITE).strip().lower()
    if raw_mode in ("azure_sql", "azure", "mssql", "cloud"):
        return DatabaseMode.AZURE_SQL
    return DatabaseMode.SQLITE


def get_azure_sql_config() -> Dict[str, Any]:
    """
    Retrieves Azure SQL configuration settings from environment variables.
    Never exposes plaintext credentials in returned string representations.
    """
    return {
        "server": os.environ.get("AZURE_SQL_SERVER", "").strip(),
        "database": os.environ.get("AZURE_SQL_DATABASE", "").strip(),
        "username": os.environ.get("AZURE_SQL_USERNAME", "").strip(),
        "password": os.environ.get("AZURE_SQL_PASSWORD", ""),
        "driver": os.environ.get("AZURE_SQL_DRIVER", "{ODBC Driver 18 for SQL Server}").strip(),
        "connection_string": os.environ.get("DATABASE_URL", "").strip(),
    }


def mask_credentials(text: str) -> str:
    """
    Sanitizes strings to strip sensitive passwords or tokens before logging or rendering.
    """
    if not text:
        return ""
    # Mask password parameters in connection strings and URLs
    sanitized = re.sub(r'(pwd|password)=[^;]+', r'\1=********', text, flags=re.IGNORECASE)
    sanitized = re.sub(r'(:\/\/[^:]+:)[^@]+(@)', r'\1********\2', sanitized)
    return sanitized


def get_active_sqlite_path(db_path: Optional[str] = None) -> str:
    """Returns the effective path for SQLite database operations."""
    if db_path:
        return db_path
    return os.environ.get("DATABASE_PATH", DEFAULT_DB_PATH)


# ---------------------------------------------------------------------------
# Connection Factories (SQLite & Azure SQL)
# ---------------------------------------------------------------------------

def get_sqlite_connection(target_path: str) -> sqlite3.Connection:
    """
    Creates and returns a SQLite database connection with:
    1. Foreign keys explicitly enabled (PRAGMA foreign_keys = ON).
    2. Row factory set to sqlite3.Row for dictionary-like column access.
    """
    if target_path != ":memory:":
        os.makedirs(os.path.dirname(os.path.abspath(target_path)), exist_ok=True)

    conn = sqlite3.connect(target_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def get_azure_sql_connection():
    """
    Initializes a connection to Azure SQL Database using pyodbc or SQLAlchemy.
    Gracefully handles driver unavailability or credential errors with sanitized logging.
    """
    creds = get_azure_sql_config()

    if not creds.get("server") or not creds.get("database"):
        raise ValueError(
            "Azure SQL Database is selected (DATABASE_MODE=azure_sql), but AZURE_SQL_SERVER "
            "or AZURE_SQL_DATABASE is missing in environment variables."
        )

    try:
        import pyodbc
    except ImportError:
        logger.error("Azure SQL connection failed: 'pyodbc' library is not installed in the environment.")
        raise RuntimeError(
            "Azure SQL connection requires the 'pyodbc' package and Microsoft ODBC Driver for SQL Server. "
            "Please install pyodbc or switch DATABASE_MODE to 'sqlite'."
        )

    conn_str = creds.get("connection_string")
    if not conn_str:
        conn_str = (
            f"DRIVER={creds['driver']};"
            f"SERVER={creds['server']};"
            f"DATABASE={creds['database']};"
            f"UID={creds['username']};"
            f"PWD={creds['password']};"
            "Encrypt=yes;"
            "TrustServerCertificate=no;"
            "Connection Timeout=30;"
        )

    try:
        conn = pyodbc.connect(conn_str)
        # Enable autocommit or manual commit handling
        return conn
    except Exception as exc:
        sanitized_err = mask_credentials(str(exc))
        logger.error("Failed to connect to Azure SQL Database: %s", sanitized_err)
        raise ConnectionError(f"Azure SQL Connection Failure: {sanitized_err}") from None


def get_db_connection(db_path: Optional[str] = None):
    """
    Unified database connection factory.
    Dispatches to SQLite or Azure SQL based on configuration.
    If db_path is explicitly provided (such as in automated test suites),
    SQLite is always used to preserve test isolation.
    """
    mode = get_database_mode()
    
    # If a specific local test db_path is provided, honor SQLite mode for test isolation
    if db_path is not None or mode == DatabaseMode.SQLITE:
        target = get_active_sqlite_path(db_path)
        return get_sqlite_connection(target)
    else:
        return get_azure_sql_connection()


def is_azure_connection(conn: Any) -> bool:
    """Helper to detect whether an active connection is Azure SQL (non-SQLite)."""
    return not isinstance(conn, sqlite3.Connection)


def row_to_dict(cursor: Any, row: Any) -> Optional[Dict[str, Any]]:
    """Converts a database row into a standard Python dictionary across both dialects."""
    if row is None:
        return None
    if isinstance(row, sqlite3.Row):
        return dict(row)
    if hasattr(row, "keys"):
        return dict(row)
    if hasattr(cursor, "description") and cursor.description:
        col_names = [col[0] for col in cursor.description]
        return dict(zip(col_names, row))
    return dict(row)


# ---------------------------------------------------------------------------
# Database Status & Health Monitoring
# ---------------------------------------------------------------------------

def get_database_status(db_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Accurately inspects the active database connection and returns status metadata.
    Rules:
    - Never displays 'Azure SQL connected' without an actual successful connection test.
    - Accurately reports: 'Local SQLite connected', 'Azure SQL connected', or 'Database unavailable'.
    """
    mode = get_database_mode() if db_path is None else DatabaseMode.SQLITE

    if mode == DatabaseMode.SQLITE:
        target_path = get_active_sqlite_path(db_path)
        try:
            conn = get_sqlite_connection(target_path)
            cur = conn.cursor()
            cur.execute("SELECT 1;")
            res = cur.fetchone()
            conn.close()
            is_connected = res is not None and res[0] == 1
        except Exception as exc:
            logger.warning("SQLite health check failed: %s", str(exc))
            is_connected = False

        return {
            "mode": "sqlite",
            "is_cloud": False,
            "status": "connected" if is_connected else "unavailable",
            "indicator": "Local SQLite connected" if is_connected else "Database unavailable",
            "details": f"SQLite database at {target_path}",
        }
    else:
        # Azure SQL mode
        creds = get_azure_sql_config()
        masked_server = creds["server"] or "unconfigured"
        masked_db = creds["database"] or "unconfigured"

        try:
            conn = get_azure_sql_connection()
            cur = conn.cursor()
            cur.execute("SELECT 1;")
            res = cur.fetchone()
            conn.close()
            is_connected = res is not None and res[0] == 1
            error_details = ""
        except Exception as exc:
            is_connected = False
            error_details = mask_credentials(str(exc))

        return {
            "mode": "azure_sql",
            "is_cloud": True,
            "status": "connected" if is_connected else "unavailable",
            "indicator": "Azure SQL connected" if is_connected else "Database unavailable",
            "details": f"Azure SQL Server [{masked_server}] Database [{masked_db}]" + (f": {error_details}" if error_details else ""),
        }


def check_db_health(db_path: Optional[str] = None) -> bool:
    """Verifies that the currently configured database is responsive to queries."""
    status_info = get_database_status(db_path)
    return status_info["status"] == "connected"


# ---------------------------------------------------------------------------
# Schema Migration & Initialization (SQLite & Azure SQL)
# ---------------------------------------------------------------------------

def migrate_db(db_path: Optional[str] = None) -> None:
    """
    Safely applies non-destructive Phase 3/4 schema migrations to SQLite.
    Preserves all existing records without data loss.
    """
    if get_database_mode() == DatabaseMode.AZURE_SQL and db_path is None:
        logger.info("Azure SQL mode active. Schema migrations are managed via migrate_to_azure.py.")
        return

    conn = get_db_connection(db_path)
    try:
        cur = conn.cursor()

        # 1. Inspect existing USERS table columns
        cur.execute("PRAGMA table_info(USERS);")
        user_cols = {row["name"] for row in cur.fetchall()}

        if "password_hash" not in user_cols:
            cur.execute("ALTER TABLE USERS ADD COLUMN password_hash TEXT;")
            logger.info("Migrated USERS: added password_hash column.")

        if "role_id" not in user_cols:
            cur.execute("ALTER TABLE USERS ADD COLUMN role_id INTEGER NOT NULL DEFAULT 1;")
            logger.info("Migrated USERS: added role_id column.")

        if "account_status" not in user_cols:
            cur.execute("ALTER TABLE USERS ADD COLUMN account_status TEXT NOT NULL DEFAULT 'ACTIVE';")
            logger.info("Migrated USERS: added account_status column.")

        # 2. Inspect AUDIT_LOGS columns
        cur.execute("PRAGMA table_info(AUDIT_LOGS);")
        audit_cols = {row["name"] for row in cur.fetchall()}
        if "details" not in audit_cols:
            cur.execute("ALTER TABLE AUDIT_LOGS ADD COLUMN details TEXT;")
            logger.info("Migrated AUDIT_LOGS: added details column.")

        # 3. Create Performance & Security Indexes
        cur.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON USERS(email);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_users_role_id ON USERS(role_id);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_event ON AUDIT_LOGS(event_type, created_at DESC);")

        # 4. Ensure Baseline Roles Exist
        cur.execute("INSERT OR IGNORE INTO ROLES (role_id, role_name, description) VALUES (1, 'user', 'Standard user');")
        cur.execute("INSERT OR IGNORE INTO ROLES (role_id, role_name, description) VALUES (2, 'admin', 'Administrator');")

        # 5. Ensure Anonymous user exists for backward compatibility
        cur.execute("INSERT OR IGNORE INTO USERS (user_id, display_name, email, password_hash, role_id, account_status) VALUES (1, 'Anonymous Dev User', NULL, NULL, 1, 'ACTIVE');")

        # 6. Ensure EXPORTED_REPORTS table exists (Phase 4, Task 3: Azure Blob Storage Integration)
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS EXPORTED_REPORTS (
                report_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                assessment_id INTEGER NOT NULL,
                blob_name TEXT UNIQUE NOT NULL,
                file_type TEXT NOT NULL DEFAULT 'json',
                file_size INTEGER NOT NULL DEFAULT 0,
                storage_status TEXT NOT NULL DEFAULT 'LOCAL' CHECK (storage_status IN ('LOCAL', 'UPLOADED', 'FAILED')),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES USERS(user_id) ON DELETE CASCADE,
                FOREIGN KEY (assessment_id) REFERENCES RISK_ASSESSMENTS(assessment_id) ON DELETE CASCADE
            );
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_exported_reports_user ON EXPORTED_REPORTS(user_id);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_exported_reports_assessment ON EXPORTED_REPORTS(assessment_id);")

        # 7. Create Analytics Views (Phase 4, Task 4: Power BI Analytics)
        cur.execute(
            """
            CREATE VIEW IF NOT EXISTS v_analytics_overview AS
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
            """
        )
        cur.execute(
            """
            CREATE VIEW IF NOT EXISTS v_risk_level_distribution AS
            SELECT
                ra.risk_level,
                COUNT(ra.assessment_id) AS assessment_count,
                COALESCE(ROUND(AVG(CAST(ra.risk_score AS FLOAT)), 2), 0.0) AS avg_score,
                COALESCE(ROUND(100.0 * COUNT(ra.assessment_id) / NULLIF((SELECT COUNT(*) FROM RISK_ASSESSMENTS), 0), 2), 0.0) AS percentage
            FROM RISK_ASSESSMENTS ra
            GROUP BY ra.risk_level;
            """
        )
        cur.execute(
            """
            CREATE VIEW IF NOT EXISTS v_risk_signal_frequency AS
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
            """
        )
        cur.execute(
            """
            CREATE VIEW IF NOT EXISTS v_assessment_trends AS
            SELECT
                DATE(ra.created_at) AS assessment_date,
                COUNT(ra.assessment_id) AS total_assessments,
                COALESCE(SUM(CASE WHEN ra.risk_level = 'Lower detected risk' THEN 1 ELSE 0 END), 0) AS low_risk_count,
                COALESCE(SUM(CASE WHEN ra.risk_level = 'Suspicious' THEN 1 ELSE 0 END), 0) AS medium_risk_count,
                COALESCE(SUM(CASE WHEN ra.risk_level = 'High risk' THEN 1 ELSE 0 END), 0) AS high_risk_count,
                COALESCE(ROUND(AVG(CAST(ra.risk_score AS FLOAT)), 2), 0.0) AS avg_risk_score
            FROM RISK_ASSESSMENTS ra
            GROUP BY DATE(ra.created_at);
            """
        )

        conn.commit()
        logger.info("Database migration check completed successfully.")
    except Exception as exc:
        conn.rollback()
        logger.error("Database migration failed: %s", str(exc))
        raise exc
    finally:
        conn.close()


def init_db(db_path: Optional[str] = None, schema_file: Optional[str] = None) -> None:
    """Initializes the SQLite database from schema.sql and runs migrations."""
    target_path = get_active_sqlite_path(db_path)
    schema_path = schema_file or SCHEMA_SQLITE_PATH

    if not os.path.exists(schema_path):
        raise FileNotFoundError(f"Schema definition file not found at: {schema_path}")

    with open(schema_path, "r", encoding="utf-8") as f:
        schema_sql = f.read()

    conn = get_sqlite_connection(target_path)
    try:
        conn.executescript(schema_sql)
        conn.commit()
        logger.info("Database initialized successfully at: %s", target_path)
    except Exception as exc:
        conn.rollback()
        logger.error("Failed to initialize database: %s", str(exc))
        raise exc
    finally:
        conn.close()

    migrate_db(target_path)


def generate_content_fingerprint(text: str) -> str:
    """Generates a cryptographic SHA-256 fingerprint of the normalized text."""
    normalized = text.strip().lower()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# User Authentication & RBAC Functions (Dual Dialect Supported)
# ---------------------------------------------------------------------------

def create_user(
    display_name: str,
    email: str,
    password_hash: str,
    role_id: int = 1,
    account_status: str = "ACTIVE",
    db_path: Optional[str] = None
) -> int:
    """
    Inserts a newly registered user account into USERS.
    Enforces unique email and non-empty display name across SQLite and Azure SQL.
    """
    conn = get_db_connection(db_path)
    is_cloud = is_azure_connection(conn)
    try:
        cur = conn.cursor()
        clean_name = display_name.strip()
        clean_email = email.strip().lower()

        if is_cloud:
            cur.execute(
                """
                INSERT INTO USERS (display_name, email, password_hash, role_id, account_status)
                OUTPUT INSERTED.user_id
                VALUES (?, ?, ?, ?, ?);
                """,
                (clean_name, clean_email, password_hash, role_id, account_status)
            )
            row = cur.fetchone()
            user_id = row[0]
        else:
            cur.execute(
                """
                INSERT INTO USERS (display_name, email, password_hash, role_id, account_status)
                VALUES (?, ?, ?, ?, ?);
                """,
                (clean_name, clean_email, password_hash, role_id, account_status)
            )
            user_id = cur.lastrowid

        conn.commit()
        logger.info("User created successfully: ID #%d, Email: %s", user_id, clean_email)
        return user_id
    except sqlite3.IntegrityError as err:
        conn.rollback()
        if "UNIQUE constraint failed: USERS.email" in str(err) or "email" in str(err).lower():
            raise ValueError("An account with this email address already exists.")
        raise err
    except Exception as exc:
        conn.rollback()
        err_str = str(exc).lower()
        if "unique" in err_str or "duplicate" in err_str:
            raise ValueError("An account with this email address already exists.")
        raise exc
    finally:
        conn.close()


def get_user_by_email(email: str, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Retrieves user record joined with role_name by email address (case-insensitive)."""
    conn = get_db_connection(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT u.user_id, u.display_name, u.email, u.password_hash, u.role_id,
                   u.account_status, u.created_at, r.role_name
            FROM USERS u
            JOIN ROLES r ON u.role_id = r.role_id
            WHERE LOWER(u.email) = LOWER(?);
            """,
            (email.strip(),)
        )
        row = cur.fetchone()
        return row_to_dict(cur, row)
    finally:
        conn.close()


def get_user_by_id(user_id: int, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Retrieves user record joined with role_name by user_id."""
    conn = get_db_connection(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT u.user_id, u.display_name, u.email, u.password_hash, u.role_id,
                   u.account_status, u.created_at, r.role_name
            FROM USERS u
            JOIN ROLES r ON u.role_id = r.role_id
            WHERE u.user_id = ?;
            """,
            (user_id,)
        )
        row = cur.fetchone()
        return row_to_dict(cur, row)
    finally:
        conn.close()


def log_audit_event(
    user_id: Optional[int],
    event_type: str,
    event_status: str,
    details: Optional[str] = None,
    db_path: Optional[str] = None
) -> int:
    """
    Records a security or administrative event into AUDIT_LOGS.
    Privacy Rule: Never logs passwords, password hashes, full messages, or secrets.
    """
    conn = get_db_connection(db_path)
    is_cloud = is_azure_connection(conn)
    try:
        cur = conn.cursor()
        if is_cloud:
            cur.execute(
                """
                INSERT INTO AUDIT_LOGS (user_id, event_type, event_status, details)
                OUTPUT INSERTED.audit_id
                VALUES (?, ?, ?, ?);
                """,
                (user_id, event_type, event_status, details)
            )
            row = cur.fetchone()
            audit_id = row[0] if row else 0
        else:
            cur.execute(
                """
                INSERT INTO AUDIT_LOGS (user_id, event_type, event_status, details)
                VALUES (?, ?, ?, ?);
                """,
                (user_id, event_type, event_status, details)
            )
            audit_id = cur.lastrowid
        conn.commit()
        return audit_id
    except Exception as exc:
        conn.rollback()
        logger.error("Failed to write audit log: %s", mask_credentials(str(exc)))
        return -1
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Transactional Persistence & History (Dual Dialect Supported)
# ---------------------------------------------------------------------------

def save_analysis_transaction(
    user_id: int,
    content_type: str,
    content_fingerprint: str,
    score: int,
    level: str,
    engine_version: str,
    recommendation: str,
    detected_signals: Dict[str, int],
    db_path: Optional[str] = None
) -> Tuple[int, int]:
    """
    Saves an analysis event into the database inside a single atomic transaction.
    Associates the record with the authenticated user_id.
    Compatible with both SQLite and Azure SQL transactions.
    """
    conn = get_db_connection(db_path)
    is_cloud = is_azure_connection(conn)
    try:
        cursor = conn.cursor()

        # 1. Insert Incident (Safe metadata only, associated with authenticated user)
        if is_cloud:
            cursor.execute(
                """
                INSERT INTO INCIDENTS (user_id, content_type, content_fingerprint, processing_status)
                OUTPUT INSERTED.incident_id
                VALUES (?, ?, ?, 'COMPLETED');
                """,
                (user_id, content_type, content_fingerprint)
            )
            incident_id = cursor.fetchone()[0]
        else:
            cursor.execute(
                """
                INSERT INTO INCIDENTS (user_id, content_type, content_fingerprint, processing_status)
                VALUES (?, ?, ?, 'COMPLETED');
                """,
                (user_id, content_type, content_fingerprint)
            )
            incident_id = cursor.lastrowid

        # 2. Insert Risk Assessment
        if is_cloud:
            cursor.execute(
                """
                INSERT INTO RISK_ASSESSMENTS (incident_id, risk_score, risk_level, engine_version, recommendation)
                OUTPUT INSERTED.assessment_id
                VALUES (?, ?, ?, ?, ?);
                """,
                (incident_id, score, level, engine_version, recommendation)
            )
            assessment_id = cursor.fetchone()[0]
        else:
            cursor.execute(
                """
                INSERT INTO RISK_ASSESSMENTS (incident_id, risk_score, risk_level, engine_version, recommendation)
                VALUES (?, ?, ?, ?, ?);
                """,
                (incident_id, score, level, engine_version, recommendation)
            )
            assessment_id = cursor.lastrowid

        # 3. Link Detected Signals via ASSESSMENT_SIGNALS
        if detected_signals:
            for signal_name, points in detected_signals.items():
                cursor.execute(
                    "SELECT signal_id FROM RISK_SIGNALS WHERE signal_name = ?;",
                    (signal_name,)
                )
                row = cursor.fetchone()
                if row:
                    signal_id = row[0] if is_cloud else row["signal_id"]
                    cursor.execute(
                        """
                        INSERT INTO ASSESSMENT_SIGNALS (assessment_id, signal_id, points_awarded)
                        VALUES (?, ?, ?);
                        """,
                        (assessment_id, signal_id, points)
                    )
                else:
                    logger.warning("Unrecognized signal name in catalog: %s", signal_name)

        conn.commit()
        logger.info("Transaction committed successfully for Incident #%d (User #%d)", incident_id, user_id)
        return incident_id, assessment_id
    except Exception as exc:
        conn.rollback()
        logger.error("Transaction failed during save_analysis_transaction: %s", mask_credentials(str(exc)))
        raise exc
    finally:
        conn.close()


def get_history(
    user_id: Optional[int] = None,
    limit: int = 20,
    db_path: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Retrieves safe analysis history records.
    Strictly scopes records to the authenticated user_id.
    Does NOT return any raw user content.
    """
    conn = get_db_connection(db_path)
    is_cloud = is_azure_connection(conn)
    try:
        cursor = conn.cursor()

        # Handle dialect-specific pagination syntax (LIMIT vs OFFSET...FETCH)
        pagination_clause = "OFFSET 0 ROWS FETCH NEXT ? ROWS ONLY" if is_cloud else "LIMIT ?"

        if user_id is not None:
            sql = f"""
                SELECT 
                    incident_id,
                    user_id,
                    content_type,
                    incident_time,
                    assessment_id,
                    risk_score,
                    risk_level,
                    engine_version,
                    recommendation,
                    signal_count
                FROM v_incident_summary
                WHERE user_id = ?
                ORDER BY incident_id DESC
                {pagination_clause};
            """
            cursor.execute(sql, (user_id, limit))
        else:
            # Anonymous / Fallback
            sql = f"""
                SELECT 
                    incident_id,
                    user_id,
                    content_type,
                    incident_time,
                    assessment_id,
                    risk_score,
                    risk_level,
                    engine_version,
                    recommendation,
                    signal_count
                FROM v_incident_summary
                ORDER BY incident_id DESC
                {pagination_clause};
            """
            cursor.execute(sql, (limit,))

        rows = cursor.fetchall()
        history_list = []
        for r in rows:
            row_dict = row_to_dict(cursor, r)
            assessment_id = row_dict["assessment_id"]

            cursor.execute(
                """
                SELECT 
                    rs.signal_name,
                    rs.category,
                    rs.description,
                    asig.points_awarded
                FROM ASSESSMENT_SIGNALS asig
                JOIN RISK_SIGNALS rs ON asig.signal_id = rs.signal_id
                WHERE asig.assessment_id = ?
                ORDER BY asig.points_awarded DESC;
                """,
                (assessment_id,)
            )
            signal_rows = cursor.fetchall()
            signals = [
                {
                    "signal_name": s["signal_name"] if isinstance(s, sqlite3.Row) else s[0],
                    "category": s["category"] if isinstance(s, sqlite3.Row) else s[1],
                    "description": s["description"] if isinstance(s, sqlite3.Row) else s[2],
                    "points_awarded": s["points_awarded"] if isinstance(s, sqlite3.Row) else s[3],
                }
                for s in signal_rows
            ]

            history_list.append({
                "incident_id": row_dict["incident_id"],
                "assessment_id": row_dict["assessment_id"],
                "created_at": str(row_dict["incident_time"]),
                "content_type": row_dict["content_type"],
                "risk_score": row_dict["risk_score"],
                "risk_level": row_dict["risk_level"],
                "engine_version": row_dict["engine_version"],
                "recommendation": row_dict["recommendation"],
                "signal_count": row_dict["signal_count"],
                "signals": signals
            })

        return history_list
    finally:
        conn.close()


def get_analytics(user_id: Optional[int] = None, db_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Computes system aggregate metrics.
    If user_id is supplied, computes personal metrics for that user.
    Otherwise computes global platform metrics.
    """
    conn = get_db_connection(db_path)
    is_cloud = is_azure_connection(conn)
    try:
        cursor = conn.cursor()
        pagination_clause = "OFFSET 0 ROWS FETCH NEXT 5 ROWS ONLY" if is_cloud else "LIMIT 5"

        if user_id is not None:
            cursor.execute(
                """
                SELECT COUNT(*) AS total 
                FROM RISK_ASSESSMENTS ra
                JOIN INCIDENTS i ON ra.incident_id = i.incident_id
                WHERE i.user_id = ?;
                """,
                (user_id,)
            )
            total_analyses = cursor.fetchone()[0]

            cursor.execute(
                """
                SELECT ra.risk_level, COUNT(*) AS count
                FROM RISK_ASSESSMENTS ra
                JOIN INCIDENTS i ON ra.incident_id = i.incident_id
                WHERE i.user_id = ?
                GROUP BY ra.risk_level;
                """,
                (user_id,)
            )
            level_rows = cursor.fetchall()

            cursor.execute(
                """
                SELECT COALESCE(ROUND(AVG(CAST(ra.risk_score AS FLOAT)), 1), 0.0) AS avg_score 
                FROM RISK_ASSESSMENTS ra
                JOIN INCIDENTS i ON ra.incident_id = i.incident_id
                WHERE i.user_id = ?;
                """,
                (user_id,)
            )
            avg_score = float(cursor.fetchone()[0] or 0.0)

            cursor.execute(
                f"""
                SELECT 
                    rs.signal_name,
                    rs.category,
                    rs.description,
                    COUNT(asig.assessment_id) AS frequency
                FROM RISK_SIGNALS rs
                JOIN ASSESSMENT_SIGNALS asig ON rs.signal_id = asig.signal_id
                JOIN RISK_ASSESSMENTS ra ON asig.assessment_id = ra.assessment_id
                JOIN INCIDENTS i ON ra.incident_id = i.incident_id
                WHERE i.user_id = ?
                GROUP BY rs.signal_id, rs.signal_name, rs.category, rs.description
                ORDER BY frequency DESC, rs.signal_name ASC
                {pagination_clause};
                """,
                (user_id,)
            )
            top_signals_rows = cursor.fetchall()
        else:
            # Global platform stats
            cursor.execute("SELECT COUNT(*) AS total FROM RISK_ASSESSMENTS;")
            total_analyses = cursor.fetchone()[0]

            cursor.execute("SELECT risk_level, COUNT(*) AS count FROM RISK_ASSESSMENTS GROUP BY risk_level;")
            level_rows = cursor.fetchall()

            cursor.execute("SELECT COALESCE(ROUND(AVG(CAST(risk_score AS FLOAT)), 1), 0.0) AS avg_score FROM RISK_ASSESSMENTS;")
            avg_score = float(cursor.fetchone()[0] or 0.0)

            cursor.execute(
                f"""
                SELECT 
                    rs.signal_name,
                    rs.category,
                    rs.description,
                    COUNT(asig.assessment_id) AS frequency
                FROM RISK_SIGNALS rs
                JOIN ASSESSMENT_SIGNALS asig ON rs.signal_id = asig.signal_id
                GROUP BY rs.signal_id, rs.signal_name, rs.category, rs.description
                ORDER BY frequency DESC, rs.signal_name ASC
                {pagination_clause};
                """
            )
            top_signals_rows = cursor.fetchall()

        counts_by_level = {
            "Lower detected risk": 0,
            "Suspicious": 0,
            "High risk": 0
        }
        for row in level_rows:
            lvl_name = row[0]
            lvl_cnt = row[1]
            if lvl_name in counts_by_level:
                counts_by_level[lvl_name] = lvl_cnt

        top_signals = [
            {
                "signal_name": r[0],
                "category": r[1],
                "description": r[2],
                "frequency": r[3]
            }
            for r in top_signals_rows
        ]

        return {
            "total_analyses": total_analyses,
            "high_risk_count": counts_by_level["High risk"],
            "suspicious_count": counts_by_level["Suspicious"],
            "lower_risk_count": counts_by_level["Lower detected risk"],
            "average_score": avg_score,
            "top_signals": top_signals
        }
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Administrator Queries (Dual Dialect Supported)
# ---------------------------------------------------------------------------

def get_admin_users(limit: int = 50, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Returns user accounts for the admin dashboard.
    Security: Never exposes password_hash.
    """
    conn = get_db_connection(db_path)
    is_cloud = is_azure_connection(conn)
    try:
        cur = conn.cursor()
        pagination_clause = "OFFSET 0 ROWS FETCH NEXT ? ROWS ONLY" if is_cloud else "LIMIT ?"
        cur.execute(
            f"""
            SELECT u.user_id, u.display_name, u.email, r.role_name,
                   u.account_status, u.created_at,
                   COUNT(i.incident_id) AS incident_count
            FROM USERS u
            JOIN ROLES r ON u.role_id = r.role_id
            LEFT JOIN INCIDENTS i ON u.user_id = i.user_id
            GROUP BY u.user_id, u.display_name, u.email, r.role_name, u.account_status, u.created_at
            ORDER BY u.user_id DESC
            {pagination_clause};
            """,
            (limit,)
        )
        return [row_to_dict(cur, row) for row in cur.fetchall()]
    finally:
        conn.close()


def get_admin_audit_logs(limit: int = 50, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Returns audit events for administrative security review."""
    conn = get_db_connection(db_path)
    is_cloud = is_azure_connection(conn)
    try:
        cur = conn.cursor()
        pagination_clause = "OFFSET 0 ROWS FETCH NEXT ? ROWS ONLY" if is_cloud else "LIMIT ?"
        cur.execute(
            f"""
            SELECT a.audit_id, a.user_id, a.event_type, a.event_status, a.details, a.created_at,
                   COALESCE(u.email, 'Anonymous/System') AS user_identifier
            FROM AUDIT_LOGS a
            LEFT JOIN USERS u ON a.user_id = u.user_id
            ORDER BY a.audit_id DESC
            {pagination_clause};
            """,
            (limit,)
        )
        return [row_to_dict(cur, row) for row in cur.fetchall()]
    finally:
        conn.close()


def get_admin_overview(db_path: Optional[str] = None) -> Dict[str, Any]:
    """Computes system-level overview counts for the admin dashboard."""
    conn = get_db_connection(db_path)
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) AS total_users FROM USERS WHERE user_id != 1;")
        total_registered_users = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) AS total_incidents FROM INCIDENTS;")
        total_incidents = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) AS total_audits FROM AUDIT_LOGS;")
        total_audits = cur.fetchone()[0]

        analytics = get_analytics(user_id=None, db_path=db_path)

        return {
            "total_registered_users": total_registered_users,
            "total_incidents": total_incidents,
            "total_audits": total_audits,
            "analytics": analytics
        }
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Exported Reports Operations (Phase 4, Task 3: Azure Blob Storage)
# ---------------------------------------------------------------------------

def create_exported_report(
    user_id: int,
    assessment_id: int,
    blob_name: str,
    file_type: str = "json",
    file_size: int = 0,
    storage_status: str = "LOCAL",
    db_path: Optional[str] = None
) -> int:
    """
    Inserts a report tracking record into EXPORTED_REPORTS.
    Compatible with both SQLite and Azure SQL dialects.
    """
    conn = get_db_connection(db_path)
    is_cloud = is_azure_connection(conn)
    try:
        cur = conn.cursor()
        if is_cloud:
            cur.execute(
                """
                INSERT INTO EXPORTED_REPORTS (user_id, assessment_id, blob_name, file_type, file_size, storage_status)
                OUTPUT INSERTED.report_id
                VALUES (?, ?, ?, ?, ?, ?);
                """,
                (user_id, assessment_id, blob_name.strip(), file_type.strip().lower(), file_size, storage_status)
            )
            report_id = cur.fetchone()[0]
        else:
            cur.execute(
                """
                INSERT INTO EXPORTED_REPORTS (user_id, assessment_id, blob_name, file_type, file_size, storage_status)
                VALUES (?, ?, ?, ?, ?, ?);
                """,
                (user_id, assessment_id, blob_name.strip(), file_type.strip().lower(), file_size, storage_status)
            )
            report_id = cur.lastrowid

        conn.commit()
        logger.info("Exported report recorded: ID #%d (User #%d, Assessment #%d, Status: %s)",
                    report_id, user_id, assessment_id, storage_status)
        return report_id
    except Exception as exc:
        conn.rollback()
        logger.error("Failed to insert exported report: %s", mask_credentials(str(exc)))
        raise exc
    finally:
        conn.close()


def get_exported_report_by_id(report_id: int, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Retrieves metadata of an exported report by its primary key ID."""
    conn = get_db_connection(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT report_id, user_id, assessment_id, blob_name, file_type, file_size, storage_status, created_at
            FROM EXPORTED_REPORTS
            WHERE report_id = ?;
            """,
            (report_id,)
        )
        row = cur.fetchone()
        return row_to_dict(cur, row)
    finally:
        conn.close()


def get_exported_reports_by_user(user_id: int, limit: int = 20, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieves all exported report metadata for a specific authenticated user."""
    conn = get_db_connection(db_path)
    is_cloud = is_azure_connection(conn)
    try:
        cur = conn.cursor()
        pagination_clause = "OFFSET 0 ROWS FETCH NEXT ? ROWS ONLY" if is_cloud else "LIMIT ?"
        cur.execute(
            f"""
            SELECT report_id, user_id, assessment_id, blob_name, file_type, file_size, storage_status, created_at
            FROM EXPORTED_REPORTS
            WHERE user_id = ?
            ORDER BY report_id DESC
            {pagination_clause};
            """,
            (user_id, limit)
        )
        return [row_to_dict(cur, row) for row in cur.fetchall()]
    finally:
        conn.close()


def update_report_storage_status(report_id: int, storage_status: str, db_path: Optional[str] = None) -> bool:
    """Updates the cloud/local storage status of an existing report."""
    conn = get_db_connection(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE EXPORTED_REPORTS
            SET storage_status = ?
            WHERE report_id = ?;
            """,
            (storage_status, report_id)
        )
        conn.commit()
        return cur.rowcount > 0
    except Exception as exc:
        conn.rollback()
        logger.error("Failed to update report storage status: %s", mask_credentials(str(exc)))
        return False
    finally:
        conn.close()


def get_assessment_for_export(
    assessment_id: int,
    user_id: Optional[int] = None,
    db_path: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """
    Retrieves full assessment metrics and associated detected signals for building an export report.
    Enforces authorization: if user_id is provided, only permits fetching if the user owns the assessment.
    """
    conn = get_db_connection(db_path)
    try:
        cur = conn.cursor()
        if user_id is not None:
            cur.execute(
                """
                SELECT 
                    ra.assessment_id, ra.incident_id, ra.risk_score, ra.risk_level,
                    ra.engine_version, ra.recommendation, ra.created_at AS assessment_time,
                    i.user_id, i.content_type, i.content_fingerprint, i.created_at AS incident_time
                FROM RISK_ASSESSMENTS ra
                JOIN INCIDENTS i ON ra.incident_id = i.incident_id
                WHERE ra.assessment_id = ? AND i.user_id = ?;
                """,
                (assessment_id, user_id)
            )
        else:
            cur.execute(
                """
                SELECT 
                    ra.assessment_id, ra.incident_id, ra.risk_score, ra.risk_level,
                    ra.engine_version, ra.recommendation, ra.created_at AS assessment_time,
                    i.user_id, i.content_type, i.content_fingerprint, i.created_at AS incident_time
                FROM RISK_ASSESSMENTS ra
                JOIN INCIDENTS i ON ra.incident_id = i.incident_id
                WHERE ra.assessment_id = ?;
                """,
                (assessment_id,)
            )

        row = cur.fetchone()
        if not row:
            return None

        assessment = row_to_dict(cur, row)

        # Retrieve linked signals
        cur.execute(
            """
            SELECT rs.signal_name, rs.category, rs.description, asig.points_awarded
            FROM ASSESSMENT_SIGNALS asig
            JOIN RISK_SIGNALS rs ON asig.signal_id = rs.signal_id
            WHERE asig.assessment_id = ?
            ORDER BY asig.points_awarded DESC;
            """,
            (assessment_id,)
        )
        signal_rows = cur.fetchall()
        signals = [
            {
                "signal_name": s["signal_name"] if hasattr(s, "__getitem__") and not isinstance(s, tuple) else s[0],
                "category": s["category"] if hasattr(s, "__getitem__") and not isinstance(s, tuple) else s[1],
                "description": s["description"] if hasattr(s, "__getitem__") and not isinstance(s, tuple) else s[2],
                "points_awarded": s["points_awarded"] if hasattr(s, "__getitem__") and not isinstance(s, tuple) else s[3],
            }
            for s in signal_rows
        ]

        assessment["signals"] = signals
        return assessment
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Power BI Analytics Layer Queries & Data Extraction (Phase 4, Task 4)
# ---------------------------------------------------------------------------

def get_analytics_overview(db_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Returns platform-wide KPI summary metrics from v_analytics_overview view.
    Handles empty database safely with standard zero values.
    """
    conn = get_db_connection(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT 
                total_assessments,
                total_low_risk,
                total_medium_risk,
                total_high_risk,
                avg_risk_score,
                pct_low_risk,
                pct_medium_risk,
                pct_high_risk,
                total_signals_detected
            FROM v_analytics_overview;
            """
        )
        row = cur.fetchone()
        if not row:
            return {
                "total_assessments": 0,
                "total_low_risk": 0,
                "total_medium_risk": 0,
                "total_high_risk": 0,
                "avg_risk_score": 0.0,
                "pct_low_risk": 0.0,
                "pct_medium_risk": 0.0,
                "pct_high_risk": 0.0,
                "total_signals_detected": 0,
            }

        data = row_to_dict(cur, row)
        return {
            "total_assessments": int(data.get("total_assessments") or 0),
            "total_low_risk": int(data.get("total_low_risk") or 0),
            "total_medium_risk": int(data.get("total_medium_risk") or 0),
            "total_high_risk": int(data.get("total_high_risk") or 0),
            "avg_risk_score": float(data.get("avg_risk_score") or 0.0),
            "pct_low_risk": float(data.get("pct_low_risk") or 0.0),
            "pct_medium_risk": float(data.get("pct_medium_risk") or 0.0),
            "pct_high_risk": float(data.get("pct_high_risk") or 0.0),
            "total_signals_detected": int(data.get("total_signals_detected") or 0),
        }
    finally:
        conn.close()


def get_risk_level_distribution(db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Returns risk classification breakdown from v_risk_level_distribution view.
    Ensures standard categories are present even when counts are zero.
    """
    conn = get_db_connection(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT risk_level, assessment_count, avg_score, percentage
            FROM v_risk_level_distribution;
            """
        )
        rows = cur.fetchall()

        found_map: Dict[str, Dict[str, Any]] = {}
        for r in rows:
            d = row_to_dict(cur, r)
            lvl = d["risk_level"]
            found_map[lvl] = {
                "risk_level": lvl,
                "assessment_count": int(d.get("assessment_count") or 0),
                "avg_score": float(d.get("avg_score") or 0.0),
                "percentage": float(d.get("percentage") or 0.0),
            }

        # Standard canonical categories in descending risk order
        categories = ["High risk", "Suspicious", "Lower detected risk"]
        result = []
        for cat in categories:
            if cat in found_map:
                result.append(found_map[cat])
            else:
                result.append({
                    "risk_level": cat,
                    "assessment_count": 0,
                    "avg_score": 0.0,
                    "percentage": 0.0,
                })
        return result
    finally:
        conn.close()


def get_risk_signal_frequency(db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Returns detected frequency and prevalence for all catalog risk signals.
    """
    conn = get_db_connection(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT signal_id, signal_name, category, description, detection_count, prevalence_pct
            FROM v_risk_signal_frequency
            ORDER BY detection_count DESC, signal_name ASC;
            """
        )
        rows = cur.fetchall()
        return [
            {
                "signal_id": int(d["signal_id"]),
                "signal_name": str(d["signal_name"]),
                "category": str(d["category"]),
                "description": str(d["description"]),
                "detection_count": int(d.get("detection_count") or 0),
                "prevalence_pct": float(d.get("prevalence_pct") or 0.0),
            }
            for d in [row_to_dict(cur, r) for r in rows]
        ]
    finally:
        conn.close()


def get_assessment_trends(interval: str = "daily", db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Returns time-based assessment counts, risk breakdown, and average risk score.
    Supports interval: 'daily', 'weekly', 'monthly'.
    """
    conn = get_db_connection(db_path)
    is_cloud = is_azure_connection(conn)
    clean_interval = interval.lower().strip()
    try:
        cur = conn.cursor()
        if clean_interval == "weekly":
            period_expr = (
                "CONVERT(VARCHAR(4), DATEPART(year, ra.created_at)) + '-W' + RIGHT('0' + CONVERT(VARCHAR(2), DATEPART(iso_week, ra.created_at)), 2)"
                if is_cloud
                else "STRFTIME('%Y-W%W', ra.created_at)"
            )
        elif clean_interval == "monthly":
            period_expr = (
                "CONVERT(VARCHAR(7), ra.created_at, 120)"
                if is_cloud
                else "STRFTIME('%Y-%m', ra.created_at)"
            )
        else:
            # Default: daily
            if not is_cloud:
                cur.execute(
                    """
                    SELECT assessment_date AS period, total_assessments, low_risk_count,
                           medium_risk_count, high_risk_count, avg_risk_score
                    FROM v_assessment_trends
                    ORDER BY assessment_date ASC;
                    """
                )
                rows = cur.fetchall()
                return [
                    {
                        "period": str(d["period"]),
                        "total_assessments": int(d.get("total_assessments") or 0),
                        "low_risk_count": int(d.get("low_risk_count") or 0),
                        "medium_risk_count": int(d.get("medium_risk_count") or 0),
                        "high_risk_count": int(d.get("high_risk_count") or 0),
                        "avg_risk_score": float(d.get("avg_risk_score") or 0.0),
                    }
                    for d in [row_to_dict(cur, r) for r in rows]
                ]
            period_expr = "CONVERT(VARCHAR(10), ra.created_at, 120)"

        query = f"""
            SELECT
                {period_expr} AS period,
                COUNT(ra.assessment_id) AS total_assessments,
                COALESCE(SUM(CASE WHEN ra.risk_level = 'Lower detected risk' THEN 1 ELSE 0 END), 0) AS low_risk_count,
                COALESCE(SUM(CASE WHEN ra.risk_level = 'Suspicious' THEN 1 ELSE 0 END), 0) AS medium_risk_count,
                COALESCE(SUM(CASE WHEN ra.risk_level = 'High risk' THEN 1 ELSE 0 END), 0) AS high_risk_count,
                COALESCE(ROUND(AVG(CAST(ra.risk_score AS FLOAT)), 2), 0.0) AS avg_risk_score
            FROM RISK_ASSESSMENTS ra
            GROUP BY {period_expr}
            ORDER BY period ASC;
        """
        cur.execute(query)
        rows = cur.fetchall()
        return [
            {
                "period": str(d["period"]),
                "total_assessments": int(d.get("total_assessments") or 0),
                "low_risk_count": int(d.get("low_risk_count") or 0),
                "medium_risk_count": int(d.get("medium_risk_count") or 0),
                "high_risk_count": int(d.get("high_risk_count") or 0),
                "avg_risk_score": float(d.get("avg_risk_score") or 0.0),
            }
            for d in [row_to_dict(cur, r) for r in rows]
        ]
    finally:
        conn.close()


def get_anonymized_assessments_for_export(db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Extracts completely anonymized assessment records for Power BI and CSV export.
    Strictly excludes: user_id, email, display_name, passwords, raw text, and full URLs.
    Includes only structural risk intelligence attributes.
    """
    conn = get_db_connection(db_path)
    try:
        cur = conn.cursor()
        # 1. Fetch core assessment attributes
        cur.execute(
            """
            SELECT 
                ra.assessment_id,
                ra.created_at AS assessment_date,
                i.content_type AS input_type,
                ra.risk_score,
                ra.risk_level AS risk_classification,
                ra.engine_version,
                ra.recommendation,
                i.content_fingerprint
            FROM RISK_ASSESSMENTS ra
            JOIN INCIDENTS i ON ra.incident_id = i.incident_id
            ORDER BY ra.assessment_id ASC;
            """
        )
        asm_rows = cur.fetchall()
        assessments = [row_to_dict(cur, r) for r in asm_rows]

        # 2. Fetch all linked signals for mapping
        cur.execute(
            """
            SELECT 
                asig.assessment_id,
                rs.signal_name,
                rs.category
            FROM ASSESSMENT_SIGNALS asig
            JOIN RISK_SIGNALS rs ON asig.signal_id = rs.signal_id
            ORDER BY asig.assessment_id ASC, rs.signal_name ASC;
            """
        )
        sig_rows = cur.fetchall()

        signals_by_asm: Dict[int, List[Dict[str, str]]] = {}
        for r in sig_rows:
            d = row_to_dict(cur, r)
            asm_id = int(d["assessment_id"])
            if asm_id not in signals_by_asm:
                signals_by_asm[asm_id] = []
            signals_by_asm[asm_id].append({
                "signal_name": str(d["signal_name"]),
                "category": str(d["category"]),
            })

        # 3. Assemble clean tabular records
        export_records = []
        for a in assessments:
            asm_id = int(a["assessment_id"])
            linked_signals = signals_by_asm.get(asm_id, [])
            sig_names = ";".join([s["signal_name"] for s in linked_signals])
            sig_categories = ";".join(sorted(list({s["category"] for s in linked_signals})))

            export_records.append({
                "Assessment_ID": asm_id,
                "Assessment_Date": str(a["assessment_date"]),
                "Input_Type": str(a.get("input_type") or "message"),
                "Risk_Score": int(a["risk_score"]),
                "Risk_Classification": str(a["risk_classification"]),
                "Detected_Signals_Count": len(linked_signals),
                "Detected_Signal_Names": sig_names if sig_names else "none",
                "Detected_Signal_Categories": sig_categories if sig_categories else "none",
                "Recommendation": str(a.get("recommendation") or ""),
                "Engine_Version": str(a.get("engine_version") or "3.0.0"),
                "Content_Fingerprint_SHA256": str(a.get("content_fingerprint") or ""),
            })

        return export_records
    finally:
        conn.close()

