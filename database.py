"""
TRUSTMESH Database Module (Phase 3)
Handles SQLite connection management, schema migrations, user authentication queries,
RBAC authorization lookups, transactional writes, and security audit logs.
"""

import hashlib
import logging
import os
import sqlite3
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("trustmesh.database")

# Default paths for database and schema
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DEFAULT_INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
DEFAULT_DB_PATH = os.path.join(DEFAULT_INSTANCE_DIR, "trustmesh.db")
SCHEMA_PATH = os.path.join(BASE_DIR, "schema.sql")


def get_db_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """
    Creates and returns a SQLite database connection with:
    1. Foreign keys explicitly enabled (PRAGMA foreign_keys = ON).
    2. Row factory set to sqlite3.Row for dictionary-like column access.
    """
    target_path = db_path or DEFAULT_DB_PATH
    
    # Ensure instance directory exists if using default or file path
    if target_path != ":memory:":
        os.makedirs(os.path.dirname(os.path.abspath(target_path)), exist_ok=True)
        
    conn = sqlite3.connect(target_path)
    conn.row_factory = sqlite3.Row
    # Enforce relational foreign key constraints in SQLite
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def migrate_db(db_path: Optional[str] = None) -> None:
    """
    Safely applies non-destructive Phase 3 schema migrations to an existing database.
    Ensures existing Phase 1 & Phase 2 records are preserved without data loss.
    """
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

        # 3. Create Phase 3 Performance & Security Indexes
        cur.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON USERS(email);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_users_role_id ON USERS(role_id);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_event ON AUDIT_LOGS(event_type, created_at DESC);")

        # 4. Ensure Roles Exist
        cur.execute("INSERT OR IGNORE INTO ROLES (role_id, role_name, description) VALUES (1, 'user', 'Standard user');")
        cur.execute("INSERT OR IGNORE INTO ROLES (role_id, role_name, description) VALUES (2, 'admin', 'Administrator');")

        # 5. Ensure Anonymous user exists for backward compatibility
        cur.execute("INSERT OR IGNORE INTO USERS (user_id, display_name, email, password_hash, role_id, account_status) VALUES (1, 'Anonymous Dev User', NULL, NULL, 1, 'ACTIVE');")

        conn.commit()
        logger.info("Database migration check completed successfully.")
    except Exception as exc:
        conn.rollback()
        logger.error("Database migration failed: %s", str(exc))
        raise exc
    finally:
        conn.close()


def init_db(db_path: Optional[str] = None, schema_file: Optional[str] = None) -> None:
    """
    Initializes the SQLite database from schema.sql and runs migrations.
    """
    target_path = db_path or DEFAULT_DB_PATH
    schema_path = schema_file or SCHEMA_PATH

    if not os.path.exists(schema_path):
        raise FileNotFoundError(f"Schema definition file not found at: {schema_path}")

    with open(schema_path, "r", encoding="utf-8") as f:
        schema_sql = f.read()

    conn = get_db_connection(target_path)
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

    # Run safe migration check in case table already existed
    migrate_db(target_path)


def generate_content_fingerprint(text: str) -> str:
    """
    Generates a cryptographic SHA-256 fingerprint of the normalized text.
    """
    normalized = text.strip().lower()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# User Authentication & RBAC Functions (Phase 3)
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
    Enforces unique email and non-empty display name.
    """
    conn = get_db_connection(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO USERS (display_name, email, password_hash, role_id, account_status)
            VALUES (?, ?, ?, ?, ?);
            """,
            (display_name.strip(), email.strip().lower(), password_hash, role_id, account_status)
        )
        user_id = cur.lastrowid
        conn.commit()
        logger.info("User created successfully: ID #%d, Email: %s", user_id, email.strip().lower())
        return user_id
    except sqlite3.IntegrityError as err:
        conn.rollback()
        if "UNIQUE constraint failed: USERS.email" in str(err) or "email" in str(err).lower():
            raise ValueError("An account with this email address already exists.")
        raise err
    except Exception as exc:
        conn.rollback()
        raise exc
    finally:
        conn.close()


def get_user_by_email(email: str, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Retrieves user record joined with role_name by email address (case-insensitive).
    """
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
        return dict(row) if row else None
    finally:
        conn.close()


def get_user_by_id(user_id: int, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Retrieves user record joined with role_name by user_id.
    """
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
        return dict(row) if row else None
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
    try:
        cur = conn.cursor()
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
        logger.error("Failed to write audit log: %s", str(exc))
        return -1
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Transactional Persistence & History (Phase 3 User-Scoped)
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
    """
    conn = get_db_connection(db_path)
    try:
        with conn:
            cursor = conn.cursor()

            # 1. Insert Incident (Safe metadata only, associated with authenticated user)
            cursor.execute(
                """
                INSERT INTO INCIDENTS (user_id, content_type, content_fingerprint, processing_status)
                VALUES (?, ?, ?, 'COMPLETED');
                """,
                (user_id, content_type, content_fingerprint)
            )
            incident_id = cursor.lastrowid

            # 2. Insert Risk Assessment
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
                        signal_id = row["signal_id"]
                        cursor.execute(
                            """
                            INSERT INTO ASSESSMENT_SIGNALS (assessment_id, signal_id, points_awarded)
                            VALUES (?, ?, ?);
                            """,
                            (assessment_id, signal_id, points)
                        )
                    else:
                        logger.warning("Unrecognized signal name in catalog: %s", signal_name)

            logger.info("Transaction committed successfully for Incident #%d (User #%d)", incident_id, user_id)
            return incident_id, assessment_id
    except Exception as exc:
        logger.error("Transaction failed during save_analysis_transaction: %s", str(exc))
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
    Phase 3: Strictly scopes records to the authenticated user_id.
    If user_id is provided, only that user's records are returned.
    Does NOT return any raw user content.
    """
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        
        if user_id is not None:
            cursor.execute(
                """
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
                LIMIT ?;
                """,
                (user_id, limit)
            )
        else:
            # Anonymous / Legacy Fallback
            cursor.execute(
                """
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
                LIMIT ?;
                """,
                (limit,)
            )
            
        rows = cursor.fetchall()

        history_list = []
        for row in rows:
            assessment_id = row["assessment_id"]
            
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
                    "signal_name": s["signal_name"],
                    "category": s["category"],
                    "description": s["description"],
                    "points_awarded": s["points_awarded"]
                }
                for s in signal_rows
            ]

            history_list.append({
                "incident_id": row["incident_id"],
                "created_at": row["incident_time"],
                "content_type": row["content_type"],
                "risk_score": row["risk_score"],
                "risk_level": row["risk_level"],
                "engine_version": row["engine_version"],
                "recommendation": row["recommendation"],
                "signal_count": row["signal_count"],
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
    try:
        cursor = conn.cursor()

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
            total_analyses = cursor.fetchone()["total"]

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
                SELECT COALESCE(ROUND(AVG(ra.risk_score), 1), 0.0) AS avg_score 
                FROM RISK_ASSESSMENTS ra
                JOIN INCIDENTS i ON ra.incident_id = i.incident_id
                WHERE i.user_id = ?;
                """,
                (user_id,)
            )
            avg_score = float(cursor.fetchone()["avg_score"])

            cursor.execute(
                """
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
                GROUP BY rs.signal_id
                ORDER BY frequency DESC, rs.signal_name ASC
                LIMIT 5;
                """,
                (user_id,)
            )
            top_signals_rows = cursor.fetchall()
        else:
            # Global platform stats
            cursor.execute("SELECT COUNT(*) AS total FROM RISK_ASSESSMENTS;")
            total_analyses = cursor.fetchone()["total"]

            cursor.execute("SELECT risk_level, COUNT(*) AS count FROM RISK_ASSESSMENTS GROUP BY risk_level;")
            level_rows = cursor.fetchall()

            cursor.execute("SELECT COALESCE(ROUND(AVG(risk_score), 1), 0.0) AS avg_score FROM RISK_ASSESSMENTS;")
            avg_score = float(cursor.fetchone()["avg_score"])

            cursor.execute(
                """
                SELECT 
                    rs.signal_name,
                    rs.category,
                    rs.description,
                    COUNT(asig.assessment_id) AS frequency
                FROM RISK_SIGNALS rs
                JOIN ASSESSMENT_SIGNALS asig ON rs.signal_id = asig.signal_id
                GROUP BY rs.signal_id
                ORDER BY frequency DESC, rs.signal_name ASC
                LIMIT 5;
                """
            )
            top_signals_rows = cursor.fetchall()

        counts_by_level = {
            "Lower detected risk": 0,
            "Suspicious": 0,
            "High risk": 0
        }
        for row in level_rows:
            counts_by_level[row["risk_level"]] = row["count"]

        top_signals = [
            {
                "signal_name": r["signal_name"],
                "category": r["category"],
                "description": r["description"],
                "frequency": r["frequency"]
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
# Administrator Queries (Phase 3 RBAC)
# ---------------------------------------------------------------------------

def get_admin_users(limit: int = 50, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Returns user accounts for the admin dashboard.
    Security: Never exposes password_hash.
    """
    conn = get_db_connection(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT u.user_id, u.display_name, u.email, r.role_name,
                   u.account_status, u.created_at,
                   COUNT(i.incident_id) AS incident_count
            FROM USERS u
            JOIN ROLES r ON u.role_id = r.role_id
            LEFT JOIN INCIDENTS i ON u.user_id = i.user_id
            GROUP BY u.user_id
            ORDER BY u.user_id DESC
            LIMIT ?;
            """,
            (limit,)
        )
        return [dict(row) for row in cur.fetchall()]
    finally:
        conn.close()


def get_admin_audit_logs(limit: int = 50, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Returns audit events for administrative security review.
    """
    conn = get_db_connection(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT a.audit_id, a.user_id, a.event_type, a.event_status, a.details, a.created_at,
                   COALESCE(u.email, 'Anonymous/System') AS user_identifier
            FROM AUDIT_LOGS a
            LEFT JOIN USERS u ON a.user_id = u.user_id
            ORDER BY a.audit_id DESC
            LIMIT ?;
            """,
            (limit,)
        )
        return [dict(row) for row in cur.fetchall()]
    finally:
        conn.close()


def get_admin_overview(db_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Computes system-level overview counts for the admin dashboard.
    """
    conn = get_db_connection(db_path)
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) AS total_users FROM USERS WHERE user_id != 1;")
        total_registered_users = cur.fetchone()["total_users"]

        cur.execute("SELECT COUNT(*) AS total_incidents FROM INCIDENTS;")
        total_incidents = cur.fetchone()["total_incidents"]

        cur.execute("SELECT COUNT(*) AS total_audits FROM AUDIT_LOGS;")
        total_audits = cur.fetchone()["total_audits"]

        analytics = get_analytics(user_id=None, db_path=db_path)

        return {
            "total_registered_users": total_registered_users,
            "total_incidents": total_incidents,
            "total_audits": total_audits,
            "analytics": analytics
        }
    finally:
        conn.close()


def check_db_health(db_path: Optional[str] = None) -> bool:
    """
    Verifies that the database is accessible and responsive to standard queries.
    """
    try:
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT 1;")
        res = cursor.fetchone()
        conn.close()
        return res is not None and res[0] == 1
    except Exception as exc:
        logger.error("Database health check failed: %s", str(exc))
        return False
