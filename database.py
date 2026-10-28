"""
TRUSTMESH Database Module (Phase 2)
Handles SQLite connection management, schema initialization,
transactional writes, history retrieval, and analytics aggregations.
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
    # CRITICAL: Enforce relational foreign key constraints in SQLite
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(db_path: Optional[str] = None, schema_file: Optional[str] = None) -> None:
    """
    Initializes the SQLite database by executing schema.sql.
    Creates all tables, constraints, views, indexes, triggers, and seed reference data.
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


def generate_content_fingerprint(text: str) -> str:
    """
    Generates a cryptographic SHA-256 fingerprint of the normalized text.
    
    Privacy Note:
    The fingerprint allows deduplication and audit trail correlation without
    storing the actual submitted message or URL in plain text.
    It is a one-way hash, though short or common phrases could theoretically be
    reverse-tested via dictionary attacks; hence it is treated as pseudonymous metadata,
    never as complete anonymization.
    """
    normalized = text.strip().lower()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


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
    Saves an analysis event into the database inside a single atomic transaction:
    1. Inserts record into INCIDENTS table (no raw user text is saved).
    2. Inserts record into RISK_ASSESSMENTS table (activates SQLite audit trigger).
    3. Resolves signal IDs from RISK_SIGNALS catalog and inserts rows into ASSESSMENT_SIGNALS.
    4. Automatically commits on success, or rolls back entirely if any error occurs.

    Returns:
        Tuple of (incident_id, assessment_id)
    """
    conn = get_db_connection(db_path)
    try:
        with conn:  # Context manager guarantees atomic transaction (commit or rollback)
            cursor = conn.cursor()

            # 1. Insert Incident (Safe metadata only)
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

            logger.info("Transaction committed successfully for Incident #%d", incident_id)
            return incident_id, assessment_id
    except Exception as exc:
        logger.error("Transaction failed during save_analysis_transaction: %s", str(exc))
        raise exc
    finally:
        conn.close()


def get_history(limit: int = 20, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Retrieves the most recent safe analysis history records.
    Uses JOINs across INCIDENTS, RISK_ASSESSMENTS, and ASSESSMENT_SIGNALS.
    Does NOT return any raw user content.
    """
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        
        # Query the top incidents using the view v_incident_summary
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
            
            # Fetch associated signal details for each assessment
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


def get_analytics(db_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Computes system aggregate metrics using SQL COUNT(), AVG(), and GROUP BY:
    - Total analyses performed
    - Breakdown by risk level category
    - Overall average risk score
    - Top 5 most frequently detected warning signals
    """
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()

        # 1. Total Analyses
        cursor.execute("SELECT COUNT(*) AS total FROM RISK_ASSESSMENTS;")
        total_analyses = cursor.fetchone()["total"]

        # 2. Risk Level Counts
        cursor.execute(
            """
            SELECT 
                risk_level, 
                COUNT(*) AS count
            FROM RISK_ASSESSMENTS
            GROUP BY risk_level;
            """
        )
        level_rows = cursor.fetchall()
        counts_by_level = {
            "Lower detected risk": 0,
            "Suspicious": 0,
            "High risk": 0
        }
        for row in level_rows:
            counts_by_level[row["risk_level"]] = row["count"]

        # 3. Average Risk Score
        cursor.execute(
            "SELECT COALESCE(ROUND(AVG(risk_score), 1), 0.0) AS avg_score FROM RISK_ASSESSMENTS;"
        )
        avg_score = float(cursor.fetchone()["avg_score"])

        # 4. Top Detected Warning Signals
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
