"""
TRUSTMESH Analytics & Export Service (Phase 4, Task 4)

Prepares, sanitizes, and exports anonymized assessment telemetry for Power BI Desktop
and internal administrative reporting. Strictly strips all PII (user identities, emails,
passwords, raw message text, and private query parameters).
"""

import csv
import io
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from database import (
    get_analytics_overview,
    get_anonymized_assessments_for_export,
    get_assessment_trends,
    get_risk_level_distribution,
    get_risk_signal_frequency,
)

logger = logging.getLogger("trustmesh.analytics")

# Canonical CSV Header Fields for Power BI Integration
CSV_EXPORT_FIELDS = [
    "Assessment_ID",
    "Assessment_Date",
    "Input_Type",
    "Risk_Score",
    "Risk_Classification",
    "Detected_Signals_Count",
    "Detected_Signal_Names",
    "Detected_Signal_Categories",
    "Recommendation",
    "Engine_Version",
    "Content_Fingerprint_SHA256",
]

# Sensitive patterns that must never appear in exports
EMAIL_REGEX = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
PASSWORD_HASH_REGEX = re.compile(r"(?:pbkdf2|scrypt|argon2|sha256\$|md5\$)", re.IGNORECASE)


def validate_anonymized_record(record: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Validates that a record conforms to privacy and anonymization standards.
    Returns (True, '') if safe, or (False, error_description) if sensitive data is detected.
    """
    # Check for forbidden sensitive keys
    forbidden_keys = {"user_id", "email", "password", "password_hash", "display_name", "session_id", "raw_message"}
    for k in record.keys():
        if k.lower() in forbidden_keys:
            return False, f"Forbidden sensitive key detected: {k}"

    # Check for email or hash leakage in string values
    for k, v in record.items():
        if isinstance(v, str):
            if k != "Content_Fingerprint_SHA256" and PASSWORD_HASH_REGEX.search(v):
                return False, f"Potential password hash pattern detected in column '{k}'"
            if EMAIL_REGEX.search(v):
                return False, f"Email pattern detected in column '{k}'"

    return True, ""


def generate_anonymized_csv(db_path: Optional[str] = None) -> Tuple[str, int]:
    """
    Extracts, validates, and serializes all assessment telemetry to a sanitized CSV string.
    Suitable for direct Power BI Desktop import or automated data pipelines.
    Returns (csv_string, total_records_count).
    """
    raw_records = get_anonymized_assessments_for_export(db_path=db_path)
    sanitized_records: List[Dict[str, Any]] = []

    for idx, rec in enumerate(raw_records, start=1):
        is_safe, err = validate_anonymized_record(rec)
        if not is_safe:
            logger.error("Data privacy validation failed on record #%d: %s", idx, err)
            continue
        sanitized_records.append(rec)

    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=CSV_EXPORT_FIELDS,
        quoting=csv.QUOTE_MINIMAL,
        lineterminator="\r\n",
    )
    writer.writeheader()

    for rec in sanitized_records:
        writer.writerow(rec)

    csv_data = output.getvalue()
    logger.info("Generated anonymized analytics CSV with %d records (%d bytes)", len(sanitized_records), len(csv_data))
    return csv_data, len(sanitized_records)


def get_analytics_dashboard_bundle(db_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Bundles all core analytics layers into a single structured response for dashboard visualization.
    """
    overview = get_analytics_overview(db_path=db_path)
    distribution = get_risk_level_distribution(db_path=db_path)
    signals = get_risk_signal_frequency(db_path=db_path)
    trends = get_assessment_trends(interval="daily", db_path=db_path)

    return {
        "overview": overview,
        "risk_distribution": distribution,
        "risk_signals": signals,
        "trends": trends,
    }

