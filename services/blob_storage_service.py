"""
TRUSTMESH Azure Blob Storage Service (Phase 4, Task 3)

Manages optional cloud report archiving and secure retrieval using Microsoft Azure Blob Storage.
Provides safe local fallbacks when cloud storage is unconfigured or unreachable.
Never exposes connection strings, access keys, or secret tokens.
"""

from datetime import datetime, timezone
import logging
import os
import re
from typing import Any, Dict, Optional, Tuple
import uuid

# Load environment configuration if python-dotenv is available
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

logger = logging.getLogger("trustmesh.storage")

# Constants & Constraints
MAX_REPORT_SIZE_BYTES = 500 * 1024  # 500 KB limit for security & memory protection
DEFAULT_CONTAINER_NAME = "trustmesh-reports"
SAFE_BLOB_NAME_REGEX = re.compile(r"^[a-zA-Z0-9_\-\.\/]+$")


def mask_storage_key(conn_str: str) -> str:
    """Masks AccountKey or SharedAccessSignature secrets in connection strings."""
    if not conn_str:
        return ""
    sanitized = re.sub(r'(AccountKey)=[^;]+', r'\1=********', conn_str, flags=re.IGNORECASE)
    sanitized = re.sub(r'(SharedAccessSignature)=[^;]+', r'\1=********', sanitized, flags=re.IGNORECASE)
    return sanitized


def get_storage_config() -> Dict[str, str]:
    """Retrieves normalized storage credentials from environment variables."""
    conn_str = os.environ.get("AZURE_STORAGE_CONNECTION_STRING", "").strip()
    acct_name = os.environ.get("AZURE_STORAGE_ACCOUNT_NAME", "").strip()
    container = os.environ.get("AZURE_STORAGE_CONTAINER_NAME", DEFAULT_CONTAINER_NAME).strip() or DEFAULT_CONTAINER_NAME

    return {
        "connection_string": conn_str,
        "account_name": acct_name,
        "container_name": container,
    }


def is_blob_storage_configured() -> bool:
    """Returns True if minimum required Azure Blob Storage credentials are provided."""
    cfg = get_storage_config()
    return bool(cfg["connection_string"] or cfg["account_name"])


def validate_blob_name(blob_name: str) -> Tuple[bool, str]:
    """
    Validates blob name to prevent path traversal, illegal characters, or excessive length.
    """
    if not blob_name or not isinstance(blob_name, str):
        return False, "Blob name cannot be empty."

    clean = blob_name.strip()
    if len(clean) > 255:
        return False, "Blob name exceeds maximum length of 255 characters."

    # Prevent path traversal attacks
    if ".." in clean or clean.startswith("/") or clean.startswith("\\"):
        return False, "Invalid blob path: Path traversal characters are forbidden."

    if not SAFE_BLOB_NAME_REGEX.match(clean):
        return False, "Blob name contains invalid characters. Use alphanumeric, hyphens, and slashes only."

    return True, ""


def generate_safe_blob_name(user_id: int, assessment_id: int, file_ext: str = "json") -> str:
    """
    Generates a deterministic, unique, partitioned blob path:
    Format: reports/user_{user_id}/trustmesh_report_asm_{assessment_id}_{YYYYMMDD_HHMMSS}_{uuid4}.json
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    unique_suffix = uuid.uuid4().hex[:8]
    ext = file_ext.lstrip(".")
    return f"reports/user_{user_id}/trustmesh_report_asm_{assessment_id}_{timestamp}_{unique_suffix}.{ext}"


def get_blob_service_client():
    """
    Initializes and returns an Azure BlobServiceClient.
    Gracefully handles SDK unavailability or configuration errors.
    """
    try:
        from azure.storage.blob import BlobServiceClient
    except ImportError:
        logger.warning("Azure Blob Storage SDK ('azure-storage-blob') is not installed in the current environment.")
        return None

    cfg = get_storage_config()
    conn_str = cfg["connection_string"]

    if conn_str:
        try:
            client = BlobServiceClient.from_connection_string(conn_str)
            return client
        except Exception as exc:
            logger.error("Failed to initialize BlobServiceClient: %s", mask_storage_key(str(exc)))
            return None
    elif cfg["account_name"]:
        # Account URL without secret key (e.g. for Managed Identity / Entra ID)
        account_url = f"https://{cfg['account_name']}.blob.core.windows.net"
        try:
            client = BlobServiceClient(account_url=account_url)
            return client
        except Exception as exc:
            logger.error("Failed to initialize BlobServiceClient with Account URL: %s", str(exc))
            return None

    return None


def check_blob_storage_health() -> Dict[str, Any]:
    """
    Inspects Azure Blob Storage connectivity.
    Accurately reports:
    - 'Azure Blob Storage connected' (verified)
    - 'Storage not configured (Local Fallback)' (unconfigured)
    - 'Storage unavailable' (configured but connection failed)
    """
    if not is_blob_storage_configured():
        return {
            "status": "not_configured",
            "is_configured": False,
            "indicator": "Storage not configured (Local Fallback)",
            "details": "Azure Blob Storage credentials not set in environment. Using local downloads.",
            "container_name": DEFAULT_CONTAINER_NAME,
        }

    client = get_blob_service_client()
    if client is None:
        return {
            "status": "unavailable",
            "is_configured": True,
            "indicator": "Storage unavailable",
            "details": "Azure Blob Storage SDK missing or client failed to initialize.",
            "container_name": DEFAULT_CONTAINER_NAME,
        }

    cfg = get_storage_config()
    container_name = cfg["container_name"]

    try:
        container_client = client.get_container_client(container_name)
        # Check existence or ping container metadata
        container_client.get_container_properties()
        return {
            "status": "connected",
            "is_configured": True,
            "indicator": "Azure Blob Storage connected",
            "details": f"Container [{container_name}] verified and accessible.",
            "container_name": container_name,
        }
    except Exception as exc:
        sanitized_err = mask_storage_key(str(exc))
        logger.warning("Blob storage health check failed: %s", sanitized_err)
        return {
            "status": "unavailable",
            "is_configured": True,
            "indicator": "Storage unavailable",
            "details": f"Connection check failed: {sanitized_err}",
            "container_name": container_name,
        }


def upload_report(
    blob_name: str,
    data_bytes: bytes,
    content_type: str = "application/json"
) -> Tuple[bool, str]:
    """
    Uploads an assessment report to the private Azure Blob Storage container.
    Enforces file size and name validations.
    """
    # 1. Validate blob name
    is_valid_name, name_err = validate_blob_name(blob_name)
    if not is_valid_name:
        return False, name_err

    # 2. Validate file size
    if not data_bytes:
        return False, "Report data cannot be empty."

    if len(data_bytes) > MAX_REPORT_SIZE_BYTES:
        return False, f"Report size ({len(data_bytes)} bytes) exceeds maximum limit of {MAX_REPORT_SIZE_BYTES} bytes."

    # 3. Check configuration
    if not is_blob_storage_configured():
        return False, "Azure Blob Storage is not configured. Report will be saved locally."

    client = get_blob_service_client()
    if client is None:
        return False, "Azure Blob Storage client could not be initialized."

    cfg = get_storage_config()
    container_name = cfg["container_name"]

    try:
        container_client = client.get_container_client(container_name)

        # Create container if it does not already exist (private access by default)
        try:
            if not container_client.exists():
                container_client.create_container()
                logger.info("Created private Azure Blob Storage container: %s", container_name)
        except Exception as c_exc:
            logger.debug("Container existence check: %s", mask_storage_key(str(c_exc)))

        blob_client = container_client.get_blob_client(blob_name)

        try:
            from azure.storage.blob import ContentSettings
            settings = ContentSettings(content_type=content_type)
            blob_client.upload_blob(data_bytes, overwrite=True, content_settings=settings)
        except ImportError:
            # Fallback when running in environments with mock or non-native azure-storage-blob
            blob_client.upload_blob(data_bytes, overwrite=True)

        logger.info("Report uploaded successfully to Azure Blob Storage: %s (%d bytes)", blob_name, len(data_bytes))
        return True, "Report successfully saved to Azure Blob Storage."
    except Exception as exc:
        sanitized_err = mask_storage_key(str(exc))
        logger.error("Failed to upload report to Blob Storage: %s", sanitized_err)
        return False, f"Cloud upload failed: {sanitized_err}"


def download_report(blob_name: str) -> Tuple[Optional[bytes], str]:
    """
    Downloads report data from Azure Blob Storage.
    Validates blob name before querying.
    """
    is_valid_name, name_err = validate_blob_name(blob_name)
    if not is_valid_name:
        return None, name_err

    if not is_blob_storage_configured():
        return None, "Azure Blob Storage is not configured in this environment."

    client = get_blob_service_client()
    if client is None:
        return None, "Azure Blob Storage client is unavailable."

    cfg = get_storage_config()
    container_name = cfg["container_name"]

    try:
        container_client = client.get_container_client(container_name)
        blob_client = container_client.get_blob_client(blob_name)

        if not blob_client.exists():
            return None, "Requested report does not exist in Azure Blob Storage."

        download_stream = blob_client.download_blob()
        data_bytes = download_stream.readall()
        logger.info("Report downloaded successfully from Azure Blob Storage: %s (%d bytes)", blob_name, len(data_bytes))
        return data_bytes, "Success"
    except Exception as exc:
        sanitized_err = mask_storage_key(str(exc))
        logger.error("Failed to download blob '%s': %s", blob_name, sanitized_err)
        return None, f"Cloud retrieval failed: {sanitized_err}"


def blob_exists(blob_name: str) -> bool:
    """Checks whether a specific report exists in the storage container."""
    is_valid, _ = validate_blob_name(blob_name)
    if not is_valid or not is_blob_storage_configured():
        return False

    client = get_blob_service_client()
    if client is None:
        return False

    cfg = get_storage_config()
    try:
        container_client = client.get_container_client(cfg["container_name"])
        blob_client = container_client.get_blob_client(blob_name)
        return blob_client.exists()
    except Exception as exc:
        logger.warning("Blob existence check failed for '%s': %s", blob_name, mask_storage_key(str(exc)))
        return False
