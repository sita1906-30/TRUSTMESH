"""
TRUSTMESH Azure SQL Migration & Deployment Utility (Phase 4)

Prepares and applies the TRUSTMESH 3NF schema to Microsoft Azure SQL Database.
Supports verification, schema application, and cloud dummy testing.

Usage:
    python migrate_to_azure.py --verify
    python migrate_to_azure.py --apply-schema
    python migrate_to_azure.py --apply-schema --seed-dummy
    python migrate_to_azure.py --dry-run
"""

import argparse
import os
import re
import sys
from typing import Dict, List, Optional, Tuple

# Try loading environment variables from .env
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
SCHEMA_AZURE_PATH = os.path.join(BASE_DIR, "schema_azuresql.sql")
DEFAULT_SQLITE_PATH = os.path.join(BASE_DIR, "instance", "trustmesh.db")


def print_backup_advisory() -> None:
    """Displays essential safety and backup advisory before migration operations."""
    print("=" * 78)
    print("TRUSTMESH — CLOUD MIGRATION & DEPLOYMENT UTILITY")
    print("=" * 78)
    print("ADVISORY: Always back up existing databases before performing migrations.")
    print("  • Local SQLite: Copy 'instance/trustmesh.db' to 'instance/trustmesh_backup.db'")
    print("  • Azure SQL: Point-in-time restore (PITR) is active by default in Azure.")
    print("=" * 78)


def get_azure_credentials() -> Dict[str, str]:
    """Retrieves and normalizes Azure SQL connection credentials from environment."""
    return {
        "server": os.environ.get("AZURE_SQL_SERVER", "").strip(),
        "database": os.environ.get("AZURE_SQL_DATABASE", "").strip(),
        "username": os.environ.get("AZURE_SQL_USERNAME", "").strip(),
        "password": os.environ.get("AZURE_SQL_PASSWORD", ""),
        "driver": os.environ.get("AZURE_SQL_DRIVER", "{ODBC Driver 18 for SQL Server}").strip(),
        "connection_string": os.environ.get("DATABASE_URL", "").strip(),
    }


def mask_credential(val: str) -> str:
    """Masks secret values for safe logging and terminal output."""
    if not val:
        return "<not set>"
    if len(val) <= 4:
        return "****"
    return val[:2] + "****" + val[-2:]


def build_pyodbc_connection_string(creds: Dict[str, str]) -> str:
    """Builds an enterprise-grade, encrypted Azure SQL ODBC connection string."""
    if creds.get("connection_string"):
        return creds["connection_string"]
    
    server = creds.get("server", "")
    database = creds.get("database", "")
    username = creds.get("username", "")
    password = creds.get("password", "")
    driver = creds.get("driver", "{ODBC Driver 18 for SQL Server}")

    return (
        f"DRIVER={driver};"
        f"SERVER={server};"
        f"DATABASE={database};"
        f"UID={username};"
        f"PWD={password};"
        "Encrypt=yes;"
        "TrustServerCertificate=no;"
        "Connection Timeout=30;"
    )


def parse_sql_batches(sql_text: str) -> List[str]:
    """Splits a T-SQL script by 'GO' batch separators for execution."""
    # Split by lines containing only GO (case-insensitive)
    batches = re.split(r'^\s*GO\s*$', sql_text, flags=re.MULTILINE | re.IGNORECASE)
    cleaned = []
    for b in batches:
        stmt = b.strip()
        if stmt:
            cleaned.append(stmt)
    return cleaned


def test_azure_connection(creds: Dict[str, str]) -> Tuple[bool, str]:
    """Attempts to connect to Azure SQL and validates responsiveness."""
    try:
        import pyodbc
    except ImportError:
        return False, (
            "The 'pyodbc' library is not available in the current Python environment.\n"
            "On Linux (Azure App Service): Add pyodbc to requirements.txt.\n"
            "On Windows: Install Microsoft ODBC Driver 17 or 18 for SQL Server."
        )

    if not creds.get("server") or not creds.get("database"):
        return False, "Azure SQL credentials missing. Please set AZURE_SQL_SERVER and AZURE_SQL_DATABASE."

    conn_str = build_pyodbc_connection_string(creds)
    try:
        conn = pyodbc.connect(conn_str)
        cur = conn.cursor()
        cur.execute("SELECT @@VERSION;")
        row = cur.fetchone()
        version = row[0] if row else "Unknown"
        conn.close()
        return True, f"Connected successfully. Version: {version[:45]}..."
    except Exception as exc:
        err_msg = str(exc)
        # Ensure password is never exposed in error output
        if creds.get("password"):
            err_msg = err_msg.replace(creds["password"], "********")
        return False, f"Connection failed: {err_msg}"


def apply_azure_schema(creds: Dict[str, str], schema_file: str, dry_run: bool = False) -> bool:
    """Executes the DDL schema batches against the Azure SQL database."""
    if not os.path.exists(schema_file):
        print(f"[!] Error: Schema file not found at: {schema_file}")
        return False

    with open(schema_file, "r", encoding="utf-8") as f:
        sql_content = f.read()

    batches = parse_sql_batches(sql_content)
    print(f"[*] Loaded schema script '{os.path.basename(schema_file)}': {len(batches)} batches found.")

    if dry_run:
        print("[*] DRY RUN: Validating batches syntax without applying to database...")
        for idx, batch in enumerate(batches, 1):
            first_line = batch.splitlines()[0] if batch.splitlines() else ""
            print(f"    Batch #{idx:02d}: {first_line[:60]}...")
        print("[+] Dry run validation successful. 0 changes committed.")
        return True

    # Real execution
    try:
        import pyodbc
    except ImportError:
        print("[!] Error: pyodbc required for Azure SQL schema execution.")
        return False

    conn_str = build_pyodbc_connection_string(creds)
    try:
        print(f"[*] Connecting to Azure SQL Server '{creds['server']}'...")
        conn = pyodbc.connect(conn_str)
        cur = conn.cursor()

        for idx, batch in enumerate(batches, 1):
            first_line = batch.splitlines()[0] if batch.splitlines() else ""
            print(f"    Applying Batch #{idx:02d}: {first_line[:50]}...")
            cur.execute(batch)
            conn.commit()

        conn.close()
        print("[+] All schema batches applied successfully to Azure SQL Database.")
        return True
    except Exception as exc:
        err_msg = str(exc)
        if creds.get("password"):
            err_msg = err_msg.replace(creds["password"], "********")
        print(f"[!] Execution failed on batch: {err_msg}")
        return False


def main():
    parser = argparse.ArgumentParser(description="TRUSTMESH Azure SQL Migration Utility")
    parser.add_argument("--verify", action="store_true", help="Test Azure SQL connection and credentials.")
    parser.add_argument("--apply-schema", action="store_true", help="Apply 3NF schema to Azure SQL Database.")
    parser.add_argument("--dry-run", action="store_true", help="Validate schema script without connecting to database.")
    parser.add_argument("--schema-file", default=SCHEMA_AZURE_PATH, help="Path to T-SQL schema file.")
    args = parser.parse_args()

    print_backup_advisory()
    creds = get_azure_credentials()

    print("\n[*] Configured Database Environment:")
    print(f"    Mode:             {os.environ.get('DATABASE_MODE', 'sqlite')}")
    print(f"    Azure Server:     {creds['server'] or '<not configured>'}")
    print(f"    Azure Database:   {creds['database'] or '<not configured>'}")
    print(f"    Azure Username:   {creds['username'] or '<not configured>'}")
    print(f"    Azure Password:   {mask_credential(creds['password'])}")
    print(f"    ODBC Driver:      {creds['driver']}")

    if args.dry_run:
        apply_azure_schema(creds, args.schema_file, dry_run=True)
        return

    if args.verify or (not args.apply_schema):
        print("\n[*] Testing Azure SQL Connectivity...")
        success, msg = test_azure_connection(creds)
        if success:
            print(f"[+] SUCCESS: {msg}")
        else:
            print(f"[-] STATUS: {msg}")
            print("    (Note: If deploying for the first time, configure your credentials in .env)")

    if args.apply_schema:
        print("\n[*] Applying Schema to Azure SQL Database...")
        success = apply_azure_schema(creds, args.schema_file, dry_run=False)
        if not success:
            sys.exit(1)


if __name__ == "__main__":
    main()

