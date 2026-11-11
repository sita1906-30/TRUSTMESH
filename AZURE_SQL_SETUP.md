# TRUSTMESH — Microsoft Azure SQL Database Setup & Migration Guide

**Academic Phase:** Phase 4: Cloud Integration & Dual-Mode Deployment  
**Target Audience:** 2nd-Year B.Tech Computer Science and Engineering (AI/ML) Students  
**Platform Version:** TRUSTMESH v3.1 (Dual Dialect: SQLite + Azure SQL)

---

## 1. Overview & Dual-Mode Architecture

TRUSTMESH is designed to run in two distinct database modes using the exact same application codebase:

```
                            +---------------------------------------+
                            |       TRUSTMESH Application Layer      |
                            |       (app.py / database.py v3.1)     |
                            +---------------------------------------+
                                                |
                 +------------------------------+------------------------------+
                 | (DATABASE_MODE=sqlite)                                      | (DATABASE_MODE=azure_sql)
                 v                                                             v
+----------------------------------+                         +----------------------------------+
|          LOCAL MODE              |                         |           CLOUD MODE             |
|   Embedded SQLite Database       |                         |  Microsoft Azure SQL Database    |
|   (instance/trustmesh.db)        |                         |  (Managed Cloud Relational DB)   |
|   Zero configuration, offline    |                         |  Encrypted TLS 1.2+, Multi-user  |
+----------------------------------+                         +----------------------------------+
```

* **Local Mode (Default):** Runs against a local SQLite file in `instance/trustmesh.db`. Requires no cloud account or Internet connection.
* **Cloud Mode:** Connects to Microsoft Azure SQL Database using encrypted connection strings over TLS 1.2+. Suitable for cloud deployments and college viva demonstrations.

---

## 2. Setting Up an Azure SQL Database (Step-by-Step)

Follow these steps in the [Azure Portal](https://portal.azure.com/) using an **Azure for Students** subscription or Free Tier:

### Step 1: Create a Resource Group
1. Sign in to the Azure Portal.
2. In the search bar, search for **Resource Groups** and select **Create**.
3. Set **Resource group name:** `rg-trustmesh-dev`.
4. Set **Region:** Choose a region close to you (e.g., `Central India` or `East US`).
5. Click **Review + create** -> **Create**.

### Step 2: Create Azure SQL Logical Server & Database
1. In the portal search bar, search for **SQL databases** and select **Create**.
2. **Project details:**
   * Subscription: Select your student/free subscription.
   * Resource Group: Select `rg-trustmesh-dev`.
3. **Database details:**
   * Database name: `trustmesh-db`
   * Server: Click **Create new**.
     * Server name: `trustmesh-sql-server-` + (your initials/unique number) (e.g., `trustmesh-sql-server-sk`).
     * Location: Same region as resource group.
     * Authentication method: **Use SQL authentication**.
     * Server admin login: `trustmeshadmin`
     * Password: Create a strong password (minimum 8 characters, alphanumeric + symbol).
     * Click **OK**.
4. **Compute + storage:**
   * Click **Configure database**.
   * Select **Serverless** or **Basic (5 DTUs)** under DTU-based purchasing (lowest cost / free grant eligible).
5. Click **Review + create** -> **Create**. (Deployment takes ~2–3 minutes).

### Step 3: Configure Azure SQL Firewall Rules
By default, Azure SQL blocks all incoming connections from the Internet. You must allow traffic from your machine and Azure services:
1. Navigate to your newly created **SQL server** in the Azure portal.
2. Under the left navigation menu, select **Security** -> **Networking**.
3. Under **Public network access**, select **Selected networks**.
4. Check **Allow Azure services and resources to access this server** (Required for Azure App Service).
5. Under **Firewall rules**, click **+ Add your client IPv4 address** (Adds your current home/college IP).
6. Click **Save**.

---

## 3. Environment Variable Configuration

Create or update your local `.env` file (copied from `.env.example`).

### Switching to Azure SQL Mode
In your `.env` file, change `DATABASE_MODE` and fill in your server credentials:

```bash
# Set mode to 'azure_sql'
DATABASE_MODE=azure_sql

# Azure SQL Server Credentials (from Azure Portal)
AZURE_SQL_SERVER=trustmesh-sql-server-sk.database.windows.net
AZURE_SQL_DATABASE=trustmesh-db
AZURE_SQL_USERNAME=trustmeshadmin
AZURE_SQL_PASSWORD=YourStrongPassword123!
AZURE_SQL_DRIVER={ODBC Driver 18 for SQL Server}

# Optional: Full URL format
# DATABASE_URL=mssql+pyodbc://trustmeshadmin:YourStrongPassword123!@trustmesh-sql-server-sk.database.windows.net/trustmesh-db?driver=ODBC+Driver+18+for+SQL+Server&Encrypt=yes
```

> **Security Rule:** Never commit the `.env` file to Git! Ensure `.env` is listed in your `.gitignore` file.

---

## 4. Database Migration & Schema Creation

Before the application can use Azure SQL, the 3NF schema (7 tables, views, triggers, and seed signals) must be created in Azure SQL.

### Step 1: Pre-Migration Backup Advisory
Always back up your local data:
```powershell
# In PowerShell:
cp instance/trustmesh.db instance/trustmesh_backup.db
```

### Step 2: Validate Connection & Dry Run
Run the migration script in `--dry-run` mode to verify that the schema file parses all batches without syntax errors:
```powershell
python migrate_to_azure.py --dry-run
```

### Step 3: Test Connectivity
Test whether your credentials and firewall allow a connection to Azure SQL:
```powershell
python migrate_to_azure.py --verify
```

### Step 4: Apply Schema to Azure SQL
Apply the 3NF tables, constraints, view, triggers, and seed signals to Azure SQL:
```powershell
python migrate_to_azure.py --apply-schema
```

*Alternatively*, you can open the **Query Editor** directly inside the Azure Portal for `trustmesh-db`, paste the contents of `schema_azuresql.sql`, and click **Run**.

---

## 5. SQL Server Compatibility Differences (Viva Defense)

When migrating from SQLite to Microsoft Azure SQL Database, several dialect adaptations were implemented in `schema_azuresql.sql` and `database.py`:

| Feature | Local SQLite | Microsoft Azure SQL Database | Reason for Adaptation |
| :--- | :--- | :--- | :--- |
| **Primary Keys** | `INTEGER PRIMARY KEY AUTOINCREMENT` | `INT IDENTITY(1,1) PRIMARY KEY` | SQL Server uses the `IDENTITY` property for sequence generation. |
| **Timestamps** | `TIMESTAMP DEFAULT CURRENT_TIMESTAMP` | `DATETIME2 DEFAULT SYSUTCDATETIME()` | `DATETIME2` offers microsecond precision and UTC timestamping in SQL Server. |
| **Text Data** | `TEXT` | `NVARCHAR(MAX)` or `NVARCHAR(n)` | `NVARCHAR` supports unicode character encoding and indexing. |
| **Pagination** | `LIMIT ?` | `OFFSET 0 ROWS FETCH NEXT ? ROWS ONLY` | T-SQL standard ANSI SQL-2012 pagination. |
| **Insert Returning** | `cur.lastrowid` | `OUTPUT INSERTED.column_id` | Atomic row identification in concurrent multi-user environments. |
| **Trigger Syntax** | SQLite `BEGIN...END;` with `NEW` row | T-SQL `CREATE OR ALTER TRIGGER` using `inserted` virtual table | SQL Server triggers operate on set-based virtual tables (`inserted` / `deleted`). |
| **Foreign Keys** | Requires `PRAGMA foreign_keys = ON;` | Enforced automatically by DBMS | SQLite disables foreign key checks by default; SQL Server enforces them natively. |

---

## 6. How Switching Works in the Application

The application detects the database mode at startup and on every connection request:

1. **`get_database_mode()` in `database.py`:**
   Reads `DATABASE_MODE` from environment variables.
   * If `DATABASE_MODE=azure_sql` -> Uses `get_azure_sql_connection()`.
   * If `DATABASE_MODE=sqlite` (or unset) -> Uses `get_sqlite_connection()`.
2. **Isolation for Automated Tests:**
   When automated test suites run (`test_phase2.py`, `test_phase3.py`), they pass an explicit `db_path` parameter to use temporary SQLite databases. The application honors this local parameter, ensuring that running tests locally never touches or pollutes the cloud database.
3. **Database Health Indicator:**
   The UI header and `/health` endpoint report live status:
   * `Local SQLite connected` (green pulse)
   * `Azure SQL connected` (blue cloud pulse)
   * `Database unavailable` (red alert pulse)
   * **Guarantee:** Azure SQL is *never* displayed as connected unless a live query (`SELECT 1;`) successfully completes.

---

## 7. Troubleshooting Common Issues

### Issue 1: "Cannot open server '...' requested by the login. Client with IP address '...' is not allowed to access the server."
* **Cause:** Your IP address changed or has not been added to the Azure SQL Server firewall.
* **Fix:** Go to Azure Portal -> SQL Server -> **Networking** -> click **Add your client IPv4 address** -> **Save**.

### Issue 2: "Login failed for user '...'"
* **Cause:** Incorrect username or password in `.env`.
* **Fix:** Verify `AZURE_SQL_USERNAME` and `AZURE_SQL_PASSWORD` in `.env`. Remember that user name is typically `username` (or `username@servername` in older configurations).

### Issue 3: "ODBC Driver 18 for SQL Server: SSL Provider: The certificate chain was issued by an authority that is not trusted."
* **Cause:** Driver 18 enforces encryption by default.
* **Fix:** The connection string in TRUSTMESH already includes `Encrypt=yes;TrustServerCertificate=no;`. If using a self-signed development certificate, set `TrustServerCertificate=yes;`.

### Issue 4: Local Driver Missing on Windows
* **Cause:** Python environment missing `pyodbc` or ODBC Driver.
* **Fix:** If developing locally without ODBC drivers, simply keep `DATABASE_MODE=sqlite`. In Linux Azure App Service, `pyodbc` installs seamlessly from pre-built binary wheels.

