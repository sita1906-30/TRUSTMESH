# TRUSTMESH — Microsoft Azure Blob Storage Integration Guide

**Academic Phase:** Phase 4, Task 3: Cloud Report Archiving & Secure Retrieval  
**Target Audience:** 2nd-Year B.Tech Computer Science and Engineering (AI/ML) Students  
**Feature:** Optional Assessment Report Archiving with Azure Blob Storage & Local Fallback

---

## 1. What is Azure Blob Storage & Why Does TRUSTMESH Use It?

### What is Azure Blob Storage?
**Microsoft Azure Blob Storage** is a massively scalable, highly available cloud object storage service designed for storing unstructured binary and text data (such as JSON documents, images, PDFs, and video files). Unlike a relational SQL database that stores data in tables with columns and rows, Blob Storage stores files as independent **blobs** (Binary Large Objects) grouped inside **containers**.

### Why Does TRUSTMESH Use It?
In TRUSTMESH, users evaluate suspicious messages and URLs. After completing an evaluation, an authenticated user can generate a structured **Assessment Report**.

1. **Separation of Concerns:** Relational databases (SQLite / Azure SQL) are optimized for transactional data and structured queries, not for storing thousands of exported document files. Storing reports as cloud blobs keeps the database lean and performant.
2. **Durability & Availability:** Azure Blob Storage provides automatic replication (LRS/GRS) ensuring zero data loss and 99.9% uptime.
3. **Privacy by Design:** Raw message content is never stored. Only the evaluation metrics, detected risk heuristics, safety guidance, and cryptographic SHA-256 fingerprints are archived.
4. **Optional Cloud Architecture:** Cloud archiving is strictly optional. If Azure Blob Storage is not configured or goes offline, TRUSTMESH gracefully provides direct local browser downloads without crashing.

---

## 2. Storage Architecture & Data Flow

```
                                      +------------------------------------+
                                      |          Authenticated User        |
                                      +------------------------------------+
                                                         |
                                                         | 1. POST /api/reports/export
                                                         v
                                      +------------------------------------+
                                      |         TRUSTMESH Backend          |
                                      |     (Flask Controller: app.py)     |
                                      +------------------------------------+
                                        /                                \
                 2. Store Report Metadata                                  3. Upload Encrypted JSON Blob
                                      /                                    (if save_to_cloud=true)
                                     v                                      \
+------------------------------------------+                                 v
| Database (SQLite / Azure SQL)            |              +-----------------------------------------+
| Table: EXPORTED_REPORTS                  |              | Azure Blob Storage                      |
| • report_id (PK)                         |              | Storage Account: yourstorageaccountname |
| • user_id (FK -> USERS)                  |              | Container: trustmesh-reports (PRIVATE)  |
| • assessment_id (FK -> ASSESSMENTS)      |              | Path:                                   |
| • blob_name: reports/user_2/report_...   |              | reports/user_2/trustmesh_report_12.json |
| • storage_status ('LOCAL' / 'UPLOADED')  |              +-----------------------------------------+
+------------------------------------------+                                 |
                                                                             | 4. GET /api/reports/<id>/download
                                                                             | (Ownership verified on backend)
                                                                             v
                                                          +-----------------------------------------+
                                                          | Browser Direct Download Attachment      |
                                                          | trustmesh_report_<id>.json              |
                                                          +-----------------------------------------+
```

---

## 3. Creating Azure Storage Account & Private Container (Step-by-Step)

Follow these steps in the [Azure Portal](https://portal.azure.com/) using an **Azure for Students** subscription or Free Tier:

### Step 1: Create a Storage Account
1. Sign in to the Azure Portal.
2. In the top search bar, search for **Storage accounts** and click **Create**.
3. **Project Details:**
   * **Subscription:** Select your student or free subscription.
   * **Resource group:** Select `rg-trustmesh-dev` (created in Task 2).
4. **Instance Details:**
   * **Storage account name:** Must be globally unique, lowercase alphanumeric only (e.g., `trustmeshstorage` + initials).
   * **Region:** Same region as your resource group (e.g., `Central India` or `East US`).
   * **Primary service:** Azure Blob Storage.
   * **Performance:** Standard.
   * **Redundancy:** Locally redundant storage (LRS) (lowest cost / free grant eligible).
5. Click **Review + create** -> **Create**.

### Step 2: Create a Private Blob Container
1. Open your newly created storage account.
2. Under the left menu, select **Data storage** -> **Containers**.
3. Click **+ Container**.
4. **Name:** `trustmesh-reports`.
5. **Anonymous access level:** **Private (no anonymous access)**.
   > **Critical Security Rule:** Never set anonymous access to Public. Keeping the container private guarantees that reports cannot be accessed without authenticated backend authorization.
6. Click **Create**.

### Step 3: Retrieve Connection String
1. Under the left menu, select **Security + networking** -> **Access keys**.
2. Under **key1**, click **Show** next to **Connection string**.
3. Copy the connection string. It looks like:
   `DefaultEndpointsProtocol=https;AccountName=yourstorageaccount;AccountKey=...;EndpointSuffix=core.windows.net`

---

## 4. Environment Variable Configuration

Update your `.env` file (never commit this file to Git):

```bash
# Azure Blob Storage Configuration
AZURE_STORAGE_ACCOUNT_NAME=yourstorageaccount
AZURE_STORAGE_CONTAINER_NAME=trustmesh-reports
AZURE_STORAGE_CONNECTION_STRING=DefaultEndpointsProtocol=https;AccountName=yourstorageaccount;AccountKey=your-secret-key;EndpointSuffix=core.windows.net
```

---

## 5. How Report Export & Archiving Works

### Upload Workflow
1. The user completes an assessment on the web scanner.
2. The user clicks **Download Assessment Report** with **Save to Azure Blob Storage** checked.
3. The frontend makes an authenticated POST request to `/api/reports/export` with the `assessment_id` and CSRF token.
4. The server verifies that the assessment belongs to the currently signed-in user (`WHERE i.user_id = session["user_id"]`).
5. The server builds a standardized JSON report payload:
   * Evaluation metadata (timestamp, engine version, platform name).
   * Risk metrics (0–100 score, tier level).
   * Detected signals breakdown with awarded points.
   * Tailored recommendations and safety disclaimers.
   * SHA-256 content fingerprint (raw text is omitted).
6. If Azure Blob Storage is configured:
   * The `blob_storage_service.py` module uploads the JSON payload over encrypted HTTPS to `reports/user_<id>/trustmesh_report_asm_<id>_<timestamp>_<uuid>.json`.
   * The database record is tagged with `storage_status = 'UPLOADED'`.
7. If Azure Blob Storage is unconfigured or unavailable:
   * The database record is tagged with `storage_status = 'LOCAL'`.
   * The browser directly downloads the file with an advisory message: *"Azure Storage is not configured. Downloaded locally."*

### Download Workflow & Access Control
1. User requests a download via `/api/reports/<report_id>/download`.
2. **Server-Side Authorization:** The server verifies `report_record["user_id"] == session["user_id"]`. If an attacker tampers with the URL to download another student's report, access is denied with **HTTP 403 Forbidden** and a security audit event is logged.
3. If `storage_status == 'UPLOADED'`, the server fetches the file securely from Azure Blob Storage and streams it as a browser attachment.
4. If cloud storage is temporarily unreachable, the system automatically regenerates the report from the database and delivers it seamlessly.

---

## 6. Security & Privacy Guarantees

* **Zero Credential Leaks:** Passwords and storage keys are never rendered in frontend HTML, JavaScript, or public logs. The `mask_storage_key()` utility scrubs keys before writing to log streams.
* **No Public Blob URLs:** The container does not allow anonymous web requests. All access is brokered through the authenticated Flask backend.
* **Input Validation & Traversal Prevention:** Blob names are validated against a strict alphanumeric regex (`^[a-zA-Z0-9_\-\.\/]+$`). Any path traversal attempts (`..` or leading slashes) are rejected.
* **File Size Limit:** Upload payloads are capped at 500 KB to protect memory and prevent storage exhaustion attacks.
* **Audit Logging:** Every report export and unauthorized access attempt is recorded in the `AUDIT_LOGS` table.

---

## 7. Testing Locally Without Azure Credentials

You can test all report export and download capabilities locally without an Azure subscription:

1. **Leave Credentials Blank:** Keep `AZURE_STORAGE_CONNECTION_STRING=` empty in your `.env`.
2. **Automatic Fallback:** Click **Export Assessment Report**. TRUSTMESH will automatically format the report, record the local metadata in `EXPORTED_REPORTS`, and download the JSON file to your device.
3. **Run Automated Test Suite:**
   ```powershell
   python -m unittest test_blob_storage.py
   ```
   All tests (authorization checks, parameter tampering prevention, mock cloud uploads/downloads, and size limits) run using memory mocks and isolated SQLite databases.

